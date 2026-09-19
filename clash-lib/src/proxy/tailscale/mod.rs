mod datagram;

use datagram::TailscaleDatagramOutbound;

use std::{
    collections::HashMap, fmt::Debug, io, net::IpAddr, path::PathBuf, sync::Arc,
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use tailscale::config::{BadFormatBehavior, load_key_file};
use tokio::sync::Mutex;

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    session::{Session, SocksAddr},
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};

const TAILSCALE_CLIENT_NAME: &str = "clash-rs";
const TAILSCALE_STATE_FILE_NAME: &str = "tailscale_state.json";

#[derive(Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub state_dir: Option<String>,
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    pub control_url: Option<String>,
    pub client_name: Option<String>,
    pub ephemeral: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    device: Mutex<Option<Arc<::tailscale::Device>>>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailscale")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            device: Mutex::new(None),
        }
    }

    /// Lazily initialise and return the shared [`tailscale::Device`].
    ///
    /// **State persistence**: when `state_dir` is set the device identity is
    /// loaded from (and automatically written back to) a JSON file so it
    /// survives process restarts.  When `state_dir` is `None` the identity is
    /// held in memory only; the device will register a fresh node on every
    /// startup unless `ephemeral: true` is also set.
    async fn get_device(&self) -> io::Result<Arc<::tailscale::Device>> {
        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(Arc::clone(device));
        }

        let key_state = if self.opts.ephemeral {
            Default::default()
        } else if let Some(state_dir) = self.opts.state_dir.as_ref() {
            // load_key_file reads persisted key material so the device keeps
            // the same Tailscale identity across restarts.  The tailscale-rs
            // crate writes updated state back to the file automatically while
            // the Device is alive; no explicit save step is required.
            let state_file =
                PathBuf::from(state_dir).join(TAILSCALE_STATE_FILE_NAME);
            load_key_file(state_file, BadFormatBehavior::Error)
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to initialize tailscale key state: {e}"
                    ))
                })?
        } else {
            // ephemeral: false but no state_dir — identity is in-memory only
            // and will be lost when the process exits.  Log so users are aware.
            tracing::warn!(
                name = %self.opts.name,
                "tailscale: ephemeral is false but no state-dir is configured; \
                 device identity will not be persisted across restarts"
            );
            Default::default()
        };

        let mut config = ::tailscale::Config {
            key_state,
            ..Default::default()
        };
        config.client_name = Some(
            self.opts
                .client_name
                .as_deref()
                .unwrap_or(TAILSCALE_CLIENT_NAME)
                .to_owned(),
        );
        config.requested_hostname = self.opts.hostname.clone();

        if let Some(control_url) = self.opts.control_url.as_ref() {
            config.control_server_url = control_url.parse().map_err(|e| {
                io::Error::other(format!("invalid tailscale control-url: {e}"))
            })?;
        }

        // tailscale-rs requires this env var as an acknowledgement that the
        // crate is experimental.  Set it on behalf of the user so they don't
        // need to configure it themselves.
        // SAFETY: single-threaded point inside a Mutex-guarded lazy-init block;
        // no other thread is reading or writing this variable concurrently.
        unsafe {
            std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");
        }

        let device = Arc::new(
            ::tailscale::Device::new(&config, self.opts.auth_key.clone())
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to initialize tailscale-rs device: {e}"
                    ))
                })?,
        );
        *guard = Some(Arc::clone(&device));
        Ok(device)
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tailscale
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedStream> {
        let remote_ip = match &sess.destination {
            SocksAddr::Ip(addr) => addr.ip(),
            SocksAddr::Domain(host, _) => resolver
                .resolve(host, false)
                .await
                .map_err(map_io_error)?
                .ok_or_else(|| io::Error::other("no dns result"))?,
        };
        let device = self.get_device().await?;
        let s = device
            .tcp_connect((remote_ip, sess.destination.port()).into())
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to connect over tailscale-rs to {}:{}: {e}",
                    remote_ip,
                    sess.destination.port()
                ))
            })?;

        let s = InstrumentedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        let device = self.get_device().await?;
        let local_ip: IpAddr = match &sess.destination {
            // Strict: IP literal family must match — fail fast rather than binding
            // wrong family
            SocksAddr::Ip(addr) if addr.is_ipv6() => {
                device.ipv6_addr().await.map(IpAddr::V6).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv6 address for ipv6 \
                         destination: {e}"
                    ))
                })?
            }
            SocksAddr::Ip(_) => {
                device.ipv4_addr().await.map(IpAddr::V4).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv4 address for ipv4 \
                         destination: {e}"
                    ))
                })?
            }
            // Domain destination: v4-first with v6 fallback is appropriate
            SocksAddr::Domain(..) => match device.ipv4_addr().await {
                Ok(ip) => IpAddr::V4(ip),
                Err(_) => device.ipv6_addr().await.map(IpAddr::V6).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale address: {e}"
                    ))
                })?,
            },
        };
        let port = rand::random_range(49152u16..=u16::MAX);
        let udp = device
            .udp_bind((local_ip, port).into())
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to bind tailscale udp socket on {local_ip}: {e}"
                ))
            })?;

        let d = TailscaleDatagramOutbound::new(udp, resolver);
        let d = InstrumentedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        if let Some(state_dir) = &self.opts.state_dir {
            m.insert("state-dir".to_owned(), Box::new(state_dir.clone()) as _);
        }
        if let Some(hostname) = &self.opts.hostname {
            m.insert("hostname".to_owned(), Box::new(hostname.clone()) as _);
        }
        if let Some(control_url) = &self.opts.control_url {
            m.insert("control-url".to_owned(), Box::new(control_url.clone()) as _);
        }
        m.insert(
            "client-name".to_owned(),
            Box::new(
                self.opts
                    .client_name
                    .as_deref()
                    .unwrap_or(TAILSCALE_CLIENT_NAME)
                    .to_owned(),
            ) as _,
        );
        m.insert("ephemeral".to_owned(), Box::new(self.opts.ephemeral) as _);
        m.insert(
            "auth-key-set".to_owned(),
            Box::new(self.opts.auth_key.is_some()) as _,
        );
        m
    }
}

impl crate::proxy::ProxyStream for ::tailscale::netstack::TcpStream {}

#[cfg(test)]
mod tests {
    use super::{Handler, HandlerOptions};
    use crate::proxy::{OutboundHandler, PlainProxyAPIResponse};

    #[cfg(target_os = "linux")]
    use std::net::SocketAddr;
    #[cfg(target_os = "linux")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(target_os = "linux")]
    use {
        crate::{proxy::datagram::UdpPacket, session::SocksAddr},
        futures::{SinkExt, StreamExt},
    };

    #[cfg(target_os = "linux")]
    const DNS_TEST_TXID: u16 = 0xBEEF;

    #[cfg(target_os = "linux")]
    fn build_dns_query(host: &str, txid: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&txid.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in host.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[tokio::test]
    async fn tailscale_support_udp_is_enabled() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: None,
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: false,
        });
        assert!(h.support_udp().await);
    }

    #[tokio::test]
    async fn tailscale_api_response_redacts_auth_key() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: Some("tskey-auth-xxxx".to_owned()),
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: false,
        });
        let map = h.as_map().await;
        assert!(
            map.contains_key("auth-key-set"),
            "auth-key-set should be present"
        );
        assert!(
            !map.contains_key("auth-key"),
            "raw auth-key must not be present"
        );
    }

    // tailscale-rs's userspace runtime works on Linux only in CI; the macOS
    // GitHub Actions sandbox blocks the control-plane connections it needs.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn tailscale_live_auth_key_supports_real_tcp_and_udp_traffic() {
        crate::setup_default_crypto_provider();

        // Surface tailscale-rs internal logs so CI can show exactly why
        // the control actor fails if the test does not pass.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| {
                        "ts_control=debug,ts_runtime=debug".parse().unwrap()
                    }),
            )
            .try_init();

        let auth_key = match std::env::var("TS_AUTH_KEY") {
            Ok(v) if !v.is_empty() => v,
            _ => return,
        };

        // Homelab services reachable via tailnet subnet router.
        let tcp_addr: SocketAddr = "10.1.0.5:5380".parse().unwrap();
        let udp_addr: SocketAddr = "10.1.0.5:53".parse().unwrap();

        let h = Handler::new(HandlerOptions {
            name: "ts-live-auth".to_owned(),
            state_dir: None,
            auth_key: Some(auth_key),
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: true,
        });

        let device = h.get_device().await.expect("tailscale device init failed");

        let addr = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            device.ipv4_addr(),
        )
        .await
        .expect("timed out waiting for tailscale IPv4 address")
        .expect("tailscale device failed to acquire IPv4 address");

        assert!(
            !addr.is_unspecified(),
            "tailscale device returned an unspecified IPv4 address"
        );

        // Wait for subnet routes from the netmap to propagate into the
        // smoltcp routing table. ipv4_addr() resolves as soon as self_node
        // is set, but the RouteUpdater processes routes asynchronously from
        // the same StateUpdate message, so a brief pause is required before
        // packets to subnet IPs (10.1.0.0/24 via the subnet router) can route.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // TCP: connect to homelab server via tailnet subnet router.
        let mut tcp_stream = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            device.tcp_connect(tcp_addr),
        )
        .await
        .expect("timed out connecting tcp over tailscale")
        .expect("tcp connect over tailscale failed");

        let req = "HEAD / HTTP/1.1\r\nHost: 10.1.0.5\r\nConnection: close\r\n\r\n";
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tcp_stream.write_all(req.as_bytes()),
        )
        .await
        .expect("timed out writing tcp request over tailscale")
        .expect("tcp write over tailscale failed");

        tcp_stream.flush().await.ok();

        let mut tcp_resp = [0u8; 256];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tcp_stream.read(&mut tcp_resp),
        )
        .await
        .expect("timed out reading tcp response over tailscale")
        .expect("tcp read over tailscale failed");

        assert!(n > 0, "expected non-empty tcp response over tailscale");

        // UDP via TailscaleDatagramOutbound: exercise connect_datagram and the
        // Sink/Stream wrappers by sending a real DNS query to the homelab.
        let resolver =
            std::sync::Arc::new(crate::proxy::utils::test_utils::noop::NoopResolver);
        let sess = crate::session::Session {
            destination: SocksAddr::Ip(udp_addr),
            ..Default::default()
        };
        let mut dgram = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            h.connect_datagram(&sess, resolver),
        )
        .await
        .expect("timed out creating tailscale datagram outbound")
        .expect("connect_datagram over tailscale failed");

        let query = build_dns_query("login.tailscale.com", DNS_TEST_TXID);
        let pkt = UdpPacket {
            data: query.into(),
            src_addr: SocksAddr::Ip(std::net::SocketAddr::new(addr.into(), 0)),
            dst_addr: SocksAddr::Ip(udp_addr),
            inbound_user: None,
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), dgram.send(pkt))
            .await
            .expect("timed out sending datagram over tailscale")
            .expect("datagram send over tailscale failed");

        let resp =
            tokio::time::timeout(std::time::Duration::from_secs(20), dgram.next())
                .await
                .expect("timed out receiving datagram over tailscale")
                .expect("datagram stream ended without a response");

        assert!(
            resp.data.len() >= 2,
            "expected non-empty datagram response over tailscale"
        );
        let resp_txid = u16::from_be_bytes([resp.data[0], resp.data[1]]);
        assert_eq!(
            resp_txid, DNS_TEST_TXID,
            "unexpected DNS transaction id in datagram response"
        );
    }
}
