mod compat;
mod handle_stream;
mod handle_task;
pub(crate) mod types;

use crate::{
    common::tls::{DefaultTlsVerifier, build_tls_client_config},
    proxy::{tuic::types::SocketAdderTrans, utils::new_udp_socket},
};
use anyhow::Result;
use async_trait::async_trait;

use tracing::debug;
use tuic_core::quinn::{
    ClientConfig as QuinnConfig, Endpoint as QuinnEndpoint, EndpointConfig,
    TokioRuntime, TransportConfig as QuinnTransportConfig, VarInt,
    bbr::BbrConfig,
    congestion::{Bbr3Config, CubicConfig, NewRenoConfig},
    crypto::rustls::QuicClientConfig,
};

use erased_serde::Serialize as ErasedSerialize;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};

use uuid::Uuid;

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    proxy::{
        DialWithConnector,
        tuic::types::{ServerAddr, TuicEndpoint},
    },
    session::Session,
};

use crate::session::SocksAddr as ClashSocksAddr;
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use self::types::{CongestionControl, TuicConnection, UdpRelayMode, UdpSession};

use super::{
    ConnectorType, HandlerCommonOptions, OutboundHandler, OutboundType,
    PlainProxyAPIResponse, datagram::UdpPacket,
};

#[derive(Debug, Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Uuid,
    pub password: String,
    pub udp_relay_mode: UdpRelayMode,
    pub disable_sni: bool,
    pub alpn: Vec<Vec<u8>>,
    pub heartbeat_interval: Duration,
    pub reduce_rtt: bool,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
    pub congestion_controller: CongestionControl,
    pub max_open_stream: VarInt,
    pub gc_interval: Duration,
    pub gc_lifetime: Duration,
    pub send_window: u64,
    pub receive_window: VarInt,
    pub skip_cert_verify: bool,

    #[allow(dead_code)]
    pub common_opts: HandlerCommonOptions,

    /// not used
    #[allow(dead_code)]
    pub max_udp_relay_packet_size: u64,
    pub ip: Option<String>,
    pub sni: Option<String>,
    /// File path or inline PEM client certificate for mTLS.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    pub tls_key: Option<String>,
}

pub struct Handler {
    opts: HandlerOptions,
    ep: OnceCell<TuicEndpoint>,
    conn: AsyncMutex<Option<Arc<TuicConnection>>>,
    next_assoc_id: AtomicU16,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tuic
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedStream> {
        self.do_connect_stream(sess, resolver).await.map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::other(e.to_string())
        })
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        self.do_connect_datagram(sess, resolver).await.map_err(|e| {
            tracing::error!("{:?}", e);
            std::io::Error::other(e.to_string())
        })
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
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert("uuid".to_owned(), Box::new(self.opts.uuid.to_string()) as _);
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        let udp_relay_mode = match &self.opts.udp_relay_mode {
            crate::proxy::tuic::types::UdpRelayMode::Native => "native",
            crate::proxy::tuic::types::UdpRelayMode::Quic => "quic",
        };
        m.insert(
            "udp-relay-mode".to_owned(),
            Box::new(udp_relay_mode.to_string()) as _,
        );
        if self.opts.skip_cert_verify {
            m.insert("skip-cert-verify".to_owned(), Box::new(true) as _);
        }
        if let Some(sni) = self.opts.sni.as_ref() {
            m.insert("sni".to_owned(), Box::new(sni.clone()) as _);
        }
        if self.opts.disable_sni {
            m.insert("disable-sni".to_owned(), Box::new(true) as _);
        }
        m
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            ep: OnceCell::new(),
            conn: AsyncMutex::new(None),
            next_assoc_id: AtomicU16::new(0),
        }
    }

    async fn init_endpoint(
        opts: HandlerOptions,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<TuicEndpoint> {
        let verifier =
            Arc::new(DefaultTlsVerifier::new(None, opts.skip_cert_verify));
        let mut crypto = build_tls_client_config(
            verifier,
            opts.tls_cert.as_deref(),
            opts.tls_key.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("tuic TLS: {e}"))?;
        // TODO(error-handling) if alpn not match the following error will be
        // throw: aborted by peer: the cryptographic handshake failed: error
        // 120: peer doesn't support any known protocol
        crypto.alpn_protocols.clone_from(&opts.alpn);
        crypto.enable_early_data = true;
        crypto.enable_sni = !opts.disable_sni;

        let mut quinn_config =
            QuinnConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
        let mut transport_config = QuinnTransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(opts.max_open_stream)
            .max_concurrent_uni_streams(opts.max_open_stream)
            .send_window(opts.send_window)
            .stream_receive_window(opts.receive_window)
            .max_idle_timeout(Some(opts.idle_timeout.try_into().unwrap()));
        match opts.congestion_controller {
            CongestionControl::Cubic => transport_config
                .congestion_controller_factory(Arc::new(CubicConfig::default())),
            CongestionControl::NewReno => transport_config
                .congestion_controller_factory(Arc::new(NewRenoConfig::default())),
            CongestionControl::Bbr => transport_config
                .congestion_controller_factory(Arc::new(BbrConfig::default())),
            CongestionControl::Bbr3 => transport_config
                .congestion_controller_factory(Arc::new(Bbr3Config::default())),
        };

        quinn_config.transport_config(Arc::new(transport_config));

        // TODO: we should try to resolve the server address once?
        let socket = {
            if resolver.ipv6() {
                new_udp_socket(
                    Some((Ipv6Addr::UNSPECIFIED, 0).into()),
                    sess.iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                    None,
                )
                .await?
            } else {
                new_udp_socket(
                    Some((Ipv4Addr::UNSPECIFIED, 0).into()),
                    None,
                    #[cfg(target_os = "linux")]
                    sess.so_mark,
                    None,
                )
                .await?
            }
        };

        debug!("binding socket to: {:?}", socket.local_addr()?);

        let endpoint = QuinnEndpoint::new(
            EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(TokioRuntime),
        )?;

        endpoint.set_default_client_config(quinn_config);

        // Parse ip field if provided
        let ip_addr = opts.ip.as_ref().and_then(|ip_str| ip_str.parse().ok());

        let endpoint = TuicEndpoint {
            ep: endpoint,
            server: ServerAddr::new(opts.server, opts.port, ip_addr, opts.sni),
            uuid: opts.uuid,
            password: Arc::from(opts.password.into_bytes().into_boxed_slice()),
            udp_relay_mode: opts.udp_relay_mode,
            zero_rtt_handshake: opts.reduce_rtt,
            heartbeat: opts.heartbeat_interval,
            gc_interval: opts.gc_interval,
            gc_lifetime: opts.gc_lifetime,
        };

        Ok(endpoint)
    }

    async fn get_conn(
        &self,
        resolver: &ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<Arc<TuicConnection>> {
        let endpoint = self
            .ep
            .get_or_try_init(|| {
                Self::init_endpoint(self.opts.clone(), resolver.clone(), sess)
            })
            .await?;

        let fut = async {
            let mut guard = self.conn.lock().await;

            let conn = match guard.as_ref() {
                None => {
                    // init
                    let new_conn = endpoint.connect(resolver, false).await?;
                    *guard = Some(new_conn.clone());
                    new_conn
                }
                Some(existing) if existing.check_open().is_err() => {
                    // reconnect
                    let new_conn = endpoint.connect(resolver, true).await?;
                    *guard = Some(new_conn.clone());
                    new_conn
                }
                Some(existing) => existing.clone(),
            };

            Ok(conn)
        };

        tokio::time::timeout(self.opts.request_timeout, fut).await?
    }

    async fn do_connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedInstrumentedStream> {
        let conn = self.get_conn(&resolver, sess).await?;
        let dest = sess.destination.clone().into_tuic();
        let tuic_tcp = conn.connect_tcp(dest).await?;
        let s = InstrumentedStreamWrapper::new(tuic_tcp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedInstrumentedDatagram> {
        let conn = self.get_conn(&resolver, sess).await?;
        let assos_id = self.next_assoc_id.fetch_add(1, Ordering::SeqCst);
        let quic_udp = TuicDatagramOutbound::new(assos_id, conn, sess.source.into());
        let s = InstrumentedDatagramWrapper::new(quic_udp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }
}

#[derive(Debug)]
struct TuicDatagramOutbound {
    send_tx: tokio_util::sync::PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
}

impl TuicDatagramOutbound {
    pub fn new(
        assoc_id: u16,
        conn: Arc<TuicConnection>,
        local_addr: ClashSocksAddr,
    ) -> Self {
        // TODO not sure about the size of buffer
        let (send_tx, send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let udp_sessions = conn.udp_sessions.clone();
        tokio::spawn(async move {
            // capture vars
            let (mut send_rx, recv_tx) = (send_rx, recv_tx);
            udp_sessions.write().await.insert(
                assoc_id,
                UdpSession {
                    incoming: recv_tx,
                    local_addr,
                },
            );
            while let Some(next_send) = send_rx.recv().await {
                let res = conn
                    .outgoing_udp(
                        next_send.data.into(),
                        next_send.dst_addr.into_tuic(),
                        assoc_id,
                    )
                    .await;
                if res.is_err() {
                    break;
                }
            }
            // TuicDatagramOutbound dropped or outgoing_udp occurs error
            tracing::info!(
                "[udp] [dissociate] closing UDP session [{assoc_id:#06x}]"
            );
            _ = conn.dissociate(assoc_id).await;
            udp_sessions.write().await.remove(&assoc_id);
            anyhow::Ok(())
        });

        Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
        }
    }
}

impl crate::proxy::ProxyStream for tuic_core::quinn::Connect {}

#[cfg(test)]
pub(crate) mod test_utils;

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{test_utils::TuicServerProcess, *};
    use crate::{
        proxy::utils::{
            GLOBAL_DIRECT_CONNECTOR,
            test_utils::{
                echo::{TcpEchoConfig, TcpEchoServer},
                noop::NoopResolver,
            },
        },
        session::Session,
    };

    fn gen_options(port: u16) -> anyhow::Result<HandlerOptions> {
        gen_options_with(port, "127.0.0.1", "127.0.0.1")
    }

    fn gen_options_v6(port: u16) -> anyhow::Result<HandlerOptions> {
        gen_options_with(port, "::1", "::1")
    }

    fn gen_options_with(
        port: u16,
        server: &str,
        ip: &str,
    ) -> anyhow::Result<HandlerOptions> {
        Ok(HandlerOptions {
            name: "test-tuic".to_owned(),
            server: server.to_owned(),
            port,
            common_opts: Default::default(),
            uuid: "00000000-0000-0000-0000-000000000001".parse()?,
            password: "passwd".into(),
            udp_relay_mode: UdpRelayMode::Native,
            disable_sni: true,
            alpn: vec!["h3".into()],
            heartbeat_interval: Duration::from_millis(3000),
            reduce_rtt: false,
            request_timeout: Duration::from_millis(4000),
            idle_timeout: Duration::from_millis(4000),
            congestion_controller: CongestionControl::Bbr,
            max_udp_relay_packet_size: 1500,
            max_open_stream: VarInt::from_u64(32)?,
            ip: Some(ip.to_owned()),
            skip_cert_verify: true,
            sni: Some("localhost".to_owned()),
            gc_interval: Duration::from_millis(3000),
            gc_lifetime: Duration::from_millis(15000),
            send_window: 8 * 1024 * 1024 * 2,
            receive_window: VarInt::from_u64(8 * 1024 * 1024)?,
            tls_cert: None,
            tls_key: None,
        })
    }

    fn ipv6_resolver() -> crate::app::dns::ThreadSafeDNSResolver {
        let mut mock = crate::app::dns::MockClashResolver::new();
        mock.expect_ipv6().return_const(true);
        Arc::new(mock)
    }

    /// TCP ping-pong test: start an echo server, connect through tuic, send
    /// "hello" and verify we receive "world" back.
    ///
    /// Skipped on non-x86_64 Linux because all such targets in CI are
    /// cross-built and run under qemu-user, where QUIC timing is unreliable
    /// (packets get reordered/dropped enough to race the TUIC idle / request
    /// timeouts and reset the relay stream). Native Linux x86_64, macOS
    /// aarch64, and Windows x86_64 still cover it.
    #[tokio::test]
    #[cfg_attr(
        qemu_emulated,
        ignore = "QUIC under qemu-user (cross test) is unreliable"
    )]
    async fn test_tuic_ping_pong_tcp() -> anyhow::Result<()> {
        crate::tests::initialize();
        let server = TuicServerProcess::start().await?;
        let port = server.port();

        let echo = TcpEchoServer::start().await?;
        let target_port = echo.port();

        let opts = gen_options(port)?;
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        let resolver = Arc::new(NoopResolver);

        let session = Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Socks5,
            source: "127.0.0.1:54321".parse()?,
            destination: format!("127.0.0.1:{target_port}").parse()?,
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        let mut stream = handler.connect_stream(&session, resolver).await?;

        for _ in 0..10 {
            stream.write_all(b"hello").await?;
            stream.flush().await?;
            let mut buf = vec![0u8; 5];
            stream.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"world");
        }

        drop(echo);
        Ok(())
    }

    /// Verify that connecting with an invalid password fails.
    #[tokio::test]
    async fn test_tuic_auth_failure() -> anyhow::Result<()> {
        crate::tests::initialize();
        let server = TuicServerProcess::start().await?;
        let port = server.port();

        let echo = TcpEchoServer::start_with(TcpEchoConfig {
            response: b"world",
            expected_request: None,
            read_size: 5,
            iterations: None,
            ..Default::default()
        })
        .await?;
        let target_port = echo.port();

        let mut opts = gen_options(port)?;
        opts.password = "wrong_password".into();

        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        let resolver = Arc::new(NoopResolver);

        let session = Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Socks5,
            source: "127.0.0.1:54321".parse()?,
            destination: format!("127.0.0.1:{target_port}").parse()?,
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        let result = handler.connect_stream(&session, resolver).await;
        // The stream connect may succeed initially (auth is async), but
        // reading/writing should fail after the server rejects authentication.
        if let Ok(mut stream) = result {
            let mut buf = [0u8; 5];
            // Give the server time to process auth and close
            tokio::time::sleep(Duration::from_secs(1)).await;
            let write_result = stream.write_all(b"hello").await;
            let read_result = stream.read_exact(&mut buf).await;
            assert!(
                write_result.is_err() || read_result.is_err(),
                "expected IO error after auth failure, but both read and write \
                 succeeded"
            );
        }
        drop(echo);
        Ok(())
    }

    /// TCP ping-pong over IPv6 loopback.
    ///
    /// Skipped on non-x86_64 Linux — see `test_tuic_ping_pong_tcp`.
    #[tokio::test]
    #[cfg_attr(
        qemu_emulated,
        ignore = "QUIC under qemu-user (cross test) is unreliable"
    )]
    async fn test_tuic_ping_pong_tcp_ipv6() -> anyhow::Result<()> {
        if std::net::UdpSocket::bind("[::1]:0").is_err() {
            eprintln!("skipping: no IPv6 loopback");
            return Ok(());
        }
        crate::tests::initialize();
        let server = TuicServerProcess::start_v6().await?;
        let port = server.port();

        let echo = TcpEchoServer::start_with(TcpEchoConfig {
            bind_addr: "::1",
            ..Default::default()
        })
        .await?;
        let target_port = echo.port();

        let opts = gen_options_v6(port)?;
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        let resolver = ipv6_resolver();

        let session = Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Socks5,
            source: "[::1]:54321".parse()?,
            destination: format!("[::1]:{target_port}").parse()?,
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        let mut stream = handler.connect_stream(&session, resolver).await?;

        for _ in 0..10 {
            stream.write_all(b"hello").await?;
            stream.flush().await?;
            let mut buf = vec![0u8; 5];
            stream.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"world");
        }

        drop(echo);
        Ok(())
    }

    /// TCP ping-pong with dual-stack server (client connects via IPv4).
    ///
    /// Skipped on non-x86_64 Linux — see `test_tuic_ping_pong_tcp`.
    #[tokio::test]
    #[cfg_attr(
        qemu_emulated,
        ignore = "QUIC under qemu-user (cross test) is unreliable"
    )]
    async fn test_tuic_ping_pong_tcp_dual_stack() -> anyhow::Result<()> {
        if std::net::UdpSocket::bind("[::1]:0").is_err() {
            eprintln!("skipping: no IPv6 loopback");
            return Ok(());
        }
        crate::tests::initialize();
        let server = TuicServerProcess::start_dual_stack().await?;
        let port = server.port();

        let echo = TcpEchoServer::start().await?;
        let target_port = echo.port();

        let opts = gen_options(port)?;
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        let resolver = ipv6_resolver();

        let session = Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Socks5,
            source: "127.0.0.1:54321".parse()?,
            destination: format!("127.0.0.1:{target_port}").parse()?,
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        let mut stream = handler.connect_stream(&session, resolver).await?;

        for _ in 0..10 {
            stream.write_all(b"hello").await?;
            stream.flush().await?;
            let mut buf = vec![0u8; 5];
            stream.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"world");
        }

        drop(echo);
        Ok(())
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use std::io::Write as _;

    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const CONTAINER_PORT: u16 = 10002;
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    // Inlined from tuic.toml — UUID/password auth, BBR, h3 ALPN
    const TUIC_SERVER_CONFIG: &str = r#"server = "0.0.0.0:10002"

data_dir = ""
zero_rtt_handshake = false
dual_stack = false

acl = '''
direct 0.0.0.0/0
direct ::/0
'''

[users]
00000000-0000-0000-0000-000000000001 = "passwd"

[tls]
certificate = "/opt/tuic/fullchain.pem"
private_key = "/opt/tuic/privkey.pem"
alpn = ["h3"]

[outbound.default]
type = "direct"
ip_mode = "auto"
"#;

    async fn get_tuic_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(TUIC_SERVER_CONFIG.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_TUIC)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/tuic/config.json"),
                (cert.to_str().unwrap(), "/opt/tuic/fullchain.pem"),
                (key.to_str().unwrap(), "/opt/tuic/privkey.pem"),
            ])
            .env(&["TUIC_FORCE_TOML=1"])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_tuic_bbr() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tuic_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("tuic container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: tuic
    server: {server}
    port: {port}
    uuid: 00000000-0000-0000-0000-000000000001
    password: passwd
    alpn:
      - h3
    congestion-controller: bbr
    disable-sni: true
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "tuic-bbr",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_tuic_bbr_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tuic_runner().await?;
        container.apply_netem(50, 1.0).await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("tuic container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: tuic
    server: {server}
    port: {port}
    uuid: 00000000-0000-0000-0000-000000000001
    password: passwd
    alpn:
      - h3
    congestion-controller: bbr
    disable-sni: true
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "tuic-bbr-netem",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_tuic_cubic() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tuic_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("tuic container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: tuic
    server: {server}
    port: {port}
    uuid: 00000000-0000-0000-0000-000000000001
    password: passwd
    alpn:
      - h3
    congestion-controller: cubic
    disable-sni: true
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "tuic-cubic",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_tuic_new_reno() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tuic_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("tuic container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: tuic
    server: {server}
    port: {port}
    uuid: 00000000-0000-0000-0000-000000000001
    password: passwd
    alpn:
      - h3
    congestion-controller: new_reno
    disable-sni: true
    skip-cert-verify: true
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = CONTAINER_PORT,
        );
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "tuic-new_reno",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await
    }
}
