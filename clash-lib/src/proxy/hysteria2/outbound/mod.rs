use super::{
    codec::{self, Fragments, Hy2TcpCodec},
    congestion::{Burtal, DynController},
    datagram::{HysteriaDatagramOutbound, UdpSession},
    stream::HystStream,
};
use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::tls::{DefaultTlsVerifier, build_tls_client_config},
    proxy::{
        ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
        PlainProxyAPIResponse, converters::hysteria2::PortGenerator,
        datagram::UdpPacket, utils::new_udp_socket,
    },
    session::{Session, SocksAddr},
};
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use erased_serde::Serialize as ErasedSerialize;
use futures::{SinkExt, StreamExt};
use h3::client::SendRequest;
use h3_quinn::OpenStreams;
use quinn::{
    ClientConfig, Connection, TokioRuntime, crypto::rustls::QuicClientConfig,
};
use quinn_proto::TransportConfig;
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    num::ParseIntError,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock, atomic::AtomicU32},
};
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

#[derive(Clone)]
pub struct SalamanderObfs {
    pub key: Vec<u8>,
}

#[derive(Clone)]
pub enum Obfs {
    Salamander(SalamanderObfs),
}

#[derive(Clone)]
pub struct HystOption {
    pub name: String,
    pub addr: SocksAddr,
    pub ports: Option<PortGenerator>,
    pub sni: Option<String>,
    pub passwd: String,
    pub obfs: Option<Obfs>,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    #[allow(dead_code)]
    pub up_down: Option<(u64, u64)>,
    pub fingerprint: Option<String>,
    pub ca: Option<PathBuf>,
    pub udp_mtu: Option<u32>,
    pub disable_mtu_discovery: bool,
    #[allow(dead_code)]
    pub ca_str: Option<String>,
    #[allow(dead_code)]
    pub cwnd: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    pub tls_key: Option<String>,
}

enum CcRx {
    Auto,
    Fixed(#[allow(dead_code)] u64),
}

impl FromStr for CcRx {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") {
            Ok(Self::Auto)
        } else {
            let n = s.parse::<u64>()?;
            Ok(Self::Fixed(n))
        }
    }
}

pub struct Handler {
    opts: HystOption,
    ep_config: quinn::EndpointConfig,
    client_config: quinn::ClientConfig,
    conn: Mutex<Option<Arc<HysteriaConnection>>>,
    next_session_id: AtomicU32,
    // a send request guard to keep the connection alive
    guard: Mutex<Option<SendRequest<OpenStreams, Bytes>>>,
    // support udp is decided by server
    support_udp: RwLock<bool>,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HystClient").finish()
    }
}

impl Handler {
    const DEFAULT_MAX_IDLE_TIMEOUT: std::time::Duration =
        std::time::Duration::from_secs(300);

    pub fn new(opts: HystOption) -> std::io::Result<Self> {
        if opts.ca.is_some() {
            warn!("hysteria2 does not support ca yet");
        }
        let verify = Arc::new(DefaultTlsVerifier::new(
            opts.fingerprint.clone(),
            opts.skip_cert_verify,
        ));
        let mut tls_config = build_tls_client_config(
            verify,
            opts.tls_cert.as_deref(),
            opts.tls_key.as_deref(),
        )
        .map_err(|e| std::io::Error::new(e.kind(), format!("hysteria2 TLS: {e}")))?;

        // should set alpn_protocol `h3` default
        tls_config.alpn_protocols = if opts.alpn.is_empty() {
            vec![b"h3".to_vec()]
        } else {
            opts.alpn.iter().map(|x| x.as_bytes().to_vec()).collect()
        };

        let mut transport = TransportConfig::default();
        if opts.disable_mtu_discovery {
            tracing::debug!("disable mtu discovery");
            transport.mtu_discovery_config(None);
        }
        // TODO
        // transport.congestion_controller_factory(DynCongestion);
        transport.max_idle_timeout(Some(
            Self::DEFAULT_MAX_IDLE_TIMEOUT.try_into().unwrap(),
        ));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));

        let quic_config: QuicClientConfig = tls_config.try_into().unwrap();
        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(Arc::new(transport));
        let ep_config = quinn::EndpointConfig::default();

        Ok(Self {
            opts,
            ep_config,
            client_config,
            next_session_id: AtomicU32::new(0),
            conn: Mutex::new(None),
            guard: Mutex::new(None),
            support_udp: RwLock::new(true),
        })
    }

    // connect and auth
    async fn new_authed_connection_inner(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> anyhow::Result<(Connection, SendRequest<OpenStreams, Bytes>)> {
        tracing::trace!(
            "hysteria2 new_authed_connection_inner: starting connection to {:?}",
            self.opts.addr
        );
        // Everytime we enstablish a new session, we should lookup the server
        // address. maybe it changed since it use ddns
        let server_socket_addr = match self.opts.addr.clone() {
            SocksAddr::Ip(ip) => ip,
            SocksAddr::Domain(d, port) => {
                let ip = resolver
                    .resolve(d.as_str(), true)
                    .await?
                    .ok_or_else(|| anyhow!("resolve domain {} failed", d))?;
                SocketAddr::new(ip, port)
            }
        };

        // Here maybe we should use a AsyncUdpSocket which implement salamander
        // obfs and port hopping
        let create_socket = || async {
            new_udp_socket(
                None,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
                Some(server_socket_addr),
            )
            .await
        };

        let mut ep = if let Some(obfs) = self.opts.obfs.as_ref() {
            match obfs {
                Obfs::Salamander(salamander_obfs) => {
                    let socket = create_socket().await?;
                    let obfs = super::salamander::Salamander::new(
                        socket.into_std()?,
                        salamander_obfs.key.to_vec(),
                    )?;

                    quinn::Endpoint::new_with_abstract_socket(
                        self.ep_config.clone(),
                        None,
                        Arc::new(obfs),
                        Arc::new(TokioRuntime),
                    )?
                }
            }
        } else if let Some(port_gen) = self.opts.ports.as_ref() {
            let udp_hop = super::udp_hop::UdpHop::new(
                server_socket_addr.port(),
                port_gen.clone(),
                None,
            )?;
            quinn::Endpoint::new_with_abstract_socket(
                self.ep_config.clone(),
                None,
                Arc::new(udp_hop),
                Arc::new(TokioRuntime),
            )?
        } else {
            let socket = create_socket().await?;

            quinn::Endpoint::new(
                self.ep_config.clone(),
                None,
                socket.into_std()?,
                Arc::new(TokioRuntime),
            )?
        };

        ep.set_default_client_config(self.client_config.clone());

        tracing::trace!("hysteria2 connecting to server: {:?}", server_socket_addr);
        let session = ep
            .connect(server_socket_addr, self.opts.sni.as_deref().unwrap_or(""))?
            .await?;
        tracing::trace!("hysteria2 QUIC connection established");
        let (guard, _rx, udp) = Self::auth(&session, &self.opts.passwd).await?;
        tracing::trace!("hysteria2 authentication successful, udp={}", udp);
        *self.support_udp.write().unwrap() = udp;
        // todo set congestion controller according to cc_rx

        match session
            .congestion_state()
            .into_any()
            .downcast::<DynController>()
        {
            Ok(any) => {
                any.set_controller(Box::new(Burtal::new(0, session.clone())));
            }
            Err(_) => {
                trace!("congestion controller is not set");
            }
        }

        Ok((session, guard))
    }

    async fn auth(
        conn: &quinn::Connection,
        passwd: &str,
    ) -> anyhow::Result<(SendRequest<OpenStreams, Bytes>, CcRx, bool)> {
        let h3_conn = h3_quinn::Connection::new(conn.clone());

        let (_, mut sender) =
            h3::client::builder().build::<_, _, Bytes>(h3_conn).await?;

        let req = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", passwd)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", codec::padding(64..=512))
            .body(())
            .unwrap();
        let mut r = sender.send_request(req).await?;
        r.finish().await?;

        let r = r.recv_response().await?;

        const HYSTERIA_STATUS_OK: u16 = 233;
        if r.status() != HYSTERIA_STATUS_OK {
            return Err(anyhow!("auth failed: response status code {}", r.status()));
        }

        // MUST have Hysteria-CC-RX and Hysteria-UDP headers according to
        // hysteria2 document
        let cc_rx = r
            .headers()
            .get("Hysteria-CC-RX")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-CC-RX header"))?
            .to_str()?
            .parse()?;

        let support_udp = r
            .headers()
            .get("Hysteria-UDP")
            .ok_or_else(|| anyhow!("auth failed: missing Hysteria-UDP header"))?
            .to_str()?
            .parse()?;

        Ok((sender, cc_rx, support_udp))
    }

    pub async fn new_authed_connection(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Arc<HysteriaConnection>> {
        let mut quinn_conn_lock = self.conn.lock().await;

        match (*quinn_conn_lock).as_ref().filter(|s| {
            match s.conn.close_reason() {
                // rust should have inspect method on Option and Result!
                Some(reason) => {
                    tracing::debug!("old connection closed: {:?}", reason);
                    false
                }
                None => true,
            }
        }) {
            Some(s) => Ok(s.clone()),
            None => {
                let (session, guard) = self
                    .new_authed_connection_inner(sess, resolver)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "connect to {} failed: {}",
                            self.opts.addr, e
                        ))
                    })?;
                let session = Arc::new(session);
                let hyst_conn = HysteriaConnection::new_with_task_loop(
                    session,
                    self.opts.udp_mtu,
                );
                *quinn_conn_lock = Some(hyst_conn.clone());
                *self.guard.lock().await = Some(guard);
                Ok(hyst_conn)
            }
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        self.opts.addr.domain()
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Hysteria2
    }

    async fn support_udp(&self) -> bool {
        *self.support_udp.read().unwrap()
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedStream> {
        let authed_conn = self.new_authed_connection(sess, resolver.clone()).await?;
        let hy_stream = authed_conn.connect_tcp(sess).await?;
        Ok(Box::new(InstrumentedStreamWrapper::new(
            Box::new(hy_stream) as crate::proxy::AnyStream,
        )))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        let authed_conn = self.new_authed_connection(sess, resolver.clone()).await?;
        let next_session_id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let hy_datagram = authed_conn.connect_udp(sess, next_session_id).await;
        let s = InstrumentedDatagramWrapper::new(hy_datagram);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait::async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        let (server, port) = match &self.opts.addr {
            crate::session::SocksAddr::Ip(addr) => {
                (addr.ip().to_string(), addr.port())
            }
            crate::session::SocksAddr::Domain(host, port) => (host.clone(), *port),
        };
        m.insert("server".to_owned(), Box::new(server) as _);
        m.insert("port".to_owned(), Box::new(port) as _);
        if let Some(sni) = self.opts.sni.as_ref() {
            m.insert("sni".to_owned(), Box::new(sni.clone()) as _);
        }
        if self.opts.skip_cert_verify {
            m.insert("skip-cert-verify".to_owned(), Box::new(true) as _);
        }
        if let Some(obfs) = self.opts.obfs.as_ref() {
            m.insert(
                "obfs".to_owned(),
                Box::new(
                    match obfs {
                        Obfs::Salamander(_) => "salamander",
                    }
                    .to_owned(),
                ) as _,
            );
        }
        if !self.opts.alpn.is_empty() {
            m.insert("alpn".to_owned(), Box::new(self.opts.alpn.clone()) as _);
        }
        m
    }
}

pub struct HysteriaConnection {
    pub conn: Arc<quinn::Connection>,
    pub udp_sessions: Arc<tokio::sync::Mutex<HashMap<u32, UdpSession>>>,

    // config
    pub udp_mtu: Option<usize>,
}

impl HysteriaConnection {
    pub fn new_with_task_loop(
        conn: Arc<quinn::Connection>,
        udp_mtu: Option<u32>,
    ) -> Arc<Self> {
        let s = Arc::new(Self {
            conn,
            udp_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            udp_mtu: udp_mtu.map(|x| x as usize),
        });
        tokio::spawn(Self::spawn_tasks(s.clone()));

        s
    }

    async fn spawn_tasks(self: Arc<Self>) {
        tracing::trace!("hysteria2 spawn_tasks: starting datagram receive loop");
        let err = loop {
            tokio::select! {
                res = self.conn.read_datagram() => {
                    match res {
                        Ok(pkt) => {
                            tracing::trace!("hysteria2 received datagram: {} bytes", pkt.len());
                            self.clone().recv_packet(pkt).await
                        },
                        Err(e) => {
                            tracing::error!("hysteria2 read datagram error: {}", e);
                            break e;
                        }
                    }
                }
            }
        };
        tracing::warn!("hysteria2 connection error: {:?}", err);
    }

    pub async fn connect_tcp(&self, sess: &Session) -> std::io::Result<HystStream> {
        let (mut tx, mut rx) = self.conn.open_bi().await?;
        tokio_util::codec::FramedWrite::new(&mut tx, Hy2TcpCodec)
            .send(&sess.destination)
            .await?;

        match tokio_util::codec::FramedRead::new(&mut rx, Hy2TcpCodec)
            .next()
            .await
        {
            Some(Ok(resp)) => {
                if resp.status != 0x00 {
                    return Err(std::io::Error::other(format!(
                        "server response error, msg: {:?}",
                        resp.msg
                    )));
                } else {
                    debug!(
                        "hysteria2 tcp request success: status: {}, msg: {:?}",
                        resp.status, resp.msg
                    );
                }
            }
            _ => {
                return Err(std::io::Error::other(
                    "not receive hysteria2 response from server",
                ));
            }
        };

        Ok(HystStream::new(tx, rx))
    }

    pub async fn connect_udp(
        self: Arc<Self>,
        sess: &Session,
        session_id: u32,
    ) -> HysteriaDatagramOutbound {
        tracing::trace!(
            "hysteria connect udp, sess: {:?}, session_id: {}",
            sess,
            session_id
        );
        HysteriaDatagramOutbound::new(
            session_id,
            self.clone(),
            sess.destination.clone(),
        )
        .await
    }

    pub fn send_packet(
        &self,
        pkt: Bytes,
        addr: SocksAddr,
        session_id: u32,
        pkt_id: u16,
    ) -> std::io::Result<()> {
        tracing::trace!(
            "hysteria2 send_packet: session_id={}, pkt_id={}, addr={:?}, \
             data_len={}",
            session_id,
            pkt_id,
            addr,
            pkt.len()
        );

        let max_frag_size = match self.udp_mtu.or(self.conn.max_datagram_size()) {
            Some(x) => {
                tracing::trace!("hysteria2 max_frag_size={}", x);
                x
            }
            None => {
                tracing::error!("hysteria2 udp mtu not set");
                return Err(std::io::Error::other(
                    "hysteria2 udp mtu not set, please check your \
                     disable_mtu_discovery and udp_mtu option",
                ));
            }
        };
        let fragments = Fragments::new(session_id, pkt_id, addr, max_frag_size, pkt);
        let mut frag_count = 0;
        for frag in fragments {
            frag_count += 1;
            tracing::trace!(
                "hysteria2 sending fragment #{} for session_id={}",
                frag_count,
                session_id
            );
            self.conn
                .send_datagram(frag)
                .map_err(std::io::Error::other)?;
        }
        tracing::trace!(
            "hysteria2 sent {} fragments for session_id={}",
            frag_count,
            session_id
        );
        Ok(())
    }

    pub async fn recv_packet(self: Arc<Self>, pkt: Bytes) {
        tracing::trace!("hysteria2 recv_packet: {} bytes", pkt.len());
        let mut buf: BytesMut = pkt.into();
        let pkt = codec::HysUdpPacket::decode(&mut buf).unwrap();
        let session_id = pkt.session_id;
        let mut udp_sessions = self.udp_sessions.lock().await;
        match udp_sessions.get_mut(&session_id) {
            Some(session) => {
                tracing::trace!(
                    "hysteria2 found session {}, feeding packet",
                    session_id
                );
                if let Some(pkt) = session.feed(pkt) {
                    tracing::trace!(
                        "hysteria2 complete packet received for session {}: {} \
                         bytes to {:?}",
                        session_id,
                        pkt.data.len(),
                        session.local_addr
                    );
                    let _ = session
                        .incoming
                        .send(UdpPacket {
                            data: pkt.data,
                            src_addr: pkt.addr,
                            dst_addr: session.local_addr.clone(),
                            inbound_user: None,
                        })
                        .await;
                } else {
                    tracing::trace!(
                        "hysteria2 packet fragment buffered for session {}",
                        session_id
                    );
                }
            }
            _ => {
                tracing::warn!("hysteria2 udp session not found: {}", session_id);
            }
        }
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::{
        io::Write,
        net::{IpAddr, Ipv4Addr},
    };

    use crate::{
        proxy::utils::{
            GLOBAL_DIRECT_CONNECTOR,
            test_utils::{
                Suite,
                config_helper::test_config_base_dir,
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    use super::*;

    const HYSTERIA_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls":{
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "obfs": {
        "type": "salamander",
        "salamander": {
            "password": "beauty will save the world"
        }
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    async fn get_hysteria_runner(
        host_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(HYSTERIA_SERVER_CONFIG.as_bytes())?;
        let (_, path) = tmp.keep()?;

        DockerTestRunnerBuilder::new()
            .image(IMAGE_HYSTERIA)
            .mounts(&[
                (path.to_str().unwrap(), "/config.json"),
                (cert.to_str().unwrap(), "/home/ubuntu/my.crt"),
                (key.to_str().unwrap(), "/home/ubuntu/my.key"),
            ])
            .cmd(&["server", "-c", "/config.json"])
            .host_port(host_port, 10002)
            .build()
            .await
    }

    #[tokio::test]
    async fn test_hysteria() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();

        let container = get_hysteria_runner(host_port).await?;

        let container_ip =
            container.container_ip().unwrap_or("127.0.0.1".to_owned());

        let ip = IpAddr::from_str(&container_ip)
            .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let port = 10002;

        let obfs = Some(Obfs::Salamander(SalamanderObfs {
            key: "beauty will save the world".to_owned().into(),
        }));

        let ports_gen = Some(
            PortGenerator::new(port)
                .parse_ports_str("")
                .map_err(|_| crate::Error::InvalidConfig("".into()))?,
        );

        let opts = HystOption {
            name: "test-hysteria".to_owned(),
            sni: "example.org".to_owned().into(),
            addr: (ip, port).into(),
            alpn: vec![],
            ca: None,
            fingerprint: None,
            skip_cert_verify: true,
            passwd: "passwd".to_owned(),
            ports: ports_gen,
            obfs,
            up_down: Some((100, 100)),
            ca_str: None,
            cwnd: None,
            udp_mtu: None,
            disable_mtu_discovery: false,
            tls_cert: None,
            tls_key: None,
        };

        let handler = Arc::new(
            Handler::new(opts).expect("failed to create hysteria2 handler"),
        );
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
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

    // Plain hysteria2 server — no obfs, auth password "passwd"
    const HYSTERIA2_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls": {
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    // Hysteria2 server with obfs-salamander, auth password "passwd"
    const HYSTERIA_SALAMANDER_SERVER_CONFIG: &str = r#"{
    "listen": ":10002",
    "tls": {
        "cert": "/home/ubuntu/my.crt",
        "key": "/home/ubuntu/my.key"
    },
    "obfs": {
        "type": "salamander",
        "salamander": {
            "password": "salamander-password"
        }
    },
    "up_mbps": 100,
    "down_mbps": 100,
    "auth": {
        "type": "password",
        "password": "passwd"
    }
}"#;

    async fn build_hysteria2_runner(
        server_config: &str,
    ) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(server_config.as_bytes())?;
        let (_, path) = tmp.keep()?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_HYSTERIA)
            .cmd(&["server", "-c", "/config.json"])
            .no_port()
            .mounts(&[
                (path.to_str().unwrap(), "/config.json"),
                (cert.to_str().unwrap(), "/home/ubuntu/my.crt"),
                (key.to_str().unwrap(), "/home/ubuntu/my.key"),
            ])
            .build()
            .await?;
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_hysteria2_plain() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = build_hysteria2_runner(HYSTERIA2_SERVER_CONFIG).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
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
    type: hysteria2
    server: {server}
    port: {port}
    password: passwd
    sni: example.org
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
                    "hysteria2-plain",
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
    async fn e2e_throughput_hysteria2_plain_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = build_hysteria2_runner(HYSTERIA2_SERVER_CONFIG).await?;
        container.apply_netem(50, 1.0).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
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
    type: hysteria2
    server: {server}
    port: {port}
    password: passwd
    sni: example.org
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
                    "hysteria2-plain-netem",
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
    async fn e2e_throughput_hysteria2_salamander() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container =
            build_hysteria2_runner(HYSTERIA_SALAMANDER_SERVER_CONFIG).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
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
    type: hysteria2
    server: {server}
    port: {port}
    password: passwd
    obfs: salamander
    obfs-password: salamander-password
    sni: example.org
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
                    "hysteria2-salamander",
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
