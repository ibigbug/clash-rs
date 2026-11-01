use erased_serde::Serialize as ErasedSerialize;
use std::{
    collections::HashMap, fmt::Debug, io, net::SocketAddr, str::FromStr, sync::Arc,
};

use async_trait::async_trait;

use compat::UdpSessionWrapper;
use shadowquic::{
    config,
    dns::ResolverManager,
    msgs::socks5::SocksAddr as SQAddr,
    quic::QuicClient,
    shadowquic::{EndClient, outbound::ShadowQuicClient},
};
use tokio::sync::{OnceCell, RwLock};
use tokio_util::sync::PollSender;
mod compat;
use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    session::{Session, SocksAddr},
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};
use crate::app::dispatcher::InstrumentedStream;
// This is ugly, it may be exposed better by shadowquic in the future
type SQConn = shadowquic::squic::SQConn<<EndClient as QuicClient>::C>;
pub type HandlerOptions = config::ShadowQuicClientCfg;

pub struct Handler {
    name: String,
    opts: HandlerOptions,
    ep: OnceCell<ShadowQuicClient>, /* Must be created after session since server
                                     * addr needs to be resolved */
    conn: RwLock<Option<SQConn>>,
}
impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("opts", &self.opts).finish()
    }
}
impl Handler {
    pub fn new(name: String, opts: HandlerOptions) -> Self {
        Self {
            name,
            opts,
            ep: Default::default(),
            conn: Default::default(),
        }
    }

    /// Resolve quic server DNS with clash DNS resolver
    pub async fn prepare_endpoint(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<&ShadowQuicClient> {
        self.ep
            .get_or_try_init(|| async {
                let addr = self.opts.addr.clone();
                let sock_addr = SocksAddr::from_str(&format!("{addr}:443"))
                    .or(SocksAddr::from_str(&addr))
                    .map_err(new_io_error)?;
                tracing::info!("resolving host:{:?}", sock_addr);
                let addr = match sock_addr {
                    SocksAddr::Domain(host, port) => {
                        let addr = resolver
                            .resolve(&host, false)
                            .await
                            .map_err(|x| {
                                io::Error::new(
                                    io::ErrorKind::AddrNotAvailable,
                                    format!(
                                        "failed to resolve shadowquic domain \
                                         name:{x:?}"
                                    ),
                                )
                            })?
                            .ok_or(io::ErrorKind::AddrNotAvailable)?;
                        SocketAddr::new(addr, port)
                    }
                    SocksAddr::Ip(socket_addr) => socket_addr,
                };
                let mut cfg = self.opts.clone();
                cfg.socket_opt.fw_mark = sess.so_mark;
                cfg.socket_opt.bind_interface = sess
                    .iface
                    .as_ref()
                    .map(|iface| config::Interface::Device(iface.name.clone()));
                let mut ep =
                    ShadowQuicClient::new(cfg, Arc::new(ResolverManager::new()));
                ep.config.addr = addr.to_string();
                Ok(ep) as io::Result<ShadowQuicClient>
            })
            .await
    }

    async fn prepare_conn(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<SQConn> {
        let ep = self.prepare_endpoint(sess, resolver).await?;
        if let Some(x) = &*self.conn.read().await
            && x.close_reason().is_none()
        {
            return Ok(x.clone());
        }
        let mut conn = self.conn.write().await;
        let newconn = ep.get_conn().await.map_err(|x| {
            io::Error::other(format!("can't open shadowquic connection due to:{x}"))
        })?;
        conn.replace(newconn.clone());
        Ok(newconn)
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    /// The name of the outbound handler
    fn name(&self) -> &str {
        &self.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.addr)
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType {
        OutboundType::ShadowQuic
    }

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool {
        true
    }

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let conn = self.prepare_conn(sess, resolver).await?;
        let conn = shadowquic::squic::outbound::connect_tcp(
            &conn,
            to_sq_socks_addr(sess.destination.clone()),
        )
        .await
        .map_err(|x| {
            io::Error::other(format!("can't open shadowquic stream due to:{x}"))
        })?;
        let s = InstrumentedStreamWrapper::new(conn);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        let conn = self.prepare_conn(sess, resolver).await?;
        // clash-rs didn't expose udp associate address, so set to unspecified
        // address
        let addr = if sess.source.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = shadowquic::squic::outbound::associate_udp(
            &conn,
            addr.parse::<SocketAddr>().unwrap().into(),
            self.opts.over_stream,
        )
        .await
        .map_err(|x| {
            io::Error::other(format!("can't open shadowquic stream due to:{x}"))
        })?;
        let chain = InstrumentedDatagramWrapper::new(UdpSessionWrapper {
            s: PollSender::new(socket.0),
            r: socket.1,
            src_addr: sess.source.into(),
        });
        chain.append_to_chain(self.name()).await;
        Ok(Box::new(chain))
    }

    /// relay related
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
        m.insert("server".to_owned(), Box::new(self.opts.addr.clone()) as _);
        m.insert(
            "server-name".to_owned(),
            Box::new(self.opts.server_name.clone()) as _,
        );
        m.insert(
            "username".to_owned(),
            Box::new(self.opts.username.clone()) as _,
        );
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        if !self.opts.alpn.is_empty() {
            m.insert("alpn".to_owned(), Box::new(self.opts.alpn.clone()) as _);
        }
        m
    }
}

fn to_sq_socks_addr(x: SocksAddr) -> SQAddr {
    match x {
        SocksAddr::Ip(socket_addr) => SQAddr::from(socket_addr),
        SocksAddr::Domain(host, port) => SQAddr::from_domain(host, port),
    }
}
fn to_clash_socks_addr(x: SQAddr) -> SocksAddr {
    match x.addr {
        shadowquic::msgs::socks5::AddrOrDomain::V4(ip) => {
            SocksAddr::Ip(SocketAddr::new(ip.into(), x.port))
        }
        shadowquic::msgs::socks5::AddrOrDomain::V6(ip) => {
            SocksAddr::Ip(SocketAddr::new(ip.into(), x.port))
        }
        shadowquic::msgs::socks5::AddrOrDomain::Domain(domain) => {
            SocksAddr::Domain(String::from_utf8(domain.contents).unwrap(), x.port)
        }
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::{io::Write, sync::Arc};

    use super::super::utils::test_utils::{
        consts::*, docker_runner::DockerTestRunner,
    };
    use crate::{
        proxy::utils::{
            GLOBAL_DIRECT_CONNECTOR,
            test_utils::{
                Suite,
                docker_runner::{DockerTestRunnerBuilder, alloc_docker_port},
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    use super::*;

    const SHADOWQUIC_SERVER_CONFIG: &str = r#"inbound:
    type: shadowquic
    bind-addr: 0.0.0.0:10002
    users:
      - password: "12345678"
        username: "87654321"
    jls-upstream:
        addr: "echo.free.beeceptor.com:443"
    alpn: ["h3"]
    congestion-control: bbr
    zero-rtt: true
outbound:
    type: direct
log-level: "trace"
"#;

    async fn get_shadowquic_runner(
        host_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SHADOWQUIC_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/shadowquic/config.yaml")])
            .host_port(host_port, 10002)
            .build()
            .await;
        drop(tmp);
        result
    }

    fn gen_options(
        opt_ip: Option<String>,
        host_port: u16,
        over_stream: bool,
    ) -> anyhow::Result<HandlerOptions> {
        let port = if opt_ip.is_some() { 10002 } else { host_port };
        Ok(HandlerOptions {
            addr: SocketAddr::new(
                opt_ip.unwrap_or(LOCAL_ADDR.to_owned()).parse().unwrap(),
                port,
            )
            .to_string(),
            password: "12345678".into(),
            username: "87654321".into(),
            server_name: "echo.free.beeceptor.com".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1400,
            zero_rtt: true,
            over_stream,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_shadowquic_over_datagram() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();

        let container = get_shadowquic_runner(host_port).await?;

        let container_ip = container.container_ip();

        let opts = gen_options(container_ip, host_port, false)?;

        let handler = Arc::new(Handler::new("test-shadowquic".into(), opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
    }
    #[tokio::test]
    async fn test_shadowquic_over_stream() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let container = get_shadowquic_runner(host_port).await?;

        let container_ip = container.container_ip();

        let mut opts = gen_options(container_ip, host_port, true)?;
        opts.over_stream = true;

        let handler = Arc::new(Handler::new("test-shadowquic".into(), opts));
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

    // Inlined from shadowquic.yaml
    const SHADOWQUIC_SERVER_CONFIG: &str = r#"inbound:
    type: shadowquic
    bind-addr: 0.0.0.0:10002
    users:
      - password: "12345678"
        username: "87654321"
    jls-upstream:
        addr: "echo.free.beeceptor.com:443"
    alpn: ["h3"]
    congestion-control: bbr
    zero-rtt: true
outbound:
    type: direct
log-level: "info"
"#;

    // Note: over-stream is a client-side setting; the server auto-detects the
    // mode, so we use the same server config as for plain shadowquic.
    const SHADOWQUIC_OVER_STREAM_SERVER_CONFIG: &str = r#"inbound:
    type: shadowquic
    bind-addr: 0.0.0.0:10002
    users:
      - password: "12345678"
        username: "87654321"
    jls-upstream:
        addr: "echo.free.beeceptor.com:443"
    alpn: ["h3"]
    congestion-control: bbr
    zero-rtt: true
outbound:
    type: direct
log-level: "info"
"#;

    async fn get_shadowquic_runner() -> anyhow::Result<DockerTestRunner> {
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SHADOWQUIC_SERVER_CONFIG.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/shadowquic/config.yaml")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_shadowquic_plain() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_shadowquic_runner().await?;
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
mode: rule
log-level: error
proxies:
  - name: proxy
    type: shadowquic
    server: {server}
    port: {port}
    password: "12345678"
    username: "87654321"
    server-name: echo.free.beeceptor.com
    alpn:
      - h3
    zero-rtt: true
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
                    "shadowquic-plain",
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
    async fn e2e_throughput_shadowquic_plain_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_shadowquic_runner().await?;
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
mode: rule
log-level: error
proxies:
  - name: proxy
    type: shadowquic
    server: {server}
    port: {port}
    password: "12345678"
    username: "87654321"
    server-name: echo.free.beeceptor.com
    alpn:
      - h3
    zero-rtt: true
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
                    "shadowquic-plain-netem",
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

    async fn get_shadowquic_over_stream_runner() -> anyhow::Result<DockerTestRunner>
    {
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SHADOWQUIC_OVER_STREAM_SERVER_CONFIG.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SHADOWQUIC)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/shadowquic/config.yaml")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_shadowquic_over_stream() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_shadowquic_over_stream_runner().await?;
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
mode: rule
log-level: error
proxies:
  - name: proxy
    type: shadowquic
    server: {server}
    port: {port}
    password: "12345678"
    username: "87654321"
    server-name: echo.free.beeceptor.com
    alpn:
      - h3
    zero-rtt: true
    over-stream: true
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
                    "shadowquic-over-stream",
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

impl<S: tokio::io::AsyncWrite + Unpin + Send, R: tokio::io::AsyncRead + Unpin + Send>
    crate::proxy::ProxyStream for shadowquic::squic::inbound::Unsplit<S, R>
{
}
