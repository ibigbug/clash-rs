use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::utils,
    impl_default_connector,
    session::Session,
};

use self::datagram::OutboundDatagramTrojan;

use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, PlainProxyAPIResponse,
    transport::TransportLayer,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};

mod datagram;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
    // might support shadow-tls?
    pub tls: Option<TransportLayer>,
    pub transport: Option<TransportLayer>,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trojan")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    /// TCP: 0x01,
    /// UDP: 0x03,
    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls_client) = self.opts.tls.as_ref() {
            tls_client.wrap(s).await?
        } else {
            s
        };

        let mut s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.wrap(s).await?
        } else {
            s
        };

        let mut buf = BytesMut::new();
        let password = Sha224::digest(self.opts.password.as_bytes());
        let password = utils::encode_hex(&password[..]);
        buf.put_slice(password.as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_u8(if udp { 0x03 } else { 0x01 });
        sess.destination.write_buf(&mut buf);
        buf.put_slice(b"\r\n");
        s.write_all(&buf).await?;

        Ok(s)
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Trojan
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        let dialer = self.connector.read().await;

        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }

        self.connect_datagram_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::All
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedStream> {
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let s = self.inner_proxy_stream(stream, sess, false).await?;
        let chained = InstrumentedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let stream = self.inner_proxy_stream(stream, sess, true).await?;

        let d = OutboundDatagramTrojan::new(stream, sess.destination.clone());

        let chained = InstrumentedDatagramWrapper::new(d);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
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
        m.insert(
            "password".to_owned(),
            Box::new(self.opts.password.clone()) as _,
        );
        if self.opts.tls.is_some() {
            m.insert("tls".to_owned(), Box::new(true) as _);
        }
        m
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::{collections::HashMap, io::Write};

    use super::*;
    use crate::{
        proxy::{
            transport::{self, TransportLayer},
            utils::test_utils::{
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

    const TROJAN_WS_SERVER_CONFIG: &str = r#"{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 10002,
    "disable_http_check": true,
    "password": [
        "example"
    ],
    "websocket": {
        "enabled": true,
        "path": "/",
        "host": "example.org"
    },
    "ssl": {
        "verify": true,
        "cert": "/fullchain.pem",
        "key": "/privkey.pem",
        "sni": "example.org"
    }
}"#;

    const TROJAN_GRPC_SERVER_CONFIG: &str = r#"{
    "inbounds": [
        {
            "port": 10002,
            "listen": "0.0.0.0",
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "example",
                        "email": "grpc@example.com"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
                            "keyFile": "/etc/ssl/v2ray/privkey.pem"
                        }
                    ]
                },
                "grpcSettings": {
                    "serviceName": "example"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ],
    "log": {
        "loglevel": "debug"
    }
}"#;

    async fn get_ws_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let trojan_cert = test_config_dir.join("certs/example.org.pem");
        let trojan_key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(TROJAN_WS_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_TROJAN_GO)
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/trojan-go/config.json"),
                (trojan_cert.to_str().unwrap(), "/fullchain.pem"),
                (trojan_key.to_str().unwrap(), "/privkey.pem"),
            ])
            .host_port(host_port, 10002)
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn test_trojan_ws() -> anyhow::Result<()> {
        let span = tracing::info_span!("test_trojan_ws");
        let _enter = span.enter();
        let host_port = alloc_docker_port();
        let transport = transport::WsClient::new(
            "".to_owned(),
            10002,
            "/".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );
        let tls = transport::TlsClient::new(
            true,
            "example.org".to_owned(),
            None,
            None,
            None,
            None,
        )
        .expect("failed to create TLS client");

        let container = get_ws_runner(host_port).await?;

        let opts = HandlerOptions {
            name: "test-trojan-ws".to_owned(),
            common_opts: Default::default(),
            server: container.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            tls: Some(TransportLayer::Tls(tls)),
            transport: Some(TransportLayer::Ws(transport)),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        // ignore the udp test
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
    }

    async fn get_grpc_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(TROJAN_GRPC_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_XRAY)
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .host_port(host_port, 10002)
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn test_trojan_grpc() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let transport = transport::GrpcClient::new(
            "example.org".to_owned(),
            "/example"
                .to_owned()
                .try_into()
                .expect("invalid grpc service name"),
        );
        let tls = transport::TlsClient::new(
            true,
            "example.org".to_owned(),
            Some(vec!["http/1.1".to_owned(), "h2".to_owned()]),
            None,
            None,
            None,
        )
        .expect("failed to create TLS client");

        let runner = get_grpc_runner(host_port).await?;

        let opts = HandlerOptions {
            name: "test-trojan-grpc".to_owned(),
            common_opts: Default::default(),
            server: runner.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            tls: Some(TransportLayer::Tls(tls)),
            transport: Some(TransportLayer::Grpc(transport)),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, runner, Suite::all()).await
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
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

    fn base_config(server: &str, port: u16, socks_port: u16, extra: &str) -> String {
        let mmdb = config_helper::test_config_base_dir()
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: rule
log-level: error
proxies:
  - name: proxy
    type: trojan
    server: {server}
    port: {port}
    password: example
    skip-cert-verify: true
    udp: false
{extra}
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = port,
            extra = extra,
        )
    }

    const TROJAN_WS_SERVER_CONFIG: &str = r#"{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 10002,
    "disable_http_check": true,
    "password": ["example"],
    "websocket": {"enabled": true, "path": "/", "host": "example.org"},
    "ssl": {"verify": true, "cert": "/fullchain.pem", "key": "/privkey.pem", "sni": "example.org"}
}"#;

    const TROJAN_GRPC_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "trojan",
        "settings": {"clients": [{"password": "example", "email": "grpc@example.com"}]},
        "streamSettings": {"network": "grpc", "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]},
            "grpcSettings": {"serviceName": "example"}}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    const TROJAN_TCP_SERVER_CONFIG: &str = r#"{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 10002,
    "disable_http_check": true,
    "password": ["example"],
    "ssl": {
        "verify": true,
        "cert": "/fullchain.pem",
        "key": "/privkey.pem",
        "sni": "example.org"
    }
}"#;

    async fn get_tcp_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(TROJAN_TCP_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_TROJAN_GO)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/trojan-go/config.json"),
                (cert.to_str().unwrap(), "/fullchain.pem"),
                (key.to_str().unwrap(), "/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    async fn get_ws_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(TROJAN_WS_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_TROJAN_GO)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/trojan-go/config.json"),
                (cert.to_str().unwrap(), "/fullchain.pem"),
                (key.to_str().unwrap(), "/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    async fn get_grpc_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(TROJAN_GRPC_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_XRAY)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/xray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn e2e_throughput_trojan_tcp() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tcp_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "trojan-tcp",
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
    async fn e2e_throughput_trojan_tcp_netem() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tcp_runner().await?;
        container.apply_netem(50, 1.0).await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "trojan-tcp-netem",
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
    async fn e2e_throughput_trojan_ws() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true
    network: ws
    ws-opts:
      path: /
      headers:
        Host: example.org"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "trojan-ws",
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
    async fn e2e_throughput_trojan_grpc() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_grpc_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true
    network: grpc
    grpc-opts:
      grpc-service-name: example"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "trojan-grpc",
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
