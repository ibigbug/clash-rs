use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, PlainProxyAPIResponse,
    transport::TransportLayer,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};
use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    session::Session,
};
use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};
use tracing::debug;
use vmess_impl::OutboundDatagramVmess;

mod vmess_impl;

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub udp: bool,
    pub transport: Option<TransportLayer>,
    // maybe shadow-tls?
    pub tls: Option<TransportLayer>,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vmess")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    async fn inner_proxy_stream<'a>(
        &'a self,
        s: AnyStream,
        sess: &'a Session,
        udp: bool,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls) = self.opts.tls.as_ref() {
            tls.wrap(s).await?
        } else {
            s
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.wrap(s).await?
        } else {
            s
        };

        let vmess_builder = vmess_impl::Builder::new(&vmess_impl::VmessOption {
            uuid: self.opts.uuid.to_owned(),
            alter_id: self.opts.alter_id,
            security: self.opts.security.to_owned(),
            udp,
            dst: sess.destination.clone(),
        })?;

        vmess_builder.proxy_stream(s).await
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

    /// The protocol of the outbound handler
    fn proto(&self) -> OutboundType {
        OutboundType::Vmess
    }

    /// whether the outbound handler support UDP
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

        let d = OutboundDatagramVmess::new(stream, sess.destination.clone());

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
        m.insert("uuid".to_owned(), Box::new(self.opts.uuid.clone()) as _);
        m.insert("alter-id".to_owned(), Box::new(self.opts.alter_id) as _);
        m.insert(
            "cipher".to_owned(),
            Box::new(self.opts.security.clone()) as _,
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
            transport::{GrpcClient, H2Client, TlsClient, TransportLayer, WsClient},
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

    const VMESS_WS_SERVER_CONFIG: &str = r#"{
    "inbounds": [
        {
            "port": 10002,
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
                            "keyFile": "/etc/ssl/v2ray/privkey.pem"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}"#;

    const VMESS_GRPC_SERVER_CONFIG: &str = r#"{
    "inbounds": [
        {
            "port": 10002,
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811"
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
                    "serviceName": "example!"
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

    const VMESS_HTTP2_SERVER_CONFIG: &str = r#"{
    "inbounds": [
        {
            "port": 10002,
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811"
                    }
                ]
            },
            "streamSettings": {
                "network": "http",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/ssl/v2ray/fullchain.pem",
                            "keyFile": "/etc/ssl/v2ray/privkey.pem"
                        }
                    ]
                },
                "httpSettings": {
                    "host": [
                        "example.org"
                    ],
                    "path": "/test"
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

    fn tls_client(alpn: Option<Vec<String>>) -> Option<TransportLayer> {
        Some(TransportLayer::Tls(
            TlsClient::new(true, "example.org".to_owned(), alpn, None, None, None)
                .expect("failed to create TLS client"),
        ))
    }

    async fn get_ws_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(VMESS_WS_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
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
    async fn test_vmess_ws() -> anyhow::Result<()> {
        initialize();
        let span = tracing::info_span!("test_vmess_ws");
        let _enter = span.enter();
        let host_port = alloc_docker_port();
        let ws_client = WsClient::new(
            "".to_owned(),
            10002,
            "".to_owned(),
            [("Host".to_owned(), "example.org".to_owned())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
            None,
            0,
            "".to_owned(),
        );

        let runner = get_ws_runner(host_port).await?;

        let opts = HandlerOptions {
            name: "test-vmess-ws".into(),
            common_opts: Default::default(),
            server: runner.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 10002,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            security: "auto".into(),
            udp: true,
            tls: tls_client(None),
            transport: Some(TransportLayer::Ws(ws_client)),
        };
        let handler = Arc::new(Handler::new(opts));

        run_test_suites_and_cleanup(handler, runner, Suite::all()).await
    }

    async fn get_grpc_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(VMESS_GRPC_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
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
    async fn test_vmess_grpc() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let grpc_client = GrpcClient::new(
            "example.org".to_owned(),
            "/example!".to_owned().try_into()?,
        );
        let container = get_grpc_runner(host_port).await?;
        let opts = HandlerOptions {
            name: "test-vmess-grpc".into(),
            common_opts: Default::default(),
            server: container.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 10002,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            security: "auto".into(),
            udp: true,
            tls: tls_client(None),
            transport: Some(TransportLayer::Grpc(grpc_client)),
        };
        let handler = Arc::new(Handler::new(opts));
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
    }

    async fn get_h2_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(VMESS_HTTP2_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
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
    async fn test_vmess_h2() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let h2_client = H2Client::new(
            vec!["example.org".into()],
            std::collections::HashMap::new(),
            http::Method::POST,
            "/test".to_owned().try_into()?,
        );
        let container = get_h2_runner(host_port).await?;
        let opts = HandlerOptions {
            name: "test-vmess-h2".into(),
            common_opts: Default::default(),
            server: container.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 10002,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            security: "auto".into(),
            udp: false,
            tls: tls_client(Some(vec!["h2".to_string()])),
            transport: Some(TransportLayer::H2(h2_client)),
        };
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;
        run_test_suites_and_cleanup(handler, container, Suite::all()).await
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
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
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
    type: vmess
    server: {server}
    port: {port}
    uuid: {uuid}
    alterId: 0
    cipher: auto
    udp: false
{extra}
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = port,
            uuid = UUID,
            extra = extra,
        )
    }

    const VMESS_WS_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "vmess",
        "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]},
        "streamSettings": {"network": "ws", "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]}}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    const VMESS_GRPC_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "vmess",
        "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]},
        "streamSettings": {"network": "grpc", "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]},
            "grpcSettings": {"serviceName": "example!"}}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    const VMESS_H2_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "vmess",
        "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]},
        "streamSettings": {"network": "http", "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]},
            "httpSettings": {"host": ["example.org"], "path": "/test"}}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    const VMESS_TCP_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "vmess",
        "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0}]}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    const VMESS_TCP_TLS_SERVER_CONFIG: &str = r#"{
    "inbounds": [{"port": 10002, "listen": "0.0.0.0", "protocol": "vmess",
        "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0}]},
        "streamSettings": {"network": "tcp", "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/etc/ssl/v2ray/fullchain.pem", "keyFile": "/etc/ssl/v2ray/privkey.pem"}]}}}],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_tcp_runner() -> anyhow::Result<DockerTestRunner> {
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(VMESS_TCP_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/v2ray/config.json")])
            .build()
            .await;
        drop(tmp);
        result
    }

    async fn get_tcp_tls_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(VMESS_TCP_TLS_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
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
        tmp.write_all(VMESS_WS_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
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
        tmp.write_all(VMESS_GRPC_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    async fn get_h2_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");
        let mut tmp = tempfile::NamedTempFile::new()?;
        use std::io::Write as _;
        tmp.write_all(VMESS_H2_SERVER_CONFIG.as_bytes())?;
        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_VMESS)
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/v2ray/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await;
        drop(tmp);
        result
    }

    #[tokio::test]
    async fn e2e_throughput_vmess_tcp() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tcp_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let config = base_config(&server, CONTAINER_PORT, socks_port, "");
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vmess-tcp",
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
    async fn e2e_throughput_vmess_tcp_tls() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_tcp_tls_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true
    skip-cert-verify: true"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vmess-tcp-tls",
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
    async fn e2e_throughput_vmess_ws() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_ws_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true
    skip-cert-verify: true
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
                    "vmess-ws",
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
    async fn e2e_throughput_vmess_grpc() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_grpc_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true
    skip-cert-verify: true
    network: grpc
    grpc-opts:
      grpc-service-name: "example!""#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vmess-grpc",
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
    async fn e2e_throughput_vmess_h2() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_h2_runner().await?;
        let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
        let gateway_ip = container.docker_gateway_ip();

        let extra = r#"    tls: true
    skip-cert-verify: true
    network: h2
    h2-opts:
      host:
        - example.org
      path: /test"#;
        let config = base_config(&server, CONTAINER_PORT, socks_port, extra);
        let binary = find_clash_rs_binary();

        container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "vmess-h2",
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
