mod datagram;

use super::socks5::{client_handshake, socks_command};
use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, PlainProxyAPIResponse,
        transport::TransportLayer,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector, new_udp_socket},
    },
    session::Session,
};
use async_trait::async_trait;
use datagram::Socks5Datagram;
use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, fmt::Debug, sync::Arc};
use tracing::{debug, trace};

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub udp: bool,
    pub tls_client: Option<TransportLayer>,
}

pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: tokio::sync::RwLock::new(None),
        }
    }

    async fn inner_connect_stream(
        &self,
        s: AnyStream,
        sess: &Session,
    ) -> std::io::Result<AnyStream> {
        let mut s = if let Some(tls_client) = self.opts.tls_client.as_ref() {
            tls_client.wrap(s).await?
        } else {
            s
        };

        client_handshake(
            &mut s,
            &sess.destination,
            socks_command::CONNECT,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        Ok(s)
    }

    async fn inner_connect_datagram(
        &self,
        s: AnyStream,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<Socks5Datagram> {
        let mut s = if let Some(tls_client) = self.opts.tls_client.as_ref() {
            tls_client.wrap(s).await?
        } else {
            s
        };

        let bind_addr = client_handshake(
            &mut s,
            &sess.destination,
            socks_command::UDP_ASSOCIATE,
            self.opts.user.clone(),
            self.opts.password.clone(),
        )
        .await?;

        let bind_ip = bind_addr
            .ip()
            .ok_or(new_io_error("missing IP in bind address"))?;
        let bind_ip = if bind_ip.is_unspecified() {
            trace!("bind address is unspecified, resolving server address");
            let remote_addr = resolver
                .resolve(&self.opts.server, false)
                .await
                .map_err(|x| new_io_error(x.to_string().as_str()))?;
            remote_addr.ok_or(new_io_error(
                "no bind addr returned from server and failed to resolve server \
                 address",
            ))?
        } else {
            trace!("using server returned bind addr {}", bind_ip);
            bind_ip
        };
        let bind_port = bind_addr.port();
        trace!("bind address resolved to {}:{}", bind_ip, bind_port);

        let udp_socket = new_udp_socket(
            None,
            sess.iface.as_ref(),
            #[cfg(target_os = "linux")]
            sess.so_mark,
            Some((bind_ip, bind_port).into()),
        )
        .await?;

        Ok(Socks5Datagram::new(
            s,
            (bind_ip, bind_port).into(),
            udp_socket,
        ))
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
        OutboundType::Socks5
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedStream> {
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

    // it;s up to the server to allow full cone UDP
    // https://github.com/wzshiming/socks5/blob/0e66f80351778057703bd652e8b177fabe443f34/server.go#L368
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
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
    ) -> std::io::Result<BoxedInstrumentedStream> {
        let s = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let s = self.inner_connect_stream(s, sess).await?;

        let s = InstrumentedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        let s = connector
            .connect_stream(
                resolver.clone(),
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let d = self.inner_connect_datagram(s, sess, resolver).await?;

        let d = InstrumentedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
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
        if let Some(username) = self.opts.user.as_ref() {
            m.insert("username".to_owned(), Box::new(username.clone()) as _);
        }
        if let Some(password) = self.opts.password.as_ref() {
            m.insert("password".to_owned(), Box::new(password.clone()) as _);
        }
        if self.opts.tls_client.is_some() {
            m.insert("tls".to_owned(), Box::new(true) as _);
        }
        m
    }
}

#[cfg(all(test, docker_test))]
mod tests {

    use std::{io::Write, sync::Arc};

    use crate::{
        proxy::{
            socks::outbound::{Handler, HandlerOptions},
            utils::{
                GLOBAL_DIRECT_CONNECTOR,
                test_utils::{
                    Suite,
                    consts::{IMAGE_SOCKS5, LOCAL_ADDR},
                    docker_runner::{
                        DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                    },
                    run_test_suites_and_cleanup,
                },
            },
        },
        tests::initialize,
    };

    const USER: &str = "user";
    const PASSWORD: &str = "password";

    const SOCKS5_NOAUTH_SERVER_CONFIG: &str = r#"{
    "log": {
        "loglevel": "debug"
    },
    "inbounds": [
        {
            "port": 10002,
            "listen": "0.0.0.0",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true,
                "ip": "0.0.0.0"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}"#;

    const SOCKS5_AUTH_SERVER_CONFIG: &str = r#"{
    "log": {
        "loglevel": "debug"
    },
    "inbounds": [
        {
            "port": 10002,
            "listen": "0.0.0.0",
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [
                    {
                        "user": "user",
                        "pass": "password"
                    }
                ],
                "udp": true,
                "ip": "0.0.0.0"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}"#;

    async fn get_socks5_runner(
        auth: bool,
        host_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let config = if auth {
            SOCKS5_AUTH_SERVER_CONFIG
        } else {
            SOCKS5_NOAUTH_SERVER_CONFIG
        };

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(config.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_SOCKS5)
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/v2ray/config.json")])
            .host_port(host_port, 10002)
            .build()
            .await;
        drop(tmp);
        result
    }

    fn server_addr(runner: &DockerTestRunner) -> String {
        runner.container_ip().unwrap_or(LOCAL_ADDR.to_owned())
    }

    #[tokio::test]
    async fn test_socks5_no_auth() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        let port = 10002_u16;
        let runner = get_socks5_runner(false, host_port).await?;
        let opts = HandlerOptions {
            name: "test-socks5-no-auth".to_owned(),
            common_opts: Default::default(),
            server: server_addr(&runner),
            port,
            user: None,
            password: None,
            udp: true,
            ..Default::default()
        };
        let handler = Arc::new(Handler::new(opts));
        run_test_suites_and_cleanup(handler, runner, Suite::all()).await
    }

    #[tokio::test]
    async fn test_socks5_auth() -> anyhow::Result<()> {
        use crate::proxy::DialWithConnector;
        initialize();
        let host_port = alloc_docker_port();
        let port = 10002_u16;
        let runner = get_socks5_runner(true, host_port).await?;
        let opts = HandlerOptions {
            name: "test-socks5-auth".to_owned(),
            common_opts: Default::default(),
            server: server_addr(&runner),
            port,
            user: Some(USER.to_owned()),
            password: Some(PASSWORD.to_owned()),
            udp: true,
            ..Default::default()
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

    const SOCKS5_NOAUTH_SERVER_CONFIG: &str = r#"{
    "log": {"loglevel": "debug"},
    "inbounds": [{
        "port": 10002,
        "listen": "0.0.0.0",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": true, "ip": "0.0.0.0"}
    }],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_socks5_noauth_runner() -> anyhow::Result<DockerTestRunner> {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SOCKS5_NOAUTH_SERVER_CONFIG.as_bytes())?;
        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SOCKS5)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/v2ray/config.json")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    const SOCKS5_AUTH_SERVER_CONFIG: &str = r#"{
    "log": {"loglevel": "debug"},
    "inbounds": [{
        "port": 10002,
        "listen": "0.0.0.0",
        "protocol": "socks",
        "settings": {
            "auth": "password",
            "accounts": [{"user": "user", "pass": "password"}],
            "udp": true,
            "ip": "0.0.0.0"
        }
    }],
    "outbounds": [{"protocol": "freedom"}]
}"#;

    async fn get_socks5_auth_runner() -> anyhow::Result<DockerTestRunner> {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(SOCKS5_AUTH_SERVER_CONFIG.as_bytes())?;
        // Keep tmp alive until the container is built
        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SOCKS5)
            .no_port()
            .mounts(&[(tmp.path().to_str().unwrap(), "/etc/v2ray/config.json")])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_socks5_noauth() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_socks5_noauth_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("socks5 container has no IP"))?;
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
    type: socks5
    server: {server}
    port: {port}
    udp: false
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
                    "socks5-noauth",
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
    async fn e2e_throughput_socks5_auth() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_socks5_auth_runner().await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("socks5 container has no IP"))?;
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
    type: socks5
    server: {server}
    port: {port}
    username: user
    password: password
    udp: false
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
                    "socks5-auth",
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
