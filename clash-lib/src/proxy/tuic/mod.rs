mod datagram;
pub(crate) mod types;

use crate::common::tls::{DefaultTlsVerifier, build_tls_client_config};
use anyhow::Result;
use async_trait::async_trait;

use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, sync::Arc, time::Duration};
use wind_core::AppContext;
use wind_quinn::VarInt;
use wind_tuic::quinn::outbound::{
    PeerResolver, ReconnectConfig, TuicOutbound, TuicOutboundOpts, UdpSocketFactory,
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
        DialWithConnector, tuic::types::ServerAddr, utils::new_udp_socket_blocking,
    },
    session::Session,
};

use tokio::sync::OnceCell;

use self::{
    datagram::TuicDatagramOutbound,
    types::{CongestionControl, UdpRelayMode},
};

use super::{
    ConnectorType, HandlerCommonOptions, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
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
    /// Shared with the Wind outbound; cancelling it on drop stops the
    /// reconnect supervisor and closes the connection.
    ctx: Arc<AppContext>,
    outbound: OnceCell<Arc<TuicOutbound>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tuic")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.ctx.token.cancel();
    }
}

impl DialWithConnector for Handler {}

type TuicTcpStream =
    tokio::io::Join<wind_quic::quinn::QuinnRecv, wind_quic::quinn::QuinnSend>;

impl crate::proxy::ProxyStream for TuicTcpStream {}

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
            ctx: Arc::new(AppContext::default()),
            outbound: OnceCell::new(),
        }
    }

    /// Build the Wind TUIC outbound for this handler's configuration.
    ///
    /// The rustls `ClientConfig` is built here (mTLS, custom verifier,
    /// `disable-sni`, ALPN) and handed to Wind verbatim so the whole
    /// connection/TLS surface stays under Clash's configuration.
    async fn init_outbound(
        opts: HandlerOptions,
        ctx: Arc<AppContext>,
        resolver: ThreadSafeDNSResolver,
        sess: &Session,
    ) -> Result<Arc<TuicOutbound>> {
        anyhow::ensure!(
            !opts.heartbeat_interval.is_zero(),
            "TUIC heartbeat interval must be positive"
        );
        anyhow::ensure!(
            !opts.gc_interval.is_zero(),
            "TUIC GC interval must be positive"
        );
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
        crypto.enable_early_data = opts.reduce_rtt;
        crypto.enable_sni = !opts.disable_sni;

        let server = ServerAddr::new(
            opts.server.clone(),
            opts.port,
            opts.ip.as_ref().and_then(|ip| ip.parse().ok()),
            opts.sni.clone(),
        );
        let peer_addr = server.resolve(&resolver).await?;

        // Re-resolve the server before each Wind reconnect so DNS rotation and
        // failover are followed instead of pinning the address resolved above.
        // An explicit `ip` override still short-circuits inside `resolve`.
        let peer_resolver: PeerResolver = {
            let server = server.clone();
            let resolver = resolver.clone();
            Arc::new(move || {
                let server = server.clone();
                let resolver = resolver.clone();
                Box::pin(async move {
                    server.resolve(&resolver).await.map_err(|e| e.to_string())
                })
            })
        };

        // Preserve Clash's outbound socket policy: bind the QUIC UDP socket to
        // the selected interface and/or set the Linux routing mark, so policy
        // routing and TUN setups don't leak the TUIC connection out the wrong
        // egress (or route it back through the tunnel).
        let socket_factory: UdpSocketFactory = {
            let iface = sess.iface.clone();
            #[cfg(target_os = "linux")]
            let so_mark = sess.so_mark;
            Arc::new(move |peer: std::net::SocketAddr| {
                new_udp_socket_blocking(
                    None,
                    iface.as_ref(),
                    #[cfg(target_os = "linux")]
                    so_mark,
                    Some(peer),
                )
                .and_then(tokio::net::UdpSocket::into_std)
            })
        };

        let wind_opts = TuicOutboundOpts {
            peer_addr,
            peer_resolver: Some(peer_resolver),
            sni: server.server_name().to_owned(),
            auth: (
                opts.uuid,
                Arc::from(opts.password.clone().into_bytes().into_boxed_slice()),
            ),
            zero_rtt_handshake: opts.reduce_rtt,
            heartbeat: opts.heartbeat_interval,
            gc_interval: opts.gc_interval,
            gc_lifetime: opts.gc_lifetime,
            skip_cert_verify: opts.skip_cert_verify,
            alpn: opts
                .alpn
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect(),
            reconnect: ReconnectConfig::default(),
            client_config: Some(Arc::new(crypto)),
            congestion_control: opts.congestion_controller.into(),
            max_concurrent_bi_streams: Some(
                u32::try_from(opts.max_open_stream.into_inner()).unwrap_or(u32::MAX),
            ),
            max_concurrent_uni_streams: Some(
                u32::try_from(opts.max_open_stream.into_inner()).unwrap_or(u32::MAX),
            ),
            send_window: Some(opts.send_window),
            stream_receive_window: Some(opts.receive_window.into_inner()),
            max_idle_time: Some(opts.idle_timeout),
            udp_relay_mode: opts.udp_relay_mode.into(),
            socket_factory: Some(socket_factory),
        };

        let outbound = tokio::time::timeout(
            opts.request_timeout,
            TuicOutbound::new(ctx, wind_opts),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TUIC connect timed out"))?
        .map_err(|e| anyhow::anyhow!("TUIC connect: {e}"))?;
        outbound
            .start_poll()
            .await
            .map_err(|e| anyhow::anyhow!("TUIC poll: {e}"))?;
        Ok(Arc::new(outbound))
    }

    async fn get_outbound(
        &self,
        sess: &Session,
        resolver: &ThreadSafeDNSResolver,
    ) -> Result<Arc<TuicOutbound>> {
        // The endpoint is built once and shared, so the first session's
        // interface / routing mark wins; these are process-wide settings in
        // practice (`interface-name` / `routing-mark`).
        self.outbound
            .get_or_try_init(|| {
                Self::init_outbound(
                    self.opts.clone(),
                    self.ctx.clone(),
                    resolver.clone(),
                    sess,
                )
            })
            .await
            .cloned()
    }

    async fn do_connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedInstrumentedStream> {
        let outbound = self.get_outbound(sess, &resolver).await?;
        let dest = sess.destination.clone().into();
        let io = tokio::time::timeout(
            self.opts.request_timeout,
            outbound.connect_tcp(&dest),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TUIC stream connect timed out"))?
        .map_err(|e| anyhow::anyhow!("TUIC stream connect: {e}"))?;
        let s = InstrumentedStreamWrapper::new(io);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn do_connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<BoxedInstrumentedDatagram> {
        let outbound = self.get_outbound(sess, &resolver).await?;
        let quic_udp = TuicDatagramOutbound::new(outbound, self.ctx.clone(), sess);
        let s = InstrumentedDatagramWrapper::new(quic_udp);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }
}

#[cfg(test)]
pub(crate) mod test_utils;

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use futures::{SinkExt, StreamExt};
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
        session::{Session, SocksAddr as ClashSocksAddr},
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

    /// 0-RTT (`reduce-rtt`) TCP ping-pong. The first connection completes a
    /// full handshake and caches a TLS session ticket; the second reconnects
    /// on the same endpoint, which may resume via `into_0rtt()`. Auth must
    /// still be sent before the Connect command on both.
    #[tokio::test]
    #[cfg_attr(
        qemu_emulated,
        ignore = "QUIC under qemu-user (cross test) is unreliable"
    )]
    async fn test_tuic_reduce_rtt_tcp() -> anyhow::Result<()> {
        crate::tests::initialize();
        let server = TuicServerProcess::start().await?;
        let port = server.port();

        let mut opts = gen_options(port)?;
        opts.reduce_rtt = true;
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        let resolver = Arc::new(NoopResolver);

        let session = |target_port: u16| Session {
            network: crate::session::Network::Tcp,
            typ: crate::session::Type::Socks5,
            source: "127.0.0.1:54321".parse().unwrap(),
            destination: format!("127.0.0.1:{target_port}").parse().unwrap(),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        // First connection: full handshake, which also caches a ticket.
        let echo = TcpEchoServer::start().await?;
        let mut stream = handler
            .connect_stream(&session(echo.port()), resolver.clone())
            .await?;
        stream.write_all(b"hello").await?;
        stream.flush().await?;
        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"world");
        drop(stream);
        drop(echo);

        // Let the NewSessionTicket arrive before tearing the connection down.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let outbound = handler
            .outbound
            .get()
            .expect("outbound must be initialized")
            .clone();
        outbound
            .connection
            .load_full()
            .inner()
            .close(0u32.into(), b"test reconnect");

        // Wait for the reconnect supervisor to swap in a fresh connection
        // (the default backoff is 500ms).
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while outbound
            .connection
            .load_full()
            .inner()
            .close_reason()
            .is_some()
        {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "TUIC client did not reconnect within 10s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Second connection: same endpoint, so it may resume with 0-RTT.
        let echo = TcpEchoServer::start().await?;
        let mut stream = handler
            .connect_stream(&session(echo.port()), resolver)
            .await?;
        stream.write_all(b"hello").await?;
        stream.flush().await?;
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"world");

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

    /// Minimal UDP echo server: every datagram is sent back to its sender.
    async fn spawn_udp_echo(bind: &str) -> anyhow::Result<SocketAddr> {
        let socket = tokio::net::UdpSocket::bind(bind).await?;
        let addr = socket.local_addr()?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                if socket.send_to(&buf[..n], peer).await.is_err() {
                    break;
                }
            }
        });
        Ok(addr)
    }

    /// UDP relay round trip in native mode: datagrams travel as `Packet`
    /// commands and are fragmented/reassembled by both sides.
    #[tokio::test]
    #[cfg_attr(
        qemu_emulated,
        ignore = "QUIC under qemu-user (cross test) is unreliable"
    )]
    async fn test_tuic_udp_roundtrip_native() -> anyhow::Result<()> {
        udp_roundtrip(UdpRelayMode::Native).await
    }

    /// UDP relay round trip in QUIC mode: each destination gets its own
    /// datagram stream.
    #[tokio::test]
    #[cfg_attr(
        qemu_emulated,
        ignore = "QUIC under qemu-user (cross test) is unreliable"
    )]
    async fn test_tuic_udp_roundtrip_quic() -> anyhow::Result<()> {
        udp_roundtrip(UdpRelayMode::Quic).await
    }

    async fn udp_roundtrip(mode: UdpRelayMode) -> anyhow::Result<()> {
        use crate::proxy::datagram::UdpPacket;

        crate::tests::initialize();
        let server = TuicServerProcess::start().await?;
        let echo = spawn_udp_echo("127.0.0.1:0").await?;

        let mut opts = gen_options(server.port())?;
        opts.udp_relay_mode = mode;
        let handler = Arc::new(Handler::new(opts));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        let session = Session {
            network: crate::session::Network::Udp,
            typ: crate::session::Type::Socks5,
            source: "127.0.0.1:54321".parse()?,
            destination: ClashSocksAddr::Ip(echo),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        let mut datagram = handler
            .connect_datagram(&session, Arc::new(NoopResolver))
            .await?;

        // Two probes on one association: the second reply must still land in
        // this session, not a freshly registered one.
        for probe in [b"hello-udp".as_slice(), b"second".as_slice()] {
            datagram
                .send(UdpPacket {
                    data: probe.to_vec(),
                    dst_addr: ClashSocksAddr::Ip(echo),
                    ..Default::default()
                })
                .await?;
            let reply =
                tokio::time::timeout(Duration::from_secs(4), datagram.next())
                    .await
                    .expect("UDP reply timed out")
                    .expect("UDP session ended before the reply");
            assert_eq!(reply.data, probe);
        }

        Ok(())
    }

    /// A dropped QUIC connection must end the existing UDP association instead
    /// of silently blackholing it: the datagram stream closes so the caller
    /// can recreate the association on the reconnected link.
    #[tokio::test]
    #[cfg_attr(
        qemu_emulated,
        ignore = "QUIC under qemu-user (cross test) is unreliable"
    )]
    async fn test_tuic_udp_association_ends_on_reconnect() -> anyhow::Result<()> {
        use crate::proxy::datagram::UdpPacket;

        crate::tests::initialize();
        let server = TuicServerProcess::start().await?;
        let echo = spawn_udp_echo("127.0.0.1:0").await?;

        let handler = Arc::new(Handler::new(gen_options(server.port())?));
        handler
            .register_connector(GLOBAL_DIRECT_CONNECTOR.clone())
            .await;

        let session = Session {
            network: crate::session::Network::Udp,
            typ: crate::session::Type::Socks5,
            source: "127.0.0.1:54321".parse()?,
            destination: ClashSocksAddr::Ip(echo),
            resolved_ip: None,
            so_mark: None,
            iface: None,
            country: None,
            asn: None,
            traffic_stats: None,
            inbound_user: None,
        };

        let mut datagram = handler
            .connect_datagram(&session, Arc::new(NoopResolver))
            .await?;

        datagram
            .send(UdpPacket {
                data: b"hello-udp".to_vec(),
                dst_addr: ClashSocksAddr::Ip(echo),
                ..Default::default()
            })
            .await?;
        let reply = tokio::time::timeout(Duration::from_secs(4), datagram.next())
            .await
            .expect("UDP reply timed out")
            .expect("UDP session ended before the reply");
        assert_eq!(reply.data, b"hello-udp");

        // Force the connection down; the supervisor reconnects with the
        // default 500ms backoff.
        let outbound = handler
            .outbound
            .get()
            .expect("outbound must be initialized")
            .clone();
        outbound
            .connection
            .load_full()
            .inner()
            .close(0u32.into(), b"test reconnect");

        // The association must end rather than keep accepting sends.
        match tokio::time::timeout(Duration::from_secs(4), datagram.next()).await {
            Ok(None) => {}
            other => panic!(
                "expected the UDP association stream to end after reconnect, got \
                 {other:?}"
            ),
        }

        // Wait for the reconnect supervisor to swap in a fresh connection.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while outbound
            .connection
            .load_full()
            .inner()
            .close_reason()
            .is_some()
        {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "TUIC client did not reconnect within 10s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // A fresh association on the reconnected link must still work.
        let mut datagram = handler
            .connect_datagram(&session, Arc::new(NoopResolver))
            .await?;
        datagram
            .send(UdpPacket {
                data: b"after-reconnect".to_vec(),
                dst_addr: ClashSocksAddr::Ip(echo),
                ..Default::default()
            })
            .await?;
        let reply = tokio::time::timeout(Duration::from_secs(4), datagram.next())
            .await
            .expect("UDP reply after reconnect timed out")
            .expect("UDP session ended before the reply after reconnect");
        assert_eq!(reply.data, b"after-reconnect");

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
