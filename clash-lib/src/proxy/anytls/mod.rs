use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, io, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedStream, InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    impl_default_connector,
    proxy::transport::TransportLayer,
    session::Session,
};

use super::{
    AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
    OutboundHandler, OutboundType, PlainProxyAPIResponse,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};
mod datagram;
use datagram::OutboundDatagramAnytls;
pub mod inbound;

// AnyTLS frame command bytes (see the anytls protocol spec).
const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SERVER_SETTINGS: u8 = 10;
/// Stream ID used for our single-stream multiplexing.
const STREAM_ID: u32 = 1;

/// Padding scheme advertised by this client: no padding on any packet.
///
/// The MD5 is pre-computed over the literal string "stop=0" (no trailing
/// newline), matching how anytls-go serialises a single-entry scheme.
const CLIENT_PADDING_SCHEME_MD5: &str = "47edb1f4ed8a99480bf416d178311f10";

/// Default duplex buffer size (16KB). Can be overridden via
/// `experimental.anytls-duplex-buffer-size` in config.
const DEFAULT_DUPLEX_BUFFER_SIZE: usize = 16 * 1024;
/// Default relay buffer size (4KB). Can be overridden via
/// `experimental.anytls-relay-buffer-size` in config.
const DEFAULT_RELAY_BUFFER_SIZE: usize = 4 * 1024;

/// Global buffer size configuration. Uses AtomicUsize so it can be
/// updated on config reload (unlike OnceLock which is set-once).
static DUPLEX_BUFFER_SIZE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_DUPLEX_BUFFER_SIZE);
static RELAY_BUFFER_SIZE_CONFIG: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_RELAY_BUFFER_SIZE);

/// Set the global AnyTLS buffer sizes. Called during config loading.
/// Validates sizes: `duplex` must be > 0, and `relay` must be in
/// `1..=u16::MAX`.
pub fn set_buffer_config(duplex: usize, relay: usize) {
    let duplex = if duplex > 0 {
        duplex
    } else {
        warn!(
            "invalid AnyTLS duplex buffer size: {}, using default {}",
            duplex, DEFAULT_DUPLEX_BUFFER_SIZE
        );
        DEFAULT_DUPLEX_BUFFER_SIZE
    };
    let relay = if (1..=u16::MAX as usize).contains(&relay) {
        relay
    } else {
        warn!(
            "invalid AnyTLS relay buffer size: {}, using default {}",
            relay, DEFAULT_RELAY_BUFFER_SIZE
        );
        DEFAULT_RELAY_BUFFER_SIZE
    };
    DUPLEX_BUFFER_SIZE.store(duplex, std::sync::atomic::Ordering::Release);
    RELAY_BUFFER_SIZE_CONFIG.store(relay, std::sync::atomic::Ordering::Release);
}

pub(crate) fn duplex_buffer_size() -> usize {
    DUPLEX_BUFFER_SIZE.load(std::sync::atomic::Ordering::Acquire)
}

pub(crate) fn relay_buffer_size() -> usize {
    RELAY_BUFFER_SIZE_CONFIG.load(std::sync::atomic::Ordering::Acquire)
}

pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub udp: bool,
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
        f.debug_struct("AnyTLS")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    const UDP_OVER_TCP_V2_MAGIC_ADDR: &str = "sp.v2.udp-over-tcp.arpa";

    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: Default::default(),
        }
    }

    async fn inner_proxy_stream(
        &self,
        s: AnyStream,
        sess: &Session,
    ) -> io::Result<AnyStream> {
        let s = if let Some(tls_client) = self.opts.tls.as_ref() {
            tls_client.wrap(s).await?
        } else {
            s
        };

        let s = if let Some(transport) = self.opts.transport.as_ref() {
            transport.wrap(s).await?
        } else {
            s
        };

        self.open_anytls_stream(s, sess).await
    }

    async fn open_anytls_stream(
        &self,
        mut stream: AnyStream,
        sess: &Session,
    ) -> io::Result<AnyStream> {
        // Build the ENTIRE handshake in one buffer so it is sent as a single
        // TLS application-data record.  sing-box reads the first record as a
        // complete auth packet; splitting the write across multiple records
        // causes it to get EOF while reading the padding-length field.
        let password = Sha256::digest(self.opts.password.as_bytes());
        let settings = format!(
            "v=2\nclient=clash-rs/{}\npadding-md5={}",
            env!("CLASH_VERSION_OVERRIDE"),
            CLIENT_PADDING_SCHEME_MD5
        );
        let mut addr_buf = BytesMut::new();
        sess.destination.write_buf(&mut addr_buf);

        let mut handshake = BytesMut::new();
        handshake.put_slice(password.as_slice()); // sha256(password) – 32 B
        handshake.put_u16(0); // padding0 length = 0 (no padding)
        handshake.extend_from_slice(&Self::encode_frame(
            CMD_SETTINGS,
            0,
            settings.as_bytes(),
        )?);
        handshake.extend_from_slice(&Self::encode_frame(CMD_SYN, STREAM_ID, &[])?);
        handshake
            .extend_from_slice(&Self::encode_frame(CMD_PSH, STREAM_ID, &addr_buf)?);

        stream.write_all(&handshake).await?;
        stream.flush().await?;

        let (mut remote_read, mut remote_write) = tokio::io::split(stream);
        let (app_stream, relay_stream) = tokio::io::duplex(duplex_buffer_size());
        let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);
        let name_a = self.opts.name.clone();
        let name_b = self.opts.name.clone();

        let cancel = CancellationToken::new();
        let cancel_a = cancel.clone();
        let cancel_b = cancel;

        tokio::spawn(async move {
            let mut buf = vec![0u8; relay_buffer_size()];
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_a.cancelled() => break,
                    result = relay_read.read(&mut buf) => {
                        let n = match result {
                            Ok(n) => n,
                            Err(err) => {
                                debug!("anytls {} relay read error: {}", name_a, err);
                                cancel_a.cancel();
                                break;
                            }
                        };

                        if n == 0 {
                            if let Err(err) =
                                Self::write_frame(&mut remote_write, CMD_FIN, STREAM_ID, &[])
                                    .await
                            {
                                debug!("anytls {} send FIN failed: {}", name_a, err);
                            }
                            if let Err(err) = remote_write.flush().await {
                                debug!("anytls {} flush FIN failed: {}", name_a, err);
                            }
                            cancel_a.cancel();
                            break;
                        }

                        if let Err(err) = Self::write_frame(
                            &mut remote_write,
                            CMD_PSH,
                            STREAM_ID,
                            &buf[..n],
                        )
                        .await
                        {
                            debug!("anytls {} send PSH failed: {}", name_a, err);
                            cancel_a.cancel();
                            break;
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_b.cancelled() => break,
                    result = Self::read_frame(&mut remote_read) => {
                        let (cmd, stream_id, data) = match result {
                            Ok(frame) => frame,
                            Err(err) => {
                                debug!("anytls {} read frame failed: {}", name_b, err);
                                cancel_b.cancel();
                                break;
                            }
                        };

                        if stream_id != STREAM_ID {
                            debug!(
                                "anytls {} ignores frame for unexpected stream id {}",
                                name_b, stream_id
                            );
                            continue;
                        }

                        match cmd {
                            CMD_PSH => {
                                if let Err(err) = relay_write.write_all(&data).await {
                                    debug!("anytls {} relay write failed: {}", name_b, err);
                                    cancel_b.cancel();
                                    break;
                                }
                            }
                            CMD_FIN => {
                                if let Err(err) = relay_write.shutdown().await {
                                    debug!(
                                        "anytls {} relay shutdown failed: {}",
                                        name_b, err
                                    );
                                }
                                cancel_b.cancel();
                                break;
                            }
                            CMD_ALERT => {
                                let msg = String::from_utf8_lossy(&data);
                                warn!("anytls {} alert: {}", name_b, msg);
                                let _ = relay_write.shutdown().await;
                                cancel_b.cancel();
                                break;
                            }
                            // v2: server settings / padding-scheme update — read
                            // and discard; we use a fixed no-padding scheme.
                            CMD_SERVER_SETTINGS | CMD_UPDATE_PADDING_SCHEME => {}
                            CMD_WASTE | CMD_SYN | CMD_SETTINGS => {}
                            _ => {}
                        }
                    }
                }
            }
        });

        Ok(Box::new(app_stream))
    }

    /// Encodes a frame into a `BytesMut` without any I/O.
    fn encode_frame(
        command: u8,
        stream_id: u32,
        data: &[u8],
    ) -> io::Result<BytesMut> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "anytls frame payload exceeds 65535 bytes",
            ));
        }
        let mut buf = BytesMut::with_capacity(7 + data.len());
        buf.put_u8(command);
        buf.put_u32(stream_id);
        buf.put_u16(data.len() as u16);
        buf.put_slice(data);
        Ok(buf)
    }

    async fn write_frame(
        writer: &mut (impl AsyncWrite + Unpin),
        command: u8,
        stream_id: u32,
        data: &[u8],
    ) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "anytls frame payload exceeds 65535 bytes",
            ));
        }

        // Build the entire frame in a single buffer to minimize syscalls.
        // Frame format: [cmd:1B][stream_id:4B][len:2B][data:NB]
        // This reduces 4 write syscalls to 1, which is critical for
        // high-throughput scenarios on resource-constrained devices.
        let mut buf = BytesMut::with_capacity(7 + data.len());
        buf.put_u8(command);
        buf.put_u32(stream_id);
        buf.put_u16(data.len() as u16);
        if !data.is_empty() {
            buf.put_slice(data);
        }
        writer.write_all(&buf).await
    }

    async fn read_frame(
        reader: &mut (impl AsyncRead + Unpin),
    ) -> io::Result<(u8, u32, Vec<u8>)> {
        // Read the 7-byte header in one syscall instead of 3 separate
        // reads (read_u8 + read_u32 + read_u16). This halves the number
        // of read syscalls per frame, improving latency on slow links.
        let mut header = [0u8; 7];
        reader.read_exact(&mut header).await?;
        let command = header[0];
        let stream_id =
            u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let data_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = vec![0u8; data_len];
        if data_len > 0 {
            reader.read_exact(&mut data).await?;
        }
        Ok((command, stream_id, data))
    }

    fn encode_uot_connect_request(dst_addr: &crate::session::SocksAddr) -> BytesMut {
        let mut request = BytesMut::new();
        request.put_u8(1); // isConnect = true (UoT v2 connect mode)
        dst_addr.write_buf(&mut request);
        request
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
        OutboundType::Anytls
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

        let s = self.inner_proxy_stream(stream, sess).await?;
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

        // AnyTLS UDP follows udp-over-tcp v2:
        // 1) open stream to sp.v2.udp-over-tcp.arpa
        // 2) send connect request (isConnect + real udp destination)
        // 3) exchange length-prefixed udp payloads.
        let mut proxy_sess = sess.clone();
        proxy_sess.destination = crate::session::SocksAddr::try_from((
            Self::UDP_OVER_TCP_V2_MAGIC_ADDR.to_owned(),
            0,
        ))?;

        let mut stream = self.inner_proxy_stream(stream, &proxy_sess).await?;
        let request = Self::encode_uot_connect_request(&sess.destination);
        stream.write_all(&request).await?;
        stream.flush().await?;

        let datagram = OutboundDatagramAnytls::new(stream, sess.destination.clone());
        let chained =
            crate::app::dispatcher::InstrumentedDatagramWrapper::new(datagram);
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

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use futures::{SinkExt, StreamExt};
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::{
        proxy::datagram::UdpPacket,
        session::{Session, SocksAddr},
    };

    #[cfg(docker_test)]
    use std::io::Write;

    #[cfg(docker_test)]
    use crate::{
        proxy::{
            transport::{self, TransportLayer},
            utils::test_utils::{
                Suite,
                config_helper::test_config_base_dir,
                consts::{IMAGE_SINGBOX, LOCAL_ADDR},
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };

    #[cfg(docker_test)]
    const ANYTLS_SERVER_CONFIG: &str = r#"{
    "log": {
        "level": "info"
    },
    "inbounds": [
        {
            "type": "anytls",
            "tag": "anytls-in",
            "listen": "0.0.0.0",
            "listen_port": 10002,
            "users": [
                {
                    "name": "user",
                    "password": "example"
                }
            ],
            "padding_scheme": ["stop=0"],
            "tls": {
                "enabled": true,
                "certificate_path": "/etc/ssl/v2ray/fullchain.pem",
                "key_path": "/etc/ssl/v2ray/privkey.pem"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ]
}"#;

    fn make_handler(udp: bool, with_tls: bool) -> Handler {
        use crate::proxy::transport::{TlsClient, TransportLayer};
        Handler::new(HandlerOptions {
            name: "test".to_owned(),
            common_opts: Default::default(),
            server: "127.0.0.1".to_owned(),
            port: 10002,
            password: "secret".to_owned(),
            udp,
            tls: if with_tls {
                Some(TransportLayer::Tls(
                    TlsClient::new(
                        true,
                        "example.org".to_owned(),
                        None,
                        None,
                        None,
                        None,
                    )
                    .expect("failed to create TLS client"),
                ))
            } else {
                None
            },
            transport: None,
        })
    }

    async fn read_frame_raw(
        r: &mut (impl AsyncReadExt + Unpin),
    ) -> (u8, u32, Vec<u8>) {
        let cmd = r.read_u8().await.unwrap();
        let sid = r.read_u32().await.unwrap();
        let len = r.read_u16().await.unwrap() as usize;
        let mut data = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut data).await.unwrap();
        }
        (cmd, sid, data)
    }

    #[test]
    fn test_encode_uot_connect_request() {
        let dst = SocksAddr::try_from(("1.1.1.1".to_owned(), 53)).unwrap();
        let req = Handler::encode_uot_connect_request(&dst);

        assert_eq!(req[0], 1);
        let parsed = SocksAddr::try_from(&req[1..]).unwrap();
        assert_eq!(parsed, dst);
    }

    #[test]
    fn test_encode_uot_connect_request_domain() {
        let dst = SocksAddr::try_from(("example.com".to_owned(), 80)).unwrap();
        let req = Handler::encode_uot_connect_request(&dst);

        assert_eq!(req[0], 1);
        let parsed = SocksAddr::try_from(&req[1..]).unwrap();
        assert_eq!(parsed, dst);
    }

    #[tokio::test]
    async fn test_handler_proto() {
        let h = make_handler(false, false);
        assert!(matches!(h.proto(), OutboundType::Anytls));
        assert_eq!(h.name(), "test");
    }

    #[tokio::test]
    async fn test_handler_support_udp_true() {
        let h = make_handler(true, false);
        assert!(h.support_udp().await);
    }

    #[tokio::test]
    async fn test_handler_support_udp_false() {
        let h = make_handler(false, false);
        assert!(!h.support_udp().await);
    }

    #[tokio::test]
    async fn test_as_map_required_fields() {
        let h = make_handler(false, false);
        let map = h.as_map().await;
        assert!(map.contains_key("server"));
        assert!(map.contains_key("port"));
        assert!(map.contains_key("password"));
        assert!(!map.contains_key("tls"), "tls absent when None");
    }

    #[tokio::test]
    async fn test_as_map_optional_flags() {
        let h = make_handler(true, true);
        let map = h.as_map().await;
        assert!(map.contains_key("tls"), "tls present when Some");
    }

    // ---- write_frame / read_frame tests ----

    #[tokio::test]
    async fn test_write_read_frame_roundtrip() {
        let (mut a, mut b) = duplex(4096);
        Handler::write_frame(&mut a, CMD_PSH, STREAM_ID, b"hello")
            .await
            .unwrap();
        let (cmd, sid, data) = Handler::read_frame(&mut b).await.unwrap();
        assert_eq!(cmd, CMD_PSH);
        assert_eq!(sid, STREAM_ID);
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn test_write_frame_empty_payload() {
        let (mut a, mut b) = duplex(4096);
        Handler::write_frame(&mut a, CMD_SYN, STREAM_ID, &[])
            .await
            .unwrap();
        let (cmd, sid, data) = Handler::read_frame(&mut b).await.unwrap();
        assert_eq!(cmd, CMD_SYN);
        assert_eq!(sid, STREAM_ID);
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn test_write_frame_rejects_oversized_payload() {
        let (mut a, _b) = duplex(4096);
        let oversized = vec![0u8; u16::MAX as usize + 1];
        let err = Handler::write_frame(&mut a, CMD_PSH, STREAM_ID, &oversized)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // ---- open_anytls_stream tests ----

    #[tokio::test]
    async fn test_open_anytls_stream_sends_handshake() {
        let h = make_handler(false, false);
        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let sess = Session {
            destination: dst.clone(),
            ..Default::default()
        };
        let (client, mut server) = duplex(65536);

        let _app = h.open_anytls_stream(Box::new(client), &sess).await.unwrap();

        // Password SHA256 hash
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        assert_eq!(&hash_buf, Sha256::digest(b"secret").as_slice());

        // Reserved u16(0)
        assert_eq!(server.read_u16().await.unwrap(), 0);

        // SETTINGS frame (stream_id = 0) — v2 protocol with padding-md5
        let (cmd, sid, data) = read_frame_raw(&mut server).await;
        assert_eq!(cmd, CMD_SETTINGS);
        assert_eq!(sid, 0);
        let settings_str = String::from_utf8(data).unwrap();
        assert!(settings_str.starts_with("v=2"), "settings must use v=2");
        assert!(
            settings_str.contains("padding-md5="),
            "settings must include padding-md5"
        );
        assert!(
            settings_str.contains(CLIENT_PADDING_SCHEME_MD5),
            "padding-md5 must match our scheme"
        );

        // SYN frame
        let (cmd, sid, data) = read_frame_raw(&mut server).await;
        assert_eq!(cmd, CMD_SYN);
        assert_eq!(sid, STREAM_ID);
        assert!(data.is_empty());

        // PSH frame carries the destination address
        let (cmd, sid, data) = read_frame_raw(&mut server).await;
        assert_eq!(cmd, CMD_PSH);
        assert_eq!(sid, STREAM_ID);
        let mut expected = BytesMut::new();
        dst.write_buf(&mut expected);
        assert_eq!(data, expected.to_vec());
    }

    #[tokio::test]
    async fn test_open_anytls_stream_relays_data() {
        let h = make_handler(false, false);
        let sess = Session {
            destination: SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap(),
            ..Default::default()
        };
        let (client, mut server) = duplex(65536);

        let mut app = h.open_anytls_stream(Box::new(client), &sess).await.unwrap();

        // Drain the initial handshake bytes from server side.
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        server.read_u16().await.unwrap();
        read_frame_raw(&mut server).await; // SETTINGS
        read_frame_raw(&mut server).await; // SYN
        read_frame_raw(&mut server).await; // PSH (dest)

        // Send a PSH frame from server → client; verify app stream receives it.
        let payload = b"response data";
        Handler::write_frame(&mut server, CMD_PSH, STREAM_ID, payload)
            .await
            .unwrap();

        let mut recv_buf = vec![0u8; payload.len()];
        app.read_exact(&mut recv_buf).await.unwrap();
        assert_eq!(recv_buf, payload);
    }

    #[tokio::test]
    async fn test_inner_proxy_stream_sends_handshake() {
        // Tests inner_proxy_stream with no TLS and no transport — exercises
        // the full code path through inner_proxy_stream → open_anytls_stream.
        let h = make_handler(false, false);
        let dst = SocksAddr::try_from(("1.2.3.4".to_owned(), 80)).unwrap();
        let sess = Session {
            destination: dst,
            ..Default::default()
        };
        let (client, mut server) = duplex(65536);

        let _app = h.inner_proxy_stream(Box::new(client), &sess).await.unwrap();

        // Verify the password hash is the first thing written.
        let mut hash_buf = [0u8; 32];
        server.read_exact(&mut hash_buf).await.unwrap();
        assert_eq!(&hash_buf, Sha256::digest(b"secret").as_slice());
    }

    // ---- datagram framing tests ----

    #[tokio::test]
    async fn test_datagram_write_length_prefix() {
        let target = SocksAddr::try_from(("1.1.1.1".to_owned(), 53)).unwrap();
        let (client, mut server) = duplex(4096);
        let mut dg = datagram::OutboundDatagramAnytls::new(Box::new(client), target);

        let payload = b"hello world";
        dg.send(UdpPacket {
            data: payload.to_vec(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
            inbound_user: None,
        })
        .await
        .unwrap();

        // The wire format is: 2-byte big-endian length followed by payload.
        let mut raw = vec![0u8; 2 + payload.len()];
        server.read_exact(&mut raw).await.unwrap();
        assert_eq!(u16::from_be_bytes([raw[0], raw[1]]) as usize, payload.len());
        assert_eq!(&raw[2..], payload);
    }

    #[tokio::test]
    async fn test_datagram_roundtrip() {
        let target = SocksAddr::try_from(("1.1.1.1".to_owned(), 53)).unwrap();
        let payload = b"roundtrip payload";

        // Build a raw response (length-prefixed) that the server "sends back".
        let mut wire = Vec::new();
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(payload);

        let (client, mut server) = duplex(4096);
        let mut dg =
            datagram::OutboundDatagramAnytls::new(Box::new(client), target.clone());

        server.write_all(&wire).await.unwrap();

        let pkt = dg.next().await.expect("should receive a packet");
        assert_eq!(pkt.data, payload);
        assert_eq!(pkt.src_addr, target);
    }

    #[tokio::test]
    async fn test_datagram_oversized_packet_rejected() {
        let target = SocksAddr::try_from(("1.1.1.1".to_owned(), 53)).unwrap();
        let (client, _server) = duplex(4096);
        let mut dg = datagram::OutboundDatagramAnytls::new(Box::new(client), target);

        let oversized = vec![0u8; u16::MAX as usize + 1];
        let result = dg
            .send(UdpPacket {
                data: oversized,
                src_addr: SocksAddr::any_ipv4(),
                dst_addr: SocksAddr::any_ipv4(),
                inbound_user: None,
            })
            .await;
        assert!(
            result.is_err(),
            "sending oversized packet should return an error"
        );
    }

    // ---- docker integration tests ----

    #[cfg(docker_test)]
    async fn get_runner(host_port: u16) -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(ANYTLS_SERVER_CONFIG.as_bytes())?;

        let result = DockerTestRunnerBuilder::new()
            .image(IMAGE_SINGBOX)
            .cmd(&["run", "-c", "/etc/sing-box/config.json"])
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/sing-box/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .host_port(host_port, 10002)
            .build()
            .await;
        drop(tmp);
        result
    }

    #[cfg(docker_test)]
    #[tokio::test]
    async fn test_anytls() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();

        let tls = transport::TlsClient::new(
            true,
            "example.org".to_owned(),
            Some(vec!["http/1.1".to_owned(), "h2".to_owned()]),
            None,
            None,
            None,
        )
        .expect("failed to create TLS client");

        let runner = get_runner(host_port).await?;

        let opts = HandlerOptions {
            name: "test-anytls".to_owned(),
            common_opts: Default::default(),
            server: runner.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 10002,
            password: "example".to_owned(),
            udp: true,
            tls: Some(TransportLayer::Tls(tls)),
            transport: None,
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

    const ANYTLS_SERVER_CONFIG: &str = r#"{
    "log": {"level": "info"},
    "inbounds": [{
        "type": "anytls",
        "tag": "anytls-in",
        "listen": "0.0.0.0",
        "listen_port": 10002,
        "users": [{"name": "user", "password": "example"}],
        "padding_scheme": ["stop=0"],
        "tls": {
            "enabled": true,
            "certificate_path": "/etc/ssl/v2ray/fullchain.pem",
            "key_path": "/etc/ssl/v2ray/privkey.pem"
        }
    }],
    "outbounds": [{"type": "direct", "tag": "direct"}]
}"#;

    async fn get_anytls_runner() -> anyhow::Result<DockerTestRunner> {
        let test_config_dir = config_helper::test_config_base_dir();
        let cert = test_config_dir.join("certs/example.org.pem");
        let key = test_config_dir.join("certs/example.org-key.pem");

        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(ANYTLS_SERVER_CONFIG.as_bytes())?;

        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_SINGBOX)
            .cmd(&["run", "-c", "/etc/sing-box/config.json"])
            .no_port()
            .mounts(&[
                (tmp.path().to_str().unwrap(), "/etc/sing-box/config.json"),
                (cert.to_str().unwrap(), "/etc/ssl/v2ray/fullchain.pem"),
                (key.to_str().unwrap(), "/etc/ssl/v2ray/privkey.pem"),
            ])
            .build()
            .await?;
        drop(tmp);
        Ok(runner)
    }

    #[tokio::test]
    async fn e2e_throughput_anytls_tls() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let container = get_anytls_runner().await?;
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
    type: anytls
    server: {server}
    port: {port}
    password: example
    skip-cert-verify: true
    sni: example.org
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
                    "anytls-tls",
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
