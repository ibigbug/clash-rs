//! Hysteria2 inbound listener — QUIC/HTTP3-based proxy server.
//!
//! ## Protocol overview
//!
//! 1. Clients connect via QUIC with TLS ALPN "h3".
//! 2. Client authenticates via an HTTP/3 POST to `https://hysteria/auth` with
//!    the `Hysteria-Auth` header.  Server replies 233 on success, 401 on
//!    failure.
//! 3. After auth the client opens raw QUIC bidirectional streams for TCP
//!    proxying (Hysteria2 frame format) and sends QUIC datagrams for UDP
//!    proxying.

use crate::app::net::SocketMark;
use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use h3_quinn::Connection as H3QuinnConnection;
use quinn::{Connection, Endpoint, ServerConfig};
use quinn_proto::crypto::rustls::QuicServerConfig;
use tokio::sync::{Mutex, mpsc};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info, trace, warn};

use crate::{
    Dispatcher,
    common::tls::resolve_server_cert_and_key,
    config::internal::listener::InboundUser,
    proxy::{
        datagram::UdpPacket,
        hysteria2::codec::{Hy2TcpReqCodec, Hy2TcpResp, Hy2TcpRespEncoder},
        inbound::InboundHandlerTrait,
        utils::ToCanonical,
    },
    session::{Network, Session, SocksAddr, Type},
};

use super::{
    codec::{Defragger, Fragments, HysUdpPacket, padding},
    stream::HystStream,
};

/// The `h3` server connection type over a Quinn transport. Held for the
/// lifetime of a QUIC connection so its `Drop` (which closes the connection)
/// does not fire until we are done proxying.
type H3ServerConnection = h3::server::Connection<H3QuinnConnection, Bytes>;

/// Build a QUIC `ServerConfig` (TLS + h3 ALPN) from optional PEM cert/key.
///
/// When both are `None`, an ephemeral self-signed certificate is used.
fn build_quic_server_config(
    certificate: Option<&str>,
    private_key: Option<&str>,
) -> std::io::Result<ServerConfig> {
    let (certs, key) =
        resolve_server_cert_and_key(certificate, private_key, "hysteria2")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("hysteria2 TLS config error: {e}"),
            )
        })?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_server_config: QuicServerConfig =
        tls_config.try_into().map_err(|e| {
            std::io::Error::other(format!(
                "failed to build hysteria2 QUIC server config: {e}"
            ))
        })?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    // Allow datagrams for UDP proxying
    if let Some(t) = Arc::get_mut(&mut server_config.transport) {
        t.max_idle_timeout(Some(
            std::time::Duration::from_secs(300).try_into().unwrap(),
        ));
        t.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
        t.datagram_send_buffer_size(16 * 1024 * 1024);
    }
    Ok(server_config)
}

/// Build a map from plaintext password → user name.
/// When `users` is empty, a single-user entry with `password` is inserted
/// under the key `password` itself (matching via direct equality).
pub fn build_user_map(
    users: &[InboundUser],
    fallback_password: &str,
) -> Arc<HashMap<String, String>> {
    let mut map = HashMap::new();
    if users.is_empty() {
        map.insert(
            fallback_password.to_owned(),
            String::new(), // no named user
        );
    } else {
        for u in users {
            map.insert(u.password.clone(), u.name.clone());
        }
    }
    Arc::new(map)
}

pub struct InboundOptions {
    pub addr: SocketAddr,
    pub password: String,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
    pub allow_lan: bool,
    pub dispatcher: Arc<Dispatcher>,
    pub fw_mark: Option<SocketMark>,
    pub users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

pub struct Hysteria2Inbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<SocketMark>,
    server_config: ServerConfig,
    password: String,
    users_rx: tokio::sync::watch::Receiver<Vec<InboundUser>>,
}

impl Drop for Hysteria2Inbound {
    fn drop(&mut self) {
        warn!("Hysteria2 inbound listener on {} stopped", self.addr);
    }
}

impl Hysteria2Inbound {
    pub fn new(opts: InboundOptions) -> std::io::Result<Self> {
        let server_config = build_quic_server_config(
            opts.certificate.as_deref(),
            opts.private_key.as_deref(),
        )?;
        Ok(Self {
            addr: opts.addr,
            allow_lan: opts.allow_lan,
            dispatcher: opts.dispatcher,
            fw_mark: opts.fw_mark,
            server_config,
            password: opts.password,
            users_rx: opts.users_rx,
        })
    }
}

#[async_trait::async_trait]
impl InboundHandlerTrait for Hysteria2Inbound {
    fn handle_tcp(&self) -> bool {
        true // QUIC is our "TCP" listener socket
    }

    fn handle_udp(&self) -> bool {
        false // UDP is multiplexed over QUIC datagrams; no separate UDP socket
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let endpoint = Endpoint::server(self.server_config.clone(), self.addr)?;
        let local_addr = endpoint.local_addr()?;
        let local_ip = local_addr.ip();

        let mut users_rx = self.users_rx.clone();
        let mut user_map =
            build_user_map(&users_rx.borrow_and_update(), &self.password);

        info!("Hysteria2 QUIC listening at: {}", local_addr);

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let incoming = match incoming {
                        Some(i) => i,
                        None => {
                            warn!("hysteria2 inbound {}: endpoint closed", self.addr);
                            break;
                        }
                    };

                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("hysteria2 inbound {}: accept error: {e}", self.addr);
                            continue;
                        }
                    };

                    // Canonicalize so an IPv4-mapped IPv6 client (e.g.
                    // ::ffff:127.0.0.1 on a dual-stack listener) compares equal
                    // to the plain IPv4 local address, matching the other
                    // inbounds' allow_lan handling.
                    let src_addr = conn.remote_address().to_canonical();
                    if !self.allow_lan
                        && !local_ip.is_unspecified()
                        && src_addr.ip() != local_ip
                    {
                        warn!(
                            "hysteria2 inbound {}: connection from {} rejected \
                             (not allowed)",
                            self.addr, src_addr
                        );
                        conn.close(0u32.into(), b"not allowed");
                        continue;
                    }

                    let dispatcher = self.dispatcher.clone();
                    let fw_mark = self.fw_mark;
                    let user_map = Arc::clone(&user_map);

                    tokio::spawn(async move {
                        handle_connection(
                            conn, src_addr, dispatcher, fw_mark, user_map,
                        )
                        .await;
                    });
                }

                Ok(()) = users_rx.changed() => {
                    let users = users_rx.borrow_and_update().clone();
                    info!(
                        "hysteria2 inbound {}: user list updated ({} users)",
                        self.addr,
                        users.len()
                    );
                    user_map = build_user_map(&users, &self.password);
                }
            }
        }
        Ok(())
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        // UDP is carried inside QUIC datagrams; no separate UDP socket.
        Ok(())
    }
}

/// Handle a single QUIC connection: authenticate, then relay TCP streams and
/// UDP datagrams until the connection closes.
async fn handle_connection(
    conn: Connection,
    src_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<SocketMark>,
    user_map: Arc<HashMap<String, String>>,
) {
    let (inbound_user, _h3_conn) = match authenticate(&conn, &user_map).await {
        Ok(u) => u,
        Err(e) => {
            debug!("hysteria2 inbound auth failed from {src_addr}: {e}");
            conn.close(0u32.into(), b"auth failed");
            return;
        }
    };
    // `_h3_conn` is intentionally kept in scope: dropping it closes the QUIC
    // connection (h3's `Drop` impl), which would kill the proxy streams below.

    debug!(
        "hysteria2 inbound {src_addr}: authenticated, user={:?}",
        inbound_user
    );

    // UDP session demultiplexer: session_id → per-session state
    let udp_sessions: Arc<Mutex<HashMap<u32, UdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn UDP datagram receiver task
    {
        let conn_clone = conn.clone();
        let dispatcher_clone = dispatcher.clone();
        let udp_sessions_clone = Arc::clone(&udp_sessions);
        let src_addr_clone = src_addr;
        let inbound_user_clone = inbound_user.clone();
        tokio::spawn(async move {
            handle_udp_datagrams(
                conn_clone,
                src_addr_clone,
                dispatcher_clone,
                fw_mark,
                inbound_user_clone,
                udp_sessions_clone,
            )
            .await;
        });
    }

    // Accept bidirectional QUIC streams for TCP proxying
    loop {
        let bi = conn.accept_bi().await;
        match bi {
            Ok((send, recv)) => {
                let dispatcher = dispatcher.clone();
                let inbound_user = inbound_user.clone();
                tokio::spawn(async move {
                    handle_tcp_stream(
                        send,
                        recv,
                        src_addr,
                        dispatcher,
                        fw_mark,
                        inbound_user,
                    )
                    .await;
                });
            }
            Err(e) => {
                debug!("hysteria2 inbound {src_addr}: connection closed: {e}");
                break;
            }
        }
    }
}

/// Perform HTTP/3 authentication on the first request of the connection.
///
/// Returns the authenticated user name (may be `None` for unnamed users) plus
/// the live `h3` server connection. The caller MUST keep that connection alive
/// for the duration of the QUIC connection: `h3::server::Connection`'s `Drop`
/// closes the underlying QUIC connection, which would otherwise tear down every
/// subsequent proxy stream/datagram immediately after auth.
async fn authenticate(
    conn: &Connection,
    user_map: &HashMap<String, String>,
) -> anyhow::Result<(Option<String>, H3ServerConnection)> {
    use h3::server::RequestResolver;

    let h3_conn = H3QuinnConnection::new(conn.clone());
    let mut h3_server = h3::server::builder().build::<_, Bytes>(h3_conn).await?;

    let resolver: RequestResolver<_, _> = h3_server
        .accept()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no auth request received"))?;

    let (req, mut stream) = resolver.resolve_request().await?;

    // The Hysteria2 auth handshake is `POST https://hysteria/auth`. Reject
    // anything else with a 404 so unrelated requests aren't treated as auth.
    if req.method() != http::Method::POST || req.uri().path() != "/auth" {
        let resp = http::Response::builder().status(404).body(()).unwrap();
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return Err(anyhow::anyhow!(
            "unexpected hysteria2 auth request: {} {}",
            req.method(),
            req.uri().path()
        ));
    }

    // `http::HeaderMap::get` is case-insensitive, so a single lookup covers any
    // header casing the client uses.
    let provided_password = req
        .headers()
        .get("hysteria-auth")
        .and_then(|v| v.to_str().ok());

    // An empty/missing auth header must never authenticate, even if the server
    // was configured with an empty password — otherwise the listener is an
    // open relay.
    let matched = provided_password
        .filter(|p| !p.is_empty())
        .and_then(|p| user_map.get(p));

    if let Some(user_name) = matched {
        // Send 233 success response
        let resp = http::Response::builder()
            .status(233)
            .header("Hysteria-CC-RX", "auto")
            .header("Hysteria-UDP", "true")
            .header(
                "Hysteria-Padding",
                String::from_utf8_lossy(&padding(64..=512)).into_owned(),
            )
            .body(())
            .unwrap();
        stream.send_response(resp).await?;
        let _ = stream.finish().await;
        let name = if user_name.is_empty() {
            None
        } else {
            Some(user_name.clone())
        };
        Ok((name, h3_server))
    } else {
        // Send 401 failure response
        let resp = http::Response::builder()
            .status(401)
            .header(
                "Hysteria-Padding",
                String::from_utf8_lossy(&padding(64..=512)).into_owned(),
            )
            .body(())
            .unwrap();
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        Err(anyhow::anyhow!("invalid password"))
    }
}

/// Handle a single bidirectional QUIC stream as a TCP proxy session.
async fn handle_tcp_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    src_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<SocketMark>,
    inbound_user: Option<String>,
) {
    // Parse the Hysteria2 TCP request from the client
    let mut framed_recv = FramedRead::new(recv, Hy2TcpReqCodec);
    let req = match framed_recv.next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => {
            debug!("hysteria2 inbound {src_addr}: failed to read TCP request: {e}");
            return;
        }
        None => {
            debug!("hysteria2 inbound {src_addr}: stream closed before request");
            return;
        }
    };

    let dest = req.addr;

    // Send success response to client
    let mut framed_send = FramedWrite::new(send, Hy2TcpRespEncoder);
    if let Err(e) = framed_send.send(Hy2TcpResp::ok()).await {
        debug!("hysteria2 inbound {src_addr}: failed to send TCP response: {e}");
        return;
    }

    debug!(
        "hysteria2 inbound TCP: src={src_addr} dest={dest} user={inbound_user:?}"
    );

    // Recombine send + recv into a stream for the dispatcher. `into_parts`
    // (not `into_inner`) preserves any payload bytes the client pipelined into
    // the same read as the request frame; `into_inner` would discard them and
    // corrupt the first bytes of the proxied connection.
    let parts = framed_recv.into_parts();
    let recv = parts.io;
    let prefix = parts.read_buf.freeze();
    let send = framed_send.into_inner();

    let stream = HystStream::with_prefix(send, recv, prefix);

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Hysteria2,
        source: src_addr,
        so_mark: fw_mark,
        destination: dest,
        inbound_user,
        ..Default::default()
    };

    dispatcher.dispatch_stream(sess, Box::new(stream)).await;
}

/// Per-UDP-session state kept by the datagram demultiplexer: the fragment
/// reassembler plus (once the first complete packet has been dispatched) the
/// channel that feeds the dispatched session. Both are dropped together when
/// the session is removed, so neither leaks.
struct UdpSession {
    defragger: Defragger,
    /// `None` until a complete packet has been assembled and the session
    /// dispatched; `Some` afterwards.
    tx: Option<mpsc::Sender<HysUdpPacket>>,
}

/// Handle incoming QUIC datagrams as UDP proxy sessions.
async fn handle_udp_datagrams(
    conn: Connection,
    src_addr: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<SocketMark>,
    inbound_user: Option<String>,
    sessions: Arc<Mutex<HashMap<u32, UdpSession>>>,
) {
    loop {
        let data = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                debug!("hysteria2 inbound {src_addr}: datagram read error: {e}");
                break;
            }
        };

        let mut buf = BytesMut::from(data.as_ref());
        let pkt = match HysUdpPacket::decode(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    "hysteria2 inbound {src_addr}: failed to decode UDP datagram: \
                     {e}"
                );
                continue;
            }
        };

        let session_id = pkt.session_id;

        // Reassemble under the lock (never held across an await). The defragger
        // lives in the session entry, so it is evicted together with the
        // session and cannot leak.
        let mut guard = sessions.lock().await;
        let session = guard.entry(session_id).or_insert_with(|| UdpSession {
            defragger: Defragger::default(),
            tx: None,
        });

        let full_pkt = match session.defragger.feed(pkt) {
            Some(p) => p,
            None => continue, // still waiting for more fragments
        };

        if let Some(tx) = &session.tx {
            // Existing dispatched session: `try_send`, not `send().await`, so a
            // single stalled destination cannot head-of-line-block datagram
            // delivery for every other session on this connection.
            match tx.try_send(full_pkt) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    guard.remove(&session_id);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    trace!(
                        "hysteria2 inbound {src_addr}: udp session {session_id} \
                         queue full, dropping datagram"
                    );
                }
            }
            continue;
        }

        // First complete packet for this session: dispatch it.
        let dest = full_pkt.addr.clone();
        let (tx, rx) = mpsc::channel::<HysUdpPacket>(64);
        let _ = tx.try_send(full_pkt);
        session.tx = Some(tx);
        drop(guard);

        let datagram = Hysteria2InboundDatagram {
            rx,
            conn: conn.clone(),
            session_id,
            src_addr,
            inbound_user: inbound_user.clone(),
            sessions: Arc::clone(&sessions),
        };

        let sess = Session {
            network: Network::Udp,
            typ: Type::Hysteria2,
            source: src_addr,
            so_mark: fw_mark,
            destination: dest,
            inbound_user: inbound_user.clone(),
            ..Default::default()
        };

        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            let _ = dispatcher.dispatch_datagram(sess, Box::new(datagram)).await;
        });
    }
}

/// Inbound datagram abstraction for Hysteria2 UDP proxying.
///
/// - `Stream` side: yields `UdpPacket`s received from the QUIC client for this
///   session.
/// - `Sink` side: sends `UdpPacket`s back to the QUIC client as QUIC datagrams.
struct Hysteria2InboundDatagram {
    /// Receives assembled UDP packets from the datagram demultiplexer task.
    rx: mpsc::Receiver<HysUdpPacket>,
    conn: Connection,
    session_id: u32,
    /// Remote address of the QUIC client (source of all packets in this
    /// session).
    src_addr: SocketAddr,
    /// Authenticated user name for this session (if any).
    inbound_user: Option<String>,
    sessions: Arc<Mutex<HashMap<u32, UdpSession>>>,
}

impl std::fmt::Debug for Hysteria2InboundDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2InboundDatagram")
            .field("session_id", &self.session_id)
            .field("src_addr", &self.src_addr)
            .finish()
    }
}

impl Drop for Hysteria2InboundDatagram {
    fn drop(&mut self) {
        let sessions = Arc::clone(&self.sessions);
        let id = self.session_id;
        tokio::spawn(async move {
            sessions.lock().await.remove(&id);
        });
    }
}

impl Stream for Hysteria2InboundDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => Poll::Ready(Some(UdpPacket {
                data: pkt.data,
                src_addr: SocksAddr::Ip(self.src_addr),
                dst_addr: pkt.addr,
                inbound_user: self.inbound_user.clone(),
            })),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<UdpPacket> for Hysteria2InboundDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        // The address embedded in the reply datagram must be the *upstream*
        // source (where the packet came from), which the dispatcher places in
        // `src_addr`. `dst_addr` here is the QUIC client itself; sending that
        // would make every reply look like it originated from the client and
        // break client-side UDP session correlation (e.g. DNS).
        let reply_addr = item.src_addr;
        let max_size = this.conn.max_datagram_size().unwrap_or(1200);
        let pkt_id: u16 = rand::random();
        let frags =
            Fragments::new(this.session_id, pkt_id, reply_addr, max_size, item.data);
        for frag in frags {
            this.conn
                .send_datagram(frag)
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
