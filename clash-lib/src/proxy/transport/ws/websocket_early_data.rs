use std::{
    cmp,
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{Future, ready};
use http::{HeaderName, HeaderValue, Request, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    client_async_with_config, tungstenite::protocol::WebSocketConfig,
};
use tracing::warn;

use crate::{
    common::errors::{map_io_error, new_io_error},
    proxy::AnyStream,
};

use super::websocket::WebsocketConn;

type HandshakeFuture =
    Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send + Sync>>;

/// Lifecycle of an early-data WebSocket connection.
///
/// ```text
/// Idle ──first poll_write──▶ Connecting ──handshake ok──▶ Open
///  │                              └──handshake err──▶ Failed
///  └──poll_shutdown (nothing ever written)──▶ Closed
/// ```
///
/// The first write's payload (up to `early_data_len` bytes) is carried in the
/// upgrade request header, so the handshake can only *start* from
/// `poll_write`. Once started, any operation (read, write, flush, shutdown)
/// drives it, so a cancelled first write cannot leave the connection stuck.
enum State {
    /// Waiting for the first write to supply early data. Boxed: the request
    /// and config dwarf the other variants.
    Idle(Box<IdleParts>),
    /// Upgrade request in flight. `early` is the payload carried in its
    /// header, acknowledged to the writer once the handshake succeeds.
    Connecting {
        fut: HandshakeFuture,
        early: Vec<u8>,
    },
    /// Handshake complete; all I/O goes to the WebSocket stream.
    Open(AnyStream),
    /// Handshake failed; every subsequent operation errors.
    Failed,
    /// Shut down before anything was written: no connection was ever made.
    Closed,
}

struct IdleParts {
    stream: AnyStream,
    req: Request<()>,
    ws_config: Option<WebSocketConfig>,
}

impl State {
    fn name(&self) -> &'static str {
        match self {
            State::Idle(_) => "idle",
            State::Connecting { .. } => "connecting",
            State::Open(_) => "open",
            State::Failed => "failed",
            State::Closed => "closed",
        }
    }
}

pub struct WebsocketEarlyDataConn {
    state: State,
    /// Early data that went out in the upgrade request but has not yet been
    /// reported to a writer (the handshake may have been completed by a
    /// read/flush after the original write was cancelled).
    unacked_early: Option<Vec<u8>>,
    /// The handshake future only remembers the last task that polled it, so
    /// each side records its own waker and all are woken on completion.
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    early_data_header_name: String,
    early_data_len: usize,
}

impl Debug for WebsocketEarlyDataConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketEarlyDataConn")
            .field("state", &self.state.name())
            .field("early_data_header_name", &self.early_data_header_name)
            .field("early_data_len", &self.early_data_len)
            .finish()
    }
}

fn handshake_failed() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "websocket early data handshake failed",
    )
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "websocket early data connection shut down",
    )
}

impl WebsocketEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        early_data_len: usize,
    ) -> Self {
        Self {
            state: State::Idle(Box::new(IdleParts {
                stream,
                req,
                ws_config,
            })),
            unacked_early: None,
            read_waker: None,
            write_waker: None,
            flush_waker: None,
            early_data_header_name,
            early_data_len,
        }
    }

    fn proxy_stream(
        stream: AnyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
    ) -> HandshakeFuture {
        async fn run(
            stream: AnyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
        ) -> io::Result<AnyStream> {
            let (stream, resp) = client_async_with_config(req, stream, config)
                .await
                .map_err(map_io_error)?;
            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(new_io_error(
                    "msg: websocket early data handshake failed",
                ));
            }
            let rv = Box::new(WebsocketConn::from_websocket(stream));
            Ok(rv)
        }

        Box::pin(run(stream, req, config))
    }

    /// `Idle` → `Connecting`: put the first `early_data_len` bytes of `buf`
    /// into the upgrade request header and start the handshake.
    fn start_handshake(&mut self, buf: &[u8]) -> io::Result<()> {
        let State::Idle(idle) = std::mem::replace(&mut self.state, State::Failed)
        else {
            unreachable!("start_handshake called outside Idle");
        };
        let IdleParts {
            stream,
            mut req,
            ws_config,
        } = *idle;

        let sent = cmp::min(self.early_data_len, buf.len());
        let name = HeaderName::from_bytes(self.early_data_header_name.as_bytes())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;
        let value = HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(&buf[..sent]))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        req.headers_mut().insert(name, value);

        self.state = State::Connecting {
            fut: Self::proxy_stream(stream, req, ws_config),
            early: buf[..sent].to_vec(),
        };
        Ok(())
    }

    /// Drive `Connecting` to `Open` or `Failed`, waking every parked side on
    /// completion. Callers record their own waker before calling this.
    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let State::Connecting { fut, early } = &mut self.state else {
            return Poll::Ready(Ok(()));
        };
        let res = ready!(fut.as_mut().poll(cx));
        let early = std::mem::take(early);
        let out = match res {
            Ok(stream) => {
                self.state = State::Open(stream);
                self.unacked_early = Some(early);
                Ok(())
            }
            Err(e) => {
                self.state = State::Failed;
                Err(e)
            }
        };
        self.wake_parked();
        Poll::Ready(out)
    }

    fn wake_parked(&mut self) {
        for w in [
            self.read_waker.take(),
            self.write_waker.take(),
            self.flush_waker.take(),
        ]
        .into_iter()
        .flatten()
        {
            w.wake();
        }
    }
}

impl AsyncRead for WebsocketEarlyDataConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                State::Open(s) => return Pin::new(s).poll_read(cx, buf),
                State::Failed => return Poll::Ready(Err(handshake_failed())),
                // Never connected and never will be: EOF.
                State::Closed => return Poll::Ready(Ok(())),
                // Only a write can start the handshake (it supplies the
                // early data), so wait for one.
                State::Idle(_) => {
                    this.read_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                State::Connecting { .. } => {
                    this.read_waker = Some(cx.waker().clone());
                    ready!(this.poll_handshake(cx))?;
                }
            }
        }
    }
}

impl AsyncWrite for WebsocketEarlyDataConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                State::Idle(_) => {
                    if let Err(e) = this.start_handshake(buf) {
                        this.wake_parked();
                        return Poll::Ready(Err(e));
                    }
                }
                State::Connecting { .. } => {
                    this.write_waker = Some(cx.waker().clone());
                    ready!(this.poll_handshake(cx))?;
                }
                State::Open(s) => {
                    if let Some(early) = this.unacked_early.take()
                        && !early.is_empty()
                    {
                        // The early data is already on the wire. If this is
                        // the retry of that first write, acknowledge it
                        // without sending it again. AsyncWrite does not
                        // promise a same-buffer retry; if the original write
                        // was cancelled and this is new data, send it as is.
                        if buf.starts_with(&early) {
                            return Poll::Ready(Ok(early.len()));
                        }
                        warn!(
                            "websocket early data from a cancelled write was \
                             already sent ({} bytes)",
                            early.len()
                        );
                    }
                    return Pin::new(s).poll_write(cx, buf);
                }
                State::Failed => return Poll::Ready(Err(handshake_failed())),
                State::Closed => return Poll::Ready(Err(closed())),
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                State::Open(s) => return Pin::new(s).poll_flush(cx),
                State::Failed => return Poll::Ready(Err(handshake_failed())),
                // Nothing has been written, so nothing to flush.
                State::Idle(_) | State::Closed => return Poll::Ready(Ok(())),
                State::Connecting { .. } => {
                    this.flush_waker = Some(cx.waker().clone());
                    ready!(this.poll_handshake(cx))?;
                }
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                State::Open(s) => return Pin::new(s).poll_shutdown(cx),
                State::Failed => return Poll::Ready(Err(handshake_failed())),
                State::Closed => return Poll::Ready(Ok(())),
                State::Idle(_) => {
                    // Nothing was ever written, so no upgrade was sent; drop
                    // the transport and let a parked reader see EOF.
                    this.state = State::Closed;
                    this.wake_parked();
                    return Poll::Ready(Ok(()));
                }
                State::Connecting { .. } => {
                    this.flush_waker = Some(cx.waker().clone());
                    ready!(this.poll_handshake(cx))?;
                }
            }
        }
    }
}

impl crate::proxy::ProxyStream for WebsocketEarlyDataConn {}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_tungstenite::{
        WebSocketStream, accept_hdr_async,
        tungstenite::{
            Message,
            handshake::server::{Request as SrvReq, Response as SrvResp},
        },
    };

    use super::*;
    use std::time::Duration;

    const HDR: &str = "Sec-WebSocket-Protocol";

    fn client_req() -> Request<()> {
        Request::builder()
            .method("GET")
            .uri("ws://example.com/")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header(HDR, "placeholder")
            .body(())
            .unwrap()
    }

    fn conn(early_len: usize) -> (WebsocketEarlyDataConn, DuplexStream) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let c = WebsocketEarlyDataConn::new(
            Box::new(client),
            client_req(),
            None,
            HDR.to_owned(),
            early_len,
        );
        (c, server)
    }

    /// Accept the upgrade, echoing the early-data header back so the client's
    /// subprotocol check passes, and return the decoded early data.
    // The callback's error type is fixed by tungstenite's `Callback` trait.
    #[allow(clippy::result_large_err)]
    async fn accept(
        server: DuplexStream,
    ) -> (WebSocketStream<DuplexStream>, Vec<u8>) {
        let mut early = None;
        let ws = accept_hdr_async(server, |req: &SrvReq, mut resp: SrvResp| {
            let v = req.headers().get(HDR).unwrap().clone();
            early = Some(URL_SAFE_NO_PAD.decode(v.as_bytes()).unwrap());
            resp.headers_mut().insert(HDR, v);
            Ok(resp)
        })
        .await
        .unwrap();
        (ws, early.unwrap())
    }

    #[tokio::test]
    async fn test_first_write_carries_early_data() {
        let (mut c, server) = conn(4);
        let srv = tokio::spawn(async move {
            let (mut ws, early) = accept(server).await;
            assert_eq!(early, b"hell");
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(msg.into_data().as_ref(), b"o");
            ws.send(Message::binary(b"pong".to_vec())).await.unwrap();
            ws
        });

        // Only the first 4 bytes fit in the header; the caller sees a short
        // write and sends the rest over the open stream.
        c.write_all(b"hello").await.unwrap();
        c.flush().await.unwrap();
        let mut out = [0u8; 4];
        c.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
        srv.await.unwrap();
    }

    /// Waker that records whether it was woken.
    struct Flag(std::sync::atomic::AtomicBool);
    impl futures::task::ArcWake for Flag {
        fn wake_by_ref(arc_self: &std::sync::Arc<Self>) {
            arc_self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Poll `c` for a read once with a recording waker; assert it parks and
    /// return the flag that flips when that waker is woken.
    fn park_reader(c: &mut WebsocketEarlyDataConn) -> std::sync::Arc<Flag> {
        let flag = std::sync::Arc::new(Flag(false.into()));
        let waker = futures::task::waker(flag.clone());
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0u8; 4];
        let mut rb = ReadBuf::new(&mut bytes);
        assert!(Pin::new(c).poll_read(&mut cx, &mut rb).is_pending());
        flag
    }

    fn woken(flag: &Flag) -> bool {
        flag.0.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn test_reader_parked_until_handshake() {
        let (mut c, server) = conn(16);
        let flag = park_reader(&mut c);
        assert!(!woken(&flag));

        let srv = tokio::spawn(async move {
            let (mut ws, early) = accept(server).await;
            assert_eq!(early, b"req");
            ws.send(Message::binary(b"ok".to_vec())).await.unwrap();
            ws
        });
        c.write_all(b"req").await.unwrap();
        assert!(woken(&flag), "parked reader must be woken on handshake");

        let mut out = [0u8; 2];
        c.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_failure_is_terminal() {
        let (mut c, server) = conn(16);
        let flag = park_reader(&mut c);

        // Server hangs up without completing the upgrade.
        drop(server);
        assert!(c.write(b"data").await.is_err());
        assert!(woken(&flag), "parked reader must be woken on failure");

        // Subsequent calls must error, not panic by re-polling the
        // finished handshake future.
        let err = c.write(b"data").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        let err = c.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    /// Poll a first write once (the server has not answered, so it parks in
    /// Connecting) and then abandon it, as a timeout/select! would.
    async fn start_and_cancel_write(c: &mut WebsocketEarlyDataConn, data: &[u8]) {
        let fut = c.write(data);
        tokio::pin!(fut);
        assert!(futures::poll!(fut.as_mut()).is_pending());
    }

    #[tokio::test]
    async fn test_cancelled_write_then_read_drives_handshake() {
        let (mut c, server) = conn(16);
        start_and_cancel_write(&mut c, b"req").await;

        let srv = tokio::spawn(async move {
            let (mut ws, early) = accept(server).await;
            assert_eq!(early, b"req");
            ws.send(Message::binary(b"ok".to_vec())).await.unwrap();
            let next = ws.next().await.unwrap().unwrap();
            next.into_data().to_vec()
        });

        // Only reads from here on: they must complete the handshake.
        let mut out = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut out))
            .await
            .expect("read hung: handshake not driven by poll_read")
            .unwrap();
        assert_eq!(&out, b"ok");

        // Retrying the original write is acknowledged without resending.
        assert_eq!(c.write(b"req").await.unwrap(), 3);
        c.write_all(b"more").await.unwrap();
        c.flush().await.unwrap();
        assert_eq!(srv.await.unwrap(), b"more");
    }

    #[tokio::test]
    async fn test_cancelled_write_then_different_data_is_sent() {
        let (mut c, server) = conn(16);
        start_and_cancel_write(&mut c, b"req").await;

        let srv = tokio::spawn(async move {
            let (mut ws, early) = accept(server).await;
            assert_eq!(early, b"req");
            ws.next().await.unwrap().unwrap().into_data().to_vec()
        });
        // A different buffer must be written in full, not acknowledged as
        // the stale early data.
        c.write_all(b"zzz").await.unwrap();
        c.flush().await.unwrap();
        assert_eq!(srv.await.unwrap(), b"zzz");
    }

    #[tokio::test]
    async fn test_shutdown_before_any_write() {
        let (mut c, _server) = conn(16);
        let flag = park_reader(&mut c);

        tokio::time::timeout(Duration::from_secs(1), c.shutdown())
            .await
            .expect("shutdown before write must not hang")
            .unwrap();
        assert!(woken(&flag), "parked reader must be woken");
        assert_eq!(c.read(&mut [0u8; 4]).await.unwrap(), 0, "EOF");
        let err = c.write(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_flush_before_any_write_is_ready() {
        let (mut c, _server) = conn(16);
        tokio::time::timeout(Duration::from_secs(1), c.flush())
            .await
            .expect("flush with nothing written must not hang")
            .unwrap();
    }
}
