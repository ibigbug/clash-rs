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
///                                 │
///                                 └──handshake err──▶ Failed
/// ```
///
/// The first write's payload (up to `early_data_len` bytes) is carried in the
/// upgrade request header, so nothing can be read or flushed until the
/// handshake completes.
enum State {
    /// Waiting for the first write to supply early data. Boxed: the request
    /// and config dwarf the other variants.
    Idle(Box<IdleParts>),
    /// Upgrade request sent; `sent` is how many bytes of the caller's first
    /// buffer it carries and is reported once the handshake succeeds.
    Connecting { fut: HandshakeFuture, sent: usize },
    /// Handshake complete; all I/O goes to the WebSocket stream.
    Open(AnyStream),
    /// Handshake failed; every subsequent operation errors.
    Failed,
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
        }
    }
}

pub struct WebsocketEarlyDataConn {
    state: State,
    /// Reader parked until the handshake finishes.
    read_waker: Option<Waker>,
    /// Flusher/shutdown parked until the handshake finishes.
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
            read_waker: None,
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
            sent,
        };
        Ok(())
    }

    fn wake_parked(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.flush_waker.take() {
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
        match &mut this.state {
            State::Open(s) => Pin::new(s).poll_read(cx, buf),
            State::Failed => Poll::Ready(Err(handshake_failed())),
            State::Idle(_) | State::Connecting { .. } => {
                this.read_waker = Some(cx.waker().clone());
                Poll::Pending
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
                State::Connecting { fut, sent } => {
                    let sent = *sent;
                    let res = ready!(fut.as_mut().poll(cx));
                    let (next, out) = match res {
                        Ok(stream) => (State::Open(stream), Ok(sent)),
                        Err(e) => (State::Failed, Err(e)),
                    };
                    this.state = next;
                    this.wake_parked();
                    return Poll::Ready(out);
                }
                State::Open(s) => return Pin::new(s).poll_write(cx, buf),
                State::Failed => return Poll::Ready(Err(handshake_failed())),
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            State::Open(s) => Pin::new(s).poll_flush(cx),
            State::Failed => Poll::Ready(Err(handshake_failed())),
            State::Idle(_) | State::Connecting { .. } => {
                this.flush_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            State::Open(s) => Pin::new(s).poll_shutdown(cx),
            State::Failed => Poll::Ready(Err(handshake_failed())),
            State::Idle(_) | State::Connecting { .. } => {
                this.flush_waker = Some(cx.waker().clone());
                Poll::Pending
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

    #[tokio::test]
    async fn test_reader_parked_until_handshake() {
        let (c, server) = conn(16);
        let (mut rd, mut wr) = tokio::io::split(c);
        let read = tokio::spawn(async move {
            let mut out = [0u8; 2];
            rd.read_exact(&mut out).await.unwrap();
            out
        });
        tokio::task::yield_now().await;
        assert!(!read.is_finished());

        let srv = tokio::spawn(async move {
            let (mut ws, early) = accept(server).await;
            assert_eq!(early, b"req");
            ws.send(Message::binary(b"ok".to_vec())).await.unwrap();
            ws
        });
        wr.write_all(b"req").await.unwrap();
        assert_eq!(&read.await.unwrap(), b"ok");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_handshake_failure_is_terminal() {
        let (c, server) = conn(16);
        let (mut rd, mut wr) = tokio::io::split(c);
        let read = tokio::spawn(async move { rd.read(&mut [0u8; 4]).await });
        tokio::task::yield_now().await;

        // Server hangs up without completing the upgrade.
        drop(server);
        assert!(wr.write(b"data").await.is_err());
        // Subsequent calls must error, not panic by re-polling the
        // finished handshake future, and the parked reader must wake.
        let err = wr.write(b"data").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        let err = read.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }
}
