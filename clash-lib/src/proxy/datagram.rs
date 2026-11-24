use crate::session::SocksAddr;
use std::fmt::{Debug, Display, Formatter};

#[derive(Clone)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    /// Logical destination for this packet. For fake-IP setups the dispatcher
    /// rewrites this to the resolved domain before forwarding, so proxy
    /// outbounds always see the intended domain rather than a fake-IP.
    pub dst_addr: SocksAddr,
    /// Authenticated user name from SS2022 EIH, propagated to the dispatcher
    /// session for per-user traffic attribution. `None` for all other
    /// protocols.
    pub inbound_user: Option<String>,
}

impl Default for UdpPacket {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: SocksAddr::any_ipv4(),
            inbound_user: None,
        }
    }
}

impl Debug for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("src_addr", &self.src_addr)
            .field("dst_addr", &self.dst_addr)
            .finish()
    }
}

impl Display for UdpPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP Packet from {} to {} with {} bytes",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
            inbound_user: None,
        }
    }
}

/// Send-side state for a `Sink<UdpPacket>` that frames packets onto a byte
/// stream (UDP-over-TCP style outbounds).
///
/// ```text
/// Idle ──start(frame)──▶ Writing ──drained──▶ Flushing ──▶ Idle
///                          │  │                   └─ flush err ─▶ Idle
///                          │  └─ err, no bytes written ─▶ Idle (dropped)
///                          └─── err after partial write ─▶ Broken (terminal)
/// ```
///
/// A frame is encoded once in `start_send` and drained across as many polls
/// as the inner writer needs. If a write fails before any byte of the frame
/// was accepted, the frame is dropped and the sink stays usable. If it fails
/// after part of the frame is on the wire, the byte stream is no longer
/// frame-aligned, so the sink becomes `Broken` and refuses every later frame
/// rather than let the peer misparse them.
#[derive(Debug, Default)]
pub(crate) enum StreamSendState {
    #[default]
    Idle,
    Writing {
        buf: bytes::BytesMut,
        /// At least one byte of this frame has been written.
        started: bool,
    },
    Flushing,
    Broken,
}

fn desynced() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "udp stream desynchronized by a partially written frame",
    )
}

impl StreamSendState {
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    /// Queue an encoded frame. Callers must only do this from `start_send`,
    /// i.e. after `poll_ready` (and therefore `poll_send`) returned `Ready`.
    pub(crate) fn start(&mut self, frame: bytes::BytesMut) -> std::io::Result<()> {
        match self {
            Self::Idle => {
                *self = Self::Writing {
                    buf: frame,
                    started: false,
                };
                Ok(())
            }
            Self::Broken => Err(desynced()),
            Self::Writing { .. } | Self::Flushing => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "previous packet not yet sent",
            )),
        }
    }

    /// Drive the queued frame to completion: write it fully, then flush.
    /// Returns `Ready(Ok(()))` immediately when idle.
    pub(crate) fn poll_send<W>(
        &mut self,
        mut w: std::pin::Pin<&mut W>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>>
    where
        W: tokio::io::AsyncWrite + ?Sized,
    {
        use bytes::Buf;
        use std::task::{Poll, ready};

        loop {
            match self {
                Self::Idle => return Poll::Ready(Ok(())),
                Self::Broken => return Poll::Ready(Err(desynced())),
                Self::Writing { buf, started } => {
                    if buf.is_empty() {
                        *self = Self::Flushing;
                        continue;
                    }
                    let res = match ready!(w.as_mut().poll_write(cx, buf)) {
                        // Ok(0) from poll_write means the stream is closed.
                        Ok(0) => Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write udp packet: stream closed",
                        )),
                        res => res,
                    };
                    match res {
                        Ok(n) => {
                            buf.advance(n);
                            *started = true;
                        }
                        Err(e) => {
                            *self = if *started { Self::Broken } else { Self::Idle };
                            return Poll::Ready(Err(e));
                        }
                    }
                }
                Self::Flushing => {
                    // The whole frame is written, so the stream stays
                    // frame-aligned even if the flush fails.
                    let res = ready!(w.as_mut().poll_flush(cx));
                    *self = Self::Idle;
                    return Poll::Ready(res);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StreamSendState;
    use bytes::BytesMut;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::AsyncWrite;

    /// Writer that accepts at most `chunk` bytes per call and returns Pending
    /// on every other call, to exercise resumption.
    struct Trickle {
        out: Vec<u8>,
        chunk: usize,
        toggle: bool,
        closed: bool,
        flushes: usize,
        /// Return an error once this many bytes have been accepted.
        fail_after: Option<usize>,
    }

    impl AsyncWrite for Trickle {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.closed {
                return Poll::Ready(Ok(0));
            }
            if self.fail_after.is_some_and(|n| self.out.len() >= n) {
                return Poll::Ready(Err(io::ErrorKind::Interrupted.into()));
            }
            self.toggle = !self.toggle;
            if self.toggle {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = buf.len().min(self.chunk);
            self.out.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn trickle(closed: bool) -> Trickle {
        Trickle {
            out: vec![],
            chunk: 3,
            toggle: false,
            closed,
            flushes: 0,
            fail_after: None,
        }
    }

    #[tokio::test]
    async fn drains_across_pending_then_flushes() {
        let mut w = trickle(false);
        let mut st = StreamSendState::default();
        st.start(BytesMut::from(&b"hello world"[..])).unwrap();
        assert!(st.start(BytesMut::new()).is_err(), "busy sink rejects");

        std::future::poll_fn(|cx| st.poll_send(Pin::new(&mut w), cx))
            .await
            .unwrap();
        assert_eq!(w.out, b"hello world");
        assert_eq!(w.flushes, 1);
        assert!(st.is_idle());
    }

    #[tokio::test]
    async fn write_zero_drops_frame_and_recovers() {
        let mut w = trickle(true);
        let mut st = StreamSendState::default();
        st.start(BytesMut::from(&b"x"[..])).unwrap();
        let err = std::future::poll_fn(|cx| st.poll_send(Pin::new(&mut w), cx))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        // Not wedged: idle again and accepts the next frame.
        assert!(st.is_idle());
        st.start(BytesMut::from(&b"y"[..])).unwrap();
    }

    #[tokio::test]
    async fn error_after_partial_write_breaks_sink() {
        let mut w = trickle(false);
        w.fail_after = Some(3);
        let mut st = StreamSendState::default();
        st.start(BytesMut::from(&b"frame-one"[..])).unwrap();
        // Writes 3 bytes, then the writer errors mid-frame.
        assert!(
            std::future::poll_fn(|cx| st.poll_send(Pin::new(&mut w), cx))
                .await
                .is_err()
        );
        assert_eq!(w.out, b"fra");

        // Even if the writer recovers, no later frame may follow the fragment.
        w.fail_after = None;
        let err = st.start(BytesMut::from(&b"frame-two"[..])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let err = std::future::poll_fn(|cx| st.poll_send(Pin::new(&mut w), cx))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(w.out, b"fra", "nothing written after the fragment");
    }

    #[tokio::test]
    async fn error_before_any_byte_drops_frame_only() {
        let mut w = trickle(false);
        w.fail_after = Some(0);
        let mut st = StreamSendState::default();
        st.start(BytesMut::from(&b"lost"[..])).unwrap();
        assert!(
            std::future::poll_fn(|cx| st.poll_send(Pin::new(&mut w), cx))
                .await
                .is_err()
        );
        assert!(st.is_idle(), "stream still frame-aligned, sink reusable");

        w.fail_after = None;
        st.start(BytesMut::from(&b"next"[..])).unwrap();
        std::future::poll_fn(|cx| st.poll_send(Pin::new(&mut w), cx))
            .await
            .unwrap();
        assert_eq!(w.out, b"next");
    }
}
