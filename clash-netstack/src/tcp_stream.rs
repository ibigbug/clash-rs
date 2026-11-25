use crate::{stack::IfaceEvent, tcp_listener::TcpStreamHandle};
use log::{error, trace};
use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

pub struct TcpStream {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,

    pub(crate) handle: Arc<TcpStreamHandle>,
    pub(crate) stack_notifier:
        tokio::sync::mpsc::UnboundedSender<IfaceEvent<'static>>,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        trace!(
            "TcpStream dropped: {} <-> {}",
            self.local_addr, self.remote_addr
        );

        // Tells poll_sockets to drain send_buffer and issue FIN, and closes
        // both halves so any concurrent poll_read / poll_write unblocks.
        self.handle.close.app_dropped();
        self.handle.recv_waker.wake();
        self.handle.send_waker.wake();
        if let Err(e) = self.stack_notifier.send(IfaceEvent::TcpSocketClosed) {
            error!("Failed to notify TCP socket closed: {e}");
        }
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
        let (r, w) = tokio::io::split(self);
        (r, w)
    }

    fn notify_tcp_socket_ready(&self) {
        if let Err(e) = self.stack_notifier.send(IfaceEvent::TcpSocketReady) {
            error!("Failed to notify TCP socket ready: {e}");
        }
    }
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        trace!(
            "TcpStream::poll_read called: {} <-> {}",
            self.local_addr, self.remote_addr
        );
        let read_buf = &self.handle.recv_buffer;

        if read_buf.is_empty() {
            // Register waker FIRST, then re-check to close the TOCTOU window.
            // If poll_sockets enqueues data between is_empty() and register(),
            // wake() is a no-op (no waker stored). The re-check below detects
            // the buffer is now non-empty and falls through to read it.
            self.handle.recv_waker.register(cx.waker());
            // Load the close flag BEFORE re-checking the buffer. poll_sockets
            // enqueues data and only then sets READ_CLOSED / SOCKET_GONE, so
            // if we observe the flag (Acquire) every byte enqueued before it
            // is visible to the emptiness check below. Checking in the other
            // order lets data + FIN land between the two loads and we would
            // report EOF with the final bytes still in recv_buffer.
            let closed = self.handle.close.read_eof();
            if read_buf.is_empty() {
                // Return EOF when smoltcp is done (socket removed) OR when the
                // read half was explicitly closed (peer FIN / local drop).
                if closed {
                    trace!("TcpStream::poll_read: socket closed, returning EOF");
                    return std::task::Poll::Ready(Ok(()));
                }
                trace!(
                    "TcpStream::poll_read: recv buffer is empty, waiting for data"
                );
                return std::task::Poll::Pending;
            }
        }

        buf.initialize_unfilled();
        let recv_buf = unsafe {
            std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(
                buf.unfilled_mut(),
            )
        };
        let n = read_buf.dequeue_slice(recv_buf);
        buf.advance(n);

        self.notify_tcp_socket_ready();
        trace!("TcpStream::poll_read: (proxy)read {n} bytes from recv buffer");

        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.handle.close.write_refused() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "TCP stream write half closed",
            )));
        }

        let send_buf = &self.handle.send_buffer;

        if send_buf.is_full() {
            // Register waker FIRST, then re-check to close the TOCTOU window.
            // If poll_sockets drains the buffer between is_full() and
            // register(), wake() is a no-op (no waker stored). The
            // re-check below detects the buffer is now non-full and
            // falls through to enqueue data.
            self.handle.send_waker.register(cx.waker());
            if send_buf.is_full() {
                trace!(
                    "TcpStream::poll_write: send buffer is full, waiting for space"
                );
                self.notify_tcp_socket_ready();
                return std::task::Poll::Pending;
            }
        }

        let n = send_buf.enqueue_slice(buf);

        self.notify_tcp_socket_ready();
        trace!("TcpStream::poll_write: (proxy)write {n} bytes to send buffer");

        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.notify_tcp_socket_ready();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        trace!("TcpStream::poll_shutdown called, client side closing");
        self.handle.close.shutdown_requested();
        self.handle.send_waker.wake();
        // Notify only after the flag is set. Notifying first (as the old
        // poll_flush call did) lets poll_sockets handle the event before the
        // flag is visible; nothing then wakes it until the next packet, app
        // I/O or the 28 s keep-alive, delaying the FIN that long.
        self.notify_tcp_socket_ready();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_listener::TcpStreamHandle;
    use futures::task::noop_waker_ref;
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        sync::mpsc,
    };

    fn build_stream() -> (TcpStream, mpsc::UnboundedReceiver<IfaceEvent<'static>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            TcpStream {
                local_addr: "127.0.0.1:12345".parse().unwrap(),
                remote_addr: "127.0.0.1:80".parse().unwrap(),
                handle: Arc::new(TcpStreamHandle::new(
                    "127.0.0.1:12345".parse().unwrap(),
                )),
                stack_notifier: tx,
            },
            rx,
        )
    }

    fn noop_cx() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    #[test]
    fn poll_read_returns_eof_after_peer_close() {
        let (mut stream, _rx) = build_stream();
        stream.handle.close.peer_fin();
        let mut cx = noop_cx();
        let mut bytes = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut bytes);

        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);

        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(buf.filled().len(), 0);
    }

    #[test]
    fn poll_read_drains_data_before_eof() {
        let (mut stream, _rx) = build_stream();
        // poll_sockets order: enqueue the final bytes, then mark peer FIN.
        stream.handle.recv_buffer.enqueue_slice(b"tail");
        stream.handle.close.peer_fin();
        let mut cx = noop_cx();
        let mut bytes = [0u8; 16];

        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert_eq!(buf.filled(), b"tail");

        let mut buf = tokio::io::ReadBuf::new(&mut bytes);
        let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert!(buf.filled().is_empty(), "EOF only after the buffer drains");
    }

    /// Stress the data-then-FIN handoff across threads: the reader must see
    /// every byte before EOF, however the two stores interleave with its
    /// loads.
    #[test]
    fn poll_read_never_loses_tail_bytes_racing_fin() {
        for _ in 0..10_000 {
            let (stream, _rx) = build_stream();
            let handle = stream.handle.clone();
            let producer = std::thread::spawn(move || {
                handle.recv_buffer.enqueue_slice(b"x");
                handle.close.peer_fin();
                handle.recv_waker.wake();
            });
            let mut stream = stream;
            let mut cx = noop_cx();
            let mut got = 0usize;
            loop {
                let mut bytes = [0u8; 4];
                let mut buf = tokio::io::ReadBuf::new(&mut bytes);
                match Pin::new(&mut stream).poll_read(&mut cx, &mut buf) {
                    Poll::Ready(Ok(())) if buf.filled().is_empty() => break,
                    Poll::Ready(Ok(())) => got += buf.filled().len(),
                    Poll::Ready(Err(e)) => panic!("{e}"),
                    Poll::Pending => std::hint::spin_loop(),
                }
            }
            producer.join().unwrap();
            assert_eq!(got, 1, "tail byte lost before EOF");
        }
    }

    #[test]
    fn poll_shutdown_marks_write_shutdown() {
        let (mut stream, mut rx) = build_stream();
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_shutdown(&mut cx);

        assert!(matches!(result, Poll::Ready(Ok(()))));
        assert!(stream.handle.close.is_shutdown_requested());
        assert!(matches!(rx.try_recv(), Ok(IfaceEvent::TcpSocketReady)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn poll_write_fails_after_write_close() {
        let (mut stream, _rx) = build_stream();
        stream.handle.close.send_closed();
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_write(&mut cx, b"hello");

        assert!(
            matches!(result, Poll::Ready(Err(err)) if err.kind() == ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn poll_flush_still_succeeds_when_notifier_closed() {
        let (mut stream, rx) = build_stream();
        drop(rx);
        let mut cx = noop_cx();

        let result = Pin::new(&mut stream).poll_flush(&mut cx);

        assert!(matches!(result, Poll::Ready(Ok(()))));
    }
}
