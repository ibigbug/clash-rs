//! Clash stream adapter for a Wind TUIC TCP stream.
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wind_quic::quinn::{QuinnRecv, QuinnSend};

/// A connected TUIC TCP stream returned by `TuicOutbound::connect_tcp`.
///
/// The joined QUIC halves keep the connection alive on their own; the Wind
/// outbound is owned by the handler for the connection's lifetime.
pub struct TuicTcpStream {
    pub io: tokio::io::Join<QuinnRecv, QuinnSend>,
}

impl crate::proxy::ProxyStream for TuicTcpStream {}

impl AsyncRead for TuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for TuicTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
