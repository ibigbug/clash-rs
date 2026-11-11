use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::oneshot,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use wind_core::{FlowContext, Outbound};

use crate::proxy::ProxyStream;

/// Wind begins polling the supplied stream only after CONNECT authentication
/// and TLS have succeeded. That first poll is the dial-completion boundary.
struct ReadyStream {
    io: DuplexStream,
    ready: Option<oneshot::Sender<()>>,
}

impl ReadyStream {
    fn ready(&mut self) {
        if let Some(tx) = self.ready.take() {
            let _ = tx.send(());
        }
    }
}

impl AsyncRead for ReadyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.ready();
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReadyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.ready();
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

pub(super) struct Stream {
    io: DuplexStream,
    // Also aborts a pending dial when its caller times out or is cancelled.
    _task: AbortOnDropHandle<io::Result<()>>,
}

pub(super) async fn connect(
    outbound: Arc<dyn Outbound>,
    flow: FlowContext,
    cancel: CancellationToken,
) -> io::Result<Stream> {
    let (io, remote) = tokio::io::duplex(64 * 1024);
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut task = AbortOnDropHandle::new(tokio::spawn(async move {
        tokio::select! {
            result = outbound.handle_tcp(flow, Box::new(ReadyStream { io: remote, ready: Some(ready_tx) })) => {
                result.map_err(|error| io::Error::other(format!("Naive CONNECT: {error}")))
            }
            _ = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "Naive connection cancelled")),
        }
    }));
    tokio::select! {
        biased;
        result = &mut task => {
            result.map_err(io::Error::other)??;
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Naive ended before CONNECT completed"))
        }
        ready = ready_rx => {
            if ready.is_err() {
                task.await.map_err(io::Error::other)??;
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Naive ended before CONNECT completed"));
            }
            Ok(Stream { io, _task: task })
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
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

impl ProxyStream for Stream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wind_core::{tcp::AbstractTcpStream, udp::UdpStream};

    struct TestOutbound {
        fail: bool,
    }
    #[async_trait::async_trait]
    impl Outbound for TestOutbound {
        async fn handle_tcp(
            &self,
            _: FlowContext,
            mut stream: Box<dyn AbstractTcpStream>,
        ) -> eyre::Result<()> {
            if self.fail {
                eyre::bail!("authentication rejected");
            }
            let mut data = [0; 4];
            stream.read_exact(&mut data).await?;
            stream.write_all(&data).await?;
            std::future::pending().await
        }

        async fn handle_udp(
            &self,
            _: FlowContext,
            _: UdpStream,
        ) -> eyre::Result<()> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn naive_connect_propagates_failure_before_returning_stream() {
        let result = connect(
            Arc::new(TestOutbound { fail: true }),
            super::super::flow(
                &Default::default(),
                wind_core::rule::NetworkType::Tcp,
            ),
            CancellationToken::new(),
        )
        .await;
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("authentication rejected")
        );
    }

    #[tokio::test]
    async fn naive_stream_relays_and_observes_handler_cancellation() {
        let cancel = CancellationToken::new();
        let mut stream = connect(
            Arc::new(TestOutbound { fail: false }),
            super::super::flow(
                &Default::default(),
                wind_core::rule::NetworkType::Tcp,
            ),
            cancel.clone(),
        )
        .await
        .unwrap();
        stream.write_all(b"test").await.unwrap();
        let mut data = [0; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"test");
        cancel.cancel();
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read(&mut data),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(n, 0);
    }
}
