use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
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
    remote_half_closed: Arc<AtomicBool>,
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
        // Publish the remote FIN before the duplex wakes its reader.
        self.remote_half_closed.store(true, Ordering::Release);
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

pub(super) struct Stream {
    io: DuplexStream,
    remote_half_closed: Arc<AtomicBool>,
    task: Option<AbortOnDropHandle<io::Result<()>>>,
    write_shutdown: WriteShutdown,
}

#[derive(PartialEq, Eq)]
enum WriteShutdown {
    Open,
    Draining,
    Complete,
}

impl Stream {
    fn poll_relay(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(task) = &mut self.task else {
            return Poll::Ready(Ok(()));
        };
        let result = ready!(Pin::new(task).poll(cx));
        self.task = None;
        Poll::Ready(result.map_err(io::Error::other)?)
    }
}

pub(super) async fn connect(
    outbound: Arc<dyn Outbound>,
    flow: FlowContext,
    cancel: CancellationToken,
) -> io::Result<Stream> {
    let (io, remote) = tokio::io::duplex(64 * 1024);
    let (ready_tx, ready_rx) = oneshot::channel();
    let remote_half_closed = Arc::new(AtomicBool::new(false));
    let remote = ReadyStream {
        io: remote,
        ready: Some(ready_tx),
        remote_half_closed: remote_half_closed.clone(),
    };
    let task = AbortOnDropHandle::new(tokio::spawn(async move {
        tokio::select! {
            result = outbound.handle_tcp(flow, Box::new(remote)) => {
                result.map_err(|error| io::Error::other(format!("Naive CONNECT: {error}")))
            }
            _ = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "Naive connection cancelled")),
        }
    }));
    // A successful CONNECT stays ready even if the relay has already ended.
    if ready_rx.await.is_err() {
        task.await.map_err(io::Error::other)??;
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Naive ended before CONNECT completed",
        ));
    }
    Ok(Stream {
        io,
        remote_half_closed,
        task: Some(task),
        write_shutdown: WriteShutdown::Open,
    })
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let filled = buf.filled().len();
        ready!(Pin::new(&mut self.io).poll_read(cx, buf))?;
        if buf.filled().len() != filled {
            return Poll::Ready(Ok(()));
        }

        if self.remote_half_closed.load(Ordering::Acquire) {
            // Deliver the peer's FIN while uploads are still possible. If
            // shutdown is draining, it owns the relay's waker and result.
            let report_relay_result = match self.write_shutdown {
                WriteShutdown::Open => {
                    self.task.as_ref().is_none_or(|task| task.is_finished())
                }
                WriteShutdown::Draining => false,
                WriteShutdown::Complete => true,
            };
            if !report_relay_result {
                return Poll::Ready(Ok(()));
            }
        }
        match ready!(self.poll_relay(cx)) {
            // Explicit handler cancellation has always closed the local stream.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Poll::Ready(Ok(())),
            result => Poll::Ready(result),
        }
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
        if self.write_shutdown == WriteShutdown::Complete {
            return Poll::Ready(Ok(()));
        }
        ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
        let result = if self.remote_half_closed.load(Ordering::Acquire) {
            // Both directions are closing. Wind finishes only after its
            // native writer drains the upload and sends END_STREAM.
            self.write_shutdown = WriteShutdown::Draining;
            ready!(self.poll_relay(cx))
        } else {
            // Let the caller read the response. The final read joins the relay.
            Ok(())
        };
        self.write_shutdown = WriteShutdown::Complete;
        Poll::Ready(result)
    }
}

impl ProxyStream for Stream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wind_core::{tcp::AbstractTcpStream, udp::UdpStream};

    enum TestOutbound {
        Reject,
        ShortReply {
            fail: bool,
        },
        Echo,
        EchoAfterEof,
        FailAfterReply,
        FailAfterFin {
            local_first: bool,
            resume: Arc<tokio::sync::Notify>,
        },
        RemoteHalfClose {
            resume: Arc<tokio::sync::Notify>,
            received: tokio::sync::mpsc::Sender<Vec<u8>>,
        },
    }
    #[async_trait::async_trait]
    impl Outbound for TestOutbound {
        async fn handle_tcp(
            &self,
            _: FlowContext,
            mut stream: Box<dyn AbstractTcpStream>,
        ) -> eyre::Result<()> {
            match self {
                Self::Reject => Err(eyre::eyre!("authentication rejected")),
                Self::ShortReply { fail } => {
                    stream.write_all(b"hello").await?;
                    if *fail {
                        eyre::bail!("short relay failed");
                    }
                    Ok(())
                }
                Self::EchoAfterEof => {
                    let mut data = Vec::new();
                    stream.read_to_end(&mut data).await?;
                    stream.write_all(&data).await?;
                    Ok(())
                }
                Self::RemoteHalfClose { resume, received } => {
                    stream.write_all(b"done").await?;
                    stream.shutdown().await?;
                    resume.notified().await;
                    let mut data = Vec::new();
                    stream.read_to_end(&mut data).await?;
                    received.send(data).await?;
                    Ok(())
                }
                Self::FailAfterFin {
                    local_first,
                    resume,
                } => {
                    if *local_first {
                        stream.read_to_end(&mut Vec::new()).await?;
                    }
                    stream.write_all(b"x").await?;
                    stream.shutdown().await?;
                    resume.notified().await;
                    eyre::bail!("native writer failed during shutdown");
                }
                Self::Echo | Self::FailAfterReply => {
                    let mut data = [0; 4];
                    stream.read_exact(&mut data).await?;
                    stream.write_all(&data).await?;
                    if matches!(self, Self::FailAfterReply) {
                        eyre::bail!("relay failed after CONNECT");
                    }
                    std::future::pending().await
                }
            }
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
            Arc::new(TestOutbound::Reject),
            super::super::tcp_flow(&Default::default()),
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
    async fn naive_connect_preserves_short_reply_when_relay_already_ended() {
        // On the current-thread runtime the relay writes and exits in one poll.
        for fail in [false, true] {
            let mut stream = connect(
                Arc::new(TestOutbound::ShortReply { fail }),
                super::super::tcp_flow(&Default::default()),
                CancellationToken::new(),
            )
            .await
            .unwrap();
            let mut reply = Vec::new();
            let result = stream.read_to_end(&mut reply).await;
            assert_eq!(reply, b"hello");
            if fail {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("short relay failed")
                );
            } else {
                assert_eq!(result.unwrap(), reply.len());
            }
        }
    }

    #[tokio::test]
    async fn naive_stream_relays_and_observes_handler_cancellation() {
        let cancel = CancellationToken::new();
        let mut stream = connect(
            Arc::new(TestOutbound::Echo),
            super::super::tcp_flow(&Default::default()),
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

    #[tokio::test]
    async fn naive_stream_reports_failure_after_buffered_response() {
        let mut stream = connect(
            Arc::new(TestOutbound::FailAfterReply),
            super::super::tcp_flow(&Default::default()),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        stream.write_all(b"data").await.unwrap();
        let mut response = Vec::new();
        let error = stream.read_to_end(&mut response).await.unwrap_err();
        assert_eq!(response, b"data");
        assert!(error.to_string().contains("relay failed after CONNECT"));
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn naive_stream_remote_half_close_preserves_upload() {
        use crate::{
            app::dispatcher::InstrumentedStreamWrapper,
            common::io::copy_bidirectional,
        };
        use std::time::Duration;

        tokio::time::timeout(Duration::from_secs(2), async {
            let resume = Arc::new(tokio::sync::Notify::new());
            let (received, mut upload) = tokio::sync::mpsc::channel(1);
            let stream = connect(
                Arc::new(TestOutbound::RemoteHalfClose {
                    resume: resume.clone(),
                    received,
                }),
                super::super::tcp_flow(&Default::default()),
                CancellationToken::new(),
            )
            .await
            .unwrap();
            let (mut client, inbound) = tokio::io::duplex(64 * 1024);
            let mut copy = Box::pin(copy_bidirectional(
                Box::new(inbound),
                Box::new(InstrumentedStreamWrapper::new(stream)),
                64 * 1024,
                Duration::from_secs(10),
                Duration::from_secs(10),
            ));
            assert!(futures::poll!(&mut copy).is_pending());
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"done");
            let payload: Vec<_> = (0..65536).map(|i| (i % 251) as u8).collect();
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            assert!(
                futures::poll!(&mut copy).is_pending(),
                "copy finished before the writer could drain"
            );
            resume.notify_one();
            assert_eq!(copy.await.unwrap(), (65536, 4));
            assert_eq!(upload.recv().await.unwrap(), payload);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn naive_final_half_close_reports_writer_failure_in_either_order() {
        for local_first in [false, true] {
            let resume = Arc::new(tokio::sync::Notify::new());
            let mut stream = connect(
                Arc::new(TestOutbound::FailAfterFin {
                    local_first,
                    resume: resume.clone(),
                }),
                super::super::tcp_flow(&Default::default()),
                CancellationToken::new(),
            )
            .await
            .unwrap();
            if local_first {
                stream.shutdown().await.unwrap();
            }
            assert_eq!(stream.read_u8().await.unwrap(), b'x');
            if !local_first {
                assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            }
            let finish = async {
                if local_first {
                    stream.read(&mut [0]).await.map(|_| ())
                } else {
                    stream.shutdown().await
                }
            };
            tokio::pin!(finish);
            assert!(futures::poll!(&mut finish).is_pending());
            resume.notify_one();
            assert!(
                finish
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("native writer failed")
            );
        }
    }

    #[tokio::test]
    async fn naive_stream_write_shutdown_preserves_response() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut stream = connect(
                Arc::new(TestOutbound::EchoAfterEof),
                super::super::tcp_flow(&Default::default()),
                CancellationToken::new(),
            )
            .await
            .unwrap();
            let payload = vec![0x5a; 256 * 1024];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, payload);
        })
        .await
        .unwrap();
    }
}
