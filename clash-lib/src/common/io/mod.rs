/// copy of https://github.com/eycorsican/leaf/blob/a77a1e497ae034f3a2a89c8628d5e7ebb2af47f0/leaf/src/common/io.rs
use std::future::Future;
use std::{
    io,
    mem::MaybeUninit,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(all(target_os = "linux", feature = "zero_copy"))]
mod splice;
#[cfg(all(target_os = "linux", feature = "zero_copy"))]
pub use splice::zero_copy_bidirectional;

use crate::{app::dispatcher::BoxedInstrumentedStream, proxy::ProxyStream};

/// Number of bytes processed by a single `CopyBuffer::poll_copy` invocation
/// before we cooperatively yield back to the tokio runtime.
///
/// Without this, a CPU-bound proxy stream (e.g. Shadowsocks AES-GCM on a
/// 78 BogoMIPS ARMv7 dual-core router) can keep a worker thread busy for
/// tens of milliseconds per `poll_write` call. With 16 concurrent SS flows
/// (32 directions) on only 2 worker threads, that starves short control
/// tasks (DNS resolution, API polling, SSH keepalive) which share the same
/// runtime, manifesting as "speedtest crashes the router / DNS times out".
///
/// Yielding every 256 KiB lets the runtime interleave ~60 DNS-sized tasks
/// per second per flow at 67 Mbit/s while costing only one extra schedule
/// per ~3 ms of cipher work. The threshold is deliberately a multiple of
/// the typical 64 KiB tcp-buffer so a single buffer-fill/write cycle is
/// not interrupted; we yield between cycles, not mid-write.
const YIELD_EVERY_BYTES: u64 = 256 * 1024;

#[derive(Debug)]
pub enum CopyBidirectionalError {
    LeftClosed(std::io::Error),
    RightClosed(std::io::Error),
    Other(std::io::Error),
}

impl std::fmt::Display for CopyBidirectionalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CopyBidirectionalError::LeftClosed(e) => {
                write!(f, "left side closed with error: {e}")
            }
            CopyBidirectionalError::RightClosed(e) => {
                write!(f, "right side closed with error: {e}")
            }
            CopyBidirectionalError::Other(e) => {
                write!(f, "error: {e}")
            }
        }
    }
}

impl std::error::Error for CopyBidirectionalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CopyBidirectionalError::LeftClosed(e) => Some(e),
            CopyBidirectionalError::RightClosed(e) => Some(e),
            CopyBidirectionalError::Other(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for CopyBidirectionalError {
    fn from(e: std::io::Error) -> Self {
        CopyBidirectionalError::Other(e)
    }
}

#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    buf: Box<[u8]>,
    /// Bytes transferred since the last cooperative yield. See
    /// [`YIELD_EVERY_BYTES`] for rationale.
    bytes_since_yield: u64,
}

impl Default for CopyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl CopyBuffer {
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: vec![0; 2 * 1024].into_boxed_slice(),
            bytes_since_yield: 0,
        }
    }

    pub fn new_with_capacity(size: usize) -> Result<Self, std::io::Error> {
        let mut buf = Vec::new();
        buf.try_reserve(size)
            .map_err(|e| std::io::Error::other(format!("new buffer failed: {e}")))?;
        buf.resize(size, 0);
        Ok(Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            buf: buf.into_boxed_slice(),
            bytes_since_yield: 0,
        })
    }

    pub fn amount_transferred(&self) -> u64 {
        self.amt
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        mut idle_timeout: Option<&mut Pin<Box<tokio::time::Sleep>>>,
        idle_timeout_duration: Option<Duration>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                let me = &mut *self;
                let mut buf = ReadBuf::new(&mut me.buf);

                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Try flushing when the reader has no progress to avoid
                        // deadlock when the reader
                        // depends on buffered writer.
                        if self.need_flush {
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }

                        return Poll::Pending;
                    }
                }

                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                    // Reset idle timeout on successful read
                    if let (Some(timeout), Some(duration)) =
                        (idle_timeout.as_mut(), idle_timeout_duration)
                    {
                        timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + duration);
                    }
                }
            }

            // If our buffer has some data, let's write it out!
            while self.pos < self.cap {
                let remaining_yield = (YIELD_EVERY_BYTES
                    .saturating_sub(self.bytes_since_yield)
                    as usize)
                    .min(self.cap - self.pos);
                let to_write = if remaining_yield > 0 {
                    remaining_yield
                } else {
                    self.cap - self.pos
                };

                let me = &mut *self;
                let i = ready!(
                    writer
                        .as_mut()
                        .poll_write(cx, &me.buf[me.pos..me.pos + to_write])
                )?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.bytes_since_yield =
                        self.bytes_since_yield.saturating_add(i as u64);
                    self.need_flush = true;
                    // Reset idle timeout on successful write
                    if let (Some(timeout), Some(duration)) =
                        (idle_timeout.as_mut(), idle_timeout_duration)
                    {
                        timeout
                            .as_mut()
                            .reset(tokio::time::Instant::now() + duration);
                    }
                }

                if self.bytes_since_yield >= YIELD_EVERY_BYTES {
                    break;
                }
            }

            // If pos larger than cap, this loop will never stop.
            // In particular, user's wrong poll_write implementation returning
            // incorrect written length may lead to thread blocking.
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }

            // Cooperative yield: after transferring `YIELD_EVERY_BYTES` since
            // the last yield, flush any buffered writes and ask the runtime
            // to re-schedule us on the next poll loop. This prevents a single
            // CPU-bound cipher (e.g. Shadowsocks AES-GCM on a 78 BogoMIPS
            // ARMv7 dual-core router) from monopolising a worker thread and
            // starving short control tasks (DNS, API, SSH) that share the
            // same tokio runtime. See [`YIELD_EVERY_BYTES`] for the rationale
            // behind the threshold.
            if self.bytes_since_yield >= YIELD_EVERY_BYTES {
                self.bytes_since_yield = 0;
                if self.need_flush {
                    ready!(writer.as_mut().poll_flush(cx))?;
                    self.need_flush = false;
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
    a_to_b_count: u64,
    b_to_a_count: u64,
    a_to_b_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    b_to_a_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
    idle_timeout: Pin<Box<tokio::time::Sleep>>,
    idle_timeout_duration: Duration,
}

impl<A, B> Future for CopyBidirectional<'_, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = Result<(u64, u64), CopyBidirectionalError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
            a_to_b_count,
            b_to_a_count,
            a_to_b_delay,
            b_to_a_delay,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
            idle_timeout,
            idle_timeout_duration,
        } = &mut *self;

        let mut a = Pin::new(a);
        let mut b = Pin::new(b);

        // Check idle timeout - if expired, force both directions to shutdown
        if idle_timeout.as_mut().poll(cx).is_ready() {
            if !matches!(a_to_b, TransferState::Done) {
                let count = match a_to_b {
                    TransferState::Running(buf) => buf.amount_transferred(),
                    TransferState::ShuttingDown(count) => *count,
                    TransferState::Done => 0,
                };
                *a_to_b = TransferState::ShuttingDown(count);
            }
            if !matches!(b_to_a, TransferState::Done) {
                let count = match b_to_a {
                    TransferState::Running(buf) => buf.amount_transferred(),
                    TransferState::ShuttingDown(count) => *count,
                    TransferState::Done => 0,
                };
                *b_to_a = TransferState::ShuttingDown(count);
            }
        }

        loop {
            match a_to_b {
                TransferState::Running(buf) => {
                    let res = buf.poll_copy(
                        cx,
                        a.as_mut(),
                        b.as_mut(),
                        Some(idle_timeout),
                        Some(*idle_timeout_duration),
                    );
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *a_to_b = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::LeftClosed(err),
                            ));
                        }
                        Poll::Pending => {
                            if let Some(delay) = a_to_b_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *a_to_b = TransferState::ShuttingDown(
                                            buf.amount_transferred(),
                                        );
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = b.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *a_to_b_count += *count;
                            *a_to_b = TransferState::Done;
                            b_to_a_delay.replace(Box::pin(tokio::time::sleep(
                                *b_to_a_timeout_duration,
                            )));
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::LeftClosed(err),
                            ));
                        }
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match b_to_a {
                TransferState::Running(buf) => {
                    let res = buf.poll_copy(
                        cx,
                        b.as_mut(),
                        a.as_mut(),
                        Some(idle_timeout),
                        Some(*idle_timeout_duration),
                    );
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *b_to_a = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::RightClosed(err),
                            ));
                        }
                        Poll::Pending => {
                            if let Some(delay) = b_to_a_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *b_to_a = TransferState::ShuttingDown(
                                            buf.amount_transferred(),
                                        );
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = a.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *b_to_a_count += *count;
                            *b_to_a = TransferState::Done;
                            a_to_b_delay.replace(Box::pin(tokio::time::sleep(
                                *a_to_b_timeout_duration,
                            )));
                            continue;
                        }
                        Poll::Ready(Err(err)) => {
                            return Poll::Ready(Err(
                                CopyBidirectionalError::RightClosed(err),
                            ));
                        }
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match (&a_to_b, &b_to_a) {
                (TransferState::Done, TransferState::Done) => break,
                _ => return Poll::Pending,
            }
        }

        Poll::Ready(Ok((*a_to_b_count, *b_to_a_count)))
    }
}

pub async fn copy_bidirectional(
    mut a: Box<dyn ProxyStream>,
    mut b: BoxedInstrumentedStream,
    size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
) -> Result<(u64, u64), CopyBidirectionalError> {
    // zero copy is only available on linux
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    {
        // for zero copy, we need to track the download and upload amount with
        // the assistance of the tracker it's somehow ugly, but i could
        // not figure out a better way
        let trackers = b.trackers();
        // for socks5 & http listener, a is a raw TcpStream
        let a_raw = a.underlying_socket();
        // for direct outbound handler **without further chains**, b is a
        // chained stream wrapper over tcpstream
        let b_raw = b.underlying_socket();
        match (a_raw, b_raw, trackers) {
            // zero copy is only available when both streams are raw TcpStream and
            // tracking is installed
            (Some(a), Some(b), Some((r_tracker, w_tracker))) => {
                tracing::trace!("using zero copy for bidirectional copy");
                zero_copy_bidirectional(
                    a,
                    b,
                    r_tracker,
                    w_tracker,
                    a_to_b_timeout_duration,
                    b_to_a_timeout_duration,
                )
                .await
            }
            _ => {
                copy_buf_bidirectional_with_timeout(
                    &mut a,
                    &mut b,
                    size,
                    a_to_b_timeout_duration,
                    b_to_a_timeout_duration,
                )
                .await
            }
        }
    }
    #[cfg(not(all(target_os = "linux", feature = "zero_copy")))]
    {
        copy_buf_bidirectional_with_timeout(
            &mut a,
            &mut b,
            size,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
        )
        .await
    }
}

pub async fn copy_buf_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
) -> Result<(u64, u64), CopyBidirectionalError>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let idle_timeout_duration = Duration::from_secs(60);
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        b_to_a: TransferState::Running(CopyBuffer::new_with_capacity(size)?),
        a_to_b_count: 0,
        b_to_a_count: 0,
        a_to_b_delay: None,
        b_to_a_delay: None,
        a_to_b_timeout_duration,
        b_to_a_timeout_duration,
        idle_timeout: Box::pin(tokio::time::sleep(idle_timeout_duration)),
        idle_timeout_duration,
    }
    .await
}

pub trait ReadExactBase {
    /// inner stream to be polled
    type I: AsyncRead + Unpin;
    /// prepare the inner stream, read buffer and read position
    fn decompose(&mut self) -> (&mut Self::I, &mut BytesMut, &mut usize);
}

pub trait ReadExt: ReadExactBase {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>>;
}

impl<T: ReadExactBase> ReadExt for T {
    fn poll_read_exact(
        &mut self,
        cx: &mut std::task::Context,
        size: usize,
    ) -> Poll<std::io::Result<()>> {
        let (raw, read_buf, read_pos) = self.decompose();
        read_buf.reserve(size);
        // # safety: read_buf has reserved `size`
        unsafe { read_buf.set_len(size) }
        loop {
            if *read_pos < size {
                // # safety: read_pos<size==read_buf.len(), and
                // read_buf[0..read_pos] is initialized
                let dst = unsafe {
                    &mut *((&mut read_buf[*read_pos..size]) as *mut _
                        as *mut [MaybeUninit<u8>])
                };
                let mut buf = ReadBuf::uninit(dst);
                let ptr = buf.filled().as_ptr();
                ready!(Pin::new(&mut *raw).poll_read(cx, &mut buf))?;
                assert_eq!(ptr, buf.filled().as_ptr());
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected eof",
                    )));
                }
                *read_pos += buf.filled().len();
            } else {
                assert!(*read_pos == size);
                *read_pos = 0;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn test_copy_buf_bidirectional_small_buffer() {
        let (mut client_io, mut server_io) = duplex(64 * 1024);
        let (mut proxy_client, mut proxy_server) = duplex(64 * 1024);

        let copy_task = tokio::spawn(async move {
            copy_buf_bidirectional_with_timeout(
                &mut server_io,
                &mut proxy_client,
                2 * 1024,
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await
        });

        let client_msg = b"hello world";
        client_io.write_all(client_msg).await.unwrap();
        client_io.shutdown().await.unwrap();

        let mut buf = vec![0u8; client_msg.len()];
        proxy_server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, client_msg);
        proxy_server.shutdown().await.unwrap();

        let (a_to_b, b_to_a) = copy_task.await.unwrap().unwrap();
        assert_eq!(a_to_b, client_msg.len() as u64);
        assert_eq!(b_to_a, 0);
    }

    #[tokio::test]
    async fn test_copy_buf_bidirectional_oversized_buffer() {
        // Test buffer larger than YIELD_EVERY_BYTES (256 KiB), e.g. 512 KiB
        let (mut client_io, mut server_io) = duplex(1024 * 1024);
        let (mut proxy_client, mut proxy_server) = duplex(1024 * 1024);

        let copy_task = tokio::spawn(async move {
            copy_buf_bidirectional_with_timeout(
                &mut server_io,
                &mut proxy_client,
                512 * 1024,
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .await
        });

        let data = vec![42u8; 600 * 1024]; // 600 KiB > 256 KiB
        let data_clone = data.clone();

        let client_task = tokio::spawn(async move {
            client_io.write_all(&data_clone).await.unwrap();
            client_io.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        proxy_server.read_to_end(&mut received).await.unwrap();
        proxy_server.shutdown().await.unwrap();

        client_task.await.unwrap();
        let (a_to_b, b_to_a) = copy_task.await.unwrap().unwrap();
        assert_eq!(a_to_b, data.len() as u64);
        assert_eq!(b_to_a, 0);
        assert_eq!(received, data);
    }
}
