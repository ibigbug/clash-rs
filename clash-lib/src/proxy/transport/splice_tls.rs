/// XTLS-splice capable TLS stream.
///
/// Wraps a `TlsStream<AnyStream>` and can switch to raw (bypass-TLS) **reads**
/// when signalled via a shared `Arc<AtomicBool>` flag.
///
/// Why reads must splice: an Xray server decides on its own to leave the outer
/// TLS layer once it has recognised the proxied traffic as TLS 1.3
/// (`VisionWriter.WriteMultiBuffer` in Xray-core `proxy/proxy.go` sets
/// `DownlinkWriterDirectCopy` and sends `CMD_PADDING_DIRECT`).  From then on
/// the inner TLS records travel as raw bytes on the TCP socket.
///
/// Why writes never splice: the server only switches its *uplink reader* to raw
/// when the client sends `CMD_PADDING_DIRECT`, and `VisionStream` never does.
/// Keeping the uplink inside TLS also means the client's `close_notify` is
/// consumed by the server's TLS layer instead of leaking into the proxied
/// connection as application bytes.
use std::{
    io::{self, Read},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::proxy::AnyStream;

pub type RealityTlsStream = tokio_rustls::client::TlsStream<AnyStream>;

/// Options passed to `VisionStream` when XTLS-splice mode is active.
///
/// `VisionStream` sets the shared flag when it receives `CMD_PADDING_DIRECT`
/// from the server; `SplicableTlsStream` and `RecordChunkIo` read it to know
/// when the peer has left the outer TLS layer.
pub struct VisionOptions {
    pub read_flag: Arc<AtomicBool>,
}

/// TLS record header: content type (1) + version (2) + length (2).
const RECORD_HEADER_LEN: usize = 5;

/// Upper bound for one TLS record (RFC 8446 caps TLSCiphertext at 2^14 + 256;
/// the older CBC suites allow 2^14 + 2048, so the larger bound is used).
const MAX_RECORD_LEN: usize = 16384 + 2048;

/// Hands the TLS layer exactly **one ciphertext record per read**.
///
/// rustls reads whatever the socket has available into its deframer and then
/// processes every complete record it buffered.  After the server's
/// `CMD_PADDING_DIRECT` record the socket carries raw inner-TLS records, which
/// are indistinguishable from outer records by header, so a single over-reading
/// `read()` makes rustls try to decrypt them and fail with
/// `cannot decrypt peer's message`.  Feeding one record at a time guarantees
/// that the DIRECT record is the last byte rustls ever buffers; everything
/// after it stays in the socket until `raw` is set and this layer becomes a
/// plain passthrough.
pub struct RecordChunkIo {
    inner: AnyStream,
    raw: Arc<AtomicBool>,
    header: [u8; RECORD_HEADER_LEN],
    header_len: usize,
    /// Total length (header included) of the record being assembled; 0 = none.
    record_total: usize,
    /// The record buffered in `pending` is complete and may be handed out.
    record_complete: bool,
    pending: BytesMut,
    scratch: Box<[u8]>,
}

impl RecordChunkIo {
    pub fn new(inner: AnyStream, raw: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            raw,
            header: [0u8; RECORD_HEADER_LEN],
            header_len: 0,
            record_total: 0,
            record_complete: false,
            pending: BytesMut::new(),
            scratch: vec![0u8; MAX_RECORD_LEN].into_boxed_slice(),
        }
    }

    fn record_len(&self) -> usize {
        u16::from_be_bytes([self.header[3], self.header[4]]) as usize
    }

    fn reset_record(&mut self) {
        self.header_len = 0;
        self.record_total = 0;
        self.record_complete = false;
        self.pending.clear();
    }
}

impl AsyncRead for RecordChunkIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            // 1. A complete record is buffered: hand it out (possibly in
            //    pieces).
            if this.record_complete {
                let amt = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..amt]);
                this.pending.advance(amt);
                if this.pending.is_empty() {
                    this.reset_record();
                }
                return Poll::Ready(Ok(()));
            }

            // 2. The peer has left TLS: the stream is opaque bytes now.  Hand
            //    over anything still buffered, then pass straight through.
            if this.raw.load(Ordering::Acquire) {
                if !this.pending.is_empty() {
                    let amt = this.pending.len().min(buf.remaining());
                    buf.put_slice(&this.pending[..amt]);
                    this.pending.advance(amt);
                    return Poll::Ready(Ok(()));
                }
                this.reset_record();
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // 3. Record header.
            if this.header_len < RECORD_HEADER_LEN {
                let mut hb = ReadBuf::new(&mut this.header[this.header_len..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut hb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = hb.filled().len();
                        if n == 0 {
                            return Poll::Ready(if this.header_len == 0 {
                                Ok(())
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated tls record header",
                                ))
                            });
                        }
                        this.header_len += n;
                    }
                }
                if this.header_len < RECORD_HEADER_LEN {
                    continue;
                }
                if this.record_len() > MAX_RECORD_LEN {
                    this.reset_record();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls record too large",
                    )));
                }
                this.record_total = RECORD_HEADER_LEN + this.record_len();
                this.pending.clear();
                this.pending.put_slice(&this.header[..RECORD_HEADER_LEN]);
                continue;
            }

            // 4. Record body.
            let want = this.record_total - this.pending.len();
            let mut bb = ReadBuf::new(&mut this.scratch[..want]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut bb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = bb.filled().len();
                    if n == 0 {
                        this.reset_record();
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated tls record",
                        )));
                    }
                    this.pending.extend_from_slice(&bb.filled());
                }
            }
            if this.pending.len() == this.record_total {
                this.record_complete = true;
            }
        }
    }
}

impl AsyncWrite for RecordChunkIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl crate::proxy::ProxyStream for RecordChunkIo {}

pub struct SplicableTlsStream {
    tls: RealityTlsStream,

    // Bytes drained from TLS plaintext buffer on the first raw-read.
    leftover: BytesMut,

    // Shared with VisionStream: set when CMD_DIRECT is received from server.
    read_flag: Arc<AtomicBool>,
    read_spliced: bool,
}

impl SplicableTlsStream {
    pub fn new(tls: RealityTlsStream, read_flag: Arc<AtomicBool>) -> Self {
        Self {
            tls,
            leftover: BytesMut::new(),
            read_flag,
            read_spliced: false,
        }
    }

    /// Drain the TLS plaintext buffer into `self.leftover` and flip
    /// `read_spliced`.  After this, reads go directly to the raw IO.
    fn activate_read_splice(&mut self) {
        debug!("SplicableTlsStream: activating read splice (bypassing outer TLS)");
        let (_, conn) = self.tls.get_mut();
        let mut tmp = [0u8; 4096];
        loop {
            match conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.leftover.put_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        self.read_spliced = true;
    }
}

impl AsyncRead for SplicableTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check if we need to switch to raw read.
        if !this.read_spliced && this.read_flag.load(Ordering::Acquire) {
            this.activate_read_splice();
        }

        // Return leftover plaintext drained from TLS first.
        if !this.leftover.is_empty() {
            let amt = this.leftover.len().min(buf.remaining());
            buf.put_slice(&this.leftover[..amt]);
            this.leftover.advance(amt);
            return Poll::Ready(Ok(()));
        }

        if this.read_spliced {
            // Bypass outer TLS — read raw bytes from the underlying IO.
            let (io, _) = this.tls.get_mut();
            Pin::new(io).poll_read(cx, buf)
        } else {
            Pin::new(&mut this.tls).poll_read(cx, buf)
        }
    }
}

impl AsyncWrite for SplicableTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().tls).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tls).poll_shutdown(cx)
    }
}

impl crate::proxy::ProxyStream for SplicableTlsStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x17, 0x03, 0x03];
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn make_io() -> (RecordChunkIo, tokio::io::DuplexStream, Arc<AtomicBool>) {
        let (client, server) = tokio::io::duplex(65536);
        let raw = Arc::new(AtomicBool::new(false));
        (
            RecordChunkIo::new(Box::new(client), Arc::clone(&raw)),
            server,
            raw,
        )
    }

    /// Reads from the TLS side in tiny pieces to prove the chunking is done by
    /// this layer regardless of the caller's buffer size.
    async fn read_exact_small(io: &mut RecordChunkIo, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < n {
            let mut piece = [0u8; 7];
            let want = (n - out.len()).min(7);
            let got = io.read(&mut piece[..want]).await.unwrap();
            assert!(got > 0, "reader stalled after {} bytes", out.len());
            out.extend_from_slice(&piece[..got]);
        }
        out
    }

    #[tokio::test]
    async fn test_record_chunk_io_yields_one_record_per_read() {
        let (mut io, mut server, _raw) = make_io();

        // Two records land in the socket at once.
        server
            .write_all(&[tls_record(b"aaaa"), tls_record(b"bb")].concat())
            .await
            .unwrap();

        let mut out = vec![0u8; 65536];
        let n = io.read(&mut out).await.unwrap();
        assert_eq!(
            &out[..n],
            &tls_record(b"aaaa"),
            "first read = record 1 only"
        );

        let n = io.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], &tls_record(b"bb"), "second read = record 2 only");
    }

    #[tokio::test]
    async fn test_record_chunk_io_assembles_split_record() {
        let (mut io, mut server, _raw) = make_io();

        let rec = tls_record(&[0x42u8; 100]);
        server.write_all(&rec[..3]).await.unwrap();
        server.write_all(&rec[3..40]).await.unwrap();
        server.write_all(&rec[40..]).await.unwrap();

        assert_eq!(read_exact_small(&mut io, rec.len()).await, rec);
    }

    #[tokio::test]
    async fn test_record_chunk_io_raw_passthrough_after_flag() {
        let (mut io, mut server, raw) = make_io();

        // The DIRECT record ...
        server
            .write_all(&tls_record(b"direct-frame"))
            .await
            .unwrap();
        let mut out = vec![0u8; 65536];
        let n = io.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], &tls_record(b"direct-frame"));

        // ... is followed on the socket by raw inner records, which must NOT
        // be handed to the TLS reader until the flag says so.
        let raw_bytes = [tls_record(b"inner-1"), tls_record(b"inner-2")].concat();
        server.write_all(&raw_bytes).await.unwrap();
        server.shutdown().await.unwrap();

        raw.store(true, Ordering::Release);

        let mut got = Vec::new();
        io.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, raw_bytes, "raw bytes pass through untouched");
    }

    #[tokio::test]
    async fn test_record_chunk_io_truncated_record_is_error() {
        let (mut io, mut server, _raw) = make_io();
        server.write_all(&tls_record(b"hello")[..7]).await.unwrap();
        drop(server);

        let mut out = vec![0u8; 64];
        let err = io.read(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_record_chunk_io_oversized_record_is_error() {
        let (mut io, mut server, _raw) = make_io();
        server
            .write_all(&[0x17, 0x03, 0x03, 0xff, 0xff])
            .await
            .unwrap();

        let mut out = vec![0u8; 64];
        let err = io.read(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_record_chunk_io_write_passthrough() {
        let (mut io, mut server, _raw) = make_io();
        io.write_all(b"outbound").await.unwrap();
        io.flush().await.unwrap();

        let mut out = vec![0u8; 64];
        let n = server.read(&mut out).await.unwrap();
        assert_eq!(&out[..n], b"outbound");
    }

    // -----------------------------------------------------------------------
    // End-to-end: server's DIRECT record followed by raw bytes on the socket
    // -----------------------------------------------------------------------

    /// Runs a real rustls client against a TLS server that behaves like an
    /// Xray server switching its downlink to direct copy: two records inside
    /// TLS, then raw bytes on the same socket — all written before the client
    /// reads anything.  Returns what the client reads after the splice flag is
    /// set (what `VisionStream` does on `CMD_PADDING_DIRECT`).
    async fn server_direct_then_raw<F>(make_client_io: F) -> io::Result<Vec<u8>>
    where
        F: FnOnce(AnyStream, Arc<AtomicBool>) -> AnyStream,
    {
        crate::setup_default_crypto_provider();
        let (certs, key) = crate::common::tls::resolve_server_cert_and_key(
            None,
            None,
            "vision-test",
        )?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let (a, b) = tokio::io::duplex(65536);
        let raw = Arc::new(AtomicBool::new(false));
        let client_io = make_client_io(Box::new(a), Arc::clone(&raw));

        // Inner TLS records, as an Xray server writes them after going raw.
        let raw_bytes = [
            tls_record(b"inner-app-data-0001"),
            tls_record(b"inner-app-data-0002"),
        ]
        .concat();

        // The server must be accepting before the client starts its handshake.
        let server = tokio::spawn(async move {
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg))
                .accept(b)
                .await?;
            tls.write_all(b"continue-frame").await?;
            tls.flush().await?;
            tls.write_all(b"direct-frame").await?;
            tls.flush().await?;
            tls.get_mut().0.write_all(&raw_bytes).await?;
            tls.get_mut().0.flush().await?;
            Ok::<(), io::Error>(())
        });

        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
            .connect(name, client_io)
            .await?;
        let mut client = SplicableTlsStream::new(tls, Arc::clone(&raw));
        server.await.unwrap()?;

        let mut framed = vec![0u8; "continue-frame".len() + "direct-frame".len()];
        client.read_exact(&mut framed).await?;
        assert_eq!(&framed, b"continue-framedirect-frame");

        raw.store(true, Ordering::Release);
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await?;
        Ok(rest)
    }

    /// Fixed shape: the socket is fed to rustls one record at a time, so the
    /// DIRECT record is the last thing rustls buffers and the raw bytes that
    /// follow it are handed over untouched.
    #[tokio::test]
    async fn test_server_direct_then_raw_with_record_chunking() {
        let rest = server_direct_then_raw(|io, raw| {
            Box::new(RecordChunkIo::new(io, raw)) as AnyStream
        })
        .await
        .expect("spliced read must succeed");
        let expected = [
            tls_record(b"inner-app-data-0001"),
            tls_record(b"inner-app-data-0002"),
        ]
        .concat();
        assert_eq!(rest, expected);
    }

    /// Negative arm (the pre-fix shape: the socket goes to rustls directly).
    /// One over-reading `read_tls` buffers the DIRECT record together with the
    /// raw records after it; rustls tries to decrypt those as outer records and
    /// the stream dies with the exact error seen on the device
    /// (`cannot decrypt peer's message`).
    #[tokio::test]
    async fn test_server_direct_then_raw_without_record_chunking_fails() {
        let err = server_direct_then_raw(|io, _raw| io)
            .await
            .expect_err("rustls must choke on the raw records");
        let msg = err.to_string();
        assert!(
            msg.contains("cannot decrypt peer's message"),
            "unexpected error ({:?}): {msg}",
            err.kind()
        );
    }
}
