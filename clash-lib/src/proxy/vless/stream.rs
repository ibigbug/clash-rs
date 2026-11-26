use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{proxy::AnyStream, session::SocksAddr};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;

/// Write side of the VLESS handshake.
///
/// `Idle` → `Sending` on the first `poll_write`; `Sending` → `Open` once the
/// request header has been fully written to `inner`.
///
/// Only the header is retained across polls. The caller's payload is taken
/// from whichever buffer the current `poll_write` passes (coalesced with the
/// remaining header into a single inner write), and only bytes of *that*
/// buffer are acknowledged. AsyncWrite does not require a retry after
/// `Pending` to use the same buffer, so a cancelled first write must never
/// cause its payload to be sent or counted later.
enum WriteState {
    /// No request header has been sent yet.
    Idle,
    /// Request header is being written; `pos` bytes of it are on the wire.
    Sending { header: BytesMut, pos: usize },
    /// Header sent; writes pass straight through.
    Open,
}

/// Read side of the VLESS handshake.
///
/// The response header is `version (1) | addon_len (1) | addon (addon_len)`.
/// It can only arrive after the request header was fully sent. Until the write
/// side is `Open`, reads pass through to `inner` so EOF/reset is still observed
/// (e.g. the client closes without sending anything); any actual data at that
/// point is a protocol violation.
enum ReadState {
    /// Reading the 2-byte fixed response header.
    Header { hdr: [u8; 2], filled: usize },
    /// Discarding `remaining` bytes of addon data.
    Addon { remaining: usize },
    /// Response consumed; reads pass straight through.
    Open,
}

pub struct VlessStream {
    inner: AnyStream,
    write_state: WriteState,
    read_state: ReadState,
    uuid: uuid::Uuid,
    destination: SocksAddr,
    is_udp: bool,
    flow: Option<String>,
}

impl VlessStream {
    pub fn new(
        stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        is_udp: bool,
        flow: Option<String>,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        debug!("VLESS stream created for destination: {}", destination);

        Ok(Self {
            inner: stream,
            write_state: WriteState::Idle,
            read_state: ReadState::Header {
                hdr: [0; 2],
                filled: 0,
            },
            uuid,
            destination: destination.clone(),
            is_udp,
            flow,
        })
    }

    fn build_handshake_header(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Addon length (1 byte)
        // + Addon bytes (variable) + Command (1 byte) + Port (2 bytes)
        // + Address type + Address
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());

        if let Some(ref flow) = self.flow {
            let addon = build_addon_bytes(flow);
            buf.put_u8(addon.len() as u8);
            buf.extend_from_slice(&addon);
        } else {
            buf.put_u8(0); // No addon
        }

        if self.is_udp {
            buf.put_u8(VLESS_COMMAND_UDP);
        } else {
            buf.put_u8(VLESS_COMMAND_TCP);
        }

        self.destination.write_to_buf_vmess(&mut buf);
        buf
    }

    /// `Sending` → `Open` without any payload: drain the rest of the request
    /// header into `inner`. Used by shutdown so a cancelled first write never
    /// leaves the server with a truncated request.
    fn poll_drain_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let WriteState::Sending { header, pos } = &mut self.write_state else {
            unreachable!("poll_drain_header called outside Sending");
        };
        while *pos < header.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &header[*pos..]))
                    .inspect_err(|e| {
                        error!("Failed to send VLESS handshake: {}", e)
                    })?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            *pos += n;
        }
        debug!("VLESS handshake sent without payload");
        self.write_state = WriteState::Open;
        Poll::Ready(Ok(()))
    }

    /// Drive the response header to completion. Returns `Ready(Ok(()))` once
    /// `read_state` is `Open`.
    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.read_state {
                ReadState::Header { hdr, filled } => {
                    let mut rb = ReadBuf::new(&mut hdr[*filled..]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))
                        .inspect_err(|e| {
                            error!("Failed to read VLESS response: {}", e)
                        })?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading VLESS response header",
                        )));
                    }
                    *filled += n;
                    if *filled < hdr.len() {
                        continue;
                    }
                    if hdr[0] != VLESS_VERSION {
                        error!("Invalid VLESS response version: {}", hdr[0]);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid VLESS response version: {}", hdr[0]),
                        )));
                    }
                    let addon_len = hdr[1] as usize;
                    self.read_state = if addon_len > 0 {
                        ReadState::Addon {
                            remaining: addon_len,
                        }
                    } else {
                        ReadState::Open
                    };
                }
                ReadState::Addon { remaining } => {
                    let mut scratch = [0u8; u8::MAX as usize];
                    let mut rb = ReadBuf::new(&mut scratch[..*remaining]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))
                        .inspect_err(|e| {
                            error!("Failed to read VLESS additional info: {}", e)
                        })?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading VLESS response addon",
                        )));
                    }
                    debug!(
                        "VLESS additional info received: {} bytes: {:02x?}",
                        n,
                        &rb.filled()[..n.min(32)],
                    );
                    *remaining -= n;
                    if *remaining == 0 {
                        self.read_state = ReadState::Open;
                    }
                }
                ReadState::Open => {
                    debug!("VLESS handshake completed successfully");
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !matches!(this.read_state, ReadState::Open) {
            if !matches!(this.write_state, WriteState::Open) {
                // Request header not fully sent yet (Idle or Sending), so a
                // valid server cannot have responded. Poll `inner` anyway so
                // EOF/errors are surfaced and our waker is registered there:
                // once the header is out, the response wakes us and the next
                // poll takes the branch below.
                let before = buf.filled().len();
                ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
                if buf.filled().len() != before {
                    buf.set_filled(before);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VLESS server sent data before the request",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            ready!(this.poll_response(cx))?;
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = &mut *self;
        loop {
            match &mut this.write_state {
                WriteState::Idle => {
                    debug!(
                        "VLESS handshake starting for destination: {}",
                        this.destination
                    );
                    this.write_state = WriteState::Sending {
                        header: this.build_handshake_header(),
                        pos: 0,
                    };
                }
                WriteState::Sending { header, pos } => {
                    // Coalesce the unsent header with *this call's* payload
                    // so the request and first data usually leave together.
                    let remaining = header.len() - *pos;
                    let mut chunk = BytesMut::with_capacity(remaining + buf.len());
                    chunk.put_slice(&header[*pos..]);
                    chunk.put_slice(buf);

                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &chunk))
                        .inspect_err(|e| {
                            error!("Failed to send VLESS handshake: {}", e)
                        })?;
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    if n < remaining {
                        *pos += n;
                        continue;
                    }
                    let payload_written = n - remaining;
                    debug!(
                        "VLESS handshake sent with {} bytes of data",
                        payload_written
                    );
                    this.write_state = WriteState::Open;
                    if payload_written == 0 && !buf.is_empty() {
                        // Header done but no payload accepted yet; write the
                        // payload directly rather than report Ok(0).
                        continue;
                    }
                    return Poll::Ready(Ok(payload_written));
                }
                WriteState::Open => {
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // If a first write was abandoned mid-header, finish sending it so the
        // server never sees a truncated request. (Not done in poll_flush: a
        // caller may still retry that write, which would then send twice.)
        if matches!(self.write_state, WriteState::Sending { .. }) {
            ready!(self.poll_drain_header(cx))?;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Encode the flow field as a Protobuf field-1 length-delimited value.
/// Format: [0x0A][varint len][bytes]
pub(crate) fn build_addon_bytes(flow: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + flow.len());
    buf.push(0x0A); // field 1, wire type 2 (length-delimited)
    buf.push(flow.len() as u8); // single-byte varint (flow strings are short)
    buf.extend_from_slice(flow.as_bytes());
    buf
}

impl crate::proxy::ProxyStream for VlessStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    fn dummy_stream() -> AnyStream {
        let (client, _server) = tokio::io::duplex(1024);
        Box::new(client)
    }

    fn tcp_dest() -> SocksAddr {
        "1.2.3.4:80".parse().unwrap()
    }

    // --- build_addon_bytes ---

    #[test]
    fn test_build_addon_bytes_empty_flow() {
        let addon = build_addon_bytes("");
        // tag(1) + len(0) = 2 bytes, no payload
        assert_eq!(addon, vec![0x0A, 0x00]);
    }

    #[test]
    fn test_build_addon_bytes_vision_flow() {
        let flow = "xtls-rprx-vision";
        let addon = build_addon_bytes(flow);
        assert_eq!(addon.len(), 2 + flow.len()); // 18 bytes
        assert_eq!(addon[0], 0x0A); // field-1, wire-type-2 tag
        assert_eq!(addon[1], flow.len() as u8); // 0x10 = 16
        assert_eq!(&addon[2..], flow.as_bytes());
    }

    // --- build_handshake_header ---

    #[test]
    fn test_handshake_header_no_flow() {
        let s = VlessStream::new(
            dummy_stream(),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            false,
            None,
        )
        .unwrap();
        let hdr = s.build_handshake_header();
        // byte 17 (0-indexed) is the addon-length byte
        assert_eq!(hdr[17], 0); // no addon
    }

    #[test]
    fn test_handshake_header_with_flow() {
        let flow = "xtls-rprx-vision";
        let s = VlessStream::new(
            dummy_stream(),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            false,
            Some(flow.to_string()),
        )
        .unwrap();
        let hdr = s.build_handshake_header();
        let addon_len = hdr[17] as usize;
        assert_eq!(addon_len, 2 + flow.len()); // 18
        let addon = &hdr[18..18 + addon_len];
        assert_eq!(addon[0], 0x0A);
        assert_eq!(addon[1], flow.len() as u8);
        assert_eq!(&addon[2..], flow.as_bytes());
    }

    // --- new() ---

    #[test]
    fn test_new_invalid_uuid() {
        let result =
            VlessStream::new(dummy_stream(), "not-a-uuid", &tcp_dest(), false, None);
        assert!(result.is_err());
    }

    // --- handshake state machine ---

    const TEST_UUID: &str = "5415d8e0-df92-3655-afa4-b79de66413f5";

    #[tokio::test]
    async fn test_header_survives_partial_writes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // An 8-byte pipe forces the header write to return Pending many
        // times; the bytes on the wire must still be exactly header+payload.
        let (client, mut server) = tokio::io::duplex(8);
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        let expected = {
            let mut b = s.build_handshake_header();
            b.extend_from_slice(b"hello");
            b.to_vec()
        };

        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; expected.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            server
        });
        s.write_all(b"hello").await.unwrap();
        reader.await.unwrap();
    }

    #[tokio::test]
    async fn test_header_fills_pipe_exactly_no_zero_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A pipe with room for exactly the header: the first inner write
        // takes the header and none of the payload. That must not surface as
        // Ok(0) (which callers read as "closed"); the write keeps going.
        let probe = VlessStream::new(
            Box::new(tokio::io::duplex(1).0),
            TEST_UUID,
            &tcp_dest(),
            false,
            None,
        )
        .unwrap();
        let header = probe.build_handshake_header().to_vec();
        let (client, mut server) = tokio::io::duplex(header.len());
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();

        {
            let fut = s.write(b"hello");
            tokio::pin!(fut);
            match futures::poll!(fut.as_mut()) {
                std::task::Poll::Pending => {}
                std::task::Poll::Ready(r) => {
                    panic!("expected Pending with a full pipe, got {r:?}")
                }
            }
        }
        let mut got = vec![0u8; header.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, header);

        assert_eq!(s.write(b"hello").await.unwrap(), 5);
        let mut payload = [0u8; 5];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
    }

    #[tokio::test]
    async fn test_response_split_across_reads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        s.write_all(b"x").await.unwrap();

        let writer = tokio::spawn(async move {
            // version, addon_len=3, addon, then payload — one byte at a time.
            for b in [0u8, 3, 0xaa, 0xbb, 0xcc, b'o', b'k'] {
                server.write_all(&[b]).await.unwrap();
                server.flush().await.unwrap();
                tokio::task::yield_now().await;
            }
            server
        });

        let mut out = [0u8; 2];
        s.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_bad_response_version() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        s.write_all(b"x").await.unwrap();
        server.write_all(&[1, 0]).await.unwrap();
        let err = s.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_read_before_write_parses_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        let (mut rd, mut wr) = tokio::io::split(s);

        let read = tokio::spawn(async move {
            let mut out = [0u8; 2];
            rd.read_exact(&mut out).await.unwrap();
            out
        });
        tokio::task::yield_now().await;
        assert!(!read.is_finished());

        wr.write_all(b"x").await.unwrap();
        server.write_all(&[0, 0, b'h', b'i']).await.unwrap();
        assert_eq!(&read.await.unwrap(), b"hi");
    }

    #[tokio::test]
    async fn test_shutdown_before_any_write_lets_reader_see_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        let (mut rd, mut wr) = tokio::io::split(s);
        let read = tokio::spawn(async move { rd.read(&mut [0u8; 8]).await });
        tokio::task::yield_now().await;

        // Client half-closes without sending anything; the server sees EOF
        // and closes too. The parked reader must observe that EOF.
        wr.shutdown().await.unwrap();
        let mut sink = Vec::new();
        server.read_to_end(&mut sink).await.unwrap();
        assert!(sink.is_empty(), "no request may be sent");
        drop(server);

        let n = tokio::time::timeout(std::time::Duration::from_secs(1), read)
            .await
            .expect("reader hung after shutdown")
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_server_data_before_request_is_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(1024);
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        server.write_all(&[0, 0, b'x']).await.unwrap();
        let err = s.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_shutdown_finishes_abandoned_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(8);
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        // Only the header: the abandoned payload must not be sent.
        let expected = s.build_handshake_header();

        // Start the first write, let it stall on the 8-byte pipe, abandon it.
        {
            let fut = s.write(b"hello");
            tokio::pin!(fut);
            assert!(futures::poll!(fut.as_mut()).is_pending());
        }

        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            got
        });
        s.shutdown().await.unwrap();
        drop(s);
        assert_eq!(reader.await.unwrap(), expected.to_vec());
    }

    #[tokio::test]
    async fn test_cancelled_first_write_payload_is_not_sent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A pipe too small for even the header: the first write makes partial
        // header progress and returns Pending, then the caller abandons it and
        // writes something else.
        let (client, mut server) = tokio::io::duplex(8);
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        let mut expected = s.build_handshake_header();
        expected.extend_from_slice(b"x");
        let total = expected.len();

        {
            let fut = s.write(b"hello");
            tokio::pin!(fut);
            assert!(futures::poll!(fut.as_mut()).is_pending());
        }

        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; total];
            server.read_exact(&mut got).await.unwrap();
            got
        });
        s.write_all(b"x").await.unwrap();
        assert_eq!(reader.await.unwrap(), expected.to_vec());
    }

    #[tokio::test]
    async fn test_server_data_while_header_partially_sent_is_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(8);
        let mut s =
            VlessStream::new(Box::new(client), TEST_UUID, &tcp_dest(), false, None)
                .unwrap();
        // First write stalls with only part of the header on the wire.
        {
            let fut = s.write(b"hello");
            tokio::pin!(fut);
            assert!(futures::poll!(fut.as_mut()).is_pending());
        }
        // A server cannot answer an incomplete request; this must not be
        // parsed as the response header and handed out as data.
        server.write_all(&[0, 0, b'x']).await.unwrap();
        let err = s.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
