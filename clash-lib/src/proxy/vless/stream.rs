use std::{
    io,
    pin::Pin,
    task::{Context, Poll, Waker, ready},
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
/// header plus the caller's first payload has been fully written to `inner`.
enum WriteState {
    /// No request header has been sent yet.
    Idle,
    /// Request header + first payload are being drained into `inner`.
    /// `data_len` is how many bytes of the caller's buffer this represents.
    Sending {
        buf: BytesMut,
        pos: usize,
        data_len: usize,
    },
    /// Header sent; writes pass straight through.
    Open,
}

/// Read side of the VLESS handshake.
///
/// The response header is `version (1) | addon_len (1) | addon (addon_len)`.
/// It can only arrive after the request was sent, so reads wait for the write
/// side to leave `WriteState::Idle` before touching `inner`.
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
    /// Reader parked while the request has not been sent yet.
    read_waker: Option<Waker>,
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
            read_waker: None,
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
            // The server only responds after it has seen our request, so
            // there is nothing to read until the first write starts.
            if matches!(this.write_state, WriteState::Idle) {
                this.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
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
                    let mut header = this.build_handshake_header();
                    header.put_slice(buf);
                    this.write_state = WriteState::Sending {
                        buf: header,
                        pos: 0,
                        data_len: buf.len(),
                    };
                    // The request is now committed; a parked reader can
                    // start waiting on the response.
                    if let Some(w) = this.read_waker.take() {
                        w.wake();
                    }
                }
                WriteState::Sending {
                    buf: header,
                    pos,
                    data_len,
                } => {
                    // Per the AsyncWrite contract the caller retries with the
                    // same buffer after Pending, so we keep draining the
                    // already-encoded bytes and report `data_len` when done.
                    while *pos < header.len() {
                        let n = ready!(
                            Pin::new(&mut this.inner)
                                .poll_write(cx, &header[*pos..])
                        )
                        .inspect_err(|e| {
                            error!("Failed to send VLESS handshake: {}", e)
                        })?;
                        if n == 0 {
                            return Poll::Ready(
                                Err(io::ErrorKind::WriteZero.into()),
                            );
                        }
                        *pos += n;
                    }
                    let n = *data_len;
                    debug!("VLESS handshake sent with {} bytes of data", n);
                    this.write_state = WriteState::Open;
                    return Poll::Ready(Ok(n));
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
        let n = s.write(b"hello").await.unwrap();
        assert_eq!(n, 5);
        reader.await.unwrap();
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
    async fn test_read_before_write_waits_for_request() {
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
}
