// a rust implementation of https://github.com/shadowsocks/simple-obfs

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use bytes::BufMut;
use chrono::Utc;
use std::{
    borrow::Cow,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::proxy::{AnyStream, transport::Transport};

const CHUNK_SIZE: usize = 1 << 14; // 16 KiB

pub struct Client {
    server: String,
}

impl Client {
    pub fn new(server: String) -> Self {
        Self { server }
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        Ok(TLSObfs::new(stream, self.server.clone()).into())
    }
}

// The TLS obfs read framing works as follows:
//   - First server response: skip 105 bytes of TLS handshake preamble
//     (ServerHello 96 bytes + ChangeCipherSpec 6 bytes + 3 type/version bytes)
//   - Each subsequent record: skip 3 bytes (type + version), then read 2-byte
//     length, then deliver `length` bytes of payload.
//
// The read state machine stores its in-progress buffers in the struct so that
// a Poll::Pending return never loses bytes that were already consumed from the
// inner stream. (The previous implementation used `read_exact` with local
// buffers pinned on the stack; dropping the future on Pending lost those bytes,
// desynchronising the frame parser and causing AEAD tag failures.)

// Maximum header size to discard: 105 bytes for the first response preamble;
// 3 bytes (type + version) for every subsequent record.
const MAX_SKIP: usize = 105;

enum ReadState {
    // Fixed-size scratch buffer avoids a heap allocation on every record
    // boundary. `target` is 105 for the initial handshake preamble, 3 for all
    // subsequent records.
    SkippingHeader {
        buf: [u8; MAX_SKIP],
        target: usize,
        filled: usize,
    },
    ReadingLength([u8; 2], usize), // (length buffer, bytes already consumed)
}

pub struct TLSObfs {
    inner: AnyStream,
    server: String,
    // bytes left to deliver from the current TLS payload record
    remain: usize,
    // write side: current TLS-wrapped chunk being sent to the inner stream
    first_request: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
    // src bytes represented by write_buf; > 0 while a chunk is in flight
    write_committed: usize,
    read_state: ReadState,
}

impl AsyncWrite for TLSObfs {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // If a previous chunk is still being sent, finish draining it first.
        // Returning Ok(write_committed) signals to the caller how many source
        // bytes that chunk covered; the caller then advances its window.
        if this.write_committed > 0 {
            ready!(drain_write_buf(this, cx))?;
            let committed = this.write_committed;
            this.write_committed = 0;
            return Poll::Ready(Ok(committed));
        }

        // Wrap the next chunk (at most CHUNK_SIZE source bytes) into a TLS
        // Application Data record (or ClientHello for the very first write).
        let end = CHUNK_SIZE.min(buf.len());
        let chunk = &buf[..end];
        this.write_buf = if this.first_request {
            this.first_request = false;
            make_client_hello_msg(chunk, &this.server).into_owned()
        } else {
            let mut v = Vec::with_capacity(5 + chunk.len());
            v.extend_from_slice(&[0x17, 0x03, 0x03]);
            v.push((chunk.len() >> 8) as u8);
            v.push((chunk.len() & 0xff) as u8);
            v.extend_from_slice(chunk);
            v
        };
        this.write_pos = 0;
        this.write_committed = end;

        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Poll::Ready(Ok(end))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        ready!(drain_write_buf(this, cx))?;
        this.write_committed = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Send all remaining bytes of `this.write_buf[this.write_pos..]` to the inner
/// stream, advancing `this.write_pos` as each partial write completes.
fn drain_write_buf(
    this: &mut TLSObfs,
    cx: &mut Context<'_>,
) -> Poll<Result<(), io::Error>> {
    while this.write_pos < this.write_buf.len() {
        let n = ready!(
            Pin::new(&mut this.inner)
                .poll_write(cx, &this.write_buf[this.write_pos..])
        )?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
        }
        this.write_pos += n;
    }
    Poll::Ready(Ok(()))
}

impl AsyncRead for TLSObfs {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            // Phase 1: deliver bytes from the current TLS payload record.
            if this.remain > 0 {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                let limit = this.remain.min(buf.remaining());
                let spare = buf.initialize_unfilled_to(limit);
                let mut sub = ReadBuf::new(&mut spare[..limit]);
                ready!(inner.as_mut().poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )));
                }
                buf.advance(n);
                this.remain -= n;
                return Poll::Ready(Ok(()));
            }

            // Phase 2: parse the next TLS record header (type + version bytes)
            // and 2-byte payload length, updating `this.remain` when done.
            // Both states persist their partial buffers in `this.read_state` so
            // that a Poll::Pending return never loses already-consumed bytes.
            let to_reading_length = match &mut this.read_state {
                ReadState::SkippingHeader {
                    buf: skip_buf,
                    target,
                    filled,
                } => {
                    while *filled < *target {
                        let mut rb = ReadBuf::new(&mut skip_buf[*filled..*target]);
                        ready!(inner.as_mut().poll_read(cx, &mut rb))?;
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::from(
                                io::ErrorKind::UnexpectedEof,
                            )));
                        }
                        *filled += n;
                    }
                    true
                }
                ReadState::ReadingLength(len_buf, filled) => {
                    while *filled < 2 {
                        let mut rb = ReadBuf::new(&mut len_buf[*filled..]);
                        ready!(inner.as_mut().poll_read(cx, &mut rb))?;
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::from(
                                io::ErrorKind::UnexpectedEof,
                            )));
                        }
                        *filled += n;
                    }
                    false
                }
            };

            if to_reading_length {
                this.read_state = ReadState::ReadingLength([0u8; 2], 0);
            } else {
                // Extract length and prepare for the next record header.
                let length = match &this.read_state {
                    ReadState::ReadingLength(len_buf, _) => {
                        BigEndian::read_u16(len_buf) as usize
                    }
                    _ => unreachable!(),
                };
                this.remain = length;
                // Subsequent records have a 3-byte header (type + version).
                this.read_state = ReadState::SkippingHeader {
                    buf: [0u8; MAX_SKIP],
                    target: 3,
                    filled: 0,
                };
                // Loop back to Phase 1 to deliver payload bytes immediately.
            }
        }
    }
}

fn make_client_hello_msg<'a>(data: &[u8], server: &str) -> Cow<'a, [u8]> {
    let random_bytes = rand::random::<[u8; 28]>();
    let session_id = rand::random::<[u8; 32]>();

    let mut buf: Vec<u8> = Vec::new();

    // handshake, TLS 1.0 version, length
    buf.put_u8(22);
    buf.put_slice(&[0x03, 0x01]);
    let length: u16 = (212 + data.len() + server.len()) as u16;
    buf.put_u8((length >> 8) as u8);
    buf.put_u8((length & 0xff) as u8);

    // clientHello, length, TLS 1.2 version
    buf.put_u8(1);
    buf.put_u8(0);
    buf.write_u16::<BigEndian>((208 + data.len() + server.len()) as u16)
        .unwrap();
    buf.put_slice(&[0x03, 0x03]);

    // random with timestamp, sid len, sid
    buf.write_u32::<BigEndian>(Utc::now().timestamp() as u32)
        .unwrap();
    buf.put_slice(&random_bytes);
    buf.put_u8(32);
    buf.put_slice(&session_id);

    // cipher suites
    buf.put_slice(&[0x00, 0x38]);
    buf.put_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
        0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b,
        0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
        0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);

    // compression
    buf.put_slice(&[0x01, 0x00]);

    // extension length
    buf.write_u16::<BigEndian>((79 + data.len() + server.len()) as u16)
        .unwrap();

    // session ticket
    buf.put_slice(&[0x00, 0x23]);
    buf.write_u16::<BigEndian>(data.len() as u16).unwrap();
    buf.put_slice(data);

    // server name
    buf.put_slice(&[0x00, 0x00]);
    buf.write_u16::<BigEndian>((server.len() + 5) as u16)
        .unwrap();
    buf.write_u16::<BigEndian>((server.len() + 3) as u16)
        .unwrap();
    buf.put_u8(0);
    buf.write_u16::<BigEndian>(server.len() as u16).unwrap();
    buf.put_slice(server.as_bytes());

    // ec_point
    buf.put_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);

    // groups
    buf.put_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19,
        0x00, 0x18,
    ]);

    // signature
    buf.put_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03,
        0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03,
        0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);

    // encrypt then mac
    buf.put_slice(&[0x00, 0x16, 0x00, 0x00]);

    // extended master secret
    buf.put_slice(&[0x00, 0x17, 0x00, 0x00]);
    Cow::Owned(buf)
}

impl TLSObfs {
    pub fn new(inner: AnyStream, server: String) -> Self {
        TLSObfs {
            inner,
            server,
            remain: 0,
            first_request: true,
            write_buf: Vec::new(),
            write_pos: 0,
            write_committed: 0,
            // First response: skip 105-byte TLS handshake preamble
            // (ServerHello 96 B + ChangeCipherSpec 6 B + type/version 3 B).
            read_state: ReadState::SkippingHeader {
                buf: [0u8; MAX_SKIP],
                target: MAX_SKIP,
                filled: 0,
            },
        }
    }
}

impl From<TLSObfs> for AnyStream {
    fn from(obfs: TLSObfs) -> Self {
        Box::new(obfs)
    }
}

impl crate::proxy::ProxyStream for TLSObfs {}
