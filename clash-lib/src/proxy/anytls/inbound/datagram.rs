use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{
        AnyStream,
        datagram::{StreamSendState, UdpPacket},
    },
    session::SocksAddr,
};

pub(super) const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

/// Wraps the post-AnyTLS-handshake TLS stream for UDP-over-TCP v2.
///
/// Packet format: `u16(len) | payload`  (big-endian length prefix).
pub struct InboundDatagramAnytls {
    inner: AnyStream,
    peer_addr: SocksAddr,

    // Write state
    send: StreamSendState,

    // Read state
    header_read: usize,
    packet_len: Option<usize>,
    packet_buf: BytesMut,
    length_buf: [u8; 2],
}

impl fmt::Debug for InboundDatagramAnytls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundDatagramAnytls")
            .field("peer_addr", &self.peer_addr)
            .finish()
    }
}

impl InboundDatagramAnytls {
    pub fn new(inner: AnyStream, peer_addr: SocksAddr) -> Self {
        Self {
            inner,
            peer_addr,
            send: StreamSendState::Idle,
            header_read: 0,
            packet_len: None,
            packet_buf: BytesMut::new(),
            length_buf: [0; 2],
        }
    }

    fn encode_packet(payload: &[u8]) -> io::Result<BytesMut> {
        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "udp payload too large for anytls uot: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }
        let mut buf = BytesMut::with_capacity(2 + payload.len());
        buf.put_u16(payload.len() as u16);
        buf.put_slice(payload);
        Ok(buf)
    }
}

impl Sink<UdpPacket> for InboundDatagramAnytls {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        this.send.poll_send(Pin::new(&mut this.inner), cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.send.start(Self::encode_packet(&item.data)?)?;
        trace!("queued anytls inbound udp packet, len={}", item.data.len());
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        this.send.poll_send(Pin::new(&mut this.inner), cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for InboundDatagramAnytls {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            if this.packet_len.is_none() {
                let mut length_read_buf =
                    ReadBuf::new(&mut this.length_buf[this.header_read..]);
                match ready!(inner.as_mut().poll_read(cx, &mut length_read_buf)) {
                    Ok(()) => {
                        let read = length_read_buf.filled().len();
                        if read == 0 {
                            return Poll::Ready(None);
                        }
                        this.header_read += read;
                        if this.header_read < this.length_buf.len() {
                            continue;
                        }
                        let packet_len =
                            u16::from_be_bytes(this.length_buf) as usize;
                        this.header_read = 0;
                        if packet_len == 0 {
                            // Zero-length packet — valid empty datagram, return
                            // immediately.
                            return Poll::Ready(Some(UdpPacket {
                                data: Vec::new(),
                                src_addr: this.peer_addr.clone(),
                                dst_addr: this.peer_addr.clone(),
                                inbound_user: None,
                            }));
                        }
                        if packet_len > MAX_PACKET_LENGTH {
                            debug!(
                                "invalid anytls inbound udp packet length: {}",
                                packet_len
                            );
                            return Poll::Ready(None);
                        }
                        this.packet_len = Some(packet_len);
                        this.packet_buf.clear();
                        this.packet_buf.reserve(packet_len);
                    }
                    Err(err) => {
                        debug!(
                            "failed to read anytls inbound udp length header: {}",
                            err
                        );
                        return Poll::Ready(None);
                    }
                }
            }

            if let Some(packet_len) = this.packet_len {
                let remaining = packet_len - this.packet_buf.len();
                let n = {
                    let spare = this.packet_buf.spare_capacity_mut();
                    let mut read_buf = ReadBuf::uninit(&mut spare[..remaining]);
                    match inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            debug!(
                                "failed to read anytls inbound udp payload: {}",
                                err
                            );
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                    }
                };
                if n == 0 {
                    return Poll::Ready(None);
                }
                // SAFETY: poll_read initialised exactly `n` bytes.
                unsafe { this.packet_buf.advance_mut(n) };

                if this.packet_buf.len() == packet_len {
                    let data = this.packet_buf.split_to(packet_len).to_vec();
                    this.packet_len = None;
                    return Poll::Ready(Some(UdpPacket {
                        data,
                        src_addr: this.peer_addr.clone(),
                        dst_addr: this.peer_addr.clone(),
                        inbound_user: None,
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn make_peer_addr() -> SocksAddr {
        SocksAddr::try_from(("127.0.0.1".to_owned(), 9999u16)).unwrap()
    }

    fn make_packet(data: Vec<u8>) -> UdpPacket {
        let addr = make_peer_addr();
        UdpPacket {
            data,
            src_addr: addr.clone(),
            dst_addr: addr,
            inbound_user: None,
        }
    }

    /// Helper: encode a single packet in wire format `u16(len) | payload`.
    fn encode_wire(payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + payload.len());
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    // ── Read path ────────────────────────────────────────────────────────────

    /// `\x00\x05hello` → `UdpPacket { data: b"hello" }`.
    #[tokio::test]
    async fn test_read_normal_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), peer_addr.clone());

        client_side.write_all(&encode_wire(b"hello")).await.unwrap();
        // Close the client end so poll_next can return None after the packet.
        drop(client_side);

        let pkt = datagram.next().await.expect("expected one packet");
        assert_eq!(pkt.data, b"hello");
        assert_eq!(pkt.src_addr, peer_addr);
        assert_eq!(pkt.dst_addr, peer_addr);
        assert!(pkt.inbound_user.is_none());

        assert!(datagram.next().await.is_none(), "expected EOF");
    }

    /// `\x00\x00` (zero-length) → `UdpPacket { data: [] }` — must NOT be
    /// dropped. This was a bug-fix regression case.
    #[tokio::test]
    async fn test_read_zero_length_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), peer_addr);

        client_side.write_all(&[0x00, 0x00]).await.unwrap();
        drop(client_side);

        let pkt = datagram
            .next()
            .await
            .expect("zero-length packet must not be None");
        assert!(
            pkt.data.is_empty(),
            "zero-length packet must yield empty data, got {:?}",
            pkt.data
        );
    }

    /// Two packets concatenated in the stream → both returned in order.
    #[tokio::test]
    async fn test_read_two_consecutive_packets() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), peer_addr);

        let mut wire = encode_wire(b"first");
        wire.extend(encode_wire(b"second"));
        client_side.write_all(&wire).await.unwrap();
        drop(client_side);

        let pkt1 = datagram.next().await.expect("expected first packet");
        assert_eq!(pkt1.data, b"first");

        let pkt2 = datagram.next().await.expect("expected second packet");
        assert_eq!(pkt2.data, b"second");

        assert!(
            datagram.next().await.is_none(),
            "expected EOF after two packets"
        );
    }

    /// EOF on inner stream → `poll_next` returns `None`.
    #[tokio::test]
    async fn test_read_eof_returns_none() {
        let (client_side, server_side) = duplex(4096);
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), make_peer_addr());

        drop(client_side); // immediate EOF

        assert!(
            datagram.next().await.is_none(),
            "EOF on inner stream must yield None"
        );
    }

    // ── Write path (Sink)
    // ─────────────────────────────────────────────────────

    /// Sending `UdpPacket { data: b"hello" }` writes `\x00\x05hello` to the
    /// inner stream.
    #[tokio::test]
    async fn test_write_normal_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), peer_addr.clone());

        datagram.send(make_packet(b"hello".to_vec())).await.unwrap();

        let mut buf = vec![0u8; 7];
        client_side.read_exact(&mut buf).await.unwrap();

        assert_eq!(
            &buf[..2],
            &[0x00, 0x05],
            "length prefix should be 5 (big-endian)"
        );
        assert_eq!(&buf[2..], b"hello", "payload mismatch");
    }

    /// Sending an empty payload writes exactly `\x00\x00` to the inner stream.
    #[tokio::test]
    async fn test_write_empty_packet() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), peer_addr.clone());

        datagram.send(make_packet(vec![])).await.unwrap();

        let mut buf = vec![0u8; 2];
        client_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            &buf,
            &[0x00, 0x00],
            "empty packet must produce two zero bytes"
        );
    }

    /// A payload larger than `u16::MAX` bytes must produce an error — not a
    /// silent truncation or panic.
    #[tokio::test]
    async fn test_write_oversized_packet_returns_error() {
        let (_client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), peer_addr.clone());

        let oversized = vec![0u8; MAX_PACKET_LENGTH + 1];
        let result = datagram.send(make_packet(oversized)).await;

        assert!(
            result.is_err(),
            "sending a payload > u16::MAX must return an error"
        );
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Verify the round-trip: write a packet, read the wire bytes back, decode
    /// them manually.
    #[tokio::test]
    async fn test_write_then_read_wire_bytes() {
        let (mut client_side, server_side) = duplex(4096);
        let peer_addr = make_peer_addr();
        let mut datagram =
            InboundDatagramAnytls::new(Box::new(server_side), peer_addr.clone());

        let payload = b"round-trip";
        datagram.send(make_packet(payload.to_vec())).await.unwrap();

        // Read the raw bytes from the other end and verify the framing.
        let expected_len = payload.len();
        let mut buf = vec![0u8; 2 + expected_len];
        client_side.read_exact(&mut buf).await.unwrap();

        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(
            len, expected_len,
            "decoded length must match payload length"
        );
        assert_eq!(&buf[2..], payload, "decoded payload must match");
    }
}
