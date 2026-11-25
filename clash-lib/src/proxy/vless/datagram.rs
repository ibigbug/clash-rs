use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::{Sink, Stream, ready};
use tokio::io::{AsyncRead, ReadBuf};
use tracing::{debug, trace};

use crate::{
    proxy::{
        AnyStream,
        datagram::{StreamSendState, UdpPacket},
    },
    session::SocksAddr,
};

const MAX_PACKET_LENGTH: usize = 1024 << 3; // 8KB max packet length

pub struct OutboundDatagramVless {
    inner: AnyStream,
    remote_addr: SocksAddr,

    // Write state
    send: StreamSendState,

    // Read state
    packet_buf: BytesMut,
    remaining_bytes: usize,
    length_buf: [u8; 2],
    header_read: usize,
}

impl OutboundDatagramVless {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            send: StreamSendState::Idle,
            packet_buf: BytesMut::new(),
            remaining_bytes: 0,
            length_buf: [0; 2],
            header_read: 0,
        }
    }

    fn encode_packet(payload: &[u8]) -> io::Result<BytesMut> {
        let mut write_buf = BytesMut::with_capacity(2 + payload.len());

        // VLESS UDP packet format is simpler than expected:
        // Just 2-byte length + payload data
        // No address encoding in the packet data phase!

        if payload.len() > MAX_PACKET_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "packet too large: {} > {}",
                    payload.len(),
                    MAX_PACKET_LENGTH
                ),
            ));
        }

        // Write length header (big-endian)
        write_buf.put_u16(payload.len() as u16);

        // Write payload
        write_buf.put_slice(payload);

        trace!("encoded VLESS UDP packet: len={}", payload.len());
        Ok(write_buf)
    }
}

impl Sink<UdpPacket> for OutboundDatagramVless {
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

        // Handle large packets by chunking them
        let total_len = item.data.len();
        if total_len == 0 {
            return Ok(()); // Skip empty packets
        }

        // For now, handle first chunk or small packets
        let chunk_size = if total_len <= MAX_PACKET_LENGTH {
            total_len
        } else {
            MAX_PACKET_LENGTH
        };

        this.send
            .start(Self::encode_packet(&item.data[..chunk_size])?)?;
        debug!("queued VLESS UDP packet, data_len={}", chunk_size);
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        this.send.poll_close(Pin::new(&mut this.inner), cx)
    }
}

impl Stream for OutboundDatagramVless {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut inner = Pin::new(&mut this.inner);

        loop {
            // Phase 1: read the 2-byte length header.  TCP may deliver a
            // single byte at a time, so we must accumulate until both bytes
            // are available.  The previous code treated a 1-byte read as
            // "incomplete" and returned EOF, prematurely closing the stream.
            if this.remaining_bytes == 0 && this.header_read < 2 {
                let mut header_read_buf =
                    ReadBuf::new(&mut this.length_buf[this.header_read..]);
                match ready!(inner.as_mut().poll_read(cx, &mut header_read_buf)) {
                    Ok(()) => {
                        let n = header_read_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(None); // connection closed
                        }
                        this.header_read += n;
                        if this.header_read < 2 {
                            continue; // need the second header byte
                        }

                        let packet_len =
                            u16::from_be_bytes(this.length_buf) as usize;
                        this.header_read = 0;

                        if packet_len == 0 {
                            trace!("received empty packet");
                            continue; // skip empty packets
                        }

                        if packet_len > MAX_PACKET_LENGTH {
                            debug!("packet too large: {} bytes", packet_len);
                            return Poll::Ready(None);
                        }

                        this.remaining_bytes = packet_len;
                        this.packet_buf.clear();
                        this.packet_buf.reserve(packet_len);
                        trace!("expecting VLESS UDP packet of {} bytes", packet_len);
                    }
                    Err(e) => {
                        debug!("failed to read length header: {}", e);
                        return Poll::Ready(None);
                    }
                }
            }

            // Phase 2: read the packet payload.  TCP may deliver it in
            // multiple chunks; we must accumulate until the full packet is
            // received before returning it.  The previous code returned a
            // UdpPacket for every poll_read call, splitting a single VLESS
            // UDP packet into multiple items and corrupting the data stream.
            if this.remaining_bytes > 0 {
                let remaining = this.remaining_bytes - this.packet_buf.len();
                let n = {
                    let spare = this.packet_buf.spare_capacity_mut();
                    let mut read_buf = ReadBuf::uninit(&mut spare[..remaining]);
                    match inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            debug!("failed to read packet data: {}", e);
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                    }
                };
                if n == 0 {
                    return Poll::Ready(None); // connection closed
                }
                // SAFETY: poll_read initialized exactly n bytes starting at
                // the beginning of the spare capacity.
                unsafe { this.packet_buf.advance_mut(n) };

                if this.packet_buf.len() == this.remaining_bytes {
                    let data =
                        this.packet_buf.split_to(this.remaining_bytes).to_vec();
                    this.remaining_bytes = 0;
                    trace!("received complete VLESS UDP packet, len={}", data.len());
                    return Poll::Ready(Some(UdpPacket {
                        data,
                        src_addr: this.remote_addr.clone(),
                        dst_addr: this.remote_addr.clone(),
                        inbound_user: None,
                    }));
                }
                // Partial read: loop and continue accumulating.
            }
        }
    }
}
