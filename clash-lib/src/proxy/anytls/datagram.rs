use std::{
    io,
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

const MAX_PACKET_LENGTH: usize = u16::MAX as usize;

pub struct OutboundDatagramAnytls {
    inner: AnyStream,
    target_addr: SocksAddr,

    // Write state
    send: StreamSendState,

    // Read state
    header_read: usize,
    packet_len: Option<usize>,
    packet_buf: BytesMut,
    length_buf: [u8; 2],
}

impl OutboundDatagramAnytls {
    pub fn new(inner: AnyStream, target_addr: SocksAddr) -> Self {
        Self {
            inner,
            target_addr,
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

impl Sink<UdpPacket> for OutboundDatagramAnytls {
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
        trace!("queued anytls udp packet, len={}", item.data.len());
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

impl Stream for OutboundDatagramAnytls {
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
                            continue; // keep looping; poll_read will register waker when it returns Pending
                        }

                        let packet_len =
                            u16::from_be_bytes(this.length_buf) as usize;
                        this.header_read = 0;
                        if packet_len == 0 {
                            continue;
                        }
                        if packet_len > MAX_PACKET_LENGTH {
                            debug!(
                                "invalid anytls udp packet length: {}",
                                packet_len
                            );
                            return Poll::Ready(None);
                        }

                        this.packet_len = Some(packet_len);
                        this.packet_buf.clear();
                        this.packet_buf.reserve(packet_len);
                    }
                    Err(err) => {
                        debug!("failed to read anytls udp length header: {}", err);
                        return Poll::Ready(None);
                    }
                }
            }

            if let Some(packet_len) = this.packet_len {
                let remaining = packet_len - this.packet_buf.len();
                // Read directly into packet_buf's spare capacity: avoids an
                // intermediate copy through a scratch buffer.
                let n = {
                    let spare = this.packet_buf.spare_capacity_mut();
                    let mut read_buf = ReadBuf::uninit(&mut spare[..remaining]);
                    match inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            debug!("failed to read anytls udp payload: {}", err);
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(())) => read_buf.filled().len(),
                    }
                };
                if n == 0 {
                    return Poll::Ready(None);
                }
                // SAFETY: poll_read initialized exactly `n` bytes starting at
                // spare_capacity_mut()[0]; advance_mut exposes them as
                // initialized.
                unsafe { this.packet_buf.advance_mut(n) };

                if this.packet_buf.len() == packet_len {
                    let data = this.packet_buf.split_to(packet_len).to_vec();
                    this.packet_len = None;
                    return Poll::Ready(Some(UdpPacket {
                        data,
                        src_addr: this.target_addr.clone(),
                        dst_addr: this.target_addr.clone(),
                        inbound_user: None,
                    }));
                }
            }
        }
    }
}
