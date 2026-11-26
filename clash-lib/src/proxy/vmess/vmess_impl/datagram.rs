use std::{io, pin::Pin, task::Poll};

use bytes::BytesMut;
use futures::{Sink, Stream, ready};
use tracing::{debug, error, instrument};

use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    proxy::{
        AnyStream,
        datagram::{StreamSendState, UdpPacket},
    },
    session::SocksAddr,
};

pub struct OutboundDatagramVmess {
    inner: AnyStream,
    remote_addr: SocksAddr,

    send: StreamSendState,
    buf: Vec<u8>,
}

impl OutboundDatagramVmess {
    pub fn new(inner: AnyStream, remote_addr: SocksAddr) -> Self {
        Self {
            inner,
            remote_addr,
            send: StreamSendState::Idle,
            buf: vec![0u8; 65535],
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramVmess {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        this.send.poll_send(Pin::new(&mut this.inner), cx)
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let this = self.get_mut();
        // A VMess UDP stream is bound to a single destination; reject the
        // packet up front so it never occupies the send slot.
        if item.dst_addr != this.remote_addr {
            error!(
                "udp packet dst_addr not match, pkt.dst_addr: {}, remote_addr: {}",
                item.dst_addr, this.remote_addr
            );
            return Err(io::Error::other("udp packet dst_addr not match"));
        }
        debug!(
            "send udp packet to remote vmess server, len: {}, remote_addr: {}",
            item.data.len(),
            this.remote_addr
        );
        this.send.start(BytesMut::from(&item.data[..]))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        this.send.poll_send(Pin::new(&mut this.inner), cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl Stream for OutboundDatagramVmess {
    type Item = UdpPacket;

    #[instrument(skip(self, cx))]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref mut inner,
            ref remote_addr,
            ..
        } = *self;

        let inner = Pin::new(inner);

        let mut buf = ReadBuf::new(buf);

        let rv = ready!(inner.poll_read(cx, &mut buf));

        match rv {
            Ok(()) => Poll::Ready(Some(UdpPacket {
                data: buf.filled().to_vec(),
                src_addr: remote_addr.clone(),
                dst_addr: SocksAddr::any_ipv4(),
                inbound_user: None,
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}
