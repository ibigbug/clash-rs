use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::{
    Sink, SinkExt, Stream, StreamExt, ready,
    stream::{SplitSink, SplitStream},
};
use shadowsocks::{
    ProxySocket,
    relay::udprelay::{
        DatagramReceive, DatagramSend, options::UdpSocketControlData,
    },
};
use tokio::io::ReadBuf;
use tracing::{debug, error, instrument};

use crate::{
    common::errors::new_io_error,
    proxy::{AnyOutboundDatagram, datagram::UdpPacket},
    session::SocksAddr,
};

/// OutboundDatagram wrapper for shadowsocks socket, that takes ShadowsocksUdpIo
/// as underlying I/O
pub struct OutboundDatagramShadowsocks<S> {
    inner: ProxySocket<S>,
    /// The SS server addr
    remote_addr: SocketAddr,

    // for Sink
    pkt: Option<UdpPacket>,

    // for Stream
    buf: Vec<u8>,

    ss_control: UdpSocketControlData,
}

impl<S> OutboundDatagramShadowsocks<S> {
    pub fn new(inner: ProxySocket<S>, remote_addr: SocketAddr) -> Self {
        let mut ss_control = UdpSocketControlData::default();
        ss_control.client_session_id = rand::random::<u64>();

        Self {
            inner,
            pkt: None,
            remote_addr,
            buf: vec![0u8; 65535],

            ss_control,
        }
    }
}

impl<S> Sink<UdpPacket> for OutboundDatagramShadowsocks<S>
where
    S: DatagramSend + Unpin,
{
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_some() {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        Ok(())
    }

    #[instrument(skip(self, cx))]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_none() {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut inner,
            ref mut pkt,
            ref remote_addr,

            ref mut ss_control,
            ..
        } = *self;

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let data = pkt.data.as_ref();
            let addr: shadowsocks::relay::Address =
                (pkt.dst_addr.host(), pkt.dst_addr.port()).into();

            let n = ready!(inner.poll_send_to_with_ctrl(
                *remote_addr,
                &addr,
                ss_control,
                data,
                cx
            ))?;

            debug!(
                "send udp packet to remote ss server, len: {}, remote_addr: {}, \
                 dst_addr: {}",
                n, remote_addr, addr
            );

            ss_control.packet_id = match ss_control.packet_id.checked_add(1) {
                Some(id) => id,
                None => {
                    error!("packet_id overflow, closing socket");
                    return Poll::Ready(Err(io::Error::other("packet_id overflow")));
                }
            };

            let wrote_all = n == data.len();
            *pkt_container = None;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to write entire datagram, written: {n}"
                )))
            };
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(io::Error::other("no packet to send")))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<S> Stream for OutboundDatagramShadowsocks<S>
where
    S: DatagramReceive + Unpin,
{
    type Item = UdpPacket;

    #[instrument(skip(self, cx))]
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let &mut Self {
            ref mut buf,
            ref inner,
            ..
        } = self.get_mut();

        let mut buf = ReadBuf::new(buf);

        let rv = ready!(inner.poll_recv(cx, &mut buf));
        debug!("recv udp packet from remote ss server: {:?}", rv);

        match rv {
            Ok((n, src, ..)) => Poll::Ready(Some(UdpPacket {
                data: buf.filled()[..n].to_vec(),
                src_addr: match src {
                    shadowsocks::relay::Address::SocketAddress(a) => a.into(),
                    _ => SocksAddr::any_ipv4(),
                },
                dst_addr: SocksAddr::any_ipv4(),
                inbound_user: None,
            })),
            Err(_) => Poll::Ready(None),
        }
    }
}

/// Shadowsocks UDP I/O that ProxySocket required
pub(crate) struct ShadowsocksUdpIo {
    w: Mutex<SplitSink<AnyOutboundDatagram, UdpPacket>>,
    r: Mutex<(SplitStream<AnyOutboundDatagram>, BytesMut)>,
}

impl ShadowsocksUdpIo {
    pub fn new(inner: AnyOutboundDatagram) -> Self {
        let (w, r) = inner.split();
        Self {
            w: Mutex::new(w),
            r: Mutex::new((r, BytesMut::new())),
        }
    }
}

impl DatagramSend for ShadowsocksUdpIo {
    fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(new_io_error("not supported for shadowsocks udp io")))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: std::net::SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let mut w = self.w.lock().unwrap();
        match w.start_send_unpin(UdpPacket {
            data: buf.to_vec(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: target.into(),
            inbound_user: None,
        }) {
            Ok(_) => {}
            Err(e) => return Poll::Ready(Err(new_io_error(e.to_string()))),
        }
        match w.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(new_io_error(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut w = self.w.lock().unwrap();
        w.poll_ready_unpin(cx)
            .map_err(|e| new_io_error(e.to_string()))
    }
}

impl DatagramReceive for ShadowsocksUdpIo {
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.r.lock().unwrap();
        let (r, remained) = &mut *g;

        if !remained.is_empty() {
            let to_consume = buf.remaining().min(remained.len());
            let consume = remained.split_to(to_consume);
            buf.put_slice(&consume);
            Poll::Ready(Ok(()))
        } else {
            match r.poll_next_unpin(cx) {
                Poll::Ready(Some(pkt)) => {
                    let to_consume = buf.remaining().min(pkt.data.len());
                    let consume = pkt.data[..to_consume].to_vec();
                    buf.put_slice(&consume);
                    if to_consume < pkt.data.len() {
                        remained.extend_from_slice(&pkt.data[to_consume..]);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(Ok(())),
            }
        }
    }

    fn poll_recv_from(
        &self,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<std::net::SocketAddr>> {
        Poll::Ready(Err(new_io_error("not supported for shadowsocks udp io")))
    }

    fn poll_recv_ready(&self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
