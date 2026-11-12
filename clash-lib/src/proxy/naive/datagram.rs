use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};
use tokio::sync::mpsc;
use tokio_util::{
    sync::{CancellationToken, PollSender},
    task::AbortOnDropHandle,
};
use wind_core::{
    Outbound,
    rule::NetworkType,
    types::TargetAddr,
    udp::{UdpPacket as WindPacket, UdpStream},
};
use wind_naive::NaiveOutbound;

use crate::{
    proxy::datagram::UdpPacket,
    session::{Session, SocksAddr},
};

pub(super) struct Datagram {
    tx: PollSender<WindPacket>,
    rx: mpsc::Receiver<WindPacket>,
    local_addr: SocksAddr,
    _task: AbortOnDropHandle<()>,
}

impl Datagram {
    pub(super) fn new(
        outbound: Arc<NaiveOutbound>,
        sess: &Session,
        cancel: CancellationToken,
    ) -> Self {
        let (tx, send_rx) = mpsc::channel(32);
        let (recv_tx, rx) = mpsc::channel(32);
        let flow = super::flow(sess, NetworkType::Udp);
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            tokio::select! {
                result = outbound.handle_udp(flow, UdpStream { tx: recv_tx, rx: send_rx }) => {
                    if let Err(error) = result { tracing::debug!("Naive UDP session ended: {error}"); }
                }
                _ = cancel.cancelled() => {}
            }
        }));
        Self {
            tx: PollSender::new(tx),
            rx,
            local_addr: sess.source.into(),
            _task: task,
        }
    }
}

impl Sink<UdpPacket> for Datagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.tx.poll_ready_unpin(cx).map_err(io::Error::other)
    }

    fn start_send(mut self: Pin<&mut Self>, packet: UdpPacket) -> io::Result<()> {
        if packet.data.len() > u16::MAX as usize
            || packet
                .dst_addr
                .domain()
                .is_some_and(|name| name.len() > u8::MAX as usize)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Naive UoT packet exceeds framing limits",
            ));
        }
        self.tx
            .start_send_unpin(WindPacket {
                source: None,
                target: super::target(&packet.dst_addr),
                payload: packet.data.into(),
            })
            .map_err(io::Error::other)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.tx.poll_flush_unpin(cx).map_err(io::Error::other)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.tx.poll_close_unpin(cx).map_err(io::Error::other)
    }
}

impl Stream for Datagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<UdpPacket>> {
        let local = self.local_addr.clone();
        self.rx.poll_recv(cx).map(|packet| {
            packet.map(|packet| {
                let peer = match packet.target {
                    TargetAddr::IPv4(ip, port) => SocksAddr::Ip((ip, port).into()),
                    TargetAddr::IPv6(ip, port) => SocksAddr::Ip((ip, port).into()),
                    TargetAddr::Domain(host, port) => SocksAddr::Domain(host, port),
                };
                UdpPacket::new(packet.payload.to_vec(), peer, local)
            })
        })
    }
}
