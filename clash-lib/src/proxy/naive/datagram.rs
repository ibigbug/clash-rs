use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use super::CachedEngine;
use futures::{Sink, SinkExt, Stream};
use tokio::sync::mpsc;
use tokio_util::{
    sync::{CancellationToken, PollSender},
    task::AbortOnDropHandle,
};
use wind_core::udp::{UdpPacket as WindPacket, UdpStream};

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
        engine: Arc<CachedEngine>,
        sess: &Session,
        deadline: tokio::time::Instant,
        cancel: CancellationToken,
    ) -> Self {
        let (tx, send_rx) = mpsc::channel(32);
        let (recv_tx, rx) = mpsc::channel(32);
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let udp = UdpStream {
                tx: recv_tx.clone(),
                rx: send_rx,
            };
            tokio::select! {
                result = engine.outbound.handle_udp_with_deadline(udp, Some(deadline)) => {
                    if let Err(error) = result {
                        engine.dial_failed();
                        tracing::debug!("Naive UDP session ended: {error}");
                    }
                }
                _ = cancel.cancelled() => {}
            }
            // Publish any failure before the caller sees the receive channel
            // close.
            drop(recv_tx);
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
            .start_send_unpin(packet.into())
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
        self.rx.poll_recv(cx).map(|packet| {
            packet.map(|packet| {
                super::super::wind::udp_reply(packet, self.local_addr.clone())
            })
        })
    }
}
