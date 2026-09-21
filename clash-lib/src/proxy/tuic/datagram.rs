//! Adapter between Clash UDP packets and a Wind TUIC UDP stream.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};
use tracing::debug;
use wind_core::{
    AppContext, FlowContext, Outbound,
    hooks::Protocol,
    rule::NetworkType,
    udp::{UdpPacket as WindUdpPacket, UdpStream as WindUdpStream},
};
use wind_tuic::quinn::outbound::TuicOutbound;

use crate::{
    common::errors::new_io_error,
    proxy::datagram::UdpPacket,
    session::{Session, SocksAddr},
};

/// Clash-side handle for one Wind-owned TUIC UDP association.
#[derive(Debug)]
pub(super) struct TuicDatagramOutbound {
    send_tx: tokio_util::sync::PollSender<WindUdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<WindUdpPacket>,
    local_addr: SocksAddr,
}

impl TuicDatagramOutbound {
    pub(super) fn new(
        outbound: Arc<TuicOutbound>,
        ctx: Arc<AppContext>,
        sess: &Session,
    ) -> Self {
        let (send_tx, send_rx) = tokio::sync::mpsc::channel(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel(32);
        let stream = WindUdpStream {
            tx: recv_tx,
            rx: send_rx,
        };
        let flow = FlowContext {
            target: sess.destination.clone().into(),
            network: NetworkType::Udp,
            source: Some(sess.source),
            inbound_tag: "tuic".into(),
            protocol: Protocol::Tuic,
            user: None,
            inbound_port: None,
            inbound_type: None,
        };

        ctx.tasks.spawn(async move {
            if let Err(err) = outbound.handle_udp(flow, stream).await {
                debug!("TUIC UDP session ended: {err}");
            }
        });

        Self {
            send_tx: tokio_util::sync::PollSender::new(send_tx),
            recv_rx,
            local_addr: sess.source.into(),
        }
    }
}

impl Sink<UdpPacket> for TuicDatagramOutbound {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|err| new_io_error(format!("{err:?}")))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        packet: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(WindUdpPacket {
                source: None,
                target: packet.dst_addr.into(),
                payload: packet.data.into(),
            })
            .map_err(|err| new_io_error(format!("{err:?}")))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|err| new_io_error(format!("{err:?}")))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|err| new_io_error(format!("{err:?}")))
    }
}

impl Stream for TuicDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let local_addr = self.local_addr.clone();
        self.recv_rx.poll_recv(cx).map(|packet| {
            packet.map(|packet| {
                UdpPacket::new(
                    packet.payload.to_vec(),
                    packet.target.into(),
                    local_addr,
                )
            })
        })
    }
}
