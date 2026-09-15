//! Sink/Stream adapters between Clash UDP packets and Wind's TUIC UDP stream.
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};
use wind_core::udp::UdpPacket as WindUdpPacket;

use crate::{
    common::errors::new_io_error,
    proxy::{datagram::UdpPacket, tuic::types::SocketAdderTrans},
};

use super::{TuicDatagramOutbound, types::from_target};

impl Sink<UdpPacket> for TuicDatagramOutbound {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let packet = WindUdpPacket {
            source: None,
            target: item.dst_addr.into_tuic(),
            payload: item.data.into(),
        };
        self.send_tx
            .start_send_unpin(packet)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|v| new_io_error(format!("{v:?}")))
    }
}

impl Stream for TuicDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let local_addr = self.local_addr.clone();
        self.recv_rx.poll_recv(cx).map(|opt| {
            opt.map(|packet| {
                UdpPacket::new(
                    packet.payload.to_vec(),
                    from_target(packet.target),
                    local_addr,
                )
            })
        })
    }
}
