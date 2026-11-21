use super::datagram::UdpPacket;
use crate::common::errors::new_io_error;
use futures::{Sink, Stream, ready};
use std::task::Poll;

#[derive(Debug)]
pub struct ChannelDatagram {
    rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    tx: tokio::sync::mpsc::Sender<UdpPacket>,

    pkt: Option<UdpPacket>,
    flushed: bool,
}

impl ChannelDatagram {
    pub fn new(
        tx: tokio::sync::mpsc::Sender<UdpPacket>,
        rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    ) -> Self {
        Self {
            rx,
            tx,
            pkt: None,
            flushed: true,
        }
    }
}

impl Stream for ChannelDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for ChannelDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(
        self: std::pin::Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut tx,
            ref mut pkt,
            ref mut flushed,
            ..
        } = *self;

        let pkt = pkt
            .take()
            .ok_or(new_io_error("no packet to send, call start_send first"))?;

        match tx.try_send(pkt) {
            Ok(_) => {
                *flushed = true;
                Poll::Ready(Ok(()))
            }
            Err(err) => {
                self.pkt = Some(err.into_inner());
                Poll::Ready(Err(new_io_error(
                    "could not send packet, queue full or disconnected",
                )))
            }
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
