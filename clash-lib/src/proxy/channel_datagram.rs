use super::datagram::UdpPacket;
use futures::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

#[derive(Debug)]
pub struct ChannelDatagram {
    rx: mpsc::Receiver<UdpPacket>,
    tx: PollSender<UdpPacket>,
}

impl ChannelDatagram {
    pub fn new(tx: mpsc::Sender<UdpPacket>, rx: mpsc::Receiver<UdpPacket>) -> Self {
        Self {
            rx,
            tx: PollSender::new(tx),
        }
    }
}

impl Stream for ChannelDatagram {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl Sink<UdpPacket> for ChannelDatagram {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.tx
            .poll_reserve(cx)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        // Reject a close we can already observe. If the receiver drops after
        // this check, send_item can still return Ok using the reserved permit.
        if self.tx.get_ref().is_some_and(mpsc::Sender::is_closed) {
            self.tx.abort_send();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.tx
            .send_item(item)
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.tx.abort_send();
        self.tx.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::SinkExt;
    use tokio_test::{assert_pending, assert_ready, task};

    fn full_queue() -> (ChannelDatagram, mpsc::Receiver<UdpPacket>) {
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(UdpPacket::default()).unwrap();
        (ChannelDatagram::new(tx, mpsc::channel(1).1), rx)
    }

    #[test]
    fn send_resumes_when_capacity_returns() {
        let (mut sink, mut rx) = full_queue();
        let packet = UdpPacket {
            data: vec![42],
            ..Default::default()
        };
        let mut send = task::spawn(sink.send(packet));
        assert_pending!(send.poll());
        assert!(rx.try_recv().unwrap().data.is_empty());
        assert!(send.is_woken());
        assert_ready!(send.poll()).unwrap();
        assert_eq!(rx.try_recv().unwrap().data, [42]);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn closing_receiver_wakes_blocked_send_with_error() {
        let (mut sink, rx) = full_queue();
        let mut send = task::spawn(sink.send(UdpPacket::default()));
        assert_pending!(send.poll());
        drop(rx);
        assert!(send.is_woken());
        assert_eq!(
            assert_ready!(send.poll()).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn receiver_closing_after_reservation_rejects_packet() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut sink = ChannelDatagram::new(tx, mpsc::channel(1).1);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_ready!(sink.poll_ready_unpin(&mut cx)).unwrap();
        rx.close();
        let err = sink.start_send_unpin(UdpPacket::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
    }
}
