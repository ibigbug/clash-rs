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
        // The sink owns the stream: shut it down so the server sees the
        // association end instead of an idle connection.
        let this = self.get_mut();
        this.send.poll_close(Pin::new(&mut this.inner), cx)
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
            // A read that fills nothing is EOF: VMess turns the empty
            // end-of-stream chunk into one. Reporting it as an empty packet
            // would keep the session reading after the server ended it.
            Ok(()) if buf.filled().is_empty() => Poll::Ready(None),
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

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};

    use super::*;

    /// Closing the sink must shut the stream down, so the server sees the
    /// association end rather than an idle connection.
    #[tokio::test]
    async fn test_vmess_datagram_close_shuts_stream_down() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let remote_addr: SocksAddr = "8.8.8.8:53".parse().unwrap();
        let mut client =
            OutboundDatagramVmess::new(Box::new(client_io), remote_addr.clone());
        let mut server =
            OutboundDatagramVmess::new(Box::new(server_io), remote_addr.clone());

        client
            .send(UdpPacket {
                data: b"last".to_vec(),
                src_addr: remote_addr.clone(),
                dst_addr: remote_addr.clone(),
                inbound_user: None,
            })
            .await
            .unwrap();
        client.close().await.expect("close must succeed");

        let first = server.next().await.expect("packet sent before close");
        assert_eq!(first.data, b"last");
        let end =
            tokio::time::timeout(std::time::Duration::from_secs(1), server.next())
                .await
                .expect("server must see EOF after the client closed the sink");
        assert!(end.is_none());
    }

    /// EOF on the stream must end it, not yield empty packets forever.
    #[tokio::test]
    async fn test_vmess_datagram_ends_on_eof() {
        let (client_io, server_io) = tokio::io::duplex(64);
        drop(server_io);
        let remote_addr: SocksAddr = "8.8.8.8:53".parse().unwrap();
        let mut client =
            OutboundDatagramVmess::new(Box::new(client_io), remote_addr);
        assert!(client.next().await.is_none());
    }
}
