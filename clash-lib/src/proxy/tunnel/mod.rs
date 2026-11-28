use crate::{
    app::{dispatcher::Dispatcher, net::SocketMark},
    common::errors::new_io_error,
    proxy::utils::{ToCanonical, try_create_dualstack_tcplistener},
    session::{Network, Session, SocksAddr, Type},
};
use async_trait::async_trait;
use futures::{Sink, Stream};
use std::{
    io,
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{io::ReadBuf, net::UdpSocket};
use tracing::{info, warn};

use super::{
    datagram::UdpPacket, inbound::InboundHandlerTrait, utils::apply_tcp_options,
};

#[derive(Clone)]
pub struct TunnelInbound {
    listen: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    network: Vec<String>,
    target: SocksAddr,
    fw_mark: Option<SocketMark>,
    proxy: Option<String>,
}

impl Drop for TunnelInbound {
    fn drop(&mut self) {
        warn!("Tunnel inbound listener on {} stopped", self.listen);
    }
}

impl TunnelInbound {
    pub fn new(
        addr: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        network: Vec<String>,
        target: String,
        fw_mark: Option<SocketMark>,
    ) -> crate::Result<Self> {
        Ok(Self {
            listen: addr,
            dispatcher,
            network,
            target: SocksAddr::from_str(&target)?,
            fw_mark,
            proxy: None,
        })
    }

    pub(crate) fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }
}

#[async_trait]
impl InboundHandlerTrait for TunnelInbound {
    fn handle_tcp(&self) -> bool {
        self.network.iter().any(|n| n.eq_ignore_ascii_case("tcp"))
    }

    fn handle_udp(&self) -> bool {
        self.network.iter().any(|n| n.eq_ignore_ascii_case("udp"))
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        if !self.handle_tcp() {
            return Ok(());
        }
        info!(
            "[Tunnel-TCP] listening on {}, remote: {}",
            self.listen, self.target
        );
        let listener = try_create_dualstack_tcplistener(self.listen)?;

        loop {
            let (socket, src_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("tunnel accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            if let Err(e) = apply_tcp_options(&socket) {
                warn!("tunnel apply_tcp_options failed: {e}");
                continue;
            }

            let dispatcher = self.dispatcher.clone();
            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tunnel,
                source: src_addr.to_canonical(),
                destination: self.target.clone(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            let proxy = self.proxy.clone();
            tokio::spawn(async move {
                dispatcher
                    .dispatch_stream_to(sess, Box::new(socket), proxy.as_deref())
                    .await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        if !self.handle_udp() {
            return Ok(());
        }
        let socket = UdpSocket::bind(self.listen).await?;
        info!(
            "[Tunnel-UDP] listening on {}, remote: {}",
            socket.local_addr().unwrap_or(self.listen),
            self.target
        );
        let sess = Session {
            network: Network::Udp,
            typ: Type::Tunnel,
            destination: self.target.clone(),
            so_mark: self.fw_mark,
            ..Default::default()
        };
        let inbound = UdpSession::new(socket, self.target.clone());

        self.dispatcher
            .datagram_session(sess, Box::new(inbound), self.proxy.clone())
            .await;
        Ok(())
    }
}

#[derive(Debug)]
struct UdpSession {
    pub socket: UdpSocket,
    pub dst_addr: SocksAddr,
    pub read_buf: Vec<u8>,
    pub send_buf: Option<(Vec<u8>, SocketAddr)>,
}

impl UdpSession {
    fn new(socket: UdpSocket, dst_addr: SocksAddr) -> Self {
        Self {
            socket,
            dst_addr,
            read_buf: Vec::with_capacity(65507),
            send_buf: None,
        }
    }
}

impl Sink<UdpPacket> for UdpSession {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        let this = self.deref_mut();
        let socket = &this.socket;
        let dst_addr = match item.dst_addr {
            SocksAddr::Ip(socket_addr) => socket_addr,
            SocksAddr::Domain(..) => {
                return Err(new_io_error(
                    "UdpPacket dst_src MUSTBE IpAddr instead of Domain",
                ));
            }
        };

        // Try to send immediately, if blocked, enter the buffer and wait for
        // poll_flush to process
        match socket.try_send_to(&item.data, dst_addr) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                this.send_buf = Some((item.data, dst_addr));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.deref_mut();
        if let Some((data, addr)) = &this.send_buf {
            std::task::ready!(this.socket.poll_send_to(cx, data, *addr))?;
            this.send_buf = None;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for UdpSession {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.deref_mut();
        let socket = &this.socket;
        this.read_buf.resize(this.read_buf.capacity(), 0);
        let mut buf = ReadBuf::new(&mut this.read_buf);
        match socket.poll_recv_from(cx, &mut buf) {
            Poll::Ready(Ok(src_addr)) => {
                let data = buf.filled().to_vec();
                let dst_addr = this.dst_addr.clone();
                let src_addr = SocksAddr::from(src_addr);
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr,
                    inbound_user: None,
                }))
            }
            Poll::Ready(Err(e)) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    Poll::Pending
                } else {
                    // FIXME
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
