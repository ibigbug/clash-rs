use crate::app::net::SocketMark;
mod udp;

use super::{channel_datagram::ChannelDatagram, inbound::InboundHandlerTrait};
use crate::{
    app::dispatcher::Dispatcher,
    common::errors::new_io_error,
    proxy::{
        datagram::UdpPacket,
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_socket},
    },
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use etherparse::PacketBuilder;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing::{info, trace, warn};
use udp::UdpReceiver;

use crate::app::dns::{ThreadSafeDNSResolver, exchange_with_resolver};

pub struct TproxyInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<SocketMark>,
    dns_resolver: Option<ThreadSafeDNSResolver>,
    dns_hijack: bool,
}

impl Drop for TproxyInbound {
    fn drop(&mut self) {
        warn!("Tproxy inbound listener on {} stopped", self.addr);
    }
}

impl TproxyInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<SocketMark>,
        dns_resolver: Option<ThreadSafeDNSResolver>,
        dns_hijack: bool,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            fw_mark,
            dns_resolver,
            dns_hijack,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for TproxyInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        true
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let (socket, dualstack) =
            try_create_dualstack_socket(self.addr, socket2::Type::STREAM)?;
        if dualstack || self.addr.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        }
        if self.addr.is_ipv6() {
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&self.addr.into())?;
        socket.listen(1024)?;

        let listener = TcpListener::from_std(socket.into())?;

        loop {
            let (socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("tproxy accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let src_addr = match socket.peer_addr() {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("tproxy peer_addr failed: {e}");
                    continue;
                }
            };
            // for dualstack socket src_addr may be ipv4 or ipv6;
            // tcpstream.local_addr() is the proxy destination
            // listener.local_addr() is [::]:port for dualstack
            // No simple way to implement allow lan logic
            // TODO
            // if !self.allow_lan && !src_addr.ip().is_loopback() {
            //     warn!("Connection from {} is not allowed localaddr:{}",
            // src_addr,listener.local_addr()?);     continue;
            // }

            if let Err(e) = apply_tcp_options(&socket) {
                warn!("tproxy apply_tcp_options failed: {e}");
                continue;
            }

            // local_addr is getsockname
            let orig_dst = match socket.local_addr() {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("tproxy local_addr failed: {e}");
                    continue;
                }
            };

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tproxy,
                source: src_addr,
                destination: orig_dst.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            trace!("tproxy new tcp conn {}", sess);

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        #[cfg(target_os = "android")]
        if let Some(mark) = self.fw_mark {
            mark.validate()?;
        }
        let (socket, dual_stack) =
            try_create_dualstack_socket(self.addr, socket2::Type::DGRAM)?;
        let bind_ip = self.addr.ip().to_canonical();
        let receive_ipv4 = dual_stack || bind_ip.is_ipv4();
        if receive_ipv4 {
            socket.set_ip_transparent_v4(true)?;
        }
        if self.addr.is_ipv6() {
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;
        let listener = UdpReceiver::bind(socket, self.addr, receive_ipv4)?;
        let replies = ReplySockets {
            v4: receive_ipv4
                .then(|| new_reply_socket(socket2::Domain::IPV4))
                .transpose()?,
            v6: bind_ip
                .is_ipv6()
                .then(|| new_reply_socket(socket2::Domain::IPV6))
                .transpose()?,
        };
        info!("TPROXY UDP listening at: {}", listener.local_addr);

        handle_inbound_datagram(
            self.allow_lan,
            Arc::new(replies),
            self.fw_mark,
            listener,
            self.dispatcher.clone(),
            self.dns_resolver.clone(),
            self.dns_hijack,
        )
        .await
    }
}

struct ReplySockets {
    v4: Option<tokio::io::unix::AsyncFd<socket2::Socket>>,
    v6: Option<tokio::io::unix::AsyncFd<socket2::Socket>>,
}

// Client replies follow the route to the client. The outbound session mark
// can select an upstream routing table with no return path to that client.
fn new_reply_socket(
    domain: socket2::Domain,
) -> io::Result<tokio::io::unix::AsyncFd<socket2::Socket>> {
    let socket = socket2::Socket::new(
        domain,
        socket2::Type::RAW,
        Some(libc::IPPROTO_RAW.into()),
    )
    .map_err(|err| {
        let hint = if err.kind() == io::ErrorKind::PermissionDenied {
            " (check CAP_NET_RAW and the process security policy)"
        } else {
            ""
        };
        io::Error::new(
            err.kind(),
            format!(
                "failed to create TPROXY UDP raw reply socket ({domain:?}): \
                 {err}{hint}"
            ),
        )
    })?;
    socket.set_nonblocking(true)?;
    // SAFETY: AsyncFd owns this socket until deregistration.
    unsafe { Ok(tokio::io::unix::AsyncFd::register(socket)?) }
}
async fn sendto_with_src(
    sockets: &ReplySockets,
    buf: &[u8],
    dst: SocketAddr,
    src: SocketAddr,
) -> io::Result<()> {
    let src = src.to_canonical();
    let dst = dst.to_canonical();
    let socket = if src.is_ipv4() {
        &sockets.v4
    } else {
        &sockets.v6
    }
    .as_ref()
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "reply address family is not enabled",
        )
    })?;
    let mut packet: Vec<u8>;
    let builder;
    match (src, dst) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            builder = PacketBuilder::ipv4(src.ip().octets(), dst.ip().octets(), 64)
                .udp(src.port(), dst.port());
            packet = Vec::<u8>::with_capacity(builder.size(buf.len()));
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            builder = PacketBuilder::ipv6(src.ip().octets(), dst.ip().octets(), 64)
                .udp(src.port(), dst.port());
            packet = Vec::<u8>::with_capacity(builder.size(buf.len()));
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and destination address families do not match",
            ));
        }
    }
    builder
        .write(&mut packet, buf)
        .map_err(|x| new_io_error(format!("failed to build udp packet:{}", x)))?;
    let addr = if let SocketAddr::V6(mut v6) = dst {
        // Linux requires port zero on an IPv6 raw socket.
        v6.set_port(0);
        SocketAddr::V6(v6)
    } else {
        dst
    };
    let addr = socket2::SockAddr::from(addr);
    socket
        .async_io(tokio::io::Interest::WRITABLE, |socket| {
            socket.send_to(&packet, &addr)
        })
        .await?;
    Ok(())
}

async fn handle_inbound_datagram(
    _allow_lan: bool,
    reply_sockets: Arc<ReplySockets>,
    fw_mark: Option<SocketMark>,
    mut socket: UdpReceiver,
    dispatcher: Arc<Dispatcher>,
    dns_resolver: Option<ThreadSafeDNSResolver>,
    dns_hijack: bool,
) -> std::io::Result<()> {
    // dispatcher <-> tproxy communications
    let (l_tx, l_rx) = tokio::sync::mpsc::channel(32);

    // forward packets from tproxy to dispatcher
    let (d_tx, d_rx) = tokio::sync::mpsc::channel(32);

    // for dispatcher - the dispatcher would receive packets from this channel,
    // which is from the stack and send back packets to this channel, which is
    // to the tproxy
    let udp_stream = ChannelDatagram::new(l_tx, d_rx);

    let sess = Session {
        network: Network::Udp,
        typ: Type::Tproxy,
        so_mark: fw_mark,
        ..Default::default()
    };

    let closer = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;
    crate::defer! {
        let _ = closer.send(0);
    }

    // dispatcher -> tproxy
    let replies = handle_packet_from_dispatcher(l_rx, &reply_sockets);

    // tproxy -> dispatcher
    let dns_limit = Arc::new(tokio::sync::Semaphore::new(256));
    let incoming = async {
        let mut buf = vec![0_u8; 1024 * 64];
        loop {
            let meta = socket.recv_msg(&mut buf).await?;
            match meta.orig_dst {
                Some(orig_dst) => {
                    if orig_dst.ip().is_multicast()
                        || match orig_dst.ip() {
                            std::net::IpAddr::V4(ip) => ip.is_broadcast(),
                            std::net::IpAddr::V6(_) => false,
                        }
                    {
                        continue;
                    }

                    trace!(
                        "recv msg:{:?} orig_dst:{:?}, local_addr:{:?}",
                        meta, orig_dst, socket.local_addr
                    );
                    for chunk in udp_datagrams(&buf[..meta.len], meta.stride) {
                        let pkt = UdpPacket {
                            data: chunk.to_vec(),
                            src_addr: meta.addr.to_canonical().into(),
                            dst_addr: orig_dst.to_canonical().into(),
                            inbound_user: None,
                        };

                        if dns_hijack
                            && orig_dst.port() == 53
                            && let Some(ref resolver) = dns_resolver
                        {
                            trace!(
                                "tproxy got dns packet: {:?}, returning from Clash \
                                 DNS server",
                                pkt
                            );
                            match hickory_proto::op::Message::from_vec(&pkt.data) {
                                Ok(msg) => {
                                    let Ok(permit) =
                                        dns_limit.clone().try_acquire_owned()
                                    else {
                                        warn!(
                                            "too many in-flight hijacked dns \
                                             queries, dropping query"
                                        );
                                        continue;
                                    };
                                    let resolver = resolver.clone();
                                    let client_addr = meta.addr.to_canonical();
                                    let dns_server_addr = orig_dst.to_canonical();
                                    let reply_sockets = reply_sockets.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        let mut resp = match exchange_with_resolver(
                                            &resolver, &msg, true,
                                        )
                                        .await
                                        {
                                            Ok(resp) => resp,
                                            Err(e) => {
                                                warn!(
                                                    "failed to exchange dns \
                                                     message: {}",
                                                    e
                                                );
                                                return;
                                            }
                                        };
                                        resp.metadata.id = msg.metadata.id;
                                        trace!(
                                            "tproxy hijack dns response: {:?}",
                                            resp
                                        );
                                        if let Ok(data) = resp.to_vec()
                                            && let Err(e) = sendto_with_src(
                                                &reply_sockets,
                                                &data,
                                                client_addr,
                                                dns_server_addr,
                                            )
                                            .await
                                        {
                                            warn!(
                                                "failed to send hijacked dns \
                                                 response: {}",
                                                e
                                            );
                                        }
                                    });
                                }
                                Err(e) => {
                                    warn!("failed to parse dns packet: {}", e);
                                }
                            }
                            continue;
                        }

                        trace!("tproxy -> dispatcher: {:?}", pkt);
                        match d_tx.send(pkt).await {
                            Ok(_) => {}
                            Err(e) => {
                                warn!("failed to send udp packet to proxy: {}", e);
                                continue;
                            }
                        }
                    }
                }
                None => {
                    trace!("recv msg:{:?} local_addr:{:?}", meta, socket.local_addr);
                    warn!("failed to get orig_dst");
                    continue;
                }
            }
        }
    };
    tokio::select! {
        () = replies => Ok(()),
        result = incoming => result,
    }
}

fn udp_datagrams(payload: &[u8], stride: usize) -> impl Iterator<Item = &[u8]> {
    let size = if stride == 0 { payload.len() } else { stride };
    // An empty UDP datagram has one payload, while chunks() yields none.
    payload
        .chunks(size.max(1))
        .chain(payload.is_empty().then_some(payload))
}

async fn handle_packet_from_dispatcher(
    mut l_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    sockets: &ReplySockets,
) {
    while let Some(pkt) = l_rx.recv().await {
        trace!("tproxy <- dispatcher: {:?}", pkt);
        // Send the reply with the original destination as its source address.
        let Some(src) = pkt.src_addr.try_into_socket_addr() else {
            warn!("tproxy: reply source is a domain");
            continue;
        };
        let Some(dst) = pkt.dst_addr.try_into_socket_addr() else {
            warn!("tproxy: reply destination is a domain");
            continue;
        };
        if let Err(e) = sendto_with_src(sockets, &pkt.data, dst, src).await {
            warn!("tproxy UDP reply from {src} to {dst} failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplySockets, new_reply_socket, sendto_with_src, udp_datagrams};
    use std::{io, net::SocketAddr, time::Duration};

    #[test]
    fn empty_datagram_has_one_payload() {
        for stride in [0, 5] {
            assert!(udp_datagrams(b"", stride).eq([b"".as_slice()]));
        }
    }

    #[test]
    fn gro_preserves_datagram_boundaries() {
        assert!(udp_datagrams(b"abcde", 0).eq([b"abcde".as_slice()]));
        assert!(udp_datagrams(b"abcde", 2).eq([b"ab".as_slice(), b"cd", b"e"]));
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_RAW"]
    async fn mapped_source_uses_ipv4_reply_socket() -> io::Result<()> {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let sockets = ReplySockets {
            v4: Some(new_reply_socket(socket2::Domain::IPV4)?),
            v6: None,
        };
        let src = "[::ffff:127.0.0.1]:32188".parse::<SocketAddr>().unwrap();
        sendto_with_src(&sockets, b"reply", receiver.local_addr()?, src).await?;
        let mut buf = [0; 5];
        let (len, peer) = tokio::time::timeout(
            Duration::from_secs(5),
            receiver.recv_from(&mut buf),
        )
        .await??;
        assert_eq!(&buf[..len], b"reply");
        assert_eq!(peer, "127.0.0.1:32188".parse::<SocketAddr>().unwrap());
        Ok(())
    }
}
