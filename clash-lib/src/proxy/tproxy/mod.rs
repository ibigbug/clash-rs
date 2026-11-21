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
use std::{io, net::SocketAddr, os::fd::AsRawFd, sync::Arc};
use tokio::net::TcpListener;
use tracing::{trace, warn};

use crate::app::dns::{ThreadSafeDNSResolver, exchange_with_resolver};

pub struct TproxyInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
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
        fw_mark: Option<u32>,
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
        let (socket, dual_stack) =
            try_create_dualstack_socket(self.addr, socket2::Type::DGRAM)?;
        if dual_stack || self.addr.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        }
        if self.addr.is_ipv6() {
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.set_broadcast(true)?;
        set_ip_recv_orig_dstaddr(
            if self.addr.is_ipv4() {
                libc::IPPROTO_IP
            } else {
                libc::IPPROTO_IPV6
            },
            &socket,
        )?;
        if dual_stack {
            set_ip_recv_orig_dstaddr(libc::IPPROTO_IP, &socket)?;
        }
        socket.bind(&self.addr.into())?;

        let listener = unix_udp_sock::UdpSocket::from_std(socket.into())?;
        // GRO is optional on the running kernel.
        if let Err(err) = listener.set_gro(true) {
            trace!("TPROXY UDP GRO unavailable: {err}");
        }

        handle_inbound_datagram(
            self.allow_lan,
            self.fw_mark,
            Arc::new(listener),
            self.dispatcher.clone(),
            self.dns_resolver.clone(),
            self.dns_hijack,
        )
        .await
    }
}

fn new_unbound_socket(
    family_hint: SocketAddr,
    fw_mark: Option<u32>,
) -> io::Result<tokio::io::unix::AsyncFd<socket2::Socket>> {
    let socket = if family_hint.is_ipv4() {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(libc::IPPROTO_RAW.into()),
        )?
    } else {
        socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(libc::IPPROTO_RAW.into()),
        )?
    };
    socket.set_nonblocking(true)?;
    // socket.set_reuse_address(true)?;
    if let Some(so_mark) = fw_mark {
        socket.set_mark(so_mark)?;
    }
    // SAFETY: AsyncFd owns this socket until deregistration.
    unsafe { Ok(tokio::io::unix::AsyncFd::register(socket)?) }
}
async fn sendto_with_src(
    socket: &tokio::io::unix::AsyncFd<socket2::Socket>,
    buf: &[u8],
    dst: SocketAddr,
    src: SocketAddr,
) -> io::Result<()> {
    let src = src.to_canonical();
    let dst = dst.to_canonical();
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
    fw_mark: Option<u32>,
    socket: Arc<unix_udp_sock::UdpSocket>,
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

    let closer: tokio::sync::oneshot::Sender<u8> = dispatcher
        .dispatch_datagram(sess, Box::new(udp_stream))
        .await;

    // dispatcher -> tproxy
    let replies = handle_packet_from_dispatcher(l_rx, fw_mark);

    // tproxy -> dispatcher
    let dns_limit = Arc::new(tokio::sync::Semaphore::new(256));
    let incoming = async move {
        let mut buf = vec![0_u8; 1024 * 64];
        while let Ok(meta) = socket.recv_msg(&mut buf).await {
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
                        meta,
                        orig_dst,
                        socket.local_addr()
                    );
                    let chunk_size = gro_chunk_size(meta.len, meta.stride);
                    if chunk_size == 0 {
                        continue;
                    }
                    for chunk in buf[0..meta.len].chunks(chunk_size) {
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
                                            && let Ok(socket_raw) =
                                                new_unbound_socket(
                                                    dns_server_addr,
                                                    fw_mark,
                                                )
                                            && let Err(e) = sendto_with_src(
                                                &socket_raw,
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
                    trace!(
                        "recv msg:{:?} local_addr:{:?}",
                        meta,
                        socket.local_addr()
                    );
                    warn!("failed to get orig_dst");
                    continue;
                }
            }
        }
        warn!("tproxy udp listening ended");
    };
    tokio::select! {
        () = replies => {},
        () = incoming => {},
    }
    let _ = closer.send(0);
    Ok(())
}

fn gro_chunk_size(len: usize, stride: usize) -> usize {
    if stride == 0 { len } else { stride }
}

fn set_ip_recv_orig_dstaddr(
    level: libc::c_int,
    socket: &socket2::Socket,
) -> io::Result<()> {
    let opt = match level {
        libc::IPPROTO_IP => libc::IP_RECVORIGDSTADDR,
        libc::IPPROTO_IPV6 => libc::IPV6_RECVORIGDSTADDR,
        _ => unreachable!("invalid sockopt level {}", level),
    };

    let enable: libc::c_int = 1;
    set_socket_option(socket, level, opt, enable)
}

async fn handle_packet_from_dispatcher(
    mut l_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    fw_mark: Option<u32>,
) {
    let socket_v4 = new_unbound_socket(SocketAddr::from(([0, 0, 0, 0], 0)), fw_mark);
    let socket_v6 =
        new_unbound_socket(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)), fw_mark);
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
        let socket = if src.is_ipv4() {
            &socket_v4
        } else {
            &socket_v6
        };
        match socket {
            Ok(socket) => {
                if let Err(e) = sendto_with_src(socket, &pkt.data, dst, src).await {
                    warn!("tproxy UDP reply from {src} to {dst} failed: {e}");
                }
            }
            Err(e) => warn!("tproxy raw socket unavailable for {src}: {e}"),
        }
    }
}

fn set_socket_option(
    socket: &socket2::Socket,
    level: i32,
    opt: i32,
    val: i32,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();

    let enable: libc::c_int = val;

    unsafe {
        let ret = libc::setsockopt(
            fd,
            level,
            opt,
            &enable as *const _ as *const _,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        );

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::gro_chunk_size;

    #[test]
    fn gro_chunk_size_uses_len_when_stride_is_zero() {
        assert_eq!(gro_chunk_size(1024, 0), 1024);
    }

    #[test]
    fn gro_chunk_size_uses_stride_when_non_zero() {
        assert_eq!(gro_chunk_size(1024, 128), 128);
    }
}
