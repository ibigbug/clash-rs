use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};

use rand::seq::IndexedRandom;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::{
        tcp::{self, RecvError},
        udp,
    },
    time::Instant,
    wire::IpCidr,
};
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender},
};
use tracing::{Instrument, debug, error, trace, trace_span, warn};

use crate::{
    app::dns::ThreadSafeDNSResolver, proxy::datagram::UdpPacket, session::SocksAddr,
};

use super::{
    events::PortProtocol,
    ports::PortPool,
    stack::{
        tcp::SocketPair,
        udp::{MAX_PACKET, UdpPair},
    },
};

#[allow(clippy::large_enum_variant)]
enum Socket {
    Tcp(
        tcp::Socket<'static>,
        SocketAddr,
        Sender<Bytes>,
        Receiver<Bytes>,
    ),
    Udp(udp::Socket<'static>, Sender<UdpPacket>, Receiver<UdpPacket>),
}

enum Transfer {
    Tcp(SocketHandle, Bytes, bool),
    Udp(SocketHandle, UdpPacket, bool),
}

enum SenderType {
    Tcp(Sender<Bytes>),
    Udp(Sender<UdpPacket>),
}

pub struct DeviceManager {
    addr: Ipv4Addr,
    addr_v6: Option<Ipv6Addr>,
    resolver: ThreadSafeDNSResolver,
    dns_servers: Vec<SocketAddr>,

    socket_set: Arc<Mutex<SocketSet<'static>>>,
    socket_pairs: Arc<Mutex<HashMap<SocketHandle, SenderType>>>,

    tcp_port_pool: PortPool,
    udp_port_pool: PortPool,

    packet_notifier: Arc<Mutex<Receiver<()>>>,

    socket_notifier: Sender<Socket>,
    socket_notifier_receiver: Arc<Mutex<Receiver<Socket>>>,
}

impl DeviceManager {
    pub fn new(
        addr: Ipv4Addr,
        addr_v6: Option<Ipv6Addr>,
        resolver: ThreadSafeDNSResolver,
        dns_servers: Vec<SocketAddr>,
        packet_notifier: Receiver<()>,
    ) -> Self {
        let socket_set = Arc::new(Mutex::new(SocketSet::new(Vec::new())));
        let socket_pairs = Arc::new(Mutex::new(HashMap::new()));

        let tcp_port_pool = PortPool::new();
        let udp_port_pool = PortPool::new();

        let (socket_notifier, socket_notifier_receiver) =
            tokio::sync::mpsc::channel(1024);

        Self {
            addr,
            addr_v6,

            resolver,
            dns_servers,

            socket_set,
            socket_pairs,

            tcp_port_pool,
            udp_port_pool,

            packet_notifier: Arc::new(Mutex::new(packet_notifier)),

            socket_notifier,
            socket_notifier_receiver: Arc::new(Mutex::new(socket_notifier_receiver)),
        }
    }

    pub async fn new_tcp_socket(&self, remote: SocketAddr) -> SocketPair {
        let socket = Self::new_client_socket();
        let read_pair = tokio::sync::mpsc::channel(1024);
        let write_pair = tokio::sync::mpsc::channel(1024);

        self.socket_notifier
            .send(Socket::Tcp(socket, remote, read_pair.0, write_pair.1))
            .await
            .unwrap();
        SocketPair::new(read_pair.1, write_pair.0)
    }

    pub async fn new_udp_socket(&self) -> UdpPair {
        let socket = Self::new_client_datagram();
        let read_pair = tokio::sync::mpsc::channel(1024);
        let write_pair = tokio::sync::mpsc::channel(1024);

        self.socket_notifier
            .send(Socket::Udp(socket, read_pair.0, write_pair.1))
            .await
            .unwrap();
        UdpPair::new(read_pair.1, write_pair.0)
    }

    pub async fn look_up_dns(
        &self,
        host: &str,
        server: SocketAddr,
    ) -> Option<IpAddr> {
        debug!("looking up {} on {}", host, server);

        async fn query(
            rtype: hickory_proto::rr::RecordType,
            host: &str,
            server: SocketAddr,
            mut socket: UdpPair,
        ) -> Option<IpAddr> {
            let mut host = host.to_string();
            'outer: loop {
                let mut msg = hickory_proto::op::Message::query();

                msg.add_query({
                    let mut q = hickory_proto::op::Query::new();
                    let name = hickory_proto::rr::Name::from_str_relaxed(&host)
                        .unwrap()
                        .append_domain(&hickory_proto::rr::Name::root())
                        .unwrap();
                    q.set_name(name);
                    q.set_query_type(rtype);
                    q
                });

                msg.metadata.recursion_desired = true;

                let pkt = UdpPacket::new(
                    msg.to_vec().unwrap(),
                    SocksAddr::any_ipv4(),
                    server.into(),
                );

                socket.feed(pkt).await.ok()?;
                socket.flush().await.ok()?;
                trace!("sent dns query: {:?}", msg);

                let pkt = match tokio::time::timeout(
                    Duration::from_secs(5),
                    socket.next(),
                )
                .await
                {
                    Ok(Some(pkt)) => pkt,
                    _ => {
                        warn!("wg dns query timed out with server {server}");
                        return None;
                    }
                };

                let msg = hickory_proto::op::Message::from_vec(&pkt.data).ok()?;
                trace!("got dns response: {:?}", msg);
                for ans in msg.answers.iter() {
                    if ans.record_type() == rtype {
                        match (rtype, &ans.data) {
                            (_, hickory_proto::rr::RData::CNAME(cname)) => {
                                debug!(
                                    "{} resolved to CNAME {}, asking recursively",
                                    host, cname.0
                                );
                                host = cname.0.to_ascii();
                                continue 'outer;
                            }
                            (
                                hickory_proto::rr::RecordType::A,
                                hickory_proto::rr::RData::A(addr),
                            ) => {
                                return Some(std::net::IpAddr::V4(addr.0));
                            }
                            (
                                hickory_proto::rr::RecordType::AAAA,
                                hickory_proto::rr::RData::AAAA(addr),
                            ) => {
                                return Some(std::net::IpAddr::V6(addr.0));
                            }
                            _ => return None,
                        }
                    }
                }
                return None;
            }
        }

        let socket = self.new_udp_socket().await;
        let v4_query = query(hickory_proto::rr::RecordType::A, host, server, socket);
        if self.addr_v6.is_some() {
            let socket = self.new_udp_socket().await;
            let v6_query =
                query(hickory_proto::rr::RecordType::AAAA, host, server, socket);
            match tokio::time::timeout(
                Duration::from_secs(5),
                futures::future::join(v4_query, v6_query),
            )
            .await
            {
                Ok((_, Some(v6))) => Some(v6),
                Ok((v4, _)) => v4,
                _ => {
                    warn!("wg dns query timed out with server {server}");
                    None
                }
            }
        } else {
            tokio::time::timeout(Duration::from_secs(5), v4_query)
                .await
                .ok()?
        }
    }

    pub async fn poll_sockets(&self, mut device: VirtualIpDevice) {
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(self.addr.into(), 32)).unwrap();

            if let Some(addr_v6) = self.addr_v6 {
                addrs.push(IpCidr::new(addr_v6.into(), 128)).unwrap();
            }
        });

        let (device_sender, mut device_receiver) = tokio::sync::mpsc::channel(1024);

        let mut tcp_queue: HashMap<SocketHandle, VecDeque<(Bytes, bool)>> =
            HashMap::new();
        let mut udp_queue: HashMap<SocketHandle, VecDeque<(UdpPacket, bool)>> =
            HashMap::new();
        let mut next_poll = None;

        loop {
            let mut sockets = self.socket_set.lock().await;
            let mut socket_pairs = self.socket_pairs.lock().await;

            let mut packet_notifier = self.packet_notifier.lock().await;
            let mut socket_notifier_receiver =
                self.socket_notifier_receiver.lock().await;

            tokio::select! {
                Some(socket) = socket_notifier_receiver.recv() => {
                    trace!("got new socket, notifying to poll sockets");

                    match socket {
                        Socket::Tcp(mut socket, remote, sender, mut receiver) => {
                            socket
                            .connect(
                                iface.context(),
                                remote,
                                (match remote {
                                    SocketAddr::V4(_) => IpAddr::V4(self.addr),
                                    SocketAddr::V6(_) => IpAddr::V6(self.addr_v6.unwrap()),
                                }, self.get_ephemeral_tcp_port().await),
                            )
                            .unwrap();

                            let handle = sockets.add(socket);

                            let device_sender = device_sender.clone();
                            tokio::spawn(async move {
                                loop {
                                    let data = match receiver.recv().await {
                                        Some(data) => data,
                                        None => {
                                            break;
                                        }
                                    };
                                    trace!("sending {} bytes", data.len());
                                    device_sender.send(Transfer::Tcp(handle, data, true)).await.unwrap();
                                }
                                trace!("socket {} closed, sending close signal", handle);
                                device_sender
                                    .send(Transfer::Tcp(handle, Vec::new().into(), false))
                                    .await
                                    .unwrap();
                            });

                            socket_pairs.insert(handle, SenderType::Tcp(sender));
                            tcp_queue.insert(handle, VecDeque::new());
                        }
                        Socket::Udp(socket, sender, mut receiver) => {
                            let handle = sockets.add(socket);

                            let device_sender = device_sender.clone();
                            tokio::spawn(async move {
                                loop {
                                    let data = match receiver.recv().await {
                                        Some(data) => data,
                                        None => {
                                            break;
                                        }
                                    };

                                    device_sender
                                        .send(Transfer::Udp(handle, data, true))
                                        .await
                                        .unwrap();
                                }

                                trace!("socket {} closed, sending close signal", handle);
                                device_sender
                                    .send(Transfer::Udp(handle, UdpPacket::default() , false))
                                    .await
                                    .unwrap();
                            });

                            socket_pairs.insert(handle, SenderType::Udp(sender));
                            udp_queue.insert(handle, VecDeque::new());
                        }
                    };


                    next_poll = None;
                }

                _ = packet_notifier.recv() => {
                    trace!("lower layer packet received, polling sockets");
                    next_poll = None;
                }

                Some(transfer) = device_receiver.recv() => {
                    match transfer {
                        Transfer::Tcp(handle, data, active) => {
                            if let Some(queue) = tcp_queue.get_mut(&handle) {
                                queue.push_back((data, active));
                                next_poll = None;
                            }
                        }

                        Transfer::Udp(handle, data, active) => {
                            if let Some(queue) = udp_queue.get_mut(&handle) {
                                queue.push_back((data, active));
                                next_poll = None;
                            }
                        }
                    }
                }

                _ = match (next_poll, socket_pairs.len()) {
                    (None, 0) => {
                        tokio::time::sleep(Duration::MAX)
                    },
                    (None, _) => {
                        tokio::time::sleep(Duration::ZERO)
                    },
                    (Some(dur), _) => {
                        tokio::time::sleep(dur)
                    }
                } => {
                    let _ = trace_span!("poll_sockets").enter();

                    let timestamp = Instant::now();
                    iface.poll(timestamp, &mut device, &mut sockets);

                    for (handle, sender) in socket_pairs.iter_mut() {
                        match sender {
                            SenderType::Tcp(sender) => {
                                let socket = sockets.get_mut::<tcp::Socket>(*handle);
                                if socket.may_recv() {
                                    match socket.recv(|data| (data.len(), data.to_owned())) {
                                        Ok(data) if !data.is_empty() => match sender.try_send(data.into()) {
                                            Ok(_) => {}
                                            Err(_) => {
                                                trace!("socket {} closed from remote(?), aboring connection", handle);
                                                socket.abort();
                                            }
                                        },
                                        Ok(_) => {}
                                        Err(RecvError::Finished) => {
                                            warn!("tcp socket finished");
                                            continue;
                                        }
                                        Err(e) => {
                                            warn!("failed to receive tcp packet: {:?}", e);
                                        }
                                    }
                                }

                                if socket.may_send()
                                    && let Some(queue) = tcp_queue.get_mut(handle) {
                                        let data = queue.pop_front();
                                        match data { Some((to_transfer_slice, active)) => {
                                            if !active {
                                                trace!("socket {} closed from local(?), aboring socket", handle);
                                                socket.abort();
                                            } else {
                                                let total = to_transfer_slice.len();
                                                trace!("socket {} sending {} bytes", handle, total);
                                                match socket.send_slice(&to_transfer_slice) {
                                                    Ok(sent) => {
                                                        if sent < total {
                                                            // Sometimes only a subset is sent, so the rest needs to be sent on the next poll
                                                            let tx_extra = Vec::from(&to_transfer_slice[sent..total]);
                                                            queue.push_front((tx_extra.into(), true));
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to send slice via virtual client socket: {:?}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                        } _ => {
                                            // the local side has closed, but we don't know if the remote should be closed
                                            // let the dispatcher timeout to close the connection
                                        }}
                                    }
                            }
                            SenderType::Udp(sender) => {
                                let socket = sockets.get_mut::<udp::Socket>(*handle);
                                if socket.can_recv() {
                                    match socket.recv() {
                                        Ok((data, md)) if !data.is_empty() => match sender.try_send(UdpPacket::new(data.into(), crate::session::SocksAddr::Ip(SocketAddr::new(md.endpoint.addr.into(), md.endpoint.port)), SocksAddr::any_ipv4())) {
                                            Ok(_) => {}
                                            Err(_) => {
                                                trace!("socket {} closed from remote(?), aboring connection", handle);
                                                socket.close();
                                            }
                                        },
                                        Ok(_) => {}
                                        Err(udp::RecvError::Exhausted) => {
                                            trace!("no more data");
                                            continue;
                                        }
                                        Err(udp::RecvError::Truncated) => {
                                            panic!("udp packet truncated - this should never happen");
                                        }
                                    }
                                }

                                if socket.can_send()
                                    && let Some(queue) = udp_queue.get_mut(handle) {
                                        let data = queue.pop_front();
                                        if let Some((pkt, active)) = data {
                                            if !active {
                                                trace!("socket {} closed from local(?), aboring socket", handle);
                                                socket.close();
                                            } else {
                                                let ip = match &pkt.dst_addr {
                                                    SocksAddr::Ip(addr) => addr.ip(),
                                                    SocksAddr::Domain(domain, _) => {
                                                        if let Ok(ip) = domain.parse::<IpAddr>() {
                                                            ip
                                                        } else {
                                                            let dns_server = self.dns_servers.choose(&mut rand::rng());
                                                            if let Some(dns_server) = dns_server {
                                                                let ip = self.look_up_dns(domain, *dns_server).await;
                                                                if let Some(ip) = ip {
                                                                    debug!("host {} resolved to {} on wg stack", domain, ip);
                                                                    ip
                                                                } else {
                                                                    warn!("failed to resolve domain on wireguard: {}", domain);
                                                                    continue;
                                                                }
                                                            } else {
                                                                match self.resolver.resolve(domain, false).await {
                                                                    Ok(Some(ip)) => {
                                                                        debug!("host {} resolved to {} on local", domain, ip);
                                                                        ip
                                                                    }
                                                                    _ => {
                                                                        warn!("failed to resolve domain on wireguard: {}", domain);
                                                                        continue;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                };

                                                if !socket.is_open() {
                                                    let local_addr: IpAddr = match ip {
                                                        IpAddr::V4(_) => self.addr.into(),
                                                        IpAddr::V6(_) => self.addr_v6.unwrap().into(),
                                                    };
                                                    socket
                                                        .bind(
                                                            (local_addr, self.get_ephemeral_udp_port().await),
                                                        )
                                                    .unwrap();
                                                }

                                                match socket.send_slice(&pkt.data, (ip, pkt.dst_addr.port())) {
                                                    Ok(_) => {}
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to send slice via virtual client socket: {:?}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                        } else {
                                            // the local side has closed, but we don't know if the remote should be closed
                                            // let the dispatcher timeout to close the connection
                                        }
                                    }

                            }
                        };
                    }

                    let mut tcp_port_to_release = Vec::new();
                    let mut udp_port_to_release = Vec::new();

                    socket_pairs.retain(|handle, sender_type| {
                        match sender_type {
                            SenderType::Tcp(_) => {
                                let socket = sockets.get::<tcp::Socket>(*handle);
                                if socket.is_active() {
                                    true
                                } else {
                                    if let Some(port) = socket.local_endpoint().map(|x| x.port) {
                                        tcp_port_to_release.push(port);
                                    } else {
                                        warn!("tcp socket {} was never connected, cannot release port", handle);
                                    }

                                    trace!("socket {} closed, shutting down connection and releasing resources", handle);
                                    sockets.remove(*handle);
                                    tcp_queue.remove(handle);
                                    false

                                }
                            }
                            SenderType::Udp(_) => {
                                let socket = sockets.get::<udp::Socket>(*handle);
                                if socket.is_open() {
                                    true
                                } else {
                                    let port = socket.endpoint().port;
                                    udp_port_to_release.push(port);

                                    trace!("socket {} closed, shutting down connection and releasing resources", handle);
                                    sockets.remove(*handle);

                                    udp_queue.remove(handle);
                                    false
                                }
                            }
                        }
                    });

                    for port in tcp_port_to_release {
                        self.release_ephemeral_tcp_port(port).await;
                    }
                    for port in udp_port_to_release {
                        self.release_ephemeral_udp_port(port).await;
                    }

                    next_poll = match iface.poll_delay(timestamp, &sockets) {
                        Some(smoltcp::time::Duration::ZERO) => None,
                        Some(delay) => {
                            trace!("device poll delay: {:?}", delay);
                            Some(delay.into())
                        }
                        None => None,
                    };
                }
            }
        }
    }

    async fn get_ephemeral_tcp_port(&self) -> u16 {
        self.tcp_port_pool.next().await.unwrap()
    }

    async fn release_ephemeral_tcp_port(&self, port: u16) {
        self.tcp_port_pool.release(port).await;
    }

    async fn get_ephemeral_udp_port(&self) -> u16 {
        self.udp_port_pool.next().await.unwrap()
    }

    async fn release_ephemeral_udp_port(&self, port: u16) {
        self.udp_port_pool.release(port).await;
    }

    fn new_client_socket() -> tcp::Socket<'static> {
        tcp::Socket::new(
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
            smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]),
        )
    }

    fn new_client_datagram() -> udp::Socket<'static> {
        let rx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let tx_meta = vec![udp::PacketMetadata::EMPTY; 10];
        let rx_data = vec![0u8; MAX_PACKET];
        let tx_data = vec![0u8; MAX_PACKET];
        let udp_rx_buffer = udp::PacketBuffer::new(rx_meta, rx_data);
        let udp_tx_buffer = udp::PacketBuffer::new(tx_meta, tx_data);

        udp::Socket::new(udp_rx_buffer, udp_tx_buffer)
    }
}

pub struct VirtualIpDevice {
    mtu: usize,

    packet_sender: Sender<Bytes>,
    packet_receiver: Receiver<(PortProtocol, Bytes)>,
}

impl VirtualIpDevice {
    pub fn new(
        // send packet to wg stack
        packet_sender: Sender<Bytes>,
        // when wg stack receives a packet, it will send it to this receiver
        mut packet_receiver: Receiver<(PortProtocol, Bytes)>,

        // when wg stack receives a packet, it will send a notification to this
        // sender
        packet_notifier: Sender<()>,
        mtu: usize,
    ) -> Self {
        let (inner_packet_sender, inner_packet_receiver) =
            tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            loop {
                let span = trace_span!("receive_packet");

                match packet_receiver.recv().instrument(span).await {
                    Some((proto, data)) => {
                        inner_packet_sender.send((proto, data)).await.unwrap();
                        let _ = packet_notifier.try_send(());
                    }
                    _ => {
                        break;
                    }
                }
            }
        });

        Self {
            mtu,
            packet_sender,
            packet_receiver: inner_packet_receiver,
        }
    }
}

impl Device for VirtualIpDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let next = self.packet_receiver.try_recv().ok();
        match next {
            Some((_proto, data)) => {
                // Convert to mutable buffer for potential checksum fix
                let mut buffer = BytesMut::from(&data[..]);

                // Fix UDP checksum if needed
                // Some environments (NAT, checksum offload, virtualization) may
                // corrupt the checksum We recalculate it here since
                // WireGuard AEAD already guarantees data integrity
                // Note: An alternative approach is to skip RX checksum
                // verification by setting `caps.checksum.udp =
                // smoltcp::phy::Checksum::Tx` in capabilities(), but
                // recalculating feels cleaner than disabling verification
                // entirely
                use smoltcp::wire::*;
                if let Ok(IpVersion::Ipv4) = IpVersion::of_packet(&buffer)
                    && let Ok(ipv4) = Ipv4Packet::new_checked(&buffer[..])
                    && ipv4.next_header() == IpProtocol::Udp
                {
                    let src_addr = ipv4.src_addr();
                    let dst_addr = ipv4.dst_addr();
                    let ip_header_len = ipv4.header_len() as usize;

                    // Recalculate UDP checksum
                    if let Ok(mut udp) =
                        UdpPacket::new_checked(&mut buffer[ip_header_len..])
                    {
                        udp.fill_checksum(
                            &IpAddress::Ipv4(src_addr),
                            &IpAddress::Ipv4(dst_addr),
                        );
                    }
                }

                let rx_token = RxToken { buffer };
                let tx_token = TxToken {
                    sender: self.packet_sender.clone(),
                };
                Some((rx_token, tx_token))
            }
            None => None,
        }
    }

    fn transmit(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            sender: self.packet_sender.clone(),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct RxToken {
    buffer: BytesMut,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct TxToken {
    sender: Sender<Bytes>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        match self.sender.try_send(buffer.into()) {
            Ok(_) => {}
            Err(err) => {
                error!("failed to send packet: {}", err);
            }
        }
        result
    }
}
