use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};

use bytes::Bytes;
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use ipnet::IpNet;
use smoltcp::wire::{IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet};
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender},
};
use tracing::{Instrument, enabled, error, trace, trace_span, warn};

use crate::{
    Error,
    app::dns::ThreadSafeDNSResolver,
    proxy::{
        AnyOutboundDatagram,
        datagram::UdpPacket,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::{Session, SocksAddr},
};

use super::events::PortProtocol;

pub struct WireguardTunnel {
    pub(crate) source_peer_ip: Ipv4Addr,
    pub(crate) source_peer_ipv6: Option<Ipv6Addr>,
    peer: Arc<Mutex<Tunn>>,
    pub(crate) endpoint: SocketAddr,
    allowed_ips: Vec<IpNet>,
    reserved_bits: [u8; 3],

    // UDP socket to the remote WireGuard endpoint
    tx: tokio::sync::Mutex<SplitSink<AnyOutboundDatagram, UdpPacket>>,
    rx: tokio::sync::Mutex<SplitStream<AnyOutboundDatagram>>,

    // send side packet going out of the tunnel
    packet_writer: Sender<(PortProtocol, Bytes)>,
    // receive side packet coming into the tunnel
    packet_reader: Arc<Mutex<Receiver<Bytes>>>,
}

impl Debug for WireguardTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireguardTunnel")
            .field("source_peer_ip", &self.source_peer_ip)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

pub struct Config {
    pub private_key: StaticSecret,
    pub endpoint_public_key: PublicKey,
    pub pre_shared_key: Option<StaticSecret>,
    pub remote_endpoint: SocketAddr,
    pub source_peer_ip: Ipv4Addr,
    pub source_peer_ipv6: Option<Ipv6Addr>,
    pub keepalive_seconds: Option<u16>,
    pub allowed_ips: Vec<IpNet>,
    pub reserved_bits: [u8; 3],
}

impl WireguardTunnel {
    pub async fn new(
        config: Config,
        packet_writer: Sender<(PortProtocol, Bytes)>,
        packet_reader: Receiver<Bytes>,
        resolver: ThreadSafeDNSResolver,
        connector: Option<Arc<dyn RemoteConnector>>,
        sess: &Session,
    ) -> Result<Self, Error> {
        let peer = Tunn::new(
            config.private_key,
            config.endpoint_public_key,
            config.pre_shared_key.map(|x| x.to_bytes()),
            config.keepalive_seconds,
            0,
            None,
        );

        let remote_endpoint = config.remote_endpoint;

        let connector = connector.unwrap_or(GLOBAL_DIRECT_CONNECTOR.clone());
        let udp = connector
            .connect_datagram(
                resolver,
                None,
                remote_endpoint.into(),
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        let (tx, rx) = udp.split();

        Ok(Self {
            source_peer_ip: config.source_peer_ip,
            source_peer_ipv6: config.source_peer_ipv6,
            peer: Arc::new(Mutex::new(peer)),
            endpoint: remote_endpoint,
            allowed_ips: config.allowed_ips,
            reserved_bits: config.reserved_bits,

            tx: tokio::sync::Mutex::new(tx),
            rx: tokio::sync::Mutex::new(rx),

            packet_writer,
            packet_reader: Arc::new(Mutex::new(packet_reader)),
        })
    }

    async fn udp_send(&self, packet: &mut [u8]) -> Result<(), std::io::Error> {
        if packet.len() > 3 {
            packet[1] = self.reserved_bits[0];
            packet[2] = self.reserved_bits[1];
            packet[3] = self.reserved_bits[2];
        }
        self.tx
            .lock()
            .await
            .send(UdpPacket {
                data: packet.to_vec(),
                src_addr: SocksAddr::any_ipv4(),
                dst_addr: self.endpoint.into(),
                inbound_user: None,
            })
            .await
    }

    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<(), Error> {
        trace_ip_packet("Sending IP packet", packet);

        let mut send_buf = vec![0u8; 65535];
        let mut peer = self.peer.lock().await;
        match peer.encapsulate(packet, &mut send_buf) {
            boringtun::noise::TunnResult::Done => {}
            boringtun::noise::TunnResult::Err(e) => {
                error!("failed to encapsulate packet: {e:?}");
            }
            boringtun::noise::TunnResult::WriteToNetwork(packet) => {
                self.udp_send(packet).await?;
            }
            _ => {
                error!("unexpected result from encapsulate");
            }
        }
        Ok(())
    }

    pub async fn start_polling(&self) {
        tokio::select! {
            _ = self.start_forwarding() => {
                trace!("forwarding stopped")
            }
            _ = self.start_heartbeat() => {
                trace!("heartbeat stopped")
            }
            _ = self.start_receiving() => {
                trace!("receiving stopped")
            }
        }
    }

    pub async fn start_forwarding(&self) {
        let mut packet_reader = self.packet_reader.lock().await;
        loop {
            match packet_reader.recv().await {
                Some(packet) => {
                    if let Err(e) = self.send_ip_packet(&packet).await {
                        error!("failed to send packet: {}", e);
                    }
                }
                None => {
                    trace!("no active connection, stopping");
                    break;
                }
            }
        }
    }

    pub async fn start_heartbeat(&self) {
        let mut send_buf = vec![0u8; 65535];

        loop {
            let mut peer = self.peer.lock().await;
            let tun_result = peer.update_timers(&mut send_buf);
            drop(peer);

            self.handle_routine_result(tun_result).await;
        }
    }

    #[tracing::instrument]
    pub async fn start_receiving(&self) {
        let mut send_buf = vec![0u8; 65535];

        loop {
            let mut item = match self
                .rx
                .lock()
                .await
                .next()
                .instrument(trace_span!(
                    "wg_receive",
                    endpoint = %self.endpoint,
                ))
                .await
            {
                Some(item) => item,
                None => {
                    continue;
                }
            };

            let mut peer = self.peer.lock().await;
            let data = &mut item.data;
            if data.len() > 3 {
                data[1] = 0;
                data[2] = 0;
                data[3] = 0;
            }

            let _ = trace_span!("wg_decapsulate", endpoint = %self.endpoint, size = data.len())
                .entered();

            match peer.decapsulate(None, data, &mut send_buf) {
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    error!("failed to decapsulate packet: {e:?}");
                    continue;
                }
                TunnResult::WriteToNetwork(packet) => {
                    let size = packet.len();
                    match self
                        .udp_send(packet)
                        .instrument(trace_span!(
                            "wg_send",
                            endpoint = %self.endpoint,
                            size = size,
                        ))
                        .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            error!("failed to send packet: {}", e);
                            continue;
                        }
                    }

                    let mut send_buf = vec![0u8; 65535];
                    while let TunnResult::WriteToNetwork(packet) =
                        peer.decapsulate(None, &[], &mut send_buf)
                    {
                        match self.udp_send(packet).await {
                            Ok(_) => {}
                            Err(e) => {
                                error!(
                                    "Failed to send decapsulation-instructed \
                                     packet to WireGuard endpoint: {:?}",
                                    e
                                );
                                break;
                            }
                        };
                    }
                }

                TunnResult::WriteToTunnelV4(packet, addr) => {
                    trace_ip_packet("Received IP packet", packet);

                    if !self.is_ip_allowed(addr.into()) {
                        trace!(
                            "received packet from {} which is not in allowed_ips",
                            addr.to_string()
                        );
                        continue;
                    }

                    let _ =
                        trace_span!("wg_write_stack", endpoint = %self.endpoint, size = packet.len())
                            .entered();

                    if let Some(proto) = self.route_protocol(packet) {
                        if let Err(e) = self
                            .packet_writer
                            .send((proto, packet.to_owned().into())) // TODO: avoid copy
                            .await
                        {
                            error!("failed to send packet to virtual device: {}", e);
                        }
                    } else {
                        warn!("wg stack received unknown data");
                    }
                }
                TunnResult::WriteToTunnelV6(packet, addr) => {
                    trace_ip_packet("Received IP packet", packet);

                    if !self.is_ip_allowed(addr.into()) {
                        trace!(
                            "received packet from {} which is not in allowed_ips",
                            addr.to_string()
                        );
                        continue;
                    }

                    let _ =
                        trace_span!("wg_write_stack", endpoint = %self.endpoint, size = packet.len())
                            .entered();
                    if let Some(proto) = self.route_protocol(packet) {
                        if let Err(e) = self
                            .packet_writer
                            .send((proto, packet.to_owned().into())) // TODO: avoid copy
                            .await
                        {
                            error!("failed to send packet to virtual device: {}", e);
                        }
                    } else {
                        warn!("wg stack received unknown data");
                    }
                }
            }
        }
    }

    async fn handle_routine_result(&self, result: TunnResult<'_>) {
        match result {
            TunnResult::Done => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                warn!("wireguard connection expired");
                let mut buf = vec![0u8; 65535];
                let mut peer = self.peer.lock().await;
                let tun_result =
                    peer.format_handshake_initiation(&mut buf[..], false);
                drop(peer);

                match tun_result {
                    TunnResult::Done => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        if let Err(e) = self.udp_send(packet).await {
                            error!("failed to send packet: {}", e);
                        }
                    }
                    TunnResult::Err(e) => {
                        error!("wireguard error: {e:?}");
                    }
                    _ => {
                        error!("unexpected result from wireguard");
                    }
                }
            }
            TunnResult::Err(e) => {
                error!("wireguard error: {e:?}");
            }
            TunnResult::WriteToNetwork(packet) => {
                if let Err(e) = self.udp_send(packet).await {
                    error!("failed to send packet: {}", e);
                }
            }
            _ => {
                error!("unexpected result from wireguard");
            }
        }
    }

    /// Determine the inner protocol of the incoming IP packet (TCP/UDP).
    #[tracing::instrument(skip(self, packet))]
    fn route_protocol(&self, packet: &[u8]) -> Option<PortProtocol> {
        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => Ipv4Packet::new_checked(&packet)
                .ok()
                .filter(|packet| packet.dst_addr() == self.source_peer_ip)
                .and_then(|packet| {
                    match packet.next_header() {
                        IpProtocol::Tcp => Some(PortProtocol::Tcp),
                        IpProtocol::Udp => Some(PortProtocol::Udp),
                        // Unrecognized protocol, so we cannot determine where
                        // to route
                        _ => None,
                    }
                }),
            Ok(IpVersion::Ipv6) => Ipv6Packet::new_checked(&packet)
                .ok()
                .filter(|packet| Some(packet.dst_addr()) == self.source_peer_ipv6)
                .and_then(|packet| {
                    match packet.next_header() {
                        IpProtocol::Tcp => Some(PortProtocol::Tcp),
                        IpProtocol::Udp => Some(PortProtocol::Udp),
                        // Unrecognized protocol, so we cannot determine where
                        // to route
                        _ => None,
                    }
                }),
            _ => None,
        }
    }

    fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        trace!("checking if {} is allowed in {:?}", ip, self.allowed_ips);
        self.allowed_ips.is_empty()
            || self.allowed_ips.iter().any(|x| x.contains(&ip))
    }
}

fn trace_ip_packet(message: &str, packet: &[u8]) {
    if enabled!(tracing::Level::TRACE) {
        use smoltcp::wire::*;

        match IpVersion::of_packet(packet) {
            Ok(IpVersion::Ipv4) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
            ),
            Ok(IpVersion::Ipv6) => trace!(
                "{}: {}",
                message,
                PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
            ),
            _ => {}
        }
    }
}
