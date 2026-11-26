use std::net::SocketAddr;
use wind_core::{types::TargetAddr, udp::UdpPacket as WindPacket};

use super::datagram::UdpPacket;
use crate::session::SocksAddr;

impl From<SocksAddr> for TargetAddr {
    fn from(addr: SocksAddr) -> Self {
        match addr {
            SocksAddr::Ip(SocketAddr::V4(addr)) => {
                TargetAddr::IPv4(*addr.ip(), addr.port())
            }
            SocksAddr::Ip(SocketAddr::V6(addr)) => {
                TargetAddr::IPv6(*addr.ip(), addr.port())
            }
            SocksAddr::Domain(domain, port) => TargetAddr::Domain(domain, port),
        }
    }
}

impl From<TargetAddr> for SocksAddr {
    fn from(addr: TargetAddr) -> Self {
        match addr {
            TargetAddr::IPv4(ip, port) => SocksAddr::Ip((ip, port).into()),
            TargetAddr::IPv6(ip, port) => SocksAddr::Ip((ip, port).into()),
            TargetAddr::Domain(domain, port) => SocksAddr::Domain(domain, port),
        }
    }
}

impl From<UdpPacket> for WindPacket {
    fn from(packet: UdpPacket) -> Self {
        Self {
            source: None,
            target: packet.dst_addr.into(),
            payload: packet.data.into(),
        }
    }
}

pub(super) fn udp_reply(packet: WindPacket, local: SocksAddr) -> UdpPacket {
    UdpPacket::new(packet.payload.to_vec(), packet.target.into(), local)
}
