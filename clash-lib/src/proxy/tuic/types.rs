//! Clash address/configuration adapters for Wind's TUIC protocol.
use anyhow::{Result, anyhow};
use std::net::{IpAddr, SocketAddr};
use wind_core::types::TargetAddr;
use wind_tuic::quinn::{
    CongestionControl as WindCongestionControl, UdpRelayMode as WindUdpRelayMode,
};

use crate::{app::dns::ThreadSafeDNSResolver, session::SocksAddr};

/// The configured TUIC server address, resolved to a socket address just
/// before the Wind outbound is built.
#[derive(Clone)]
pub struct ServerAddr {
    domain: String,
    port: u16,
    ip: Option<IpAddr>,
    sni: Option<String>,
}

impl ServerAddr {
    pub fn new(
        domain: String,
        port: u16,
        ip: Option<IpAddr>,
        sni: Option<String>,
    ) -> Self {
        Self {
            domain,
            port,
            ip,
            sni,
        }
    }

    pub fn server_name(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.domain)
    }

    pub async fn resolve(
        &self,
        resolver: &ThreadSafeDNSResolver,
    ) -> Result<SocketAddr> {
        let ip = if let Some(ip) = self.ip {
            ip
        } else if let Ok(ip) = self
            .domain
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
        {
            ip
        } else {
            resolver
                .resolve(&self.domain, false)
                .await?
                .ok_or_else(|| {
                    anyhow!("TUIC server resolution returned no address")
                })?
        };
        Ok(SocketAddr::new(ip, self.port))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum UdpRelayMode {
    Native,
    Quic,
}
impl From<&str> for UdpRelayMode {
    #[inline]
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("native") {
            Self::Native
        } else if s.eq_ignore_ascii_case("quic") {
            Self::Quic
        } else {
            // TODO logging
            Self::Quic
        }
    }
}
impl From<UdpRelayMode> for WindUdpRelayMode {
    fn from(mode: UdpRelayMode) -> Self {
        match mode {
            UdpRelayMode::Native => Self::Native,
            UdpRelayMode::Quic => Self::Quic,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub enum CongestionControl {
    Cubic,
    NewReno,
    #[default]
    Bbr,
    Bbr3,
}
impl From<&str> for CongestionControl {
    #[inline]
    fn from(s: &str) -> Self {
        if s.eq_ignore_ascii_case("cubic") {
            Self::Cubic
        } else if s.eq_ignore_ascii_case("new_reno")
            || s.eq_ignore_ascii_case("newreno")
        {
            Self::NewReno
        } else if s.eq_ignore_ascii_case("bbr") {
            Self::Bbr
        } else if s.eq_ignore_ascii_case("bbr3") {
            Self::Bbr3
        } else {
            tracing::warn!(
                "Unknown congestion controller {s}. Use default controller"
            );
            Self::default()
        }
    }
}
impl From<CongestionControl> for WindCongestionControl {
    fn from(cc: CongestionControl) -> Self {
        match cc {
            CongestionControl::Cubic => Self::Cubic,
            CongestionControl::NewReno => Self::NewReno,
            CongestionControl::Bbr => Self::Bbr,
            CongestionControl::Bbr3 => Self::Bbr3,
        }
    }
}

pub trait SocketAdderTrans {
    fn into_tuic(self) -> TargetAddr;
}
impl SocketAdderTrans for SocksAddr {
    fn into_tuic(self) -> TargetAddr {
        match self {
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

pub fn from_target(addr: TargetAddr) -> SocksAddr {
    match addr {
        TargetAddr::IPv4(ip, port) => SocksAddr::Ip((ip, port).into()),
        TargetAddr::IPv6(ip, port) => SocksAddr::Ip((ip, port).into()),
        TargetAddr::Domain(domain, port) => SocksAddr::Domain(domain, port),
    }
}
