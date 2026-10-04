use crate::{
    config::internal::proxy::{Hysteria2Obfs, OutboundHysteria2},
    proxy::hysteria2::{self, Handler, HystOption, SalamanderObfs},
    session::SocksAddr,
};
use std::{
    num::{NonZeroU16, ParseIntError},
    ops::RangeInclusive,
};

#[derive(Clone)]
pub struct PortGenerator {
    // must have a default port
    pub default: u16,
    ports: Vec<u16>,
    range: Vec<RangeInclusive<u16>>,
}

impl PortGenerator {
    pub fn new(port: u16) -> Self {
        PortGenerator {
            default: port,
            ports: vec![],
            range: vec![],
        }
    }

    pub fn add_single(&mut self, port: u16) {
        self.ports.push(port);
    }

    fn add_range(&mut self, start: u16, end: u16) {
        self.range.push(start..=end);
    }

    pub fn get(&self) -> u16 {
        let len =
            1 + self.ports.len() + self.range.iter().map(|r| r.len()).sum::<usize>();
        let idx = rand::random_range(0..len);
        match idx {
            0 => self.default,
            idx if idx <= self.ports.len() => self.ports[idx - 1],
            idx => {
                let mut x = self.range.iter().cloned().flatten();
                x.nth(idx - 1 - self.ports.len()).unwrap()
            }
        }
    }

    pub fn all_ports(&self) -> Vec<u16> {
        let mut list =
            Vec::with_capacity(1 + self.ports.len() + self.range.len() * 10);
        list.push(self.default);
        let mut other = Vec::new();
        other.extend_from_slice(&self.ports);
        for r in &self.range {
            for p in r.clone() {
                other.push(p);
            }
        }
        other.sort_unstable();
        other.dedup();
        other.retain(|&p| p != self.default);
        list.extend(other);
        list
    }

    pub fn parse_ports_str(self, ports: &str) -> Result<Self, ParseIntError> {
        if ports.is_empty() {
            return Ok(self);
        }
        ports
            .split(',')
            .map(|s| s.trim())
            .try_fold(self, |mut acc, ports| {
                let x: Result<_, ParseIntError> = ports
                    .parse::<u16>()
                    .map(|p| acc.add_single(p))
                    .or_else(|e| {
                        let mut iter = ports.split('-');
                        let start = iter.next().ok_or(e.clone())?;
                        let end = iter.next().ok_or(e)?;
                        let start = start.parse::<NonZeroU16>()?;
                        let end = end.parse::<NonZeroU16>()?;
                        acc.add_range(start.get(), end.get());
                        Ok(())
                    })
                    .map(|_| acc);
                x
            })
    }
}

impl TryFrom<OutboundHysteria2> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundHysteria2) -> Result<Self, Self::Error> {
        let addr = SocksAddr::try_from((value.server, value.port))?;

        let obfs = match (value.obfs, value.obfs_password.as_ref()) {
            (Some(obfs), Some(passwd)) => match obfs {
                Hysteria2Obfs::Salamander => {
                    Some(hysteria2::Obfs::Salamander(SalamanderObfs {
                        key: passwd.to_owned().into(),
                    }))
                }
            },
            (Some(_), None) => {
                return Err(crate::Error::InvalidConfig(
                    "hysteria2 found obfs enable, but obfs password is none"
                        .to_owned(),
                ));
            }
            _ => None,
        };

        let ports_gen = if let Some(ports) = value.ports {
            Some(
                PortGenerator::new(value.port)
                    .parse_ports_str(&ports)
                    .map_err(|e| {
                        crate::Error::InvalidConfig(format!(
                            "hysteria2 parse ports error: {e:?}, ports: {ports:?}"
                        ))
                    })?,
            )
        } else {
            None
        };
        let hop_interval = value.hop_interval.map(std::time::Duration::from_secs);
        let opts = HystOption {
            name: value.name,
            sni: value.sni.or(addr.domain().map(|s| s.to_owned())),
            addr,
            alpn: value.alpn.unwrap_or_default(),
            ca: value.ca.map(|s| s.into()),
            fingerprint: value.fingerprint,
            skip_cert_verify: value.skip_cert_verify,
            passwd: value.password,
            ports: ports_gen,
            hop_interval,
            obfs,
            up_down: value.up.zip(value.down),
            ca_str: value.ca_str,
            cwnd: value.cwnd,
            udp_mtu: value.udp_mtu,
            disable_mtu_discovery: value.disable_mtu_discovery.unwrap_or(false),
            tls_cert: value.tls_cert,
            tls_key: value.tls_key,
        };

        Ok(Handler::new(opts)?)
    }
}

#[test]
fn test_port_gen() {
    let p = PortGenerator::new(1000).parse_ports_str("").unwrap();
    let p = p.parse_ports_str("1001,1002,1003, 5000-5001").unwrap();

    let all = p.all_ports();
    assert_eq!(all, vec![1000, 1001, 1002, 1003, 5000, 5001]);

    for _ in 0..100 {
        let port = p.get();
        assert!(all.contains(&port));
    }
}
