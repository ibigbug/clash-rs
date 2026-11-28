use std::{fmt, net::SocketAddr};

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor, value::MapAccessDeserializer},
};

use super::{
    config::BindAddress,
    listener::{CommonInboundOpts, InboundOpts},
};
use crate::{Error, app::net::SocketMark, session::SocksAddr};

// The map and comma-separated forms describe the same listener.
#[derive(Deserialize)]
#[serde(remote = "Self")]
pub struct Tunnel {
    network: Vec<String>,
    address: String,
    target: String,
    proxy: Option<String>,
}

impl<'de> Deserialize<'de> for Tunnel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TunnelVisitor;
        impl<'de> Visitor<'de> for TunnelVisitor {
            type Value = Tunnel;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a tunnel mapping or network,address,target[,proxy]")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Tunnel, A::Error> {
                Tunnel::deserialize(MapAccessDeserializer::new(map))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Tunnel, E> {
                let parts: Vec<_> = value.split(',').map(str::trim).collect();
                let [network, address, target, rest @ ..] = parts.as_slice() else {
                    return Err(E::invalid_length(parts.len(), &self));
                };
                if rest.len() > 1 {
                    return Err(E::invalid_length(parts.len(), &self));
                }
                Ok(Tunnel {
                    network: network
                        .split('/')
                        .map(|n| n.trim().to_owned())
                        .collect(),
                    address: (*address).to_owned(),
                    target: (*target).to_owned(),
                    proxy: rest.first().map(|name| (*name).to_owned()),
                })
            }
        }
        deserializer.deserialize_any(TunnelVisitor)
    }
}

impl Tunnel {
    pub(super) fn into_listener(
        self,
        fw_mark: Option<SocketMark>,
    ) -> Result<InboundOpts, Error> {
        let mut network = self.network;
        if network.is_empty()
            || network.iter().any(|n| !matches!(n.as_str(), "tcp" | "udp"))
        {
            return Err(Error::InvalidConfig(
                "tunnel network must specify tcp, udp, or both".into(),
            ));
        }
        network.sort_unstable();
        network.dedup();
        let addr = self.address.as_str();
        let listen: SocketAddr = if let Some((host, port)) = addr.rsplit_once(':')
            && (host.is_empty()
                || host == "*"
                || host.eq_ignore_ascii_case("localhost"))
        {
            let ip = if host.eq_ignore_ascii_case("localhost") {
                BindAddress::local()
            } else {
                BindAddress::all_v4()
            };
            SocketAddr::new(
                ip.0,
                port.parse().map_err(|_| {
                    Error::InvalidConfig(format!("invalid tunnel port: {port}"))
                })?,
            )
        } else {
            addr.parse().map_err(|_| {
                Error::InvalidConfig(format!(
                    "invalid tunnel listen address: {addr}"
                ))
            })?
        };
        let target = self.target.parse::<SocksAddr>().map_err(|_| {
            Error::InvalidConfig(format!("invalid tunnel target: {}", self.target))
        })?;
        if matches!(&target, SocksAddr::Domain(host, _) if url::Host::parse(host).is_err())
            || target.port() == 0
        {
            return Err(Error::InvalidConfig(format!(
                "invalid tunnel target: {}",
                self.target
            )));
        }
        Ok(InboundOpts::Tunnel {
            common_opts: CommonInboundOpts {
                name: format!("tunnel-{}-{listen}", network.join("-")),
                listen: BindAddress(listen.ip()),
                port: listen.port(),
                allow_lan: !listen.ip().is_loopback(),
                fw_mark,
            },
            network,
            target: target.to_string(),
            proxy: self.proxy.filter(|name| !name.is_empty()),
        })
    }
}
