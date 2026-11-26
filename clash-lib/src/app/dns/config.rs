pub use super::dns_client::DNSNetMode;
use crate::{
    Error,
    app::net::{
        OutboundInterface, SocketMark, get_interface_by_name, get_outbound_interface,
    },
    common::trie,
    config::def::{DNSListen, DNSMode, EdnsClientSubnet as DefEdnsClientSubnet},
};
use ipnet::{AddrParseError, Ipv4Net, Ipv6Net};
use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tracing::warn;
use url::Url;
pub use watfaq_dns::{DNSListenAddr, DoH3Config, DoHConfig, DoTConfig};

#[derive(Clone, Debug)]
pub struct NameServer {
    pub net: DNSNetMode,
    pub host: url::Host<String>,
    pub port: u16,
    pub interface: Option<OutboundInterface>,
    pub proxy: Option<String>,
}
impl Display for NameServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}://{}:{}#{:?}",
            self.net, self.host, self.port, self.interface,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct FallbackFilter {
    pub geo_ip: bool,
    pub geo_ip_code: String,
    pub ip_cidr: Option<Vec<ipnet::IpNet>>,
    pub domain: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EdnsClientSubnet {
    pub ipv4: Option<Ipv4Net>,
    pub ipv6: Option<Ipv6Net>,
}

#[derive(Default)]
pub struct Config {
    pub enable: bool,
    pub ipv6: bool,
    pub nameserver: Vec<NameServer>,
    pub fallback: Vec<NameServer>,
    pub fallback_filter: FallbackFilter,
    pub listen: DNSListenAddr,
    pub enhance_mode: DNSMode,
    pub default_nameserver: Vec<NameServer>,
    pub proxy_server_nameserver: Option<Vec<NameServer>>,
    pub fake_ip_range: ipnet::IpNet,
    pub fake_ip_filter: Vec<String>,
    pub store_fake_ip: bool,
    pub store_smart_stats: bool,
    pub hosts: Option<trie::StringTrie<IpAddr>>,
    pub nameserver_policy: HashMap<String, NameServer>,
    pub edns_client_subnet: Option<EdnsClientSubnet>,
    pub fw_mark: Option<SocketMark>,
    pub respect_rules: bool,
}

impl Config {
    pub(crate) fn inherit_interface(
        &mut self,
        interface: Option<&OutboundInterface>,
    ) {
        if let Some(interface) = interface {
            for server in self
                .default_nameserver
                .iter_mut()
                .chain(&mut self.nameserver)
                .chain(&mut self.fallback)
                .chain(self.proxy_server_nameserver.iter_mut().flatten())
                .chain(self.nameserver_policy.values_mut())
            {
                server.interface.get_or_insert_with(|| interface.clone());
            }
        }
    }

    pub fn parse_nameserver(servers: &[String]) -> Result<Vec<NameServer>, Error> {
        let mut nameservers = vec![];

        for (i, server) in servers.iter().enumerate() {
            let mut server = server.clone();

            if server == "system" {
                warn!("'system' is not supported as dns nameserver, skipping");
                continue;
            }

            // If the server doesn't contain a scheme, assume it's a UDP
            // address.
            if !server.contains("://") {
                if server.contains(':') && !server.starts_with('[') {
                    server = format!("udp://[{}]", server);
                } else {
                    server = "udp://".to_owned() + &server;
                }
            }

            let url = Url::parse(&server).map_err(|_x| {
                Error::InvalidConfig(format!(
                    "invalid dns server: {}",
                    server.as_str()
                ))
            })?;

            let host = url.host().ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "invalid dns server: no host found in {}",
                    server.as_str()
                ))
            })?;

            let host = match host {
                url::Host::Domain(v) => {
                    // Try to parse domain as IPv4 address because of WHATWG
                    // standard
                    match v.parse::<std::net::Ipv4Addr>() {
                        Ok(ipv4) => url::Host::Ipv4(ipv4),
                        Err(_) => url::Host::Domain(v),
                    }
                }
                v => v,
            };

            let iface = Self::parse_outbound_interface(&url);
            let proxy = Self::parse_outbound_proxy(&url);
            let net: &str;
            let port: u16;

            match url.scheme() {
                "udp" => {
                    port = url.port().unwrap_or(53);
                    net = "UDP";
                }
                "tcp" => {
                    port = url.port().unwrap_or(53);
                    net = "TCP";
                }
                "tls" => {
                    port = url.port().unwrap_or(853);
                    net = "DoT";
                }
                "https" => {
                    port = url.port().unwrap_or(443);
                    net = "DoH";
                }
                "dhcp" => {
                    port = url.port().unwrap_or(0);
                    net = "DHCP";
                }

                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "DNS nameserver [{}] unsupported scheme: {}",
                        i,
                        url.scheme()
                    )));
                }
            }

            let net = net.parse()?;
            nameservers.push(NameServer {
                host: host.to_owned(),
                port,
                net,
                interface: iface
                    .map(|x| match x.as_str() {
                        "auto" => {
                            get_outbound_interface().ok_or(Error::InvalidConfig(
                                "DNS nameserver [auto] no outbound interface found"
                                    .into(),
                            ))
                        }
                        name => get_interface_by_name(name).ok_or(
                            Error::InvalidConfig(format!(
                                "DNS nameserver [{i}] invalid interface: {name}"
                            )),
                        ),
                    })
                    .transpose()?,
                proxy,
            });
        }

        Ok(nameservers)
    }

    pub fn parse_nameserver_policy(
        policy_map: &HashMap<String, String>,
    ) -> Result<HashMap<String, NameServer>, Error> {
        let mut policy = HashMap::new();

        for (domain, server) in policy_map {
            let nameservers =
                Config::parse_nameserver(std::slice::from_ref(server))?;

            let (_, valid) = trie::valid_and_split_domain(domain);
            if !valid {
                return Err(Error::InvalidConfig(format!(
                    "DNS ResolverRule invalid domain: {domain}"
                )));
            }
            policy.insert(domain.into(), nameservers[0].clone());
        }
        Ok(policy)
    }

    pub fn parse_fallback_ip_cidr(
        ipcidr: &[String],
    ) -> anyhow::Result<Vec<ipnet::IpNet>> {
        let mut output = vec![];

        for ip in ipcidr.iter() {
            let net: ipnet::IpNet = ip
                .parse()
                .map_err(|x: AddrParseError| Error::InvalidConfig(x.to_string()))?;
            output.push(net);
        }

        Ok(output)
    }

    pub fn parse_hosts(
        hosts_mapping: &HashMap<String, String>,
    ) -> anyhow::Result<trie::StringTrie<IpAddr>> {
        let mut tree = trie::StringTrie::new();
        tree.insert(
            "localhost",
            Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()),
        );

        for (host, ip_str) in hosts_mapping.iter() {
            let ip = ip_str.parse::<IpAddr>()?;
            tree.insert(host.as_str(), Arc::new(ip));
        }

        Ok(tree)
    }
}

fn parse_listen_addr(addr: &str) -> Result<SocketAddr, Error> {
    if addr.starts_with(':') {
        format!("0.0.0.0{addr}").parse().map_err(|_| {
            Error::InvalidConfig(format!("invalid dns listen address: {addr}"))
        })
    } else {
        addr.parse().map_err(|_| {
            Error::InvalidConfig(format!("invalid dns listen address: {addr}"))
        })
    }
}

impl Config {
    pub fn parse_outbound_proxy(url: &Url) -> Option<String> {
        let frag = url.fragment()?;
        let pairs = frag.split("&");
        for pair in pairs {
            if pair.starts_with("proxy=") {
                let outbound = pair.trim_start_matches("proxy=");
                return Some(outbound.into());
            } else if !pair.contains("=") {
                return Some(pair.into());
            }
        }

        None
    }

    pub fn parse_outbound_interface(url: &Url) -> Option<String> {
        let frag = url.fragment()?;
        let pairs = frag.split("&");
        for first in pairs {
            if first.starts_with("interface=") {
                let iface = first.trim_start_matches("interface=");
                return Some(iface.into());
            }
        }

        None
    }
}

impl TryFrom<crate::config::def::Config> for Config {
    type Error = Error;

    fn try_from(value: crate::def::Config) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&crate::config::def::Config> for Config {
    type Error = Error;

    fn try_from(c: &crate::config::def::Config) -> Result<Self, Self::Error> {
        let dc = &c.dns;
        if dc.enable && dc.nameserver.is_empty() {
            return Err(Error::InvalidConfig(String::from(
                "dns enabled, no nameserver specified",
            )));
        }

        let nameservers = Config::parse_nameserver(&dc.nameserver)?;
        let fallback = Config::parse_nameserver(&dc.fallback)?;
        let nameserver_policy =
            Config::parse_nameserver_policy(&dc.nameserver_policy)?;

        if dc.default_nameserver.is_empty() {
            return Err(Error::InvalidConfig(String::from(
                "default nameserver empty",
            )));
        }

        let default_nameserver = Config::parse_nameserver(&dc.default_nameserver)?;

        for ns in &default_nameserver {
            if let url::Host::Domain(_) = ns.host {
                return Err(Error::InvalidConfig(String::from(
                    "default dns must be ip address",
                )));
            }
        }

        // Domain hostnames are allowed here: they are bootstrapped through
        // `default-nameserver` at client-construction time, mirroring how
        // `nameserver` resolves its own DoH/DoT hosts.
        let proxy_server_nameserver = if !dc.proxy_server_nameserver.is_empty() {
            let ns = Config::parse_nameserver(&dc.proxy_server_nameserver)?;
            if ns.is_empty() {
                return Err(Error::InvalidConfig(String::from(
                    "proxy-server-nameserver has no usable entries (all skipped)",
                )));
            }
            Some(ns)
        } else {
            None
        };

        let edns_client_subnet = dc
            .edns_client_subnet
            .as_ref()
            .map(parse_edns_client_subnet)
            .transpose()?;

        Ok(Self {
            enable: dc.enable,
            ipv6: c.ipv6 && dc.ipv6,
            fw_mark: c.routing_mark,
            nameserver: nameservers,
            fallback,
            fallback_filter: dc.fallback_filter.clone().into(),
            listen: dc
                .listen
                .clone()
                .map(|l| -> Result<DNSListenAddr, Error> {
                    match l {
                        DNSListen::Udp(u) => {
                            let addr = parse_listen_addr(&u)?;
                            Ok(DNSListenAddr {
                                udp: Some(addr),
                                ..Default::default()
                            })
                        }
                        DNSListen::Multiple(m) => {
                            let udp = m
                                .udp
                                .as_deref()
                                .map(parse_listen_addr)
                                .transpose()?;
                            let tcp = m
                                .tcp
                                .as_deref()
                                .map(parse_listen_addr)
                                .transpose()?;
                            // DoHConfig and DoH3Config have identical fields;
                            // helper
                            // avoids duplication.
                            let map_doh_fields =
                                |c: crate::config::def::DohListenDef| {
                                    parse_listen_addr(&c.addr).map(|addr| {
                                        (addr, c.ca_cert, c.ca_key, c.hostname)
                                    })
                                };
                            let doh = m
                                .doh
                                .map(|c| {
                                    map_doh_fields(c).map(
                                        |(addr, ca_cert, ca_key, hostname)| {
                                            DoHConfig {
                                                addr,
                                                ca_cert,
                                                ca_key,
                                                hostname,
                                            }
                                        },
                                    )
                                })
                                .transpose()?;
                            let dot = m
                                .dot
                                .map(|c| -> Result<DoTConfig, Error> {
                                    Ok(DoTConfig {
                                        addr: parse_listen_addr(&c.addr)?,
                                        ca_cert: c.ca_cert,
                                        ca_key: c.ca_key,
                                    })
                                })
                                .transpose()?;
                            let doh3 = m
                                .doh3
                                .map(|c| {
                                    map_doh_fields(c).map(
                                        |(addr, ca_cert, ca_key, hostname)| {
                                            DoH3Config {
                                                addr,
                                                ca_cert,
                                                ca_key,
                                                hostname,
                                            }
                                        },
                                    )
                                })
                                .transpose()?;
                            Ok(DNSListenAddr {
                                udp,
                                tcp,
                                doh,
                                dot,
                                doh3,
                            })
                        }
                    }
                })
                .transpose()?
                .unwrap_or_default(),
            enhance_mode: dc.enhanced_mode.clone(),
            default_nameserver,
            proxy_server_nameserver,
            fake_ip_range: dc.fake_ip_range.parse::<ipnet::IpNet>().map_err(
                |_| Error::InvalidConfig(String::from("invalid fake ip range")),
            )?,
            fake_ip_filter: dc.fake_ip_filter.clone(),
            store_fake_ip: c.profile.store_fake_ip,
            store_smart_stats: c.profile.store_smart_stats,
            hosts: if dc.use_hosts && !c.hosts.is_empty() {
                Config::parse_hosts(&c.hosts).ok()
            } else {
                let mut tree = trie::StringTrie::new();
                tree.insert(
                    "localhost",
                    Arc::new("127.0.0.1".parse::<IpAddr>().unwrap()),
                );
                Some(tree)
            },
            nameserver_policy,
            edns_client_subnet,
            respect_rules: dc.respect_rules,
        })
    }
}

fn parse_edns_client_subnet(
    ecs: &DefEdnsClientSubnet,
) -> Result<EdnsClientSubnet, Error> {
    let ipv4 = ecs
        .ipv4
        .as_ref()
        .map(|value| {
            value.parse::<Ipv4Net>().map_err(|_| {
                Error::InvalidConfig(format!(
                    "invalid edns-client-subnet ipv4 network: {value}"
                ))
            })
        })
        .transpose()?;

    let ipv6 = ecs
        .ipv6
        .as_ref()
        .map(|value| {
            value.parse::<Ipv6Net>().map_err(|_| {
                Error::InvalidConfig(format!(
                    "invalid edns-client-subnet ipv6 network: {value}"
                ))
            })
        })
        .transpose()?;

    if ipv4.is_none() && ipv6.is_none() {
        return Err(Error::InvalidConfig(
            "edns-client-subnet requires at least one of ipv4/ipv6".into(),
        ));
    }

    Ok(EdnsClientSubnet { ipv4, ipv6 })
}

impl From<crate::config::def::FallbackFilter> for FallbackFilter {
    fn from(c: crate::config::def::FallbackFilter) -> Self {
        let ipcidr = Config::parse_fallback_ip_cidr(&c.ip_cidr);
        Self {
            geo_ip: c.geo_ip,
            geo_ip_code: c.geo_ip_code.to_uppercase(),
            ip_cidr: ipcidr.ok(),
            domain: c.domain,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_servers_inherit_only_missing_interfaces() {
        let interface = |name: &str| {
            OutboundInterface::from(network_interface::NetworkInterface {
                name: name.to_owned(),
                addr: vec![],
                mac_addr: None,
                index: 1,
                internal: false,
            })
        };
        let server = Config::parse_nameserver(&["192.0.2.1".to_owned()])
            .unwrap()
            .remove(0);
        let mut cfg = Config {
            nameserver: vec![NameServer {
                interface: Some(interface("explicit")),
                ..server.clone()
            }],
            default_nameserver: vec![server.clone()],
            fallback: vec![server.clone()],
            proxy_server_nameserver: Some(vec![server.clone()]),
            nameserver_policy: HashMap::from([("example.org".into(), server)]),
            ..Config::default()
        };
        cfg.inherit_interface(None);
        assert!(cfg.default_nameserver[0].interface.is_none());
        cfg.inherit_interface(Some(&interface("detected")));
        for ns in [
            &cfg.default_nameserver[0],
            &cfg.fallback[0],
            &cfg.proxy_server_nameserver.as_ref().unwrap()[0],
            &cfg.nameserver_policy["example.org"],
        ] {
            assert_eq!(ns.interface.as_ref().unwrap().name, "detected");
        }
        assert_eq!(
            cfg.nameserver[0].interface.as_ref().unwrap().name,
            "explicit"
        );
    }

    #[test]
    fn parse_nameserver_ipv6_without_scheme() {
        let servers = vec!["2400:3200::1".to_string()];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].host.to_string(), "[2400:3200::1]");
        assert_eq!(ns[0].port, 53);
        assert_eq!(ns[0].net, DNSNetMode::Udp);
        let _sock: std::net::SocketAddr = format!("{}:{}", ns[0].host, ns[0].port)
            .parse()
            .expect("address should parse to SocketAddr");
    }

    #[test]
    fn parse_nameserver_ipv6_with_brackets_and_port() {
        let servers = vec!["[2400:3200::1]:5353".to_string()];
        let ns = Config::parse_nameserver(&servers).expect("parse failed");
        assert_eq!(ns.len(), 1);
        assert_eq!(ns[0].host.to_string(), "[2400:3200::1]");
        assert_eq!(ns[0].port, 5353);
        assert_eq!(ns[0].net, DNSNetMode::Udp);
        let _sock: std::net::SocketAddr = format!("{}:{}", ns[0].host, ns[0].port)
            .parse()
            .expect("address should parse to SocketAddr");
    }
}
