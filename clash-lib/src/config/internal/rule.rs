use crate::{Error, app::router::rules::port::PortRange};
use std::{fmt::Display, str::FromStr};

#[derive(Clone, Default)]
pub struct RuleOptions {
    pub(crate) no_resolve: bool,
    pub(crate) interface: Option<String>,
}

impl RuleOptions {
    fn parse(params: Option<Vec<&str>>) -> Result<Self, Error> {
        let mut options = Self::default();

        for param in params.unwrap_or_default() {
            match param {
                "no-resolve" if options.no_resolve => {
                    return Err(Error::InvalidConfig(
                        "rule option `no-resolve` can only be specified once"
                            .to_string(),
                    ));
                }
                "no-resolve" => options.no_resolve = true,
                param => {
                    let Some(interface) = param.strip_prefix("interface=") else {
                        return Err(Error::InvalidConfig(format!(
                            "unsupported rule option: {param}"
                        )));
                    };
                    if interface.is_empty() {
                        return Err(Error::InvalidConfig(
                            "rule interface cannot be empty".to_string(),
                        ));
                    }
                    if options.interface.replace(interface.to_string()).is_some() {
                        return Err(Error::InvalidConfig(
                            "rule interface can only be specified once".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(options)
    }
}

#[derive(Clone)]
pub struct RuleType {
    kind: RuleKind,
    options: RuleOptions,
}

#[derive(Clone)]
pub enum RuleKind {
    Domain {
        domain: String,
        target: String,
    },
    DomainSuffix {
        domain_suffix: String,
        target: String,
    },
    DomainRegex {
        regex: regex::Regex,
        target: String,
    },
    DomainKeyword {
        domain_keyword: String,
        target: String,
    },
    GeoIP {
        target: String,
        country_code: String,
    },
    GeoSite {
        target: String,
        country_code: String,
    },
    IpCidr {
        ipnet: ipnet::IpNet,
        target: String,
    },
    SrcCidr {
        ipnet: ipnet::IpNet,
        target: String,
    },
    SRCPort {
        target: String,
        ports: Vec<PortRange>,
        raw_ports: String,
    },
    DSTPort {
        target: String,
        ports: Vec<PortRange>,
        raw_ports: String,
    },
    InType {
        in_type: crate::session::Type,
        target: String,
    },
    InUser {
        user: String,
        target: String,
    },
    ProcessName {
        process_name: String,
        target: String,
    },
    ProcessPath {
        process_path: String,
        target: String,
    },
    RuleSet {
        rule_set: String,
        target: String,
    },
    Match {
        target: String,
    },
    Network {
        network: crate::session::Network,
        target: String,
    },
    Composite {
        operator: String,
        expression: String,
        target: String,
    },
}

impl From<RuleKind> for RuleType {
    fn from(kind: RuleKind) -> Self {
        Self {
            kind,
            options: RuleOptions::default(),
        }
    }
}

fn split_rule_tokens(line: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    for (idx, ch) in line.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                tokens.push(line[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    tokens.push(line[start..].trim());
    tokens
}

/// Parses port configurations into a list of [`PortRange`].
///
/// Supports single ports (e.g. `80`) and ranges (e.g. `8000-8080` or
/// `8000:8080`). Multiple entries can be delimited by `/` (standard in
/// comma-separated rule lines, e.g. `DST-PORT,80/443/8000-8080,DIRECT`) or `,`
/// (in standalone payloads).
fn parse_ports(payload: &str) -> Result<Vec<PortRange>, Error> {
    let mut ranges = Vec::new();
    let items = payload
        .split([',', '/'])
        .map(str::trim)
        .filter(|s| !s.is_empty());
    for item in items {
        if let Some((start_str, end_str)) =
            item.split_once('-').or_else(|| item.split_once(':'))
        {
            let start: u16 = start_str.trim().parse().map_err(|_| {
                Error::InvalidConfig(format!(
                    "invalid port range start in `{payload}`"
                ))
            })?;
            let end: u16 = end_str.trim().parse().map_err(|_| {
                Error::InvalidConfig(format!(
                    "invalid port range end in `{payload}`"
                ))
            })?;
            if start > end {
                return Err(Error::InvalidConfig(format!(
                    "invalid port range `{item}` in `{payload}`: start ({start}) > \
                     end ({end})"
                )));
            }
            ranges.push(PortRange::Range(start, end));
        } else {
            let port: u16 = item.parse().map_err(|_| {
                Error::InvalidConfig(format!("invalid port `{item}` in `{payload}`"))
            })?;
            ranges.push(PortRange::Single(port));
        }
    }
    if ranges.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "empty port rule payload: `{payload}`"
        )));
    }
    Ok(ranges)
}

impl RuleType {
    pub fn target(&self) -> &str {
        match &self.kind {
            RuleKind::Domain { target, .. }
            | RuleKind::DomainSuffix { target, .. }
            | RuleKind::DomainRegex { target, .. }
            | RuleKind::DomainKeyword { target, .. }
            | RuleKind::GeoIP { target, .. }
            | RuleKind::GeoSite { target, .. }
            | RuleKind::IpCidr { target, .. }
            | RuleKind::SrcCidr { target, .. }
            | RuleKind::SRCPort { target, .. }
            | RuleKind::DSTPort { target, .. }
            | RuleKind::InType { target, .. }
            | RuleKind::InUser { target, .. }
            | RuleKind::ProcessName { target, .. }
            | RuleKind::ProcessPath { target, .. }
            | RuleKind::RuleSet { target, .. }
            | RuleKind::Match { target, .. }
            | RuleKind::Network { target, .. }
            | RuleKind::Composite { target, .. } => target,
        }
    }

    pub fn interface(&self) -> Option<&str> {
        self.options.interface.as_deref()
    }

    pub fn kind(&self) -> &RuleKind {
        &self.kind
    }

    pub fn options(&self) -> &RuleOptions {
        &self.options
    }

    pub fn into_parts(self) -> (RuleKind, RuleOptions) {
        (self.kind, self.options)
    }
}

impl Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            RuleKind::Domain { domain, target, .. } => {
                write!(f, "DOMAIN,{domain},{target}")
            }
            RuleKind::DomainRegex { regex, target, .. } => {
                write!(f, "DOMAIN-REGEX,{regex},{target}")
            }
            RuleKind::DomainSuffix { .. } => write!(f, "DOMAIN-SUFFIX"),
            RuleKind::DomainKeyword { .. } => write!(f, "DOMAIN-KEYWORD"),
            RuleKind::GeoIP { .. } => write!(f, "GEOIP"),
            RuleKind::GeoSite { .. } => write!(f, "GEOSITE"),
            RuleKind::IpCidr { .. } => write!(f, "IP-CIDR"),
            RuleKind::SrcCidr { .. } => write!(f, "SRC-IP-CIDR"),
            RuleKind::SRCPort { .. } => write!(f, "SRC-PORT"),
            RuleKind::DSTPort { .. } => write!(f, "DST-PORT"),
            RuleKind::InType { .. } => write!(f, "IN-TYPE"),
            RuleKind::InUser { .. } => write!(f, "IN-USER"),
            RuleKind::ProcessName { .. } => write!(f, "PROCESS-NAME"),
            RuleKind::ProcessPath { .. } => write!(f, "PROCESS-PATH"),
            RuleKind::RuleSet { .. } => write!(f, "RULE-SET"),
            RuleKind::Match { .. } => write!(f, "MATCH"),
            RuleKind::Network { .. } => write!(f, "NETWORK"),
            RuleKind::Composite { .. } => write!(f, "COMPOSITE"),
        }?;

        if let Some(interface) = &self.options.interface {
            write!(f, ",interface={interface}")?;
        }

        Ok(())
    }
}

impl RuleType {
    pub fn new(
        proto: &str,
        payload: &str,
        target: &str,
        params: Option<Vec<&str>>,
    ) -> Result<Self, Error> {
        let options = RuleOptions::parse(params)?;

        let kind = match proto {
            "DOMAIN" => Ok(RuleKind::Domain {
                domain: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-REGEX" => Ok(RuleKind::DomainRegex {
                regex: regex::RegexBuilder::new(payload)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| Error::InvalidConfig(e.to_string()))?,
                target: target.to_string(),
            }),
            "DOMAIN-SUFFIX" => Ok(RuleKind::DomainSuffix {
                domain_suffix: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-KEYWORD" => Ok(RuleKind::DomainKeyword {
                domain_keyword: payload.to_string(),
                target: target.to_string(),
            }),
            "GEOSITE" => Ok(RuleKind::GeoSite {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "GEOIP" => Ok(RuleKind::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleKind::IpCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
            }),
            "SRC-IP-CIDR" => Ok(RuleKind::SrcCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
            }),
            "SRC-PORT" | "SRC-PORT-RANGE" => {
                let ports = parse_ports(payload)?;
                Ok(RuleKind::SRCPort {
                    target: target.to_string(),
                    ports,
                    raw_ports: payload.to_string(),
                })
            }
            "DST-PORT" | "DST-PORT-RANGE" | "PORT-RANGE" => {
                let ports = parse_ports(payload)?;
                Ok(RuleKind::DSTPort {
                    target: target.to_string(),
                    ports,
                    raw_ports: payload.to_string(),
                })
            }
            "IN-TYPE" => {
                let in_type = payload.parse()?;
                Ok(RuleKind::InType {
                    in_type,
                    target: target.to_string(),
                })
            }
            "IN-USER" => {
                let user = payload.trim();
                if user.is_empty() {
                    return Err(Error::InvalidConfig(
                        "IN-USER payload cannot be empty".to_string(),
                    ));
                }
                Ok(RuleKind::InUser {
                    user: user.to_string(),
                    target: target.to_string(),
                })
            }
            "PROCESS-NAME" => Ok(RuleKind::ProcessName {
                process_name: payload.to_string(),
                target: target.to_string(),
            }),
            "PROCESS-PATH" => Ok(RuleKind::ProcessPath {
                process_path: payload.to_string(),
                target: target.to_string(),
            }),
            "RULE-SET" => Ok(RuleKind::RuleSet {
                rule_set: payload.to_string(),
                target: target.to_string(),
            }),
            "MATCH" => Ok(RuleKind::Match {
                target: target.to_string(),
            }),
            "NETWORK" => {
                let network = match payload {
                    "TCP" | "tcp" => crate::session::Network::Tcp,
                    "UDP" | "udp" => crate::session::Network::Udp,
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "invalid network type: {}, expected TCP or UDP",
                            payload
                        )));
                    }
                };
                Ok(RuleKind::Network {
                    network,
                    target: target.to_string(),
                })
            }
            "AND" | "OR" | "NOT" => Ok(RuleKind::Composite {
                operator: proto.to_string(),
                expression: payload.to_string(),
                target: target.to_string(),
            }),

            _ => Err(Error::InvalidConfig(format!(
                "unsupported rule type: {proto}"
            ))),
        }?;

        if options.no_resolve
            && !matches!(
                &kind,
                RuleKind::GeoIP { .. }
                    | RuleKind::IpCidr { .. }
                    | RuleKind::SrcCidr { .. }
            )
        {
            return Err(Error::InvalidConfig(format!(
                "rule option `no-resolve` is not supported for {proto}"
            )));
        }

        Ok(Self { kind, options })
    }
}

impl TryFrom<String> for RuleType {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let parts = split_rule_tokens(&line);

        match parts.as_slice() {
            [proto, target] => RuleType::new(proto, "", target, None),
            ["MATCH", target, params @ ..] => {
                RuleType::new("MATCH", "", target, Some(params.to_vec()))
            }
            [proto, payload, target] => RuleType::new(proto, payload, target, None),
            [proto, payload, target, params @ ..] => {
                RuleType::new(proto, payload, target, Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {line}"))),
        }
    }
}

impl FromStr for RuleType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_rule_parsing() {
        // Test TCP network rule
        let rule = RuleType::try_from("NETWORK,TCP,PROXY".to_string()).unwrap();
        match rule.kind {
            RuleKind::Network {
                network, target, ..
            } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test UDP network rule
        let rule = RuleType::try_from("NETWORK,UDP,PROXY".to_string()).unwrap();
        match rule.kind {
            RuleKind::Network {
                network, target, ..
            } => {
                assert_eq!(network, crate::session::Network::Udp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test lowercase network types
        let rule = RuleType::try_from("NETWORK,tcp,PROXY".to_string()).unwrap();
        match rule.kind {
            RuleKind::Network {
                network, target, ..
            } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test invalid network type
        let rule = RuleType::try_from("NETWORK,INVALID,PROXY".to_string());
        assert!(rule.is_err());
    }

    #[test]
    fn test_interface_option_does_not_change_target() {
        let rule = RuleType::try_from(
            "DOMAIN,google.com,IFACE_en0,interface=pdp_ip0".to_string(),
        )
        .unwrap();

        assert_eq!(rule.target(), "IFACE_en0");
        assert_eq!(rule.interface(), Some("pdp_ip0"));

        let rule = RuleType::try_from("DOMAIN,google.com,interface=en0".to_string())
            .unwrap();
        assert_eq!(rule.target(), "interface=en0");
        assert_eq!(rule.interface(), None);
    }

    #[test]
    fn test_match_interface_option() {
        let rule =
            RuleType::try_from("MATCH,DIRECT,interface=en0".to_string()).unwrap();

        assert_eq!(rule.target(), "DIRECT");
        assert_eq!(rule.interface(), Some("en0"));
    }

    #[test]
    fn test_composite_interface_option() {
        let rule = RuleType::try_from(
            "AND,((DOMAIN,google.com),(NETWORK,TCP)),PROXY,interface=en0"
                .to_string(),
        )
        .unwrap();

        assert_eq!(rule.target(), "PROXY");
        assert_eq!(rule.interface(), Some("en0"));
    }

    #[test]
    fn test_rule_options_are_strictly_typed() {
        assert!(
            RuleType::try_from("DOMAIN,google.com,PROXY,unknown-option".to_string())
                .is_err()
        );
        assert!(
            RuleType::try_from("DOMAIN,google.com,PROXY,no-resolve".to_string())
                .is_err()
        );
        assert!(
            RuleType::try_from(
                "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve,interface=en0".to_string()
            )
            .is_ok()
        );
    }

    #[test]
    fn test_port_range_and_inbound_rules_parsing() {
        let rule = RuleType::try_from("DST-PORT,80/443/8000-8080,PROXY".to_string())
            .unwrap();
        assert_eq!(rule.target(), "PROXY");
        match rule.kind {
            RuleKind::DSTPort {
                ports, raw_ports, ..
            } => {
                assert_eq!(raw_ports, "80/443/8000-8080");
                assert_eq!(ports.len(), 3);
                assert!(ports[0].contains(80));
                assert!(ports[1].contains(443));
                assert!(ports[2].contains(8050));
                assert!(!ports[2].contains(8081));
            }
            _ => panic!("Expected DSTPort rule"),
        }

        let rule =
            RuleType::try_from("PORT-RANGE,3000:4000,DIRECT".to_string()).unwrap();
        match rule.kind {
            RuleKind::DSTPort { ports, .. } => {
                assert!(ports[0].contains(3500));
            }
            _ => panic!("Expected DSTPort rule for PORT-RANGE"),
        }

        let rule = RuleType::try_from("SRC-PORT-RANGE,1000-2000,PROXY".to_string())
            .unwrap();
        match rule.kind {
            RuleKind::SRCPort { ports, .. } => {
                assert!(ports[0].contains(1500));
            }
            _ => panic!("Expected SRCPort rule for SRC-PORT-RANGE"),
        }

        let rule = RuleType::try_from("IN-TYPE,TUN,DIRECT".to_string()).unwrap();
        assert_eq!(rule.target(), "DIRECT");
        match rule.kind {
            RuleKind::InType { in_type, .. } => {
                assert_eq!(in_type, crate::session::Type::Tun);
            }
            _ => panic!("Expected InType rule"),
        }

        let rule = RuleType::try_from("IN-USER,alice,PROXY".to_string()).unwrap();
        assert_eq!(rule.target(), "PROXY");
        match rule.kind {
            RuleKind::InUser { user, .. } => {
                assert_eq!(user, "alice");
            }
            _ => panic!("Expected InUser rule"),
        }

        // Test invalid port inputs and standalone comma parsing
        assert!(parse_ports("80,443").is_ok());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("100-50").is_err());
        assert!(parse_ports("").is_err());
        assert!(RuleType::try_from("DST-PORT,70000,DIRECT".to_string()).is_err());
        assert!(RuleType::try_from("DST-PORT,100-50,DIRECT".to_string()).is_err());
    }
}
