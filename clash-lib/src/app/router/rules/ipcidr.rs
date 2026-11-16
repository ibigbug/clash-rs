use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct IpCidr {
    pub ipnet: ipnet::IpNet,
    pub target: String,
    pub match_src: bool,
    pub no_resolve: bool,
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.target,
            if self.match_src { "src" } else { "dst" },
            self.ipnet
        )
    }
}

impl RuleMatcher for IpCidr {
    fn apply(&self, sess: &Session) -> bool {
        if self.match_src {
            self.ipnet.contains(&sess.source.ip())
        } else {
            let ip = sess.resolved_ip.or(sess.destination.ip());

            if let Some(ip) = ip {
                self.ipnet.contains(&ip)
            } else {
                false
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn should_resolve_ip(&self) -> bool {
        // SRC-IP-CIDR matches the source address and never needs the
        // destination resolved
        !self.match_src && !self.no_resolve
    }

    fn payload(&self) -> String {
        self.ipnet.to_string()
    }

    fn type_name(&self) -> &str {
        "IPCIDR"
    }
}
