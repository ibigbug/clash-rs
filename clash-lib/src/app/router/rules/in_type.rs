use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct InType {
    pub in_type: crate::session::Type,
    pub target: String,
}

impl std::fmt::Display for InType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} in-type {}", self.target, self.in_type)
    }
}

impl RuleMatcher for InType {
    fn apply(&self, sess: &Session) -> bool {
        sess.typ == self.in_type
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.in_type.to_string()
    }

    fn type_name(&self) -> &str {
        "IN-TYPE"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Network, SocksAddr, Type};
    use std::net::SocketAddr;

    #[test]
    fn test_in_type_matcher() {
        let matcher = InType {
            in_type: Type::Tun,
            target: "DIRECT".to_string(),
        };

        let sess_tun = Session {
            network: Network::Tcp,
            typ: Type::Tun,
            source: "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
            destination: SocksAddr::Domain("example.com".to_string(), 80),
            inbound_user: None,
            ..Default::default()
        };
        assert!(matcher.apply(&sess_tun));

        let sess_http = Session {
            network: Network::Tcp,
            typ: Type::Http,
            source: "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
            destination: SocksAddr::Domain("example.com".to_string(), 80),
            inbound_user: None,
            ..Default::default()
        };
        assert!(!matcher.apply(&sess_http));
    }
}
