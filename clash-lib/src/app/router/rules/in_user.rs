use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone)]
pub struct InUser {
    pub user: String,
    pub target: String,
}

impl std::fmt::Display for InUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} in-user {}", self.target, self.user)
    }
}

impl RuleMatcher for InUser {
    fn apply(&self, sess: &Session) -> bool {
        sess.inbound_user.as_deref() == Some(&self.user)
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.user.clone()
    }

    fn type_name(&self) -> &str {
        "IN-USER"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Network, SocksAddr, Type};
    use std::net::SocketAddr;

    #[test]
    fn test_in_user_matcher() {
        let matcher = InUser {
            user: "alice".to_string(),
            target: "PROXY".to_string(),
        };

        let sess_alice = Session {
            network: Network::Tcp,
            typ: Type::Shadowsocks,
            source: "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
            destination: SocksAddr::Domain("example.com".to_string(), 80),
            inbound_user: Some("alice".to_string()),
            ..Default::default()
        };
        assert!(matcher.apply(&sess_alice));

        let sess_bob = Session {
            network: Network::Tcp,
            typ: Type::Shadowsocks,
            source: "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
            destination: SocksAddr::Domain("example.com".to_string(), 80),
            inbound_user: Some("bob".to_string()),
            ..Default::default()
        };
        assert!(!matcher.apply(&sess_bob));

        let sess_no_user = Session {
            network: Network::Tcp,
            typ: Type::Shadowsocks,
            source: "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
            destination: SocksAddr::Domain("example.com".to_string(), 80),
            inbound_user: None,
            ..Default::default()
        };
        assert!(!matcher.apply(&sess_no_user));
    }
}
