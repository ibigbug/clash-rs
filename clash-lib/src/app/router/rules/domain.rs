use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct Domain {
    pub domain: String,
    pub target: String,
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} domain {}", self.target, self.domain)
    }
}

impl RuleMatcher for Domain {
    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(_) => false,
            session::SocksAddr::Domain(domain, _) => {
                self.domain.eq_ignore_ascii_case(domain)
            }
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.domain.clone()
    }

    fn type_name(&self) -> &str {
        "Domain"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Session, SocksAddr};

    #[test]
    fn test_domain_case_insensitive() {
        let rule = Domain {
            domain: "example.com".to_string(),
            target: "DIRECT".to_string(),
        };

        let sess_lower = Session {
            destination: SocksAddr::Domain("example.com".to_string(), 80),
            ..Default::default()
        };
        assert!(rule.apply(&sess_lower));

        let sess_upper = Session {
            destination: SocksAddr::Domain("EXAMPLE.COM".to_string(), 80),
            ..Default::default()
        };
        assert!(rule.apply(&sess_upper));

        let sess_mixed = Session {
            destination: SocksAddr::Domain("ExAmPlE.cOm".to_string(), 80),
            ..Default::default()
        };
        assert!(rule.apply(&sess_mixed));

        let sess_other = Session {
            destination: SocksAddr::Domain("other.com".to_string(), 80),
            ..Default::default()
        };
        assert!(!rule.apply(&sess_other));
    }
}
