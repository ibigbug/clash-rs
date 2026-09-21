use std::fmt::Display;

use crate::session;

use super::RuleMatcher;

#[derive(Clone)]
pub struct DomainKeyword {
    pub keyword: String,
    pub target: String,
}

impl Display for DomainKeyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} keyword {}", self.target, self.keyword)
    }
}

impl RuleMatcher for DomainKeyword {
    fn apply(&self, sess: &session::Session) -> bool {
        match &sess.destination {
            session::SocksAddr::Ip(_) => false,
            session::SocksAddr::Domain(domain, _) => {
                let d = domain.to_ascii_lowercase();
                let k = self.keyword.to_ascii_lowercase();
                d.contains(&k)
            }
        }
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.keyword.to_owned()
    }

    fn type_name(&self) -> &str {
        "DomainKeyword"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Session, SocksAddr};

    #[test]
    fn test_domain_keyword_case_insensitive() {
        let rule = DomainKeyword {
            keyword: "google".to_string(),
            target: "PROXY".to_string(),
        };

        let sess_lower = Session {
            destination: SocksAddr::Domain("www.google.com".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&sess_lower));

        let sess_upper = Session {
            destination: SocksAddr::Domain("WWW.GOOGLE.COM".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&sess_upper));

        let sess_mixed = Session {
            destination: SocksAddr::Domain("news.GooGle.com.hk".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&sess_mixed));

        let sess_other = Session {
            destination: SocksAddr::Domain("www.youtube.com".to_string(), 443),
            ..Default::default()
        };
        assert!(!rule.apply(&sess_other));
    }
}
