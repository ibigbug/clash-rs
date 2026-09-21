use crate::{
    app::router::rules::RuleMatcher,
    session::{Session, SocksAddr},
};

#[derive(Clone)]
pub struct DomainSuffix {
    pub suffix: String,
    pub target: String,
}

impl std::fmt::Display for DomainSuffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} suffix {}", self.target, self.suffix)
    }
}

impl RuleMatcher for DomainSuffix {
    fn apply(&self, sess: &Session) -> bool {
        match &sess.destination {
            SocksAddr::Ip(_) => false,
            SocksAddr::Domain(domain, _) => {
                if domain.eq_ignore_ascii_case(&self.suffix) {
                    return true;
                }
                if domain.len() > self.suffix.len() {
                    let dot_idx = domain.len() - self.suffix.len() - 1;
                    if domain.as_bytes()[dot_idx] == b'.' {
                        return domain[dot_idx + 1..]
                            .eq_ignore_ascii_case(&self.suffix);
                    }
                }
                false
            }
        }
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.suffix.clone()
    }

    fn type_name(&self) -> &str {
        "DomainSuffix"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_suffix_case_insensitive() {
        let rule = DomainSuffix {
            suffix: "google.com".to_string(),
            target: "PROXY".to_string(),
        };

        let sess_exact = Session {
            destination: SocksAddr::Domain("google.com".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&sess_exact));

        let sess_exact_upper = Session {
            destination: SocksAddr::Domain("GOOGLE.COM".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&sess_exact_upper));

        let sess_sub_mixed = Session {
            destination: SocksAddr::Domain("Mail.Google.Com".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&sess_sub_mixed));

        let sess_sub_upper = Session {
            destination: SocksAddr::Domain("WWW.GOOGLE.COM".to_string(), 443),
            ..Default::default()
        };
        assert!(rule.apply(&sess_sub_upper));

        let sess_fake = Session {
            destination: SocksAddr::Domain("fakegoogle.com".to_string(), 443),
            ..Default::default()
        };
        assert!(!rule.apply(&sess_fake));
    }
}
