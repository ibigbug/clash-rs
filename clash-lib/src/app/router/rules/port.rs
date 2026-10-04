use crate::{app::router::rules::RuleMatcher, session::Session};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortRange {
    Single(u16),
    Range(u16, u16),
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Single(p) => *p == port,
            Self::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

#[derive(Clone)]
pub struct Port {
    pub ports: Vec<PortRange>,
    pub raw: String,
    pub target: String,
    pub is_src: bool,
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} port {}",
            self.target,
            if self.is_src { "src" } else { "dst" },
            self.raw
        )
    }
}

impl RuleMatcher for Port {
    fn apply(&self, sess: &Session) -> bool {
        let p = if self.is_src {
            sess.source.port()
        } else {
            sess.destination.port()
        };
        self.ports.iter().any(|range| range.contains(p))
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.raw.clone()
    }

    fn type_name(&self) -> &str {
        if self.is_src { "SRC-PORT" } else { "DST-PORT" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_range_contains() {
        let single = PortRange::Single(80);
        assert!(single.contains(80));
        assert!(!single.contains(81));

        let range = PortRange::Range(8000, 8080);
        assert!(range.contains(8000));
        assert!(range.contains(8050));
        assert!(range.contains(8080));
        assert!(!range.contains(7999));
        assert!(!range.contains(8081));
    }
}
