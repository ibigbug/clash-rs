use std::{collections::HashMap, fmt::Display};

use erased_serde::Serialize;

use crate::session::Session;

pub mod composite;
pub mod domain;
pub mod domain_keyword;
pub mod domain_regex;
pub mod domain_suffix;
pub mod final_;
pub mod geodata;
pub mod geoip;
pub mod in_type;
pub mod in_user;
pub mod ipcidr;
pub mod network;
pub mod port;
pub mod process;
pub mod ruleset;

pub trait RuleMatcher: Send + Sync + Unpin + Display {
    /// check if the rule should apply to the session
    fn apply(&self, sess: &Session) -> bool;

    /// the Proxy to use
    fn target(&self) -> &str;

    /// the actual content of the rule
    fn payload(&self) -> String;

    /// the type of the rule
    fn type_name(&self) -> &str;

    fn should_resolve_ip(&self) -> bool {
        false
    }

    fn size(&self) -> u16 {
        0
    }

    fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut m: HashMap<String, Box<dyn Serialize + Send>> = HashMap::new();
        m.insert("type".to_string(), Box::new(self.type_name().to_owned()));
        m.insert("proxy".to_string(), Box::new(self.target().to_owned()));
        m.insert("payload".to_string(), Box::new(self.payload()));
        m.insert("size".to_string(), Box::new(self.size()));
        m
    }
}
