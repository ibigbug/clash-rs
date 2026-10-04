use crate::{
    app::router::rules::geodata::str_matcher::{Matcher, try_new_matcher},
    common::{
        domain_trie::DomainSuffixTrie,
        geodata::geodata_proto::{Domain, domain::Type},
    },
};
use aho_corasick::AhoCorasick;
use std::collections::HashSet;

pub trait DomainGroupMatcher: Send + Sync {
    fn apply(&self, domain: &str) -> bool;
}

pub struct SuccinctMatcherGroup {
    exact: HashSet<String>,
    suffix_trie: DomainSuffixTrie<()>,
    plain_ac: Option<AhoCorasick>,
    regex_matchers: Vec<Box<dyn Matcher>>,
    not: bool,
}

impl SuccinctMatcherGroup {
    pub fn try_new(domains: Vec<Domain>, not: bool) -> Result<Self, crate::Error> {
        let mut exact = HashSet::new();
        let mut suffix_trie = DomainSuffixTrie::new();
        let mut plain_patterns = Vec::new();
        let mut regex_matchers = Vec::new();

        for domain in domains {
            let t = Type::try_from(domain.r#type).map_err(|x| {
                crate::Error::InvalidConfig(format!("invalid domain type: {x}"))
            })?;

            match t {
                Type::Plain => {
                    plain_patterns.push(domain.value);
                }
                Type::Regex => {
                    let matcher = try_new_matcher(domain.value, t)?;
                    regex_matchers.push(matcher);
                }
                Type::Domain => {
                    suffix_trie.insert(&domain.value, ());
                }
                Type::Full => {
                    exact.insert(domain.value.to_ascii_lowercase());
                }
            }
        }

        let plain_ac = if !plain_patterns.is_empty() {
            aho_corasick::AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(&plain_patterns)
                .ok()
        } else {
            None
        };

        Ok(SuccinctMatcherGroup {
            exact,
            suffix_trie,
            plain_ac,
            regex_matchers,
            not,
        })
    }
}

impl DomainGroupMatcher for SuccinctMatcherGroup {
    fn apply(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        let is_matched = self.exact.contains(&domain_lower)
            || self.suffix_trie.search(domain).is_some()
            || self.plain_ac.as_ref().is_some_and(|ac| ac.is_match(domain))
            || self.regex_matchers.iter().any(|m| m.matches(domain));

        if self.not { !is_matched } else { is_matched }
    }
}
