use radix_trie::Trie;

/// A Radix Trie specialized for domain suffix matching.
///
/// By storing domains in reverse label order with a terminating delimiter (e.g.
/// `moc.elgoog.`), any subdomain query like `mail.google.com`
/// (`moc.elgoog.liam.`) can find its suffix match via `get_ancestor_value` in
/// O(L) time, where L is the length of the query domain.
pub struct DomainSuffixTrie<T> {
    trie: Trie<String, T>,
}

impl<T> Default for DomainSuffixTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> DomainSuffixTrie<T> {
    pub fn new() -> Self {
        Self { trie: Trie::new() }
    }

    /// Normalize and reverse the domain with a trailing dot:
    /// e.g. "google.com" -> "moc.elgoog."
    fn format_key(domain: &str) -> String {
        let domain = domain.trim().trim_start_matches('.').trim_end_matches('.');
        let mut s = String::with_capacity(domain.len() + 1);
        for c in domain.chars().rev() {
            s.push(c.to_ascii_lowercase());
        }
        s.push('.');
        s
    }

    pub fn insert(&mut self, domain: &str, val: T) {
        let key = Self::format_key(domain);
        self.trie.insert(key, val);
    }

    /// Search for the longest matching suffix of `domain`.
    /// Returns the associated value if a suffix rule matches.
    pub fn search(&self, domain: &str) -> Option<&T> {
        let key = Self::format_key(domain);
        self.trie.get_ancestor_value(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_suffix_trie() {
        let mut trie = DomainSuffixTrie::new();
        trie.insert("google.com", "GOOGLE");
        trie.insert("mail.google.com", "MAIL_GOOGLE");
        trie.insert("github.com", "GITHUB");
        trie.insert(".cn", "CN");

        // Exact match
        assert_eq!(trie.search("google.com"), Some(&"GOOGLE"));
        assert_eq!(trie.search("GOOGLE.COM"), Some(&"GOOGLE"));

        // Subdomain match
        assert_eq!(trie.search("www.google.com"), Some(&"GOOGLE"));
        assert_eq!(trie.search("sub.www.google.com"), Some(&"GOOGLE"));

        // Longest match (most specific)
        assert_eq!(trie.search("mail.google.com"), Some(&"MAIL_GOOGLE"));
        assert_eq!(trie.search("sub.mail.google.com"), Some(&"MAIL_GOOGLE"));

        // Different domain
        assert_eq!(trie.search("github.com"), Some(&"GITHUB"));
        assert_eq!(trie.search("api.github.com"), Some(&"GITHUB"));

        // TLD match
        assert_eq!(trie.search("baidu.cn"), Some(&"CN"));
        assert_eq!(trie.search("sub.baidu.cn"), Some(&"CN"));

        // Non-matches
        assert_eq!(trie.search("fakegoogle.com"), None);
        assert_eq!(trie.search("notgoogle.com"), None);
        assert_eq!(trie.search("google.com.org"), None);
        assert_eq!(trie.search("mygithub.com"), None);
        assert_eq!(trie.search("example.com"), None);
    }
}
