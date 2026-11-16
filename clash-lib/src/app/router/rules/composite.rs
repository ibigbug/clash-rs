use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use crate::{
    app::{
        remote_content_manager::providers::rule_provider::ThreadSafeRuleProvider,
        router::{RuleMatcher, map_rule_type},
    },
    common::{geodata::GeoDataLookup, mmdb::MmdbLookup},
    config::internal::rule::RuleType,
    session,
};

/// Represents a node in the composite rule expression tree
enum RuleExpression {
    /// A leaf node containing an actual rule matcher
    Rule(Box<dyn RuleMatcher>),

    /// AND operator - all sub-expressions must match
    And(Vec<RuleExpression>),

    /// OR operator - at least one sub-expression must match
    Or(Vec<RuleExpression>),

    /// NOT operator - inverts the result of the sub-expression
    Not(Box<RuleExpression>),
}

impl RuleExpression {
    /// Evaluate this expression against a session
    fn evaluate(&self, sess: &session::Session) -> bool {
        match self {
            RuleExpression::Rule(matcher) => matcher.apply(sess),
            RuleExpression::And(exprs) => exprs.iter().all(|e| e.evaluate(sess)),
            RuleExpression::Or(exprs) => exprs.iter().any(|e| e.evaluate(sess)),
            RuleExpression::Not(expr) => !expr.evaluate(sess),
        }
    }

    /// Whether any leaf rule in this expression needs the destination IP
    fn should_resolve_ip(&self) -> bool {
        match self {
            RuleExpression::Rule(matcher) => matcher.should_resolve_ip(),
            RuleExpression::And(exprs) | RuleExpression::Or(exprs) => {
                exprs.iter().any(|e| e.should_resolve_ip())
            }
            RuleExpression::Not(expr) => expr.should_resolve_ip(),
        }
    }
}

/// Split trailing rule options (`no-resolve`, `interface=...`) off a sub-rule
/// body such as `cncidr,no-resolve`. Only recognized options are split off, so
/// payloads that contain commas (e.g. `DOMAIN-REGEX,^a{1,3}$`) are kept whole.
fn split_sub_rule_options(rest: &str) -> (&str, Vec<&str>) {
    let mut payload = rest;
    let mut params = Vec::new();
    while let Some((head, last)) = payload.rsplit_once(',') {
        let last = last.trim();
        if last == "no-resolve" || last.starts_with("interface=") {
            params.push(last);
            payload = head;
        } else {
            break;
        }
    }
    params.reverse();
    (payload.trim(), params)
}

pub struct CompositeRule {
    operator: String,
    expression: RuleExpression,
    target: String,
    raw_expression: String, // Keep the original string for payload()
}

impl CompositeRule {
    /// Create a new CompositeRule
    ///
    /// # Arguments
    /// * `operator` - The operator type: "AND", "OR", or "NOT"
    /// * `expression` - The expression string to parse
    /// * `target` - The target proxy name
    pub fn new(
        operator: &str,
        expression: &str,
        target: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<Self, crate::Error> {
        let parsed_expr = Self::parse_expression(
            operator,
            expression,
            mmdb,
            geodata,
            rule_provider_registry,
        )?;

        Ok(Self {
            operator: operator.to_string(),
            expression: parsed_expr,
            target: target.to_string(),
            raw_expression: expression.to_string(),
        })
    }

    /// Parse the expression string into a RuleExpression tree
    /// Supports nested composite rules via recursion
    fn parse_expression(
        operator: &str,
        expression: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<RuleExpression, crate::Error> {
        let expr = expression.trim();
        if !expr.starts_with('(') || !expr.ends_with(')') {
            return Err(crate::Error::InvalidConfig(format!(
                "composite expression must be wrapped in parentheses: {}",
                expression
            )));
        }
        // Remove outer parentheses
        let inner = &expr[1..expr.len() - 1];

        let sub_exprs = Self::parse_sub_expressions(
            inner,
            mmdb,
            geodata,
            rule_provider_registry,
        )?;

        match operator {
            "AND" => Ok(RuleExpression::And(sub_exprs)),
            "OR" => Ok(RuleExpression::Or(sub_exprs)),
            "NOT" => {
                if sub_exprs.len() != 1 {
                    return Err(crate::Error::InvalidConfig(
                        "NOT operator requires exactly one sub-expression"
                            .to_string(),
                    ));
                }
                Ok(RuleExpression::Not(Box::new(
                    sub_exprs.into_iter().next().unwrap(),
                )))
            }
            _ => Err(crate::Error::InvalidConfig(format!(
                "unknown composite operator: {}",
                operator
            ))),
        }
    }

    /// Parse comma-separated sub-expressions wrapped in parentheses
    /// Scans for balanced parentheses and recursively parses each expression
    fn parse_sub_expressions(
        input: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<Vec<RuleExpression>, crate::Error> {
        let mut expressions = Vec::new();
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            // Skip whitespace and commas
            if chars[i].is_whitespace() || chars[i] == ',' {
                i += 1;
                continue;
            }

            // Must start with '('
            if chars[i] != '(' {
                return Err(crate::Error::InvalidConfig(format!(
                    "expected '(' at position {} in: {}",
                    i, input
                )));
            }

            // Find matching closing paren
            let start = i;
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '(' {
                    depth += 1;
                } else if chars[i] == ')' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1; // Move past the closing paren
                        break;
                    }
                }
                i += 1;
            }

            if depth != 0 {
                return Err(crate::Error::InvalidConfig(format!(
                    "unbalanced parentheses in: {}",
                    input
                )));
            }

            // Extract the expression
            let expr_str: String = chars[start..i].iter().collect();
            expressions.push(Self::parse_one_expression(
                &expr_str,
                mmdb.clone(),
                geodata.clone(),
                rule_provider_registry,
            )?);
        }

        if expressions.is_empty() {
            return Err(crate::Error::InvalidConfig(
                "no sub-expressions found".to_string(),
            ));
        }

        Ok(expressions)
    }

    /// Parse a single expression: either (RULE-TYPE,payload...) or
    /// (OPERATOR,((sub-exprs)))
    fn parse_one_expression(
        expr_str: &str,
        mmdb: Option<MmdbLookup>,
        geodata: Option<GeoDataLookup>,
        rule_provider_registry: Option<&HashMap<String, ThreadSafeRuleProvider>>,
    ) -> Result<RuleExpression, crate::Error> {
        let expr_str = expr_str.trim();
        if !expr_str.starts_with('(') || !expr_str.ends_with(')') {
            return Err(crate::Error::InvalidConfig(format!(
                "expression must be wrapped in parentheses: {}",
                expr_str
            )));
        }

        let inner = &expr_str[1..expr_str.len() - 1];

        // Find first comma to get the rule type/operator
        let mut depth = 0;
        let mut first_comma_pos = None;
        for (i, ch) in inner.chars().enumerate() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    first_comma_pos = Some(i);
                    break;
                }
                _ => {}
            }
        }

        let first_comma_pos = first_comma_pos.ok_or_else(|| {
            crate::Error::InvalidConfig(format!(
                "no comma found in expression: {}",
                expr_str
            ))
        })?;

        let rule_type = inner[..first_comma_pos].trim();
        let rest = &inner[first_comma_pos + 1..];

        // Check if this is a composite operator
        if matches!(rule_type, "AND" | "OR" | "NOT") {
            // Recursively parse as composite rule
            // rest should be like: ((expr1),(expr2),...)
            return Self::parse_expression(
                rule_type,
                rest,
                mmdb,
                geodata,
                rule_provider_registry,
            );
        }

        // It's a leaf rule - parse as RuleType
        let (payload, params) = split_sub_rule_options(rest);
        let rule = RuleType::new(rule_type, payload, "", Some(params))?;
        if rule.interface().is_some() {
            return Err(crate::Error::InvalidConfig(format!(
                "rule option `interface` is not supported inside composite \
                 sub-rules, set it on the composite rule instead: {expr_str}"
            )));
        }
        let matcher = map_rule_type(rule, mmdb, geodata, rule_provider_registry);
        Ok(RuleExpression::Rule(matcher))
    }
}

impl Display for CompositeRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.target,
            self.operator.to_lowercase(),
            self.raw_expression
        )
    }
}

impl Debug for CompositeRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompositeRule {{ operator: {}, expression: {}, target: {} }}",
            self.operator, self.raw_expression, self.target
        )
    }
}

impl RuleMatcher for CompositeRule {
    fn apply(&self, sess: &session::Session) -> bool {
        self.expression.evaluate(sess)
    }

    fn target(&self) -> &str {
        &self.target
    }

    fn payload(&self) -> String {
        self.raw_expression.clone()
    }

    fn type_name(&self) -> &str {
        &self.operator
    }

    fn should_resolve_ip(&self) -> bool {
        self.expression.should_resolve_ip()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Network, Session, SocksAddr};

    fn create_test_session(domain: &str, port: u16, network: Network) -> Session {
        Session {
            destination: SocksAddr::Domain(domain.to_string(), port),
            network,
            ..Default::default()
        }
    }

    #[test]
    fn test_sub_rule_no_resolve_option() {
        // no-resolve is parsed as an option, not as part of the payload
        let rule = CompositeRule::new(
            "AND",
            "((IP-CIDR,10.0.0.0/8,no-resolve),(NETWORK,UDP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!rule.should_resolve_ip());

        let sess = Session {
            destination: SocksAddr::Ip("10.1.2.3:53".parse().unwrap()),
            network: Network::Udp,
            ..Default::default()
        };
        assert!(rule.apply(&sess));

        // without no-resolve, a nested IP rule makes the composite resolve
        let rule = CompositeRule::new(
            "OR",
            "((DOMAIN,example.com),(NOT,((IP-CIDR,10.0.0.0/8))))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(rule.should_resolve_ip());

        // domain-only composites never resolve
        let rule = CompositeRule::new(
            "AND",
            "((DOMAIN,example.com),(NETWORK,TCP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!rule.should_resolve_ip());
    }

    #[test]
    fn test_sub_rule_whitespace() {
        let rule = CompositeRule::new(
            "AND",
            "(( IP-CIDR , 10.0.0.0/8 , no-resolve ),( NETWORK, UDP ))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!rule.should_resolve_ip());
        assert!(rule.apply(&Session {
            destination: SocksAddr::Ip("10.1.2.3:53".parse().unwrap()),
            network: Network::Udp,
            ..Default::default()
        }));
    }

    #[test]
    fn test_src_ip_cidr_does_not_resolve() {
        let rule = CompositeRule::new(
            "AND",
            "((DOMAIN,example.com),(SRC-IP-CIDR,192.168.0.0/16))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(!rule.should_resolve_ip());
    }

    #[test]
    fn test_sub_rule_options() {
        // payloads containing commas are kept whole
        let rule = CompositeRule::new(
            "AND",
            r"((DOMAIN-REGEX,^a{1,3}\.example\.com$),(NETWORK,TCP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();
        assert!(rule.apply(&create_test_session(
            "aa.example.com",
            443,
            Network::Tcp
        )));

        // interface belongs on the composite rule, not on sub-rules
        assert!(
            CompositeRule::new(
                "AND",
                "((DOMAIN,example.com,interface=en0),(NETWORK,TCP))",
                "DIRECT",
                None,
                None,
                None,
            )
            .is_err()
        );

        // options still follow the per-rule-type rules
        assert!(
            CompositeRule::new(
                "AND",
                "((DOMAIN,example.com,no-resolve),(NETWORK,TCP))",
                "DIRECT",
                None,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn test_and_operator_both_match() {
        let rule = CompositeRule::new(
            "AND",
            "((DOMAIN,baidu.com),(NETWORK,UDP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();

        let sess = create_test_session("baidu.com", 53, Network::Udp);
        assert!(rule.apply(&sess));
        assert_eq!(rule.target(), "DIRECT");
        assert_eq!(rule.type_name(), "AND");
    }

    #[test]
    fn test_and_operator_one_fails() {
        let rule = CompositeRule::new(
            "AND",
            "((DOMAIN,baidu.com),(NETWORK,UDP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();

        // Wrong network
        let sess = create_test_session("baidu.com", 53, Network::Tcp);
        assert!(!rule.apply(&sess));

        // Wrong domain
        let sess = create_test_session("google.com", 53, Network::Udp);
        assert!(!rule.apply(&sess));
    }

    #[test]
    fn test_or_operator_one_matches() {
        let rule = CompositeRule::new(
            "OR",
            "((DOMAIN,baidu.com),(NETWORK,UDP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();

        // Domain matches, network doesn't
        let sess = create_test_session("baidu.com", 443, Network::Tcp);
        assert!(rule.apply(&sess));

        // Network matches, domain doesn't
        let sess = create_test_session("google.com", 53, Network::Udp);
        assert!(rule.apply(&sess));

        // Both match
        let sess = create_test_session("baidu.com", 53, Network::Udp);
        assert!(rule.apply(&sess));
    }

    #[test]
    fn test_or_operator_none_match() {
        let rule = CompositeRule::new(
            "OR",
            "((DOMAIN,baidu.com),(NETWORK,UDP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();

        let sess = create_test_session("google.com", 443, Network::Tcp);
        assert!(!rule.apply(&sess));
    }

    #[test]
    fn test_not_operator() {
        let rule = CompositeRule::new(
            "NOT",
            "((DOMAIN,baidu.com))",
            "PROXY",
            None,
            None,
            None,
        )
        .unwrap();

        // Should match everything except baidu.com
        let sess = create_test_session("google.com", 443, Network::Tcp);
        assert!(rule.apply(&sess));

        let sess = create_test_session("baidu.com", 443, Network::Tcp);
        assert!(!rule.apply(&sess));
    }

    #[test]
    fn test_not_operator_multiple_subrules_error() {
        let result = CompositeRule::new(
            "NOT",
            "((DOMAIN,baidu.com),(NETWORK,UDP))",
            "PROXY",
            None,
            None,
            None,
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exactly one sub-expression")
        );
    }

    #[test]
    fn test_nested_and_with_or() {
        // AND with nested OR: domain=example.com AND (network=UDP OR
        // network=TCP)
        let rule = CompositeRule::new(
            "AND",
            "((DOMAIN,example.com),(OR,((NETWORK,UDP),(NETWORK,TCP))))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();

        // Matches: correct domain + UDP
        let sess = create_test_session("example.com", 53, Network::Udp);
        assert!(rule.apply(&sess));

        // Matches: correct domain + TCP
        let sess = create_test_session("example.com", 443, Network::Tcp);
        assert!(rule.apply(&sess));

        // Doesn't match: wrong domain
        let sess = create_test_session("other.com", 53, Network::Udp);
        assert!(!rule.apply(&sess));
    }

    #[test]
    fn test_nested_or_with_and() {
        // OR with nested AND: (domain=a.com AND network=UDP) OR (domain=b.com
        // AND network=TCP)
        let rule = CompositeRule::new(
            "OR",
            "((AND,((DOMAIN,a.com),(NETWORK,UDP))),(AND,((DOMAIN,b.com),(NETWORK,\
             TCP))))",
            "PROXY",
            None,
            None,
            None,
        )
        .unwrap();

        // First AND matches
        let sess = create_test_session("a.com", 53, Network::Udp);
        assert!(rule.apply(&sess));

        // Second AND matches
        let sess = create_test_session("b.com", 443, Network::Tcp);
        assert!(rule.apply(&sess));

        // Neither matches: wrong combination
        let sess = create_test_session("a.com", 443, Network::Tcp);
        assert!(!rule.apply(&sess));

        let sess = create_test_session("b.com", 53, Network::Udp);
        assert!(!rule.apply(&sess));
    }

    #[test]
    fn test_nested_not_in_and() {
        // domain=example.com AND NOT(network=TCP)
        let rule = CompositeRule::new(
            "AND",
            "((DOMAIN,example.com),(NOT,((NETWORK,TCP))))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();

        // Matches: correct domain + UDP (not TCP)
        let sess = create_test_session("example.com", 53, Network::Udp);
        assert!(rule.apply(&sess));

        // Doesn't match: correct domain but TCP
        let sess = create_test_session("example.com", 443, Network::Tcp);
        assert!(!rule.apply(&sess));
    }

    #[test]
    fn test_multiple_rules_in_or() {
        let rule = CompositeRule::new(
            "OR",
            "((DOMAIN,a.com),(DOMAIN,b.com),(DOMAIN,c.com))",
            "PROXY",
            None,
            None,
            None,
        )
        .unwrap();

        assert!(rule.apply(&create_test_session("a.com", 443, Network::Tcp)));
        assert!(rule.apply(&create_test_session("b.com", 443, Network::Tcp)));
        assert!(rule.apply(&create_test_session("c.com", 443, Network::Tcp)));
        assert!(!rule.apply(&create_test_session("d.com", 443, Network::Tcp)));
    }

    #[test]
    fn test_domain_suffix_in_composite() {
        let rule = CompositeRule::new(
            "AND",
            "((DOMAIN-SUFFIX,example.com),(NETWORK,TCP))",
            "DIRECT",
            None,
            None,
            None,
        )
        .unwrap();

        assert!(rule.apply(&create_test_session(
            "test.example.com",
            443,
            Network::Tcp
        )));
        assert!(rule.apply(&create_test_session(
            "api.example.com",
            443,
            Network::Tcp
        )));
        assert!(!rule.apply(&create_test_session(
            "test.example.com",
            53,
            Network::Udp
        )));
        assert!(!rule.apply(&create_test_session("other.com", 443, Network::Tcp)));
    }

    #[test]
    fn test_domain_keyword_in_composite() {
        let rule = CompositeRule::new(
            "OR",
            "((DOMAIN-KEYWORD,google),(DOMAIN-KEYWORD,youtube))",
            "PROXY",
            None,
            None,
            None,
        )
        .unwrap();

        assert!(rule.apply(&create_test_session(
            "www.google.com",
            443,
            Network::Tcp
        )));
        assert!(rule.apply(&create_test_session("youtube.com", 443, Network::Tcp)));
        assert!(rule.apply(&create_test_session(
            "m.youtube.com",
            443,
            Network::Tcp
        )));
        assert!(!rule.apply(&create_test_session(
            "facebook.com",
            443,
            Network::Tcp
        )));
    }

    #[test]
    fn test_port_rules_in_composite() {
        let rule = CompositeRule::new(
            "AND",
            "((DST-PORT,443),(NETWORK,TCP))",
            "HTTPS-PROXY",
            None,
            None,
            None,
        )
        .unwrap();

        assert!(rule.apply(&create_test_session("example.com", 443, Network::Tcp)));
        assert!(!rule.apply(&create_test_session("example.com", 80, Network::Tcp)));
        assert!(!rule.apply(&create_test_session("example.com", 443, Network::Udp)));
    }

    #[test]
    fn test_error_missing_parentheses() {
        let result = CompositeRule::new(
            "AND",
            "(DOMAIN,baidu.com),(NETWORK,UDP)",
            "DIRECT",
            None,
            None,
            None,
        );

        assert!(result.is_err());
        // This will fail because it doesn't start with (( and end with ))
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parentheses") || err.contains("expected"));
    }

    #[test]
    fn test_error_unbalanced_parentheses_too_many_closing() {
        let result = CompositeRule::new(
            "AND",
            "((DOMAIN,baidu.com)),(NETWORK,UDP)))",
            "DIRECT",
            None,
            None,
            None,
        );

        assert!(result.is_err());
        // Extra closing paren at the end
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parentheses") || err.contains("expected"));
    }

    #[test]
    fn test_error_unbalanced_parentheses_unclosed() {
        let result = CompositeRule::new(
            "AND",
            "((DOMAIN,baidu.com),(NETWORK,UDP)",
            "DIRECT",
            None,
            None,
            None,
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unbalanced parentheses")
        );
    }

    #[test]
    fn test_error_invalid_operator() {
        let result = CompositeRule::new(
            "XOR",
            "((DOMAIN,baidu.com),(NETWORK,UDP))",
            "DIRECT",
            None,
            None,
            None,
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown composite operator")
        );
    }

    #[test]
    fn test_error_empty_expression() {
        let result = CompositeRule::new("AND", "()", "DIRECT", None, None, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_payload_and_display() {
        let expression = "((DOMAIN,baidu.com),(NETWORK,UDP))";
        let rule = CompositeRule::new("AND", expression, "DIRECT", None, None, None)
            .unwrap();

        assert_eq!(rule.payload(), expression);
        assert!(rule.to_string().contains("DIRECT"));
        assert!(rule.to_string().contains("and"));
    }

    #[test]
    fn test_deeply_nested_expression() {
        // (domain=a.com AND network=TCP) OR (domain=b.com AND network=UDP)
        let rule = CompositeRule::new(
            "OR",
            "((AND,((DOMAIN,a.com),(NETWORK,TCP))),(AND,((DOMAIN,b.com),(NETWORK,\
             UDP))))",
            "COMPLEX",
            None,
            None,
            None,
        )
        .unwrap();

        // Matches: a.com + TCP (first AND is true)
        let sess = create_test_session("a.com", 443, Network::Tcp);
        assert!(rule.apply(&sess));

        // Matches: b.com + UDP (second AND is true)
        let sess = create_test_session("b.com", 53, Network::Udp);
        assert!(rule.apply(&sess));

        // Doesn't match: wrong combinations
        let sess = create_test_session("a.com", 53, Network::Udp);
        assert!(!rule.apply(&sess));

        let sess = create_test_session("b.com", 443, Network::Tcp);
        assert!(!rule.apply(&sess));
    }
}
