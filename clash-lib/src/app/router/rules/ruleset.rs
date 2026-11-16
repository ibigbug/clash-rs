use crate::{
    app::{
        remote_content_manager::providers::rule_provider::{
            RuleSetBehavior, ThreadSafeRuleProvider,
        },
        router::rules::RuleMatcher,
    },
    session::Session,
};

#[derive(Clone)]
pub struct RuleSet {
    pub rule_set: String,
    pub target: String,
    pub rule_provider: ThreadSafeRuleProvider,
    pub no_resolve: bool,
}

impl RuleSet {
    pub fn new(
        rule_set: String,
        target: String,
        rule_provider: ThreadSafeRuleProvider,
        no_resolve: bool,
    ) -> Self {
        Self {
            rule_set,
            target,
            rule_provider,
            no_resolve,
        }
    }
}

impl std::fmt::Display for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} rule-set {}", self.target, self.rule_set)
    }
}

impl RuleMatcher for RuleSet {
    fn apply(&self, sess: &Session) -> bool {
        self.rule_provider.search(sess)
    }

    fn target(&self) -> &str {
        self.target.as_str()
    }

    fn payload(&self) -> String {
        self.rule_set.clone()
    }

    fn type_name(&self) -> &str {
        "RuleSet"
    }

    /// Resolve the destination domain before matching unless `no-resolve` is
    /// set. Domain rule-sets never match on IPs, so they never
    /// need resolution.
    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
            && !matches!(self.rule_provider.behavior(), RuleSetBehavior::Domain)
    }
}
