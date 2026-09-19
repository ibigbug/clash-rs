use async_trait::async_trait;

use std::fmt::Debug;

use hickory_proto::op;
use std::sync::Arc;

#[cfg(test)]
use mockall::automock;

pub mod config;
mod dhcp;
mod dns_client;
mod fakeip;
mod filters;
mod helper;
pub mod resolver;
mod rule_dispatch;
mod runtime;
mod server;

pub use config::{Config, EdnsClientSubnet};

pub use filters::PendingMmdb;
pub use rule_dispatch::{PendingOutboundManager, PendingRouter, RuleDispatch};

pub use resolver::{EnhancedResolver, SystemResolver, new as new_resolver};

pub use server::DnsRunner;
#[cfg(feature = "tun")]
pub use server::exchange_with_resolver;

#[async_trait]
pub trait Client: Sync + Send + Debug {
    /// used to identify the client for logging
    fn id(&self) -> String;
    async fn exchange(&self, msg: &op::Message) -> anyhow::Result<op::Message>;
}

type ThreadSafeDNSClient = Arc<dyn Client>;

pub enum ResolverKind {
    Clash,
    System,
}

pub type ThreadSafeDNSResolver = Arc<dyn ClashResolver>;

/// A implementation of "anti-poisoning" Resolver
/// it can hold multiple clients in different protocols
/// each client can also hold a "default_resolver"
/// in case they need to resolve DoH in domain names etc.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait ClashResolver: Sync + Send {
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>>;
    async fn resolve_v4(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>>;
    async fn resolve_v6(
        &self,
        host: &str,
        enhanced: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>>;

    async fn cached_for(&self, ip: std::net::IpAddr) -> Option<String>;

    /// Used for DNS Server
    async fn exchange(&self, message: &op::Message) -> anyhow::Result<op::Message>;

    /// Only used for look up fake IP
    async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Option<String>;
    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool;
    fn fake_ip_enabled(&self) -> bool;

    fn ipv6(&self) -> bool;
    fn set_ipv6(&self, enable: bool);

    fn kind(&self) -> ResolverKind;

    /// Clear all in-memory caches (DNS response cache, reverse lookup cache).
    /// Called under memory pressure to free RSS.  Default no-op for resolvers
    /// that don't cache (e.g. SystemResolver).
    async fn clear_cache(&self) {}
}

/// Returns the IP address if `host` is a valid IP literal, otherwise `None`.
/// Used by resolvers to short-circuit DNS resolution for IP literals.
pub(crate) fn parse_ip_literal(host: &str) -> Option<std::net::IpAddr> {
    host.parse().ok()
}
