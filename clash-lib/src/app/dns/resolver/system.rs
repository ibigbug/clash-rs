use std::sync::atomic::AtomicBool;

use crate::{
    Error,
    app::dns::{ClashResolver, ResolverKind, parse_ip_literal},
};
use async_trait::async_trait;
use rand::seq::IteratorRandom;
use tracing::{debug, warn};

pub struct SystemResolver {
    ipv6: AtomicBool,
}

/// SystemResolver is a resolver that uses libc getaddrinfo to resolve
/// hostnames.
impl SystemResolver {
    pub fn new(ipv6: bool) -> anyhow::Result<Self> {
        debug!("creating system resolver with ipv6={}", ipv6);
        Ok(Self {
            ipv6: AtomicBool::new(ipv6),
        })
    }
}

#[async_trait]
impl ClashResolver for SystemResolver {
    async fn resolve(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }

        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|x| {
                if self.ipv6() || x.is_ipv4() {
                    Some(x.ip())
                } else {
                    warn!(
                        "resolved v6 address {} for {} but ipv6 is disabled",
                        x.ip(),
                        host
                    );
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        if let Some(std::net::IpAddr::V4(ip)) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }
        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        if !self.ipv6() {
            return Err(Error::DNSError("ipv6 disabled".into()).into());
        }
        if let Some(std::net::IpAddr::V6(ip)) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }
        let response = tokio::net::lookup_host(format!("{host}:0"))
            .await?
            .filter_map(|x| match x.ip() {
                std::net::IpAddr::V6(ip) => Some(ip),
                _ => None,
            })
            .collect::<Vec<_>>();
        Ok(response.into_iter().choose(&mut rand::rng()))
    }

    async fn cached_for(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn exchange(
        &self,
        _: &hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        Err(anyhow::anyhow!(
            "system resolver does not support advanced dns features, please enable \
             the dns server in your config"
        ))
    }

    fn ipv6(&self) -> bool {
        self.ipv6.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_ipv6(&self, val: bool) {
        self.ipv6.store(val, std::sync::atomic::Ordering::Relaxed);
    }

    fn kind(&self) -> ResolverKind {
        ResolverKind::System
    }

    fn fake_ip_enabled(&self) -> bool {
        false
    }

    async fn is_fake_ip(&self, _: std::net::IpAddr) -> bool {
        false
    }

    async fn reverse_lookup(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::app::dns::{ClashResolver, resolver::SystemResolver};

    #[tokio::test]
    async fn test_system_resolver_default_config() {
        let resolver = SystemResolver::new(false).unwrap();
        let response = resolver.resolve("www.google.com", false).await.unwrap();
        assert!(response.is_some());
    }
}
