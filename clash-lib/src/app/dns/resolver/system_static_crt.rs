use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use rand::seq::IteratorRandom;

use crate::app::dns::{ClashResolver, ResolverKind, parse_ip_literal};

pub struct SystemResolver {
    inner: TokioResolver,
    ipv6: AtomicBool,
}

/// Bug in libc, use tokio impl instead: https://sourceware.org/bugzilla/show_bug.cgi?id=10652
impl SystemResolver {
    pub fn new(ipv6: bool) -> anyhow::Result<Self> {
        Ok(Self {
            inner: TokioResolver::builder_tokio()?.build()?,
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

        let response = self.inner.lookup_ip(host).await?;
        Ok(response
            .iter()
            .filter(|x| self.ipv6() || x.is_ipv4())
            .choose(&mut rand::rng()))
    }

    async fn resolve_v4(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
        if let Some(std::net::IpAddr::V4(ip)) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }
        let response = self.inner.ipv4_lookup(host).await?;
        Ok(response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                hickory_proto::rr::RData::A(a) => Some(a.0),
                _ => None,
            })
            .choose(&mut rand::rng()))
    }

    async fn resolve_v6(
        &self,
        host: &str,
        _: bool,
    ) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
        if let Some(std::net::IpAddr::V6(ip)) = parse_ip_literal(host) {
            return Ok(Some(ip));
        }
        let response = self.inner.ipv6_lookup(host).await?;
        Ok(response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                hickory_proto::rr::RData::AAAA(aaaa) => Some(aaaa.0),
                _ => None,
            })
            .choose(&mut rand::rng()))
    }

    async fn cached_for(&self, _: std::net::IpAddr) -> Option<String> {
        None
    }

    async fn exchange(
        &self,
        _: &hickory_proto::op::Message,
    ) -> anyhow::Result<hickory_proto::op::Message> {
        Err(anyhow::anyhow!("unsupported"))
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
    use crate::app::dns::{ClashResolver, SystemResolver};

    #[tokio::test]
    async fn test_system_resolver_default_config() {
        let resolver = SystemResolver::new(false).unwrap();
        let response = resolver.resolve("www.google.com", false).await.unwrap();
        assert!(response.is_some());
    }
}
