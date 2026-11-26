mod datagram;
mod stream;

use std::{collections::HashMap, io, sync::Arc, time::Duration};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use wind_core::{FlowContext, hooks::Protocol, rule::NetworkType};
use wind_naive::{NaiveOutbound, NaiveOutboundOpts, SocketPolicy};

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    session::Session,
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};

pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub udp: bool,
    pub request_timeout: Duration,
    pub wind: NaiveOutboundOpts,
}

struct CachedEngine {
    outbound: Arc<NaiveOutbound>,
    resolver_rule: Option<String>,
    // Late failures only invalidate this engine's DNS pin.
    check_dns: AtomicBool,
}

impl CachedEngine {
    fn dial_failed(&self) {
        self.check_dns.store(true, Ordering::Relaxed);
    }
}

type EngineCell = Mutex<Option<Arc<CachedEngine>>>;

/// Each policy owns a Cronet connection pool.
const MAX_POLICY_ENGINES: usize = 8;

/// Least recently used first. Active sessions keep evicted engines alive.
#[derive(Default)]
struct PolicyEngines(tokio::sync::Mutex<Vec<(SocketPolicy, Arc<EngineCell>)>>);

impl PolicyEngines {
    /// Return the active cell and any evicted cell for shutdown outside the
    /// lock.
    async fn claim(
        &self,
        policy: &SocketPolicy,
    ) -> (Arc<EngineCell>, Option<Arc<EngineCell>>) {
        let mut engines = self.0.lock().await;
        if let Some(position) =
            engines.iter().position(|(cached, _)| cached == policy)
        {
            let (cached, cell) = engines.remove(position);
            engines.push((cached, cell.clone()));
            return (cell, None);
        }
        let cell = Arc::new(EngineCell::default());
        engines.push((policy.clone(), cell.clone()));
        let evicted = if engines.len() > MAX_POLICY_ENGINES {
            Some(engines.remove(0).1)
        } else {
            None
        };
        (cell, evicted)
    }
}

// Cronet shutdown can block the thread that releases its last reference.
fn retire_engine<T: Send + 'static>(evicted: Option<T>) {
    if let Some(engine) = evicted {
        drop(tokio::task::spawn_blocking(move || drop(engine)));
    }
}

pub struct Handler {
    opts: HandlerOptions,
    outbound: EngineCell,
    policy_engines: PolicyEngines,
    cancel: CancellationToken,
    /// Guards the one-shot unpinned-server warning.
    dns_checked: std::sync::Once,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            outbound: EngineCell::default(),
            policy_engines: Default::default(),
            cancel: CancellationToken::new(),
            dns_checked: std::sync::Once::new(),
        }
    }

    async fn outbound(
        &self,
        sess: &Session,
        resolver: &ThreadSafeDNSResolver,
    ) -> io::Result<Arc<CachedEngine>> {
        #[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
        if let Some(policy) = session_socket_policy(sess)? {
            let (cell, evicted) = self.policy_engines.claim(&policy).await;
            retire_engine(evicted);
            return self.cached_engine(&cell, Some(policy), resolver).await;
        }
        #[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
        if sess.iface.is_some() || sess.so_mark.is_some() {
            static WARN_IGNORED_SOCKET_OPTIONS: std::sync::Once =
                std::sync::Once::new();
            WARN_IGNORED_SOCKET_OPTIONS.call_once(|| {
                tracing::warn!(
                    "Naive ignores session interface bindings and routing marks \
                     because Cronet manages its own sockets on this platform"
                );
            });
        }
        self.cached_engine(&self.outbound, None, resolver).await
    }

    async fn cached_engine(
        &self,
        cell: &EngineCell,
        policy: Option<SocketPolicy>,
        resolver: &ThreadSafeDNSResolver,
    ) -> io::Result<Arc<CachedEngine>> {
        // Each policy refreshes independently; active sessions retain their
        // engine.
        let mut cached = cell.lock().await;
        if let Some(engine) = cached.as_ref()
            && !engine.check_dns.load(Ordering::Relaxed)
        {
            return Ok(engine.clone());
        }
        let opts = self.wind_opts(resolver).await;
        let resolver_rule = opts.host_resolver_rules.clone();
        if let Some(engine) = cached.as_ref()
            && (resolver_rule.is_none() || resolver_rule == engine.resolver_rule)
        {
            // A temporary DNS failure must not discard a usable pin.
            engine.check_dns.store(false, Ordering::Relaxed);
            return Ok(engine.clone());
        }
        let outbound = match policy {
            Some(policy) => {
                NaiveOutbound::new_with_socket_policy(
                    opts,
                    policy,
                    self.opts.request_timeout,
                )
                .await
            }
            None => NaiveOutbound::new(opts).await,
        }
        .map_err(|error| io::Error::other(format!("Naive engine: {error}")))?;
        let engine = Arc::new(CachedEngine {
            outbound: Arc::new(outbound),
            resolver_rule,
            check_dns: AtomicBool::new(false),
        });
        retire_engine(cached.replace(engine.clone()));
        Ok(engine)
    }

    /// Build the engine options, pinning the server to a Clash-resolved
    /// address. The pin lasts for the engine's lifetime.
    async fn wind_opts(
        &self,
        resolver: &ThreadSafeDNSResolver,
    ) -> NaiveOutboundOpts {
        let mut wind = self.opts.wind.clone();
        if wind.host_resolver_rules.is_some()
            || self.opts.server.parse::<std::net::IpAddr>().is_ok()
        {
            return wind;
        }

        // Leave time for engine startup after a slow lookup.
        let timeout = (self.opts.request_timeout / 2)
            .min(Duration::from_secs(3))
            .max(Duration::from_millis(100));
        match resolve_server_rule(&self.opts.server, resolver, timeout).await {
            Some(rule) => {
                tracing::debug!(
                    "Naive pins server {} with {rule}",
                    self.opts.server
                );
                wind.host_resolver_rules = Some(rule);
            }
            None => self.warn_unpinned_server(),
        }
        wind
    }

    fn warn_unpinned_server(&self) {
        self.dns_checked.call_once(|| {
            tracing::warn!(
                "Naive could not pin server {} to an address resolved by Clash; \
                 Cronet will resolve the name itself and may receive a fake IP \
                 under TUN + fake-ip. Configure dns.proxy-server-nameserver or add \
                 {} to dns.fake-ip-filter.",
                self.opts.server,
                self.opts.server
            );
        });
    }
}

/// Resolve `server` once into a `HostResolverRules` rule.
///
/// IP literals, failed lookups, and fake-IP answers produce `None`.
async fn resolve_server_rule(
    server: &str,
    resolver: &ThreadSafeDNSResolver,
    timeout: Duration,
) -> Option<String> {
    if server.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let ips = tokio::time::timeout(timeout, resolver.resolve_all(server, false))
        .await
        .ok()?
        .ok()?;
    // A pinned IPv6 address has no Happy Eyeballs fallback.
    let ip = ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())?
        .to_owned();

    if resolver.is_fake_ip(ip).await {
        return None;
    }

    Some(host_resolver_rule(server, ip))
}

fn host_resolver_rule(host: &str, ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => {
            format!("MAP {} {ip}", host.to_ascii_lowercase())
        }
        std::net::IpAddr::V6(ip) => {
            format!("MAP {} [{ip}]", host.to_ascii_lowercase())
        }
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
fn session_socket_policy(sess: &Session) -> io::Result<Option<SocketPolicy>> {
    #[cfg(target_os = "linux")]
    {
        if sess.iface.is_none() && sess.so_mark.is_none() {
            return Ok(None);
        }
        Ok(Some(SocketPolicy {
            interface: sess.iface.as_ref().map(socket_interface),
            so_mark: sess.so_mark.map(u32::from),
        }))
    }

    #[cfg(any(target_vendor = "apple", windows))]
    {
        if sess.so_mark.is_some() {
            static WARN_IGNORED_SO_MARK: std::sync::Once = std::sync::Once::new();
            WARN_IGNORED_SO_MARK.call_once(|| {
                tracing::warn!(
                    "Naive ignores the session routing mark on {} because SO_MARK \
                     is Linux-only and has no effect on this platform",
                    std::env::consts::OS,
                );
            });
        }
        match &sess.iface {
            Some(interface) => Ok(Some(SocketPolicy {
                interface: Some(socket_interface(interface)),
                so_mark: None,
            })),
            None if sess.typ == crate::session::Type::Tun => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Naive TUN session has no outbound interface to bind; refusing to \
                 follow the default route back into the TUN",
            )),
            None => Ok(None),
        }
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
fn socket_interface(
    interface: &crate::app::net::OutboundInterface,
) -> wind_naive::SocketInterface {
    wind_naive::SocketInterface {
        name: interface.name.clone(),
        index: interface.index,
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Naive")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Naive
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let deadline = tokio::time::sleep(self.opts.request_timeout).deadline();
        let timed_out =
            |_| io::Error::new(io::ErrorKind::TimedOut, "Naive CONNECT timed out");
        let engine =
            tokio::time::timeout_at(deadline, self.outbound(sess, &resolver))
                .await
                .map_err(timed_out)??;
        let io = tokio::time::timeout_at(
            deadline,
            stream::connect(
                engine.outbound.clone(),
                tcp_flow(sess),
                self.cancel.child_token(),
            ),
        )
        .await
        .map_err(timed_out)
        .flatten()
        .inspect_err(|_| engine.dial_failed())?;
        let stream = InstrumentedStreamWrapper::new(io);
        stream.append_to_chain(self.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        if !self.opts.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Naive UDP-over-TCP is disabled",
            ));
        }
        let deadline = tokio::time::sleep(self.opts.request_timeout).deadline();
        let outbound =
            tokio::time::timeout_at(deadline, self.outbound(sess, &resolver))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Naive engine initialization timed out",
                    )
                })??;
        let datagram = InstrumentedDatagramWrapper::new(datagram::Datagram::new(
            outbound,
            sess,
            deadline,
            self.cancel.child_token(),
        ));
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        // Do not expose authentication material or native library paths.
        let mut map: HashMap<String, Box<dyn ErasedSerialize + Send>> =
            HashMap::new();
        map.insert("server".into(), Box::new(self.opts.server.clone()));
        map.insert("port".into(), Box::new(self.opts.port));
        map.insert("quic".into(), Box::new(self.opts.wind.quic_enabled));
        map.insert("udp".into(), Box::new(self.opts.udp));
        map
    }
}

fn tcp_flow(sess: &Session) -> FlowContext {
    FlowContext {
        target: sess.destination.clone().into(),
        network: NetworkType::Tcp,
        source: Some(sess.source),
        inbound_tag: "naive".into(),
        protocol: Protocol::Naive,
        user: None,
        inbound_port: None,
        inbound_type: None,
    }
}

#[cfg(test)]
mod timeout_tests;

#[cfg(all(test, any(target_os = "linux", target_vendor = "apple", windows)))]
mod tests {
    use super::*;
    use crate::app::net::OutboundInterface;

    fn interface(name: &str, index: u32) -> OutboundInterface {
        OutboundInterface {
            name: name.into(),
            addr_v4: Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            netmask_v4: None,
            broadcast_v4: None,
            addr_v6: None,
            netmask_v6: None,
            broadcast_v6: None,
            index,
            mac_addr: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_policy_carries_the_interface_and_mark() {
        let session = Session {
            iface: Some(interface("eth0", 2)),
            so_mark: Some(42.into()),
            ..Default::default()
        };
        let policy = session_socket_policy(&session).unwrap().unwrap();
        let iface = policy.interface.unwrap();
        assert_eq!(iface.name, "eth0");
        assert_eq!(iface.index, 2);
        assert_eq!(policy.so_mark, Some(42));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_policy_is_absent_without_socket_options() {
        assert!(
            session_socket_policy(&Session::default())
                .unwrap()
                .is_none()
        );
    }

    #[cfg(any(target_vendor = "apple", windows))]
    #[test]
    fn apple_and_windows_policy_use_the_interface_index_only() {
        let session = Session {
            iface: Some(interface("en0", 4)),
            so_mark: Some(42.into()),
            ..Default::default()
        };
        let policy = session_socket_policy(&session).unwrap().unwrap();
        let iface = policy.interface.unwrap();
        assert_eq!(iface.name, "en0");
        assert_eq!(iface.index, 4);
        assert_eq!(policy.so_mark, None);
    }

    #[cfg(any(target_vendor = "apple", windows))]
    #[test]
    fn apple_and_windows_policy_ignore_a_mark_without_an_interface() {
        let session = Session {
            so_mark: Some(42.into()),
            ..Default::default()
        };
        assert!(session_socket_policy(&session).unwrap().is_none());
    }

    #[cfg(any(target_vendor = "apple", windows))]
    #[test]
    fn apple_and_windows_tun_session_without_an_interface_is_rejected() {
        use crate::session::Type;

        let session = Session {
            typ: Type::Tun,
            ..Default::default()
        };
        let error = session_socket_policy(&session).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;
    use crate::app::dns::MockClashResolver;

    fn resolver(mock: MockClashResolver) -> ThreadSafeDNSResolver {
        Arc::new(mock)
    }

    fn handler(server: &str) -> Handler {
        Handler::new(HandlerOptions {
            name: "test".into(),
            server: server.into(),
            port: 443,
            udp: true,
            request_timeout: Duration::from_secs(1),
            wind: NaiveOutboundOpts {
                server_address: format!("{server}:443"),
                server_name: Some(format!("{server}:443")),
                ..Default::default()
            },
        })
    }

    #[tokio::test]
    async fn wind_opts_pins_the_resolved_address() {
        let mut mock = MockClashResolver::new();
        mock.expect_resolve_all()
            .returning(|_, _| Ok(vec!["203.0.113.7".parse().unwrap()]));
        mock.expect_is_fake_ip().returning(|_| false);

        let opts = handler("proxy.example").wind_opts(&resolver(mock)).await;
        assert_eq!(
            opts.host_resolver_rules.as_deref(),
            Some("MAP proxy.example 203.0.113.7")
        );
    }

    #[tokio::test]
    async fn wind_opts_keeps_a_preconfigured_rule() {
        let mut handler = handler("proxy.example");
        handler.opts.wind.host_resolver_rules =
            Some("MAP proxy.example 203.0.113.9".into());

        // No expectations: the preconfigured rule must skip resolution.
        let opts = handler.wind_opts(&resolver(MockClashResolver::new())).await;
        assert_eq!(
            opts.host_resolver_rules.as_deref(),
            Some("MAP proxy.example 203.0.113.9")
        );
    }

    #[tokio::test]
    async fn wind_opts_leaves_ip_literals_alone() {
        // No expectations: an IP literal needs no lookup.
        let opts = handler("203.0.113.7")
            .wind_opts(&resolver(MockClashResolver::new()))
            .await;
        assert!(opts.host_resolver_rules.is_none());
    }

    #[test]
    fn rules_format_ipv4_and_ipv6() {
        assert_eq!(
            host_resolver_rule("Proxy.Example", "203.0.113.7".parse().unwrap()),
            "MAP proxy.example 203.0.113.7"
        );
        assert_eq!(
            host_resolver_rule("proxy.example", "2001:db8::7".parse().unwrap()),
            "MAP proxy.example [2001:db8::7]"
        );
    }

    #[tokio::test]
    async fn server_ip_literal_needs_no_lookup() {
        // No expectations: any lookup panics.
        let mock = MockClashResolver::new();
        assert!(
            resolve_server_rule(
                "203.0.113.7",
                &resolver(mock),
                Duration::from_secs(1),
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn ipv4_answer_is_pinned_over_ipv6() {
        let mut mock = MockClashResolver::new();
        mock.expect_resolve_all().returning(|_, _| {
            Ok(vec![
                "2001:db8::7".parse().unwrap(),
                "203.0.113.7".parse().unwrap(),
            ])
        });
        mock.expect_is_fake_ip().returning(|_| false);

        let rule = resolve_server_rule(
            "proxy.example",
            &resolver(mock),
            Duration::from_secs(1),
        )
        .await
        .expect("real address must be pinned");
        assert_eq!(rule, "MAP proxy.example 203.0.113.7");
    }

    #[tokio::test]
    async fn ipv6_only_answer_is_pinned_in_brackets() {
        let mut mock = MockClashResolver::new();
        mock.expect_resolve_all()
            .returning(|_, _| Ok(vec!["2001:db8::7".parse().unwrap()]));
        mock.expect_is_fake_ip().returning(|_| false);

        let rule = resolve_server_rule(
            "proxy.example",
            &resolver(mock),
            Duration::from_secs(1),
        )
        .await
        .expect("real address must be pinned");
        assert_eq!(rule, "MAP proxy.example [2001:db8::7]");
    }

    #[tokio::test]
    async fn fake_ip_is_not_pinned() {
        let mut mock = MockClashResolver::new();
        mock.expect_resolve_all()
            .returning(|_, _| Ok(vec!["198.18.0.7".parse().unwrap()]));
        mock.expect_is_fake_ip().returning(|_| true);

        assert!(
            resolve_server_rule(
                "proxy.example",
                &resolver(mock),
                Duration::from_secs(1),
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn empty_or_failed_lookup_is_not_pinned() {
        let mut mock = MockClashResolver::new();
        mock.expect_resolve_all().returning(|_, _| Ok(vec![]));
        assert!(
            resolve_server_rule(
                "proxy.example",
                &resolver(mock),
                Duration::from_secs(1),
            )
            .await
            .is_none()
        );

        let mut mock = MockClashResolver::new();
        mock.expect_resolve_all()
            .returning(|_, _| Err(anyhow::anyhow!("synthetic failure")));
        assert!(
            resolve_server_rule(
                "proxy.example",
                &resolver(mock),
                Duration::from_secs(1),
            )
            .await
            .is_none()
        );
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    /// Synthetic policies: the cache compares keys and never dials, so no
    /// engine (and no Cronet library) is built by these tests.
    fn policy(index: u32) -> SocketPolicy {
        SocketPolicy {
            interface: Some(wind_naive::SocketInterface {
                name: format!("eth{index}"),
                index,
            }),
            so_mark: None,
        }
    }

    async fn fill(engines: &PolicyEngines) -> Vec<Arc<EngineCell>> {
        let mut cells = Vec::new();
        for index in 0..MAX_POLICY_ENGINES as u32 {
            let (cell, evicted) = engines.claim(&policy(index)).await;
            assert!(evicted.is_none(), "the cache evicted below its bound");
            cells.push(cell);
        }
        cells
    }

    #[tokio::test]
    async fn policy_engines_evict_the_least_recently_used_entry() {
        let engines = PolicyEngines::default();
        let cells = fill(&engines).await;

        let (_, evicted) = engines.claim(&policy(MAX_POLICY_ENGINES as u32)).await;
        let evicted = evicted.expect("one more policy must evict a stale entry");
        assert!(Arc::ptr_eq(&evicted, &cells[0]));
        assert_eq!(engines.0.lock().await.len(), MAX_POLICY_ENGINES);
    }

    #[tokio::test]
    async fn policy_engines_refresh_a_reused_policy() {
        let engines = PolicyEngines::default();
        let cells = fill(&engines).await;

        // Reaching for a cached policy neither evicts nor rebuilds it.
        let (reused, evicted) = engines.claim(&policy(0)).await;
        assert!(evicted.is_none());
        assert!(Arc::ptr_eq(&reused, &cells[0]));

        // The policy it displaced is now the oldest and goes out first.
        let (_, evicted) = engines.claim(&policy(MAX_POLICY_ENGINES as u32)).await;
        let evicted = evicted.expect("one more policy must evict a stale entry");
        assert!(Arc::ptr_eq(&evicted, &cells[1]));
        assert_eq!(engines.0.lock().await.len(), MAX_POLICY_ENGINES);
    }
}
