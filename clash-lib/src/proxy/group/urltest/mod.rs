use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tracing::{debug, trace, warn};

use crate::{
    Error,
    app::{
        dispatcher::{BoxedInstrumentedDatagram, BoxedInstrumentedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, get_global_traffic_rate,
            providers::proxy_provider::ArcProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        group::{GroupProxyAPIResponse, selector::SelectorControl},
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

// ============================================================================
// Passive Failure Circuit Breaker Configuration Constants & State
// ============================================================================

/// Number of consecutive passive connection failures required to trip the
/// circuit breaker
const CIRCUIT_BREAKER_FAILURES_THRESHOLD: u32 = 3;

/// Circuit breaker cooldown period (30 seconds)
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(30);

/// Failure count expiration duration (60 seconds): if the interval between two
/// failures exceeds this duration without tripping, reset consecutive failure
/// count
const CIRCUIT_BREAKER_FAILURE_EXPIRY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct NodeFailureRecord {
    consecutive_failures: u32,
    last_failure: Instant,
    tripped_until: Option<Instant>,
}

#[derive(Debug, Default)]
struct CircuitBreakerState {
    nodes: HashMap<String, NodeFailureRecord>,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    fn record_success(&mut self, name: &str) {
        if let Some(record) = self.nodes.get_mut(name) {
            record.consecutive_failures = 0;
            record.tripped_until = None;
        }
    }

    /// Record a passive connection failure. Returns true if this node just
    /// tripped the circuit breaker (or tripped again during half-open
    /// trial).
    fn record_failure(&mut self, name: &str, now: Instant) -> bool {
        let record = self.nodes.entry(name.to_string()).or_insert_with(|| {
            NodeFailureRecord {
                consecutive_failures: 0,
                last_failure: now,
                tripped_until: None,
            }
        });

        let was_tripped = record.tripped_until.map(|t| now < t).unwrap_or(false);

        // If the last failure occurred long ago without tripping, reset count
        // to 1
        if !was_tripped
            && record.tripped_until.is_none()
            && now.duration_since(record.last_failure)
                > CIRCUIT_BREAKER_FAILURE_EXPIRY
        {
            record.consecutive_failures = 1;
        } else {
            record.consecutive_failures =
                record.consecutive_failures.saturating_add(1);
        }

        record.last_failure = now;

        if record.consecutive_failures >= CIRCUIT_BREAKER_FAILURES_THRESHOLD {
            record.tripped_until = Some(now + CIRCUIT_BREAKER_COOLDOWN);
            !was_tripped
        } else {
            false
        }
    }

    fn is_tripped(&self, name: &str, now: Instant) -> bool {
        self.nodes
            .get(name)
            .and_then(|record| record.tripped_until)
            .is_some_and(|tripped_until| now < tripped_until)
    }
}

// ============================================================================
// Adaptive Tolerance Configuration Constants
// ============================================================================

/// Number of consecutive rounds without switching before checking if tolerance
/// should be downgraded
const ADAPTIVE_ROUNDS_THRESHOLD: u32 = 12;

/// Downgrade condition: average (current_delay - min_delay) per round exceeds
/// this threshold (ms)
const ADAPTIVE_DIFF_THRESHOLD_MS: u64 = 20;

/// Downgraded tolerance (ms)
const ADAPTIVE_LOW_TOLERANCE: u16 = 20;

/// Traffic skip threshold: global traffic (including direct) > this value
/// (bytes/sec) skips switching round 250 KB/s = 256000 bytes/sec
const TRAFFIC_SKIP_THRESHOLD_BPS: u64 = 250 * 1024;

// ============================================================================
// Adaptive Tolerance State
// ============================================================================

/// Tracks runtime state for adaptive tolerance
struct AdaptiveState {
    /// Number of rounds since last node switch (incremented when a new
    /// check_round is detected)
    rounds_since_switch: u32,
    /// Per-round (current_delay - min_delay) difference (ms), used to compute
    /// average
    delay_diffs: VecDeque<u64>,
    /// Currently effective tolerance (ms), may be decreased by adaptive logic
    current_tolerance: u16,
    /// Last processed check_round value, used to detect a new round of
    /// healthcheck
    last_seen_round: u64,
}

impl AdaptiveState {
    fn new(base_tolerance: u16) -> Self {
        Self {
            rounds_since_switch: 0,
            delay_diffs: VecDeque::with_capacity(ADAPTIVE_ROUNDS_THRESHOLD as usize),
            current_tolerance: base_tolerance,
            last_seen_round: 0,
        }
    }

    /// Record delay difference for a round and check if tolerance downgrade
    /// should trigger. Returns true if a switch occurred (caller should
    /// reset state).
    fn record_round(&mut self, diff_ms: u64, switched: bool, base_tolerance: u16) {
        if switched {
            // Switched: reset state, restore base tolerance
            self.rounds_since_switch = 0;
            self.delay_diffs.clear();
            self.current_tolerance = base_tolerance;
            debug!(
                "adaptive: switch detected, tolerance reset to {}ms",
                base_tolerance
            );
            return;
        }

        self.rounds_since_switch = self.rounds_since_switch.saturating_add(1);
        self.delay_diffs.push_back(diff_ms);
        // Only keep data for the most recent ADAPTIVE_ROUNDS_THRESHOLD rounds
        if self.delay_diffs.len() > ADAPTIVE_ROUNDS_THRESHOLD as usize {
            self.delay_diffs.pop_front();
        }

        // Check downgrade condition: N consecutive rounds without switch and
        // avg diff > threshold
        if self.rounds_since_switch >= ADAPTIVE_ROUNDS_THRESHOLD
            && self.delay_diffs.len() >= ADAPTIVE_ROUNDS_THRESHOLD as usize
        {
            let avg_diff: f64 = self.delay_diffs.iter().sum::<u64>() as f64
                / self.delay_diffs.len() as f64;
            if avg_diff > ADAPTIVE_DIFF_THRESHOLD_MS as f64
                && self.current_tolerance > ADAPTIVE_LOW_TOLERANCE
            {
                self.current_tolerance = ADAPTIVE_LOW_TOLERANCE;
                debug!(
                    avg_diff_ms = avg_diff,
                    rounds = self.rounds_since_switch,
                    new_tolerance = ADAPTIVE_LOW_TOLERANCE,
                    "adaptive: tolerance lowered (no switch for {} rounds, avg \
                     diff {:.1}ms > {}ms)",
                    self.rounds_since_switch,
                    avg_diff,
                    ADAPTIVE_DIFF_THRESHOLD_MS
                );
            }
        }
    }
}

#[derive(Default)]
pub struct HandlerOptions {
    pub common_opts: HandlerCommonOptions,
    pub name: String,
    pub udp: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    /// Base tolerance (configured value, e.g. 30ms), restored upon switching
    base_tolerance: u16,
    providers: Vec<ArcProxyProvider>,
    proxy_manager: ProxyManager,
    fastest_proxy_index: AtomicU16,
    /// Adaptive tolerance runtime state.
    /// On PoisonError lock() returns Err; if let Ok silently falls back to
    /// base_tolerance (very rare, critical section is only arithmetic,
    /// fallback is safe).
    adaptive_state: Mutex<AdaptiveState>,
    /// Force switch flag set after manual healthcheck (via force_fastest() API)
    force_switch: AtomicBool,
    /// Manually locked node name (set when user manually selects a node via PUT
    /// /proxies/AUTO) Some(name) = locked to specified proxy name,
    /// fastest() returns it without auto-switching None = auto mode
    /// (default)
    manual_lock: Mutex<Option<String>>,
    /// Passive failure circuit breaker state
    circuit_breaker: Mutex<CircuitBreakerState>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrlTest")
            .field("name", &self.opts.name)
            .field("base_tolerance", &self.base_tolerance)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        tolerance: u16,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            base_tolerance: tolerance,
            providers,
            proxy_manager,
            fastest_proxy_index: AtomicU16::new(0),
            adaptive_state: Mutex::new(AdaptiveState::new(tolerance)),
            force_switch: AtomicBool::new(false),
            manual_lock: Mutex::new(None),
            circuit_breaker: Mutex::new(CircuitBreakerState::new()),
        }
    }

    pub(crate) fn record_failure(&self, name: &str) {
        if let Ok(mut cb) = self.circuit_breaker.lock() {
            let newly_tripped = cb.record_failure(name, Instant::now());
            if newly_tripped {
                warn!(
                    proxy = name,
                    group = self.name(),
                    cooldown_secs = CIRCUIT_BREAKER_COOLDOWN.as_secs(),
                    "circuit breaker tripped for proxy after consecutive failures"
                );
            }
        }
    }

    pub(crate) fn record_success(&self, name: &str) {
        if let Ok(mut cb) = self.circuit_breaker.lock() {
            cb.record_success(name);
        }
    }

    #[cfg(test)]
    pub(crate) fn is_tripped(&self, name: &str) -> bool {
        if let Ok(cb) = self.circuit_breaker.lock() {
            cb.is_tripped(name, Instant::now())
        } else {
            false
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    /// Select fastest node, including adaptive tolerance + traffic skip + force
    /// switch logic.
    ///
    /// # Switch Decision Priority
    /// 1. **Force switch** (force_switch=true): After manual healthcheck,
    ///    ignore all conditions and directly pick lowest latency.
    /// 2. **Traffic skip**: When proxy traffic > 250KB/s, skip switching round
    ///    (keep current node).
    /// 3. **Adaptive tolerance**:
    ///    - Base tolerance = 30ms (configured)
    ///    - 12 consecutive rounds without switch and avg delay diff > 20ms ->
    ///      drop to 20ms
    ///    - Restores to 30ms after a switch occurs
    /// 4. **Normal tolerance logic**: Current delay > (fastest delay +
    ///    tolerance) before switching.
    async fn fastest(&self, touch: bool) -> Option<AnyOutboundHandler> {
        let proxy_manager = self.proxy_manager.clone();

        let proxies = self.get_proxies(touch).await;
        if proxies.is_empty() {
            return None;
        }

        // --- Check manual lock (user manually selects node via PUT
        // /proxies/AUTO) --- When locked: return locked node without
        // auto-switching. If locked node was removed, clear lock and
        // resume auto selection.
        if let Ok(mut lock) = self.manual_lock.lock()
            && let Some(locked_name) = lock.clone()
        {
            if let Some((idx, proxy)) = proxies
                .iter()
                .enumerate()
                .find(|(_, p)| p.name() == locked_name)
            {
                self.fastest_proxy_index
                    .store(idx as u16, Ordering::Relaxed);
                self.force_switch.swap(false, Ordering::Relaxed);
                return Some(proxy.clone());
            } else {
                *lock = None;
                warn!(
                    locked_name = locked_name,
                    "manual_lock: node no longer exists, lock cleared"
                );
            }
        }

        let current_fastest_index = std::cmp::min(
            self.fastest_proxy_index
                .load(std::sync::atomic::Ordering::Relaxed),
            proxies.len() as u16 - 1,
        ) as usize;

        let now = Instant::now();
        let mut fastest_untripped = None;
        let mut fastest_any = None;
        let mut current_alive = false;
        let mut current_tripped = false;
        let mut current_delay = Duration::MAX;
        for (index, proxy) in proxies.iter().enumerate() {
            let (alive, delay) =
                proxy_manager.alive_and_last_delay(proxy.name()).await;
            let is_tripped = if let Ok(cb) = self.circuit_breaker.lock() {
                cb.is_tripped(proxy.name(), now)
            } else {
                false
            };

            if index == current_fastest_index {
                current_alive = alive;
                current_tripped = is_tripped;
            }
            if !alive {
                continue;
            }

            let delay = delay.unwrap_or(Duration::MAX);
            if index == current_fastest_index {
                current_delay = delay;
            }
            if match fastest_any {
                None => true,
                Some((_, fastest_delay)) => delay < fastest_delay,
            } {
                fastest_any = Some((index, delay));
            }

            if !is_tripped
                && match fastest_untripped {
                    None => true,
                    Some((_, fastest_delay)) => delay < fastest_delay,
                }
            {
                fastest_untripped = Some((index, delay));
            }
        }

        let fastest = fastest_untripped.or(fastest_any);

        // --- Check force switch flag (triggered by manual healthcheck) ---
        // Fix(2026-08-04): when every proxy failed the manual test (fastest is
        // None), do NOT force-switch to index 0 (possibly dead) - keep current.
        let force_switch = self.force_switch.swap(false, Ordering::Relaxed);
        if force_switch {
            if let Some((fastest_index, fastest_delay)) = fastest {
                warn!(
                    fastest = %proxies[fastest_index].name(),
                    delay = ?fastest_delay,
                    from = %proxies[current_fastest_index].name(),
                    "force_switch: manual test triggered, selecting fastest"
                );
                self.fastest_proxy_index
                    .store(fastest_index as u16, Ordering::Relaxed);
                // Reset adaptive state
                if let Ok(mut state) = self.adaptive_state.lock() {
                    state.rounds_since_switch = 0;
                    state.delay_diffs.clear();
                    state.current_tolerance = self.base_tolerance;
                }
                return Some(proxies[fastest_index].clone());
            } else {
                warn!(
                    from = %proxies[current_fastest_index].name(),
                    "force_switch: all proxies failed manual test, keeping current"
                );
                return Some(proxies[current_fastest_index].clone());
            }
        }

        let (fastest_index, fastest_delay) = fastest.unwrap_or((0, Duration::MAX));

        // --- Check global traffic rate to determine whether to skip switching
        // round ---
        let traffic_rate = get_global_traffic_rate();
        let traffic_skip = traffic_rate > TRAFFIC_SKIP_THRESHOLD_BPS;

        // --- Get current tolerance (may be reduced by adaptive logic) ---
        let effective_tolerance = if let Ok(state) = self.adaptive_state.lock() {
            state.current_tolerance
        } else {
            self.base_tolerance
        };

        // --- Detect whether this is a new round of healthcheck ---
        // Do not update last_seen_round when traffic is high; process this
        // round after traffic drops (avoids permanent loss of adaptive
        // data due to traffic skip)
        let current_round = proxy_manager
            .last_test_round_for(proxies.iter().map(|p| p.name()))
            .await;
        let is_new_round = if !traffic_skip && current_round > 0 {
            if let Ok(mut state) = self.adaptive_state.lock() {
                if current_round != state.last_seen_round {
                    state.last_seen_round = current_round;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // --- Tolerance switch decision ---
        let tolerance = Duration::from_millis(effective_tolerance as u64);
        let switch_threshold = fastest_delay
            .checked_add(tolerance)
            .unwrap_or(Duration::MAX);

        // Whether we should switch to fastest node (based on tolerance or node
        // dead/tripped)
        let current_effective_alive = current_alive && !current_tripped;
        let should_switch_by_tolerance =
            !current_effective_alive || current_delay > switch_threshold;

        // Skip switching when traffic is high (unless current node is dead or
        // tripped)
        let selected_index = if traffic_skip {
            if !current_effective_alive {
                fastest_index
            } else {
                current_fastest_index
            }
        } else if should_switch_by_tolerance {
            fastest_index
        } else {
            current_fastest_index
        };

        // --- Detect if switch occurred ---
        let switched = selected_index != current_fastest_index;

        // --- Reset adaptive state on switch (regardless of traffic_skip) ---
        // Emergency switch when traffic_skip + current dead/tripped also needs
        // reset, otherwise rounds_since_switch does not reset, causing
        // premature tolerance downgrade later.
        if switched && let Ok(mut state) = self.adaptive_state.lock() {
            state.rounds_since_switch = 0;
            state.delay_diffs.clear();
            state.current_tolerance = self.base_tolerance;
        }

        // --- Record adaptive state (only on new healthcheck round and not
        // skipped by traffic) ---
        if is_new_round && !traffic_skip {
            // Compute difference between current delay and lowest delay (ms)
            let diff_ms = if current_delay != Duration::MAX
                && fastest_delay != Duration::MAX
            {
                current_delay.saturating_sub(fastest_delay).as_millis() as u64
            } else {
                0
            };

            if let Ok(mut state) = self.adaptive_state.lock() {
                state.record_round(diff_ms, switched, self.base_tolerance);
            }
        }

        self.fastest_proxy_index
            .store(selected_index as u16, Ordering::Relaxed);

        let selected = &proxies[selected_index];
        let selected_delay = if selected_index == fastest_index {
            fastest_delay
        } else {
            current_delay
        };

        if traffic_skip && switched {
            // High traffic but current node died or tripped, emergency switch
            // to fastest node
            debug!(
                from = %proxies[current_fastest_index].name(),
                to = %selected.name(),
                delay = ?selected_delay,
                traffic_rate_kibps = traffic_rate / 1024,
                "traffic skip but current died or tripped, emergency switch to fastest"
            );
        } else if current_tripped && switched {
            warn!(
                from = %proxies[current_fastest_index].name(),
                to = %selected.name(),
                delay = ?selected_delay,
                "circuit breaker: current node tripped, bypassing to fastest available node"
            );
        } else if traffic_skip {
            trace!(
                traffic_rate_kibps = traffic_rate / 1024,
                current = %selected.name(),
                "traffic skip: >250KB/s, keeping current node"
            );
        } else if switched {
            debug!(
                from = %proxies[current_fastest_index].name(),
                to = %selected.name(),
                delay = ?selected_delay,
                tolerance_ms = effective_tolerance,
                "switched node"
            );
        }

        trace!(
            fastest = %selected.name(),
            delay = ?selected_delay,
            tolerance_ms = effective_tolerance,
            traffic_kibps = traffic_rate / 1024,
            "`{}` fastest",
            self.name(),
        );

        Some(selected.clone())
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::UrlTest
    }

    async fn support_udp(&self) -> bool {
        if self.opts.udp {
            return true;
        }
        match self.fastest(false).await {
            Some(fastest) => fastest.support_udp().await,
            None => false,
        }
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let fastest = self.fastest(false).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        match fastest.connect_stream(sess, resolver).await {
            Ok(s) => {
                self.record_success(fastest.name());
                s.append_to_chain(self.name()).await;
                Ok(s)
            }
            Err(e) => {
                self.record_failure(fastest.name());
                Err(e)
            }
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        let fastest = self.fastest(false).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        match fastest.connect_datagram(sess, resolver).await {
            Ok(d) => {
                self.record_success(fastest.name());
                d.append_to_chain(self.name()).await;
                Ok(d)
            }
            Err(e) => {
                self.record_failure(fastest.name());
                Err(e)
            }
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        match self.fastest(false).await {
            Some(fastest) => fastest.support_connector().await,
            None => ConnectorType::Tcp,
        }
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedStream> {
        let fastest = self.fastest(true).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        match fastest
            .connect_stream_with_connector(sess, resolver, connector)
            .await
        {
            Ok(s) => {
                self.record_success(fastest.name());
                s.append_to_chain(self.name()).await;
                Ok(s)
            }
            Err(e) => {
                self.record_failure(fastest.name());
                Err(e)
            }
        }
    }

    async fn connect_datagram_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        let fastest = self.fastest(true).await.ok_or_else(|| {
            io::Error::other(format!("no proxy found for {}", self.name()))
        })?;
        match fastest
            .connect_datagram_with_connector(sess, resolver, connector)
            .await
        {
            Ok(d) => {
                self.record_success(fastest.name());
                Ok(d)
            }
            Err(e) => {
                self.record_failure(fastest.name());
                Err(e)
            }
        }
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl GroupProxyAPIResponse for Handler {
    async fn get_proxies(&self) -> Vec<AnyOutboundHandler> {
        Handler::get_proxies(self, false).await
    }

    async fn get_active_proxy(&self) -> Option<AnyOutboundHandler> {
        self.fastest(false).await
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }

    /// Set force switch flag after manual healthcheck.
    /// Next fastest() call will ignore tolerance and directly choose lowest
    /// latency node.
    fn force_fastest(&self) {
        self.force_switch.store(true, Ordering::Relaxed);
        warn!("force_fastest: flag set, will switch on next fastest() call");
    }
}

#[async_trait]
impl SelectorControl for Handler {
    /// Manually select node (lock to specified node).
    /// PUT /proxies/AUTO {"name": "JP01"} invokes this method.
    /// Once locked, fastest() will always return this node without
    /// auto-switching. Pass empty string "" or non-existent
    /// "auto"/"default" to restore automatic mode.
    async fn select(&self, name: &str) -> Result<(), Error> {
        let proxies = self.get_proxies(false).await;
        if name.is_empty()
            || (!proxies.iter().any(|p| p.name() == name)
                && (name.eq_ignore_ascii_case("auto")
                    || name.eq_ignore_ascii_case("default")))
        {
            if let Ok(mut lock) = self.manual_lock.lock() {
                *lock = None;
                warn!("manual_lock: cleared, resuming auto mode");
                return Ok(());
            } else {
                return Err(Error::Operation("manual_lock poisoned".to_string()));
            }
        }

        if let Some((idx, proxy)) =
            proxies.iter().enumerate().find(|(_, p)| p.name() == name)
        {
            if let Ok(mut lock) = self.manual_lock.lock() {
                *lock = Some(proxy.name().to_string());
                self.fastest_proxy_index
                    .store(idx as u16, Ordering::Relaxed);
                warn!(node = name, "manual_lock: locked to node");
                Ok(())
            } else {
                Err(Error::Operation("manual_lock poisoned".to_string()))
            }
        } else {
            Err(Error::Operation(format!("proxy {name} not found")))
        }
    }

    #[cfg(test)]
    async fn current(&self) -> String {
        let proxies = self.get_proxies(false).await;
        let idx = self.fastest_proxy_index.load(Ordering::Relaxed) as usize;
        proxies
            .get(idx)
            .map(|p| p.name().to_string())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use crate::{
        app::remote_content_manager::ProxyManager,
        proxy::{
            AnyOutboundHandler,
            group::GroupProxyAPIResponse,
            mocks::MockDummyProxyProvider,
            utils::test_utils::noop::{NoopOutboundHandler, NoopResolver},
        },
    };

    #[tokio::test]
    async fn test_empty_provider_returns_none_active_proxy() {
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_name().return_const("provider1".to_owned());
        provider.expect_proxies().returning(Vec::new);

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "test".to_owned(),
                udp: true,
                ..Default::default()
            },
            0,
            vec![Arc::new(provider)],
            proxy_manager,
        );

        assert!(handler.get_active_proxy().await.is_none());
    }

    #[tokio::test]
    async fn test_tolerance_and_liveness_select_proxy() {
        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(50))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(40))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("a", true, Duration::from_millis(20))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        proxy_manager
            .report_delay("a", false, Duration::from_millis(20))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        proxy_manager
            .report_delay("b", false, Duration::from_millis(50))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");
    }

    #[tokio::test]
    async fn test_force_fastest_ignores_tolerance() {
        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        // a=100ms, b=110ms, tolerance=50ms -> normal: no switch, pick a
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(110))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            50,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        // Initially select a (lowest latency)
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // b becomes 95ms (diff 5ms < tolerance 50ms, normal: no switch)
        proxy_manager
            .report_delay("b", true, Duration::from_millis(95))
            .await;
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // Manual healthcheck triggers force switch -> choose b (now fastest)
        handler.force_fastest();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");
    }

    #[tokio::test]
    async fn test_manual_lock_by_name_and_unlock() {
        use crate::proxy::group::selector::SelectorControl;

        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        // a=100ms, b=50ms -> b is faster
        proxy_manager
            .report_delay("a", true, Duration::from_millis(100))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(50))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        // Initially b is chosen
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        // Manually lock to "a"
        handler.select("a").await.unwrap();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // force_fastest() should NOT clear manual_lock
        handler.force_fastest();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // Unlock by selecting empty string or "auto"
        handler.select("").await.unwrap();
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");
    }

    #[tokio::test]
    async fn test_circuit_breaker_bypasses_failing_node() {
        let proxies: Vec<AnyOutboundHandler> = vec![
            Arc::new(NoopOutboundHandler { name: "a".into() }),
            Arc::new(NoopOutboundHandler { name: "b".into() }),
        ];
        let mut provider = MockDummyProxyProvider::new();
        provider.expect_proxies().returning({
            let proxies = proxies.clone();
            move || proxies.clone()
        });

        let proxy_manager = ProxyManager::new(Arc::new(NoopResolver), None);
        // a=20ms, b=50ms -> a is faster
        proxy_manager
            .report_delay("a", true, Duration::from_millis(20))
            .await;
        proxy_manager
            .report_delay("b", true, Duration::from_millis(50))
            .await;
        let handler = super::Handler::new(
            super::HandlerOptions {
                name: "url-test".to_owned(),
                ..Default::default()
            },
            20,
            vec![Arc::new(provider)],
            proxy_manager.clone(),
        );

        // Initially "a" is chosen because it has lower delay
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");
        assert!(!handler.is_tripped("a"));

        // Simulate 2 passive failures on "a" - threshold is 3, so not tripped
        // yet
        handler.record_failure("a");
        assert!(!handler.is_tripped("a"));
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        handler.record_failure("a");
        assert!(!handler.is_tripped("a"));
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");

        // 3rd failure trips the circuit breaker on "a"
        handler.record_failure("a");
        assert!(handler.is_tripped("a"));

        // Now "a" is tripped, so fastest() bypasses "a" and selects "b"!
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "b");

        // If "b" also trips, circuit breaker falls back gracefully to fastest
        // available node
        handler.record_failure("b");
        handler.record_failure("b");
        handler.record_failure("b");
        assert!(handler.is_tripped("b"));
        // Both tripped: falls back to fastest available (a has 20ms < 50ms)
        // without returning None
        assert!(handler.get_active_proxy().await.is_some());

        // Once "a" succeeds (half-open recovery), it resets consecutive
        // failures
        handler.record_success("a");
        assert!(!handler.is_tripped("a"));
        assert_eq!(handler.get_active_proxy().await.unwrap().name(), "a");
    }
}
