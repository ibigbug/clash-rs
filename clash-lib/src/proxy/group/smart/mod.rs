//! Smart proxy group implementation
//!
//! This module provides an intelligent proxy group that automatically selects
//! the best proxy based on performance metrics, site preferences, traffic
//! patterns, and adaptive learning algorithms.
//!
//! - [`penalty`] - Proxy penalty system for performance tracking
//! - [`stats`] - Statistics collection and performance metrics
//! - [`state`] - Centralized state management

use async_trait::async_trait;
use std::{collections::HashSet, io, sync::Arc, time::Instant};
use tracing::{debug, info};

use crate::{
    app::{
        dispatcher::{BoxedInstrumentedDatagram, BoxedInstrumentedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ArcProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

pub mod penalty;
pub mod state;
pub mod stats;

use crate::proxy::group::GroupProxyAPIResponse;
pub use state::SmartState;

/// Error type for smart group failures
#[derive(Debug)]
enum SmartError {
    /// No proxy available in the smart group
    NoProxy,
    /// All proxies in the group failed to connect
    AllProxiesFailed(Vec<String>),
}

impl std::fmt::Display for SmartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProxy => write!(f, "no available proxy in smart group"),
            Self::AllProxiesFailed(names) => {
                write!(f, "all proxies failed: {names:?}")
            }
        }
    }
}

impl std::error::Error for SmartError {}

impl SmartError {
    /// Log the error using the tracing framework
    fn log_error(&self) {
        match self {
            Self::NoProxy => debug!("no available proxy in smart group"),
            Self::AllProxiesFailed(names) => {
                debug!("all proxies failed: {:?}", names)
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct HandlerOptions {
    /// Common proxy handler options
    pub common_opts: HandlerCommonOptions,
    /// Name of this proxy group
    pub name: String,
    /// Whether UDP is supported
    pub udp: bool,
    /// Maximum retries for failed connections
    pub max_retries: Option<u32>,
    /// Bandwidth consideration weight
    pub bandwidth_weight: Option<f64>,
}

/// Smart proxy group handler
pub struct Handler {
    /// Configuration options
    opts: HandlerOptions,
    /// Proxy providers for obtaining available proxies
    providers: Vec<ArcProxyProvider>,
    /// Proxy manager for health checks and metrics
    proxy_manager: ProxyManager,
    /// Centralized state management
    smart_state: Arc<tokio::sync::Mutex<SmartState>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmartHandler")
            .field("name", &self.opts.name)
            .field("udp", &self.opts.udp)
            .field("max_retries", &self.opts.max_retries)
            .finish()
    }
}

impl Handler {
    /// Create a new smart proxy group handler with persistence support
    pub async fn new_with_cache(
        opts: HandlerOptions,
        providers: Vec<ArcProxyProvider>,
        proxy_manager: ProxyManager,
        cache_store: crate::app::profile::ThreadSafeCacheFile,
    ) -> Self {
        let group_name = opts.name.clone();

        info!("{} attempting to load smart stats from cache", group_name);
        let stored_data: Option<state::SmartStateData> =
            cache_store.get_smart_stats(&group_name).await;

        if stored_data.is_some() {
            info!("{} successfully loaded smart stats from cache", group_name);
        } else {
            info!(
                "{} no smart stats found in cache, initializing new state",
                group_name
            );
        }

        let smart_state = SmartState::new_with_imported_data(stored_data);

        let handler = Self {
            opts,
            providers,
            proxy_manager,
            smart_state: Arc::new(tokio::sync::Mutex::new(smart_state)),
        };

        // Set up periodic persistence for smart_stats
        let cache_store_clone = cache_store;
        let group_name_clone = group_name;
        let state_clone = Arc::clone(&handler.smart_state);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let state_guard = state_clone.lock().await;
                let data_to_save = state_guard.export_data();
                drop(state_guard);

                cache_store_clone
                    .set_smart_stats(&group_name_clone, data_to_save)
                    .await;
            }
        });

        handler
    }

    /// Get all available proxies from providers
    ///
    /// # Arguments
    /// * `touch` - Whether to update provider statistics
    ///
    /// # Returns
    /// Vector of available proxy handlers
    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    /// Smart proxy selection considering all available metrics
    ///
    /// Implements comprehensive proxy selection algorithm that considers:
    /// - Site preferences and stickiness
    /// - Historical performance metrics
    /// - Traffic pattern analysis
    /// - Custom weight configuration
    /// - Penalty scores
    /// - Real-time health status
    ///
    /// # Arguments
    /// * `sess` - Session information for the connection
    /// * `excluded` - Set of proxy names to skip (already tried in this round)
    ///
    /// # Returns
    /// Selected proxy handler, or None if no suitable proxy available
    async fn pick_smart(
        &self,
        sess: &Session,
        excluded: &HashSet<String>,
    ) -> Option<AnyOutboundHandler> {
        let proxies = self.get_proxies(false).await;
        if proxies.is_empty() {
            debug!("{} no proxies available", self.name());
            return None;
        }

        let site = sess.destination.host();
        let dest_ip = sess.destination.ip().map(|ip| ip.to_string());

        debug!(
            "{} selecting proxy for site: {}, ip: {:?}, excluded: {:?}",
            self.name(),
            site,
            dest_ip,
            excluded
        );

        // Phase 1: Batch-fetch all proxy metrics from proxy_manager WITHOUT
        // holding the smart_state lock.  This avoids blocking other tasks
        // that need smart_state while we await async proxy_manager calls.
        struct ProxyMetrics {
            proxy: AnyOutboundHandler,
            name: String,
            delay: f64,
            packet_loss: f64,
            rtt: f64,
            alive: bool,
        }

        let mut metrics_list: Vec<ProxyMetrics> = Vec::new();
        for proxy in proxies {
            let name = proxy.name().to_string();
            if excluded.contains(&name) {
                continue;
            }

            let delay = self
                .proxy_manager
                .last_delay(&name)
                .await
                .map(|d| d.as_millis_f64())
                .unwrap_or(9999.0);
            let packet_loss = self
                .proxy_manager
                .get_packet_loss(&name)
                .await
                .unwrap_or(1.0);
            let rtt = self.proxy_manager.get_rtt(&name).await.unwrap_or(9999.0);
            let alive = self.proxy_manager.alive(&name).await;

            debug!(
                "{} proxy {} metrics - delay: {:.1}ms, loss: {:.1}%, rtt: {:.1}ms, \
                 alive: {}",
                self.name(),
                name,
                delay,
                packet_loss * 100.0,
                rtt,
                alive
            );

            metrics_list.push(ProxyMetrics {
                proxy,
                name,
                delay,
                packet_loss,
                rtt,
                alive,
            });
        }

        if metrics_list.is_empty() {
            debug!("{} no candidates after exclusion filter", self.name());
            return None;
        }

        // Phase 2: Briefly lock smart_state to get traffic_stats for the
        // enhanced session, then release for the site_tuning call.
        let mut enhanced_sess = sess.clone();
        {
            let state_guard = self.smart_state.lock().await;
            if let Some(traffic_stats) = state_guard.get_traffic_stats(sess) {
                enhanced_sess.traffic_stats = Some(traffic_stats);
                debug!(
                    "{} using traffic pattern analysis for session {}",
                    self.name(),
                    SmartState::generate_session_id(sess)
                );
            }
        }

        let site_tuning = self.proxy_manager.get_site_tuning(&enhanced_sess).await;

        // Use traffic-aware tuning parameters
        let delay_weight = site_tuning.delay_weight.unwrap_or(1.0);
        let packet_loss_weight = site_tuning.packet_loss_weight.unwrap_or(1000.0);
        let rtt_weight = site_tuning.rtt_weight.unwrap_or(1.0);
        let alive_penalty = site_tuning.alive_penalty.unwrap_or(5000.0);
        let bandwidth_weight = self.opts.bandwidth_weight.unwrap_or(0.0);

        debug!(
            "{} using tuning weights - delay: {:.2}, loss: {:.1}, rtt: {:.2}, \
             alive_penalty: {:.1}, bandwidth: {:.2}",
            self.name(),
            delay_weight,
            packet_loss_weight,
            rtt_weight,
            alive_penalty,
            bandwidth_weight
        );

        // Phase 3: Lock smart_state for pure in-memory scoring computation.
        let mut state_guard = self.smart_state.lock().await;
        state_guard.cleanup_stale();

        let mut candidates: Vec<(f64, AnyOutboundHandler, String)> = Vec::new();

        for m in metrics_list {
            let name = &m.name;

            // Get historical performance data
            let site_stats = state_guard.get_site_stats(name, &site).map(|s| {
                (
                    s.get_delay_score(),
                    s.success_rate(),
                    s.get_trend(),
                    s.latency_stability(),
                )
            });

            let ip_stats = dest_ip.as_ref().and_then(|ip| {
                state_guard.get_site_stats(name, ip).map(|s| {
                    (
                        s.get_delay_score(),
                        s.success_rate(),
                        s.get_trend(),
                        s.latency_stability(),
                    )
                })
            });

            if let Some((sd, sr, st, stability)) = site_stats {
                debug!(
                    "{} proxy {} site history - avg delay: {:.1}ms, success rate: \
                     {:.1}%, trend: {}, stability: {:.2}",
                    self.name(),
                    name,
                    sd,
                    sr * 100.0,
                    match st {
                        1 => "improving",
                        -1 => "degrading",
                        _ => "stable",
                    },
                    stability
                );
            }

            if let Some((id, ir, it, stability)) = ip_stats {
                debug!(
                    "{} proxy {} IP history - avg delay: {:.1}ms, success rate: \
                     {:.1}%, trend: {}, stability: {:.2}",
                    self.name(),
                    name,
                    id,
                    ir * 100.0,
                    match it {
                        1 => "improving",
                        -1 => "degrading",
                        _ => "stable",
                    },
                    stability
                );
            }

            // Apply penalty scores
            let penalty_score = state_guard
                .get_penalty(name)
                .map(|p| p.value())
                .unwrap_or(0.0);

            debug!(
                "{} proxy {} current penalty score: {:.1}",
                self.name(),
                name,
                penalty_score
            );

            // Calculate comprehensive score with trend consideration
            let site_delay = site_stats
                .map(|(d, r, t, _)| {
                    let trend_multiplier = match t {
                        1 => 0.9,  // Improving trend gets 10% bonus
                        -1 => 1.1, // Degrading trend gets 10% penalty
                        _ => 1.0,  // Stable trend no change
                    };
                    d * (2.0 - r) * trend_multiplier
                })
                .unwrap_or(m.delay);

            let ip_delay = ip_stats
                .map(|(d, r, t, _)| {
                    let trend_multiplier = match t {
                        1 => 0.9,  // Improving trend gets 10% bonus
                        -1 => 1.1, // Degrading trend gets 10% penalty
                        _ => 1.0,  // Stable trend no change
                    };
                    d * (2.0 - r) * trend_multiplier
                })
                .unwrap_or(m.delay);

            // Calculate stability penalty factor
            let stability_penalty = site_stats
                .map(|(_, _, _, s)| s * 0.5) // Each point of stability adds 0.5 to score
                .unwrap_or(0.0)
                + ip_stats.map(|(_, _, _, s)| s * 0.5).unwrap_or(0.0);

            let mut base_score = ((site_delay + ip_delay) / 2.0) * delay_weight
                + m.packet_loss * packet_loss_weight
                + m.rtt * rtt_weight
                + stability_penalty // Add stability penalty
                + if m.alive { 0.0 } else { alive_penalty }
                + penalty_score;

            // Apply bandwidth consideration if enabled
            if bandwidth_weight > 0.0 {
                // Simple heuristic: lower delay suggests better bandwidth
                let bandwidth_score = m.delay * 0.1;
                base_score += bandwidth_score * bandwidth_weight;
            }

            // TODO: custom weight multiplier
            let final_score = base_score;

            debug!(
                "{} proxy {} final score: {:.1}",
                self.name(),
                name,
                final_score
            );

            candidates.push((final_score, m.proxy, m.name));
        }

        // Sort by score (lower is better)
        candidates.sort_by(|a, b| {
            a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
        });

        if candidates.is_empty() {
            debug!("{} no candidates after filtering", self.name());
            return None;
        }

        // Select the best candidate (lowest score)
        let (_, selected_proxy, selected_name) = candidates[0].clone();

        debug!("{} selected proxy: {}", self.name(), selected_name);
        Some(selected_proxy)
    }

    /// Adaptive retry mechanism with exponential backoff and state updates
    ///
    /// Implements intelligent retry logic that:
    /// - Calculates optimal retry count based on site history
    /// - Uses exponential backoff for retry delays
    /// - Updates performance metrics and penalties
    /// - Tracks traffic patterns and site preferences
    /// - Avoids trying the same failed proxy repeatedly
    ///
    /// # Arguments
    /// * `sess` - Session information
    /// * `resolver` - DNS resolver for name resolution
    ///
    /// # Returns
    /// Successful connection stream or error
    async fn adaptive_retry(
        &self,
        sess: &Session,
        resolver: &ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let site = sess.destination.host();
        let dest_ip = sess.destination.ip().map(|ip| ip.to_string());
        let mut tried = HashSet::new();
        let mut retry_delay = 100; // Initial retry delay in ms

        // Start traffic tracking for this session
        {
            let mut state_guard = self.smart_state.lock().await;
            state_guard.start_traffic_tracking(sess);
            state_guard.record_request(sess);
        }

        // Calculate adaptive retry configuration
        let max_retries = self.calculate_max_retries(&site).await;
        let mut retries = 0;

        debug!(
            "{} starting adaptive retry for {}, max_retries: {}",
            self.name(),
            site,
            max_retries
        );

        while retries < max_retries {
            match self.pick_smart(sess, &tried).await {
                Some(proxy) => {
                    let name = proxy.name().to_string();
                    // pick_smart already excludes tried proxies, so this
                    // proxy is guaranteed to be new.  Record it now so the
                    // next iteration skips it even if scoring changes.
                    tried.insert(name.clone());

                    let start = Instant::now();
                    match proxy.connect_stream(sess, resolver.clone()).await {
                        Ok(stream) => {
                            let delay = start.elapsed().as_secs_f64() * 1000.0;

                            // Update success metrics
                            self.record_success(
                                &name,
                                &site,
                                dest_ip.as_deref(),
                                delay,
                                sess,
                            )
                            .await;

                            debug!(
                                "{} successfully connected to {} via {}, delay: \
                                 {:.2}ms, attempts: {}",
                                self.name(),
                                site,
                                &name,
                                delay,
                                retries + 1
                            );

                            stream.append_to_chain(self.name()).await;

                            return Ok(stream);
                        }
                        Err(e) => {
                            debug!(
                                "{} proxy {} connection failed: {}",
                                self.name(),
                                name,
                                e
                            );

                            // Update failure metrics
                            self.record_failure(
                                &name,
                                &site,
                                dest_ip.as_deref(),
                                sess,
                            )
                            .await;

                            // Exponential backoff with jitter
                            tokio::time::sleep(std::time::Duration::from_millis(
                                retry_delay,
                            ))
                            .await;
                            retry_delay = (retry_delay * 2).min(5000); // Cap at 5 seconds
                            retries += 1;

                            debug!(
                                "{} retry {} of {} for {}, next delay: {}ms",
                                self.name(),
                                retries,
                                max_retries,
                                site,
                                if retries < max_retries {
                                    retry_delay
                                } else {
                                    0
                                }
                            );
                            continue;
                        }
                    }
                }
                None => {
                    break; // No untried proxy available
                }
            }
        }

        if tried.is_empty() {
            let error = SmartError::NoProxy;
            error.log_error();
            Err(io::Error::other("no available proxy in smart group"))
        } else {
            let error = SmartError::AllProxiesFailed(tried.into_iter().collect());
            error.log_error();
            Err(io::Error::other(format!(
                "smart proxy selection failed after {retries} retries"
            )))
        }
    }

    /// Calculate optimal retry count based on site history
    async fn calculate_max_retries(&self, site: &str) -> u32 {
        let state_guard = self.smart_state.lock().await;

        // Collect site success rate data, filtering out proxies with no
        // history for this site (their success_rate defaults to 1.0 which
        // would skew the average optimistically without real evidence).
        let site_stats: Vec<_> = state_guard
            .site_stats
            .values()
            .filter_map(|stats| stats.get(site))
            .filter(|s| !s.success_history.is_empty())
            .collect();

        let avg_success_rate = if !site_stats.is_empty() {
            site_stats.iter().map(|s| s.success_rate()).sum::<f64>()
                / site_stats.len() as f64
        } else {
            1.0 // Optimistic default for new sites
        };

        drop(state_guard);

        // Use configured max retries or calculate based on site history
        let configured_max = self.opts.max_retries.unwrap_or(0);
        let calculated_max = (3.0 * (2.0 - avg_success_rate)).round() as u32;

        if configured_max > 0 {
            configured_max
        } else {
            calculated_max.clamp(2, 6) // Reasonable bounds
        }
    }

    /// Record successful connection metrics
    async fn record_success(
        &self,
        proxy_name: &str,
        site: &str,
        dest_ip: Option<&str>,
        delay: f64,
        _sess: &Session,
    ) {
        let mut state_guard = self.smart_state.lock().await;

        // Record connection result
        state_guard.record_connection_result(proxy_name, site, dest_ip, delay, true);
    }

    /// Record failed connection metrics
    async fn record_failure(
        &self,
        proxy_name: &str,
        site: &str,
        dest_ip: Option<&str>,
        sess: &Session,
    ) {
        let mut state_guard = self.smart_state.lock().await;

        // Record connection result - this will apply penalty and update stats
        state_guard
            .record_connection_result(proxy_name, site, dest_ip, 9999.0, false);

        // Record failed request
        state_guard.record_request(sess);
    }
}
impl DialWithConnector for Handler {}
#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Smart
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        debug!("{} starting smart proxy selection", self.name());
        match self.adaptive_retry(sess, &resolver).await {
            Ok(stream) => {
                debug!(
                    "{} successfully connected using smart selection",
                    self.name()
                );
                Ok(stream)
            }
            Err(e) => {
                debug!(
                    "{} failed to connect with all available proxies: {:?}",
                    self.name(),
                    e
                );
                Err(e)
            }
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        // For UDP we use the best proxy without retries for simplicity
        if let Some(proxy) = self.pick_smart(sess, &HashSet::new()).await {
            debug!("{} use proxy {} (smart)", self.name(), proxy.name());
            let s = proxy.connect_datagram(sess, resolver).await?;

            s.append_to_chain(self.name()).await;

            Ok(s)
        } else {
            Err(io::Error::other("no available proxy in smart group"))
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedStream> {
        if let Some(proxy) = self.pick_smart(sess, &HashSet::new()).await {
            debug!("{} use proxy {} (smart)", self.name(), proxy.name());
            proxy
                .connect_stream_with_connector(sess, resolver, connector)
                .await
        } else {
            Err(io::Error::other("no available proxy in smart group"))
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
        None
    }

    fn get_latency_test_url(&self) -> Option<String> {
        self.opts.common_opts.url.clone()
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}

#[cfg(feature = "shadowsocks")]
#[cfg(all(test, docker_test))]
mod tests {
    use super::*;
    use crate::{
        SystemResolver,
        profile::ThreadSafeCacheFile,
        proxy::{
            mocks::MockDummyProxyProvider,
            utils::test_utils::{
                Suite,
                consts::*,
                docker_runner::{
                    DockerTestRunner, DockerTestRunnerBuilder, alloc_docker_port,
                },
                run_test_suites_and_cleanup,
            },
        },
        tests::initialize,
    };
    use tempfile::tempdir;

    // Constants for the mock Shadowsocks server
    const PASSWORD: &str = "FzcLbKs2dY9mhL_smart";
    const CIPHER: &str = "aes-256-gcm";

    // Helper function to get a Shadowsocks Docker runner
    async fn get_ss_runner(port: u16) -> anyhow::Result<DockerTestRunner> {
        let host = format!("0.0.0.0:{}", port);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_SS_RUST)
            .port(port)
            .entrypoint(&["ssserver"])
            .cmd(&["-s", &host, "-m", CIPHER, "-k", PASSWORD, "-U"])
            .build()
            .await
    }

    #[tokio::test]
    async fn test_smart_group_smoke() -> anyhow::Result<()> {
        initialize();
        let ss_port = alloc_docker_port();

        let docker_runner = get_ss_runner(ss_port).await?;

        let ss_opts = crate::proxy::shadowsocks::outbound::HandlerOptions {
            name: "test-ss-for-smart".to_owned(),
            common_opts: Default::default(),
            server: docker_runner
                .container_ip()
                .unwrap_or(LOCAL_ADDR.to_owned()),
            port: ss_port,
            password: PASSWORD.to_owned(),
            cipher: CIPHER.to_owned(),
            plugin: Default::default(),
            udp: true,
        };
        let ss_handler: AnyOutboundHandler =
            Arc::new(crate::proxy::shadowsocks::outbound::Handler::new(ss_opts))
                as _;

        let mut provider = MockDummyProxyProvider::new();
        provider.expect_touch().returning(|| ());
        provider.expect_healthcheck().returning(|| ());
        provider
            .expect_proxies()
            .returning(move || vec![ss_handler.clone()]);
        let thread_safe_provider: ArcProxyProvider = Arc::new(provider);

        // Setup HandlerOptions for Smart group
        let smart_opts = super::HandlerOptions {
            common_opts: Default::default(),
            name: "test-smart-group".to_string(),
            udp: true,
            max_retries: Some(3),
            bandwidth_weight: Some(0.1),
        };

        let temp_dir_hdl = tempdir()?;
        let cache_path = temp_dir_hdl.path().join("smart_test_cache.db");
        let cache_store = ThreadSafeCacheFile::new(
            cache_path.to_str().expect("Cache path is not valid UTF-8"),
            false,
        );

        let resolver = SystemResolver::new(false).map_err(|e| {
            anyhow::anyhow!("Failed to create system resolver: {}", e)
        })?;
        let thread_safe_resolver = Arc::new(resolver);

        let proxy_manager = ProxyManager::new(thread_safe_resolver.clone(), None);

        let smart_handler_instance = super::Handler::new_with_cache(
            smart_opts,
            vec![thread_safe_provider],
            proxy_manager,
            cache_store,
        )
        .await;
        let any_smart_handler: AnyOutboundHandler = Arc::new(smart_handler_instance);

        run_test_suites_and_cleanup(any_smart_handler, docker_runner, Suite::all())
            .await
    }
}
