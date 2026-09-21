use super::dns::ThreadSafeDNSResolver;
use crate::{
    app::net::DEFAULT_OUTBOUND_INTERFACE,
    common::{
        errors::{IntoIoResultExt as _, new_io_error},
        timed_future::TimedFuture,
        tls::GLOBAL_ROOT_STORE,
        utils::serialize_duration,
    },
    proxy::{AnyOutboundHandler, OutboundType},
    session::Session,
};
use anyhow::Context;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use http_body_util::Empty;
use hyper::Request;
use hyper_util::rt::TokioIo;
use portable_atomic::AtomicU64;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, instrument, trace, warn};

pub mod healthcheck;
pub mod providers;

static GLOBAL_TRAFFIC_RATE_BPS: AtomicU64 = AtomicU64::new(0);

pub fn get_global_traffic_rate() -> u64 {
    GLOBAL_TRAFFIC_RATE_BPS.load(Ordering::Relaxed)
}
pub fn set_global_traffic_rate(upload: u64, download: u64) {
    GLOBAL_TRAFFIC_RATE_BPS.store(upload + download, Ordering::Relaxed);
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TrafficStats {
    /// Total bytes uploaded in this session
    pub bytes_uploaded: u64,
    /// Total bytes downloaded in this session
    pub bytes_downloaded: u64,
    /// Duration of the connection
    pub connection_duration: Duration,
    /// Average throughput in bytes per second
    pub average_throughput: f64,
    /// Peak throughput observed
    pub peak_throughput: f64,
    /// Frequency of requests per second
    pub request_frequency: f64,
    /// Whether traffic flows both ways significantly
    pub is_bidirectional: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TrafficPatternType {
    /// Web browsing - moderate download, low upload, short-medium duration
    WebBrowsing,
    /// Video streaming - high download, low upload, long duration, steady
    /// throughput
    VideoStreaming,
    /// File download - very high download, minimal upload, variable duration
    FileDownload,
    /// File upload - minimal download, high upload, variable duration
    FileUpload,
    /// Gaming - low throughput, high frequency, bidirectional, low latency
    /// critical
    Gaming,
    /// Voice call - moderate bidirectional, steady throughput, medium duration
    VoiceCall,
    /// Video call - high bidirectional, steady throughput, medium-long duration
    VideoCall,
    /// Messaging - very low throughput, sporadic, bidirectional
    Messaging,
    /// Unknown pattern
    Unknown,
}

/// Result of traffic pattern analysis with confidence score
#[derive(Clone, Debug)]
pub struct TrafficPattern {
    pub pattern_type: TrafficPatternType,
    /// Confidence score from 0.0 to 1.0
    pub confidence: f64,
}

#[derive(Clone, Serialize)]
pub struct DelayHistory {
    time: DateTime<Utc>,
    #[serde(serialize_with = "serialize_duration")]
    delay: Duration,
}

#[derive(Default)]
struct ProxyState {
    alive: AtomicBool,
    delay_history: VecDeque<DelayHistory>,
    /// Consecutive failure count for fixed-interval backoff.
    /// Incremented on failure, reset to 0 on success.
    /// Used by `check()` to skip dead proxies: after 3+ consecutive
    /// failures, a proxy is tested only every `backoff_rounds` rounds
    /// (default 12 rounds, configurable via CLASH_RS_BACKOFF_ROUNDS env var).
    /// This minimizes the impact of permanently-dead nodes (e.g. AnyTLS
    /// servers that are down) while still detecting when they come back.
    consecutive_failures: u32,
    /// Last healthcheck round this proxy was tested in.
    /// Used together with `consecutive_failures` to implement backoff.
    last_test_round: u64,
}

/// ProxyManager is the latency registry.
#[derive(Clone)]
pub struct ProxyManager {
    proxy_state: Arc<RwLock<HashMap<String, ProxyState>>>,
    dns_resolver: ThreadSafeDNSResolver,
    /// Firewall Mark for url test
    fw_mark: Option<u32>,
    /// Monotonically increasing round counter for healthcheck backoff.
    /// Incremented each time `check()` is called.
    check_round: Arc<AtomicU64>,
    /// Rounds to wait before re-testing a consistently-failing proxy (cf>=3).
    /// Configurable via `CLASH_RS_BACKOFF_ROUNDS` env var (default 12 rounds).
    /// A dead proxy is tested once every N rounds; if it succeeds,
    /// `consecutive_failures` resets to 0 and normal per-round testing resumes.
    backoff_rounds: u64,
    /// Shared semaphore limiting concurrent healthcheck requests across all
    /// groups and providers.
    /// Configurable via `CLASH_RS_HEALTHCHECK_CONCURRENCY` env var (default 8).
    /// Limits CPU/memory burst on low-RAM routers when many proxies are alive.
    check_semaphore: Arc<Semaphore>,
}

#[derive(Clone, Default)]
pub struct SiteTuning {
    pub delay_weight: Option<f64>,
    pub packet_loss_weight: Option<f64>,
    pub rtt_weight: Option<f64>,
    pub alive_penalty: Option<f64>,
}

impl ProxyManager {
    pub fn new(dns_resolver: ThreadSafeDNSResolver, fw_mark: Option<u32>) -> Self {
        let backoff_rounds = std::env::var("CLASH_RS_BACKOFF_ROUNDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|v: &u64| *v > 0)
            .unwrap_or(12);
        let concurrency = std::env::var("CLASH_RS_HEALTHCHECK_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|v: &usize| *v > 0)
            .unwrap_or(8);
        Self {
            dns_resolver,
            proxy_state: Default::default(),
            fw_mark,
            check_round: Arc::new(AtomicU64::new(0)),
            backoff_rounds,
            check_semaphore: Arc::new(Semaphore::new(concurrency)),
        }
    }

    /// Handy wrapper of `url_test` that checks multiple proxies
    /// Implements fixed-interval backoff for consistently-failing proxies
    /// to minimize the impact of dead nodes while still detecting revival.
    ///
    /// `force` controls whether backoff is applied:
    /// - `false` (automatic health checks): proxies with `consecutive_failures
    ///   >= 3` are tested only once every `backoff_rounds` rounds, so dead
    ///   nodes don't waste CPU/bandwidth on a 78 BogoMIPS router.
    /// - `true` (manual user-triggered latency test): backoff is bypassed and
    ///   every node is tested, because the user explicitly asked for a fresh
    ///   result (e.g. after restarting a server, or to verify the backoff list
    ///   is still accurate).
    #[instrument(skip(self))]
    pub async fn check(
        &self,
        outbounds: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Option<Duration>,
        force: bool,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        let round = self
            .check_round
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;

        // Determine which proxies to test vs skip (exponential backoff)
        let mut to_test = Vec::with_capacity(outbounds.len());
        let mut skip_results: HashMap<
            String,
            std::io::Result<(Duration, Duration)>,
        > = HashMap::new();

        {
            let state = self.proxy_state.read().await;
            for outbound in outbounds {
                let name = outbound.name();
                if !force && let Some(s) = state.get(name) {
                    let cf = s.consecutive_failures;
                    if cf >= 3 {
                        // Fixed-interval backoff: test every
                        // `backoff_rounds` rounds
                        // (default 12 = ~60min at 5min/round, configurable
                        // via
                        // CLASH_RS_BACKOFF_ROUNDS env var). A
                        // consistently-failing
                        // proxy is re-tested once every N rounds; on
                        // success it
                        // is reactivated (consecutive_failures reset to 0).
                        let backoff = self.backoff_rounds;
                        let elapsed = round.saturating_sub(s.last_test_round);
                        if elapsed < backoff {
                            // Skip this proxy — it's in backoff
                            skip_results.insert(
                                name.to_owned(),
                                Err(new_io_error(format!(
                                    "healthcheck skipped (backoff: {} consecutive \
                                     failures, next test in {} round(s))",
                                    cf,
                                    backoff.saturating_sub(elapsed)
                                ))),
                            );
                            continue;
                        }
                    }
                }
                to_test.push(outbound.clone());
            }
        }
        // Update last_test_round for proxies being tested this round
        {
            let mut state = self.proxy_state.write().await;
            for outbound in &to_test {
                let name = outbound.name();
                let entry = state.entry(name.to_owned()).or_default();
                entry.last_test_round = round;
            }
        }

        let mut futs = vec![];
        // Limit concurrency to avoid burst resource consumption on low-RAM
        // routers. Configurable via CLASH_RS_HEALTHCHECK_CONCURRENCY
        // env var (default 8).
        let sem = self.check_semaphore.clone();
        for outbound in to_test {
            let outbound = outbound.clone();
            let url = url.to_owned();
            let manager = self.clone();
            let sem = sem.clone();
            futs.push(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                let proxy_name = outbound.name().to_owned();
                let result = manager
                    .url_test(outbound, url.as_str(), timeout)
                    .await
                    .inspect_err(|e| {
                        warn!("healthcheck {} -> {} failed: {}", proxy_name, url, e)
                    });
                (proxy_name, result)
            });
        }

        let futs: FuturesUnordered<_> = futs.into_iter().collect();
        let r: Vec<_> = futs.collect().await;

        // Build a map of tested results by proxy name
        let mut tested_results: HashMap<
            String,
            std::io::Result<(Duration, Duration)>,
        > = HashMap::new();
        for (name, result) in r {
            tested_results.insert(name, result);
        }

        // Track consecutive failures for exponential backoff:
        // Only automatic healthcheck failures (!force) increment
        // consecutive_failures. Successful tests (both automatic and
        // forced) reset consecutive_failures to 0.
        {
            let mut state = self.proxy_state.write().await;
            for (name, result) in &tested_results {
                let entry = state.entry(name.clone()).or_default();
                if result.is_ok() {
                    entry.consecutive_failures = 0;
                } else if !force {
                    entry.consecutive_failures =
                        entry.consecutive_failures.saturating_add(1);
                }
            }
        }

        // Merge results in original outbound order, including skipped proxies
        let mut results = vec![];
        for outbound in outbounds {
            let name = outbound.name();
            if let Some(r) = skip_results.remove(name) {
                results.push(r);
            } else {
                results.push(tested_results.remove(name).unwrap_or_else(|| {
                    Err(new_io_error("healthcheck result missing".to_string()))
                }));
            }
        }
        results
    }

    pub fn check_round(&self) -> u64 {
        self.check_round.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn last_test_round_for<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
    ) -> u64 {
        let state = self.proxy_state.read().await;
        names
            .into_iter()
            .filter_map(|name| state.get(name).map(|s| s.last_test_round))
            .max()
            .unwrap_or(0)
    }

    pub async fn alive(&self, name: &str) -> bool {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|x| x.alive.load(Ordering::Relaxed))
            .unwrap_or(true) // if not found, assume it's alive
    }

    pub(crate) async fn alive_and_last_delay(
        &self,
        name: &str,
    ) -> (bool, Option<Duration>) {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map_or((true, None), |state| {
                (
                    state.alive.load(Ordering::Relaxed),
                    state.delay_history.back().map(|history| history.delay),
                )
            })
    }

    pub async fn report_alive(
        &self,
        name: &str,
        alive: bool,
        history: Option<DelayHistory>,
    ) {
        let mut state = self.proxy_state.write().await;
        let entry = state.entry(name.to_owned()).or_default();
        entry.alive.store(alive, Ordering::Relaxed);
        // Reset consecutive failures on success
        if alive {
            entry.consecutive_failures = 0;
        }
        if let Some(ins) = history {
            entry.delay_history.push_back(ins);
            if entry.delay_history.len() > 10 {
                entry.delay_history.pop_front();
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn report_delay(
        &self,
        name: &str,
        alive: bool,
        delay: Duration,
    ) {
        self.report_alive(
            name,
            alive,
            Some(DelayHistory {
                time: Utc::now(),
                delay,
            }),
        )
        .await;
    }

    pub async fn delay_history(&self, name: &str) -> Vec<DelayHistory> {
        self.proxy_state
            .read()
            .await
            .get(name)
            .map(|x| x.delay_history.clone())
            .unwrap_or_default()
            .into()
    }

    pub async fn last_delay(&self, name: &str) -> Option<Duration> {
        let (alive, delay) = self.alive_and_last_delay(name).await;
        if alive { delay } else { None }
    }

    pub async fn get_packet_loss(&self, name: &str) -> Option<f64> {
        let history = self.delay_history(name).await;
        if history.is_empty() {
            None
        } else {
            let failed_count = history.iter().filter(|x| x.delay.is_zero()).count();
            Some(failed_count as f64 / history.len() as f64)
        }
    }

    pub async fn get_rtt(&self, name: &str) -> Option<f64> {
        let history = self.delay_history(name).await;
        if history.is_empty() {
            None
        } else {
            let avg_rtt =
                history.iter().map(|x| x.delay.as_millis_f64()).sum::<f64>()
                    / history.len() as f64;
            Some(avg_rtt)
        }
    }

    /// This method analyzes traffic characteristics using multiple detection
    /// algorithms and applies confidence boosting based on session context.
    pub async fn analyze_traffic_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut patterns = Vec::new();

        // Early exit for minimal data
        if stats.bytes_uploaded + stats.bytes_downloaded < 1024 {
            return TrafficPattern {
                pattern_type: TrafficPatternType::Unknown,
                confidence: 0.1,
            };
        }

        // Run all pattern detection algorithms
        patterns.push(self.detect_streaming_pattern(stats, sess));
        patterns.push(self.detect_download_pattern(stats, sess));
        patterns.push(self.detect_upload_pattern(stats, sess));
        patterns.push(self.detect_gaming_pattern(stats, sess));
        patterns.push(self.detect_voip_pattern(stats, sess));
        patterns.push(self.detect_video_call_pattern(stats, sess));
        patterns.push(self.detect_web_browsing_pattern(stats, sess));
        patterns.push(self.detect_messaging_pattern(stats, sess));

        // Find the pattern with highest confidence
        let best_pattern = patterns
            .into_iter()
            .max_by(|a, b| {
                a.confidence
                    .partial_cmp(&b.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap_or(TrafficPattern {
                pattern_type: TrafficPatternType::Unknown,
                confidence: 0.0,
            });

        debug!(
            "Traffic pattern analysis for {}: {:?} (confidence: {:.2})",
            sess.destination.host(),
            best_pattern.pattern_type,
            best_pattern.confidence
        );

        best_pattern
    }

    fn detect_streaming_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let duration_secs = stats.connection_duration.as_secs();
        let mut confidence = 0.0;

        // Domain-based detection boost
        let host = sess.destination.host().to_lowercase();
        if host.contains("youtube")
            || host.contains("netflix")
            || host.contains("twitch")
            || host.contains("video")
            || host.contains("stream")
            || host.contains("hls")
        {
            confidence += 0.2;
        }

        // High download ratio (>88% download, slightly relaxed)
        if download_ratio > 0.88 {
            confidence += 0.3;
        }

        // Long duration indicates streaming
        match duration_secs {
            0..=60 => {}                      // Too short for streaming
            61..=300 => confidence += 0.1,    // Short stream
            301..=1800 => confidence += 0.25, // Medium stream
            _ => confidence += 0.3,           // Long stream
        }

        // Steady moderate to high throughput
        if stats.average_throughput > 500_000.0
            && stats.average_throughput < 100_000_000.0
        {
            confidence += 0.25;
        }

        // Consistent throughput (streaming should be relatively stable)
        if stats.peak_throughput > 0.0 && stats.average_throughput > 0.0 {
            let variance_ratio = stats.peak_throughput / stats.average_throughput;
            if variance_ratio < 4.0 {
                // Less variance indicates streaming
                confidence += 0.15;
            }
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VideoStreaming,
            confidence,
        }
    }

    fn detect_download_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Domain-based detection
        if host.contains("cdn")
            || host.contains("download")
            || host.contains("files")
            || host.contains("github")
            || host.contains("releases")
        {
            confidence += 0.2;
        }

        // Very high download ratio (>94%)
        if download_ratio > 0.94 {
            confidence += 0.4;
        }

        // High sustained throughput
        if stats.average_throughput > 5_000_000.0 {
            confidence += 0.3;
        }

        // Large total download size
        match stats.bytes_downloaded {
            10_000_000..=100_000_000 => confidence += 0.2, // 10-100MB
            100_000_001.. => confidence += 0.3,            // >100MB
            _ => {}
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::FileDownload,
            confidence,
        }
    }

    fn detect_upload_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Domain-based detection
        if host.contains("upload")
            || host.contains("cloud")
            || host.contains("drive")
            || host.contains("storage")
            || host.contains("backup")
        {
            confidence += 0.2;
        }

        // High upload ratio (>75%)
        if upload_ratio > 0.75 {
            confidence += 0.4;
        }

        // Sustained upload throughput
        if stats.average_throughput > 2_000_000.0 {
            confidence += 0.3;
        }

        // Large upload size
        if stats.bytes_uploaded > 20_000_000 {
            // 20MB+
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::FileUpload,
            confidence,
        }
    }

    fn detect_gaming_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();
        let port = sess.destination.port();

        // Gaming-related domains and ports
        if host.contains("game")
            || host.contains("steam")
            || host.contains("riot")
            || host.contains("blizzard")
            || host.contains("xbox")
            || host.contains("playstation")
        {
            confidence += 0.3;
        }

        // Common gaming ports
        if matches!(port, 3478..=3480 | 27000..=28000 | 7777..=7784) {
            confidence += 0.2;
        }

        // High request frequency with low latency requirements
        if stats.request_frequency > 20.0 {
            confidence += 0.3;
        }

        // Low overall throughput but highly bidirectional
        if stats.average_throughput < 1_000_000.0 && stats.is_bidirectional {
            confidence += 0.3;
        }

        // Gaming sessions tend to be long
        if stats.connection_duration.as_secs() > 600 {
            // 10+ minutes
            confidence += 0.2;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::Gaming,
            confidence,
        }
    }

    fn detect_voip_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_download_ratio = if stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64 / stats.bytes_downloaded as f64
        } else {
            f64::INFINITY
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // VoIP service domains
        if host.contains("skype")
            || host.contains("zoom")
            || host.contains("teams")
            || host.contains("discord")
            || host.contains("webex")
            || host.contains("voip")
        {
            confidence += 0.3;
        }

        // Balanced upload/download (0.4 to 2.5 ratio for VoIP)
        if upload_download_ratio > 0.4 && upload_download_ratio < 2.5 {
            confidence += 0.4;
        }

        // Voice codec throughput range
        if stats.average_throughput > 16_000.0
            && stats.average_throughput < 320_000.0
        {
            confidence += 0.3;
        }

        // Call duration patterns
        match stats.connection_duration.as_secs() {
            60..=3600 => confidence += 0.3, // 1 minute to 1 hour
            3601.. => confidence += 0.2,    // Very long calls
            _ => {}
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VoiceCall,
            confidence,
        }
    }

    fn detect_video_call_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let upload_download_ratio = if stats.bytes_downloaded > 0 {
            stats.bytes_uploaded as f64 / stats.bytes_downloaded as f64
        } else {
            f64::INFINITY
        };

        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Video call service domains
        if host.contains("zoom")
            || host.contains("teams")
            || host.contains("meet")
            || host.contains("webex")
            || host.contains("facetime")
            || host.contains("hangouts")
        {
            confidence += 0.3;
        }

        // Balanced but higher bandwidth than voice
        if upload_download_ratio > 0.2 && upload_download_ratio < 5.0 {
            confidence += 0.3;
        }

        // Video call throughput range
        if stats.average_throughput > 200_000.0
            && stats.average_throughput < 15_000_000.0
        {
            confidence += 0.4;
        }

        // Video call duration patterns
        if stats.connection_duration.as_secs() > 120 {
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::VideoCall,
            confidence,
        }
    }

    fn detect_web_browsing_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let port = sess.destination.port();
        let host = sess.destination.host().to_lowercase();

        // HTTP/HTTPS ports get strong signal
        if port == 80 || port == 443 {
            confidence += 0.4;
        }

        // Common web domains
        if host.contains("www")
            || host.contains("com")
            || host.contains("org")
            || host.contains("net")
            || host.ends_with(".io")
        {
            confidence += 0.1;
        }

        // Web browsing download preference
        let download_ratio = if stats.bytes_uploaded + stats.bytes_downloaded > 0 {
            stats.bytes_downloaded as f64
                / (stats.bytes_uploaded + stats.bytes_downloaded) as f64
        } else {
            0.0
        };

        if download_ratio > 0.65 && download_ratio < 0.93 {
            confidence += 0.3;
        }

        // Web browsing throughput characteristics
        if stats.average_throughput > 50_000.0
            && stats.average_throughput < 8_000_000.0
        {
            confidence += 0.2;
        }

        // Browsing sessions are typically shorter
        if stats.connection_duration.as_secs() < 1800 {
            // Less than 30 minutes
            confidence += 0.1;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::WebBrowsing,
            confidence,
        }
    }

    fn detect_messaging_pattern(
        &self,
        stats: &TrafficStats,
        sess: &Session,
    ) -> TrafficPattern {
        let mut confidence = 0.0;
        let host = sess.destination.host().to_lowercase();

        // Messaging service domains
        if host.contains("whatsapp")
            || host.contains("telegram")
            || host.contains("signal")
            || host.contains("messenger")
            || host.contains("slack")
            || host.contains("discord")
        {
            confidence += 0.3;
        }

        // Very low sustained throughput
        if stats.average_throughput < 100_000.0 {
            confidence += 0.4;
        }

        // Bidirectional but low volume
        if stats.is_bidirectional
            && stats.bytes_uploaded + stats.bytes_downloaded < 5_000_000
        {
            // Less than 5MB total
            confidence += 0.3;
        }

        // Messaging can have long idle connections
        if stats.connection_duration.as_secs() > 300 {
            confidence += 0.3;
        }

        TrafficPattern {
            pattern_type: TrafficPatternType::Messaging,
            confidence,
        }
    }

    /// Calculate adjustment factor based on total data transferred
    fn calculate_data_size_factor(&self, stats: &TrafficStats) -> f64 {
        let total_bytes = stats.bytes_uploaded + stats.bytes_downloaded;

        match total_bytes {
            0..=1_000_000 => 1.0,           // Small data: standard weights
            1_000_001..=100_000_000 => 1.2, // Medium data: slightly favor stability
            100_000_001..=1_000_000_000 => 1.5, // Large data: favor stability more
            _ => 2.0,                       /* Very large data: heavily favor
                                              * stability */
        }
    }

    #[instrument(skip(self, outbound))]
    /// returns (actual_http_round_trip_time,
    /// overall_round_trip_time_including_tls_handshake)
    pub async fn url_test(
        &self,
        outbound: AnyOutboundHandler,
        url: &str,
        timeout: Option<Duration>,
    ) -> std::io::Result<(Duration, Duration)> {
        trace!("started");
        let name = outbound.name().to_owned();
        let name_clone = name.clone();
        let default_timeout = Duration::from_secs(5);
        let timeout = timeout.unwrap_or(default_timeout);

        let dns_resolver = self.dns_resolver.clone();
        let tester = async move {
            let name = name_clone;

            let uri = url
                .parse::<http::Uri>()
                .map_err(|e| new_io_error(format!("invalid url: {url}: {e}")))?;

            let host = uri
                .host()
                .ok_or(new_io_error(format!("invalid url: {url}: no host found")))?
                .to_owned();
            let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
                None => 80,
                Some(s) => match s {
                    "http" => 80,
                    "https" => 443,
                    _ => {
                        return Err(new_io_error(format!(
                            "invalid url: {url}: unsupported scheme {s}"
                        )));
                    }
                },
            });

            let sess = Session {
                destination: (host.to_owned(), port)
                    .try_into()
                    .expect("must be valid destination"),
                iface: DEFAULT_OUTBOUND_INTERFACE.read().await.clone(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            let (stream, connect_delay) = tokio::time::timeout(
                timeout,
                TimedFuture::new(
                    outbound.connect_stream(&sess, dns_resolver.clone()),
                ),
            )
            .await
            .context("URL test timeout")
            .into_io()?;

            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    if matches!(outbound.proto(), OutboundType::Anytls) {
                        let tcp_ms = connect_delay.as_millis();
                        debug!(
                            "AnyTLS {} handshake failed ({e}, {tcp_ms}ms TCP)",
                            name
                        );
                    }
                    return Err(e);
                }
            };

            let req = Request::get(url)
                .header(hyper::header::HOST, host.as_str())
                .header("Connection", "Close")
                .version(hyper::Version::HTTP_11)
                .body(Empty::<Bytes>::new())
                .unwrap();

            let mut tls_handshake_delay = None;
            let resp = match uri.scheme() {
                Some(scheme) if scheme == &http::uri::Scheme::HTTP => {
                    let io = TokioIo::new(stream);
                    let (mut sender, conn) = tokio::time::timeout(
                        timeout,
                        hyper::client::conn::http1::handshake(io),
                    )
                    .await
                    .map_err(|_| new_io_error("HTTP handshake timed out"))?
                    .map_err(|e| {
                        new_io_error(format!("failed to handshake: {e}"))
                    })?;

                    tokio::task::spawn(async move {
                        if let Err(err) = conn.await {
                            warn!("HTTP connection error: {}", err);
                        }
                    });

                    TimedFuture::new(sender.send_request(req).boxed())
                }
                Some(scheme) if scheme == &http::uri::Scheme::HTTPS => {
                    let mut tls_config = rustls::ClientConfig::builder()
                        .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                        .with_no_client_auth();

                    if std::env::var("SSLKEYLOGFILE").is_ok() {
                        debug!("Enabling TLS key logging");
                        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
                    }

                    let connector =
                        tokio_rustls::TlsConnector::from(Arc::new(tls_config));

                    let (stream, delay) = tokio::time::timeout(
                        timeout,
                        TimedFuture::new(connector.connect(
                            host.try_into().expect("must be valid SNI"),
                            stream,
                        )),
                    )
                    .await?;

                    let stream = stream?;

                    let io = TokioIo::new(stream);

                    let (mut sender, conn) = tokio::time::timeout(
                        timeout,
                        hyper::client::conn::http1::handshake(io),
                    )
                    .await
                    .map_err(|_| new_io_error("HTTPS handshake timed out"))?
                    .map_err(|e| {
                        new_io_error(format!("failed to handshake: {e}"))
                    })?;

                    tokio::task::spawn(async move {
                        if let Err(err) = conn.await {
                            warn!("HTTP connection error: {}", err);
                        }
                    });

                    tls_handshake_delay = Some(delay);

                    TimedFuture::new(sender.send_request(req).boxed())
                }
                _ => {
                    return Err(new_io_error(format!(
                        "invalid url: {url}: unsupported scheme"
                    )));
                }
            };

            let delay = match tokio::time::timeout(timeout, resp).await {
                Ok((res, delay)) => match res {
                    Ok(res) => {
                        trace!(
                            delay = ?delay,
                            status = ?res.status(),
                            "success"
                        );
                        Ok(delay)
                    }
                    Err(e) => {
                        warn!(
                            e = ?e,
                            "failed"
                        );
                        Err(new_io_error(format!(
                            "urltest for proxy {name} failed: {e}"
                        )))
                    }
                },
                Err(_) => {
                    warn!("timed out");
                    Err(new_io_error(format!("timeout for {url}").as_str()))
                }
            }?;

            Ok((
                delay,
                (connect_delay + tls_handshake_delay.unwrap_or_default() + delay),
            ))
        };

        let result = tester.await;

        self.report_alive(
            &name,
            result.is_ok(),
            Some(DelayHistory {
                time: Utc::now(),
                delay: result
                    .as_ref()
                    .map(|(actual, _)| *actual)
                    .unwrap_or_default(),
            }),
        )
        .await;

        result
    }

    /// Based on session characteristics and traffic statistics.
    pub async fn get_site_tuning(&self, sess: &Session) -> SiteTuning {
        // Extract traffic statistics from the session if available
        let traffic_stats = sess.traffic_stats.as_ref();

        // Attempt intelligent pattern detection if traffic statistics are
        // available
        if let Some(stats) = traffic_stats {
            let pattern = self.analyze_traffic_pattern(stats, sess).await;

            // Only use pattern-specific tuning if confidence is high enough
            if pattern.confidence > 0.6 {
                // Apply pattern-specific tuning parameters optimized for each
                // traffic type
                let mut tuning = match pattern.pattern_type {
                    // Gaming: Ultra-low latency critical, high packet loss penalty
                    TrafficPatternType::Gaming => SiteTuning {
                        delay_weight: Some(0.1),
                        packet_loss_weight: Some(8000.0),
                        rtt_weight: Some(0.1),
                        alive_penalty: Some(20000.0),
                    },
                    // Voice calls: Low latency important, moderate packet loss
                    // sensitivity
                    TrafficPatternType::VoiceCall => SiteTuning {
                        delay_weight: Some(0.2),
                        packet_loss_weight: Some(6000.0),
                        rtt_weight: Some(0.2),
                        alive_penalty: Some(15000.0),
                    },
                    // Video calls: Balance between latency and stability
                    TrafficPatternType::VideoCall => SiteTuning {
                        delay_weight: Some(0.4),
                        packet_loss_weight: Some(5000.0),
                        rtt_weight: Some(0.3),
                        alive_penalty: Some(12000.0),
                    },
                    // Video streaming: Favor stability over low latency
                    TrafficPatternType::VideoStreaming => SiteTuning {
                        delay_weight: Some(0.5),
                        packet_loss_weight: Some(4000.0),
                        rtt_weight: Some(0.4),
                        alive_penalty: Some(10000.0),
                    },
                    // Web browsing: Balanced approach for general usage
                    TrafficPatternType::WebBrowsing => SiteTuning {
                        delay_weight: Some(0.6),
                        packet_loss_weight: Some(2000.0),
                        rtt_weight: Some(0.5),
                        alive_penalty: Some(6000.0),
                    },
                    // Messaging: Moderate latency tolerance, low bandwidth
                    TrafficPatternType::Messaging => SiteTuning {
                        delay_weight: Some(0.8),
                        packet_loss_weight: Some(1500.0),
                        rtt_weight: Some(0.4),
                        alive_penalty: Some(5000.0),
                    },
                    // File upload: Prioritize connection stability over speed
                    TrafficPatternType::FileUpload => SiteTuning {
                        delay_weight: Some(1.2),
                        packet_loss_weight: Some(800.0),
                        rtt_weight: Some(0.8),
                        alive_penalty: Some(4000.0),
                    },
                    // File download: Maximum stability for large transfers
                    TrafficPatternType::FileDownload => SiteTuning {
                        delay_weight: Some(1.5),
                        packet_loss_weight: Some(500.0),
                        rtt_weight: Some(1.0),
                        alive_penalty: Some(3000.0),
                    },
                    // Unknown patterns: Use fallback logic
                    _ => self.get_fallback_tuning(sess),
                };

                // Apply data size scaling factor for large transfers
                // Larger transfers benefit more from stable connections
                let data_size_factor = self.calculate_data_size_factor(stats);
                if let Some(ref mut delay_weight) = tuning.delay_weight {
                    *delay_weight *= data_size_factor;
                }
                return tuning;
            }
        }

        // Fallback to protocol and port-based tuning when no traffic data
        // is available or pattern confidence is too low
        self.get_fallback_tuning(sess)
    }

    /// Fallback tuning based on protocol and port
    fn get_fallback_tuning(&self, sess: &Session) -> SiteTuning {
        let is_udp = matches!(sess.network, crate::session::Network::Udp);
        let port = sess.destination.port();

        if is_udp {
            // UDP: games, VoIP, real-time - prioritize low latency
            SiteTuning {
                delay_weight: Some(0.3),
                packet_loss_weight: Some(3000.0),
                rtt_weight: Some(0.3),
                alive_penalty: Some(15000.0),
            }
        } else if port == 80 || port == 443 {
            // HTTP/HTTPS: balance latency and stability
            SiteTuning {
                delay_weight: Some(0.7),
                packet_loss_weight: Some(2000.0),
                rtt_weight: Some(0.7),
                alive_penalty: Some(8000.0),
            }
        } else if matches!(port, 21 | 22 | 115 | 989 | 990) {
            // FTP/SFTP: prioritize stability for file transfers
            SiteTuning {
                delay_weight: Some(1.2),
                packet_loss_weight: Some(1000.0),
                rtt_weight: Some(1.2),
                alive_penalty: Some(5000.0),
            }
        } else {
            // Default balanced tuning
            SiteTuning::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        app::{
            dispatcher::InstrumentedStreamWrapper, dns::MockClashResolver,
            remote_content_manager,
        },
        config::internal::proxy::PROXY_DIRECT,
        proxy::{direct, mocks::MockDummyOutboundHandler},
        tests::initialize,
    };
    use futures::TryFutureExt;
    use httpmock::{Method::GET, MockServer};
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    #[tokio::test]
    async fn test_proxy_manager_alive() {
        initialize();

        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/generate_204");
            then.status(204);
        });
        let url = server.url("/generate_204");

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver
            .expect_resolve()
            .returning(|_, _| Ok(Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))));
        mock_resolver.expect_ipv6().return_const(false);

        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(mock_resolver), None);

        let mock_handler = Arc::new(direct::Handler::new(PROXY_DIRECT));

        manager
            .url_test(mock_handler.clone(), &url, None)
            .await
            .expect("test failed");

        assert!(manager.alive(PROXY_DIRECT).await);
        assert!(
            manager
                .last_delay(PROXY_DIRECT)
                .await
                .is_some_and(|x| x.as_nanos() > 0)
        );
        assert!(!manager.delay_history(PROXY_DIRECT).await.is_empty());

        manager.report_alive(PROXY_DIRECT, false, None).await;
        assert!(!manager.alive(PROXY_DIRECT).await);

        for _ in 0..10 {
            manager
                .url_test(mock_handler.clone(), &url, None)
                .await
                .expect("test failed");
        }

        assert!(manager.alive(PROXY_DIRECT).await);
        assert!(
            manager
                .last_delay(PROXY_DIRECT)
                .await
                .is_some_and(|x| x.as_nanos() > 0)
        );
        assert_eq!(manager.delay_history(PROXY_DIRECT).await.len(), 10);
    }

    #[tokio::test]
    async fn test_proxy_manager_timeout() {
        initialize();

        let mut mock_resolver = MockClashResolver::new();
        mock_resolver.expect_resolve().returning(|_, _| {
            Ok(Some(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))))
        });

        let manager =
            remote_content_manager::ProxyManager::new(Arc::new(mock_resolver), None);

        let mut mock_handler = MockDummyOutboundHandler::new();
        mock_handler
            .expect_name()
            .return_const(PROXY_DIRECT.to_owned());
        mock_handler
            .expect_proto()
            .return_const(crate::proxy::OutboundType::Direct);
        mock_handler.expect_connect_stream().returning(|_, _| {
            Ok(Box::new(InstrumentedStreamWrapper::new(
                tokio_test::io::Builder::new()
                    .wait(Duration::from_secs(10))
                    .build(),
            )))
        });

        let mock_handler = Arc::new(mock_handler);

        let result = manager
            .url_test(
                mock_handler.clone(),
                "http://www.gstatic.com/generate_204",
                Some(Duration::from_secs(3)),
            )
            .map_err(|x| assert!(x.to_string().contains("timeout")))
            .await;

        assert!(result.is_err());
        assert!(!manager.alive(PROXY_DIRECT).await);
        assert_eq!(manager.last_delay(PROXY_DIRECT).await, None);
        assert_eq!(manager.delay_history(PROXY_DIRECT).await.len(), 1);
    }
}
