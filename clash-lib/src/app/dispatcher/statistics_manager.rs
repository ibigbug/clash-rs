use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Weak, atomic::Ordering},
};

use chrono::Utc;
use memory_stats::memory_stats;
use portable_atomic::AtomicU64;
use serde::Serialize;
use tokio::sync::{Mutex, RwLock, oneshot::Sender};
use tracing::warn;

use crate::{app::dns::ThreadSafeDNSResolver, session::Session};

use super::tracked::Tracked;

/// Memory limit mode for the manager.
/// When memory exceeds the limit, connections are closed to reduce memory
/// usage instead of crashing the process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MemLimitMode {
    /// No memory limit.
    #[default]
    None,
    /// Soft limit: rejects new connections when exceeded while keeping existing
    /// ones alive.
    Soft,
    /// Hard limit: rejects new connections and evicts up to 20% of existing
    /// connections when the hard ratio is exceeded.
    Hard,
}

/// Per-user traffic since the last drain.  Both upload and download are in
/// bytes.
#[derive(Serialize, Clone, Debug, Default)]
pub struct UserTraffic {
    pub upload: u64,
    pub download: u64,
}

#[derive(Default, Clone, Debug)]
pub struct ProxyChain(Arc<RwLock<Vec<String>>>);

impl ProxyChain {
    pub async fn push(&self, s: String) {
        let mut chain = self.0.write().await;
        chain.push(s);
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.0.read().await.clone()
    }
}

#[derive(Serialize, Default)]
pub struct TrackerInfo {
    #[serde(rename = "id")]
    pub uuid: uuid::Uuid,
    #[serde(rename = "metadata")]
    pub session: HashMap<String, Box<dyn erased_serde::Serialize + Send + Sync>>,
    #[serde(rename = "upload")]
    pub upload_total: AtomicU64,
    #[serde(rename = "download")]
    pub download_total: AtomicU64,
    #[serde(rename = "start")]
    pub start_time: chrono::DateTime<Utc>,
    #[serde(rename = "chains")]
    pub proxy_chain: Vec<String>,
    #[serde(rename = "rule")]
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,

    #[serde(skip)]
    pub proxy_chain_holder: ProxyChain,
    #[serde(skip)]
    pub session_holder: Session,

    /// Per-user byte counters, separate from `upload_total`/`download_total`.
    /// Only incremented when `session_holder.inbound_user` is set.
    /// Swapped to 0 on drain — never touched by `snapshot()`.
    #[serde(skip)]
    pub user_upload: AtomicU64,
    #[serde(skip)]
    pub user_download: AtomicU64,
}

impl TrackerInfo {
    pub fn account_download(&self, mgr: &Manager, n: usize) {
        if n == 0 {
            return;
        }
        mgr.push_downloaded(n);
        self.download_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        if self.session_holder.inbound_user.is_some() {
            self.user_download
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn account_upload(&self, mgr: &Manager, n: usize) {
        if n == 0 {
            return;
        }
        mgr.push_uploaded(n);
        self.upload_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        if self.session_holder.inbound_user.is_some() {
            self.user_upload
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    download_total: u64,
    upload_total: u64,
    connections: Vec<TrackerInfo>,
    memory: usize,
}

type ConnectionMap = HashMap<uuid::Uuid, (Tracked, Option<Sender<()>>)>;

/// Lightweight record stored in the `closed_flows` ring buffer.
/// Unlike `TrackerInfo`, this does NOT hold `session_holder` (Session) or
/// `proxy_chain_holder` (ProxyChain), which are the biggest memory consumers
/// per connection. This prevents the ring buffer from retaining large objects
/// after connections close, which was the root cause of "memory keeps growing
/// after speed test stops".
///
/// Fields are stored as concrete types (not trait objects) so callers can
/// access them directly without downcasting.
#[derive(Serialize, Clone)]
pub struct ClosedFlowInfo {
    #[serde(rename = "id")]
    pub uuid: uuid::Uuid,
    #[serde(rename = "upload")]
    pub upload_total: u64,
    #[serde(rename = "download")]
    pub download_total: u64,
    #[serde(rename = "start")]
    pub start_time: chrono::DateTime<Utc>,
    #[serde(rename = "chains")]
    pub proxy_chain: Vec<String>,
    #[serde(rename = "rule")]
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
    /// Pre-extracted from Session for /flows API consumption.
    pub host: String,
    pub destination_port: u16,
    pub network: String,
    pub source_ip: String,
    pub country: Option<String>,
    pub asn: Option<String>,
}

impl ClosedFlowInfo {
    /// Create from a `TrackerInfo` by snapshotting atomic counters and
    /// extracting concrete fields from session_holder. The heavy
    /// `session_holder` and `proxy_chain_holder` are NOT carried over.
    pub async fn from_tracker_info(info: &TrackerInfo) -> Self {
        let chain = info.proxy_chain_holder.snapshot().await;
        Self {
            uuid: info.uuid,
            upload_total: info.upload_total.load(Ordering::Acquire),
            download_total: info.download_total.load(Ordering::Acquire),
            start_time: info.start_time,
            proxy_chain: chain,
            rule: info.rule.clone(),
            rule_payload: info.rule_payload.clone(),
            host: info.session_holder.destination.host(),
            destination_port: info.session_holder.destination.port(),
            network: match info.session_holder.network {
                crate::session::Network::Tcp => "tcp".to_string(),
                crate::session::Network::Udp => "udp".to_string(),
            },
            source_ip: info.session_holder.source.ip().to_string(),
            country: info.session_holder.country.clone(),
            asn: info.session_holder.asn.clone(),
        }
    }
}

pub struct Manager {
    connections: Arc<Mutex<ConnectionMap>>,
    /// Ring buffer of recently closed connections for the /flows API.
    /// Uses `ClosedFlowInfo` (lightweight) instead of `Arc<TrackerInfo>`
    /// to avoid retaining `Session` and `ProxyChain` after close.
    closed_flows: Arc<Mutex<VecDeque<ClosedFlowInfo>>>,
    upload_temp: AtomicU64,
    download_temp: AtomicU64,
    upload_blip: AtomicU64,
    download_blip: AtomicU64,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    /// Bytes accumulated from **closed** connections, keyed by inbound_user.
    /// Drained (and reset) by [`Manager::drain_user_stats`].
    user_period_stats: Arc<Mutex<HashMap<String, UserTraffic>>>,
    /// Memory limit in bytes. 0 = unlimited.
    mem_limit_bytes: AtomicU64,
    /// Current memory limit mode.
    mem_limit_mode: Mutex<MemLimitMode>,
    /// Number of connections closed due to memory pressure (for stats).
    mem_pressure_closes: AtomicU64,
    /// Number of new connections rejected due to memory pressure (for stats).
    mem_pressure_rejects: AtomicU64,
    /// DNS resolver for clearing DNS caches under memory pressure.
    /// Stored as a `Weak` reference to allow the resolver graph to be dropped
    /// immediately when `RuntimeComponents` are replaced during reload.
    dns_resolver: RwLock<Option<Weak<dyn crate::app::dns::ClashResolver>>>,
    /// Hard-mode trigger ratio (e.g. 2.0 = trigger at 2x limit).
    /// Stored as the multiplier * 100 (200 = 2.0x) to fit in AtomicU64.
    /// 0 = Hard mode disabled (user prefers OOM kill over connection drop).
    mem_hard_ratio_x100: AtomicU64,
    /// Cached memory usage in bytes, periodically refreshed by `kick_off`.
    mem_usage_cached: AtomicU64,
    /// Indicates whether the background stats loop is active.
    running: Arc<std::sync::atomic::AtomicBool>,
}

/// Default capacity of the `closed_flows` ring buffer.
/// Can be overridden via `experimental.closed-flows-cap` in config.
pub const DEFAULT_CLOSED_FLOWS_CAP: usize = 50;

/// Global closed_flows capacity. Uses AtomicUsize so it can be
/// updated on config reload (unlike OnceLock which is set-once).
static CLOSED_FLOWS_CAP_CONFIG: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_CLOSED_FLOWS_CAP);

/// Set the global closed_flows capacity. Called during config loading.
pub fn set_closed_flows_cap(cap: usize) {
    CLOSED_FLOWS_CAP_CONFIG.store(cap, std::sync::atomic::Ordering::Release);
}

fn closed_flows_cap() -> usize {
    CLOSED_FLOWS_CAP_CONFIG.load(std::sync::atomic::Ordering::Acquire)
}

/// Default hard-mode trigger: 2x the soft limit.
const DEFAULT_HARD_RATIO_X100: u64 = 200;
/// When Hard mode fires, close this fraction of connections (20%).
const HARD_CLOSE_FRACTION_NUM: u64 = 20;
const HARD_CLOSE_FRACTION_DEN: u64 = 100;

impl Manager {
    pub fn new() -> Arc<Self> {
        // Read memory limit from environment variable.
        // Format: CLASH_RS_MEM_LIMIT_MB=40  (soft limit, close oldest conns)
        //         CLASH_RS_MEM_LIMIT_MB=40:hard  (close all conns when
        // exceeded)
        let (limit_bytes, mode) = match std::env::var("CLASH_RS_MEM_LIMIT_MB") {
            Ok(val) => {
                let val = val.trim();
                let (num_str, mode) = if let Some(rest) = val.strip_suffix(":hard") {
                    (rest, MemLimitMode::Hard)
                } else if let Some(rest) = val.strip_suffix(":soft") {
                    (rest, MemLimitMode::Soft)
                } else {
                    (val, MemLimitMode::Soft)
                };
                match num_str.parse::<u64>() {
                    // Fix(2026-08-04): saturating to avoid u64 overflow on
                    // absurd values (mb * 1024 * 1024 overflows at mb >= 2^44).
                    Ok(mb) if mb > 0 => {
                        (mb.saturating_mul(1024).saturating_mul(1024), mode)
                    }
                    _ => (0, MemLimitMode::None),
                }
            }
            Err(_) => (0, MemLimitMode::None),
        };

        // Read optional hard-mode trigger ratio.
        // Format: CLASH_RS_MEM_HARD_RATIO=1.5  (trigger Hard at 1.5x limit)
        //         CLASH_RS_MEM_HARD_RATIO=0    (disable Hard mode entirely)
        // Default: 2.0 (Hard triggers at 2x limit)
        let hard_ratio_x100 = match std::env::var("CLASH_RS_MEM_HARD_RATIO") {
            Ok(val) => {
                let val = val.trim();
                match val.parse::<f64>() {
                    Ok(r) if r < 0.0 => DEFAULT_HARD_RATIO_X100,
                    Ok(0.0) => 0, // user explicitly disables Hard
                    // ratio < 1.0 is nonsensical: Hard mode (close existing
                    // conns) would trigger BEFORE Soft mode (reject new conns
                    // at 1x limit).  Clamp to default to avoid logic inversion.
                    Ok(r) if r < 1.0 => DEFAULT_HARD_RATIO_X100,
                    // Fix(2026-08-04): guard NaN/Inf (parse::<f64>("NaN") is
                    // Ok(NaN); (NaN*100) as u64 == 0 silently disabled Hard).
                    Ok(r) if r.is_finite() && r >= 1.0 => (r * 100.0).round() as u64,
                    Ok(_) => DEFAULT_HARD_RATIO_X100,
                    Err(_) => DEFAULT_HARD_RATIO_X100,
                }
            }
            Err(_) => DEFAULT_HARD_RATIO_X100,
        };

        let v = Arc::new(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            closed_flows: Arc::new(Mutex::new(VecDeque::new())),
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
            upload_blip: AtomicU64::new(0),
            download_blip: AtomicU64::new(0),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            user_period_stats: Arc::new(Mutex::new(HashMap::new())),
            mem_limit_bytes: AtomicU64::new(limit_bytes),
            mem_limit_mode: Mutex::new(mode),
            mem_pressure_closes: AtomicU64::new(0),
            mem_pressure_rejects: AtomicU64::new(0),
            dns_resolver: RwLock::new(None),
            mem_hard_ratio_x100: AtomicU64::new(hard_ratio_x100),
            mem_usage_cached: AtomicU64::new(0),
            running: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        });
        let c = v.clone();
        tokio::spawn(async move {
            c.kick_off().await;
        });
        v
    }

    /// Set memory limit at runtime (bytes). 0 = unlimited.
    pub async fn set_memory_limit(&self, bytes: u64, mode: MemLimitMode) {
        self.mem_limit_bytes.store(bytes, Ordering::Relaxed);
        let mut m = self.mem_limit_mode.lock().await;
        *m = mode;
    }

    /// Returns the configured memory limit in bytes (0 = unlimited).
    pub fn memory_limit(&self) -> u64 {
        self.mem_limit_bytes.load(Ordering::Relaxed)
    }

    /// Returns the count of connections closed due to memory pressure.
    pub fn memory_pressure_closes(&self) -> u64 {
        self.mem_pressure_closes.load(Ordering::Relaxed)
    }

    /// Inject the DNS resolver so caches can be cleared under memory pressure.
    /// Called once during startup after both the resolver and manager exist.
    pub async fn set_dns_resolver(&self, r: ThreadSafeDNSResolver) {
        let mut guard = self.dns_resolver.write().await;
        *guard = Some(Arc::downgrade(&r));
    }

    pub async fn track(&self, item: Tracked, close_notify: Sender<()>) {
        // Memory pressure check: reject NEW connections when over limit.
        // Existing connections are kept alive (network stays up, just slower).
        // When memory drops below limit, new connections are accepted again.
        let limit = self.mem_limit_bytes.load(Ordering::Relaxed);
        if limit > 0 {
            let current = self.mem_usage_cached.load(Ordering::Relaxed);
            if current > limit {
                // Memory over limit - reject this new connection.
                // close_notify signals the connection to close immediately.
                let _ = close_notify.send(());
                self.mem_pressure_rejects.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "memory pressure: {} bytes > {} limit, rejected new connection \
                     (existing conns kept alive)",
                    current, limit
                );
                return;
            }
        }

        let mut connections = self.connections.lock().await;
        connections.insert(item.id(), (item, Some(close_notify)));
    }

    /// Untrack a connection.
    /// This method is not async because it is called in Drop.
    /// When the connection has an inbound_user, its final byte counts are
    /// accumulated into `user_period_stats` so they survive connection close.
    pub fn untrack(&self, id: uuid::Uuid) {
        let connections = self.connections.clone();
        let user_period_stats = self.user_period_stats.clone();
        let closed_flows = self.closed_flows.clone();

        tokio::spawn(async move {
            // Phase 1: hold connections lock only to remove the entry.
            // We must NOT acquire user_period_stats or closed_flows while
            // holding connections, because drain_user_stats acquires
            // user_period_stats -> connections (reverse order = AB-BA
            // deadlock).
            let info = {
                let mut connections = connections.lock().await;
                connections
                    .remove(&id)
                    .map(|(tracked, _)| tracked.tracker_info())
            };
            // --- connections lock released ---

            if let Some(info) = info {
                // Phase 2: update user stats (no connections lock held).
                let upload = info.user_upload.swap(0, Ordering::AcqRel);
                let download = info.user_download.swap(0, Ordering::AcqRel);
                if let Some(ref user) = info.session_holder.inbound_user
                    && (upload > 0 || download > 0)
                {
                    let mut stats = user_period_stats.lock().await;
                    let entry = stats
                        .entry(user.clone())
                        .or_insert_with(UserTraffic::default);
                    entry.upload += upload;
                    entry.download += download;
                }

                // Phase 3: push lightweight ClosedFlowInfo to closed_flows.
                // This avoids retaining session_holder and proxy_chain_holder
                // in the ring buffer, which was the root cause of memory
                // growing after speed test stops.
                let flow = ClosedFlowInfo::from_tracker_info(&info).await;
                // info (Arc<TrackerInfo>) is dropped here — no more references
                // to the heavy Session/ProxyChain from the ring buffer.
                drop(info);
                let mut ring = closed_flows.lock().await;
                let cap = closed_flows_cap();
                ring.push_back(flow);
                while ring.len() > cap {
                    ring.pop_front();
                }
            }
        });
    }

    /// Return `Arc<TrackerInfo>` for every currently-active connection.
    /// Unlike `snapshot()`, this preserves the full `session_holder` so
    /// callers can access destination, source, and network fields directly.
    pub async fn active_connections_snapshot(&self) -> Vec<Arc<TrackerInfo>> {
        let conns = self.connections.lock().await;
        conns
            .values()
            .map(|(tracked, _)| tracked.tracker_info())
            .collect()
    }

    /// Return a snapshot of recently closed connections.
    pub async fn closed_flows_snapshot(&self) -> Vec<ClosedFlowInfo> {
        let ring = self.closed_flows.lock().await;
        ring.iter().cloned().collect()
    }

    /// Return per-user traffic accumulated since the last call (for both closed
    /// and currently-active connections) and reset all counters.
    ///
    /// Called by the `/user-stats` REST endpoint so FAC can poll for deltas.
    pub async fn drain_user_stats(&self) -> HashMap<String, UserTraffic> {
        // Drain the closed-connection accumulator.
        let mut result: HashMap<String, UserTraffic> = {
            let mut stats = self.user_period_stats.lock().await;
            std::mem::take(&mut *stats)
        };

        // Include bytes from still-active connections by atomically swapping
        // their user counters to 0. upload_total/download_total are untouched
        // so /connections keeps seeing the correct cumulative values.
        let connections = self.connections.lock().await;
        for (tracked, _) in connections.values() {
            let info = tracked.tracker_info();
            if let Some(ref user) = info.session_holder.inbound_user {
                let upload = info.user_upload.swap(0, Ordering::AcqRel);
                let download = info.user_download.swap(0, Ordering::AcqRel);
                if upload > 0 || download > 0 {
                    let entry = result.entry(user.clone()).or_default();
                    entry.upload += upload;
                    entry.download += download;
                }
            }
        }

        result
    }

    pub async fn close(&self, id: uuid::Uuid) {
        let connections = self.connections.clone();

        tokio::spawn(async move {
            let mut connections = connections.lock().await;
            if let Some((_, close_notify_opt)) = connections.get_mut(&id)
                && let Some(close_notify) = close_notify_opt.take()
            {
                let _ = close_notify.send(());
            }
        });
    }

    pub async fn close_all(&self) {
        let connections = self.connections.clone();

        let mut connections = connections.lock().await;
        for (_, close_notify_opt) in connections.values_mut() {
            if let Some(close_notify) = close_notify_opt.take() {
                let _ = close_notify.send(());
            }
        }
    }

    pub fn push_uploaded(&self, n: usize) {
        self.upload_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.upload_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn push_downloaded(&self, n: usize) {
        self.download_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.download_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn now(&self) -> (u64, u64) {
        (
            self.upload_blip.load(std::sync::atomic::Ordering::Relaxed),
            self.download_blip
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub async fn snapshot(&self) -> Snapshot {
        let mut connections = vec![];
        let conns = self.connections.lock().await;
        for v in conns.values() {
            let t = v.0.tracker_info();
            let chain = t.proxy_chain_holder.0.read().await;
            connections.push(TrackerInfo {
                uuid: t.uuid,
                upload_total: AtomicU64::new(t.upload_total.load(Ordering::Acquire)),
                download_total: AtomicU64::new(
                    t.download_total.load(Ordering::Acquire),
                ),
                start_time: t.start_time,
                proxy_chain: chain.clone(),
                rule: t.rule.clone(),
                rule_payload: t.rule_payload.clone(),
                session: t.session_holder.as_map(),
                ..Default::default()
            });
        }

        Snapshot {
            download_total: self
                .download_total
                .load(std::sync::atomic::Ordering::Relaxed),
            upload_total: self
                .upload_total
                .load(std::sync::atomic::Ordering::Relaxed),
            connections,
            memory: self.memory_usage(),
        }
    }

    #[allow(dead_code)]
    pub fn reset_statistic(&self) {
        self.upload_temp.store(0, Ordering::Relaxed);
        self.upload_blip.store(0, Ordering::Relaxed);
        self.upload_total.store(0, Ordering::Relaxed);
        self.download_temp.store(0, Ordering::Relaxed);
        self.download_blip.store(0, Ordering::Relaxed);
        self.download_total.store(0, Ordering::Relaxed);
    }

    pub fn memory_usage(&self) -> usize {
        memory_stats().map(|x| x.physical_mem).unwrap_or(0)
    }

    /// Test helper: directly populate `user_period_stats` to simulate closed
    /// connections without going through the full `Tracked` machinery.
    #[cfg(test)]
    pub async fn inject_closed_user_bytes(
        &self,
        user: &str,
        upload: u64,
        download: u64,
    ) {
        let mut stats = self.user_period_stats.lock().await;
        let entry = stats.entry(user.to_string()).or_default();
        entry.upload += upload;
        entry.download += download;
    }

    /// Stop the background ticker and release injected references.
    pub async fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let mut guard = self.dns_resolver.write().await;
        *guard = None;
    }

    async fn kick_off(&self) {
        // Memory check runs every 5 seconds (not every 1s) to reduce CPU load.
        // Traffic blip still updates every 1s.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut mem_check_counter: u32 = 0;
        while self.running.load(Ordering::Relaxed) {
            ticker.tick().await;
            self.upload_blip
                .store(self.upload_temp.load(Ordering::Relaxed), Ordering::Relaxed);
            self.upload_temp.store(0, Ordering::Relaxed);
            self.download_blip.store(
                self.download_temp.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.download_temp.store(0, Ordering::Relaxed);

            // Memory pressure check every 5 seconds
            mem_check_counter += 1;
            if mem_check_counter >= 5 {
                mem_check_counter = 0;
                self.check_memory_pressure().await;
            }
        }
    }

    /// Check memory usage and take action if over the limit.
    ///
    /// Strategy (network stays up, just slower):
    /// - New connections are rejected in `track()` when over limit (soft &
    ///   hard)
    /// - Soft mode: only reject new connections, keep all existing alive
    /// - Hard mode: also close existing connections when severely over limit
    ///   (2x) to prevent OOM crash. This is last-resort, only triggers at 2x
    ///   limit.
    ///
    /// When memory drops below limit, all restrictions auto-clear.
    ///
    /// **Business-layer cache cleanup** (both modes, when over 1x limit):
    /// - Clear `closed_flows` ring buffer (frees TrackerInfo with Session
    ///   strings)
    /// - Clear DNS reverse_lookup_cache via injected resolver
    ///
    /// This releases references so jemalloc can reclaim pages (with short
    /// decay_ms configured in main.rs, pages return to OS within ~1
    /// second).
    async fn check_memory_pressure(&self) {
        let limit = self.mem_limit_bytes.load(Ordering::Relaxed);
        if limit == 0 {
            return;
        }

        let current = self.memory_usage();
        self.mem_usage_cached
            .store(current as u64, Ordering::Relaxed);
        // Fix(2026-08-04): keep u64 on 32-bit targets (`as usize` truncates
        // limits >= 4GiB to 0).
        let limit_u64 = limit;

        // --- Business-layer cache cleanup (both modes, when over 1x limit) ---
        // Free references so jemalloc can reclaim pages.  This is the primary
        // mechanism for RSS reduction: without freeing the objects, no amount
        // of allocator tuning will help.
        if (current as u64) > limit_u64 {
            // 1. Clear closed_flows ring buffer (biggest business-layer cache)
            {
                let mut ring = self.closed_flows.lock().await;
                let freed = ring.len();
                if freed > 0 {
                    ring.clear();
                    warn!(
                        "memory pressure: cleared {} closed_flows entries ({} \
                         bytes > {} limit)",
                        freed, current, limit_u64
                    );
                }
            }

            // 2. Clear DNS caches (reverse_lookup_cache & lru_cache)
            // Fix(2026-08-04): upgrade Weak resolver ref before .await to avoid
            // holding the read lock across the async boundary, which can
            // deadlock set_dns_resolver().
            {
                let guard = self.dns_resolver.read().await;
                let resolver_opt = guard.as_ref().and_then(|w| w.upgrade());
                drop(guard);
                if let Some(r) = resolver_opt {
                    r.clear_cache().await;
                }
            }
        }

        // --- Existing-connection closure (Hard mode only, at configurable
        // ratio) ---
        let mode = *self.mem_limit_mode.lock().await;
        let ratio_x100 = self.mem_hard_ratio_x100.load(Ordering::Relaxed);
        match mode {
            MemLimitMode::None | MemLimitMode::Soft => {
                // Soft mode: never close existing connections.
                // New connections are already rejected in track().
            }
            MemLimitMode::Hard if ratio_x100 == 0 => {
                // User explicitly disabled Hard mode
                // (CLASH_RS_MEM_HARD_RATIO=0). They prefer OOM
                // kill over forced connection drop.
            }
            MemLimitMode::Hard => {
                // Hard mode: close some existing connections when memory
                // exceeds the configured ratio (default 2x) of
                // the limit.
                //
                // Re-read memory AFTER cache cleanup above: clearing
                // closed_flows / DNS caches frees references, and while
                // jemalloc decay takes time, the dropped allocations themselves
                // are immediate.  Using the stale pre-cleanup value would risk
                // closing connections that are no longer necessary.
                let current = self.memory_usage();
                // Fix(2026-08-04): clamp u128 -> usize (32-bit safety).
                let threshold = ((limit_u64 as u128 * ratio_x100 as u128 / 100)
                    .min(usize::MAX as u128))
                    as usize;
                if current <= threshold {
                    return;
                }

                // --- Phase 1: hold the lock only to collect candidates ---
                // We must NOT call close_notify.send() while holding the
                // connections lock: send() can block (if the receiver is slow
                // or dropped), which would stall the entire routing table and
                // freeze all new connections.  Read-decide-remove under the
                // lock, then drop the lock before signaling.
                let (count, to_close, mut pending_close) = {
                    let mut connections = self.connections.lock().await;
                    let count = connections.len() as u64;
                    if count == 0 {
                        return;
                    }

                    // Smart eviction: prioritize closing connections that are
                    // (a) UDP (cheaper to reconnect — P2P/QUIC retransmit)
                    // (b) idle (lowest total bytes transferred)
                    // This avoids killing active TCP streams (SSH, video,
                    // downloads).
                    let mut candidates: Vec<(uuid::Uuid, u64, bool)> = connections
                        .iter()
                        .filter(|(_, (_, close_notify_opt))| {
                            close_notify_opt.is_some()
                        })
                        .map(|(id, (tracked, _))| {
                            let info = tracked.tracker_info();
                            let bytes = info.upload_total.load(Ordering::Relaxed)
                                + info.download_total.load(Ordering::Relaxed);
                            let is_udp = info.session_holder.network
                                == crate::session::Network::Udp;
                            (*id, bytes, is_udp)
                        })
                        .collect();
                    // Sort: UDP first (evict before TCP), then by ascending
                    // bytes (idle before active).  Stable
                    // sort keeps insertion order
                    // for ties (older connections evicted first).
                    candidates.sort_by(|a, b| {
                        // UDP (true) sorts before TCP (false)
                        b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1))
                    });

                    // Close only the bottom 20% (not 50%) to keep network
                    // partially up — gives the system room to recover.
                    // .max(1) guarantees we always evict at least one
                    // connection when triggered (avoids the integer-division
                    // trap where 2 * 20 / 100 == 0).
                    let to_close = (count * HARD_CLOSE_FRACTION_NUM
                        / HARD_CLOSE_FRACTION_DEN)
                        .max(1) as usize;

                    // Take the close notifiers WITHOUT removing the connection
                    // entries from the map. When the connection tasks receive
                    // close_notify, they terminate and invoke `untrack(id)`
                    // naturally on drop, which finalizes their full byte counts
                    // in /flows and /user-stats after traffic has completely
                    // stopped.
                    let mut pending: Vec<Sender<()>> = Vec::with_capacity(to_close);
                    for (id, ..) in candidates {
                        if pending.len() >= to_close {
                            break;
                        }
                        if let Some((_, close_notify_opt)) = connections.get_mut(&id)
                            && let Some(close_notify) = close_notify_opt.take()
                        {
                            pending.push(close_notify);
                        }
                    }
                    (count, to_close, pending)
                };
                // --- Lock released ---

                // --- Phase 2: signal closure outside the lock ---
                let mut closed = 0u64;
                for close_notify in pending_close.drain(..) {
                    let _ = close_notify.send(());
                    closed += 1;
                }

                if closed > 0 {
                    self.mem_pressure_closes
                        .fetch_add(closed, Ordering::Relaxed);
                    warn!(
                        "memory pressure SEVERE: {} bytes > {}x{} limit, \
                         smart-evicted {}/{} connections (target {}, UDP+idle \
                         first, hard mode)",
                        current, ratio_x100, limit_u64, closed, count, to_close
                    );
                }
            }
        }
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drain_user_stats_empty() {
        let mgr = Manager::new();
        let stats = mgr.drain_user_stats().await;
        assert!(stats.is_empty(), "fresh manager should have no user stats");
    }

    #[tokio::test]
    async fn test_drain_user_stats_returns_closed_connection_bytes() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 1000, 2000).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 1000);
        assert_eq!(u.download, 2000);
    }

    #[tokio::test]
    async fn test_drain_user_stats_resets_on_read() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 500, 750).await;

        let first = mgr.drain_user_stats().await;
        assert!(!first.is_empty());

        let second = mgr.drain_user_stats().await;
        assert!(
            second.is_empty(),
            "second drain should be empty after reset"
        );
    }

    #[tokio::test]
    async fn test_drain_user_stats_multiple_users() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("alice", 100, 200).await;
        mgr.inject_closed_user_bytes("bob", 300, 400).await;

        let stats = mgr.drain_user_stats().await;
        assert_eq!(stats.len(), 2);
        assert_eq!(stats["alice"].upload, 100);
        assert_eq!(stats["alice"].download, 200);
        assert_eq!(stats["bob"].upload, 300);
        assert_eq!(stats["bob"].download, 400);
    }

    #[tokio::test]
    async fn test_drain_user_stats_accumulates_across_connections() {
        let mgr = Manager::new();
        // Same user closes two separate connections before a drain.
        mgr.inject_closed_user_bytes("user1", 100, 200).await;
        mgr.inject_closed_user_bytes("user1", 50, 80).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 150, "upload should be sum of both connections");
        assert_eq!(
            u.download, 280,
            "download should be sum of both connections"
        );
    }
}
