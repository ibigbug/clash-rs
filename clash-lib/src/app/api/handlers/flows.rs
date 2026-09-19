use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    app::{api::AppState, dispatcher::StatisticsManager},
    session::Network,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct FlowState {
    pub statistics_manager: Arc<StatisticsManager>,
}

pub fn routes(statistics_manager: Arc<StatisticsManager>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(handle))
        .with_state(FlowState { statistics_manager })
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FlowQuery {
    /// Maximum number of flow records to return (default 20).
    pub top: Option<usize>,
    /// Field to group by (currently only "dst_host" is supported, kept for
    /// forward compatibility).
    #[allow(dead_code)]
    pub group_by: Option<String>,
    /// Whether to include recently-closed connections (default true).
    pub include_closed: Option<bool>,
    /// WebSocket polling interval in seconds (default 5, min 1).
    #[allow(dead_code)]
    pub interval: Option<u64>,
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FlowRecord {
    pub dst_host: String,
    pub dst_port: u16,
    pub protocol: String,
    pub src_ips: Vec<String>,
    pub conn_count: usize,
    pub active_count: usize,
    pub closed_count: usize,
    pub upload_total: u64,
    pub download_total: u64,
    pub bytes_total: u64,
    pub rule: String,
    pub rule_payload: String,
    pub chains: Vec<String>,
    /// ISO 3166-1 alpha-2 country code from country mmdb.
    pub country: Option<String>,
    /// ASN org name from ASN mmdb.
    pub asn: Option<String>,
    pub last_seen: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Aggregation key
// ---------------------------------------------------------------------------

#[derive(Hash, PartialEq, Eq)]
struct FlowKey {
    dst_host: String,
    dst_port: u16,
    protocol: String,
}

// ---------------------------------------------------------------------------
// Per-key accumulator
// ---------------------------------------------------------------------------

/// Data extracted from one connection tracker, passed into `Acc::apply`.
struct ConnEntry {
    src_ip: String,
    upload: u64,
    download: u64,
    rule: String,
    rule_payload: String,
    chains: Vec<String>,
    country: Option<String>,
    asn: Option<String>,
    start_time: DateTime<Utc>,
    is_active: bool,
}

struct Acc {
    src_ips: Vec<String>,
    conn_count: usize,
    active_count: usize,
    closed_count: usize,
    upload_total: u64,
    download_total: u64,
    rule: String,
    rule_payload: String,
    chains: Vec<String>,
    country: Option<String>,
    asn: Option<String>,
    last_seen: DateTime<Utc>,
}

impl Acc {
    fn apply(&mut self, entry: ConnEntry) {
        if !entry.src_ip.is_empty() && !self.src_ips.contains(&entry.src_ip) {
            self.src_ips.push(entry.src_ip);
        }
        self.conn_count += 1;
        if entry.is_active {
            self.active_count += 1;
        } else {
            self.closed_count += 1;
        }
        self.upload_total += entry.upload;
        self.download_total += entry.download;
        if self.rule.is_empty() && !entry.rule.is_empty() {
            self.rule = entry.rule;
        }
        if self.rule_payload.is_empty() && !entry.rule_payload.is_empty() {
            self.rule_payload = entry.rule_payload;
        }
        if self.chains.is_empty() && !entry.chains.is_empty() {
            self.chains = entry.chains;
        }
        if self.country.is_none() && entry.country.is_some() {
            self.country = entry.country;
        }
        if self.asn.is_none() && entry.asn.is_some() {
            self.asn = entry.asn;
        }
        if entry.start_time > self.last_seen {
            self.last_seen = entry.start_time;
        }
    }
}

// ---------------------------------------------------------------------------
// Core aggregation logic
// ---------------------------------------------------------------------------

async fn build_flow_records(
    mgr: &StatisticsManager,
    top: usize,
    include_closed: bool,
) -> Vec<FlowRecord> {
    use std::sync::atomic::Ordering;

    let mut map: HashMap<FlowKey, Acc> = HashMap::new();

    // Helper to insert/merge one TrackerInfo into the map.
    macro_rules! merge_info {
        ($info:expr, $chains:expr, $is_active:expr) => {{
            let info = $info;
            let dst_host = info.session_holder.destination.host();
            let dst_port = info.session_holder.destination.port();
            let protocol = match info.session_holder.network {
                Network::Tcp => "tcp".to_string(),
                Network::Udp => "udp".to_string(),
            };
            let key = FlowKey {
                dst_host,
                dst_port,
                protocol,
            };
            let acc = map.entry(key).or_insert_with(|| Acc {
                src_ips: Vec::new(),
                conn_count: 0,
                active_count: 0,
                closed_count: 0,
                upload_total: 0,
                download_total: 0,
                rule: String::new(),
                rule_payload: String::new(),
                chains: Vec::new(),
                country: None,
                asn: None,
                last_seen: DateTime::<Utc>::MIN_UTC,
            });
            acc.apply(ConnEntry {
                src_ip: info.session_holder.source.ip().to_string(),
                upload: info.upload_total.load(Ordering::Relaxed),
                download: info.download_total.load(Ordering::Relaxed),
                rule: info.rule.clone(),
                rule_payload: info.rule_payload.clone(),
                chains: $chains,
                country: info.session_holder.country.clone(),
                asn: info.session_holder.asn.clone(),
                start_time: info.start_time,
                is_active: $is_active,
            });
        }};
    }

    // Active connections — use active_connections_snapshot so session_holder
    // is preserved (snapshot() materialises a reduced view that drops it).
    let active = mgr.active_connections_snapshot().await;
    for info in &active {
        let chains = info.proxy_chain_holder.snapshot().await;
        merge_info!(info, chains, true);
    }

    // Closed connections (ring buffer) — uses ClosedFlowInfo which has
    // pre-extracted concrete fields (no session_holder/proxy_chain_holder
    // needed).
    if include_closed {
        let closed = mgr.closed_flows_snapshot().await;
        for info in &closed {
            let key = FlowKey {
                dst_host: info.host.clone(),
                dst_port: info.destination_port,
                protocol: info.network.clone(),
            };
            let acc = map.entry(key).or_insert_with(|| Acc {
                src_ips: Vec::new(),
                conn_count: 0,
                active_count: 0,
                closed_count: 0,
                upload_total: 0,
                download_total: 0,
                rule: String::new(),
                rule_payload: String::new(),
                chains: Vec::new(),
                country: None,
                asn: None,
                last_seen: DateTime::<Utc>::MIN_UTC,
            });
            acc.apply(ConnEntry {
                src_ip: info.source_ip.clone(),
                upload: info.upload_total,
                download: info.download_total,
                rule: info.rule.clone(),
                rule_payload: info.rule_payload.clone(),
                chains: info.proxy_chain.clone(),
                country: info.country.clone(),
                asn: info.asn.clone(),
                start_time: info.start_time,
                is_active: false,
            });
        }
    }

    // Convert accumulator map → sorted FlowRecord list.
    let mut records: Vec<FlowRecord> = map
        .into_iter()
        .map(|(key, acc)| {
            let bytes_total = acc.upload_total + acc.download_total;
            FlowRecord {
                dst_host: key.dst_host,
                dst_port: key.dst_port,
                protocol: key.protocol,
                src_ips: acc.src_ips,
                conn_count: acc.conn_count,
                active_count: acc.active_count,
                closed_count: acc.closed_count,
                upload_total: acc.upload_total,
                download_total: acc.download_total,
                bytes_total,
                rule: acc.rule,
                rule_payload: acc.rule_payload,
                chains: acc.chains,
                country: acc.country,
                asn: acc.asn,
                last_seen: acc.last_seen,
            }
        })
        .collect();

    records.sort_by_key(|r| std::cmp::Reverse(r.bytes_total));
    records.truncate(top);
    records
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn handle(
    State(state): State<FlowState>,
    Query(q): Query<FlowQuery>,
) -> impl IntoResponse {
    let top = q.top.unwrap_or(20).clamp(1, 500);
    let include_closed = q.include_closed.unwrap_or(true);

    let records =
        build_flow_records(&state.statistics_manager, top, include_closed).await;
    Json(records).into_response()
}

// ---------------------------------------------------------------------------
// WebSocket handler (used from websocket.rs via AppState)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WsFlowQuery {
    pub interval: Option<u64>,
    pub top: Option<usize>,
    pub include_closed: Option<bool>,
}

pub async fn ws_handle(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(q): Query<WsFlowQuery>,
) -> impl IntoResponse {
    let top = q.top.unwrap_or(20).clamp(1, 500);
    let include_closed = q.include_closed.unwrap_or(true);
    let interval_secs = q.interval.unwrap_or(5).max(1);

    let callback = async move |mut socket: axum::extract::ws::WebSocket| {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            let records =
                build_flow_records(&state.statistics_manager, top, include_closed)
                    .await;
            let body = match serde_json::to_string(&records) {
                Ok(s) => s,
                Err(e) => {
                    warn!("failed to serialize flow records: {}", e);
                    break;
                }
            };
            if let Err(e) = socket.send(Message::Text(body.into())).await {
                debug!("ws/flows send error: {}", e);
                break;
            }
        }
    };

    ws.on_failed_upgrade(|e| warn!("ws/flows upgrade error: {}", e))
        .on_upgrade(async move |socket| {
            callback(socket).await;
        })
}
