use std::sync::Arc;

use axum::{Json, extract::State};

use crate::app::{api::AppState, dispatcher::StatisticsManager};

/// `GET /user-stats`
///
/// Returns per-`inboundUser` traffic accumulated since the last call, then
/// resets all counters.  Intended for FAC to poll periodically (≤ every 60 s).
///
/// Response: `{ "<user_id>": { "upload": <bytes>, "download": <bytes> }, … }`
pub async fn handle(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mgr: Arc<StatisticsManager> = state.statistics_manager();
    let stats = mgr.drain_user_stats().await;
    Json(
        serde_json::to_value(stats)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
    )
}
