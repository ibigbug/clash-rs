use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade, ws::Message},
    response::IntoResponse,
};

use serde::Serialize;
use tracing::warn;

use crate::app::api::AppState;

#[derive(Serialize)]
struct TrafficResponse {
    up: u64,
    down: u64,
}
pub async fn handle(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_failed_upgrade(move |e| {
        warn!("ws upgrade error: {} with {}", e, addr);
    })
    .on_upgrade(move |mut socket| async move {
        loop {
            let (up, down) = state.statistics_manager().now();
            let res = TrafficResponse { up, down };
            let j_str = match serde_json::to_string(&res) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to serialize traffic stats: {}", e);
                    continue;
                }
            };

            if let Err(e) = socket.send(Message::Text(j_str.into())).await {
                warn!("ws send error: {}", e);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
}
