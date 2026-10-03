use std::sync::{Arc, RwLock};

use axum::{
    Json, Router,
    body::Body,
    extract::{
        FromRequest, Path, Query, Request, State, WebSocketUpgrade, ws::Message,
    },
    response::IntoResponse,
    routing::{delete, get},
};
use http::HeaderMap;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{
    RuntimeComponents,
    app::{
        api::{AppState, handlers::utils::is_request_websocket},
        dispatcher::StatisticsManager,
    },
};

#[derive(Clone)]
struct ConnectionState {
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
}

impl ConnectionState {
    fn statistics_manager(&self) -> Arc<StatisticsManager> {
        self.components.read().unwrap().statistics_manager.clone()
    }
}

pub fn routes(
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_connections).delete(close_all_connection))
        .route("/{id}", delete(close_connection))
        .with_state(ConnectionState { components })
}

#[derive(Deserialize)]
pub struct GetConnectionsQuery {
    pub interval: Option<u64>,
}

async fn get_connections(
    headers: HeaderMap,
    State(state): State<ConnectionState>,
    q: Query<GetConnectionsQuery>,
    req: Request<Body>,
) -> impl IntoResponse {
    if !is_request_websocket(&headers) {
        let mgr = state.statistics_manager();
        let snapshot = mgr.snapshot().await;
        return Json(snapshot).into_response();
    }

    let ws = match WebSocketUpgrade::from_request(req, &state).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!("ws upgrade error: {}", e);
            return e.into_response();
        }
    };

    ws.on_failed_upgrade(|e| {
        warn!("ws upgrade error: {}", e);
    })
    .on_upgrade(move |mut socket| async move {
        let interval = q.interval;

        loop {
            let snapshot = state.statistics_manager().snapshot().await;
            let body = match serde_json::to_string(&snapshot) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to serialize connection snapshot: {}", e);
                    continue;
                }
            };

            if let Err(e) = socket.send(Message::Text(body.into())).await {
                // likely client gone
                debug!("ws send error: {}", e);
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(
                interval.unwrap_or(1).max(1),
            ))
            .await;
        }
    })
}

async fn close_connection(
    State(state): State<ConnectionState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager();
    mgr.close(id).await;
    format!("connection {id} closed").into_response()
}

async fn close_all_connection(
    State(state): State<ConnectionState>,
) -> impl IntoResponse {
    let mgr = state.statistics_manager();
    mgr.close_all().await;
    "all connections closed".into_response()
}
