use std::sync::Arc;

use axum::{Json, extract::State, response::IntoResponse};

use serde::{Deserialize, Serialize};

use crate::app::api::AppState;

#[derive(Deserialize)]
pub struct GetMemoryQuery {
    pub interval: Option<u64>,
}

#[derive(Serialize)]
pub struct GetMemoryResponse {
    pub inuse: usize,
    pub oslimit: usize,
}

pub async fn handle(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mgr = state.statistics_manager.clone();
    let snapshot = GetMemoryResponse {
        inuse: mgr.memory_usage(),
        oslimit: usize::try_from(mgr.memory_limit()).unwrap_or(usize::MAX),
    };
    Json(snapshot).into_response()
}
