use std::sync::{Arc, RwLock};

use axum::{
    Json, Router, extract::State, http::StatusCode, response::IntoResponse,
    routing::post,
};
use serde_json::json;

use crate::{RuntimeComponents, app::api::AppState};

#[derive(Clone)]
struct CacheState {
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
}

pub fn routes(
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
) -> Router<Arc<AppState>> {
    let state = CacheState { components };
    Router::new()
        .route("/fakeip/flush", post(flush_fakeip))
        .route("/dns/flush", post(flush_dns))
        .with_state(state)
}

async fn flush_fakeip(State(state): State<CacheState>) -> impl IntoResponse {
    let resolver = state.components.read().unwrap().dns_resolver.clone();
    if !resolver.fake_ip_enabled() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "message": "fakeip is not enabled"
            })),
        )
            .into_response();
    }
    resolver.flush_fakeip().await;
    StatusCode::NO_CONTENT.into_response()
}

async fn flush_dns(State(state): State<CacheState>) -> impl IntoResponse {
    let resolver = state.components.read().unwrap().dns_resolver.clone();
    resolver.clear_cache().await;
    StatusCode::NO_CONTENT.into_response()
}
