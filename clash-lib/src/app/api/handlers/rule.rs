use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use axum::{Router, extract::State, response::IntoResponse, routing::get};

use crate::{RuntimeComponents, app::api::AppState};

#[derive(Clone)]
struct RuleState {
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
}

pub fn routes(
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
) -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(get_rules))
        .with_state(RuleState { components })
}

async fn get_rules(State(state): State<RuleState>) -> impl IntoResponse {
    let comps = state.components.read().unwrap().clone();
    let rules = comps.router.get_all_rules();
    let mut r = HashMap::new();
    r.insert(
        "rules",
        rules.iter().map(|r| r.as_map()).collect::<Vec<_>>(),
    );
    axum::response::Json(r)
}
