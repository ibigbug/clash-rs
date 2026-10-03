use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::Request,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};

use http::StatusCode;
use tracing::instrument;

use crate::{
    RuntimeComponents,
    app::{
        api::{
            AppState,
            handlers::utils::{DelayRequest, group_url_test},
        },
        outbound::manager::ThreadSafeOutboundManager,
    },
    proxy::AnyOutboundHandler,
};

#[derive(Clone)]
pub struct GroupState {
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
}

impl GroupState {
    fn outbound_manager(&self) -> ThreadSafeOutboundManager {
        self.components.read().unwrap().outbound_manager.clone()
    }
}

pub fn routes(
    components: Arc<RwLock<Arc<RuntimeComponents>>>,
) -> Router<Arc<AppState>> {
    let state = GroupState { components };
    Router::new()
        .nest(
            "/{name}",
            Router::new()
                .route("/delay", get(get_group_delay))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    find_group_by_name,
                ))
                .with_state(state.clone()),
        )
        .with_state(state)
}

async fn find_group_by_name(
    State(state): State<GroupState>,
    Path(name): Path<String>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let outbound_manager = state.outbound_manager();
    match outbound_manager.get_outbound(&name).await {
        Some(proxy) => {
            req.extensions_mut().insert(outbound_manager);
            req.extensions_mut().insert(proxy);
            next.run(req).await
        }
        _ => (StatusCode::NOT_FOUND, format!("group {name} not found"))
            .into_response(),
    }
}

#[instrument(skip_all, fields(name = %proxy.name()))]
async fn get_group_delay(
    Extension(outbound_manager): Extension<ThreadSafeOutboundManager>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let timeout = Duration::from_millis(q.timeout.into());
    let name = proxy.name().to_owned();

    if proxy.try_as_group_handler().is_some() {
        let (actual, _) =
            match group_url_test(&outbound_manager, proxy, &q.url, timeout).await {
                Ok(result) => result,
                Err(err) => {
                    return (StatusCode::BAD_REQUEST, err.to_string())
                        .into_response();
                }
            };
        let mut res = HashMap::new();
        res.insert(name, actual.as_millis());
        Json(res).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            format!("proxy {} is not a group", proxy.name()),
        )
            .into_response()
    }
}
