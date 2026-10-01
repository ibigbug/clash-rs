use std::{collections::HashMap, sync::Arc, time::Duration};

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
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = GroupState { outbound_manager };
    Router::new()
        .route("/", get(get_groups))
        .nest(
            "/{name}",
            Router::new()
                .route("/", get(get_group))
                .route("/delay", get(get_group_delay))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    find_group_by_name,
                ))
                .with_state(state.clone()),
        )
        .with_state(state)
}

async fn get_groups(State(state): State<GroupState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let mut res = HashMap::new();
    let groups = outbound_manager.get_groups().await;
    res.insert("proxies".to_owned(), groups);
    Json(res)
}

async fn get_group(
    Extension(proxy): Extension<AnyOutboundHandler>,
    State(state): State<GroupState>,
) -> impl IntoResponse {
    if proxy.try_as_group_handler().is_none() {
        return (
            StatusCode::NOT_FOUND,
            format!("proxy {} is not a group", proxy.name()),
        )
            .into_response();
    }
    let outbound_manager = state.outbound_manager.clone();
    Json(outbound_manager.get_proxy(&proxy).await).into_response()
}

async fn find_group_by_name(
    State(state): State<GroupState>,
    Path(name): Path<String>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let outbound_manager = state.outbound_manager.clone();
    match outbound_manager.get_outbound(&name).await {
        Some(proxy) => {
            req.extensions_mut().insert(proxy);
            next.run(req).await
        }
        _ => (StatusCode::NOT_FOUND, format!("group {name} not found"))
            .into_response(),
    }
}

#[instrument(skip_all, fields(name = %proxy.name()))]
async fn get_group_delay(
    State(state): State<GroupState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
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
