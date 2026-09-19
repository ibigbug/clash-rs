use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use axum::{
    Extension, Router,
    extract::{Path, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    app::{
        api::AppState, outbound::manager::ThreadSafeOutboundManager,
        remote_content_manager::providers::proxy_provider::ArcProxyProvider,
        router::ArcRouter,
    },
    proxy::AnyOutboundHandler,
    session::{Network, Session, SocksAddr, Type},
};
#[derive(Clone)]
struct ProviderState {
    outbound_manager: ThreadSafeOutboundManager,
}

pub fn routes(outbound_manager: ThreadSafeOutboundManager) -> Router<Arc<AppState>> {
    let state = ProviderState { outbound_manager };
    Router::new()
        .route("/", get(get_providers))
        .nest(
            "/{provider_name}",
            Router::new()
                .route("/", get(get_provider).put(update_provider))
                .route("/healthcheck", get(provider_healthcheck))
                .nest(
                    "/{proxy_name}",
                    Router::new()
                        .route("/", get(get_proxy))
                        .route("/healthcheck", get(get_proxy_delay))
                        .layer(middleware::from_fn_with_state(
                            state.clone(),
                            find_proxy_provider_proxy_by_name,
                        ))
                        .with_state(state.clone()),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    find_proxy_provider_by_name,
                ))
                .with_state(state.clone()),
        )
        .with_state(state)
}

async fn get_providers(State(state): State<ProviderState>) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let mut res = HashMap::new();

    let mut providers = HashMap::new();

    for (name, p) in outbound_manager.get_proxy_providers() {
        let proxies = p.proxies().await;
        let proxies = futures::future::join_all(
            proxies.iter().map(|x| outbound_manager.get_proxy(x)),
        );
        let mut m = p.as_map().await;
        m.insert("proxies".to_owned(), Box::new(proxies.await));
        providers.insert(name, m);
    }

    res.insert("providers".to_owned(), providers);
    axum::response::Json(res)
}

#[derive(Deserialize)]
struct ProviderNamePath {
    provider_name: String,
}
async fn find_proxy_provider_by_name(
    State(state): State<ProviderState>,
    Path(ProviderNamePath { provider_name }): Path<ProviderNamePath>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let outbound_manager = state.outbound_manager.clone();
    match outbound_manager.get_proxy_provider(&provider_name) {
        Some(provider) => {
            req.extensions_mut().insert(provider);
            next.run(req).await
        }
        _ => (
            StatusCode::NOT_FOUND,
            format!("proxy provider {provider_name} not found"),
        )
            .into_response(),
    }
}

async fn get_provider(
    Extension(provider): Extension<ArcProxyProvider>,
) -> impl IntoResponse {
    axum::response::Json(provider.as_map().await)
}

async fn update_provider(
    Extension(provider): Extension<ArcProxyProvider>,
) -> impl IntoResponse {
    match provider.update().await {
        Ok(_) => (
            StatusCode::ACCEPTED,
            axum::response::Json(json!({"message": "provider update started"})),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "update proxy provider {} failed with error {}",
                provider.name(),
                err
            ),
        )
            .into_response(),
    }
}

async fn provider_healthcheck(
    Extension(provider): Extension<ArcProxyProvider>,
) -> impl IntoResponse {
    provider.healthcheck().await;

    (
        StatusCode::ACCEPTED,
        axum::response::Json(json!({"message": "provider healthcheck started"})),
    )
}

#[derive(Deserialize)]
struct ProviderProxyPath {
    proxy_name: String,
}
async fn find_proxy_provider_proxy_by_name(
    Extension(provider): Extension<ArcProxyProvider>,
    Path(ProviderProxyPath { proxy_name }): Path<ProviderProxyPath>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let proxies = provider.proxies().await;
    let proxy = proxies.iter().find(|x| x.name() == proxy_name);

    if let Some(proxy) = proxy {
        req.extensions_mut().insert(proxy.clone());
        next.run(req).await
    } else {
        (
            StatusCode::NOT_FOUND,
            format!(
                "proxy {} not found in provider {}",
                proxy_name,
                provider.name()
            ),
        )
            .into_response()
    }
}

async fn get_proxy(
    Extension(proxy): Extension<AnyOutboundHandler>,
    State(state): State<ProviderState>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    axum::response::Json(outbound_manager.get_proxy(&proxy).await)
}

#[derive(Deserialize)]
struct DelayRequest {
    url: String,
    timeout: u16,
}
async fn get_proxy_delay(
    State(state): State<ProviderState>,
    Extension(proxy): Extension<AnyOutboundHandler>,
    Query(q): Query<DelayRequest>,
) -> impl IntoResponse {
    let outbound_manager = state.outbound_manager.clone();
    let timeout = Duration::from_millis(q.timeout.into());
    let n = proxy.name().to_owned();
    let result = outbound_manager
        .url_test(&vec![proxy], &q.url, timeout, true)
        .await;
    match result.first().unwrap() {
        Ok((actual, overall)) => {
            let mut r = HashMap::new();
            r.insert("delay".to_owned(), actual.as_millis());
            r.insert("overall".to_owned(), overall.as_millis());
            axum::response::Json(r).into_response()
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            format!("get delay for {n} failed with error: {err}"),
        )
            .into_response(),
    }
}

// ── Rule provider routes ────────────────────────────────────────────────────

#[derive(Clone)]
struct RuleProviderState {
    router: ArcRouter,
}

pub fn rule_routes(router: ArcRouter) -> Router<Arc<AppState>> {
    let state = RuleProviderState { router };
    Router::new()
        .route("/", get(get_rule_providers))
        .route(
            "/{provider_name}",
            get(get_rule_provider).put(update_rule_provider),
        )
        .route("/{provider_name}/rules", get(get_rule_provider_rules))
        .route("/{provider_name}/match", get(match_rule_provider))
        .with_state(state)
}

async fn get_rule_providers(
    State(state): State<RuleProviderState>,
) -> impl IntoResponse {
    let mut providers = HashMap::new();
    for (name, p) in state.router.get_rule_providers() {
        providers.insert(name.clone(), p.as_map().await);
    }
    let mut res = HashMap::new();
    res.insert("providers", providers);
    axum::response::Json(res)
}

#[derive(Deserialize)]
struct RuleProviderNamePath {
    provider_name: String,
}

async fn get_rule_provider(
    State(state): State<RuleProviderState>,
    Path(RuleProviderNamePath { provider_name }): Path<RuleProviderNamePath>,
) -> impl IntoResponse {
    match state.router.get_rule_providers().get(&provider_name) {
        Some(p) => axum::response::Json(p.as_map().await).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            format!("rule provider {provider_name} not found"),
        )
            .into_response(),
    }
}

async fn update_rule_provider(
    State(state): State<RuleProviderState>,
    Path(RuleProviderNamePath { provider_name }): Path<RuleProviderNamePath>,
) -> impl IntoResponse {
    match state.router.get_rule_providers().get(&provider_name) {
        Some(p) => match p.update().await {
            Ok(_) => (
                StatusCode::ACCEPTED,
                axum::response::Json(
                    json!({"message": "rule provider update started"}),
                ),
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("update rule provider {provider_name} failed: {err}"),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            format!("rule provider {provider_name} not found"),
        )
            .into_response(),
    }
}

async fn get_rule_provider_rules(
    State(state): State<RuleProviderState>,
    Path(RuleProviderNamePath { provider_name }): Path<RuleProviderNamePath>,
) -> impl IntoResponse {
    match state.router.get_rule_providers().get(&provider_name) {
        Some(p) => {
            let rules = p.list_rules(500).await;
            let mut res = HashMap::new();
            res.insert("rules", rules);
            axum::response::Json(res).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            format!("rule provider {provider_name} not found"),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct MatchQuery {
    target: String,
}

#[derive(Serialize)]
struct MatchResponse {
    #[serde(rename = "match")]
    matched: bool,
}

async fn match_rule_provider(
    State(state): State<RuleProviderState>,
    Path(RuleProviderNamePath { provider_name }): Path<RuleProviderNamePath>,
    Query(q): Query<MatchQuery>,
) -> impl IntoResponse {
    let Some(p) = state.router.get_rule_providers().get(&provider_name) else {
        return (
            StatusCode::NOT_FOUND,
            format!("rule provider {provider_name} not found"),
        )
            .into_response();
    };

    let destination = match SocksAddr::from_str(&q.target) {
        Ok(addr) => addr,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid target").into_response();
        }
    };

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Http,
        source: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        destination,
        resolved_ip: None,
        so_mark: None,
        iface: None,
        asn: None,
        country: None,
        traffic_stats: None,
        inbound_user: None,
    };

    axum::response::Json(MatchResponse {
        matched: p.search(&sess),
    })
    .into_response()
}
