use std::{
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
};

use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use http::{Method, header};
use tokio::sync::{Mutex, broadcast::Sender};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, Any, CorsLayer},
    services::ServeDir,
    trace::TraceLayer,
};
use tracing::{debug, error, info, warn};

use crate::{
    GlobalState,
    app::{
        api::{AppState, handlers, ipc, middlewares, websocket},
        dispatcher::{self, StatisticsManager},
        dns::{ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        outbound::manager::ThreadSafeOutboundManager,
        profile::ThreadSafeCacheFile,
        router::ArcRouter,
    },
    config::config::Controller,
    runner::Runner,
};

pub struct ApiRunner {
    controller_cfg: Controller,
    log_source: Sender<LogEvent>,
    inbound_manager: Arc<InboundManager>,
    dispatcher: Arc<dispatcher::Dispatcher>,
    global_state: Arc<Mutex<GlobalState>>,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: ThreadSafeOutboundManager,
    statistics_manager: Arc<StatisticsManager>,
    cache_store: ThreadSafeCacheFile,
    router: ArcRouter,
    cwd: String,

    cancellation_token: tokio_util::sync::CancellationToken,
    dns_listen_addr: DNSListenAddr,
    dns_enabled: bool,
    task_handle: StdMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ApiRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        controller_cfg: Controller,
        log_source: Sender<LogEvent>,
        inbound_manager: Arc<InboundManager>,
        dispatcher: Arc<dispatcher::Dispatcher>,
        global_state: Arc<Mutex<GlobalState>>,
        dns_resolver: ThreadSafeDNSResolver,
        outbound_manager: ThreadSafeOutboundManager,
        statistics_manager: Arc<StatisticsManager>,
        cache_store: ThreadSafeCacheFile,
        router: ArcRouter,
        cwd: String,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
        dns_listen_addr: DNSListenAddr,
        dns_enabled: bool,
    ) -> Self {
        Self {
            controller_cfg,
            log_source,
            inbound_manager,
            dispatcher,
            global_state,
            dns_resolver,
            outbound_manager,
            statistics_manager,
            cache_store,
            router,
            cwd,
            cancellation_token: cancellation_token.unwrap_or_default(),
            dns_listen_addr,
            dns_enabled,
            task_handle: StdMutex::new(None),
        }
    }
}

impl Runner for ApiRunner {
    fn run_async(&self) {
        let inbound_manager = self.inbound_manager.clone();
        let dispatcher = self.dispatcher.clone();
        let global_state = self.global_state.clone();
        let dns_resolver = self.dns_resolver.clone();
        let outbound_manager = self.outbound_manager.clone();
        let statistics_manager = self.statistics_manager.clone();
        let cache_store = self.cache_store.clone();
        let controller_cfg = self.controller_cfg.clone();
        let router = self.router.clone();
        let cwd = self.cwd.clone();
        let dns_listen_addr = self.dns_listen_addr.clone();
        let dns_enabled = self.dns_enabled;

        let ipc_addr = controller_cfg.external_controller_ipc;
        let tcp_addr = controller_cfg.external_controller;

        let origins: AllowOrigin =
            if let Some(origins) = &controller_cfg.cors_allow_origins {
                let has_wildcard = origins.iter().any(|origin| origin.trim() == "*");
                if has_wildcard {
                    if origins.iter().any(|origin| origin.trim() != "*") {
                        warn!(
                            "CORS origin '*' enables all origins; ignoring \
                             additional configured origins"
                        );
                    }
                    Any.into()
                } else {
                    origins
                        .iter()
                        .filter_map(|v| match v.parse() {
                            Ok(origin) => Some(origin),
                            Err(e) => {
                                warn!("ignored invalid CORS origin '{}': {}", v, e);
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .into()
                }
            } else {
                Any.into()
            };

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .allow_private_network(true)
            .allow_origin(origins);

        let app_state = Arc::new(AppState {
            log_source_tx: self.log_source.clone(),
            statistics_manager: statistics_manager.clone(),
        });
        let cancellation_token = self.cancellation_token.clone();
        let handle = tokio::spawn(async move {
            let mut router = Router::new()
                .route("/", get(handlers::hello::handle))
                .route("/logs", get(handlers::log::handle))
                .route("/traffic", get(handlers::traffic::handle))
                .route("/user-stats", get(handlers::user_stats::handle))
                .route("/version", get(handlers::version::handle))
                .route("/memory", get(handlers::memory::handle))
                .route("/restart", post(handlers::restart::handle))
                .nest("/ws", websocket::routes(app_state.clone()))
                .nest(
                    "/configs",
                    handlers::config::routes(
                        inbound_manager,
                        dispatcher,
                        global_state,
                        dns_resolver.clone(),
                        dns_listen_addr,
                        dns_enabled,
                    ),
                )
                .nest("/rules", handlers::rule::routes(router.clone()))
                .nest("/group", handlers::group::routes(outbound_manager.clone()))
                .nest(
                    "/proxies",
                    handlers::proxy::routes(outbound_manager.clone(), cache_store),
                )
                .nest(
                    "/providers/proxies",
                    handlers::provider::routes(outbound_manager),
                )
                .nest("/providers/rules", handlers::provider::rule_routes(router))
                .nest(
                    "/connections",
                    handlers::connection::routes(statistics_manager.clone()),
                )
                .nest("/flows", handlers::flows::routes(statistics_manager))
                .nest("/dns", handlers::dns::routes(dns_resolver))
                .layer(middleware::from_fn(
                    middlewares::fix_json_content_type::fix_content_type,
                ))
                .route_layer(cors)
                .with_state(app_state)
                .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

            if let Some(external_ui) = controller_cfg.external_ui {
                let ui_path = PathBuf::from(&cwd).join(&external_ui);
                // Check if the external-ui directory exists and contains files.
                // If the directory is empty or missing, fall back to the
                // embedded dashboard (when the `dashboard` feature is enabled)
                // so the web UI is always available even on fresh deployments.
                let has_files = ui_path.is_dir()
                    && std::fs::read_dir(&ui_path)
                        .map(|mut d| d.next().is_some())
                        .unwrap_or(false);

                if has_files {
                    info!("serving external UI from {}", ui_path.display());
                    router = router
                        .route("/ui", get(|| async { Redirect::to("/ui/") }))
                        .nest_service("/ui/", ServeDir::new(ui_path));
                } else {
                    #[cfg(feature = "dashboard")]
                    {
                        info!(
                            "external-ui directory '{}' is empty or missing, \
                             falling back to embedded dashboard",
                            ui_path.display()
                        );
                        use super::embedded_dashboard;
                        router = router
                            .route("/ui", get(|| async { Redirect::to("/ui/") }))
                            .route("/ui/", get(embedded_dashboard::serve_index))
                            .route(
                                "/ui/{*path}",
                                get(embedded_dashboard::serve_asset),
                            );
                    }
                    #[cfg(not(feature = "dashboard"))]
                    {
                        warn!(
                            "external-ui directory '{}' is empty or missing and \
                             dashboard feature is not compiled in; UI will not be \
                             available",
                            ui_path.display()
                        );
                    }
                }
            } else {
                #[cfg(feature = "dashboard")]
                {
                    use super::embedded_dashboard;
                    router = router
                        .route("/ui", get(|| async { Redirect::to("/ui/") }))
                        .route("/ui/", get(embedded_dashboard::serve_index))
                        .route("/ui/{*path}", get(embedded_dashboard::serve_asset));
                }
            }

            // Create display strings before moving values
            let tcp_addr_display = tcp_addr.as_ref().map(|addr| addr.to_string());
            let ipc_addr_display = ipc_addr.clone();

            // Handle TCP listening
            let tcp_fut = tcp_addr.map(|bind_addr| {
                let bind_addr = if bind_addr.starts_with(':') {
                    info!(
                        "TCP API Server address not supplied, listening on \
                         `127.0.0.1`"
                    );
                    format!("127.0.0.1{bind_addr}")
                } else {
                    bind_addr
                };
                let auth_secret = controller_cfg.secret.clone().unwrap_or_default();
                let cors_allow_origins = controller_cfg.cors_allow_origins.clone();
                super::tcp::serve_tcp(
                    bind_addr,
                    router.clone(),
                    auth_secret,
                    cors_allow_origins,
                )
            });
            // Handle IPC listening
            let ipc_fut = ipc_addr.as_ref().map(|ipc_path| {
                let ipc_path = ipc_path.clone();
                async move { ipc::serve_ipc(router, &ipc_path).await }
            });

            match (tcp_addr_display.as_deref(), ipc_addr_display.as_deref()) {
                (Some(tcp), Some(ipc)) => debug!(
                    "API server is running on both TCP {} and IPC {}",
                    tcp, ipc
                ),
                (Some(tcp), None) => debug!("API server is running on TCP {}", tcp),
                (None, Some(ipc)) => debug!("API server is running on IPC {}", ipc),
                (None, None) => {
                    info!("API server: no listener configured, skipping");
                    return;
                }
            }

            let result = tokio::select! {
                Some(result) = futures::future::OptionFuture::from(tcp_fut) => result,
                Some(result) = futures::future::OptionFuture::from(ipc_fut) => result,
                _ = cancellation_token.cancelled() => {
                    info!("API server closed");
                    Ok(())
                }
            };
            if let Err(e) = result {
                error!("API server failed to start, error: {}", e);
            }
        });
        *self.task_handle.lock().unwrap() = Some(handle);
    }

    fn shutdown(&self) {
        info!("Shutting down API server");
        self.cancellation_token.cancel();
    }

    fn join(&self) -> futures::future::BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move {
            let handle = self.task_handle.lock().unwrap().take();
            if let Some(h) = handle {
                let _ = h.await;
            }
            Ok(())
        })
    }
}
