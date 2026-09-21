use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{
    app::{
        dispatcher::Dispatcher,
        dns::ThreadSafeDNSResolver,
        inbound::network_listener::build_network_listeners,
        remote_content_manager::providers::{
            file_vehicle, http_vehicle, inbound_provider::InboundSetProvider,
        },
    },
    common::auth::ThreadSafeAuthenticator,
    config::internal::{
        config::BindAddress,
        listener::{
            InboundFileProvider, InboundHttpProvider, InboundOpts,
            InboundProviderDef, InboundUser,
        },
    },
    runner::Runner,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

/// Per-listener handle entry: the spawned task plus an optional channel to
/// push user-list updates without restarting the listener.
struct ProviderHandleEntry {
    handle: Option<JoinHandle<()>>,
    /// Present only for Shadowsocks and AnyTLS listeners — used to push updated
    /// user lists without restarting the listener.
    /// lists into the running listener without a restart.
    #[allow(dead_code)]
    users_tx: Option<tokio::sync::watch::Sender<Vec<InboundUser>>>,
}

/// Per-listener handle entry for static (non-provider) inbounds.
struct StaticHandleEntry {
    handle: Option<JoinHandle<()>>,
    /// Present only for AnyTLS (and Shadowsocks) listeners — used to push
    /// updated user lists without restarting the listener.
    #[allow(dead_code)]
    users_tx: Option<tokio::sync::watch::Sender<Vec<InboundUser>>>,
}

type ProviderHandles =
    Arc<RwLock<HashMap<String, HashMap<InboundOpts, ProviderHandleEntry>>>>;
use tracing::{error, info, warn};

/// Legacy ports configuration for inbounds.
/// Newer inbounds have their own port configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ports {
    pub port: Option<u16>,
    #[serde(rename = "socks-port")]
    pub socks_port: Option<u16>,
    #[serde(rename = "redir-port")]
    pub redir_port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundEndpoint {
    pub name: String,
    #[serde(rename = "type")]
    pub inbound_type: String,
    pub port: u16,
    pub active: bool,
}

pub struct InboundManager {
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,

    /// Inbound options for each inbound type -> listening Task
    inbound_handlers: Arc<RwLock<HashMap<InboundOpts, StaticHandleEntry>>>,

    /// provider name -> (InboundOpts -> JoinHandle) for provider-owned
    /// listeners
    provider_handles: ProviderHandles,

    /// provider name -> provider (kept alive for lifecycle management)
    inbound_providers: Arc<RwLock<HashMap<String, Arc<InboundSetProvider>>>>,

    cancellation_token: tokio_util::sync::CancellationToken,
}

impl Runner for InboundManager {
    fn run_async(&self) {
        let inbound_handlers = self.inbound_handlers.clone();
        let dispatcher = self.dispatcher.clone();
        let authenticator = self.authenticator.clone();
        let cancellation_token = self.cancellation_token.clone();

        tokio::spawn(async move {
            Self::start_all_listeners(
                dispatcher,
                authenticator,
                inbound_handlers,
                cancellation_token,
            )
            .await;
        });
    }

    fn shutdown(&self) {
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move { self.join_all_listeners().await })
    }
}
impl InboundManager {
    pub async fn new(
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbounds_opt: HashSet<InboundOpts>,
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            inbound_handlers: Arc::new(RwLock::new(
                inbounds_opt
                    .into_iter()
                    .map(|opts| {
                        (
                            opts,
                            StaticHandleEntry {
                                handle: None,
                                users_tx: None,
                            },
                        )
                    })
                    .collect(),
            )),
            provider_handles: Arc::new(RwLock::new(HashMap::new())),
            inbound_providers: Arc::new(RwLock::new(HashMap::new())),
            dispatcher,
            authenticator,
            cancellation_token: cancellation_token.unwrap_or_default(),
        }
    }

    /// Load and initialise inbound providers (http/file), analogous to
    /// `OutboundManager::load_proxy_providers`. Should be called once after
    /// `new()`, before `run_async()`.
    pub async fn load_inbound_providers(
        &self,
        cwd: String,
        providers: HashMap<String, InboundProviderDef>,
        dns_resolver: ThreadSafeDNSResolver,
    ) {
        for (name, def) in providers {
            let (vehicle, interval): (
                Arc<dyn crate::app::remote_content_manager::providers::ProviderVehicle + Send + Sync>,
                Duration,
            ) = match def {
                InboundProviderDef::Http(InboundHttpProvider {
                    url,
                    path,
                    interval,
                    ..
                }) => {
                    let uri = match url.parse::<hyper::Uri>() {
                        Ok(u) => u,
                        Err(e) => {
                            error!(provider = %name, "invalid inbound provider URL: {e}");
                            continue;
                        }
                    };
                    let path = path.unwrap_or_else(|| {
                        let md5 = crate::common::utils::md5_str(url.as_bytes());
                        format!("inbound_providers/{md5}.yaml")
                    });
                    let v = http_vehicle::Vehicle::new(
                        uri,
                        path,
                        Some(cwd.clone()),
                        dns_resolver.clone(),
                    );
                    (Arc::new(v), Duration::from_secs(interval.unwrap_or(86400)))
                }
                InboundProviderDef::File(InboundFileProvider { path, interval, .. }) => {
                    let v = file_vehicle::Vehicle::new(&path);
                    (Arc::new(v), Duration::from_secs(interval.unwrap_or(0)))
                }
            };

            let provider_handles = self.provider_handles.clone();
            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();
            let cancellation_token = self.cancellation_token.clone();
            let provider_name = name.clone();

            let on_update = move |new_opts: Vec<InboundOpts>| {
                let provider_handles = provider_handles.clone();
                let dispatcher = dispatcher.clone();
                let authenticator = authenticator.clone();
                let cancellation_token = cancellation_token.clone();
                let provider_name = provider_name.clone();

                Box::pin(async move {
                    let mut provider_handles_guard = provider_handles.write().await;
                    let mut old_handles = provider_handles_guard
                        .remove(&provider_name)
                        .unwrap_or_default();

                    // Partition new_opts: reuse or user-update existing
                    // listeners, collect truly new opts
                    // that need a fresh listener.
                    let mut new_handles: HashMap<InboundOpts, ProviderHandleEntry> =
                        HashMap::new();
                    let mut opts_to_start: Vec<InboundOpts> = Vec::new();

                    for opts in new_opts {
                        if let Some(entry) = old_handles.remove(&opts) {
                            // Structural key matched (same
                            // port/cipher/password).
                            // Push updated user list via watch channel if
                            // present — this avoids
                            // restarting the listener entirely.
                            #[cfg(feature = "shadowsocks")]
                            if let (InboundOpts::Shadowsocks { users, .. }, Some(tx)) =
                                (&opts, &entry.users_tx)
                                && tx.send(users.clone()).is_ok()
                            {
                                info!(
                                    "inbound provider {provider_name}: user list \
                                     updated in place ({} users)",
                                    users.len()
                                );
                            }
                            if let (InboundOpts::Anytls { users, .. }, Some(tx)) =
                                (&opts, &entry.users_tx)
                                && tx.send(users.clone()).is_ok()
                            {
                                info!(
                                    "inbound provider {provider_name}: anytls user \
                                     list updated in place ({} users)",
                                    users.len()
                                );
                            }
                            if let (InboundOpts::Hysteria2 { users, .. }, Some(tx)) =
                                (&opts, &entry.users_tx)
                                && tx.send(users.clone()).is_ok()
                            {
                                info!(
                                    "inbound provider {provider_name}: hysteria2 \
                                     user list updated in place ({} users)",
                                    users.len()
                                );
                            }
                            new_handles.insert(opts, entry);
                        } else {
                            opts_to_start.push(opts);
                        }
                    }

                    // Abort removed handles BEFORE starting new ones so UDP
                    // ports are released before we try to bind them again.
                    let has_removed = !old_handles.is_empty();
                    for (removed_opts, entry) in old_handles {
                        info!(
                            "inbound provider {provider_name}: removing listener \
                             '{}'",
                            removed_opts.common_opts().name
                        );
                        if let Some(h) = entry.handle {
                            h.abort();
                        }
                    }

                    // Yield so aborted tasks can drop their sockets before we
                    // attempt to bind the same ports again.
                    if has_removed && !opts_to_start.is_empty() {
                        tokio::task::yield_now().await;
                    }

                    // Start listeners for new opts.
                    for opts in opts_to_start {
                        let ct = cancellation_token.clone();
                        let listener_name = opts.common_opts().name.clone();
                        info!(
                            "inbound provider {provider_name}: starting listener \
                             '{listener_name}'"
                        );

                        // For Shadowsocks, AnyTLS, and Hysteria2, create a
                        // watch channel so future
                        // user-list updates can be pushed
                        // without a restart.
                        #[cfg(feature = "shadowsocks")]
                        let (users_rx, users_tx) = match &opts {
                            InboundOpts::Shadowsocks { users, .. }
                            | InboundOpts::Anytls { users, .. }
                            | InboundOpts::Hysteria2 { users, .. } => {
                                let (tx, rx) =
                                    tokio::sync::watch::channel(users.clone());
                                (Some(rx), Some(tx))
                            }
                            _ => (None, None),
                        };
                        #[cfg(not(feature = "shadowsocks"))]
                        let (users_rx, users_tx) = match &opts {
                            InboundOpts::Anytls { users, .. }
                            | InboundOpts::Hysteria2 { users, .. } => {
                                let (tx, rx) =
                                    tokio::sync::watch::channel(users.clone());
                                (Some(rx), Some(tx))
                            }
                            _ => (
                                None::<tokio::sync::watch::Receiver<Vec<InboundUser>>>,
                                None,
                            ),
                        };

                        let handle = build_network_listeners(
                            &opts,
                            dispatcher.clone(),
                            authenticator.clone(),
                            users_rx,
                        )
                        .map(|runners| {
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = futures::future::join_all(runners) => {
                                        warn!("Provider inbound {} exited", listener_name);
                                    }
                                    _ = ct.cancelled() => {
                                        info!("Provider inbound {} closed", listener_name);
                                    }
                                }
                            })
                        });
                        new_handles
                            .insert(opts, ProviderHandleEntry { handle, users_tx });
                    }

                    provider_handles_guard.insert(provider_name, new_handles);
                }) as BoxFuture<'static, ()>
            };

            match InboundSetProvider::new(name.clone(), interval, vehicle, on_update)
            {
                Ok(provider) => {
                    let provider = Arc::new(provider);
                    match provider.initialize().await {
                        Ok(initial_opts) => {
                            info!(
                                "inbound provider '{name}' initialised ({} \
                                 listeners)",
                                initial_opts.len()
                            );
                            self.inbound_providers
                                .write()
                                .await
                                .insert(name, provider);
                        }
                        Err(e) => {
                            error!(provider = %name, "inbound provider init failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!(provider = %name, "failed to create inbound provider: {e}")
                }
            }
        }
    }

    async fn start_all_listeners(
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        inbound_handlers: Arc<RwLock<HashMap<InboundOpts, StaticHandleEntry>>>,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) {
        for (opts, entry) in inbound_handlers.write().await.iter_mut() {
            let cancellation_token = cancellation_token.clone();
            let name = opts.common_opts().name.clone();

            // For AnyTLS, Hysteria2 (and Shadowsocks), create a watch channel
            // so user-list updates can be pushed without a full
            // restart.
            #[cfg(feature = "shadowsocks")]
            let (users_rx, users_tx) = match opts {
                InboundOpts::Shadowsocks { users, .. }
                | InboundOpts::Anytls { users, .. }
                | InboundOpts::Hysteria2 { users, .. } => {
                    let (tx, rx) = tokio::sync::watch::channel(users.clone());
                    (Some(rx), Some(tx))
                }
                _ => (None, None),
            };
            #[cfg(not(feature = "shadowsocks"))]
            let (users_rx, users_tx) = match opts {
                InboundOpts::Anytls { users, .. }
                | InboundOpts::Hysteria2 { users, .. } => {
                    let (tx, rx) = tokio::sync::watch::channel(users.clone());
                    (Some(rx), Some(tx))
                }
                _ => (None::<tokio::sync::watch::Receiver<Vec<InboundUser>>>, None),
            };

            entry.users_tx = users_tx;
            entry.handle = build_network_listeners(
                opts,
                dispatcher.clone(),
                authenticator.clone(),
                users_rx,
            )
            .map(|r| {
                tokio::spawn(async move {
                    tokio::select! {
                        _ = futures::future::join_all(r) => {
                            warn!("Inbound handler {} has exited", name);
                        },
                        _ = cancellation_token.cancelled() => {
                            info!("Inbound handler {} is closed", name);
                        },
                    }
                })
            });
        }
    }

    async fn stop_all_listeners(&self) {
        for (opt, entry) in self.inbound_handlers.write().await.iter_mut() {
            if let Some(handler) = entry.handle.take() {
                warn!("Shutting down inbound handler: {}", opt.common_opts().name);
                handler.abort();
            }
        }
        for handles in self.provider_handles.write().await.values_mut() {
            for (opt, entry) in handles.iter_mut() {
                if let Some(h) = entry.handle.take() {
                    warn!(
                        "Shutting down provider inbound handler: {}",
                        opt.common_opts().name
                    );
                    h.abort();
                }
            }
        }
    }

    #[allow(dead_code)]
    async fn join_all_listeners(&self) -> Result<(), crate::Error> {
        let mut last_join_error = None;
        for (opt, entry) in self.inbound_handlers.write().await.iter_mut() {
            if let Some(handler) = entry.handle.take() {
                warn!("Shutting down inbound handler: {}", opt.common_opts().name);
                handler.await.unwrap_or_else(|e| {
                    warn!(
                        "Inbound handler {} shutdown with error: {}",
                        opt.common_opts().name,
                        e
                    );
                    last_join_error = Some(e);
                });
            }
        }
        for handles in self.provider_handles.write().await.values_mut() {
            for (opt, entry) in handles.iter_mut() {
                if let Some(h) = entry.handle.take() {
                    warn!(
                        "Shutting down provider inbound handler: {}",
                        opt.common_opts().name
                    );
                    h.await.unwrap_or_else(|e| {
                        warn!(
                            "Provider inbound handler {} shutdown with error: {}",
                            opt.common_opts().name,
                            e
                        );
                        last_join_error = Some(e);
                    });
                }
            }
        }
        last_join_error
            .map(|e| Err(std::io::Error::other(e).into()))
            .unwrap_or(Ok(()))
    }

    // RESTFUL API handlers below
    pub async fn restart(&self) -> Result<(), crate::Error> {
        self.stop_all_listeners().await;

        let inbound_handlers = self.inbound_handlers.clone();
        let dispatcher = self.dispatcher.clone();
        let authenticator = self.authenticator.clone();
        let cancellation_token = self.cancellation_token.clone();
        Self::start_all_listeners(
            dispatcher,
            authenticator,
            inbound_handlers,
            cancellation_token,
        )
        .await;
        Ok(())
    }

    pub async fn get_ports(&self) -> Ports {
        let mut ports = Ports::default();
        let guard = self.inbound_handlers.read().await;
        for opts in guard.keys() {
            match &opts {
                InboundOpts::Http { common_opts } => {
                    ports.port = Some(common_opts.port)
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port = Some(common_opts.port)
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port = Some(common_opts.port)
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { common_opts, .. } => {
                    ports.tproxy_port = Some(common_opts.port)
                }
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port = Some(common_opts.port)
                }
                _ => {}
            }
        }
        ports
    }

    pub async fn get_allow_lan(&self) -> bool {
        let guard = self.inbound_handlers.read().await;
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().allow_lan
        } else {
            false
        }
    }

    pub async fn set_allow_lan(&self, allow_lan: bool) {
        let mut guard = self.inbound_handlers.write().await;
        let new_map = guard
            .drain()
            .map(|(mut opts, entry)| {
                opts.common_opts_mut().allow_lan = allow_lan;
                (opts, entry)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    pub async fn get_bind_address(&self) -> BindAddress {
        let guard = self.inbound_handlers.read().await;
        if let Some((opts, _)) = guard.iter().next() {
            opts.common_opts().listen
        } else {
            BindAddress::default()
        }
    }

    pub async fn get_listeners(&self) -> Vec<InboundEndpoint> {
        let mut result: Vec<InboundEndpoint> = self
            .inbound_handlers
            .read()
            .await
            .iter()
            .map(|(opts, entry)| {
                let common = opts.common_opts();
                let active = entry.handle.as_ref().is_some_and(|h| !h.is_finished());
                InboundEndpoint {
                    name: common.name.clone(),
                    inbound_type: opts.type_name().to_string(),
                    port: common.port,
                    active,
                }
            })
            .collect();

        for handles in self.provider_handles.read().await.values() {
            for (opts, entry) in handles {
                let common = opts.common_opts();
                let active = entry.handle.as_ref().is_some_and(|h| !h.is_finished());
                result.push(InboundEndpoint {
                    name: common.name.clone(),
                    inbound_type: opts.type_name().to_string(),
                    port: common.port,
                    active,
                });
            }
        }

        result
    }

    pub async fn set_bind_address(&self, bind_address: BindAddress) {
        let mut guard = self.inbound_handlers.write().await;
        let new_map = guard
            .drain()
            .map(|(mut opts, entry)| {
                opts.common_opts_mut().listen = bind_address;
                (opts, entry)
            })
            .collect::<HashMap<_, _>>();
        *guard = new_map;
    }

    // returns true if any listener ports were changed (i.e. a restart is
    // needed)
    pub async fn change_ports(&self, ports: Ports) -> bool {
        let mut guard = self.inbound_handlers.write().await;

        let listeners: HashMap<InboundOpts, StaticHandleEntry> = guard
            .extract_if(|opts, _| match &opts {
                InboundOpts::Http { common_opts } => {
                    ports.port.is_some() && Some(common_opts.port) == ports.port
                }
                InboundOpts::Socks { common_opts, .. } => {
                    ports.socks_port.is_some()
                        && Some(common_opts.port) == ports.socks_port
                }
                InboundOpts::Mixed { common_opts, .. } => {
                    ports.mixed_port.is_some()
                        && Some(common_opts.port) == ports.mixed_port
                }
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { common_opts, .. } => {
                    ports.tproxy_port.is_some()
                        && Some(common_opts.port) == ports.tproxy_port
                }
                #[cfg(feature = "redir")]
                InboundOpts::Redir { common_opts } => {
                    ports.redir_port.is_some()
                        && Some(common_opts.port) == ports.redir_port
                }
                _ => false,
            })
            .collect();

        let changed = !listeners.is_empty();

        for (mut opts, entry) in listeners {
            // extract_if already guarantees the matching port field is Some.
            // Use a plain match + if-let (stable) rather than if-let guards
            // in match arms (which require the nightly `if_let_guard` feature).
            let new_port = match &opts {
                InboundOpts::Http { .. } => ports.port,
                InboundOpts::Socks { .. } => ports.socks_port,
                InboundOpts::Mixed { .. } => ports.mixed_port,
                #[cfg(feature = "tproxy")]
                InboundOpts::TProxy { .. } => ports.tproxy_port,
                #[cfg(feature = "redir")]
                InboundOpts::Redir { .. } => ports.redir_port,
                _ => {
                    warn!(
                        "Port for listener '{}' is not changed",
                        opts.common_opts().name
                    );
                    continue;
                }
            };
            let Some(port) = new_port else {
                warn!(
                    "Port for listener '{}' is not changed",
                    opts.common_opts().name
                );
                continue;
            };
            opts.common_opts_mut().port = port;
            guard.insert(opts, entry);
        }

        changed
    }
}
