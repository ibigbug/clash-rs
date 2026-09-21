use super::utils::proxy_groups_dag_sort;
#[cfg(feature = "shadowquic")]
use crate::proxy::shadowquic;
#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks;
#[cfg(feature = "ssh")]
use crate::proxy::ssh;
#[cfg(feature = "tailscale")]
use crate::proxy::tailscale;
#[cfg(feature = "onion")]
use crate::proxy::tor;
#[cfg(feature = "tuic")]
use crate::proxy::tuic;
#[cfg(feature = "wireguard")]
use crate::proxy::wg;
use crate::{
    Error,
    app::{
        dns::ThreadSafeDNSResolver,
        profile::ThreadSafeCacheFile,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{
                ProviderVehicleType, ThreadSafeProviderVehicle, file_vehicle,
                http_vehicle,
                proxy_provider::{
                    ArcProxyProvider, PlainProvider, ProxySetProvider,
                },
            },
        },
    },
    config::internal::proxy::{
        OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
        PROXY_DIRECT, PROXY_GLOBAL, PROXY_REJECT,
    },
    print_and_exit,
    proxy::{
        AnyOutboundHandler, anytls,
        direct::{self},
        fallback,
        group::smart,
        hysteria2, loadbalance, reject, relay,
        selector::{self, ThreadSafeSelectorControl},
        socks, trojan, urltest,
        utils::{DirectConnector, OutboundHandlerRegistry, ProxyConnector},
        vless, vmess,
    },
};
use anyhow::Result;
use erased_serde::Serialize;
use hyper::Uri;
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tracing::{debug, error, info};
use uuid::Uuid;

static RESERVED_PROVIDER_NAME: &str = "default";

pub struct OutboundManager {
    /// Shared registry used by both OutboundManager lookups and the DNS /
    /// HTTP bootstrap clients.  Populated at the end of `new()` and is the
    /// single source of truth for all handlers after initialization.
    registry: OutboundHandlerRegistry,
    /// name -> provider
    proxy_providers: HashMap<String, ArcProxyProvider>,
    proxy_manager: ProxyManager,
    selector_control: HashMap<String, ThreadSafeSelectorControl>,
}

static DEFAULT_LATENCY_TEST_URL: &str = "http://www.gstatic.com/generate_204";

pub type ThreadSafeOutboundManager = Arc<OutboundManager>;

/// Init process:
/// 1. Load all plaint outbounds from config using the unbounded function
///    `load_plain_outbounds`, so that any bootstrap proxy can be used to
///    download datasets
/// 2. Load all proxy providers from config, this should happen before loading
///    groups as groups my reference providers with `use_provider`
/// 3. Finally load all groups, and create `PlainProvider` for each explicit
///    referenced proxies in each group and register them in the
///    `proxy_providers` map.
/// 4. Create a `PlainProvider` for the global proxy set, which is the GLOBAL
///    selector, which should contain all plain outbound + provider proxies +
///    groups
///
/// Note that the `PlainProvider` is a special provider that contains plain
/// proxies for API compatibility with actual remote providers.
/// TODO: refactor this giant class
#[allow(clippy::too_many_arguments)]
impl OutboundManager {
    pub async fn new(
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        proxy_names: Vec<String>,
        dns_resolver: ThreadSafeDNSResolver,
        cache_store: ThreadSafeCacheFile,
        cwd: String,
        fw_mark: Option<u32>,
        registry: OutboundHandlerRegistry,
    ) -> Result<Self, Error> {
        // Build all handlers in a plain HashMap during initialization.
        // Once fully assembled it is written into the shared registry so that
        // DNS clients and the HTTP client can look up any handler by name.
        let mut handlers: HashMap<String, AnyOutboundHandler> = HashMap::new();
        let provider_registry = HashMap::new();
        let selector_control = HashMap::new();
        let proxy_manager = ProxyManager::new(dns_resolver.clone(), fw_mark);

        let mut m = Self {
            registry,
            proxy_manager,
            selector_control,
            proxy_providers: provider_registry,
        };

        debug!("initializing proxy providers");
        m.load_proxy_providers(cwd, proxy_providers, dns_resolver)
            .await?;

        debug!("initializing handlers");
        m.load_handlers(
            &mut handlers,
            outbounds,
            outbound_groups,
            proxy_names,
            cache_store,
        )
        .await?;

        debug!("initializing connectors");
        m.init_handler_connectors(&handlers).await?;

        // Replace the shared registry with the freshly assembled handler map.
        // Using `clone()` + `*reg = ...` ensures stale entries from previous
        // initialisation rounds (e.g. across hot reloads) are removed.
        {
            let mut reg = m.registry.write().await;
            *reg = handlers
                .iter()
                .map(|(k, v)| {
                    debug!("registering outbound '{}' in bootstrap registry", k);
                    (k.clone(), v.clone())
                })
                .collect();
        }

        Ok(m)
    }

    /// Look up a handler by name. Returns `None` when the name is not
    /// registered.  The registry is read under a shared lock, so this method
    /// is `async` — callers must `.await` the result.
    /// If not found in the static registry, searches in proxy providers.
    pub async fn get_outbound(&self, name: &str) -> Option<AnyOutboundHandler> {
        if let Some(h) = self.registry.read().await.get(name).cloned() {
            return Some(h);
        }
        for provider in self.proxy_providers.values() {
            for proxy in provider.proxies().await {
                if proxy.name() == name {
                    return Some(proxy);
                }
            }
        }
        None
    }

    /// this doesn't populate history/liveness information
    pub fn get_proxy_provider(&self, name: &str) -> Option<ArcProxyProvider> {
        self.proxy_providers.get(name).cloned()
    }

    // API handles start
    pub fn get_selector_control(
        &self,
        name: &str,
    ) -> Option<ThreadSafeSelectorControl> {
        self.selector_control.get(name).cloned()
    }

    /// Get all proxies in the manager, excluding those in providers.
    pub async fn get_proxies(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = HashMap::new();

        // Snapshot the registry without holding the lock across async calls.
        let handlers: Vec<(String, AnyOutboundHandler)> = self
            .registry
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (k, v) in handlers {
            let mut m = if let Some(g) = v.try_as_group_handler() {
                g.as_map().await
            } else if let Some(p) = v.try_as_plain_handler() {
                p.as_map().await
            } else {
                HashMap::new()
            };

            self.apply_common_proxy_fields(&mut m, &v, &k).await;

            r.insert(k.clone(), Box::new(m) as _);
        }

        r
    }

    pub async fn get_proxy(
        &self,
        proxy: &AnyOutboundHandler,
    ) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut r = if let Some(g) = proxy.try_as_group_handler() {
            g.as_map().await
        } else if let Some(p) = proxy.try_as_plain_handler() {
            p.as_map().await
        } else {
            HashMap::new()
        };
        self.apply_common_proxy_fields(&mut r, proxy, proxy.name())
            .await;

        r
    }

    async fn apply_common_proxy_fields(
        &self,
        m: &mut HashMap<String, Box<dyn Serialize + Send>>,
        proxy: &AnyOutboundHandler,
        name: &str,
    ) {
        let alive = self.proxy_manager.alive(name).await;
        let history = self.proxy_manager.delay_history(name).await;
        let support_udp = proxy.support_udp().await;

        let id = Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes());
        m.insert("id".to_string(), Box::new(id.to_string()));
        m.insert("history".to_string(), Box::new(history));
        m.insert("alive".to_string(), Box::new(alive));
        m.insert("name".to_string(), Box::new(name.to_owned()));
        m.insert("type".to_string(), Box::new(proxy.proto().to_string()));
        m.insert("udp".to_string(), Box::new(support_udp));
        m.insert("uot".to_string(), Box::new(false));
        m.insert("xudp".to_string(), Box::new(false));
        m.insert("tfo".to_string(), Box::new(false));
        m.insert("mptcp".to_string(), Box::new(false));
        m.insert("smux".to_string(), Box::new(false));
        m.insert("interface".to_string(), Box::new(""));
        m.insert("dialer-proxy".to_string(), Box::new(""));
        m.insert("routing-mark".to_string(), Box::new(0));
        m.insert("provider-name".to_string(), Box::new(""));
        m.insert(
            "extra".to_string(),
            Box::new(HashMap::<String, String>::new()),
        );
    }

    /// a wrapper of proxy_manager.url_test so that proxy_manager is not
    /// exposed.
    ///
    /// `force` is forwarded to [`ProxyManager::check`]: `true` for manual
    /// user-triggered latency tests (bypass backoff, test every node),
    /// `false` for automatic health checks (honour backoff for dead nodes).
    pub async fn url_test(
        &self,
        outbounds: &Vec<AnyOutboundHandler>,
        url: &str,
        timeout: Duration,
        force: bool,
    ) -> Vec<std::io::Result<(Duration, Duration)>> {
        let proxy_manager = self.proxy_manager.clone();
        proxy_manager
            .check(outbounds, url, Some(timeout), force)
            .await
    }

    pub fn get_proxy_providers(&self) -> HashMap<String, ArcProxyProvider> {
        self.proxy_providers.clone()
    }

    // API handlers end

    /// Lazy initialization of connectors for each handler.
    async fn init_handler_connectors(
        &self,
        handlers: &HashMap<String, AnyOutboundHandler>,
    ) -> Result<(), Error> {
        // Merge the passed-in handler map with every proxy provider's
        // handlers.  Healthcheck / url_test hold Arc clones of provider
        // handlers; if a provider handler declares a `connect-via` /
        // `dialer-proxy` connector it MUST be registered here too, otherwise
        // delay tests silently fall back to a direct connection that may be
        // RST-blocked upstream (e.g. AnyTLS on a filtered port).
        let mut all_handlers = handlers.clone();
        for provider in self.proxy_providers.values() {
            for proxy in provider.proxies().await {
                all_handlers.entry(proxy.name().to_owned()).or_insert(proxy);
            }
        }

        let mut connectors = HashMap::new();
        for handler in all_handlers.values() {
            if let Some(connector_name) = handler.support_dialer() {
                let outbound = all_handlers
                    .get(connector_name)
                    .ok_or(Error::InvalidConfig(format!(
                        "connector {connector_name} not found"
                    )))?
                    .clone();
                let connector =
                    connectors.entry(connector_name).or_insert_with(|| {
                        Arc::new(ProxyConnector::new(
                            outbound,
                            Box::new(DirectConnector::new()),
                        ))
                    });
                handler.register_connector(connector.clone()).await;
            }
        }

        Ok(())
    }

    pub fn load_plain_outbounds(
        outbounds: Vec<OutboundProxyProtocol>,
    ) -> Vec<AnyOutboundHandler> {
        outbounds
            .into_iter()
            .filter_map(|outbound| match outbound {
                OutboundProxyProtocol::Direct(d) => {
                    Some(Arc::new(direct::Handler::new(&d.name)) as _)
                }
                OutboundProxyProtocol::Reject(r) => {
                    Some(Arc::new(reject::Handler::new(&r.name)) as _)
                }
                #[cfg(feature = "shadowsocks")]
                OutboundProxyProtocol::Ss(s) => {
                    let name = s.common_opts.name.clone();
                    s.try_into()
                        .map(|x: shadowsocks::outbound::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .inspect_err(|e| {
                            error!(
                                "failed to load shadowsocks outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                OutboundProxyProtocol::Socks5(s) => {
                    let name = s.common_opts.name.clone();
                    s.try_into()
                        .map(|x: socks::outbound::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .inspect_err(|e| {
                            error!("failed to load socks5 outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Anytls(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: anytls::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load anytls outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Vmess(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: vmess::Handler| Arc::new(x) as AnyOutboundHandler)
                        .inspect_err(|e| {
                            error!("failed to load vmess outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Vless(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: vless::Handler| Arc::new(x) as AnyOutboundHandler)
                        .inspect_err(|e| {
                            error!("failed to load vless outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Trojan(v) => {
                    let name = v.common_opts.name.clone();
                    v.try_into()
                        .map(|x: trojan::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load trojan outbound {}: {}", name, e);
                        })
                        .ok()
                }
                OutboundProxyProtocol::Hysteria2(h) => {
                    let name = h.name.clone();
                    h.try_into()
                        .map(|x: hysteria2::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!(
                                "failed to load hysteria2 outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                #[cfg(feature = "wireguard")]
                OutboundProxyProtocol::Wireguard(wg) => {
                    let name = wg.common_opts.name.clone();
                    wg.try_into()
                        .map(|x: wg::Handler| Arc::new(x) as AnyOutboundHandler)
                        .inspect_err(|e| {
                            error!(
                                "failed to load wireguard outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                #[cfg(feature = "ssh")]
                OutboundProxyProtocol::Ssh(ssh) => {
                    let name = ssh.common_opts.name.clone();
                    ssh.try_into()
                        .map(|x: ssh::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load ssh outbound {}: {}", name, e);
                        })
                        .ok()
                }
                #[cfg(feature = "onion")]
                OutboundProxyProtocol::Tor(tor) => {
                    let name = tor.name.clone();
                    tor.try_into()
                        .map(|x: tor::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load tor outbound {}: {}", name, e);
                        })
                        .ok()
                }
                #[cfg(feature = "tuic")]
                OutboundProxyProtocol::Tuic(tuic) => {
                    let name = tuic.common_opts.name.clone();
                    tuic.try_into()
                        .map(|x: tuic::Handler| Arc::new(x) as _)
                        .inspect_err(|e| {
                            error!("failed to load tuic outbound {}: {}", name, e);
                        })
                        .ok()
                }
                #[cfg(feature = "shadowquic")]
                OutboundProxyProtocol::ShadowQuic(sqcfg) => {
                    let name = sqcfg.common_opts.name.clone();
                    sqcfg
                        .try_into()
                        .map(|x: shadowquic::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .inspect_err(|e| {
                            error!(
                                "failed to load shadowquic outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
                #[cfg(feature = "tailscale")]
                OutboundProxyProtocol::Tailscale(tscfg) => {
                    let name = tscfg.name.clone();
                    tscfg
                        .try_into()
                        .map(|x: tailscale::Handler| {
                            Arc::new(x) as AnyOutboundHandler
                        })
                        .inspect_err(|e| {
                            error!(
                                "failed to load tailscale outbound {}: {}",
                                name, e
                            );
                        })
                        .ok()
                }
            })
            .collect()
    }
}

impl OutboundManager {
    /// Load handlers from the provided outbound protocols and groups.
    /// handlers in proxy_providers are not loaded here as they are stored in
    /// the provider separately.
    async fn load_handlers(
        &mut self,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        outbounds: Vec<AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        proxy_names: Vec<String>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        handlers.extend(outbounds.into_iter().map(|h| {
            let name = h.name().to_owned();
            (name, h)
        }));

        self.load_group_outbounds(handlers, outbound_groups, cache_store.clone())
            .await?;

        // insert GLOBAL
        let mut g = vec![];
        let mut keys = handlers.keys().collect::<Vec<_>>();
        keys.sort_by(|a, b| {
            proxy_names
                .iter()
                .position(|x| &x == a)
                .cmp(&proxy_names.iter().position(|x| &x == b))
        });
        for name in keys {
            g.push(handlers.get(name).unwrap().clone());
        }
        let hc = HealthCheck::new(
            g.clone(),
            DEFAULT_LATENCY_TEST_URL.to_owned(),
            0, // this is a manual HC
            true,
            self.proxy_manager.clone(),
        );

        let pd: ArcProxyProvider =
            Arc::new(PlainProvider::new(PROXY_GLOBAL.to_owned(), g, hc)?);

        let stored_selection = cache_store.get_selected(PROXY_GLOBAL).await;
        let mut providers: Vec<ArcProxyProvider> = vec![pd.clone()];
        for p in self.proxy_providers.values() {
            let vehicle_type = p.vehicle_type();
            if matches!(
                vehicle_type,
                ProviderVehicleType::Http | ProviderVehicleType::File
            ) {
                providers.push(p.clone());
            }
        }

        let h = selector::Handler::new(
            selector::HandlerOptions {
                name: PROXY_GLOBAL.to_owned(),
                udp: true,
                common_opts: crate::proxy::HandlerCommonOptions {
                    icon: None,
                    ..Default::default()
                },
            },
            providers,
            stored_selection,
        )
        .await;

        self.proxy_providers
            .insert(RESERVED_PROVIDER_NAME.to_owned(), pd);
        handlers.insert(PROXY_GLOBAL.to_owned(), Arc::new(h.clone()));
        self.selector_control
            .insert(PROXY_GLOBAL.to_owned(), Arc::new(h));

        Ok(())
    }

    async fn load_group_outbounds(
        &mut self,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        outbound_groups: Vec<OutboundGroupProtocol>,
        cache_store: ThreadSafeCacheFile,
    ) -> Result<(), Error> {
        // Sort outbound groups to ensure dependencies are resolved
        let mut outbound_groups = outbound_groups;
        proxy_groups_dag_sort(&mut outbound_groups)?;

        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        let selector_control = &mut self.selector_control;

        /// Common boilerplate: build providers list from proxies and
        /// use_provider. Returns `Vec<ArcProxyProvider>`
        /// directly — the caller checks for emptiness.
        #[allow(clippy::too_many_arguments)]
        fn build_group_providers(
            name: &str,
            proxies: &Option<Vec<String>>,
            use_provider: &Option<Vec<String>>,
            url: Option<&str>,
            interval: u64,
            lazy: bool,
            handlers: &HashMap<String, AnyOutboundHandler>,
            proxy_manager: &ProxyManager,
            provider_registry: &mut HashMap<String, ArcProxyProvider>,
        ) -> Result<Vec<ArcProxyProvider>, Error> {
            let mut providers: Vec<ArcProxyProvider> = vec![];

            if let Some(proxies) = proxies
                && !proxies.is_empty()
            {
                let pd = make_provider_from_proxies(
                    name,
                    proxies,
                    url,
                    interval,
                    lazy,
                    handlers,
                    proxy_manager.clone(),
                    provider_registry,
                )?;
                providers.push(pd);
            }

            if let Some(provider_names) = use_provider {
                for provider_name in provider_names {
                    let provider = provider_registry
                        .get(provider_name)
                        .unwrap_or_else(|| {
                            print_and_exit!("provider {} not found", provider_name);
                        })
                        .clone();
                    providers.push(provider);
                }
            }

            Ok(providers)
        }

        #[allow(clippy::too_many_arguments)]
        fn make_provider_from_proxies(
            name: &str,
            proxies: &[String],
            url: Option<&str>,
            interval: u64,
            lazy: bool,
            handlers: &HashMap<String, AnyOutboundHandler>,
            proxy_manager: ProxyManager,
            provider_registry: &mut HashMap<String, ArcProxyProvider>,
        ) -> Result<ArcProxyProvider, Error> {
            if name == PROXY_DIRECT || name == PROXY_REJECT {
                return Err(Error::InvalidConfig(format!(
                    "proxy group name `{name}` is reserved"
                )));
            }
            let proxies = proxies
                .iter()
                .map(|x| {
                    handlers
                        .get(x)
                        .ok_or_else(|| {
                            Error::InvalidConfig(format!("proxy {x} not found"))
                        })
                        .cloned()
                })
                .collect::<Result<Vec<_>, _>>()?;

            let hc_url = url.unwrap_or(DEFAULT_LATENCY_TEST_URL);
            let hc = HealthCheck::new(
                proxies.clone(),
                hc_url.to_owned(),
                interval,
                lazy,
                proxy_manager,
            );

            let pd: ArcProxyProvider = Arc::new(
                PlainProvider::new(name.to_owned(), proxies, hc).map_err(|x| {
                    Error::InvalidConfig(format!("invalid provider config: {x}"))
                })?,
            );

            provider_registry.insert(name.to_owned(), pd.clone());

            Ok(pd)
        }

        // Initialize handlers for each outbound group protocol
        for outbound_group in outbound_groups.iter() {
            match outbound_group {
                OutboundGroupProtocol::Relay(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        proto.url.as_deref(),
                        0,
                        true,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }

                    handlers.insert(
                        proto.name.clone(),
                        relay::Handler::new(
                            relay::HandlerOptions {
                                name: proto.name.clone(),
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: proto.url.clone(),
                                    connector: None,
                                },
                            },
                            providers,
                        ),
                    );
                }
                OutboundGroupProtocol::UrlTest(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        Some(proto.url.as_str()),
                        proto.interval,
                        proto.lazy.unwrap_or_default(),
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }

                    let url_test = urltest::Handler::new(
                        urltest::HandlerOptions {
                            name: proto.name.clone(),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: Some(proto.url.clone()),
                                connector: None,
                            },
                            ..Default::default()
                        },
                        proto.tolerance.unwrap_or_default(),
                        providers,
                        proxy_manager.clone(),
                    );

                    // url-test 也注册 selector_control, 支持手动锁定节点
                    // (PUT /proxies/AUTO {"name":"JP01"} 会锁定到JP01,
                    // 不自动切换) url_test_arc 同时实现
                    // OutboundHandler 和 SelectorControl
                    let url_test_arc: Arc<urltest::Handler> = Arc::new(url_test);
                    handlers.insert(
                        proto.name.clone(),
                        url_test_arc.clone() as AnyOutboundHandler,
                    );
                    selector_control.insert(
                        proto.name.clone(),
                        url_test_arc.clone() as ThreadSafeSelectorControl,
                    );
                }
                OutboundGroupProtocol::Fallback(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        Some(proto.url.as_str()),
                        proto.interval,
                        proto.lazy.unwrap_or_default(),
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }

                    handlers.insert(
                        proto.name.clone(),
                        Arc::new(fallback::Handler::new(
                            fallback::HandlerOptions {
                                name: proto.name.clone(),
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: Some(proto.url.clone()),
                                    connector: None,
                                },
                                ..Default::default()
                            },
                            providers,
                            proxy_manager.clone(),
                        )),
                    );
                }
                OutboundGroupProtocol::LoadBalance(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        Some(proto.url.as_str()),
                        proto.interval,
                        proto.lazy.unwrap_or_default(),
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }

                    handlers.insert(
                        proto.name.clone(),
                        Arc::new(loadbalance::Handler::new(
                            loadbalance::HandlerOptions {
                                name: proto.name.clone(),
                                common_opts: crate::proxy::HandlerCommonOptions {
                                    icon: proto.icon.clone(),
                                    url: Some(proto.url.clone()),
                                    connector: None,
                                },
                                ..Default::default()
                            },
                            providers,
                            proxy_manager.clone(),
                        )),
                    );
                }
                OutboundGroupProtocol::Select(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        proto.url.as_deref(),
                        0,
                        true,
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }

                    let stored_selection =
                        cache_store.get_selected(&proto.name).await;

                    let selector = selector::Handler::new(
                        selector::HandlerOptions {
                            name: proto.name.clone(),
                            udp: proto.udp.unwrap_or(true),
                            common_opts: crate::proxy::HandlerCommonOptions {
                                icon: proto.icon.clone(),
                                url: proto.url.clone(),
                                connector: None,
                            },
                        },
                        providers,
                        stored_selection,
                    )
                    .await;

                    handlers.insert(proto.name.clone(), Arc::new(selector.clone()));
                    selector_control.insert(proto.name.clone(), Arc::new(selector));
                }
                OutboundGroupProtocol::Smart(proto) => {
                    let providers = build_group_providers(
                        &proto.name,
                        &proto.proxies,
                        &proto.use_provider,
                        proto.url.as_deref(),
                        0,
                        proto.lazy.unwrap_or_default(),
                        handlers,
                        proxy_manager,
                        provider_registry,
                    )?;
                    if providers.is_empty() {
                        return Err(Error::InvalidConfig(format!(
                            "proxy group {} has no proxies",
                            proto.name
                        )));
                    }

                    handlers.insert(
                        proto.name.clone(),
                        Arc::new(
                            smart::Handler::new_with_cache(
                                smart::HandlerOptions {
                                    name: proto.name.clone(),
                                    common_opts:
                                        crate::proxy::HandlerCommonOptions {
                                            icon: proto.icon.clone(),
                                            url: proto.url.clone(),
                                            connector: None,
                                        },
                                    udp: proto.udp.unwrap_or(true),
                                    max_retries: proto.max_retries,
                                    bandwidth_weight: proto.bandwidth_weight,
                                },
                                providers,
                                proxy_manager.clone(),
                                cache_store.clone(),
                            )
                            .await,
                        ),
                    );
                }
            }
        }

        Ok(())
    }

    async fn load_proxy_providers(
        &mut self,
        cwd: String,
        proxy_providers: HashMap<String, OutboundProxyProviderDef>,
        resolver: ThreadSafeDNSResolver,
    ) -> Result<(), Error> {
        let proxy_manager = &self.proxy_manager;
        let provider_registry = &mut self.proxy_providers;
        let registry = self.registry.clone();
        let make_proxy_set_provider =
            move |name: &str,
                  vehicle: ThreadSafeProviderVehicle,
                  interval_secs: u64,
                  hc: HealthCheck|
                  -> Result<ArcProxyProvider, Error> {
                ProxySetProvider::new(
                    name.to_owned(),
                    Duration::from_secs(interval_secs),
                    vehicle,
                    hc,
                    Some(registry.clone()),
                )
                .map(|p| Arc::new(p) as ArcProxyProvider)
                .map_err(|x| {
                    Error::InvalidConfig(format!("invalid provider config: {x}"))
                })
            };

        for (name, provider) in proxy_providers.into_iter() {
            let (vehicle, interval_secs, health_check) = match provider {
                OutboundProxyProviderDef::Http(http) => {
                    let path = http.path.unwrap_or_else(|| {
                        let md5 = crate::common::utils::md5_str(http.url.as_bytes());
                        format!("proxy_providers/{md5}.yaml")
                    });
                    let vehicle = http_vehicle::Vehicle::new(
                        http.url.parse::<Uri>().unwrap_or_else(|_| {
                            print_and_exit!("invalid provider url: {}", http.url);
                        }),
                        path,
                        Some(cwd.clone()),
                        resolver.clone(),
                    );
                    (
                        Arc::new(vehicle) as ThreadSafeProviderVehicle,
                        http.interval.unwrap_or(86400),
                        http.health_check,
                    )
                }
                OutboundProxyProviderDef::File(file) => {
                    let vehicle = file_vehicle::Vehicle::new(
                        PathBuf::from(cwd.clone())
                            .join(&file.path)
                            .to_str()
                            .unwrap(),
                    );
                    (
                        Arc::new(vehicle) as ThreadSafeProviderVehicle,
                        file.interval.unwrap_or_default(),
                        file.health_check,
                    )
                }
            };

            let hc = HealthCheck::new(
                vec![],
                health_check
                    .as_ref()
                    .and_then(|h| h.url.clone())
                    .unwrap_or_else(|| {
                        "http://www.gstatic.com/generate_204".to_string()
                    }),
                health_check
                    .as_ref()
                    .and_then(|h| h.interval)
                    .unwrap_or(300),
                health_check.as_ref().and_then(|h| h.lazy).unwrap_or(true),
                proxy_manager.clone(),
            );

            let provider =
                make_proxy_set_provider(&name, vehicle, interval_secs, hc)?;
            provider_registry.insert(name, provider);
        }

        let mut failed = Vec::new();
        for p in provider_registry.values() {
            let name = p.name().to_owned();
            info!("initializing provider {}", name);
            if let Err(err) = p.initialize().await {
                error!("failed to initialize proxy provider {}: {}", name, err);
                failed.push(name);
                continue;
            }
            info!("initialized provider {}", name);
        }
        for name in &failed {
            provider_registry.remove(name);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::{dns::MockClashResolver, profile::ThreadSafeCacheFile},
        config::internal::proxy::{
            OutboundGroupFallback, OutboundGroupProtocol, OutboundGroupSelect,
            OutboundGroupUrlTest,
        },
        proxy::mocks::{MockDummyOutboundHandler, MockDummyProxyProvider},
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_group_healthcheck_url() {
        let mut node1 = MockDummyOutboundHandler::new();
        node1.expect_name().return_const("node-1".to_owned());
        let node1 = Arc::new(node1);
        let outbounds: Vec<AnyOutboundHandler> = vec![node1];
        let outbound_groups = vec![
            OutboundGroupProtocol::UrlTest(OutboundGroupUrlTest {
                name: "url-test-grp".to_string(),
                proxies: Some(vec!["node-1".to_string()]),
                url: "http://custom-url.test/generate_204".to_string(),
                interval: 300,
                lazy: Some(true),
                ..Default::default()
            }),
            OutboundGroupProtocol::Fallback(OutboundGroupFallback {
                name: "fallback-grp".to_string(),
                proxies: Some(vec!["node-1".to_string()]),
                url: "http://fallback-url.test/generate_204".to_string(),
                interval: 300,
                lazy: Some(true),
                ..Default::default()
            }),
            OutboundGroupProtocol::Select(OutboundGroupSelect {
                name: "select-grp".to_string(),
                proxies: Some(vec!["node-1".to_string()]),
                url: None, // should default to DEFAULT_LATENCY_TEST_URL
                ..Default::default()
            }),
        ];

        let resolver = Arc::new(MockClashResolver::new());
        let cache_store = ThreadSafeCacheFile::new("", false);
        let registry = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        let mgr = OutboundManager::new(
            outbounds,
            outbound_groups,
            HashMap::new(),
            vec!["node-1".to_string()],
            resolver,
            cache_store,
            ".".to_string(),
            None,
            registry,
        )
        .await
        .expect("build outbound manager");

        let urltest_provider = mgr
            .proxy_providers
            .get("url-test-grp")
            .expect("url-test provider");
        assert_eq!(
            urltest_provider.healthcheck_url(),
            Some("http://custom-url.test/generate_204")
        );

        let fallback_provider = mgr
            .proxy_providers
            .get("fallback-grp")
            .expect("fallback provider");
        assert_eq!(
            fallback_provider.healthcheck_url(),
            Some("http://fallback-url.test/generate_204")
        );

        let select_provider = mgr
            .proxy_providers
            .get("select-grp")
            .expect("select provider");
        assert_eq!(
            select_provider.healthcheck_url(),
            Some(DEFAULT_LATENCY_TEST_URL)
        );
    }

    #[tokio::test]
    async fn test_get_outbound_finds_provider_proxy() {
        let resolver = Arc::new(MockClashResolver::new());
        let cache_store = ThreadSafeCacheFile::new("", false);
        let registry = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        let mut direct_node = MockDummyOutboundHandler::new();
        direct_node
            .expect_name()
            .return_const("direct-node".to_owned());
        let outbounds: Vec<AnyOutboundHandler> = vec![Arc::new(direct_node)];

        let mut mgr = OutboundManager::new(
            outbounds,
            vec![],
            HashMap::new(),
            vec!["direct-node".to_string()],
            resolver,
            cache_store,
            ".".to_string(),
            None,
            registry,
        )
        .await
        .expect("build outbound manager");

        let mut mock_provider = MockDummyProxyProvider::new();
        mock_provider
            .expect_name()
            .return_const("sub-provider".to_owned());
        mock_provider.expect_proxies().returning(|| {
            let mut node = MockDummyOutboundHandler::new();
            node.expect_name().return_const("sub-node-1".to_owned());
            vec![Arc::new(node)]
        });

        mgr.proxy_providers
            .insert("sub-provider".to_string(), Arc::new(mock_provider));

        let found = mgr.get_outbound("sub-node-1").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), "sub-node-1");

        let not_found = mgr.get_outbound("non-existent-node").await;
        assert!(not_found.is_none());
    }
}
