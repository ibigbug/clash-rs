use super::ProxyProvider;
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
    app::remote_content_manager::{
        healthcheck::HealthCheck,
        providers::{
            Provider, ProviderType, ProviderVehicleType, ThreadSafeProviderVehicle,
            fetcher::Fetcher,
        },
    },
    common::errors::map_io_error,
    config::internal::proxy::OutboundProxyProtocol,
    proxy::{
        AnyOutboundHandler, anytls,
        direct::{self},
        hysteria2, reject, socks, trojan,
        utils::{
            DirectConnector, OutboundHandlerRegistry, ProxyConnector,
            RemoteConnector,
        },
        vless, vmess,
    },
};
use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::{debug, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    #[serde(rename = "proxies")]
    proxies: Option<Vec<HashMap<String, Value>>>,
}

struct Inner {
    proxies: Vec<AnyOutboundHandler>,
}

type ProxyUpdater = Box<
    dyn Fn(Vec<AnyOutboundHandler>) -> BoxFuture<'static, ()>
        + Send
        + Sync
        + 'static,
>;
type ProxyParser = Box<
    dyn Fn(&[u8]) -> anyhow::Result<Vec<AnyOutboundHandler>> + Send + Sync + 'static,
>;

pub struct ProxySetProvider {
    fetcher: Fetcher<ProxyUpdater, ProxyParser>,
    hc: Arc<HealthCheck>,
    inner: Arc<tokio::sync::RwLock<Inner>>,
}

impl ProxySetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        hc: HealthCheck,
        registry: Option<OutboundHandlerRegistry>,
    ) -> anyhow::Result<Self> {
        let hc = Arc::new(hc);

        if hc.auto() {
            let hc = hc.clone();
            debug!("kicking off healthcheck for: {}", &name);
            tokio::spawn(async move {
                hc.kick_off().await;
            });
        }

        let inner = Arc::new(tokio::sync::RwLock::new(Inner { proxies: vec![] }));

        let inner_clone = inner.clone();

        let n = name.clone();
        let hc_updater = hc.clone();
        let updater: ProxyUpdater = Box::new(
            move |input: Vec<AnyOutboundHandler>| -> BoxFuture<'static, ()> {
                let hc = hc_updater.clone();
                let n = n.clone();
                let inner: Arc<tokio::sync::RwLock<Inner>> = inner_clone.clone();
                let registry = registry.clone();
                Box::pin(async move {
                    if let Some(ref registry) = registry {
                        let reg = registry.read().await;
                        let mut connectors: HashMap<
                            String,
                            Arc<dyn RemoteConnector>,
                        > = HashMap::new();
                        for handler in &input {
                            if let Some(connector_name) = handler.support_dialer() {
                                let outbound =
                                    reg.get(connector_name).cloned().or_else(|| {
                                        input
                                            .iter()
                                            .find(|p| p.name() == connector_name)
                                            .cloned()
                                    });
                                if let Some(outbound) = outbound {
                                    let connector = connectors
                                        .entry(connector_name.to_string())
                                        .or_insert_with(|| {
                                            Arc::new(ProxyConnector::new(
                                                outbound,
                                                Box::new(DirectConnector::new()),
                                            ))
                                        });
                                    handler
                                        .register_connector(connector.clone())
                                        .await;
                                } else {
                                    warn!(
                                        provider = n.as_str(),
                                        "connector '{connector_name}' for proxy \
                                         '{}' not found",
                                        handler.name()
                                    );
                                }
                            }
                        }
                    }
                    {
                        let mut inner = inner.write().await;
                        debug!("updating {} proxies for: {}", n, input.len());
                        inner.proxies.clone_from(&input);
                    }
                    hc.update(input).await;
                    tokio::spawn(async move {
                        hc.check(false).await;
                    });
                })
            },
        );

        let n = name.clone();
        let parser: ProxyParser = Box::new(
            move |input: &[u8]| -> anyhow::Result<Vec<AnyOutboundHandler>> {
                let scheme: ProviderScheme =
                    serde_yaml::from_slice(input).map_err(|x| {
                        Error::InvalidConfig(format!(
                            "proxy provider parse error {n}: {x}"
                        ))
                    })?;
                let proxies = scheme.proxies;
                match proxies {
                    Some(proxies) => {
                        let proxies = proxies
                            .into_iter()
                            .filter_map(|x| {
                                match OutboundProxyProtocol::try_from(x) {
                                    Ok(p) => Some(p),
                                    Err(e) => {
                                        warn!(
                                            provider = n.as_str(),
                                            "skipping proxy due to parse error: {e}"
                                        );
                                        None
                                    }
                                }
                            })
                            .map(|x| match x {
                                OutboundProxyProtocol::Direct(d) => {
                                    Ok(Arc::new(direct::Handler::new(&d.name)) as _)
                                }
                                OutboundProxyProtocol::Reject(r) => {
                                    Ok(Arc::new(reject::Handler::new(&r.name)) as _)
                                }
                                #[cfg(feature = "shadowsocks")]
                                OutboundProxyProtocol::Ss(s) => {
                                    let h: shadowsocks::outbound::Handler =
                                        s.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Socks5(s) => {
                                    let h: socks::outbound::Handler =
                                        s.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Anytls(anytls) => {
                                    let h: anytls::Handler = anytls.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Trojan(tr) => {
                                    let h: trojan::Handler = tr.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Vmess(vm) => {
                                    let h: vmess::Handler = vm.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Vless(vl) => {
                                    let h: vless::Handler = vl.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                OutboundProxyProtocol::Hysteria2(h) => {
                                    let h: hysteria2::Handler = h.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "ssh")]
                                OutboundProxyProtocol::Ssh(s) => {
                                    let h: ssh::Handler = s.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "wireguard")]
                                OutboundProxyProtocol::Wireguard(wg) => {
                                    let h: wg::Handler = wg.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "onion")]
                                OutboundProxyProtocol::Tor(tor) => {
                                    let h: tor::Handler = tor.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "tuic")]
                                OutboundProxyProtocol::Tuic(tuic) => {
                                    let h: tuic::Handler = tuic.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "shadowquic")]
                                OutboundProxyProtocol::ShadowQuic(sq) => {
                                    let h: crate::proxy::shadowquic::Handler =
                                        sq.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                                #[cfg(feature = "tailscale")]
                                OutboundProxyProtocol::Tailscale(tscfg) => {
                                    let h: tailscale::Handler = tscfg.try_into()?;
                                    Ok(Arc::new(h) as _)
                                }
                            })
                            .collect::<Result<Vec<_>, crate::Error>>();
                        match proxies {
                            Ok(proxies) => Ok(proxies),
                            Err(e) => {
                                warn!(
                                    provider = n.as_str(),
                                    "proxy provider failed to construct handler: \
                                     {e}"
                                );
                                Err(e.into())
                            }
                        }
                    }
                    _ => Err(Error::InvalidConfig(format!("{n}: proxies is empty"))
                        .into()),
                }
            },
        );

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater));
        Ok(Self { fetcher, hc, inner })
    }
}

#[async_trait]
impl Provider for ProxySetProvider {
    fn name(&self) -> &str {
        self.fetcher.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.fetcher.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Proxy
    }

    async fn initialize(&self) -> std::io::Result<()> {
        let ele = self.fetcher.initial().await.map_err(map_io_error)?;
        debug!("{} initialized with {} proxies", self.name(), ele.len());
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(ele).await;
        }
        // Auto-watch local file providers. Best-effort: watcher setup can fail
        // (inotify limits, unsupported filesystems), so log and keep serving
        // the loaded proxies instead of failing init. No-op for
        // non-file vehicles.
        if let Err(e) = self.fetcher.start_watch().await {
            warn!(
                "proxy provider '{}': live file watching unavailable, falling back \
                 to interval polling: {}",
                self.name(),
                e
            );
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (ele, same) = self.fetcher.update().await.map_err(map_io_error)?;
        debug!(
            "{} updated with {} proxies, same? {}",
            self.name(),
            ele.len(),
            same
        );
        if !same && let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(ele).await;
        }
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();

        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );

        m.insert(
            "updatedAt".to_owned(),
            Box::new(self.fetcher.updated_at().await),
        );

        m
    }
}

#[async_trait]
impl ProxyProvider for ProxySetProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        self.inner.read().await.proxies.to_vec()
    }

    async fn touch(&self) {
        self.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.hc.check(true).await;
    }

    fn healthcheck_url(&self) -> Option<&str> {
        Some(self.hc.url())
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::time::sleep;

    use crate::app::{
        dns::MockClashResolver,
        remote_content_manager::{
            ProxyManager,
            healthcheck::HealthCheck,
            providers::{
                MockProviderVehicle, Provider, ProviderVehicleType,
                proxy_provider::{
                    ProxyProvider, proxy_set_provider::ProxySetProvider,
                },
            },
        },
    };

    #[tokio::test]
    async fn test_proxy_set_provider() {
        let mut mock_vehicle = MockProviderVehicle::new();

        mock_vehicle.expect_read().returning(|| {
            Ok(r#"
proxies:
  - name: "socks5"
    type: socks5
    server: localhost
    port: 1080
    udp: true
"#
            .as_bytes()
            .to_vec())
        });
        mock_vehicle
            .expect_path()
            .return_const("/tmp/test_proxy_set_provider".to_owned());
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let vehicle = Arc::new(mock_vehicle);

        let mock_resolver = MockClashResolver::new();

        let latency_manager = ProxyManager::new(Arc::new(mock_resolver), None);
        let hc = HealthCheck::new(
            vec![],
            "http://www.google.com".to_owned(),
            0,
            true,
            latency_manager.clone(),
        );

        let provider = ProxySetProvider::new(
            "test".to_owned(),
            Duration::from_secs(1),
            vehicle,
            hc,
            None,
        )
        .unwrap();

        assert_eq!(provider.proxies().await.len(), 0);

        provider.initialize().await.unwrap();

        sleep(Duration::from_secs_f64(1.5)).await;

        assert_eq!(provider.proxies().await.len(), 1);
    }
}
