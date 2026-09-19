use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use erased_serde::Serialize;
use tracing::debug;

use crate::{
    Error,
    app::remote_content_manager::{
        healthcheck::HealthCheck,
        providers::{Provider, ProviderType, ProviderVehicleType},
    },
    proxy::AnyOutboundHandler,
};

use super::ProxyProvider;

/// A plain provider that holds a list of outbound handlers (proxies).
/// No vehicle no background update.
/// Used in GroupOutbounds to manage proxy health checks.
pub struct PlainProvider {
    name: String,
    proxies: Vec<AnyOutboundHandler>,
    hc: Arc<HealthCheck>,
}

impl PlainProvider {
    pub fn new(
        name: String,
        proxies: Vec<AnyOutboundHandler>,
        hc: HealthCheck,
    ) -> anyhow::Result<Self> {
        let hc = Arc::new(hc);

        if proxies.is_empty() {
            return Err(
                Error::InvalidConfig(format!("{name}: proxies is empty")).into()
            );
        }

        if hc.auto() {
            debug!("kicking off healthcheck: {}", name);
            let hc = hc.clone();
            tokio::spawn(async move {
                hc.kick_off().await;
            });
        }

        Ok(Self { name, proxies, hc })
    }
}

#[async_trait]
impl Provider for PlainProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        ProviderVehicleType::Compatible
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Proxy
    }

    async fn initialize(&self) -> std::io::Result<()> {
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let mut m: HashMap<String, Box<dyn Serialize + Send>> = HashMap::new();

        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );

        m
    }
}

#[async_trait]
impl ProxyProvider for PlainProvider {
    async fn proxies(&self) -> Vec<AnyOutboundHandler> {
        self.proxies.clone()
    }

    async fn touch(&self) {
        self.hc.touch().await;
    }

    async fn healthcheck(&self) {
        self.hc.check(true).await;
    }
}
