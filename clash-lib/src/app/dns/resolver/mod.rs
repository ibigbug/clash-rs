mod enhanced;

#[cfg(all(target_feature = "crt-static", target_env = "gnu"))]
#[path = "system_static_crt.rs"]
mod system;

#[cfg(not(all(target_feature = "crt-static", target_env = "gnu")))]
#[path = "system.rs"]
mod system;

use std::sync::Arc;

pub use enhanced::EnhancedResolver;
pub use system::SystemResolver;

use super::{Config, ThreadSafeDNSResolver};
use crate::{
    app::{
        net::{DEFAULT_OUTBOUND_INTERFACE, OutboundInterface},
        profile::ThreadSafeCacheFile,
    },
    dns::{RuleDispatch, filters::PendingMmdb},
    print_and_exit,
    proxy::utils::OutboundHandlerRegistry,
};

pub async fn new(
    cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<PendingMmdb>,
    outbounds: OutboundHandlerRegistry,
    rule_dispatch: Option<Arc<RuleDispatch>>,
) -> ThreadSafeDNSResolver {
    let interface = DEFAULT_OUTBOUND_INTERFACE.read().await.clone();
    new_with_interface(
        cfg,
        store,
        mmdb,
        outbounds,
        rule_dispatch,
        interface.as_ref(),
    )
    .await
}

pub(crate) async fn new_with_interface(
    cfg: Config,
    store: Option<ThreadSafeCacheFile>,
    mmdb: Option<PendingMmdb>,
    outbounds: OutboundHandlerRegistry,
    rule_dispatch: Option<Arc<RuleDispatch>>,
    interface: Option<&OutboundInterface>,
) -> ThreadSafeDNSResolver {
    if cfg.enable {
        match store {
            Some(store) => Arc::new(
                EnhancedResolver::new_with_interface(
                    cfg,
                    store,
                    mmdb,
                    outbounds,
                    rule_dispatch,
                    interface,
                )
                .await,
            ),
            _ => print_and_exit!("enhanced resolver requires cache store"),
        }
    } else {
        Arc::new(
            SystemResolver::new(cfg.ipv6).expect("failed to create system resolver"),
        )
    }
}
