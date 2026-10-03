use crate::{
    common::auth::ThreadSafeAuthenticator,
    config::listener::{InboundOpts, InboundUser},
    proxy::{
        anytls::inbound::{AnytlsInbound, InboundOptions as AnytlsInboundOptions},
        http::HttpInbound,
        hysteria2::inbound::{
            Hysteria2Inbound, InboundOptions as Hysteria2InboundOptions,
        },
        inbound::InboundHandlerTrait,
        mixed::MixedInbound,
        socks::inbound::SocksInbound,
        tunnel::TunnelInbound,
    },
};

#[cfg(all(target_os = "linux", feature = "redir"))]
use crate::proxy::redir::RedirInbound;
#[cfg(all(target_os = "linux", feature = "tproxy"))]
use crate::proxy::tproxy::TproxyInbound;

use crate::Dispatcher;
use futures::future::BoxFuture;
use tracing::{error, info, warn};

#[cfg(feature = "shadowsocks")]
use crate::proxy::shadowsocks::inbound::{InboundOptions, ShadowsocksInbound};
use std::sync::Arc;

use crate::app::dns::ThreadSafeDNSResolver;

pub(crate) fn build_network_listeners(
    inbound_opts: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    users_rx: Option<tokio::sync::watch::Receiver<Vec<InboundUser>>>,
    dns_resolver: Option<ThreadSafeDNSResolver>,
) -> Option<Vec<BoxFuture<'static, Result<(), crate::Error>>>> {
    let name = &inbound_opts.common_opts().name;
    let addr = inbound_opts.common_opts().listen.0;
    let port = inbound_opts.common_opts().port;

    if let Some(handler) = build_handler(
        inbound_opts,
        dispatcher,
        authenticator,
        users_rx,
        dns_resolver,
    ) {
        let mut runners: Vec<BoxFuture<'static, Result<(), crate::Error>>> =
            Vec::new();

        if handler.handle_tcp() {
            let tcp_listener = handler.clone();

            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} TCP listening at: {}:{}", name, addr, port,);
                tcp_listener
                    .listen_tcp()
                    .await
                    .inspect_err(|x| {
                        error!("handler {} tcp listen failed: {x}", name);
                    })
                    .map_err(|e| e.into())
            }));
        }

        if handler.handle_udp() {
            let udp_listener = handler.clone();
            let name = name.clone();
            runners.push(Box::pin(async move {
                info!("{} UDP listening at: {}:{}", name, addr, port,);
                udp_listener
                    .listen_udp()
                    .await
                    .inspect_err(|x| {
                        error!("handler {} udp listen failed: {x}", name);
                    })
                    .map_err(|e| e.into())
            }));
        }

        if runners.is_empty() {
            warn!("no listener for {}", name);
            return None;
        }
        Some(runners)
    } else {
        None
    }
}

fn build_handler(
    listener: &InboundOpts,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    #[allow(unused)] users_rx: Option<
        tokio::sync::watch::Receiver<Vec<InboundUser>>,
    >,
    #[allow(unused)] dns_resolver: Option<ThreadSafeDNSResolver>,
) -> Option<Arc<dyn InboundHandlerTrait>> {
    let fw_mark = listener.common_opts().fw_mark;
    match listener {
        InboundOpts::Http { common_opts, .. } => Some(Arc::new(HttpInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),

        InboundOpts::Socks { common_opts, .. } => Some(Arc::new(SocksInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        InboundOpts::Mixed { common_opts, .. } => Some(Arc::new(MixedInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            common_opts.allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        ))),
        #[cfg(feature = "tproxy")]
        InboundOpts::TProxy {
            #[cfg(target_os = "linux")]
            common_opts,
            #[cfg(target_os = "linux")]
            dns_hijack,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(TproxyInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                    dns_resolver,
                    *dns_hijack,
                )))
            }

            #[cfg(not(target_os = "linux"))]
            {
                warn!("tproxy is not supported on this platform");
                None
            }
        }
        #[cfg(feature = "redir")]
        InboundOpts::Redir {
            #[cfg(target_os = "linux")]
            common_opts,
            ..
        } => {
            #[cfg(target_os = "linux")]
            {
                Some(Arc::new(RedirInbound::new(
                    (common_opts.listen.0, common_opts.port).into(),
                    common_opts.allow_lan,
                    dispatcher,
                    fw_mark,
                )))
            }
            #[cfg(not(target_os = "linux"))]
            {
                warn!("redir is not supported on this platform");
                None
            }
        }
        InboundOpts::Tunnel {
            common_opts,
            network,
            target,
        } => TunnelInbound::new(
            (common_opts.listen.0, common_opts.port).into(),
            dispatcher,
            network.clone(),
            target.clone(),
            fw_mark,
        )
        .inspect_err(|x| {
            warn!("tunnel inbound handler failed to create: {x}");
        })
        .map(|x| Arc::new(x) as _)
        .ok(),
        #[cfg(feature = "shadowsocks")]
        InboundOpts::Shadowsocks {
            common_opts,
            udp,
            cipher,
            password,
            users,
        } => {
            // Use the provided watch receiver, or create a static one for
            // non-provider (static config) inbounds whose user list never
            // changes.
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            Some(Arc::new(ShadowsocksInbound::new(InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                udp: *udp,
                cipher: cipher.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                authenticator,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            })))
        }
        InboundOpts::Anytls {
            common_opts,
            password,
            certificate,
            private_key,
            fallback,
            users,
        } => {
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            match AnytlsInbound::new(AnytlsInboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                fallback: fallback.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("anytls inbound failed to init: {e}");
                    None
                }
            }
        }
        InboundOpts::Hysteria2 {
            common_opts,
            password,
            certificate,
            private_key,
            users,
        } => {
            let rx = users_rx
                .unwrap_or_else(|| tokio::sync::watch::channel(users.clone()).1);
            match Hysteria2Inbound::new(Hysteria2InboundOptions {
                addr: (common_opts.listen.0, common_opts.port).into(),
                password: password.clone(),
                certificate: certificate.clone(),
                private_key: private_key.clone(),
                allow_lan: common_opts.allow_lan,
                dispatcher,
                fw_mark: common_opts.fw_mark,
                users_rx: rx,
            }) {
                Ok(h) => Some(Arc::new(h)),
                Err(e) => {
                    warn!("hysteria2 inbound failed to init: {e}");
                    None
                }
            }
        }
    }
}
