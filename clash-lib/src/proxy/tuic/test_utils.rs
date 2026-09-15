//! In-process Wind server, assembled like tuic-server's plugin.
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use wind_base::direct::{DirectOutbound, DirectOutboundOpts};
use wind_core::{
    App, FlowContext, RouteAction, Router, StaticTuicAuth, SystemResolver,
    utils::StackPrefer,
};
use wind_tuic::quinn::inbound::{TlsProvider, TuicInbound, TuicInboundOpts};

struct DirectRouter;
impl Router for DirectRouter {
    async fn route(&self, _ctx: &FlowContext) -> eyre::Result<RouteAction> {
        Ok(RouteAction::Forward("direct".into()))
    }
}

/// Cancels every server connection as well as the listener on drop.
pub struct TuicServerProcess {
    handle: tokio::task::JoinHandle<eyre::Result<()>>,
    cancel: CancellationToken,
    port: u16,
}

impl TuicServerProcess {
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_at("127.0.0.1:0").await
    }

    pub async fn start_v6() -> anyhow::Result<Self> {
        Self::start_at("[::1]:0").await
    }

    pub async fn start_dual_stack() -> anyhow::Result<Self> {
        Self::start_at("[::]:0").await
    }

    async fn start_at(bind: &str) -> anyhow::Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let users = HashMap::from([(
            "00000000-0000-0000-0000-000000000001".parse()?,
            "passwd".to_owned(),
        )]);
        let (bound_tx, mut bound_rx) = watch::channel(None);
        let tls = TlsProvider::Files {
            certificate: vec![cert.cert.der().clone()],
            private_key: rustls::pki_types::PrivatePkcs8KeyDer::from(
                cert.signing_key.serialize_der(),
            )
            .into(),
        };
        let listen_addr = bind.parse()?;
        let app = App::new()
            .set_router(DirectRouter)
            .set_tuic_authenticator(Arc::new(StaticTuicAuth::from_passwords(&users)))
            .add_outbound(
                "direct",
                Arc::new(DirectOutbound::new(
                    DirectOutboundOpts {
                        bind_ipv4: None,
                        bind_ipv6: None,
                        bind_device: None,
                        stream_timeout: Duration::from_secs(5),
                        tcp_keepalive: None,
                        ip_mode: None,
                        routing_mark: None,
                        tfo: false,
                        mptcp: false,
                    },
                    Arc::new(SystemResolver::new(StackPrefer::V4first)),
                )),
            )
            .add_inbound_with(move |hooks, ctx| {
                TuicInbound::new(
                    ctx,
                    TuicInboundOpts {
                        hooks,
                        listen_addr,
                        tls,
                        bound_addr: Some(bound_tx),
                        max_idle_time: Duration::from_secs(30),
                        zero_rtt: true,
                        ..Default::default()
                    },
                )
            });
        let cancel = app.context().token.clone();
        let handle = tokio::spawn(app.run());
        // Construct the drop guard before waiting, so failed startup cleans up.
        let mut server = Self {
            handle,
            cancel,
            port: 0,
        };
        server.port = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(addr) = *bound_rx.borrow_and_update() {
                    return Ok::<_, anyhow::Error>(addr.port());
                }
                bound_rx.changed().await?;
            }
        })
        .await??;
        Ok(server)
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}
impl Drop for TuicServerProcess {
    fn drop(&mut self) {
        self.cancel.cancel();
        // App observes cancellation and drains its tracked connection tasks.
        // Dropping a JoinHandle detaches that orderly shutdown.
        let _ = &self.handle;
    }
}
