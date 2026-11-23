use crate::app::net::SocketMark;
mod auth;
mod connector;
mod proxy;

use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    proxy::{
        inbound::InboundHandlerTrait,
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener},
    },
};
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
pub use proxy::handle as handle_http;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

#[derive(Clone)]
pub struct HttpInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<SocketMark>,
}

impl Drop for HttpInbound {
    fn drop(&mut self) {
        warn!("HTTP inbound listener on {} stopped", self.addr);
    }
}

impl HttpInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        fw_mark: Option<SocketMark>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            authenticator,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for HttpInbound {
    fn handle_tcp(&self) -> bool {
        true
    }

    fn handle_udp(&self) -> bool {
        false
    }

    async fn listen_tcp(&self) -> std::io::Result<()> {
        let listener = try_create_dualstack_tcplistener(self.addr)?;

        loop {
            let (socket, _) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("http accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let src_addr = match socket.peer_addr() {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("http peer_addr failed: {e}");
                    continue;
                }
            };
            if !self.allow_lan {
                let local_ip = match socket.local_addr() {
                    Ok(a) => a.ip().to_canonical(),
                    Err(e) => {
                        warn!("http local_addr failed: {e}");
                        continue;
                    }
                };
                if src_addr.ip() != local_ip {
                    warn!("Connection from {} is not allowed", src_addr);
                    continue;
                }
            }

            if let Err(e) = apply_tcp_options(&socket) {
                warn!("http apply_tcp_options failed: {e}");
                continue;
            }

            let dispatcher = self.dispatcher.clone();
            let author = self.authenticator.clone();
            let fw_mark = self.fw_mark;
            tokio::spawn(async move {
                proxy::handle(
                    TokioIo::new(Box::new(socket)),
                    src_addr,
                    dispatcher,
                    author,
                    fw_mark,
                )
                .await
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("unsupported UDP protocol for HTTP inbound"))
    }
}
