use crate::{
    Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    proxy::utils::{ToCanonical, try_create_dualstack_tcplistener},
    session::{Network, Session},
};

use super::{http, inbound::InboundHandlerTrait, socks, utils::apply_tcp_options};
use crate::common::errors::new_io_error;
use async_trait::async_trait;
use hyper_util::rt::TokioIo;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

pub struct MixedInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<u32>,
}

impl Drop for MixedInbound {
    fn drop(&mut self) {
        warn!("MixedPort inbound listener on {} stopped", self.addr);
    }
}

impl MixedInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        authenticator: ThreadSafeAuthenticator,
        fw_mark: Option<u32>,
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
impl InboundHandlerTrait for MixedInbound {
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
                    warn!("failed to accept socket on {}: {:?}", self.addr, e);
                    continue;
                }
            };
            let src_addr = match socket.peer_addr() {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("failed to get peer address: {:?}", e);
                    continue;
                }
            };
            if !self.allow_lan {
                let local_ip = match socket.local_addr() {
                    Ok(a) => a.ip().to_canonical(),
                    Err(e) => {
                        warn!("mixed local_addr failed: {e}");
                        continue;
                    }
                };
                if src_addr.ip() != local_ip {
                    warn!("Connection from {} is not allowed", src_addr);
                    continue;
                }
            }
            if let Err(e) = apply_tcp_options(&socket) {
                warn!("mixed apply_tcp_options failed: {e}");
                continue;
            }

            let mut p = [0; 1];
            let n = match socket.peek(&mut p).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        "failed to peek socket on mixed listener {}: {:?}",
                        self.addr, e
                    );
                    continue;
                }
            };
            if n != 1 {
                warn!("failed to peek socket on mixed listener {}", self.addr);
                continue;
            }

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();
            let fw_mark = self.fw_mark;

            match p[0] {
                socks::SOCKS5_VERSION => {
                    let mut sess = Session {
                        network: Network::Tcp,
                        source: src_addr,
                        so_mark: fw_mark,
                        ..Default::default()
                    };

                    tokio::spawn(async move {
                        socks::inbound::handle_tcp(
                            &mut sess,
                            socket,
                            dispatcher,
                            authenticator,
                        )
                        .await
                    });
                }

                _ => {
                    let src = src_addr;
                    let authenticator = authenticator.clone();
                    tokio::spawn(async move {
                        http::handle_http(
                            TokioIo::new(Box::new(socket) as _),
                            src,
                            dispatcher,
                            authenticator,
                            fw_mark,
                        )
                        .await;
                    });
                }
            }
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("UDP is not supported"))
    }
}
