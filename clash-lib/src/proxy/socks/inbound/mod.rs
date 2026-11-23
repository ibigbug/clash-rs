use crate::app::net::SocketMark;
mod datagram;
mod stream;

use crate::{
    Dispatcher,
    common::auth::ThreadSafeAuthenticator,
    proxy::{
        inbound::InboundHandlerTrait,
        utils::{ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener},
    },
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
pub use stream::handle_tcp;
use tracing::warn;

use crate::common::errors::new_io_error;
pub use datagram::Socks5UDPCodec;

pub struct SocksInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<SocketMark>,
}

impl Drop for SocksInbound {
    fn drop(&mut self) {
        warn!("SOCKS5 inbound listener on {} stopped", self.addr);
    }
}

impl SocksInbound {
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
impl InboundHandlerTrait for SocksInbound {
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
                    warn!("socks accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let src_addr = match socket.peer_addr() {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("socks peer_addr failed: {e}");
                    continue;
                }
            };
            if !self.allow_lan {
                let local_ip = match socket.local_addr() {
                    Ok(a) => a.ip().to_canonical(),
                    Err(e) => {
                        warn!("socks local_addr failed: {e}");
                        continue;
                    }
                };
                if src_addr.ip() != local_ip {
                    warn!("Connection from {} is not allowed", src_addr);
                    continue;
                }
            }
            if let Err(e) = apply_tcp_options(&socket) {
                warn!("socks apply_tcp_options failed: {e}");
                continue;
            }

            let mut sess = Session {
                network: Network::Tcp,
                typ: Type::Socks5,
                source: src_addr,
                so_mark: self.fw_mark,

                ..Default::default()
            };

            let dispatcher = self.dispatcher.clone();
            let authenticator = self.authenticator.clone();

            tokio::spawn(async move {
                handle_tcp(&mut sess, socket, dispatcher, authenticator).await
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("UDP is not supported"))
    }
}
