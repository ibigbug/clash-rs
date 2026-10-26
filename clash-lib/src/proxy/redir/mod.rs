use super::inbound::InboundHandlerTrait;
use crate::{
    app::dispatcher::Dispatcher,
    common::errors::new_io_error,
    proxy::utils::{
        ToCanonical, apply_tcp_options, try_create_dualstack_tcplistener,
    },
    session::{Network, Session, Type},
};

use async_trait::async_trait;
use std::{io, net::SocketAddr, os::fd::AsRawFd, sync::Arc};
use tokio::net::TcpStream;
use tracing::{trace, warn};

pub struct RedirInbound {
    addr: SocketAddr,
    allow_lan: bool,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<u32>,
}

impl Drop for RedirInbound {
    fn drop(&mut self) {
        warn!("Redir inbound listener on {} stopped", self.addr);
    }
}

impl RedirInbound {
    pub fn new(
        addr: SocketAddr,
        allow_lan: bool,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<u32>,
    ) -> Self {
        Self {
            addr,
            allow_lan,
            dispatcher,
            fw_mark,
        }
    }
}

#[async_trait]
impl InboundHandlerTrait for RedirInbound {
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
                    warn!("redir accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let src_addr = match socket.peer_addr() {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("redir peer_addr failed: {e}");
                    continue;
                }
            };

            if !self.allow_lan {
                let local_ip = match socket.local_addr() {
                    Ok(a) => a.ip().to_canonical(),
                    Err(e) => {
                        warn!("redir local_addr failed: {e}");
                        continue;
                    }
                };
                if src_addr.ip() != local_ip {
                    warn!("Connection from {} is not allowed", src_addr);
                    continue;
                }
            }

            if let Err(e) = apply_tcp_options(&socket) {
                warn!("redir apply_tcp_options failed: {e}");
                continue;
            }

            // get redirect traffic original destination
            let orig_dst = match get_original_destination_addr(&socket) {
                Ok(a) => a.to_canonical(),
                Err(e) => {
                    warn!("redir get_original_destination failed: {e}");
                    continue;
                }
            };

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Redir,
                source: src_addr,
                destination: orig_dst.into(),
                so_mark: self.fw_mark,
                ..Default::default()
            };

            trace!("redir new tcp conn {}", sess);

            let dispatcher = self.dispatcher.clone();
            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(socket)).await;
            });
        }
    }

    async fn listen_udp(&self) -> std::io::Result<()> {
        Err(new_io_error("unsupported UDP protocol for Redir inbound"))
    }
}

// get original destination
// https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/local/redir/tcprelay/sys/unix/linux.rs#L111
fn get_original_destination_addr(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();

    unsafe {
        let (_, target_addr) =
            socket2::SockAddr::try_init(|target_addr, target_addr_len| {
                // No sufficient method to know whether the destination IPv4 or
                // IPv6. Follow the method in shadowsocks-libev.

                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IPV6,
                    libc::IP6T_SO_ORIGINAL_DST,
                    target_addr as *mut _,
                    target_addr_len, // libc::socklen_t
                );

                if ret == 0 {
                    return Ok(());
                } else {
                    let err = io::Error::last_os_error();
                    match err.raw_os_error() {
                        None => return Err(err),
                        // ENOPROTOOPT, EOPNOTSUPP (ENOTSUP):
                        // IP6T_SO_ORIGINAL_DST doesn't exist ENOENT:
                        // Destination address is not IPv6
                        #[allow(unreachable_patterns)]
                        Some(libc::ENOPROTOOPT)
                        | Some(libc::ENOENT)
                        | Some(libc::EOPNOTSUPP)
                        | Some(libc::ENOTSUP) => {}
                        Some(..) => return Err(err),
                    }
                }

                let ret = libc::getsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::SO_ORIGINAL_DST,
                    target_addr as *mut _,
                    target_addr_len, // libc::socklen_t
                );

                if ret != 0 {
                    let err = io::Error::last_os_error();
                    return Err(err);
                }

                Ok(())
            })?;

        // Convert sockaddr_storage to SocketAddr
        target_addr.as_socket().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "not a socket address")
        })
    }
}
