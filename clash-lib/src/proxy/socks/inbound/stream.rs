use crate::{
    Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::new_io_error},
    proxy::{
        socks::{
            SOCKS5_VERSION,
            inbound::{Socks5UDPCodec, datagram::InboundUdp},
            socks5::{auth_methods, response_code, socks_command},
        },
        utils::new_udp_socket,
    },
    session::{Network, Session, SocksAddr, Type},
};

use bytes::{BufMut, BytesMut};

use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::udp::UdpFramed;
use tracing::{instrument, trace, warn};

#[instrument(skip(sess, s, dispatcher, authenticator))]
pub async fn handle_tcp(
    sess: &mut Session,
    mut s: TcpStream,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
) -> io::Result<()> {
    // handshake
    let mut buf = BytesMut::new();
    {
        // TODO: move this to a function
        buf.resize(2, 0);
        s.read_exact(&mut buf[..]).await?;

        if buf[0] != SOCKS5_VERSION {
            return Err(io::Error::other("unsupported SOCKS version"));
        }

        let n_methods = buf[1] as usize;
        if n_methods == 0 {
            return Err(io::Error::other("malformed SOCKS data"));
        }

        buf.resize(n_methods, 0);
        s.read_exact(&mut buf[..]).await?;

        let mut response = [SOCKS5_VERSION, auth_methods::NO_METHODS];
        let methods = &buf[..];

        if authenticator.enabled() {
            if !methods.contains(&auth_methods::USER_PASS) {
                response[1] = response_code::FAILURE;
                s.write_all(&response).await?;
                s.shutdown().await?;
                return Err(new_io_error("auth required"));
            }

            response[1] = auth_methods::USER_PASS;
            s.write_all(&response).await?;

            // +----+------+----------+------+----------+
            // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            // +----+------+----------+------+----------+
            // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            // +----+------+----------+------+----------+
            buf.resize(2, 0);
            s.read_exact(&mut buf[..]).await?;
            let ulen = buf[1] as usize;
            buf.resize(ulen, 0);
            s.read_exact(&mut buf[..]).await?;
            let user = String::from_utf8_lossy(&buf[..]).into_owned();

            s.read_exact(&mut buf[..1]).await?;
            let plen = buf[0] as usize;
            buf.resize(plen, 0);
            s.read_exact(&mut buf[..]).await?;
            let pass = String::from_utf8_lossy(&buf[..]).into_owned();

            match authenticator.authenticate(&user, &pass) {
                // +----+--------+
                // |VER | STATUS |
                // +----+--------+
                // | 1  |   1    |
                // +----+--------+
                true => {
                    response = [0x1, response_code::SUCCEEDED];
                    s.write_all(&response).await?;
                }
                false => {
                    response = [0x1, response_code::FAILURE];
                    s.write_all(&response).await?;
                    s.shutdown().await?;
                    return Err(io::Error::other("auth failure"));
                }
            }
        } else if methods.contains(&auth_methods::NO_AUTH) {
            response[1] = auth_methods::NO_AUTH;
            s.write_all(&response).await?;
        } else {
            response[1] = auth_methods::NO_METHODS;
            s.write_all(&response).await?;
            s.shutdown().await?;
            return Err(io::Error::other("auth failure"));
        }
    }

    buf.resize(3, 0);
    s.read_exact(&mut buf[..]).await?;
    if buf[0] != SOCKS5_VERSION {
        return Err(io::Error::other("unsupported SOCKS version"));
    }

    let dst = SocksAddr::read_from(&mut s).await?;

    match buf[1] {
        socks_command::CONNECT => {
            trace!("Got a CONNECT request from {}", s.peer_addr()?);

            buf.clear();
            buf.put_u8(SOCKS5_VERSION);
            buf.put_u8(response_code::SUCCEEDED);
            buf.put_u8(0x0);
            let bnd = SocksAddr::from(s.local_addr()?);
            bnd.write_buf(&mut buf);
            s.write_all(&buf[..]).await?;
            sess.destination = dst;

            dispatcher
                .dispatch_stream(sess.to_owned(), Box::new(s))
                .await;

            Ok(())
        }
        socks_command::UDP_ASSOCIATE => {
            let udp_addr = SocketAddr::new(s.local_addr()?.ip(), 0);
            let udp_inbound = new_udp_socket(
                Some(udp_addr),
                None,
                #[cfg(target_os = "linux")]
                None,
                None,
            )
            .await?;

            trace!(
                "Got a UDP_ASSOCIATE request from {}, UDP assigned at {}",
                s.peer_addr()?,
                udp_inbound.local_addr()?
            );

            buf.clear();
            buf.put_u8(SOCKS5_VERSION);
            buf.put_u8(response_code::SUCCEEDED);
            buf.put_u8(0x0);
            let bnd = SocksAddr::from(udp_inbound.local_addr()?);
            bnd.write_buf(&mut buf);

            let (close_handle, close_listener) = tokio::sync::oneshot::channel();

            let framed = UdpFramed::new(udp_inbound, Socks5UDPCodec);
            let so_mark = sess.so_mark;
            let iface = sess.iface.clone();
            let sess = Session {
                network: Network::Udp,
                typ: Type::Socks5,
                so_mark,
                iface,
                ..Default::default()
            };

            let dispatcher_cloned = dispatcher.clone();

            tokio::spawn(async move {
                let handle = dispatcher_cloned
                    .dispatch_datagram(sess, Box::new(InboundUdp::new(framed)))
                    .await;
                close_listener.await.ok();
                handle.send(0).ok();
            });

            s.write_all(&buf[..]).await?;

            buf.resize(1, 0);
            match s.read(&mut buf[..]).await {
                Ok(_) => {
                    trace!("UDP association finished, closing");
                }
                Err(e) => {
                    warn!("SOCKS client closed connection: {}", e);
                }
            }

            let _ = close_handle.send(1);

            Ok(())
        }
        _ => {
            buf.clear();
            buf.put_u8(SOCKS5_VERSION);
            buf.put_u8(response_code::COMMAND_NOT_SUPPORTED);
            buf.put_u8(0x0);
            SocksAddr::any_ipv4().write_buf(&mut buf);
            s.write_all(&buf).await?;
            Err(io::Error::other("unsupported SOCKS command"))
        }
    }
}
