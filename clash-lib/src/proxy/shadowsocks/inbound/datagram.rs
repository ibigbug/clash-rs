use crate::{
    common::errors::new_io_error,
    proxy::{datagram::UdpPacket, utils::ToCanonical},
    session::SocksAddr,
};
use futures::ready;
use shadowsocks::{ProxySocket, relay::udprelay::options::UdpSocketControlData};
use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;
use tracing::{debug, error};

pub(crate) struct InboundShadowsocksDatagram {
    // Per-client control data keyed by the client's SocketAddr.
    //
    // SS2022 multi-user UDP: the server must encrypt each response with the
    // same uPSK (user key) that was used to authenticate the corresponding
    // request, and must echo the client's session ID.  Because this single
    // socket receives packets from *all* clients, a single shared
    // `UdpSocketControlData` field is insufficient: in a concurrent setting
    // the field would be overwritten by the most-recently-received packet,
    // causing responses for earlier clients to be encrypted with the wrong
    // key (MAC failure on the client side).
    //
    // The server_session_id is the same for all clients (it identifies this
    // server-side socket session). packet_id is tracked per-client to satisfy
    // the monotonic-ID replay-protection requirement at each individual client.
    server_session_id: u64,
    client_controls: HashMap<SocketAddr, UdpSocketControlData>,

    socket: ProxySocket<shadowsocks::net::UdpSocket>,

    // for Sink
    pkt: Option<UdpPacket>,

    // for Stream
    buf: bytes::BytesMut,
}

impl std::fmt::Debug for InboundShadowsocksDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundShadowsocksDatagram")
            .field("server_session_id", &self.server_session_id)
            .field("socket", &self.socket)
            .finish()
    }
}

impl InboundShadowsocksDatagram {
    pub fn new(socket: ProxySocket<shadowsocks::net::UdpSocket>) -> Self {
        Self {
            buf: bytes::BytesMut::with_capacity(65535),
            socket,
            server_session_id: rand::random::<u64>(),
            client_controls: HashMap::new(),
            pkt: None,
        }
    }
}

impl futures::Stream for InboundShadowsocksDatagram {
    type Item = UdpPacket;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut buf,
            ref socket,
            ref server_session_id,
            ref mut client_controls,
            ..
        } = *self.get_mut();

        loop {
            buf.resize(buf.capacity(), 0);
            let mut read_buf = ReadBuf::new(buf);

            let rv = ready!(socket.poll_recv_from_with_ctrl(cx, &mut read_buf));
            debug!("recv udp packet from inbound: {:?}", rv);

            match rv {
                Ok((n, src, target, _, ctrl)) => {
                    // Canonicalize IPv4-mapped IPv6 source addresses (e.g.
                    // ::ffff:x.x.x.x → x.x.x.x) so the key stored here
                    // matches the canonical sess.source the dispatcher assigns
                    // after commit 6783909.  Without this, the Sink's
                    // client_controls lookup uses the canonical address
                    // (from pkt.dst_addr = sess.source) but finds no entry
                    // because it was stored under the raw IPv4-mapped form,
                    // producing "no control entry" and dropping all IPv4 UDP
                    // replies.
                    let src = src.to_canonical();

                    // Upsert the per-client control entry so responses to this
                    // client are encrypted with the correct uPSK and echo the
                    // correct client_session_id.  packet_id is kept per-client
                    // for monotonic replay protection at each individual
                    // client.
                    if let Some(ref c) = ctrl {
                        let entry =
                            client_controls.entry(src).or_insert_with(|| {
                                let mut d = UdpSocketControlData::default();
                                d.server_session_id = *server_session_id;
                                d
                            });
                        entry.client_session_id = c.client_session_id;
                        entry.user = c.user.clone();
                    }

                    return Poll::Ready(Some(UdpPacket {
                        data: read_buf.filled()[..n].to_vec(),
                        src_addr: src.into(),
                        dst_addr: match target {
                            shadowsocks::relay::Address::SocketAddress(a) => {
                                a.into()
                            }
                            shadowsocks::relay::Address::DomainNameAddress(
                                domain,
                                port,
                            ) => SocksAddr::Domain(domain, port),
                        },
                        inbound_user: ctrl
                            .and_then(|c| c.user)
                            .map(|u| u.name().to_owned()),
                    }));
                }
                Err(e) => {
                    // Log the error but keep the stream alive. Without looping
                    // here, returning Poll::Pending would leave the task
                    // without a registered waker (the waker
                    // was consumed when data
                    // arrived), permanently suspending the UDP dispatch loop.
                    error!("failed to receive udp packet: {}", e);
                    // Fall through to the next loop iteration: if the socket
                    // is empty, poll_recv_from_with_ctrl will re-register the
                    // waker and return Poll::Pending via ready!().
                }
            }
        }
    }
}

impl futures::Sink<UdpPacket> for InboundShadowsocksDatagram {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_some() {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.pkt = Some(item);
        debug!("start sending udp packet: {:?}", pin.pkt);
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pkt.is_none() {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut socket,
            ref mut pkt,
            ref mut client_controls,
            ..
        } = *self;

        let pkt_container = pkt;

        if let Some(pkt) = pkt_container {
            let addr: shadowsocks::relay::Address = match &pkt.src_addr {
                SocksAddr::Ip(addr) => {
                    shadowsocks::relay::Address::SocketAddress(*addr)
                }
                SocksAddr::Domain(host, port) => {
                    shadowsocks::relay::Address::DomainNameAddress(
                        host.clone(),
                        *port,
                    )
                }
            };

            // Look up the per-client control for this response's destination.
            // This entry must already exist: a response can only arrive after
            // poll_next() has received and dispatched the corresponding request
            // from this client, which is what populates client_controls.
            // A missing entry would mean we have no user key, so we'd silently
            // encrypt with iPSK and the client would get a MAC failure --
            // exactly the bug we are fixing. Error out loudly instead.
            let client_addr = pkt.dst_addr.clone().must_into_socket_addr();
            let control = match client_controls.get_mut(&client_addr) {
                Some(c) => c,
                None => {
                    error!(
                        "no control entry for client {client_addr} - dropping \
                         response to avoid iPSK fallback"
                    );
                    *pkt_container = None;
                    return Poll::Ready(Ok(()));
                }
            };

            let n = ready!(socket.poll_send_to_with_ctrl(
                client_addr,
                &addr,
                control,
                pkt.data.as_ref(),
                cx
            ))?;

            debug!("send udp packet to client {}", pkt);

            control.packet_id = match control.packet_id.checked_add(1) {
                Some(id) => id,
                None => {
                    error!("packet_id overflow, closing socket");
                    return Poll::Ready(Err(std::io::Error::other(
                        "packet_id overflow",
                    )));
                }
            };

            let wrote_all = n == pkt.data.len();
            *pkt_container = None;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(new_io_error(format!(
                    "failed to write entire datagram, written: {n}"
                )))
            };
            Poll::Ready(res)
        } else {
            debug!("no udp packet to send");
            Poll::Ready(Err(std::io::Error::other("no packet to send")))
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}
