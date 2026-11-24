use crate::{
    app::dns::ThreadSafeDNSResolver, common::errors::new_io_error,
    proxy::datagram::UdpPacket, session::SocksAddr,
};
use futures::{Sink, Stream, ready};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{io::ReadBuf, net::UdpSocket, task::JoinHandle};

const UDP_DOMAIN_MAP_TTL: Duration = Duration::from_secs(60);

/// Send-side state of [`OutboundDatagramImpl`].
///
/// ```text
/// Idle ──start_send(ip)─────────────────────────────▶ Sending
///   └───start_send(domain)──▶ Resolving ──resolved──▶ Sending ──sent──▶ Idle
///                                 └──── dns error ───▶ Idle (dropped)
/// ```
///
/// Any error drops the queued packet and returns to `Idle`, so one
/// unresolvable or unsendable packet cannot block the packets behind it.
enum SendState {
    Idle,
    /// DNS lookup for a domain destination is in flight. Uses a spawned task
    /// (`JoinHandle` is `Send + Sync`) rather than a boxed future so the
    /// datagram satisfies the `Sync` bound required by
    /// `InstrumentedDatagram`; it is spawned once and awaited across polls.
    Resolving {
        pkt: UdpPacket,
        task: JoinHandle<io::Result<SocketAddr>>,
    },
    /// Destination resolved; waiting for the socket to accept the datagram.
    Sending {
        pkt: UdpPacket,
        dst: SocketAddr,
    },
}

#[must_use = "sinks do nothing unless polled"]
// TODO: maybe we should use abstract datagram IO interface instead of the
// Stream + Sink trait
pub struct OutboundDatagramImpl {
    inner: UdpSocket,
    resolver: ThreadSafeDNSResolver,
    send: SendState,
    recv_buf: Vec<u8>,
    // real upstream IP → dst_addr of the most recent outgoing packet to that
    // IP; used in poll_next to translate src_addr back to dst_addr.
    ip_to_logical: HashMap<SocketAddr, (SocksAddr, Instant)>,
}

impl OutboundDatagramImpl {
    pub fn new(udp: UdpSocket, resolver: ThreadSafeDNSResolver) -> Self {
        Self {
            inner: udp,
            resolver,
            send: SendState::Idle,
            recv_buf: vec![0u8; 65535],
            ip_to_logical: HashMap::new(),
        }
    }

    fn spawn_resolve(
        &self,
        domain: String,
        port: u16,
    ) -> io::Result<JoinHandle<io::Result<SocketAddr>>> {
        let is_ipv6 = self.inner.local_addr()?.is_ipv6();
        let resolver = self.resolver.clone();
        Ok(tokio::spawn(async move {
            let ip = if is_ipv6 {
                resolver
                    .resolve(&domain, false)
                    .await
                    .map_err(|_| io::Error::other("resolve domain failed"))?
            } else {
                resolver
                    .resolve_v4(&domain, false)
                    .await
                    .map_err(|_| io::Error::other("resolve domain failed"))?
                    .map(IpAddr::V4)
            };
            match ip {
                Some(ip) => Ok(SocketAddr::from((ip, port))),
                None => {
                    Err(io::Error::other(format!("resolve domain failed: {domain}")))
                }
            }
        }))
    }
}

impl Sink<UdpPacket> for OutboundDatagramImpl {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: UdpPacket) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        // Sink contract: start_send follows a Ready poll_ready, so we should
        // be Idle. If not, the queued packet is superseded.
        if let SendState::Resolving { task, .. } = &pin.send {
            task.abort();
        }
        pin.send = match &item.dst_addr {
            SocksAddr::Ip(addr) => SendState::Sending {
                dst: *addr,
                pkt: item,
            },
            SocksAddr::Domain(domain, port) => SendState::Resolving {
                task: pin.spawn_resolve(domain.clone(), *port)?,
                pkt: item,
            },
        };
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        loop {
            match &mut this.send {
                SendState::Idle => return Poll::Ready(Ok(())),
                SendState::Resolving { task, .. } => {
                    let join_result = ready!(Pin::new(task).poll(cx));
                    // The task has completed: leave Resolving now so the
                    // JoinHandle is never polled again.
                    let SendState::Resolving { pkt, .. } =
                        std::mem::replace(&mut this.send, SendState::Idle)
                    else {
                        unreachable!("matched Resolving above");
                    };
                    let dst = match join_result {
                        Ok(Ok(dst)) => dst,
                        Ok(Err(e)) => return Poll::Ready(Err(e)),
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "DNS task panicked: {e}"
                            ))));
                        }
                    };
                    this.send = SendState::Sending { pkt, dst };
                }
                SendState::Sending { pkt, dst } => {
                    let dst = *dst;
                    // When sending from a dual-stack AF_INET6 socket, the OS
                    // requires IPv4 destinations to be expressed as
                    // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x). Tokio's
                    // poll_send_to does not do this automatically and will
                    // return EINVAL otherwise.
                    let send_dst = match (this.inner.local_addr(), dst) {
                        (Ok(local), SocketAddr::V4(v4)) if local.is_ipv6() => {
                            SocketAddr::V6(std::net::SocketAddrV6::new(
                                v4.ip().to_ipv6_mapped(),
                                v4.port(),
                                0,
                                0,
                            ))
                        }
                        _ => dst,
                    };

                    let res = ready!(this.inner.poll_send_to(
                        cx,
                        pkt.data.as_slice(),
                        send_dst
                    ));
                    let SendState::Sending { pkt, .. } =
                        std::mem::replace(&mut this.send, SendState::Idle)
                    else {
                        unreachable!("matched Sending above");
                    };
                    let n = res?;

                    let now = Instant::now();
                    this.ip_to_logical.retain(|_, (_, ts)| {
                        now.duration_since(*ts) < UDP_DOMAIN_MAP_TTL
                    });
                    this.ip_to_logical.insert(dst, (pkt.dst_addr, now));

                    return if n == pkt.data.len() {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Ready(Err(new_io_error(format!(
                            "failed to send all data, only sent {n} bytes"
                        ))))
                    };
                }
            }
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

impl Stream for OutboundDatagramImpl {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut inner,
            ref mut recv_buf,
            ref ip_to_logical,
            ..
        } = *self;
        let mut buf = ReadBuf::new(recv_buf.as_mut_slice());
        match ready!(inner.poll_recv_from(cx, &mut buf)) {
            Ok(src) => {
                let data = buf.filled().to_vec();
                // On dual-stack (AF_INET6) sockets the OS returns IPv4
                // sender addresses in IPv4-mapped form (::ffff:x.x.x.x).
                // Canonicalize back to plain IPv4 so that ip_to_logical
                // lookups succeed and the returned src_addr matches what the
                // caller (e.g. a DNS client) expects.
                let src = match src {
                    SocketAddr::V6(v6) => {
                        if let Some(v4) = v6.ip().to_ipv4_mapped() {
                            SocketAddr::from((v4, v6.port()))
                        } else {
                            src
                        }
                    }
                    _ => src,
                };
                let src_addr = ip_to_logical
                    .get(&src)
                    .map(|(logical, _)| logical.clone())
                    .unwrap_or_else(|| src.into());
                Poll::Ready(Some(UdpPacket {
                    data,
                    src_addr,
                    dst_addr: SocksAddr::any_ipv4(),
                    ..Default::default()
                }))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::dns::MockClashResolver;
    use futures::{SinkExt, StreamExt};
    use std::{collections::HashSet, net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::net::UdpSocket;

    /// Spawn a loopback UDP echo server; returns its port.
    async fn spawn_echo_server() -> u16 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        port
    }

    /// Build an `OutboundDatagramImpl` backed by a loopback socket with a mock
    /// resolver that maps every domain to `127.0.0.1`.
    async fn make_datagram() -> OutboundDatagramImpl {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_v4()
            .returning(|_, _| Ok(Some(Ipv4Addr::LOCALHOST)));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        OutboundDatagramImpl::new(udp, Arc::new(resolver))
    }

    #[tokio::test]
    async fn test_single_dest_domain_src_addr_restored() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);
        datagram
            .send(UdpPacket {
                data: b"hello".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");

        assert_eq!(pkt.src_addr, dst, "src_addr must be restored to the domain");
        assert_eq!(pkt.data, b"hello");
    }

    /// A single outbound socket sends to **two** different domain destinations
    /// (1→N); each response must carry the correct logical src_addr.
    #[tokio::test]
    async fn test_multi_dest_1_to_n_src_addr_restored() {
        let port_a = spawn_echo_server().await;
        let port_b = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        let dst_a = SocksAddr::Domain("echo1.test".to_owned(), port_a);
        let dst_b = SocksAddr::Domain("echo2.test".to_owned(), port_b);

        // One socket, two destinations — 1→N.
        datagram
            .send(UdpPacket {
                data: b"to-a".to_vec(),
                dst_addr: dst_a.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        datagram
            .send(UdpPacket {
                data: b"to-b".to_vec(),
                dst_addr: dst_b.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        // Responses may arrive in any order.
        let timeout = Duration::from_secs(2);
        let pkt1 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for first response")
            .expect("stream ended");
        let pkt2 = tokio::time::timeout(timeout, datagram.next())
            .await
            .expect("timed out waiting for second response")
            .expect("stream ended");

        let got: HashSet<SocksAddr> =
            [pkt1.src_addr, pkt2.src_addr].into_iter().collect();
        assert!(got.contains(&dst_a), "missing echo1.test src_addr");
        assert!(got.contains(&dst_b), "missing echo2.test src_addr");
    }

    /// A packet whose domain never resolves must be dropped, not retried on
    /// every subsequent `poll_ready`, so later packets still go out.
    #[tokio::test]
    async fn test_unresolvable_domain_does_not_block_sink() {
        let mut resolver = MockClashResolver::new();
        resolver
            .expect_resolve_v4()
            .returning(|_, _| Err(anyhow::anyhow!("NXDOMAIN")));
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = OutboundDatagramImpl::new(udp, Arc::new(resolver));
        let echo_port = spawn_echo_server().await;

        let bad = SocksAddr::Domain("nx.test".to_owned(), echo_port);
        assert!(
            datagram
                .send(UdpPacket {
                    data: b"lost".to_vec(),
                    dst_addr: bad,
                    ..Default::default()
                })
                .await
                .is_err()
        );

        let good = SocksAddr::Ip((Ipv4Addr::LOCALHOST, echo_port).into());
        datagram
            .send(UdpPacket {
                data: b"ok".to_vec(),
                dst_addr: good.clone(),
                ..Default::default()
            })
            .await
            .expect("send to an IP must not be blocked by the failed domain");

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("echo timed out")
            .expect("stream ended");
        assert_eq!(pkt.data, b"ok");
        assert_eq!(pkt.src_addr, good);
    }

    /// When DNS resolution fails, `poll_flush` must return an error and leave
    /// `Resolving` so that a subsequent `send` can start a fresh DNS query
    /// without panicking with "JoinHandle polled after completion".
    #[tokio::test]
    async fn test_dns_failure_does_not_panic_on_retry() {
        let mut resolver = MockClashResolver::new();
        // First call: resolution fails.
        // Second call (after retry): resolution succeeds.
        let mut call_count = 0u8;
        resolver.expect_resolve_v4().returning(move |_, _| {
            call_count += 1;
            if call_count == 1 {
                Err(anyhow::anyhow!("simulated DNS failure"))
            } else {
                Ok(Some(Ipv4Addr::LOCALHOST))
            }
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = OutboundDatagramImpl::new(udp, Arc::new(resolver));

        let echo_port = spawn_echo_server().await;
        let dst = SocksAddr::Domain("fail.test".to_owned(), echo_port);

        // First send: DNS fails — must return Err, not panic.
        let result = datagram
            .send(UdpPacket {
                data: b"hello".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await;
        assert!(result.is_err(), "expected error on DNS failure");

        // Second send (same destination): DNS succeeds — must NOT panic.
        datagram
            .send(UdpPacket {
                data: b"hello again".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .expect("second send must succeed after DNS recovers");
    }
    /// inbound packets to the outbound socket and they are forwarded.
    /// The src_addr of an unsolicited packet falls back to the raw IP.
    #[tokio::test]
    async fn test_full_cone_unsolicited_inbound_accepted() {
        let echo_port = spawn_echo_server().await;
        let mut datagram = make_datagram().await;

        // Read the outbound port before moving `datagram` into the stream.
        let outbound_port = {
            let addr = datagram
                .inner
                .local_addr()
                .expect("local_addr must be available");
            addr.port()
        };

        // Establish a session to the echo server so ip_to_logical is populated.
        let dst = SocksAddr::Domain("echo.test".to_owned(), echo_port);
        datagram
            .send(UdpPacket {
                data: b"establish".to_vec(),
                dst_addr: dst.clone(),
                ..Default::default()
            })
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out")
            .expect("stream ended");
        assert_eq!(
            pkt.src_addr, dst,
            "echo response must restore domain src_addr"
        );

        // A third-party socket (absent from ip_to_logical) sends unsolicited.
        let third_party = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let third_party_addr = third_party.local_addr().unwrap();
        third_party
            .send_to(b"unsolicited", ("127.0.0.1", outbound_port))
            .await
            .unwrap();

        let pkt = tokio::time::timeout(Duration::from_secs(2), datagram.next())
            .await
            .expect("timed out waiting for unsolicited packet")
            .expect("stream ended");

        // Full-cone: the packet is delivered (not dropped).
        assert_eq!(pkt.data, b"unsolicited");
        // src_addr is the raw IP because the sender is not in ip_to_logical.
        assert_eq!(pkt.src_addr, SocksAddr::Ip(third_party_addr));
    }
}
