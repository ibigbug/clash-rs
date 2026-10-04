use super::platform::must_bind_socket_on_interface;
use crate::app::net::OutboundInterface;

use futures::{StreamExt, io, stream::FuturesUnordered};
use socket2::TcpKeepalive;
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};
use tracing::{debug, error, instrument, trace};

pub fn apply_tcp_options(s: &TcpStream) -> std::io::Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;
    }
    #[cfg(target_os = "windows")]
    {
        let sock_ref = socket2::SockRef::from(s);
        sock_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
    }
    // Disable Nagle's algorithm so that small writes (e.g. HTTP response
    // headers arriving from the proxy side) are forwarded to the client
    // immediately without waiting for a full TCP segment.
    s.set_nodelay(true)
}

#[instrument(skip(so_mark))]
pub async fn new_tcp_stream(
    endpoint: SocketAddr,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    let (socket, family) = match endpoint {
        SocketAddr::V4(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV4,
        ),
        SocketAddr::V6(_) => (
            socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                None,
            )?,
            socket2::Domain::IPV6,
        ),
    };
    debug!("created tcp socket");

    if !cfg!(target_os = "android")
        && let Some(iface) = iface
        && !endpoint.ip().is_loopback()
    {
        must_bind_socket_on_interface(&socket, iface, family)?;
        trace!("tcp socket bound to interface: {socket:?}");
    }

    #[cfg(not(target_os = "android"))]
    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_keepalive(true)?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;

    timeout(
        Duration::from_secs(10),
        TcpSocket::from_std_stream(socket.into()).connect(endpoint),
    )
    .await?
}

/// Default connection attempt delay for Happy Eyeballs v2 (RFC 8305 Section
/// 5.2).
pub const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(200);

/// Sorts socket addresses according to RFC 8305 Section 5 (Happy Eyeballs v2).
///
/// IPv6 and IPv4 addresses are interleaved, starting with IPv6:
/// `[v6_0, v4_0, v6_1, v4_1, ...]`
pub fn sort_addrs_happy_eyeballs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();

    for &addr in addrs {
        if addr.is_ipv6() {
            v6.push(addr);
        } else {
            v4.push(addr);
        }
    }

    if v6.is_empty() {
        return v4;
    }
    if v4.is_empty() {
        return v6;
    }

    let mut result = Vec::with_capacity(addrs.len());
    let mut v6_iter = v6.into_iter();
    let mut v4_iter = v4.into_iter();

    loop {
        match (v6_iter.next(), v4_iter.next()) {
            (Some(a6), Some(a4)) => {
                result.push(a6);
                result.push(a4);
            }
            (Some(a6), None) => {
                result.push(a6);
                result.extend(v6_iter);
                break;
            }
            (None, Some(a4)) => {
                result.push(a4);
                result.extend(v4_iter);
                break;
            }
            (None, None) => break,
        }
    }

    result
}

/// Connects to one of the candidate endpoints using Happy Eyeballs v2 (RFC
/// 8305).
///
/// Addresses are sorted and interleaved (IPv6 first). The preferred address is
/// dialed immediately. If the first attempt does not connect within
/// [`HAPPY_EYEBALLS_DELAY`], subsequent candidates are dialed in parallel.
/// Whichever TCP connection succeeds first is returned immediately,
/// and the remaining in-flight attempts are aborted.
#[instrument(skip(so_mark))]
pub async fn new_tcp_stream_happy_eyeballs(
    endpoints: &[SocketAddr],
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    if endpoints.is_empty() {
        return Err(std::io::Error::other("no destination address provided"));
    }
    if endpoints.len() == 1 {
        return new_tcp_stream(
            endpoints[0],
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await;
    }

    async fn connect_candidate(
        addr: SocketAddr,
        iface: Option<OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> (std::io::Result<TcpStream>, SocketAddr) {
        let res = new_tcp_stream(
            addr,
            iface.as_ref(),
            #[cfg(target_os = "linux")]
            so_mark,
        )
        .await;
        (res, addr)
    }

    let sorted = sort_addrs_happy_eyeballs(endpoints);
    let mut candidate_idx = 0;
    let mut in_flight = FuturesUnordered::new();
    let mut last_error = None;

    // Start dialing the first candidate immediately
    let first_addr = sorted[candidate_idx];
    candidate_idx += 1;
    in_flight.push(connect_candidate(
        first_addr,
        iface.cloned(),
        #[cfg(target_os = "linux")]
        so_mark,
    ));

    let mut delay_timer = Some(Box::pin(tokio::time::sleep(HAPPY_EYEBALLS_DELAY)));

    loop {
        tokio::select! {
            res = in_flight.next() => {
                match res {
                    Some((Ok(stream), addr)) => {
                        trace!(addr = %addr, "happy eyeballs: connection established");
                        return Ok(stream);
                    }
                    Some((Err(err), addr)) => {
                        trace!(addr = %addr, error = %err, "happy eyeballs: connection attempt failed");
                        last_error = Some(err);
                        // If no other connections are currently in flight and more candidates remain,
                        // start the next candidate immediately (RFC 8305 Section 5.2)
                        if in_flight.is_empty() && candidate_idx < sorted.len() {
                            let next_addr = sorted[candidate_idx];
                            candidate_idx += 1;
                            in_flight.push(connect_candidate(
                                next_addr,
                                iface.cloned(),
                                #[cfg(target_os = "linux")]
                                so_mark,
                            ));
                            delay_timer = if candidate_idx < sorted.len() {
                                Some(Box::pin(tokio::time::sleep(HAPPY_EYEBALLS_DELAY)))
                            } else {
                                None
                            };
                        }
                    }
                    None => {
                        if candidate_idx >= sorted.len() {
                            break;
                        }
                    }
                }
            }

            _ = async {
                if let Some(ref mut timer) = delay_timer {
                    timer.as_mut().await
                } else {
                    futures::future::pending::<()>().await
                }
            }, if delay_timer.is_some() && candidate_idx < sorted.len() => {
                let next_addr = sorted[candidate_idx];
                candidate_idx += 1;
                in_flight.push(connect_candidate(
                    next_addr,
                    iface.cloned(),
                    #[cfg(target_os = "linux")]
                    so_mark,
                ));
                delay_timer = if candidate_idx < sorted.len() {
                    Some(Box::pin(tokio::time::sleep(HAPPY_EYEBALLS_DELAY)))
                } else {
                    None
                };
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| std::io::Error::other("all connection attempts failed")))
}

#[instrument(skip(so_mark))]
pub fn new_std_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
    // Optional family hint for the socket.
    // If not provided, the family will be determined based on the source
    // address or interface.
    family_hint: Option<std::net::SocketAddr>,
) -> std::io::Result<std::net::UdpSocket> {
    // Determine the socket family based on the source address or interface
    // logic:
    // - If family_hint is provided, use it.
    // - If src is provided and is IPv6, use IPv6.
    // - If iface is provided and is IPv6, use IPv6.
    // - Otherwise, default to IPv4.
    let (socket, family) = match (family_hint, src, iface) {
        (Some(family_hint), ..) => {
            let domain = socket2::Domain::for_address(family_hint);
            (
                socket2::Socket::new(domain, socket2::Type::DGRAM, None)?,
                domain,
            )
        }
        (None, Some(src), _) if src.is_ipv6() => (
            try_create_dualstack_socket(src, socket2::Type::DGRAM)?.0,
            socket2::Domain::IPV6,
        ),
        (None, _, Some(iface)) if iface.addr_v6.is_some() => (
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV6,
        ),
        _ => (
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            socket2::Domain::IPV4,
        ),
    };
    debug!("created udp socket");

    if !cfg!(target_os = "android") {
        // Skip interface binding for loopback destinations — binding a socket
        // to an outbound interface prevents reaching localhost addresses.
        let dst_is_loopback =
            family_hint.map(|a| a.ip().is_loopback()).unwrap_or(false);
        match (src, iface) {
            (_, Some(iface)) if !dst_is_loopback => {
                must_bind_socket_on_interface(&socket, iface, family).inspect_err(
                    |x| {
                        error!("failed to bind socket to interface: {}", x);
                    },
                )?;
                // binding is not necessary for linux but is required on windows
                // Without binding local_addr can't be obtained by system call
                // which is required on quinn.
                #[cfg(target_os = "windows")]
                if let Some(addr) = src {
                    socket.bind(&socket2::SockAddr::from(addr))?;
                }

                trace!(iface = ?iface, "udp socket bound: {socket:?}");
            }
            (Some(src), _) => {
                // Either no interface, or destination is loopback (skip iface
                // binding so localhost is reachable).
                socket.bind(&src.into())?;
                trace!(src = ?src, "udp socket bound: {socket:?}");
            }
            (None, _) => {
                // On Windows, UDP sockets must be bound to get a valid
                // local_addr which is required for some
                // operations (e.g., quinn/QUIC)
                #[cfg(target_os = "windows")]
                {
                    let bind_addr = match family {
                        socket2::Domain::IPV4 => {
                            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
                        }
                        socket2::Domain::IPV6 => {
                            "[::]:0".parse::<SocketAddr>().unwrap()
                        }
                        _ => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
                    };
                    socket.bind(&socket2::SockAddr::from(bind_addr))?;
                    trace!(addr = ?bind_addr, "udp socket bound to default address on Windows: {socket:?}");
                }
                #[cfg(not(target_os = "windows"))]
                trace!("udp socket not bound to any specific address: {socket:?}");
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

#[instrument(skip(so_mark))]
pub async fn new_udp_socket(
    src: Option<SocketAddr>,
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
    // Optional family hint for the socket.
    // If not provided, the family will be determined based on the source
    // address or interface.
    family_hint: Option<std::net::SocketAddr>,
) -> std::io::Result<UdpSocket> {
    let std_socket = new_std_udp_socket(
        src,
        iface,
        #[cfg(target_os = "linux")]
        so_mark,
        family_hint,
    )?;
    UdpSocket::from_std(std_socket)
}

/// Convert ipv6 mapped ipv4 address back to ipv4. Other address remain
/// unchanged. e.g. ::ffff:127.0.0.1 -> 127.0.0.1
pub trait ToCanonical {
    fn to_canonical(self) -> SocketAddr;
}

impl ToCanonical for SocketAddr {
    fn to_canonical(mut self) -> SocketAddr {
        self.set_ip(self.ip().to_canonical());
        self
    }
}

/// Create dualstack socket if it can
/// If failed, fallback to single stack silently
pub fn try_create_dualstack_socket(
    addr: SocketAddr,
    tcp_or_udp: socket2::Type,
) -> std::io::Result<(socket2::Socket, bool)> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let mut dualstack = false;
    let socket = socket2::Socket::new(domain, tcp_or_udp, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        if let Err(e) = socket.set_only_v6(false) {
            // If setting dualstack fails, fallback to single stack
            tracing::warn!(
                "dualstack not supported, falling back to ipv6 only: {e}"
            );
        } else {
            dualstack = true;
        }
    };
    Ok((socket, dualstack))
}

/// Create a dual-stack UDP socket bound to `[::]`, falling back to an IPv4
/// socket bound to `0.0.0.0` if IPv6 is unavailable.  The resulting socket
/// can send to both IPv4 and IPv6 destinations without EAFNOSUPPORT, which
/// is required when one outbound socket is reused across destinations with
/// different address families (e.g. in the DIRECT handler).
pub fn new_dual_stack_udp_socket(
    iface: Option<&OutboundInterface>,
    #[cfg(target_os = "linux")] so_mark: Option<u32>,
) -> std::io::Result<UdpSocket> {
    let dual_stack = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let ipv4_only = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let (socket, bind_addr) =
        match try_create_dualstack_socket(dual_stack, socket2::Type::DGRAM) {
            Ok((s, true)) => (s, dual_stack),
            Ok((_, false)) | Err(_) => (
                socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    None,
                )?,
                ipv4_only,
            ),
        };

    if let Some(iface) = iface {
        let family = socket2::Domain::for_address(bind_addr);
        must_bind_socket_on_interface(&socket, iface, family).inspect_err(|x| {
            error!("failed to bind socket to interface: {}", x);
        })?;
    }
    // must_bind_socket_on_interface only sets a socket option (SO_BINDTODEVICE
    // / IP_BOUND_IF / IPV6_UNICAST_IF); it does not assign a local port.
    // Always bind explicitly so the socket has a valid local address on all
    // platforms — required on Windows to avoid WSAEINVAL (10022) from sendto.
    socket.bind(&bind_addr.into())?;

    #[cfg(target_os = "linux")]
    if let Some(so_mark) = so_mark {
        socket.set_mark(so_mark)?;
    }

    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

pub fn try_create_dualstack_tcplistener(
    addr: SocketAddr,
) -> io::Result<TcpListener> {
    let (socket, _dualstack) =
        try_create_dualstack_socket(addr, socket2::Type::STREAM)?;

    socket.set_nonblocking(true)?;
    // For fast restart avoid Address In Use Error
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::SocketAddrV6, time::Duration};

    /// Locate the loopback network interface on the current host.
    /// Returns `None` if the interface cannot be found or enumeration fails.
    fn find_loopback_iface() -> Option<OutboundInterface> {
        use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
        let ifaces = NetworkInterface::show().ok()?;
        let lo = ifaces.into_iter().find(|iface| {
            iface.addr.iter().any(|a| match a {
                Addr::V4(v4) => v4.ip.is_loopback(),
                _ => false,
            })
        })?;
        Some(OutboundInterface {
            name: lo.name,
            addr_v4: Some(Ipv4Addr::LOCALHOST),
            addr_v6: Some(Ipv6Addr::LOCALHOST),
            index: lo.index,
            netmask_v4: None,
            broadcast_v4: None,
            netmask_v6: None,
            broadcast_v6: None,
            mac_addr: None,
        })
    }

    // Regression test for https://github.com/Watfaq/clash-rs/issues/1399.
    //
    // new_dual_stack_udp_socket must call bind() even when `iface` is provided.
    // Before the fix, the iface branch skipped bind() so the socket was
    // "unbound"; sendto with an IPv4-mapped destination then returned
    // WSAEINVAL (os error 10022) on Windows.

    /// Without an iface: socket is bound and IPv4-mapped round-trip works.
    #[tokio::test]
    async fn test_dual_stack_no_iface_is_bound_and_sends_ipv4_mapped() {
        let sock = new_dual_stack_udp_socket(
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .expect("failed to create dual-stack socket");

        let local = sock.local_addr().expect("local_addr failed");
        assert_ne!(local.port(), 0, "socket must have a non-zero local port");

        // Only exercise IPv4-mapped sendto when we actually got a dual-stack
        // (IPv6) socket; on hosts without IPv6 the fallback is an IPv4 socket.
        if !local.is_ipv6() {
            return;
        }

        let echo = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind echo server");
        let echo_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        let dst = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            echo_port,
            0,
            0,
        ));
        sock.send_to(b"ping", dst).await.expect("send_to failed");

        let mut buf = vec![0u8; 64];
        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
                .await
                .expect("timed out")
                .expect("recv_from failed");
        assert_eq!(&buf[..n], b"ping");
    }

    /// With an iface (loopback): socket must still be bound after
    /// must_bind_socket_on_interface so that sendto does not return WSAEINVAL.
    ///
    /// Skipped on Linux when SO_BINDTODEVICE requires elevated privileges.
    #[tokio::test]
    async fn test_dual_stack_with_iface_is_bound() {
        let Some(iface) = find_loopback_iface() else {
            eprintln!("skipping: loopback interface not found");
            return;
        };

        let result = new_dual_stack_udp_socket(
            Some(&iface),
            #[cfg(target_os = "linux")]
            None,
        );

        // On Linux, SO_BINDTODEVICE requires CAP_NET_RAW; skip gracefully.
        #[cfg(target_os = "linux")]
        if result.is_err() {
            eprintln!("skipping: SO_BINDTODEVICE requires elevated privileges");
            return;
        }

        let sock = result.expect("failed to create dual-stack socket with iface");
        let local = sock.local_addr().expect("local_addr failed");
        assert_ne!(
            local.port(),
            0,
            "socket must have a non-zero local port even when iface is set"
        );
    }

    #[test]
    fn test_sort_addrs_happy_eyeballs() {
        let v4_1: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let v4_2: SocketAddr = "2.2.2.2:80".parse().unwrap();
        let v6_1: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let v6_2: SocketAddr = "[2001:db8::2]:80".parse().unwrap();

        // Dual-stack: should interleave starting with IPv6
        let sorted = super::sort_addrs_happy_eyeballs(&[v4_1, v4_2, v6_1, v6_2]);
        assert_eq!(sorted, vec![v6_1, v4_1, v6_2, v4_2]);

        // Single family IPv4
        let sorted_v4 = super::sort_addrs_happy_eyeballs(&[v4_1, v4_2]);
        assert_eq!(sorted_v4, vec![v4_1, v4_2]);

        // Single family IPv6
        let sorted_v6 = super::sort_addrs_happy_eyeballs(&[v6_1, v6_2]);
        assert_eq!(sorted_v6, vec![v6_1, v6_2]);
    }

    #[tokio::test]
    async fn test_happy_eyeballs_races_and_connects_to_working_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let working_addr = listener.local_addr().unwrap();

        // First address is a port on localhost that is not listening
        let non_listening_port = working_addr.port().wrapping_add(100);
        let dummy_addr: SocketAddr =
            format!("127.0.0.1:{non_listening_port}").parse().unwrap();

        let stream = super::new_tcp_stream_happy_eyeballs(
            &[dummy_addr, working_addr],
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .await;

        assert!(
            stream.is_ok(),
            "Happy Eyeballs should connect to the working address"
        );
    }
}
