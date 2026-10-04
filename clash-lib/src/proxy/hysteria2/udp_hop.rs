use std::{
    fmt::Debug,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller, udp::Transmit};

use crate::{
    app::net::OutboundInterface, proxy::converters::hysteria2::PortGenerator,
};

struct HopState {
    prev_conn: Option<Arc<dyn AsyncUdpSocket>>,
    prev_retire_at: Instant,
    cur_conn: Arc<dyn AsyncUdpSocket>,
    last_hop_at: Instant,
    cur_port: u16,
    recv_waker: Option<std::task::Waker>,
}

#[derive(Debug)]
struct UdpHopPoller {
    hop: Arc<UdpHop>,
    conn: Arc<dyn AsyncUdpSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
}

impl UdpPoller for UdpHopPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.hop.check_hop();
        let conn = this.hop.current_conn();
        if !Arc::ptr_eq(&conn, &this.conn) {
            this.inner = conn.clone().create_io_poller();
            this.conn = conn;
        }
        this.inner.as_mut().poll_writable(cx)
    }
}

/// A UDP socket hopper for Hysteria 2.
/// Periodically hops to a new UDP port according to the specified interval,
/// while draining in-flight packets from the previous socket.
///
/// https://v2.hysteria.network/docs/advanced/Port-Hopping/
pub struct UdpHop {
    state: Mutex<HopState>,
    server_addr: SocketAddr,
    port_range: PortGenerator,
    interval: Duration,
    iface: Option<OutboundInterface>,
    #[cfg(target_os = "linux")]
    so_mark: Option<u32>,
}

impl UdpHop {
    pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

    pub fn new(
        server_addr: SocketAddr,
        port_range: PortGenerator,
        interval: Option<Duration>,
        iface: Option<OutboundInterface>,
        #[cfg(target_os = "linux")] so_mark: Option<u32>,
    ) -> io::Result<Self> {
        let bind_addr = if server_addr.is_ipv6() {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let std_socket = crate::proxy::utils::new_std_udp_socket(
            Some(bind_addr),
            iface.as_ref(),
            #[cfg(target_os = "linux")]
            so_mark,
            Some(server_addr),
        )?;
        let cur_conn = TokioRuntime.wrap_udp_socket(std_socket)?;
        let cur_port = server_addr.port();
        let now = Instant::now();

        let state = HopState {
            prev_conn: None,
            prev_retire_at: now,
            cur_conn,
            last_hop_at: now,
            cur_port,
            recv_waker: None,
        };

        Ok(Self {
            state: Mutex::new(state),
            server_addr,
            port_range,
            interval: interval.unwrap_or(Self::DEFAULT_INTERVAL),
            iface,
            #[cfg(target_os = "linux")]
            so_mark,
        })
    }

    #[cfg(test)]
    pub fn new_with_socket(
        server_addr: SocketAddr,
        port_range: PortGenerator,
        interval: Option<Duration>,
        cur_conn: Arc<dyn AsyncUdpSocket>,
    ) -> Self {
        let cur_port = server_addr.port();
        let now = Instant::now();
        let state = HopState {
            prev_conn: None,
            prev_retire_at: now,
            cur_conn,
            last_hop_at: now,
            cur_port,
            recv_waker: None,
        };

        Self {
            state: Mutex::new(state),
            server_addr,
            port_range,
            interval: interval.unwrap_or(Self::DEFAULT_INTERVAL),
            iface: None,
            #[cfg(target_os = "linux")]
            so_mark: None,
        }
    }

    pub fn current_conn(&self) -> Arc<dyn AsyncUdpSocket> {
        self.state.lock().unwrap().cur_conn.clone()
    }

    #[cfg(test)]
    pub fn current_port(&self) -> u16 {
        self.state.lock().unwrap().cur_port
    }

    fn create_socket(&self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let bind_addr = if self.server_addr.is_ipv6() {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let std_socket = crate::proxy::utils::new_std_udp_socket(
            Some(bind_addr),
            self.iface.as_ref(),
            #[cfg(target_os = "linux")]
            self.so_mark,
            Some(self.server_addr),
        )?;
        TokioRuntime.wrap_udp_socket(std_socket)
    }

    pub fn check_hop(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(state.last_hop_at) >= self.interval {
            let mut new_port = self.port_range.get();
            if self.port_range.all_ports().len() > 1 {
                for _ in 0..5 {
                    if new_port != state.cur_port {
                        break;
                    }
                    new_port = self.port_range.get();
                }
            }

            match self.create_socket() {
                Ok(new_conn) => {
                    tracing::debug!(
                        from = state.cur_port,
                        to = new_port,
                        "hysteria2 udp hop to new port"
                    );
                    state.prev_conn = Some(state.cur_conn.clone());
                    let drain_duration =
                        std::cmp::min(self.interval, Duration::from_secs(10));
                    state.prev_retire_at = now + drain_duration;
                    state.cur_conn = new_conn;
                    state.cur_port = new_port;
                    state.last_hop_at = now;
                    if let Some(waker) = state.recv_waker.take() {
                        waker.wake();
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "hysteria2 failed to create socket for hopping: {}",
                        e
                    );
                    // Avoid busy-looping if socket creation fails
                    state.last_hop_at =
                        now - (self.interval.saturating_sub(Duration::from_secs(1)));
                }
            }
        }
    }
}

impl Debug for UdpHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpHop")
            .field("server_addr", &self.server_addr)
            .field("interval", &self.interval)
            .finish()
    }
}

impl AsyncUdpSocket for UdpHop {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let conn = self.current_conn();
        Box::pin(UdpHopPoller {
            hop: self,
            inner: conn.clone().create_io_poller(),
            conn,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.check_hop();
        let (cur_conn, cur_port) = {
            let state = self.state.lock().unwrap();
            (state.cur_conn.clone(), state.cur_port)
        };

        let mut transmit = transmit.clone();
        transmit.destination.set_port(cur_port);

        cur_conn.try_send(&transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (prev_conn, cur_conn) = {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            if state.prev_conn.is_some() && now >= state.prev_retire_at {
                state.prev_conn = None;
            }
            state.recv_waker = Some(cx.waker().clone());
            (state.prev_conn.clone(), state.cur_conn.clone())
        };

        let orig_port = self.server_addr.port();

        // 1. If we have a draining previous socket, poll it for in-flight
        //    packets
        if let Some(ref prev) = prev_conn {
            match prev.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) if n > 0 => {
                    for m in &mut meta[..n] {
                        m.addr.set_port(orig_port);
                    }
                    return Poll::Ready(Ok(n));
                }
                Poll::Ready(Err(e)) => {
                    tracing::trace!("hysteria2 prev socket poll_recv err: {}", e);
                    let mut state = self.state.lock().unwrap();
                    state.prev_conn = None;
                }
                Poll::Ready(Ok(_)) | Poll::Pending => {}
            }
        }

        // 2. Poll the active current socket
        match cur_conn.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => {
                for m in &mut meta[..n] {
                    m.addr.set_port(orig_port);
                }
                Poll::Ready(Ok(n))
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.current_conn().local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.current_conn().may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.current_conn().max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.current_conn().max_receive_segments()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Waker,
    };

    use super::*;

    #[derive(Debug)]
    struct MockSocket {
        poll_count: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct MockPoller {
        poll_count: Arc<AtomicUsize>,
    }

    impl UdpPoller for MockPoller {
        fn poll_writable(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<io::Result<()>> {
            self.poll_count.fetch_add(1, Ordering::Relaxed);
            Poll::Pending
        }
    }

    impl AsyncUdpSocket for MockSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(MockPoller {
                poll_count: self.poll_count.clone(),
            })
        }

        fn try_send(&self, _transmit: &Transmit) -> io::Result<()> {
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            _bufs: &mut [io::IoSliceMut<'_>],
            _meta: &mut [quinn::udp::RecvMeta],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }
    }

    #[test]
    fn io_poller_tracks_current_socket_after_hop() {
        let first_polls = Arc::new(AtomicUsize::new(0));
        let second_polls = Arc::new(AtomicUsize::new(0));
        let first: Arc<dyn AsyncUdpSocket> = Arc::new(MockSocket {
            poll_count: first_polls.clone(),
        });
        let second: Arc<dyn AsyncUdpSocket> = Arc::new(MockSocket {
            poll_count: second_polls.clone(),
        });
        let hop = Arc::new(UdpHop::new_with_socket(
            SocketAddr::from(([127, 0, 0, 1], 443)),
            PortGenerator::new(443),
            Some(Duration::from_secs(300)),
            first,
        ));
        let mut poller = hop.clone().create_io_poller();

        hop.state.lock().unwrap().cur_conn = second;

        let mut cx = Context::from_waker(Waker::noop());
        assert!(poller.as_mut().poll_writable(&mut cx).is_pending());
        assert_eq!(first_polls.load(Ordering::Relaxed), 0);
        assert_eq!(second_polls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_udp_hop_ipv4_and_ipv6_binding() {
        let port_gen = PortGenerator::new(443)
            .parse_ports_str("1000-1005")
            .unwrap();

        let hop_v4 = UdpHop::new(
            SocketAddr::from(([127, 0, 0, 1], 443)),
            port_gen.clone(),
            Some(Duration::from_secs(10)),
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .expect("IPv4 hop creation failed");
        assert!(hop_v4.local_addr().unwrap().is_ipv4());

        let hop_v6 = UdpHop::new(
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
            port_gen,
            Some(Duration::from_secs(10)),
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .expect("IPv6 hop creation failed");
        assert!(hop_v6.local_addr().unwrap().is_ipv6());
    }

    #[tokio::test]
    async fn test_udp_hop_multi_hop_cycle() {
        let port_gen = PortGenerator::new(443)
            .parse_ports_str("2000-2010")
            .unwrap();
        let all_ports = port_gen.all_ports();
        let hop = UdpHop::new(
            SocketAddr::from(([127, 0, 0, 1], 443)),
            port_gen,
            Some(Duration::from_millis(10)),
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();

        let initial_socket = hop.current_conn();
        let initial_port = hop.current_port();
        assert_eq!(initial_port, 443);

        // Hop 1
        tokio::time::sleep(Duration::from_millis(20)).await;
        hop.check_hop();
        let socket_1 = hop.current_conn();
        let port_1 = hop.current_port();
        assert!(!Arc::ptr_eq(&initial_socket, &socket_1));
        assert!(hop.state.lock().unwrap().prev_conn.is_some());
        assert!(all_ports.contains(&port_1));

        // Hop 2 (must continue hopping!)
        tokio::time::sleep(Duration::from_millis(20)).await;
        hop.check_hop();
        let socket_2 = hop.current_conn();
        let port_2 = hop.current_port();
        assert!(!Arc::ptr_eq(&socket_1, &socket_2));
        assert!(hop.state.lock().unwrap().prev_conn.is_some());
        assert!(all_ports.contains(&port_2));

        // Hop 3
        tokio::time::sleep(Duration::from_millis(20)).await;
        hop.check_hop();
        let socket_3 = hop.current_conn();
        assert!(!Arc::ptr_eq(&socket_2, &socket_3));

        // After drain interval, prev_conn is retired
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut cx = Context::from_waker(Waker::noop());
        let mut bufs = [io::IoSliceMut::new(&mut [])];
        let mut meta = [quinn::udp::RecvMeta {
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            len: 0,
            stride: 0,
            dst_ip: None,
            ecn: None,
        }];
        let _ = hop.poll_recv(&mut cx, &mut bufs, &mut meta);
        assert!(hop.state.lock().unwrap().prev_conn.is_none());
    }

    #[tokio::test]
    async fn test_udp_hop_packet_rewrite_and_drain() {
        let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        let port_gen = PortGenerator::new(server_addr.port())
            .parse_ports_str(&format!(
                "{}-{}",
                server_addr.port() + 1,
                server_addr.port() + 5
            ))
            .unwrap();

        let hop = Arc::new(
            UdpHop::new(
                server_addr,
                port_gen,
                Some(Duration::from_millis(300)),
                None,
                #[cfg(target_os = "linux")]
                None,
            )
            .unwrap(),
        );

        let initial_local_addr = hop.local_addr().unwrap();

        // 1. Hop to new socket
        tokio::time::sleep(Duration::from_millis(350)).await;
        hop.check_hop();

        let new_local_addr = hop.local_addr().unwrap();
        assert_ne!(initial_local_addr, new_local_addr);

        // 2. Send packet from server to the PREVIOUS socket
        // Note: the socket was bound to 0.0.0.0:XYZ (INADDR_ANY); sending to
        // 0.0.0.0 fails on macOS/Darwin with EHOSTUNREACH ("No route to
        // host"), so we send to server_addr.ip() (127.0.0.1) with the
        // target socket's port.
        let prev_target =
            SocketAddr::new(server_addr.ip(), initial_local_addr.port());
        server_sock.send_to(b"prev_packet", prev_target).unwrap();

        let mut buf = [0u8; 64];
        let mut io_slices = [io::IoSliceMut::new(&mut buf)];
        let mut metas = [quinn::udp::RecvMeta {
            addr: SocketAddr::from(([127, 0, 0, 1], 9999)),
            len: 0,
            stride: 0,
            dst_ip: None,
            ecn: None,
        }];

        let start = Instant::now();
        let res = loop {
            let mut cx = Context::from_waker(Waker::noop());
            match hop.poll_recv(&mut cx, &mut io_slices, &mut metas) {
                Poll::Ready(Ok(n)) => break Poll::Ready(Ok(n)),
                Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
                Poll::Pending => {
                    if start.elapsed() > Duration::from_secs(2) {
                        break Poll::Pending;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        };

        match res {
            Poll::Ready(Ok(n)) => {
                assert_eq!(n, 1);
                assert_eq!(metas[0].len, 11);
                assert_eq!(&buf[..11], b"prev_packet");
                // Address port must be rewritten to server_addr.port()
                assert_eq!(metas[0].addr.port(), server_addr.port());
            }
            other => panic!("expected Poll::Ready(Ok(1)), got {:?}", other),
        }

        // 3. Send packet from server to the CURRENT socket
        let cur_target = SocketAddr::new(server_addr.ip(), new_local_addr.port());
        server_sock.send_to(b"cur_packet", cur_target).unwrap();

        let mut buf2 = [0u8; 64];
        let mut io_slices2 = [io::IoSliceMut::new(&mut buf2)];
        let mut metas2 = [quinn::udp::RecvMeta {
            addr: SocketAddr::from(([127, 0, 0, 1], 9999)),
            len: 0,
            stride: 0,
            dst_ip: None,
            ecn: None,
        }];

        let start2 = Instant::now();
        let res2 = loop {
            let mut cx = Context::from_waker(Waker::noop());
            match hop.poll_recv(&mut cx, &mut io_slices2, &mut metas2) {
                Poll::Ready(Ok(n)) => break Poll::Ready(Ok(n)),
                Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
                Poll::Pending => {
                    if start2.elapsed() > Duration::from_secs(2) {
                        break Poll::Pending;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        };

        match res2 {
            Poll::Ready(Ok(n)) => {
                assert_eq!(n, 1);
                assert_eq!(metas2[0].len, 10);
                assert_eq!(&buf2[..10], b"cur_packet");
                assert_eq!(metas2[0].addr.port(), server_addr.port());
            }
            other => panic!("expected Poll::Ready(Ok(1)), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_check_hop_wakes_recv_driver() {
        use std::sync::atomic::AtomicBool;

        struct TestWaker(Arc<AtomicBool>);
        impl std::task::Wake for TestWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let port_gen = PortGenerator::new(443)
            .parse_ports_str("1000-1005")
            .unwrap();
        let hop = UdpHop::new(
            SocketAddr::from(([127, 0, 0, 1], 443)),
            port_gen,
            Some(Duration::from_millis(10)),
            None,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();

        let woken = Arc::new(AtomicBool::new(false));
        let waker = Waker::from(Arc::new(TestWaker(woken.clone())));
        let mut cx = Context::from_waker(&waker);

        let mut buf = [0u8; 16];
        let mut io_slices = [io::IoSliceMut::new(&mut buf)];
        let mut metas = [quinn::udp::RecvMeta {
            addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            len: 0,
            stride: 0,
            dst_ip: None,
            ecn: None,
        }];

        // Poll recv to register the waker
        assert!(
            hop.poll_recv(&mut cx, &mut io_slices, &mut metas)
                .is_pending()
        );
        assert!(!woken.load(Ordering::SeqCst));

        // Advance time past hop interval and check hop
        tokio::time::sleep(Duration::from_millis(20)).await;
        hop.check_hop();

        // The receive waker must have been triggered!
        assert!(woken.load(Ordering::SeqCst));
    }
}
