use self::docker_runner::RunAndCleanup;
use crate::{
    app::{
        dispatcher::{BoxedInstrumentedDatagram, InstrumentedStream},
        remote_content_manager::ProxyManager,
    },
    proxy::{OutboundHandler, datagram::UdpPacket},
    session::{Session, SocksAddr},
};
use anyhow::{anyhow, bail};
use futures::{SinkExt, StreamExt, future::select_all};
use std::{
    sync::{Arc, atomic::AtomicU16},
    time::{Duration, Instant},
};
use sysinfo::Networks;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split},
    net::{TcpListener, UdpSocket},
};
use tracing::{debug, info, trace};

// ── Port allocator
// ────────────────────────────────────────────────────────────
//
// Both `alloc_port()` (throughput tests) and `alloc_docker_port()` (docker
// tests) share this single process-wide counter so that no two allocations
// within the same test process ever return the same port number.
//
// The previous approach — bind("127.0.0.1:0"), record the port, drop the
// listener — has an unavoidable TOCTOU race: the port is freed the instant
// the listener is dropped, and with --test-threads=8 another concurrent
// test's echo-listener or clash-rs subprocess can claim it before the
// original allocator manages to re-bind it.  The result is a silent
// EADDRINUSE inside clash-rs that causes it to exit before any tracing
// output is produced, which manifests as "port not ready after 60s".
//
// Using a strictly-incrementing counter avoids this entirely.  Ports
// 30001-31000 are below the Linux ephemeral range (32768-60999) and are not
// occupied by well-known system services on typical CI runners.
#[cfg(any(docker_test, throughput_test))]
pub(super) static PORT_COUNTER: AtomicU16 = AtomicU16::new(30001);

/// Allocate a unique TCP port number for use in a test.
///
/// Uses a process-global monotonically-increasing counter rather than the
/// OS bind-and-release pattern to eliminate the TOCTOU race that occurs
/// when many tests run concurrently (`--test-threads=8`).
#[cfg(throughput_test)]
pub fn alloc_port() -> u16 {
    PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ── ThroughputResult
// ──────────────────────────────────────────────────────────
#[cfg(throughput_test)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThroughputResult {
    pub label: String,
    pub upload_mbps: f64,         // median across runs
    pub download_mbps: f64,       // median across runs
    pub upload_stdev_mbps: f64,   // stdev across runs
    pub download_stdev_mbps: f64, // stdev across runs
    pub runs: usize,
    pub total_bytes: usize,
    pub netem: Option<String>, // e.g. "50ms 1%loss"
}

/// Append one result line to the file named by `THROUGHPUT_RESULTS_FILE` (if
/// set).  Each line is a self-contained JSON object so the file can be parsed
/// incrementally even when multiple tests run in parallel.
#[cfg(all(docker_test, throughput_test))]
fn write_throughput_result(result: &ThroughputResult) {
    let Some(path) = std::env::var_os("THROUGHPUT_RESULTS_FILE") else {
        return;
    };
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("THROUGHPUT_RESULTS_FILE: cannot open for append");
    let mut line = serde_json::to_string(result)
        .expect("ThroughputResult serialization failed");
    line.push('\n');
    file.write_all(line.as_bytes())
        .expect("THROUGHPUT_RESULTS_FILE: write failed");
}

#[cfg(all(docker_test, throughput_test))]
fn median_mbps(samples: &[std::time::Duration], mb: f64) -> f64 {
    let mut mbps: Vec<f64> =
        samples.iter().map(|d| mb * 8.0 / d.as_secs_f64()).collect();
    mbps.sort_by(|a, b| a.partial_cmp(b).unwrap());
    mbps[mbps.len() / 2]
}

#[cfg(all(docker_test, throughput_test))]
fn stdev_mbps(samples: &[std::time::Duration], mb: f64) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mbps: Vec<f64> =
        samples.iter().map(|d| mb * 8.0 / d.as_secs_f64()).collect();
    let mean = mbps.iter().sum::<f64>() / mbps.len() as f64;
    let var = mbps.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
        / (mbps.len() - 1) as f64;
    var.sqrt()
}

// ── find_clash_rs_binary
// ──────────────────────────────────────────────────────
/// Locate the clash-rs binary.  Prefers the debug build (faster iteration) and
/// falls back to the release build.  Panics if neither exists.
#[cfg(throughput_test)]
pub fn find_clash_rs_binary() -> std::path::PathBuf {
    let root = config_helper::root_dir();
    let debug = root.join("target/debug/clash-rs");
    let release = root.join("target/release/clash-rs");
    if debug.exists() {
        debug
    } else if release.exists() {
        release
    } else {
        panic!("clash-rs binary not found — run `cargo build -p clash-rs` first")
    }
}

pub mod config_helper;
pub mod consts;
pub mod docker_runner;

fn destination_list(gateway_ip: Option<String>) -> Vec<String> {
    let mut destination_list = vec!["host.docker.internal".to_owned()];
    if let Some(ip) = gateway_ip {
        debug!("gateway_ip Ip: {}", ip);
        destination_list.push(ip);
    }
    if let Ok(ip) = std::env::var("CLIENT_IP") {
        debug!("client Ip: {}", &ip);
        destination_list.insert(0, ip);
    } else {
        debug!("CLIENT_IP env not set, ");
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh(true);

        trace!("networks: {:?}", networks);
        // 收集所有有流量的网卡的 IPv4 地址
        let mut active_interfaces = networks
            .iter()
            .filter(|(_, data)| {
                data.mac_address().to_string() != "00:00:00:00:00:00"
            })
            .collect::<Vec<_>>();

        // 按流量排序：优先按发送流量降序，其次按接收流量降序
        active_interfaces.sort_by(|a, b| {
            b.1.total_transmitted()
                .cmp(&a.1.total_transmitted())
                .then_with(|| b.1.total_received().cmp(&a.1.total_received()))
        });
        for (iface_name, data) in active_interfaces {
            trace!("Processing interface: {}, {:#?}", iface_name, data);

            // 获取该网卡的所有 IP 地址
            for ip_network in data.ip_networks() {
                let addr = ip_network.addr;
                // 只添加 IPv4 地址，排除 loopback
                if addr.is_ipv4() && !addr.is_loopback() {
                    let ip_str = addr.to_string();
                    // 跳过已存在的 IP
                    if !destination_list.contains(&ip_str) {
                        debug!("Found IPv4 address on {}: {}", iface_name, ip_str);
                        destination_list.push(ip_str);
                    }
                }
            }
        }
    }
    destination_list
}

// TODO: add the throughput metrics
pub async fn ping_pong_test(
    handler: Arc<dyn OutboundHandler>,
    gateway_ip: Option<String>,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let destination_list = destination_list(gateway_ip);

    let resolver = config_helper::build_dns_resolver().await?;

    // Bind to port 0: OS assigns a free port atomically, no TOCTOU window.
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();

    info!("target local server started at: {}", listener.local_addr()?);

    async fn destination_fn<T>(incoming: T) -> anyhow::Result<()>
    where
        T: AsyncRead + AsyncWrite,
    {
        // Use inbound_stream here
        let (mut read_half, mut write_half) = split(incoming);
        let chunk = "world";
        let mut buf = vec![0; 5];

        info!("destination_fn(tcp) start read");

        for _ in 0..100 {
            read_half.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"hello");
        }

        info!("destination_fn(tcp) start write");
        for _ in 0..100 {
            write_half.write_all(chunk.as_bytes()).await?;
            write_half.flush().await?;
        }

        info!("destination_fn(tcp) end");
        Ok(())
    }
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let target_local_server_handler = tokio::spawn(async move {
        let mut rx = rx;
        loop {
            tokio::select! {
                data = listener.accept() => {
                    match data {
                        Ok((stream, _)) => {
                            info!(
                                "Accepted connection(tcp) from: {:?}",
                                stream.peer_addr().ok()
                            );
                            if let Err(e) = destination_fn(stream).await {
                                info!("Error handling connection(tcp): {}", e);
                            }
                        },
                        Err(e) => {
                            info!("Error accepting connection(tcp): {}", e);
                            continue;
                        }
                    }
                }
                _ = &mut rx => {
                    info!("target_local_server_handler(tcp) received shutdown signal, exiting...");
                    return Ok(());
                }
            }
        }
    });

    async fn proxy_fn(stream: Box<dyn InstrumentedStream>) -> anyhow::Result<()> {
        let (mut read_half, mut write_half) = split(stream);

        let chunk = "hello";
        let mut buf = vec![0; 5];

        info!("proxy_fn(tcp) start write");

        for i in 0..100 {
            write_half
                .write_all(chunk.as_bytes())
                .await
                .inspect_err(|x| {
                    tracing::error!(
                        "proxy_fn(tcp) write error at iteration {}: {x:?}",
                        i
                    );
                })?;
        }
        write_half.flush().await?;

        info!("proxy_fn start(tcp) read");

        for i in 0..100 {
            read_half.read_exact(&mut buf).await.inspect_err(|x| {
                tracing::error!(
                    "proxy_fn(tcp) read error at iteration {}: {x:?}",
                    i
                );
            })?;
            assert_eq!(buf, "world".as_bytes().to_owned());
        }

        info!("proxy_fn(tcp) end");

        Ok(())
    }

    let proxy_task = tokio::spawn(async move {
        // give some time for the target local server to start
        tokio::time::sleep(Duration::from_secs(3)).await;

        let mut first_error: Option<anyhow::Error> = None;

        for destination in &destination_list {
            tracing::trace!("Attempting TCP connection(tcp) to: {}", destination);

            let dst: SocksAddr = match (destination.clone(), port).try_into() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!(
                        "Failed to parse destination address(tcp): {}",
                        e
                    );
                    continue;
                }
            };

            let sess = Session {
                destination: dst.clone(),
                ..Default::default()
            };

            let stream = match tokio::time::timeout(
                Duration::from_secs(3),
                handler.connect_stream(&sess, resolver.clone()),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    tracing::info!("Successfully connected(tcp) to: {:?}", dst);
                    stream
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "Failed to proxy connection(tcp) to {:?}: {}",
                        dst,
                        e
                    );
                    if first_error.is_none() {
                        first_error = Some(e.into());
                    }
                    continue;
                }
                Err(_) => {
                    tracing::error!(
                        "connect_stream timeout (5s) for destination(tcp): {}",
                        destination
                    );
                    continue;
                }
            };

            match tokio::time::timeout(Duration::from_secs(3), proxy_fn(stream))
                .await
            {
                Ok(Ok(())) => {
                    tracing::info!(
                        "proxy_fn succeeded for destination(tcp): {}",
                        destination
                    );
                    return Ok(());
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "proxy_fn failed for destination(tcp) {}: {}",
                        destination,
                        e
                    );
                    continue;
                }
                Err(_) => {
                    tracing::error!(
                        "proxy_fn timeout (3s) for destination(tcp): {}",
                        destination
                    );
                    continue;
                }
            }
        }

        // Return the first connection error if available, otherwise return
        // generic error
        if let Some(err) = first_error {
            Err(err)
        } else {
            Err(anyhow!(
                "all destination test error(tcp): [{:?}]",
                destination_list
            ))
        }
    });

    let futs = vec![proxy_task, target_local_server_handler];

    let res = select_all(futs).await.0?;
    tx.send(()).ok(); // signal the target local server to shutdown
    res
}

pub async fn ping_pong_udp_test(
    handler: Arc<dyn OutboundHandler>,
    gateway_ip: Option<String>,
) -> anyhow::Result<()> {
    // PATH: our proxy handler -> proxy-server(container) -> target local
    // server(127.0.0.1:port)

    let destination_list = destination_list(gateway_ip);

    let resolver = config_helper::build_dns_resolver().await?;

    // Bind to port 0: OS assigns a free port atomically, no TOCTOU window.
    let listener = UdpSocket::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();
    info!("target local server started at: {}", listener.local_addr()?);

    async fn destination_fn(
        mut rx: tokio::sync::oneshot::Receiver<()>,
        listener: UdpSocket,
    ) -> anyhow::Result<()> {
        // Use inbound_stream here
        let chunk = "world";
        let mut buf = vec![0; 5];

        info!(
            "destination_fn(udp) waiting for data on {}",
            listener.local_addr()?
        );
        tracing::trace!("destination_fn start read");

        loop {
            tokio::select! {
                data = listener.recv_from(&mut buf) => {
                    match data {
                        Ok((len, src) ) => {
                            info!(
                                "destination_fn(udp) received {} bytes from {}: {:?}",
                                len,
                                src,
                                &buf[..len]
                            );
                            assert_eq!(&buf, b"hello");
                            info!("destination_fn(udp) sending response to {}", src);
                            tracing::trace!("destination_fn start write");
                            let sent = listener.send_to(chunk.as_bytes(), src).await?;
                            info!("destination_fn(udp) sent {} bytes", sent);
                            tracing::trace!("destination_fn end");
                        },
                        Err(e) => {
                            info!("Error accepting connection(tcp): {}", e);
                            continue;
                        }
                    }
                }
                _ = &mut rx => {
                    info!("target_local_server_handler(tcp) received shutdown signal, exiting...");
                    return Ok(());
                }
            }
        }
    }
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let target_local_server_handler: tokio::task::JoinHandle<
        Result<(), anyhow::Error>,
    > = tokio::spawn(async move { destination_fn(rx, listener).await });

    async fn proxy_fn(
        mut datagram: BoxedInstrumentedDatagram,
        src_addr: SocksAddr,
        dst_addr: SocksAddr,
    ) -> anyhow::Result<()> {
        // let (mut sink, mut stream) = datagram.split();
        let packet =
            UdpPacket::new(b"hello".to_vec(), src_addr.clone(), dst_addr.clone());

        info!(
            "proxy_fn(udp) sending packet: src={:?}, dst={:?}, data={:?}",
            src_addr, dst_addr, b"hello"
        );
        trace!("proxy_fn(udp) start write");

        datagram.send(packet.clone()).await.map_err(|x| {
            tracing::error!("proxy_fn(udp) write error: {}", x);
            anyhow::Error::new(x)
        })?;

        info!("proxy_fn(udp) packet sent successfully, waiting for response...");
        trace!("proxy_fn(udp) start read");

        let pkt =
            tokio::time::timeout(Duration::from_secs(5), datagram.next()).await;

        match pkt {
            Ok(Some(pkt)) => {
                tracing::info!(
                    "proxy_fn(udp) received response: {} bytes, data={:?}",
                    pkt.data.len(),
                    pkt.data
                );
                assert_eq!(pkt.data, b"world");
                tracing::trace!("proxy_fn(udp) end");
                Ok(())
            }
            Ok(None) => {
                tracing::error!(
                    "proxy_fn(udp) datagram stream closed without response"
                );
                Err(anyhow!("datagram stream closed"))
            }
            Err(_) => {
                tracing::error!("proxy_fn(udp) timeout waiting for response (5s)");
                Err(anyhow!("timeout waiting for UDP response"))
            }
        }
    }

    let proxy_task = tokio::spawn(async move {
        // give some time for the target local server to start
        tokio::time::sleep(Duration::from_secs(3)).await;

        for destination in &destination_list {
            let src = ("127.0.0.1".to_owned(), 10005)
                .try_into()
                .expect("Failed to parse source address");

            let dst: SocksAddr = match (destination.clone(), port).try_into() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!("Failed to parse destination address: {}", e);
                    continue;
                }
            };

            let sess = Session {
                destination: dst.clone(),
                ..Default::default()
            };

            let datagram =
                match handler.connect_datagram(&sess, resolver.clone()).await {
                    Ok(datagram) => datagram,
                    Err(e) => {
                        tracing::error!("Failed to proxy connection(udp): {}", e);
                        continue;
                    }
                };

            match tokio::time::timeout(
                Duration::from_secs(3),
                proxy_fn(datagram, src, dst),
            )
            .await
            {
                Ok(Ok(())) => {
                    tracing::info!(
                        "proxy_fn(udp) succeeded for destination: {}",
                        destination
                    );
                    return Ok(());
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "proxy_fn(udp) failed for destination {}: {}",
                        destination,
                        e
                    );
                    continue;
                }
                Err(_) => {
                    tracing::error!(
                        "proxy_fn(udp) timeout (3s) for destination: {}",
                        destination
                    );
                    continue;
                }
            }
        }
        Err(anyhow!(
            "all destination test error(udp): [{:?}]",
            destination_list
        ))
    });

    let futs = vec![proxy_task, target_local_server_handler];
    let res = select_all(futs).await.0?;
    tx.send(()).ok();
    res
}

// latency test of the proxy, will reuse the `url_test` ability
pub async fn latency_test(
    handler: Arc<dyn OutboundHandler>,
) -> anyhow::Result<(Duration, Duration)> {
    let resolver = config_helper::build_dns_resolver().await?;
    let proxy_manager = ProxyManager::new(resolver.clone(), None);

    for attempt in 1..=3 {
        match proxy_manager
            .url_test(
                handler.clone(),
                "https://google.com",
                Some(Duration::from_secs(10)),
            )
            .await
        {
            Ok(latency) => return Ok(latency),
            Err(_) if attempt < 3 => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!()
}

pub async fn dns_test(handler: Arc<dyn OutboundHandler>) -> anyhow::Result<()> {
    let src = SocksAddr::Ip(
        "127.0.0.1:0"
            .parse()
            .expect("Failed to parse source address"),
    );
    let dst = SocksAddr::Ip(
        "1.0.0.1:53"
            .parse()
            .expect("Failed to parse destination address"),
    );

    let sess = Session {
        destination: dst.clone(),
        ..Default::default()
    };

    let resolver = config_helper::build_dns_resolver().await?;
    let stream = handler.connect_datagram(&sess, resolver).await?;
    let (mut sink, mut stream) = stream.split();

    // DNS request for www.google.com A record
    let dns_req = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
    let udp_packet = UdpPacket::new(dns_req.to_vec(), src, dst);

    let start_time = Instant::now();

    for _ in 0..3 {
        sink.send(udp_packet.clone()).await?;

        if let Some(pkt) = stream.next().await {
            assert!(!pkt.data.is_empty());
            tracing::debug!("dns test time cost: {:?}", start_time.elapsed());
            return Ok(());
        }
    }

    bail!("Failed to receive DNS response after 3 attempts")
}

#[derive(Clone, Copy)]
pub enum Suite {
    PingPongTcp,
    PingPongUdp,
    LatencyTcp,
    DnsUdp,
}

impl Suite {
    pub const fn all() -> &'static [Suite] {
        &[
            Suite::PingPongTcp,
            Suite::PingPongUdp,
            Suite::LatencyTcp,
            Suite::DnsUdp,
        ]
    }

    // some outbound handlers doesn't support udp
    #[allow(dead_code)]
    pub const fn tcp_tests() -> &'static [Suite] {
        &[Suite::PingPongTcp, Suite::LatencyTcp]
    }
}

// ── SOCKS5 / process-level e2e helpers (docker_test only) ────────────────────

/// Connect to a SOCKS5 proxy at `proxy_addr` and issue a CONNECT to
/// `target_host:target_port`.  Returns a `TcpStream` ready for data.
#[cfg(all(docker_test, throughput_test))]
async fn socks5_connect(
    proxy_addr: std::net::SocketAddr,
    target_host: &str,
    target_port: u16,
) -> std::io::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    // Greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH(0)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::other("SOCKS5 auth negotiation failed"));
    }
    // CONNECT request: VER=5, CMD=CONNECT(1), RSV=0
    // Use ATYP=IPv4 for numeric IP addresses so the proxy chain doesn't need
    // to do DNS resolution; fall back to ATYP=DOMAIN for hostnames.
    let mut req = Vec::with_capacity(10 + target_host.len());
    if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
        req.extend_from_slice(&ip.octets());
    } else {
        let host_bytes = target_host.as_bytes();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    // Response header: VER, REP, RSV, ATYP
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 CONNECT failed: REP={}",
            hdr[1]
        )));
    }
    // Skip bound address
    match hdr[3] {
        0x01 => {
            let mut _skip = [0u8; 6];
            stream.read_exact(&mut _skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut _skip = [0u8; 18];
            stream.read_exact(&mut _skip).await?;
        }
        _ => {}
    }
    Ok(stream)
}

/// Wait until a TCP port accepts connections, or until `timeout_secs` elapses.
#[cfg(all(docker_test, throughput_test))]
async fn wait_for_port(port: u16, timeout_secs: u64) -> anyhow::Result<()> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("port {} not ready after {}s", port, timeout_secs);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Start clash-rs as a subprocess with `config_yaml`, then run a full-stack
/// upload+download throughput test through its SOCKS5 inbound.
///
/// The echo server is bound locally on `echo_port`; the SOCKS5 CONNECT target
/// is resolved using `destination_list(gateway_ip)` so docker containers can
/// reach back to the host.
///
/// `payload_bytes` is transferred in each direction (upload then download).
/// Results are logged with `tracing::info!` and — when
/// `THROUGHPUT_RESULTS_FILE` is set — appended as a JSON line to that file for
/// CI collection.
#[cfg(all(docker_test, throughput_test))]
pub async fn clash_process_e2e_throughput(
    binary: &std::path::Path,
    config_yaml: &str,
    label: &str,
    socks_port: u16,
    echo_port: u16,
    gateway_ip: Option<String>,
    payload_bytes: usize,
) -> anyhow::Result<ThroughputResult> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // --- write config to a temp file ---
    // Keep `cfg_file` alive for the entire function: Rust's async generator
    // drops unused locals before the first `.await`, so if we only used
    // `cfg_file` to obtain `cfg_path` the file would be deleted before
    // clash-rs finishes reading it (a race that surfaces under load when the
    // child process starts slowly).
    let mut cfg_file = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut cfg_file, config_yaml.as_bytes())?;
    let cfg_path = cfg_file.path().to_owned();

    // --- spawn clash-rs subprocess ---
    // Compatibility mode auto-sets `geosite = "geosite.dat"` which triggers a
    // network download on CI when the file is absent, causing concurrent
    // clash-rs instances to race-write the same file and corrupt it
    // ("geosite decode failed: buffer underflow"). Tests set all required
    // config values explicitly, so compatibility mode is not needed — and
    // since the binary now defaults `--compatibility` to false, we just omit
    // the flag entirely.
    let mut child = tokio::process::Command::new(binary)
        .arg("-c")
        .arg(&cfg_path)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn clash-rs: {e}"))?;

    // Retain `cfg_file` past the first `.await` below so the temp file is
    // not deleted before the child process opens it.
    let _cfg_file = cfg_file;

    // --- bind echo listener once; reuse across runs ---
    let echo_listener = std::sync::Arc::new(
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", echo_port)).await?,
    );

    // --- wait for SOCKS5 inbound to be ready ---
    // 90s gives clash-rs headroom on resource-constrained CI runners where
    // multiple Docker containers + subprocesses compete for 2 CPUs.
    wait_for_port(socks_port, 90).await.map_err(|e| {
        // Diagnose whether clash-rs exited early or simply never bound.
        // A silent crash before tracing-init produces zero output, so the
        // exit status is the only signal available in CI logs.
        match child.try_wait() {
            Ok(Some(status)) => {
                eprintln!(
                    "[clash-rs/{label}] exited early (status: {status}) before \
                     SOCKS port {socks_port} became ready"
                );
            }
            Ok(None) => {
                eprintln!(
                    "[clash-rs/{label}] still running after 90s but SOCKS port \
                     {socks_port} never became ready; killing"
                );
            }
            Err(ref e2) => {
                eprintln!("[clash-rs/{label}] try_wait failed: {e2}");
            }
        }
        child.start_kill().ok();
        e
    })?;

    // --- find a target address reachable from docker ---
    let destinations = destination_list(gateway_ip);
    let mut last_err = anyhow::anyhow!("no destinations");

    const RUNS: usize = 3;

    for dest in &destinations {
        let mut upload_samples: Vec<std::time::Duration> = Vec::with_capacity(RUNS);
        let mut download_samples: Vec<std::time::Duration> =
            Vec::with_capacity(RUNS);
        let mut dest_ok = true;

        for _run in 0..RUNS {
            let listener_clone = echo_listener.clone();
            let pbe = payload_bytes;
            let echo_task = tokio::spawn(async move {
                let chunk_size = 64 * 1024_usize;
                let mut buf = vec![0u8; chunk_size];
                let (mut stream, _) = listener_clone.accept().await?;
                // Phase 1: receive payload
                let mut received = 0usize;
                while received < pbe {
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        anyhow::bail!("echo: premature EOF on receive");
                    }
                    received += n;
                }
                // Sync barrier: send marker byte, then wait for client ACK
                // before starting phase 2 — prevents TCP from coalescing the
                // marker with the first download bytes, which would bias the
                // download timer.
                stream.write_all(&[0xACu8]).await?;
                stream.flush().await?;
                // Wait for client ACK (distinct value to detect misframes)
                let mut ack = [0u8; 1];
                stream.read_exact(&mut ack).await?;
                if ack != [0xCAu8] {
                    anyhow::bail!("echo server: invalid barrier ACK {ack:?}");
                }
                // Phase 2: send payload back
                let data = vec![0x42u8; chunk_size];
                let mut sent = 0usize;
                while sent < pbe {
                    let to_send = chunk_size.min(pbe - sent);
                    stream.write_all(&data[..to_send]).await?;
                    sent += to_send;
                }
                stream.flush().await?;
                anyhow::Ok(())
            });

            // client side
            let proxy_addr: std::net::SocketAddr =
                format!("127.0.0.1:{}", socks_port).parse().unwrap();
            let mut conn = match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                socks5_connect(proxy_addr, dest, echo_port),
            )
            .await
            {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    last_err = e.into();
                    echo_task.abort();
                    dest_ok = false;
                    break;
                }
                Err(_) => {
                    last_err = anyhow::anyhow!("socks5_connect timeout");
                    echo_task.abort();
                    dest_ok = false;
                    break;
                }
            };

            // Upload
            let upload_start = std::time::Instant::now();
            let chunk_size = 64 * 1024_usize;
            let upload_data = vec![0x42u8; chunk_size];
            let mut sent = 0usize;
            while sent < payload_bytes {
                let to_send = chunk_size.min(payload_bytes - sent);
                if let Err(e) = conn.write_all(&upload_data[..to_send]).await {
                    last_err = e.into();
                    echo_task.abort();
                    dest_ok = false;
                    break;
                }
                sent += to_send;
            }
            if !dest_ok {
                break;
            }
            if let Err(e) = conn.flush().await {
                last_err = e.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }

            // Sync byte: wait until echo server has received everything
            let mut sync = [0u8; 1];
            if let Err(e) = conn.read_exact(&mut sync).await {
                last_err = e.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }
            if sync != [0xACu8] {
                last_err = anyhow::anyhow!("invalid sync marker: {sync:?}");
                echo_task.abort();
                dest_ok = false;
                break;
            }
            let upload_elapsed = upload_start.elapsed();

            // Send ACK (0xCA) to echo server so it can start the download phase
            // without buffering the marker + first download bytes together.
            if let Err(e) = conn.write_all(&[0xCAu8]).await {
                last_err = e.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }
            if let Err(e) = conn.flush().await {
                last_err = e.into();
                echo_task.abort();
                dest_ok = false;
                break;
            }

            // Download
            let mut read_buf = vec![0u8; chunk_size];
            let download_start = std::time::Instant::now();
            let mut received = 0usize;
            loop {
                match conn.read(&mut read_buf).await {
                    Ok(0) => {
                        last_err = anyhow::anyhow!("premature EOF on download");
                        echo_task.abort();
                        dest_ok = false;
                        break;
                    }
                    Ok(n) => {
                        received += n;
                        if received >= payload_bytes {
                            break;
                        }
                    }
                    Err(e) => {
                        last_err = e.into();
                        echo_task.abort();
                        dest_ok = false;
                        break;
                    }
                }
            }
            if !dest_ok {
                break;
            }
            let download_elapsed = download_start.elapsed();

            echo_task.await??;

            upload_samples.push(upload_elapsed);
            download_samples.push(download_elapsed);
        }

        if dest_ok {
            let mb = payload_bytes as f64 / 1024.0 / 1024.0;
            let upload_mbps = median_mbps(&upload_samples, mb);
            let download_mbps = median_mbps(&download_samples, mb);
            let upload_stdev = stdev_mbps(&upload_samples, mb);
            let download_stdev = stdev_mbps(&download_samples, mb);

            tracing::info!(
                "e2e throughput [{}] ({} MB, {} runs): upload={:.1}±{:.1} Mbps  \
                 download={:.1}±{:.1} Mbps",
                label,
                payload_bytes / 1024 / 1024,
                RUNS,
                upload_mbps,
                upload_stdev,
                download_mbps,
                download_stdev,
            );

            child.start_kill().ok();
            let result = ThroughputResult {
                label: label.to_owned(),
                upload_mbps,
                download_mbps,
                upload_stdev_mbps: upload_stdev,
                download_stdev_mbps: download_stdev,
                runs: RUNS,
                total_bytes: payload_bytes,
                netem: None,
            };
            write_throughput_result(&result);
            return Ok(result);
        }
    }

    child.start_kill().ok();
    Err(last_err)
}

// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_test_suites_and_cleanup(
    handler: Arc<dyn OutboundHandler>,
    docker_test_runner: impl RunAndCleanup,
    suites: &[Suite],
) -> anyhow::Result<()> {
    let suites = suites.to_owned();
    let gateway_ip = docker_test_runner.docker_gateway_ip();
    docker_test_runner
        .run_and_cleanup(async move {
            for suite in suites {
                match suite {
                    Suite::PingPongTcp => {
                        let rv = ping_pong_test(handler.clone(), gateway_ip.clone())
                            .await;
                        if rv.is_err() {
                            tracing::error!("ping_pong_test failed: {:?}", rv);
                            return rv;
                        } else {
                            tracing::info!("ping_pong_test success");
                        }
                    }
                    Suite::PingPongUdp => {
                        let rv =
                            ping_pong_udp_test(handler.clone(), gateway_ip.clone())
                                .await;
                        if rv.is_err() {
                            tracing::error!("ping_pong_udp_test failed: {:?}", rv);
                            return rv;
                        } else {
                            tracing::info!("ping_pong_udp_test success");
                        }
                    }
                    Suite::LatencyTcp => {
                        let rv = latency_test(handler.clone()).await;
                        match rv {
                            Ok(_) => {
                                tracing::info!("url test success: ",);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Suite::DnsUdp => {
                        let rv = dns_test(handler.clone()).await;
                        if let Err(rv) = rv {
                            return Err(rv);
                        } else {
                            tracing::info!("dns_test success");
                        }
                    }
                }
            }

            Ok(())
        })
        .await
}
