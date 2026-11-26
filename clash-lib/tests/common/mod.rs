use futures::TryFutureExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::{
    net::{Shutdown, TcpStream},
    sync::atomic::{AtomicU16, Ordering},
};

/// Backward-compatible wrapper used by integration_tests.rs.
#[allow(dead_code)]
pub fn start_clash(options: clash_lib::Options) -> Result<(), clash_lib::Error> {
    clash_lib::start_scaffold(options)
}

/// Global port counter. Each test claims a contiguous block starting here.
#[allow(dead_code)]
static NEXT_PORT: AtomicU16 = AtomicU16::new(20000);

/// Allocate `n` consecutive port numbers (no binding, just counter).
#[allow(dead_code)]
pub fn alloc_ports(n: u16) -> u16 {
    NEXT_PORT.fetch_add(n, Ordering::Relaxed)
}

/// Build a client config YAML string from the bundled rules.yaml template,
/// substituting all hardcoded local ports with unique values derived from
/// `port_base`.
///
/// Port layout (offsets from `port_base`):
///   +0  external-controller (API)
///   +1  HTTP proxy
///   +2  SOCKS5 proxy
///   +3  mixed proxy
///   +4  DNS UDP/TCP
///   +5  DNS DoT
///   +6  DNS DoH / DoH3
#[allow(dead_code)]
pub fn make_client_config_str(port_base: u16) -> String {
    let tpl = include_str!("../data/config/client/rules.yaml");
    tpl.replace(":9090", &format!(":{}", port_base))
        .replace("port: 8888", &format!("port: {}", port_base + 1))
        .replace("\"8889\"", &format!("\"{}\"", port_base + 2))
        .replace(
            "mixed-port: 8899",
            &format!("mixed-port: {}", port_base + 3),
        )
        .replace("127.0.0.1:53553", &format!("127.0.0.1:{}", port_base + 4))
        .replace("127.0.0.1:53554", &format!("127.0.0.1:{}", port_base + 5))
        .replace("127.0.0.1:53555", &format!("127.0.0.1:{}", port_base + 6))
}

pub fn wait_port_ready(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 300 {
        if let Ok(stream) = TcpStream::connect(&addr) {
            stream.shutdown(Shutdown::Both).ok();
            return Ok(());
        }
        attempts += 1;
        // 100ms polling instead of 2s for faster startup detection
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is not ready after 300 attempts (30s)", port),
    )))
}

#[allow(dead_code)]
fn wait_port_closed(port: u16) -> Result<(), clash_lib::Error> {
    let addr = format!("127.0.0.1:{}", port);
    let mut attempts = 0;
    while attempts < 30 {
        if TcpStream::connect(&addr).is_err() {
            return Ok(());
        }
        attempts += 1;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(clash_lib::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Port {} is still open after 15 seconds", port),
    )))
}

/// RAII guard for an isolated Clash instance.
///
/// On drop: cancels this instance's shutdown token, waits for all ports to
/// close, then joins the background thread. Does NOT touch the global
/// SHUTDOWN_TOKEN, so concurrent instances are unaffected.
#[allow(dead_code)]
pub struct ClashInstance {
    ports: Vec<u16>,
    handle: Option<std::thread::JoinHandle<()>>,
    token: tokio_util::sync::CancellationToken,
}

impl ClashInstance {
    #[allow(dead_code)]
    pub fn start(
        options: clash_lib::Options,
        ports: Vec<u16>,
    ) -> Result<Self, clash_lib::Error> {
        let (handle, token) = clash_lib::start_scaffold_instance(options)?;

        let instance = Self {
            ports,
            handle: Some(handle),
            token,
        };
        for &port in &instance.ports {
            wait_port_ready(port)?;
        }
        Ok(instance)
    }
}

impl Drop for ClashInstance {
    fn drop(&mut self) {
        // Cancel only this instance — does not affect sibling instances.
        self.token.cancel();

        // Wait for all ports to be released.
        for &port in &self.ports {
            if let Err(e) = wait_port_closed(port) {
                eprintln!(
                    "Warning: Failed to wait for port {} to close: {}",
                    port, e
                );
            }
        }

        // Join the thread to ensure it has fully exited.
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Sends an HTTP request to the specified URL using a TCP connection.
/// Don't use any domain name in the URL, which will trigger DNS resolution.
/// And libnss_files will likely cause a coredump(in static crt build).
#[allow(dead_code)]
pub async fn send_http_request<T>(
    url: hyper::Uri,
    req: hyper::Request<T>,
) -> std::io::Result<http::Response<Incoming>>
where
    T: hyper::body::Body + Send + 'static,
    <T as hyper::body::Body>::Data: Send,
    <T as hyper::body::Body>::Error: Sync + Send + std::error::Error,
{
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    let stream = tokio::net::TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .map_err(|e| {
            std::io::Error::other(format!("Failed to establish connection: {}", e))
        })
        .await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let res = sender
        .send_request(req)
        .map_err(|e| std::io::Error::other(format!("Failed to send request: {}", e)))
        .await?;

    Ok(res)
}

// ── SOCKS5 UDP client ────────────────────────────────────────────────────────

/// A SOCKS5 UDP relay session.
///
/// Keeps the control TCP connection alive for the duration of the session.
/// Provides helpers for sending and receiving SOCKS5 UDP datagrams with both
/// IPv4 (ATYP 0x01) and domain-name (ATYP 0x03) addressing.
#[allow(dead_code)]
pub struct Socks5UdpSession {
    // The TCP control connection must stay open for the relay to remain alive.
    _tcp: tokio::net::TcpStream,
    pub socket: tokio::net::UdpSocket,
    pub relay_addr: std::net::SocketAddr,
}

#[allow(dead_code)]
impl Socks5UdpSession {
    /// Perform a SOCKS5 UDP ASSOCIATE handshake against `proxy_port` on
    /// 127.0.0.1 and return the ready session.
    pub async fn connect(proxy_port: u16) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
            .await
            .unwrap();

        // Auth: no-auth
        tcp.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        tcp.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "SOCKS5 auth failed");

        // UDP ASSOCIATE with zeroed client address
        tcp.write_all(&[0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await
            .unwrap();

        let mut hdr = [0u8; 4];
        tcp.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[1], 0x00, "SOCKS5 UDP ASSOCIATE rejected");

        let relay_addr: std::net::SocketAddr = match hdr[3] {
            0x01 => {
                let mut ip = [0u8; 4];
                let mut port = [0u8; 2];
                tcp.read_exact(&mut ip).await.unwrap();
                tcp.read_exact(&mut port).await.unwrap();
                (std::net::Ipv4Addr::from(ip), u16::from_be_bytes(port)).into()
            }
            atyp => panic!("unexpected ATYP {atyp} in UDP ASSOCIATE reply"),
        };

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        Self {
            _tcp: tcp,
            socket,
            relay_addr,
        }
    }

    /// Send `data` addressed to `dst_ip:dst_port` (ATYP=0x01, IPv4).
    pub async fn send_ipv4(&self, data: &[u8], dst_ip: [u8; 4], dst_port: u16) {
        let mut dgram = Vec::with_capacity(10 + data.len());
        dgram.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // RSV, FRAG, ATYP=IPv4
        dgram.extend_from_slice(&dst_ip);
        dgram.extend_from_slice(&dst_port.to_be_bytes());
        dgram.extend_from_slice(data);
        self.socket.send_to(&dgram, self.relay_addr).await.unwrap();
    }

    /// Send `data` addressed to `domain:port` (ATYP=0x03, domain name).
    pub async fn send_domain(&self, data: &[u8], domain: &str, port: u16) {
        let domain_bytes = domain.as_bytes();
        assert!(domain_bytes.len() <= 255, "domain too long");
        let mut dgram = Vec::with_capacity(5 + domain_bytes.len() + 2 + data.len());
        dgram.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // RSV, FRAG, ATYP=domain
        dgram.push(domain_bytes.len() as u8);
        dgram.extend_from_slice(domain_bytes);
        dgram.extend_from_slice(&port.to_be_bytes());
        dgram.extend_from_slice(data);
        self.socket.send_to(&dgram, self.relay_addr).await.unwrap();
    }

    /// Receive one SOCKS5 UDP datagram. Returns `(payload, src_addr_str)`
    pub async fn recv(&self) -> (Vec<u8>, String) {
        let mut buf = vec![0u8; 65535];
        let (n, sender) = self.socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            sender, self.relay_addr,
            "UDP datagram came from unexpected sender: expected {}, got {}",
            self.relay_addr, sender
        );
        let pkt = &buf[..n];

        // Skip RSV(2) + FRAG(1)
        assert!(pkt.len() >= 4);
        let atyp = pkt[3];
        let mut pos = 4usize;

        let src = match atyp {
            0x01 => {
                let ip = std::net::Ipv4Addr::from([
                    pkt[pos],
                    pkt[pos + 1],
                    pkt[pos + 2],
                    pkt[pos + 3],
                ]);
                pos += 4;
                let port = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                pos += 2;
                format!("{ip}:{port}")
            }
            0x03 => {
                let len = pkt[pos] as usize;
                pos += 1;
                let domain = std::str::from_utf8(&pkt[pos..pos + len])
                    .unwrap()
                    .to_owned();
                pos += len;
                let port = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                pos += 2;
                format!("{domain}:{port}")
            }
            0x04 => {
                let mut ip6 = [0u8; 16];
                ip6.copy_from_slice(&pkt[pos..pos + 16]);
                let ip = std::net::Ipv6Addr::from(ip6);
                pos += 16;
                let port = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
                pos += 2;
                format!("[{ip}]:{port}")
            }
            atyp => panic!("unknown ATYP {atyp}"),
        };

        (pkt[pos..].to_vec(), src)
    }
}
