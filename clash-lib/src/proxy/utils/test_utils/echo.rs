#![allow(dead_code)]

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

const DEFAULT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct TcpEchoConfig {
    pub response: &'static [u8],
    pub expected_request: Option<&'static [u8]>,
    pub read_size: usize,
    pub iterations: Option<usize>,
    pub bind_addr: &'static str,
}

impl Default for TcpEchoConfig {
    fn default() -> Self {
        Self {
            response: b"world",
            expected_request: Some(b"hello"),
            read_size: 5,
            iterations: Some(10),
            bind_addr: "127.0.0.1",
        }
    }
}

pub struct TcpEchoServer {
    handle: Option<tokio::task::JoinHandle<()>>,
    port: u16,
}

impl TcpEchoServer {
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with(TcpEchoConfig::default()).await
    }

    pub async fn start_with(config: TcpEchoConfig) -> anyhow::Result<Self> {
        let bind_to = format!("{}:0", config.bind_addr);
        let listener = tokio::net::TcpListener::bind(bind_to.as_str()).await?;
        let port = listener.local_addr()?.port();

        let handle = tokio::spawn(async move {
            let stream = match tokio::time::timeout(
                DEFAULT_ACCEPT_TIMEOUT,
                listener.accept(),
            )
            .await
            {
                Ok(Ok((stream, _))) => stream,
                _ => return,
            };
            let (mut reader, mut writer) = stream.into_split();
            let mut buf = vec![0u8; config.read_size];

            match config.iterations {
                Some(n) => {
                    for _ in 0..n {
                        if reader.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        if let Some(expected) = config.expected_request {
                            assert_eq!(buf.as_slice(), expected);
                        }
                        if writer.write_all(config.response).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                }
                None => {
                    while reader.read_exact(&mut buf).await.is_ok() {
                        if let Some(expected) = config.expected_request {
                            assert_eq!(buf.as_slice(), expected);
                        }
                        if writer.write_all(config.response).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                }
            }
        });

        Ok(Self {
            handle: Some(handle),
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for TcpEchoServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

pub(super) async fn serve_udp_ping_pong(listener: UdpSocket) -> std::io::Result<()> {
    let mut buf = vec![0; u16::MAX as usize];
    loop {
        let (len, peer) = listener.recv_from(&mut buf).await?;
        // A reused ephemeral port can still receive unrelated datagrams.
        if &buf[..len] == b"hello" {
            listener.send_to(b"world", peer).await?;
        }
    }
}

#[tokio::test]
async fn udp_ping_pong_ignores_unrelated_datagrams() -> std::io::Result<()> {
    let listener = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(serve_udp_ping_pong(listener));
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(addr).await?;
    let mut buf = [0; 16];
    client.send(&[97, 214, 129, 128, 0]).await?;
    client.send(b"hello!").await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), client.recv(&mut buf))
            .await
            .is_err()
    );
    client.send(b"hello").await?;
    let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await??;
    assert_eq!(&buf[..n], b"world");
    server.abort();
    Ok(())
}
