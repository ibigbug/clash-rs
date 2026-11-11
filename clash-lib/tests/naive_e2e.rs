//! Real client/server interoperability: SOCKS -> Clash -> Wind/Cronet ->
//! sing-box Naive inbound -> loopback HTTP/UDP target. No public proxy is used.
#![cfg(feature = "naive")]

mod common;

use std::{
    net::{TcpListener, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{Router, body::Bytes, routing::post};
use common::{ClashInstance, Socks5UdpSession};
use serde_json::json;
use tokio_util::task::AbortOnDropHandle;

fn free_port() -> Result<u16> {
    // Windows can reserve different ephemeral ranges for TCP and UDP.
    // A TCP-selected port is therefore only a candidate for a dual listener.
    for _ in 0..64 {
        let tcp = TcpListener::bind("127.0.0.1:0")
            .context("allocate ephemeral TCP port")?;
        let port = tcp.local_addr()?.port();
        match UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
            Ok(_udp) => return Ok(port),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrInUse
                        | std::io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => return Err(error).context("probe matching UDP port"),
        }
    }
    bail!("could not find a loopback port available for both TCP and UDP")
}

struct Server {
    process: Child,
    dir: tempfile::TempDir,
    port: u16,
    ca: String,
}

impl Server {
    async fn start(quic: bool) -> Result<Self> {
        let executable = std::env::var_os("CLASH_NAIVE_SING_BOX").context(
            "set CLASH_NAIVE_SING_BOX to a sing-box binary with QUIC support",
        )?;
        let dir = tempfile::tempdir()?;
        let port = free_port()?;
        let mut params = rcgen::CertificateParams::new(vec![
            "localhost".into(),
            "127.0.0.1".into(),
        ])?;
        params.not_before =
            time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
        let key = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let ca = cert.pem();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &ca)?;
        std::fs::write(&key_path, key.serialize_pem())?;
        let config_path = dir.path().join("server.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&json!({
                "log": {"level": "info", "timestamp": false},
                "inbounds": [{
                    "type": "naive", "tag": "naive-in", "listen": "127.0.0.1", "listen_port": port,
                    "network": if quic { "udp" } else { "tcp" },
                    "users": [{"username": "e2e-user", "password": "e2e-password"}],
                    "tls": {"enabled": true, "certificate_path": cert_path, "key_path": key_path}
                }],
                "outbounds": [{"type": "direct", "tag": "direct"}]
            }))?,
        )?;
        let log = std::fs::File::create(dir.path().join("server.log"))?;
        let mut command = Command::new(executable);
        command
            .args(["run", "-c"])
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let process = command.spawn().context("start sing-box")?;
        let mut server = Self {
            process,
            dir,
            port,
            ca,
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let log =
                    std::fs::read_to_string(server.dir.path().join("server.log"))?;
                if let Some(status) = server.process.try_wait()? {
                    bail!("sing-box exited {status}: {log}");
                }
                if log.contains("sing-box started") {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .context("sing-box startup timeout")??;
        Ok(server)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

struct Client {
    _instance: ClashInstance,
    _dir: tempfile::TempDir,
    socks_port: u16,
    api_port: u16,
}

impl Client {
    fn start(
        server: &Server,
        quic: bool,
        password: &str,
        trust: bool,
        udp: bool,
    ) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let socks_port = free_port()?;
        let api_port = free_port()?;
        std::fs::write(dir.path().join("ca.pem"), &server.ca)?;
        let mut proxy = json!({
            "type": "naive", "name": "naive-e2e", "server": "127.0.0.1", "port": server.port,
            "username": "e2e-user", "password": password, "quic": quic, "udp": udp,
            "request-timeout": 5000, "concurrency": 2
        });
        if trust {
            proxy["ca-cert"] = json!("ca.pem");
        }
        if let Some(path) = std::env::var_os("CLASH_NAIVE_CRONET_LIB") {
            proxy["cronet-lib-path"] = json!(PathBuf::from(path));
        }
        let config = serde_yaml::to_string(&json!({
            "socks-port": socks_port, "bind-address": "127.0.0.1",
            "external-controller": format!("127.0.0.1:{api_port}"),
            "mode": "rule", "log-level": "warn",
            "proxies": [proxy], "rules": ["MATCH,naive-e2e"]
        }))?;
        let instance = ClashInstance::start(
            clash_lib::Options {
                config: clash_lib::Config::Str(config),
                cwd: Some(dir.path().to_string_lossy().into_owned()),
                rt: None,
                log_file: None,
                config_path: None,
            },
            vec![api_port, socks_port],
        )?;
        Ok(Self {
            _instance: instance,
            _dir: dir,
            socks_port,
            api_port,
        })
    }

    fn http(&self) -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!(
                "socks5h://127.0.0.1:{}",
                self.socks_port
            ))?)
            .timeout(Duration::from_secs(10))
            .build()?)
    }
}

async fn http_target() -> Result<(String, Arc<AtomicUsize>, AbortOnDropHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/echo", listener.local_addr()?);
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let router = Router::new().route(
        "/echo",
        post(move |body: Bytes| {
            counter.fetch_add(1, Ordering::SeqCst);
            async move { body }
        }),
    );
    let task = AbortOnDropHandle::new(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    Ok((url, calls, task))
}

async fn tcp_roundtrip(quic: bool) -> Result<()> {
    let server = Server::start(quic).await?;
    let client = Client::start(&server, quic, "e2e-password", true, false)?;
    let (url, calls, _target) = http_target().await?;
    // Cross both Naive's initial padded frames and the adapter's 64 KiB buffer.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let http = client.http()?;
    let requests = (0..3).map(|_| async {
        let response = http
            .post(&url)
            .body(payload.clone())
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(response.bytes().await?.as_ref(), payload.as_slice());
        Ok::<_, anyhow::Error>(())
    });
    futures::future::try_join_all(requests).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let api_response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(format!(
            "http://127.0.0.1:{}/proxies/naive-e2e",
            client.api_port
        ))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let api: serde_json::Value = serde_json::from_slice(&api_response)?;
    assert_eq!(api["type"], "Naive");
    assert!(!api.to_string().contains("e2e-password"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "requires sing-box and libcronet; see tests/naive/README.md"]
async fn naive_e2e_h2_tcp() -> Result<()> {
    tcp_roundtrip(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "requires sing-box and libcronet; see tests/naive/README.md"]
async fn naive_e2e_h3_tcp() -> Result<()> {
    tcp_roundtrip(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "requires sing-box and libcronet; see tests/naive/README.md"]
async fn naive_e2e_authentication_and_certificate_rejection() -> Result<()> {
    let server = Server::start(false).await?;
    let (url, calls, _target) = http_target().await?;
    for (password, trust) in [("wrong-password", true), ("e2e-password", false)] {
        let client = Client::start(&server, false, password, trust, false)?;
        assert!(
            client
                .http()?
                .post(&url)
                .body("must not arrive")
                .send()
                .await
                .is_err()
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "failed tunnels must never fall back to DIRECT"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
#[ignore = "requires sing-box and libcronet; see tests/naive/README.md"]
async fn naive_e2e_udp_over_tcp() -> Result<()> {
    let server = Server::start(false).await?;
    let client = Client::start(&server, false, "e2e-password", true, true)?;
    let udp = Socks5UdpSession::connect(client.socks_port).await;
    for _ in 0..2 {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = echo.local_addr()?;
        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut buf = [0; 4096];
            let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], peer).await.unwrap();
        }));
        let payload = vec![0x5a; 2048];
        udp.send_ipv4(&payload, [127, 0, 0, 1], addr.port()).await;
        let (reply, source) =
            tokio::time::timeout(Duration::from_secs(10), udp.recv()).await?;
        assert_eq!(reply, payload);
        assert_eq!(source, addr.to_string());
        task.await?;
    }
    Ok(())
}
