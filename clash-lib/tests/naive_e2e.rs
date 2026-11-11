//! Real client/server interoperability: SOCKS -> Clash -> Wind/Cronet ->
//! Docker sing-box Naive inbound -> host HTTP/UDP target. No public proxy is
//! used.
#![cfg(all(feature = "naive", docker_test))]

mod common;

#[path = "common/docker.rs"]
mod docker;

use std::{
    future::Future,
    net::Ipv4Addr,
    panic::AssertUnwindSafe,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::{Router, body::Bytes, routing::post};
use common::{ClashInstance, Socks5UdpSession};
use docker::{
    consts::IMAGE_NAIVE_SINGBOX,
    docker_runner::{DockerTestRunnerBuilder, RunAndCleanup, alloc_docker_port},
};
use futures::FutureExt;
use serde_json::json;
use tokio_util::task::AbortOnDropHandle;

const SERVER_PORT: u16 = 10002;

struct Server {
    host: String,
    port: u16,
    ca: String,
    target_ip: Ipv4Addr,
}

impl Server {
    async fn run<F, Fut>(quic: bool, test: F) -> Result<()>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send,
    {
        let host = match std::env::var("DOCKER_HOST") {
            Ok(endpoint)
                if endpoint.starts_with("tcp://")
                    || endpoint.starts_with("http://")
                    || endpoint.starts_with("https://") =>
            {
                url::Url::parse(&endpoint)?
                    .host_str()
                    .context("DOCKER_HOST has no hostname")?
                    .to_owned()
            }
            _ => "127.0.0.1".to_owned(),
        };
        let dir = tempfile::tempdir()?;
        let port = alloc_docker_port();
        let mut params = rcgen::CertificateParams::new(vec![host.clone()])?;
        params.not_before =
            time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
        let key = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let ca = cert.pem();
        std::fs::write(dir.path().join("cert.pem"), &ca)?;
        std::fs::write(dir.path().join("key.pem"), key.serialize_pem())?;
        std::fs::write(
            dir.path().join("server.json"),
            serde_json::to_vec(&json!({
                "log": {"level": "info", "timestamp": false},
                "inbounds": [{
                    "type": "naive", "tag": "naive-in", "listen": "0.0.0.0", "listen_port": SERVER_PORT,
                    "network": if quic { "udp" } else { "tcp" },
                    "users": [{"username": "e2e-user", "password": "e2e-password"}],
                    "tls": {"enabled": true, "certificate_path": "/etc/naive/cert.pem", "key_path": "/etc/naive/key.pem"}
                }],
                "outbounds": [{"type": "direct", "tag": "direct"}]
            }))?,
        )?;
        let runner = DockerTestRunnerBuilder::new()
            .image(IMAGE_NAIVE_SINGBOX)
            .cmd(&["run", "-c", "/etc/naive/server.json"])
            .mounts(&[(
                dir.path().to_str().context("non-UTF-8 fixture path")?,
                "/etc/naive",
            )])
            .host_port(port, SERVER_PORT)
            .build()
            .await?;
        // Resolve the destination from the container's perspective. Remote
        // Docker needs an explicit route back to the machine running this test.
        let ready = async {
            runner
                .wait_for_log("sing-box started", Duration::from_secs(15))
                .await?;
            if let Ok(ip) = std::env::var("CLIENT_IP") {
                return ip.parse::<Ipv4Addr>().context(
                    "CLIENT_IP must be an IPv4 address reachable from Docker",
                );
            }
            if std::env::var("DOCKER_HOST").is_ok_and(|endpoint| {
                endpoint.starts_with("tcp://")
                    || endpoint.starts_with("http://")
                    || endpoint.starts_with("https://")
            }) {
                bail!(
                    "set CLIENT_IP to the test host's IPv4 address when using \
                     remote Docker"
                );
            }
            if cfg!(target_os = "linux") {
                return runner
                    .gateway_ip()
                    .context("Docker network has no gateway")?
                    .parse::<Ipv4Addr>()
                    .context("Docker gateway is not IPv4");
            }
            let hosts = runner
                .exec_command(&["getent", "hosts", "host.docker.internal"])
                .await?;
            hosts
                .split_whitespace()
                .find_map(|part| part.parse::<Ipv4Addr>().ok())
                .context(
                    "cannot resolve host.docker.internal; set CLIENT_IP to the \
                     test host's IPv4 address",
                )
        }
        .await;
        let target_ip = match ready {
            Ok(ip) => ip,
            Err(error) => {
                runner.cleanup().await?;
                return Err(error);
            }
        };
        let server = Self {
            host,
            port,
            ca,
            target_ip,
        };
        // Catch assertion panics so the shared runner still removes the
        // container. Keep fixtures outside the timed future, including
        // on timeout/failure.
        let result = runner
            .run_and_cleanup(async move {
                match AssertUnwindSafe(async move { test(server).await })
                    .catch_unwind()
                    .await
                {
                    Ok(result) => result,
                    Err(panic) => {
                        let message = panic
                            .downcast_ref::<String>()
                            .map(String::as_str)
                            .or_else(|| panic.downcast_ref::<&str>().copied())
                            .unwrap_or("test panicked");
                        bail!("Naive Docker test panicked: {message}")
                    }
                }
            })
            .await;
        drop(dir);
        result
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
        let socks_port = alloc_docker_port();
        let api_port = alloc_docker_port();
        std::fs::write(dir.path().join("ca.pem"), &server.ca)?;
        let mut proxy = json!({
            "type": "naive", "name": "naive-e2e", "server": server.host, "port": server.port,
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

async fn http_target(
    target_ip: Ipv4Addr,
) -> Result<(String, Arc<AtomicUsize>, AbortOnDropHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
    let url = format!("http://{target_ip}:{}/echo", listener.local_addr()?.port());
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
    Server::run(quic, move |server| async move {
        let client = Client::start(&server, quic, "e2e-password", true, false)?;
        let (url, calls, _target) = http_target(server.target_ip).await?;
        // Cross both Naive's initial padded frames and the adapter's 64 KiB
        // buffer.
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
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_h2_tcp() -> Result<()> {
    tcp_roundtrip(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_h3_tcp() -> Result<()> {
    tcp_roundtrip(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_authentication_and_certificate_rejection() -> Result<()> {
    Server::run(false, |server| async move {
        let (url, calls, _target) = http_target(server.target_ip).await?;
        {
            let client = Client::start(&server, false, "e2e-password", true, false)?;
            let response = client
                .http()?
                .post(&url)
                .body("control")
                .send()
                .await?
                .error_for_status()?;
            assert_eq!(response.text().await?, "control");
        }
        assert_eq!(calls.swap(0, Ordering::SeqCst), 1);
        for (password, trust) in [("wrong-password", true), ("e2e-password", false)]
        {
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
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_udp_over_tcp() -> Result<()> {
    Server::run(false, |server| async move {
        let client = Client::start(&server, false, "e2e-password", true, true)?;
        let udp = Socks5UdpSession::connect(client.socks_port).await;
        for _ in 0..2 {
            let echo = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let addr = echo.local_addr()?;
            let task = AbortOnDropHandle::new(tokio::spawn(async move {
                let mut buf = [0; 4096];
                let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
                echo.send_to(&buf[..n], peer).await.unwrap();
            }));
            let payload = vec![0x5a; 2048];
            udp.send_ipv4(&payload, server.target_ip.octets(), addr.port())
                .await;
            let (reply, source) =
                tokio::time::timeout(Duration::from_secs(10), udp.recv()).await?;
            assert_eq!(reply, payload);
            assert_eq!(source, format!("{}:{}", server.target_ip, addr.port()));
            task.await?;
        }
        Ok(())
    })
    .await
}
