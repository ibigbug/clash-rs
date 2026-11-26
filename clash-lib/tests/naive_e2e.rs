//! Real client/server interoperability: SOCKS -> Clash -> Wind/Cronet ->
//! Docker sing-box Naive inbound -> container-local HTTP/TCP/UDP targets. No
//! public proxy is used.
//!
//! ```sh
//! CLASH_DOCKER_TEST=true cargo test --locked -p clash-lib --features naive --test naive_e2e
//! ```
//! For dynamic builds, set `CLASH_NAIVE_CRONET_LIB` to the absolute path of the
//! shared library.
#![cfg(all(feature = "naive", docker_test))]

mod common;

#[path = "common/cronet.rs"]
mod cronet;

#[path = "common/docker.rs"]
mod docker;

use std::{future::Future, net::Ipv4Addr, panic::AssertUnwindSafe, time::Duration};

use anyhow::{Context, Result, bail};
use common::{ClashInstance, Socks5UdpSession};
use docker::{
    consts::IMAGE_NAIVE_SINGBOX,
    docker_runner::{
        DockerTestRunnerBuilder, MultiDockerTestRunner, RunAndCleanup,
        alloc_docker_port,
    },
};
use futures::FutureExt;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SERVER_PORT: u16 = 10002;
const TARGET_IMAGE: &str =
    "rust:1.90-alpine3.22@sha256:\
     b4b54b176a74db7e5c68fdfe6029be39a02ccbcfe72b6e5a3e18e2c61b57ae26";
const HTTP_TARGET: &str = "127.0.0.1:10080";

struct Server {
    host: String,
    port: u16,
    ca: String,
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
        let target_path = dir.path().join("targets.rs");
        std::fs::write(&target_path, include_bytes!("naive/targets.rs"))?;
        let target_path = target_path.to_str().context("non-UTF-8 fixture path")?;
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
        let targets = DockerTestRunnerBuilder::new()
            .image(TARGET_IMAGE)
            .no_port()
            .net_mode(&format!("container:{}", runner.container_id()))
            .cmd(&[
                "sh",
                "-ec",
                "rustc --edition=2024 /targets.rs -o /tmp/targets && exec \
                 /tmp/targets",
            ])
            .mounts(&[(target_path, "/targets.rs")])
            .build()
            .await;
        let targets = match targets {
            Ok(targets) => targets,
            Err(error) => {
                runner.cleanup().await?;
                return Err(error);
            }
        };
        let ready = async {
            runner
                .wait_for_log("sing-box started", Duration::from_secs(15))
                .await?;
            targets
                .wait_for_log("naive targets ready", Duration::from_secs(15))
                .await
        }
        .await;
        // Remove the namespace-sharing fixture before the proxy container.
        let mut runners = MultiDockerTestRunner::default();
        runners.add_with_runner(targets);
        runners.add_with_runner(runner);
        let server = Self { host, port, ca };
        // Convert panics to errors so the runner still cleans up both
        // containers.
        let result = runners
            .run_and_cleanup(async move {
                ready?;
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
        if let Some(path) = cronet::library_path()? {
            proxy["cronet-lib-path"] = json!(path);
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

async fn tcp_roundtrip(quic: bool) -> Result<()> {
    Server::run(quic, move |server| async move {
        let client = Client::start(&server, quic, "e2e-password", true, false)?;
        let url = format!("http://{HTTP_TARGET}/echo");
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
        assert_eq!(
            http.get(format!("http://{HTTP_TARGET}/count"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?,
            "3"
        );
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

async fn tcp_half_close(quic: bool) -> Result<()> {
    Server::run(quic, move |server| async move {
        for round in 0..3 {
            let client = Client::start(&server, quic, "e2e-password", true, false)?;
            for (index, size) in [0, 7, 256 * 1024].into_iter().enumerate() {
                tokio::time::timeout(Duration::from_secs(15), async {
                    let port = 10003 + index as u16;
                    let payload: Vec<_> =
                        (0..size).map(|i| (i % 251) as u8).collect();
                    let mut socket = docker::socks5::connect(
                        (Ipv4Addr::LOCALHOST, client.socks_port).into(),
                        "127.0.0.1",
                        port,
                    )
                    .await?;
                    socket.write_all(&payload).await?;
                    socket.shutdown().await?;
                    socket.shutdown().await?;
                    let mut response = Vec::new();
                    socket.read_to_end(&mut response).await?;
                    assert_eq!(response.len(), 256 * 1024);
                    assert!(response.iter().all(|byte| *byte == 0xa5));
                    Ok::<_, anyhow::Error>(())
                })
                .await
                .with_context(|| {
                    format!(
                        "EOF-delimited request timed out (round={round}, \
                         size={size}, quic={quic})"
                    )
                })??;
            }
        }
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_h2_half_close() -> Result<()> {
    tcp_half_close(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_h3_half_close() -> Result<()> {
    tcp_half_close(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_authentication_and_certificate_rejection() -> Result<()> {
    Server::run(false, |server| async move {
        let url = format!("http://{HTTP_TARGET}/echo");
        let control = Client::start(&server, false, "e2e-password", true, false)?;
        let http = control.http()?;
        let response = http
            .post(&url)
            .body("control")
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(response.text().await?, "control");
        assert_eq!(
            http.get(format!("http://{HTTP_TARGET}/count"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?,
            "1"
        );
        // DIRECT reaches this loopback socket on the client.
        let canary = tokio::net::TcpListener::bind(HTTP_TARGET).await?;
        for (password, trust) in [("wrong-password", true), ("e2e-password", false)]
        {
            let client = Client::start(&server, false, password, trust, false)?;
            let request = client.http()?.post(&url).body("must not arrive").send();
            tokio::select! {
                biased;
                incoming = canary.accept() => {
                    bail!("failed tunnel fell back to DIRECT from {}", incoming?.1);
                }
                response = request => assert!(response.is_err()),
            }
        }
        assert_eq!(
            http.get(format!("http://{HTTP_TARGET}/count"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?,
            "1",
            "only the control POST should reach the container"
        );
        Ok(())
    })
    .await
}

async fn udp_roundtrip(quic: bool) -> Result<()> {
    Server::run(quic, move |server| async move {
        let client = Client::start(&server, quic, "e2e-password", true, true)?;
        let udp = Socks5UdpSession::connect(client.socks_port).await;
        for sequence in 0..12 {
            let port = 10090 + sequence % 2;
            // WSL mirrored loopback can drop SOCKS5 payloads above 1462 bytes.
            // Use native Linux loopback for the larger packets.
            let payload =
                vec![sequence as u8; [1, 2048, 4096][sequence as usize % 3]];
            udp.send_ipv4(&payload, Ipv4Addr::LOCALHOST.octets(), port)
                .await;
            let (reply, source) =
                tokio::time::timeout(Duration::from_secs(10), udp.recv())
                    .await
                    .with_context(|| {
                        format!(
                            "UDP reply timed out (quic={quic}, \
                             sequence={sequence}, port={port}, size={})",
                            payload.len()
                        )
                    })?;
            assert_eq!(reply, payload);
            assert_eq!(source, format!("127.0.0.1:{port}"));
        }
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_udp_over_tcp() -> Result<()> {
    udp_roundtrip(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn naive_e2e_h3_udp_over_tcp() -> Result<()> {
    udp_roundtrip(true).await
}
