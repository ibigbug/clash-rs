use std::{collections::HashMap, path::Path};

use anyhow;
use bollard::{
    API_DEFAULT_VERSION, Docker, body_full,
    config::ContainerInspectResponse,
    models::{ContainerCreateBody, HostConfig, Mount, MountType, PortBinding},
    query_parameters::{
        CreateContainerOptions, CreateImageOptions, CreateImageOptionsBuilder,
        LogsOptions, RemoveContainerOptions, StartContainerOptions,
        UploadToContainerOptions,
    },
};
use bytes::Bytes;
use futures::{Future, StreamExt, TryStreamExt};
use tar;

const TIMEOUT_DURATION: u64 = 120;

/// Creates a tar archive from a source path with the given target path.
/// This is a blocking operation and should be called from `spawn_blocking`.
fn create_tar_archive(source: &str, target: &str) -> anyhow::Result<Vec<u8>> {
    let mut ar = tar::Builder::new(Vec::new());

    // Remove leading slash for tar path
    let tar_path = if target.starts_with('/') {
        &target[1..]
    } else {
        target
    };

    let source_path = Path::new(source);
    let metadata = std::fs::metadata(source_path)?;

    if metadata.is_file() {
        // Handle single file
        let content = std::fs::read(source_path)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        ar.append_data(&mut header, tar_path, &content[..])?;
    } else if metadata.is_dir() {
        // Handle directory recursively
        ar.append_dir_all(tar_path, source_path)?;
    } else {
        anyhow::bail!("Unsupported file type for source: {}", source);
    }

    let tar_data = ar.into_inner()?;

    // Debug: Print all files in the tar archive
    tracing::trace!(
        "=== TAR Archive Contents for mount {} -> {} ===",
        source,
        target
    );
    let mut archive = tar::Archive::new(&tar_data[..]);
    for (idx, entry) in archive.entries()?.enumerate() {
        match entry {
            Ok(e) => {
                let path = e.path().ok();
                let size = e.header().size().ok();
                tracing::trace!("  [{}] {:?} (size: {:?})", idx, path, size);
            }
            Err(e) => {
                tracing::warn!("  [{}] Error reading entry: {}", idx, e);
            }
        }
    }
    tracing::trace!("=== End TAR Archive Contents ===");

    Ok(tar_data)
}

pub struct DockerTestRunner {
    instance: Docker,
    id: String,
    inspect: ContainerInspectResponse,
}

impl DockerTestRunner {
    pub async fn try_new(
        image_conf: Option<CreateImageOptions>,
        mut container_conf: ContainerCreateBody,
    ) -> anyhow::Result<Self> {
        let docker: Docker = if let Some(url) = std::env::var("DOCKER_HOST").ok() {
            if url.starts_with("http://")
                || url.starts_with("https://")
                || url.starts_with("tcp://")
            {
                Docker::connect_with_http(&url, 60, API_DEFAULT_VERSION)?
            } else if url.starts_with("unix://") || url.starts_with("npipe://") {
                Docker::connect_with_socket(&url, 60, API_DEFAULT_VERSION)?
            } else {
                anyhow::bail!("invalid DOCKER_HOST url: {}", url);
            }
        } else {
            Docker::connect_with_socket_defaults()?
        };

        let mut pull_attempts = 0;
        loop {
            match docker
                .create_image(image_conf.clone(), None, None)
                .try_collect::<Vec<_>>()
                .await
            {
                Ok(_) => break,
                Err(e) if pull_attempts < 3 => {
                    pull_attempts += 1;
                    tracing::warn!(
                        "create_image failed (attempt {}): {}, retrying in 2s...",
                        pull_attempts,
                        e
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }

        // For remote Docker, we need to handle mounts differently
        let mounts = container_conf
            .host_config
            .as_mut()
            .and_then(|hc| hc.mounts.take());
        let files_to_copy = if std::env::var("DOCKER_HOST")
            .ok()
            .map(|url| {
                url.starts_with("http://")
                    || url.starts_with("https://")
                    || url.starts_with("tcp://")
            })
            .unwrap_or(false)
        {
            // Remote Docker - collect files to copy via API
            mounts
        } else {
            // Local Docker - keep mounts in config
            if let Some(mounts) = mounts {
                container_conf.host_config.as_mut().unwrap().mounts = Some(mounts);
            }
            None
        };

        let container = docker
            .create_container(
                Some(CreateContainerOptions::default()),
                container_conf,
            )
            .await?;
        let id = container.id;

        // Copy files to container if needed (for remote Docker)
        if let Some(mounts) = files_to_copy {
            for mount in mounts {
                if let (Some(source), Some(target)) =
                    (mount.source.as_deref(), mount.target.as_deref())
                {
                    // Create tar archive in blocking context
                    let source = source.to_string();
                    let target = target.to_string();
                    let tar_data = tokio::task::spawn_blocking(move || {
                        create_tar_archive(&source, &target)
                    })
                    .await??;

                    // Upload to container root directory
                    docker
                        .upload_to_container(
                            &id,
                            Some(UploadToContainerOptions {
                                path: "/".to_string(),
                                ..Default::default()
                            }),
                            body_full(Bytes::from(tar_data)),
                        )
                        .await?;
                }
            }
        }

        // Try to start the container, cleanup if it fails
        if let Err(e) = docker
            .start_container(&id, Some(StartContainerOptions::default()))
            .await
        {
            // Cleanup the created container before returning error
            let _ = docker
                .remove_container(
                    &id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
            return Err(e.into());
        }
        let inspect = docker.inspect_container(&id, None).await?;
        Ok(Self {
            instance: docker,
            id,
            inspect,
        })
    }

    pub fn container_ip(&self) -> Option<String> {
        self.inspect
            .network_settings
            .as_ref()
            .and_then(|i| i.networks.as_ref())
            .and_then(|b| {
                b.values().find_map(|j| {
                    [
                        (&j.gateway, &j.ip_address),
                        (&j.ipv6_gateway, &j.global_ipv6_address),
                    ]
                    .into_iter()
                    .find(|(gateway, _)| {
                        gateway.as_ref().map_or(false, |g| !g.is_empty())
                    })
                    .and_then(|(_, ip)| ip.as_ref())
                    .filter(|ip| !ip.is_empty())
                    .map(|ip| ip.to_string())
                })
            })
            .inspect(|e| {
                tracing::trace!("container_ip: {:?}", e);
            })
    }

    pub fn gateway_ip(&self) -> Option<String> {
        self.inspect
            .network_settings
            .as_ref()
            .and_then(|i| i.networks.as_ref())
            .and_then(|b| {
                b.values().find_map(|j| {
                    [(&j.gateway), (&j.ipv6_gateway)]
                        .into_iter()
                        .find(|gateway| {
                            gateway.as_ref().map_or(false, |g| !g.is_empty())
                        })
                        .and_then(|gateway| gateway.as_ref())
                        .filter(|ip| !ip.is_empty())
                        .map(|ip| ip.to_string())
                })
            })
            .inspect(|e| {
                tracing::trace!("gateway_ip: {:?}", e);
            })
    }

    /// For debugging use
    #[allow(dead_code)]
    pub async fn exec_command(&self, cmd: &[&str]) -> anyhow::Result<String> {
        use bollard::exec::{CreateExecOptions, StartExecResults};

        let exec = self
            .instance
            .create_exec(
                &self.id,
                CreateExecOptions {
                    cmd: Some(cmd.iter().map(|s| s.to_string()).collect()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await?;

        let start_result = self.instance.start_exec(&exec.id, None).await?;

        match start_result {
            StartExecResults::Attached { mut output, .. } => {
                let mut result = String::new();
                while let Some(log) = output.next().await {
                    match log {
                        Ok(log_output) => {
                            result.push_str(&log_output.to_string());
                        }
                        Err(e) => {
                            tracing::warn!("Error reading exec output: {}", e);
                            break;
                        }
                    }
                }
                Ok(result)
            }
            StartExecResults::Detached => Ok(String::new()),
        }
    }

    /// Apply tc netem traffic shaping to this container's eth0 interface by
    /// starting a short-lived `nicolaka/netshoot` sidecar that shares the
    /// container's network namespace and has NET_ADMIN capability.
    ///
    /// `delay_ms`: one-way delay in milliseconds (e.g. 50 for 50ms)
    /// `loss_pct`: packet loss percentage (e.g. 1.0 = 1%)
    #[cfg(all(docker_test, throughput_test))]
    pub async fn apply_netem(
        &self,
        delay_ms: u32,
        loss_pct: f32,
    ) -> anyhow::Result<()> {
        use super::consts::IMAGE_NETEM;
        use bollard::query_parameters::WaitContainerOptionsBuilder;
        use futures::StreamExt as _;

        let tc_cmd = format!(
            "tc qdisc add dev eth0 root netem delay {}ms loss {}%",
            delay_ms, loss_pct
        );
        let network_mode = format!("container:{}", self.id);

        let body = ContainerCreateBody {
            image: Some(IMAGE_NETEM.to_owned()),
            cmd: Some(vec!["sh".to_owned(), "-c".to_owned(), tc_cmd]),
            host_config: Some(HostConfig {
                network_mode: Some(network_mode),
                cap_add: Some(vec!["NET_ADMIN".to_owned()]),
                auto_remove: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let sidecar = self
            .instance
            .create_container(Some(CreateContainerOptions::default()), body)
            .await?;

        self.instance
            .start_container(
                &sidecar.id,
                None::<bollard::query_parameters::StartContainerOptions>,
            )
            .await?;

        // Wait for the sidecar to finish running
        let mut wait_stream = self.instance.wait_container(
            &sidecar.id,
            Some(
                WaitContainerOptionsBuilder::new()
                    .condition("not-running")
                    .build(),
            ),
        );
        while let Some(result) = wait_stream.next().await {
            match result {
                Ok(status) => {
                    if status.status_code != 0 {
                        // Explicit cleanup before bailing
                        self.instance
                            .remove_container(
                                &sidecar.id,
                                Some(RemoveContainerOptions {
                                    force: true,
                                    ..Default::default()
                                }),
                            )
                            .await
                            .ok();
                        anyhow::bail!(
                            "netem sidecar exited with code {}: {:?}",
                            status.status_code,
                            status.error
                        );
                    }
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        // Explicitly remove the sidecar now that we have verified the exit code
        self.instance
            .remove_container(
                &sidecar.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .ok();

        Ok(())
    }

    // you can run the cleanup manually
    pub async fn cleanup(self) -> anyhow::Result<()> {
        let logs = self
            .instance
            .logs(
                &self.id,
                Some(LogsOptions {
                    follow: false,
                    stdout: true,
                    stderr: true,
                    ..Default::default()
                }),
            )
            .try_collect::<Vec<_>>()
            .await?;

        for log in logs {
            eprintln!("{}", log);
        }

        self.instance
            .remove_container(
                &self.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;
        Ok(())
    }
}

#[derive(Default)]
pub struct MultiDockerTestRunner {
    runners: Vec<DockerTestRunner>,
}

#[cfg(docker_test)]
impl MultiDockerTestRunner {
    #[allow(dead_code)]
    pub async fn add(
        &mut self,
        creator: impl Future<Output = anyhow::Result<DockerTestRunner>>,
    ) -> anyhow::Result<()> {
        match creator.await {
            Ok(runner) => {
                self.runners.push(runner);
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "cannot start container, please check the docker environment, \
                     error: {:?}",
                    e
                );
                // Cleanup all previously added containers before returning
                // error
                for runner in std::mem::take(&mut self.runners) {
                    let _ = runner.cleanup().await;
                }
                Err(e)
            }
        }
    }

    #[allow(dead_code)]
    pub fn add_with_runner(&mut self, runners: DockerTestRunner) {
        self.runners.push(runners);
    }
}

#[async_trait::async_trait]
pub trait RunAndCleanup {
    /// Get the docker gateway IP address.
    fn docker_gateway_ip(&self) -> Option<String>;
    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl RunAndCleanup for DockerTestRunner {
    fn docker_gateway_ip(&self) -> Option<String> {
        self.gateway_ip()
    }

    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()> {
        let fut = Box::pin(f);
        // let res = fut.await;
        // make sure the container is cleaned up
        let res = tokio::select! {
            res = fut => {
                res
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(TIMEOUT_DURATION))=> {
                tracing::warn!("timeout");
                Err(anyhow::anyhow!("timeout"))
            }
        };

        self.cleanup().await?;

        res
    }
}

#[async_trait::async_trait]
impl RunAndCleanup for MultiDockerTestRunner {
    fn docker_gateway_ip(&self) -> Option<String> {
        self.runners.iter().find_map(|d| d.gateway_ip())
    }

    async fn run_and_cleanup(
        self,
        f: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    ) -> anyhow::Result<()> {
        let fut = Box::pin(f);
        // let res = fut.await;
        // make sure the container is cleaned up
        let res = tokio::select! {
            res = fut => {
                res
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(TIMEOUT_DURATION))=> {
                tracing::warn!("timeout");
                Err(anyhow::anyhow!("timeout"))
            }
        };

        // cleanup all the docker containers
        for runner in self.runners {
            runner.cleanup().await?;
        }

        res
    }
}

const PORT: u16 = 10002;
const EXPOSED_TCP: &str = "10002/tcp";
const EXPOSED_UDP: &str = "10002/udp";
const EXPOSED_PORTS: &[&str] = &[EXPOSED_TCP, EXPOSED_UDP];

#[derive(Debug)]
pub struct DockerTestRunnerBuilder {
    image: String,
    host_config: HostConfig,
    exposed_ports: Vec<String>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    _server_port: u16,
}

impl Default for DockerTestRunnerBuilder {
    fn default() -> Self {
        Self {
            image: "hello-world".to_string(),
            host_config: get_host_config(PORT),
            exposed_ports: EXPOSED_PORTS
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            cmd: None,
            env: None,
            entrypoint: None,
            _server_port: PORT,
        }
    }
}

impl DockerTestRunnerBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn image(mut self, image: &str) -> Self {
        self.image = image.to_string();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self._server_port = port;
        self.exposed_ports = vec![format!("{}/tcp", port), format!("{}/udp", port)];
        let new_host_config = get_host_config(port);
        self.host_config.network_mode = new_host_config.network_mode;
        self.host_config.port_bindings = new_host_config.port_bindings;

        self
    }

    /// Map a dynamic host port to a fixed container port.
    /// Use when the container always listens on `container_port` (hardcoded in
    /// its config file) but we need a unique host port to avoid EADDRINUSE
    /// collisions between parallel tests.
    #[allow(dead_code)]
    pub fn host_port(mut self, host_port: u16, container_port: u16) -> Self {
        self._server_port = host_port;
        self.exposed_ports = vec![
            format!("{}/tcp", container_port),
            format!("{}/udp", container_port),
        ];
        let bindings: std::collections::HashMap<String, Option<Vec<PortBinding>>> =
            [
                (
                    format!("{}/tcp", container_port),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(format!("{}", host_port)),
                    }]),
                ),
                (
                    format!("{}/udp", container_port),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(format!("{}", host_port)),
                    }]),
                ),
            ]
            .into_iter()
            .collect();
        self.host_config.port_bindings = Some(bindings);
        self
    }

    /// Do not bind any host port.  Use this when the container is accessed
    /// exclusively via its internal docker network IP (e.g. e2e tests that
    /// spawn a clash-rs subprocess which connects via container IP).  Avoids
    /// EADDRINUSE errors that occur when Docker tries to bind a host port in
    /// the OS ephemeral range.
    #[allow(dead_code)]
    pub fn no_port(mut self) -> Self {
        self.exposed_ports = vec![];
        self.host_config.port_bindings = Some(HashMap::new());
        self
    }

    pub fn cmd(mut self, cmd: &[&str]) -> Self {
        self.cmd = Some(cmd.iter().map(|x| x.to_string()).collect());
        self
    }

    #[allow(dead_code)]
    pub fn env(mut self, env: &[&str]) -> Self {
        self.env = Some(env.iter().map(|x| x.to_string()).collect());
        self
    }

    #[cfg(docker_test)]
    #[allow(dead_code)]
    pub fn entrypoint(mut self, entrypoint: &[&str]) -> Self {
        self.entrypoint = Some(entrypoint.iter().map(|x| x.to_string()).collect());
        self
    }

    pub fn mounts(mut self, pairs: &[(&str, &str)]) -> Self {
        self.host_config.mounts = Some(
            pairs
                .iter()
                .map(|(src, dst)| Mount {
                    target: Some(dst.to_string()),
                    source: Some(src.to_string()),
                    typ: Some(MountType::BIND),
                    read_only: Some(false),
                    ..Default::default()
                })
                .collect::<Vec<_>>(),
        );

        self
    }

    #[allow(dead_code)]
    pub fn sysctls(mut self, sysctls: &[(&str, &str)]) -> Self {
        self.host_config.sysctls = Some(
            sysctls
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        );

        self
    }

    #[allow(dead_code)]
    pub fn cap_add(mut self, caps: &[&str]) -> Self {
        self.host_config.cap_add =
            Some(caps.iter().map(|x| x.to_string()).collect());
        self
    }

    #[allow(dead_code)]
    pub fn net_mode(mut self, mode: &str) -> Self {
        self.host_config.network_mode = Some(mode.to_string());
        self
    }

    pub async fn build(self) -> anyhow::Result<DockerTestRunner> {
        tracing::trace!("building docker test runner: {:?}", &self);

        DockerTestRunner::try_new(
            Some(
                CreateImageOptionsBuilder::new()
                    .from_image(&self.image)
                    .build(),
            ),
            ContainerCreateBody {
                image: Some(self.image),
                tty: Some(true),
                entrypoint: self.entrypoint,
                cmd: self.cmd,
                env: self.env,
                exposed_ports: Some(self.exposed_ports),
                host_config: Some(self.host_config),
                ..Default::default()
            },
        )
        .await
        .map_err(Into::into)
    }
}

/// Allocate a unique TCP port number for use in a Docker test.
///
/// Delegates to the same process-global counter used by `alloc_port()` so
/// that Docker port mappings and clash-rs SOCKS/echo ports can never
/// collide when multiple tests run concurrently.
#[cfg(docker_test)]
pub fn alloc_docker_port() -> u16 {
    super::PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub fn get_host_config(port: u16) -> HostConfig {
    HostConfig {
        port_bindings: Some(
            [
                (
                    (format!("{}/tcp", port)),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(format!("{}", port)),
                    }]),
                ),
                (
                    (format!("{}/udp", port)),
                    Some(vec![PortBinding {
                        host_ip: Some("0.0.0.0".to_owned()),
                        host_port: Some(format!("{}", port)),
                    }]),
                ),
            ]
            .into_iter()
            .collect::<HashMap<_, _>>(),
        ),
        // #[cfg(not(target_os = "macos"))]
        // network_mode: Some("host".to_owned()),
        ..Default::default()
    }
}
