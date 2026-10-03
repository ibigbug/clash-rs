use std::{
    borrow::Cow, collections::HashMap, io, pin::Pin, sync::Arc, time::Duration,
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;

mod auth;
mod connector;
use connector::Client;
use russh::{
    ChannelStream, Preferred,
    client::{self, Handle, Msg},
    kex::*,
    keys::Algorithm,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    session::Session,
};

use super::{
    ConnectorType, DialWithConnector, HandlerCommonOptions, OutboundHandler,
    OutboundType, PlainProxyAPIResponse,
    utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
};

/// Wrapper for `ChannelStream` for `Debug` trait
struct ChannelStreamWrapper {
    inner: ChannelStream<Msg>,
}

impl std::fmt::Debug for ChannelStreamWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelStreamWrapper").finish()
    }
}

impl AsyncRead for ChannelStreamWrapper {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChannelStreamWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
#[derive(Debug)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub username: String,
    /// try public key first, then password
    pub password: Option<String>,
    /// TOTP secret, support full config and Rfc6238
    pub totp: Option<totp_rs::TOTP>,
    /// key content or path
    /// if contains "PRIVATE KEY", it's raw content, otherwise it's a file path
    /// if so, it can start with "~" to represent home directory,
    pub private_key: Option<String>,
    /// password to protect private key file when `private_key` is a file path
    pub private_key_passphrase: Option<String>,
    /// if empty, will not verify host key
    pub host_key: Option<Vec<String>>,
    /// supported host key algorithms:
    ///   * `ssh-ed25519`
    ///   * `rsa-sha2-256`
    ///   * `rsa-sha2-512`
    ///   * `ssh-rsa` ✨
    ///   * `ecdsa-sha2-nistp256` ✨
    ///   * `ecdsa-sha2-nistp384` ✨
    ///   * `ecdsa-sha2-nistp521` ✨
    pub host_key_algorithms: Option<Vec<Algorithm>>,
}

#[derive(Debug)]
pub struct Handler {
    opts: HandlerOptions,

    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: tokio::sync::RwLock::new(None),
        }
    }
}

/// default values defined in golang's crypto/ssh (used by mihomo)
/// https://github.com/golang/crypto/blob/9290511cd23ab9813a307b7f2615325e3ca98902/ssh/common.go#L65
const KEX_ALGORITHMS: &[Name] = &[
    CURVE25519,
    CURVE25519_PRE_RFC_8731,
    DH_GEX_SHA1,
    DH_GEX_SHA256,
    DH_G14_SHA1,
    DH_G14_SHA256,
    ECDH_SHA2_NISTP256,
    ECDH_SHA2_NISTP384,
    ECDH_SHA2_NISTP521,
    NONE,
    EXTENSION_SUPPORT_AS_CLIENT,
];

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Ssh
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let dialer = self.connector.read().await;

        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedStream> {
        let stream = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;

        // key exchange algorithms
        let kex = Cow::Borrowed(KEX_ALGORITHMS);
        // host key algorithms
        let key = match self.opts.host_key_algorithms.clone() {
            Some(host_key_algorithms) => Cow::Owned(host_key_algorithms),
            None => Default::default(),
        };
        // TODO: make inactivity_timeout configurable
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            preferred: Preferred {
                kex,
                key,
                ..Default::default()
            },
            ..<_>::default()
        };

        let config = Arc::new(config);

        let server_public_key = self.opts.host_key.as_ref().map(|x| {
            x.iter()
                .filter_map(|x| {
                    russh::keys::ssh_key::PublicKey::from_openssh(x).ok()
                })
                .collect::<Vec<_>>()
        });
        let sh = connector::Client { server_public_key };

        let mut session = client::connect_stream(config, stream, sh)
            .await
            .map_err(io::Error::other)?;

        auth0(&mut session, &self.opts).await?;

        let dst = sess.destination.clone();
        let channel = session
            .channel_open_direct_tcpip(
                dst.host(),
                sess.destination.port() as _,
                "0.0.0.0",
                0,
            )
            .await
            .map_err(io::Error::other)?;
        let s: crate::proxy::AnyStream = Box::new(ChannelStreamWrapper {
            inner: channel.into_stream(),
        });
        let chained = InstrumentedStreamWrapper::new(s);
        chained.append_to_chain(self.name()).await;
        Ok(Box::new(chained))
    }

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        Err(new_io_error("ssh udp is not implemented yet"))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        m.insert(
            "username".to_owned(),
            Box::new(self.opts.username.clone()) as _,
        );
        if self.opts.password.is_some() {
            m.insert("password".to_owned(), Box::new(true) as _);
        }
        if self.opts.private_key.is_some() {
            m.insert("private-key".to_owned(), Box::new(true) as _);
        }
        m
    }
}

async fn auth0(
    client: &mut Handle<Client>,
    opts: &HandlerOptions,
) -> io::Result<()> {
    let res = auth::authenticate(client, opts).await;

    match res {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!("ssh auth failed: {:?}", e);
            Err(new_io_error("ssh auth failed"))
        }
    }
}

#[cfg(all(test, docker_test))]
mod tests {
    use std::{future::Future, path::PathBuf};

    use rand_chacha::rand_core::SeedableRng;
    use russh::keys::HashAlg;
    use tempfile::tempdir;

    use super::{
        super::utils::test_utils::{consts::*, docker_runner::DockerTestRunner},
        *,
    };
    use crate::{
        proxy::utils::test_utils::{
            Suite,
            config_helper::test_config_base_dir,
            docker_runner::{DockerTestRunnerBuilder, alloc_docker_port},
            run_test_suites_and_cleanup,
        },
        tests::initialize,
    };

    const PASSWORD: &str = "123456789";

    /// equals to:
    /// docker run -d \
    /// --name=openssh-server \
    /// --hostname=openssh-server `#optional` \
    /// -e PUID=1000 \
    /// -e PGID=1000 \
    /// -e TZ=Etc/UTC \
    /// -e SUDO_ACCESS=true `#optional` \
    /// -e PASSWORD_ACCESS=true `#optional` \
    /// -e USER_PASSWORD=123456789 `#optional` \
    /// -e LOG_STDOUT= `#optional` \
    /// -p 2222:2222 \
    /// -v /tmp/.xxx/ssh:/config \
    /// --restart unless-stopped \
    /// docker.io/linuxserver/openssh-server:latest
    ///
    /// /tmp/.xxx is the temporary directory generated by tempfile.
    /// in `clash/test/config/ssh/.ssh``, we have test_ed25519, test_rsa (the
    /// pub keys are already put in the authorized_keys for further test).
    /// `clash/test/config/ssh/ssh_host_keys/sshd_config" will be used as
    /// `/config/sshd/sshd_config` in the container.
    /// before starting the container, we need to generate host key pairs in
    /// /tmp/.xxx/ssh/ssh_host_keys.
    async fn get_openssh_server_runner(
        ssh_config_path: PathBuf,
        host_port: u16,
    ) -> anyhow::Result<DockerTestRunner> {
        let password = format!("USER_PASSWORD={}", PASSWORD);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_OPENSSH)
            .env(&[
                "PUID=1000",
                "PGID=1000",
                "TZ=Etc/UTC",
                "SUDO_ACCESS=true",
                "PASSWORD_ACCESS=true",
                &password,
            ])
            .mounts(&[(ssh_config_path.to_str().unwrap(), "/config")])
            .host_port(host_port, 2222)
            .build()
            .await
    }

    fn gen_ssh_key_pair(
        algo: russh::keys::Algorithm,
    ) -> anyhow::Result<(String, String)> {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed(Default::default());
        let ssh_private_key = russh::keys::PrivateKey::random(&mut rng, algo)?;
        let ssh_public_key = ssh_private_key.public_key();

        let ssh_private_key_str = ssh_private_key
            .to_openssh(ssh_key::LineEnding::LF)?
            .to_string();
        let ssh_public_key_str = ssh_public_key.to_openssh()?;

        Ok((ssh_private_key_str, ssh_public_key_str))
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    struct TestOption {
        password: bool,                // password or private key
        rsa: bool,                     // rsa or ed25519
        host_key: Option<Vec<String>>, // host key
    }

    async fn test_ssh_inner(opt: TestOption, host_port: u16) -> anyhow::Result<()> {
        tracing::info!("testing ssh, using option: {:?}", opt);

        // Prepare SSH config directory for the docker container
        // We need a writable temp directory because:
        // 1. Host keys must be generated at runtime
        // 2. Container needs to write logs
        let temp_dir = tempdir()?;
        let test_config_base_dir = test_config_base_dir();
        let ssh_config_path = test_config_base_dir.join("ssh");
        let ssh_config_tmp_path = temp_dir.path().join("ssh");

        // Copy SSH config files using Rust APIs (cross-platform)
        copy_dir_recursive(&ssh_config_path, &ssh_config_tmp_path).await?;

        // IMPORTANT: Container expects sshd_config at /config/sshd/sshd_config
        // Our source has it at ssh_host_keys/sshd_config, but the container
        // startup script will ignore/delete it from there and generate a
        // default config if /config/sshd/sshd_config doesn't exist.
        // So we need to copy it to the correct location.
        let source_sshd_config = ssh_config_tmp_path
            .join("ssh_host_keys")
            .join("sshd_config");
        let target_sshd_dir = ssh_config_tmp_path.join("sshd");
        tokio::fs::create_dir_all(&target_sshd_dir).await?;
        let target_sshd_config = target_sshd_dir.join("sshd_config");
        tokio::fs::copy(&source_sshd_config, &target_sshd_config).await?;
        tracing::info!(
            "Copied sshd_config from {:?} to {:?}",
            source_sshd_config,
            target_sshd_config
        );

        // Debug: print directory structure
        tracing::debug!("SSH config directory structure after copy:");
        print_dir_structure(&ssh_config_tmp_path, 0).await?;

        tracing::info!("ssh_config tmp mounting path: {:?}", ssh_config_tmp_path);

        // Create logs directory
        tokio::fs::create_dir_all(&ssh_config_tmp_path.join("logs").join("openssh"))
            .await?;

        // Generate host key pairs (ecdsa, ed25519, and rsa for test_ssh2)
        // Note: RSA key generation doesn't need hash parameter (hash is only
        // for signing)
        let name_and_key_pairs = [
            (
                "ecdsa",
                Algorithm::Ecdsa {
                    curve: russh::keys::EcdsaCurve::NistP256,
                },
            ),
            ("ed25519", Algorithm::Ed25519),
        ]
        .into_iter()
        .map(|(name, algo)| {
            let (private_key, public_key) =
                gen_ssh_key_pair(algo).expect("Key generation failed");
            (name, private_key, public_key)
        })
        .collect::<Vec<_>>();

        let host_key_path = ssh_config_tmp_path.join("ssh_host_keys");
        for (name, private_key, public_key) in name_and_key_pairs {
            let private_key_path =
                host_key_path.join(format!("ssh_host_{}_key", name));
            tokio::fs::write(private_key_path, private_key).await?;
            let public_key_path =
                host_key_path.join(format!("ssh_host_{}_key.pub", name));
            tokio::fs::write(public_key_path, public_key).await?;
        }

        // Start the container
        let container =
            get_openssh_server_runner(ssh_config_tmp_path.clone(), host_port)
                .await?;

        // Configure client to connect to container
        let ssh_private_key_path = ssh_config_path.join(".ssh").join(if opt.rsa {
            "test_rsa"
        } else {
            "test_ed25519"
        });
        let ssh_private_key_path = ssh_private_key_path.to_str().unwrap();

        let password = if opt.password {
            Some(PASSWORD.to_owned())
        } else {
            None
        };
        let private_key = if !opt.password {
            Some(ssh_private_key_path.to_owned())
        } else {
            None
        };

        let opts = HandlerOptions {
            name: "test-ssh".to_owned(),
            common_opts: Default::default(),
            server: container.container_ip().unwrap_or(LOCAL_ADDR.to_owned()),
            port: 2222,
            password,
            private_key,
            private_key_passphrase: None,
            username: "linuxserver.io".to_owned(),
            host_key: opt.host_key.clone(),
            host_key_algorithms: Some(vec![
                Algorithm::Ed25519,
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
            ]),
            totp: None,
        };
        let handler: Arc<dyn OutboundHandler> = Arc::new(Handler::new(opts));

        run_test_suites_and_cleanup(handler, container, Suite::tcp_tests()).await
    }

    /// Recursively copy a directory using async Rust APIs
    fn copy_dir_recursive<'a>(
        src: &'a std::path::Path,
        dst: &'a std::path::Path,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
        Box::pin(async move {
            tokio::fs::create_dir_all(dst).await?;

            let mut entries = tokio::fs::read_dir(src).await?;
            while let Some(entry) = entries.next_entry().await? {
                let src_path = entry.path();
                let dst_path = dst.join(entry.file_name());

                if entry.file_type().await?.is_dir() {
                    copy_dir_recursive(&src_path, &dst_path).await?;
                } else {
                    tokio::fs::copy(&src_path, &dst_path).await?;
                }
            }

            Ok(())
        })
    }

    /// Print directory structure for debugging
    fn print_dir_structure<'a>(
        path: &'a std::path::Path,
        indent: usize,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
        Box::pin(async move {
            let mut entries = tokio::fs::read_dir(path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let file_name = entry.file_name();
                let indent_str = "  ".repeat(indent);

                if entry.file_type().await?.is_dir() {
                    tracing::debug!(
                        "{}{}/",
                        indent_str,
                        file_name.to_string_lossy()
                    );
                    print_dir_structure(&entry.path(), indent + 1).await?;
                } else {
                    tracing::debug!("{}{}", indent_str, file_name.to_string_lossy());
                }
            }
            Ok(())
        })
    }

    #[tokio::test]
    async fn test_ssh1() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        test_ssh_inner(
            TestOption {
                password: true,
                rsa: false,
                host_key: None,
            },
            host_port,
        )
        .await
    }

    #[tokio::test]
    async fn test_ssh2() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        test_ssh_inner(
            TestOption {
                password: false,
                rsa: true,
                host_key: None,
            },
            host_port,
        )
        .await
    }

    #[tokio::test]
    async fn test_ssh3() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        test_ssh_inner(
            TestOption {
                password: false,
                rsa: false,
                host_key: None,
            },
            host_port,
        )
        .await
    }

    #[tokio::test]
    async fn test_ssh4() -> anyhow::Result<()> {
        initialize();
        let host_port = alloc_docker_port();
        // config wrong host key, expect failure
        let host_key = Some(
            vec![
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtnezeRnexr9UgviTV66AcQ0uGQ9gx4t0GjVA29SstlBgZ5750DmKdxYt3PrCC2qslVOfnpW/1XNMSmRtuqM2C0/uaRBx/lAPyjEQ3IwLHTk7CxirzNw46nYBeIKBKYcdP6LIfdvZ9+avd6+SGIJVrBovBHzV2aIpDEG3dO+9op7gzGPpdRHP4WnOdAuSnLCaAvrSs+amFEmrD+nZLMwUMfX5H9huGJNxo1/ma4Ti3jclY8Utw+K6y2NUNB7YXuiJg2Ugfnu6d54VBg9lA2o481Ol0ys2i46sdmWhaVPRGlWTmQ1fAsbd+9u3/2ae6n9Oc6V88izGUrH8sFb23FmlAbHF5tT2nnOs1XzQPCiUsHgn2XVidEONe2Q/FJbfoA4fUYmoQPGprXzHcvtguUajww7dwYfyEXU6IxNRVl5H+64fnsQ2shVAnpJ10fzSrK1RtcnF3zWGvix2z/wOzgx2ydUV9lNp7tU3bOX2iL8CvYBFwnFqEHRGH5Ry9km1ujdE=".to_owned()
        ]);
        let res = test_ssh_inner(
            TestOption {
                password: false,
                rsa: false,
                host_key,
            },
            host_port,
        )
        .await;
        assert!(res.is_err());
        Ok(())
    }
}

#[cfg(all(test, docker_test, throughput_test))]
mod e2e {
    use std::{future::Future, path::PathBuf, pin::Pin};

    use rand_chacha::rand_core::SeedableRng;
    use russh::keys::Algorithm;

    use crate::{
        proxy::utils::test_utils::{
            config_helper,
            consts::*,
            docker_runner::{
                DockerTestRunner, DockerTestRunnerBuilder, RunAndCleanup,
            },
            docker_utils::{
                alloc_port, clash_process_e2e_throughput, find_clash_rs_binary,
            },
        },
        tests::initialize,
    };

    const SSH_PORT: u16 = 2222;
    const PASSWORD: &str = "123456789";
    const E2E_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB

    fn gen_ssh_key_pair(
        algo: russh::keys::Algorithm,
    ) -> anyhow::Result<(String, String)> {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed(Default::default());
        let ssh_private_key = russh::keys::PrivateKey::random(&mut rng, algo)?;
        let ssh_public_key = ssh_private_key.public_key();
        let ssh_private_key_str = ssh_private_key
            .to_openssh(ssh_key::LineEnding::LF)?
            .to_string();
        let ssh_public_key_str = ssh_public_key.to_openssh()?;
        Ok((ssh_private_key_str, ssh_public_key_str))
    }

    fn copy_dir_recursive<'a>(
        src: &'a std::path::Path,
        dst: &'a std::path::Path,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'a>> {
        Box::pin(async move {
            tokio::fs::create_dir_all(dst).await?;
            let mut entries = tokio::fs::read_dir(src).await?;
            while let Some(entry) = entries.next_entry().await? {
                let src_path = entry.path();
                let dst_path = dst.join(entry.file_name());
                if entry.file_type().await?.is_dir() {
                    copy_dir_recursive(&src_path, &dst_path).await?;
                } else {
                    tokio::fs::copy(&src_path, &dst_path).await?;
                }
            }
            Ok(())
        })
    }

    async fn prepare_ssh_config_dir(
        base_dir: &std::path::Path,
    ) -> anyhow::Result<tempfile::TempDir> {
        let temp_dir = tempfile::tempdir()?;
        let ssh_config_path = base_dir.join("ssh");
        let ssh_config_tmp_path = temp_dir.path().join("ssh");

        copy_dir_recursive(&ssh_config_path, &ssh_config_tmp_path).await?;

        // Container expects sshd_config at /config/sshd/sshd_config
        let source_sshd_config = ssh_config_tmp_path
            .join("ssh_host_keys")
            .join("sshd_config");
        let target_sshd_dir = ssh_config_tmp_path.join("sshd");
        tokio::fs::create_dir_all(&target_sshd_dir).await?;
        tokio::fs::copy(&source_sshd_config, target_sshd_dir.join("sshd_config"))
            .await?;

        tokio::fs::create_dir_all(&ssh_config_tmp_path.join("logs").join("openssh"))
            .await?;

        // Generate server host key pairs
        let host_key_path = ssh_config_tmp_path.join("ssh_host_keys");
        for (name, algo) in [
            (
                "ecdsa",
                Algorithm::Ecdsa {
                    curve: russh::keys::EcdsaCurve::NistP256,
                },
            ),
            ("ed25519", Algorithm::Ed25519),
        ] {
            let (private_key, public_key) = gen_ssh_key_pair(algo)?;
            tokio::fs::write(
                host_key_path.join(format!("ssh_host_{name}_key")),
                private_key,
            )
            .await?;
            tokio::fs::write(
                host_key_path.join(format!("ssh_host_{name}_key.pub")),
                public_key,
            )
            .await?;
        }

        Ok(temp_dir)
    }

    async fn get_ssh_runner(
        ssh_config_tmp_path: PathBuf,
    ) -> anyhow::Result<DockerTestRunner> {
        let password_env = format!("USER_PASSWORD={}", PASSWORD);
        DockerTestRunnerBuilder::new()
            .image(IMAGE_OPENSSH)
            .env(&[
                "PUID=1000",
                "PGID=1000",
                "TZ=Etc/UTC",
                "SUDO_ACCESS=true",
                "PASSWORD_ACCESS=true",
                &password_env,
            ])
            .no_port()
            .mounts(&[(ssh_config_tmp_path.to_str().unwrap(), "/config")])
            .build()
            .await
    }

    #[tokio::test]
    async fn e2e_throughput_ssh_password() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let test_config_dir = config_helper::test_config_base_dir();
        let temp_dir = prepare_ssh_config_dir(&test_config_dir).await?;
        let ssh_config_tmp_path = temp_dir.path().join("ssh");

        let container = get_ssh_runner(ssh_config_tmp_path).await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("ssh container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = test_config_dir
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: ssh
    server: {server}
    port: {port}
    username: linuxserver.io
    password: "{password}"
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = SSH_PORT,
            password = PASSWORD,
        );
        let binary = find_clash_rs_binary();

        // Keep temp_dir alive until after the test
        let result = container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ssh-password",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await;
        drop(temp_dir);
        result
    }

    #[tokio::test]
    async fn e2e_throughput_ssh_ed25519() -> anyhow::Result<()> {
        initialize();
        let socks_port = alloc_port();
        let echo_port = alloc_port();

        let test_config_dir = config_helper::test_config_base_dir();
        let temp_dir = prepare_ssh_config_dir(&test_config_dir).await?;
        let ssh_config_tmp_path = temp_dir.path().join("ssh");
        let private_key_path = ssh_config_tmp_path
            .join(".ssh")
            .join("test_ed25519")
            .to_str()
            .unwrap()
            .to_owned();

        let container = get_ssh_runner(ssh_config_tmp_path).await?;
        let server = container
            .container_ip()
            .ok_or_else(|| anyhow::anyhow!("ssh container has no IP"))?;
        let gateway_ip = container.docker_gateway_ip();

        let mmdb = test_config_dir
            .join("Country.mmdb")
            .to_str()
            .unwrap()
            .to_owned();
        let config = format!(
            r#"
socks-port: {socks_port}
bind-address: 127.0.0.1
mmdb: "{mmdb}"
mode: global
log-level: error
proxies:
  - name: proxy
    type: ssh
    server: {server}
    port: {port}
    username: linuxserver.io
    private-key: "{private_key_path}"
rules:
  - MATCH,proxy
"#,
            socks_port = socks_port,
            mmdb = mmdb,
            server = server,
            port = SSH_PORT,
            private_key_path = private_key_path,
        );
        let binary = find_clash_rs_binary();

        // Keep temp_dir alive until after the test
        let result = container
            .run_and_cleanup(async move {
                clash_process_e2e_throughput(
                    &binary,
                    &config,
                    "ssh-ed25519",
                    socks_port,
                    echo_port,
                    gateway_ip,
                    E2E_PAYLOAD_BYTES,
                )
                .await
                .map(|_| ())
            })
            .await;
        drop(temp_dir);
        result
    }
}

impl crate::proxy::ProxyStream for ChannelStreamWrapper {}
