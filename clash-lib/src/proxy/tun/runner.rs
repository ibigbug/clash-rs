use std::sync::Arc;

use futures::{FutureExt, SinkExt, StreamExt, future::BoxFuture};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::{
    Error,
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::config::TunConfig,
    proxy::tun::{
        datagram::handle_inbound_datagram, routes, stream::handle_inbound_stream,
    },
    runner::Runner,
};

/// Maximum number of attempts to wait for a newly created TUN interface to
/// become visible via NetworkInterface::show().
const TUN_VISIBILITY_MAX_ATTEMPTS: u32 = 40;
/// Interval in milliseconds between each visibility poll attempt.
const TUN_VISIBILITY_POLL_INTERVAL_MS: u64 = 50;

#[derive(Default)]
struct TunInitializationConfig {
    fd: Option<u32>,
    tun_name: Option<String>,
    #[cfg(target_os = "windows")]
    guid: Option<u128>,
}

pub struct TunRunner {
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    cancellation_token: CancellationToken,
}

impl TunRunner {
    pub fn new(
        cfg: TunConfig,
        dispatcher: Arc<Dispatcher>,
        resolver: ThreadSafeDNSResolver,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<TunRunner, Error> {
        Ok(Self {
            cfg,
            dispatcher,
            resolver,
            cancellation_token: cancellation_token.unwrap_or_default(),
        })
    }

    async fn new_internal(
        cfg: &TunConfig,
    ) -> Result<
        (
            tun_rs::AsyncDevice,
            watfaq_netstack::NetStack,
            watfaq_netstack::TcpListener,
            watfaq_netstack::UdpSocket,
        ),
        Error,
    > {
        let mut tun_init_config = TunInitializationConfig::default();
        match Url::parse(&cfg.device_id) {
            Ok(u) => match u.scheme() {
                "fd" => {
                    let fd = u
                        .host()
                        .expect("tun fd must be provided")
                        .to_string()
                        .parse()
                        .map_err(|x| Error::InvalidConfig(format!("tun fd {x}")))?;
                    tun_init_config.fd = Some(fd);
                }
                "dev" => {
                    let dev =
                        u.host().expect("tun dev must be provided").to_string();
                    if cfg!(target_os = "macos") && !dev.starts_with("utun") {
                        return Err(Error::InvalidConfig(format!(
                            "invalid device id: {}. tun name must be utunX",
                            cfg.device_id
                        )));
                    }
                    tun_init_config.tun_name = Some(dev);
                    #[cfg(target_os = "windows")]
                    {
                        let guid = u.query_pairs().find(|(k, _)| k == "guid");
                        if let Some((_, v)) = guid {
                            let guid = uuid::Uuid::parse_str(&v).map_err(|x| {
                                Error::InvalidConfig(format!("invalid guid: {x}"))
                            })?;
                            tun_init_config.guid = Some(guid.as_u128());
                        }
                    }
                }
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}",
                        cfg.device_id
                    )));
                }
            },
            Err(_) => {
                if cfg!(target_os = "macos") && !&cfg.device_id.starts_with("utun") {
                    return Err(Error::InvalidConfig(format!(
                        "invalid device id: {}. tun name must be utunX",
                        cfg.device_id
                    )));
                }
                tun_init_config.tun_name = Some(cfg.device_id.clone());
            }
        };

        let tun =
            if let Some(fd) = tun_init_config.fd {
                #[cfg(target_family = "unix")]
                {
                    info!("tun started with fd {}", fd);
                    unsafe { tun_rs::AsyncDevice::from_fd(fd as _)? }
                }

                #[cfg(not(target_family = "unix"))]
                {
                    return Err(Error::InvalidConfig(format!(
                        "tun fd({fd}) is only supported on Unix-like systems"
                    )));
                }
            } else {
                #[cfg(not(any(target_os = "ios", target_os = "android")))]
                {
                    use crate::proxy::tun::routes::maybe_add_routes;
                    use network_interface::NetworkInterfaceConfig;
                    use tun_rs::DeviceBuilder;

                    let tun_name =
                        tun_init_config.tun_name.expect("tun name must be provided");
                    let tun_exist = network_interface::NetworkInterface::show()
                        .map(|ifs| ifs.into_iter().any(|x| x.name == tun_name))
                        .unwrap_or_default();

                    if tun_exist {
                        info!("tun device {} already exists, using it.", &tun_name);
                    } else {
                        info!("tun device {} does not exist, creating.", &tun_name);
                    }

                    let mut tun_builder = DeviceBuilder::new();
                    tun_builder =
                        tun_builder.name(&tun_name).mtu(cfg.mtu.unwrap_or(
                            if cfg!(windows) { 65535u16 } else { 1500u16 },
                        ));

                    if !tun_exist {
                        debug!("setting tun ipv4 addr: {:?}", cfg.gateway);
                        tun_builder = tun_builder.ipv4(
                            cfg.gateway.addr(),
                            cfg.gateway.netmask(),
                            None,
                        );

                        if let Some(gateway_v6) = cfg.gateway_v6 {
                            debug!("setting tun ipv6 addr: {:?}", cfg.gateway_v6);
                            tun_builder = tun_builder
                                .ipv6(gateway_v6.addr(), gateway_v6.netmask());
                        }
                    }
                    #[cfg(target_os = "windows")]
                    {
                        // Use the explicitly configured GUID, or derive a
                        // deterministic one from the device name so that the
                        // same adapter is reused across restarts instead of
                        // creating a new one every time.
                        let guid = tun_init_config.guid.unwrap_or_else(|| {
                            uuid::Uuid::new_v5(
                                &uuid::Uuid::NAMESPACE_DNS,
                                tun_name.as_bytes(),
                            )
                            .as_u128()
                        });
                        tun_builder = tun_builder.device_guid(guid);
                    }

                    // FreeBSD materialises `/dev/<tun_name>` only while the
                    // network interface exists. tun-rs opens that node directly
                    // without creating the interface, so pre-create it here to
                    // avoid `open("/dev/tun0") -> ENOENT` on a fresh host.
                    #[cfg(target_os = "freebsd")]
                    let created_tun = if !tun_exist {
                        routes::ensure_tun_device(&tun_name)?;
                        true
                    } else {
                        false
                    };
                    #[cfg(not(target_os = "freebsd"))]
                    let created_tun = false;

                    let dev = match tun_builder.build_async() {
                        Ok(dev) => dev,
                        Err(e) => {
                            // If we pre-created the tun device on FreeBSD but
                            // build_async() fails, destroy the interface so we
                            // don't leave a dangling tun device behind.
                            if created_tun {
                                #[cfg(target_os = "freebsd")]
                                {
                                    let _ = std::process::Command::new("ifconfig")
                                        .arg(&tun_name)
                                        .arg("destroy")
                                        .output();
                                }
                            }
                            return Err(e.into());
                        }
                    };

                    if !tun_exist {
                        // After build_async(), the new TUN interface may not be
                        // immediately visible via NetworkInterface::show().
                        // Poll up to TUN_VISIBILITY_MAX_ATTEMPTS times (≈2 s)
                        // before setting up routes, but never sleep after the
                        // final check.
                        let mut tun_visible = false;
                        let mut last_show_err: Option<String> = None;
                        let mut attempt = 0u32;
                        loop {
                            match network_interface::NetworkInterface::show() {
                                Ok(ifs) => {
                                    if ifs.into_iter().any(|x| x.name == tun_name) {
                                        tun_visible = true;
                                        break;
                                    }
                                }
                                Err(e) => {
                                    last_show_err = Some(e.to_string());
                                }
                            }
                            attempt += 1;
                            if attempt >= TUN_VISIBILITY_MAX_ATTEMPTS {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(
                                TUN_VISIBILITY_POLL_INTERVAL_MS,
                            ))
                            .await;
                        }

                        if !tun_visible {
                            #[cfg(target_os = "freebsd")]
                            if created_tun {
                                let _ = std::process::Command::new("ifconfig")
                                    .arg(&tun_name)
                                    .arg("destroy")
                                    .output();
                            }
                            let total_ms = TUN_VISIBILITY_MAX_ATTEMPTS as u64
                                * TUN_VISIBILITY_POLL_INTERVAL_MS;
                            let err_msg = match last_show_err {
                                Some(e) => format!(
                                    "tun device {} not visible after waiting {}ms \
                                     (last error: {})",
                                    tun_name, total_ms, e
                                ),
                                None => format!(
                                    "tun device {} not visible after waiting {}ms",
                                    tun_name, total_ms
                                ),
                            };
                            return Err(Error::Operation(err_msg));
                        }

                        info!("setting up routes for tun {}", &tun_name);
                        if let Err(e) = maybe_add_routes(cfg, &tun_name) {
                            #[cfg(target_os = "freebsd")]
                            if created_tun {
                                let _ = std::process::Command::new("ifconfig")
                                    .arg(&tun_name)
                                    .arg("destroy")
                                    .output();
                            }
                            return Err(e.into());
                        }
                    } else {
                        info!("skipping route setup for existing tun {}", &tun_name);
                    }

                    dev
                }
                #[cfg(any(target_os = "ios", target_os = "android"))]
                {
                    return Err(Error::InvalidConfig(
                        "only fd is supported on mobile platforms".to_string(),
                    ));
                }
            };

        let (stack, tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();
        Ok((tun, stack, tcp_listener, udp_socket))
    }
}

impl Runner for TunRunner {
    fn run_async(&self) {
        if !self.cfg.enable {
            info!("tun is disabled, skipping");
            return;
        }

        let cfg = self.cfg.clone();
        let so_mark = self.cfg.so_mark;
        let dispatcher = self.dispatcher.clone();
        let resolver = self.resolver.clone();
        let dns_hijack = self.cfg.dns_hijack;
        let cancellation_token = self.cancellation_token.clone();

        tokio::spawn(async move {
            let (tun, stack, mut tcp_listener, udp_socket) =
                TunRunner::new_internal(&cfg)
                    .await
                    .inspect_err(|e| match e {
                        Error::Io(e) => {
                            if e.kind() == std::io::ErrorKind::PermissionDenied {
                                error!(
                                    "tun initialization failed: permission denied. \
                                     Please make sure the program has the \
                                     necessary permissions to create and manage \
                                     TUN interfaces."
                                );
                            } else {
                                error!("tun initialization I/O error: {}", e);
                            }
                        }
                        _ => {
                            error!("tun initialization error: {}", e);
                        }
                    })?;

            let framed = tun_rs::async_framed::DeviceFramed::new(
                tun,
                tun_rs::async_framed::BytesCodec::new(),
            );

            let (mut tun_sink, mut tun_stream) = framed.split::<bytes::Bytes>();
            let (mut stack_sink, mut stack_stream) = stack.split();

            // dispatcher -> stack -> tun
            let mut fut_dispatcher_tun = async || {
                while let Some(pkt) = stack_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = tun_sink.send(pkt.into_bytes()).await {
                                // TimedOut means the Wintun/TUN send ring
                                // buffer
                                // was full for too long (driver backpressure).
                                // Drop
                                // the packet and keep the runner alive — packet
                                // loss
                                // is normal at the IP layer; TCP will
                                // retransmit and
                                // UDP is inherently best-effort.
                                if e.kind() == std::io::ErrorKind::TimedOut
                                    || e.kind() == std::io::ErrorKind::WouldBlock
                                {
                                    warn!(
                                        "tun send buffer full, dropping packet: {}",
                                        e
                                    );
                                    continue;
                                }
                                error!("failed to send pkt to tun: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stack error: {}", e);
                            break;
                        }
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 0".to_string()))
            };

            // tun -> stack -> dispatcher
            let mut fut_tun_dispatcher = async || {
                while let Some(pkt) = tun_stream.next().await {
                    match pkt {
                        Ok(pkt) => {
                            if let Err(e) = stack_sink
                                .send(watfaq_netstack::Packet::new(pkt))
                                .await
                            {
                                error!("failed to send pkt to stack: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("tun stream error: {}", e);
                            break;
                        }
                    }
                }

                Err(Error::Operation("tun stopped unexpectedly 1".to_string()))
            };

            let dsp = dispatcher.clone();
            let mut fut_tcp_dispatch = async || {
                while let Some(stream) = tcp_listener.next().await {
                    debug!(
                        "new tun TCP connection: {} -> {}",
                        stream.local_addr(),
                        stream.remote_addr()
                    );

                    tokio::spawn(handle_inbound_stream(
                        stream,
                        dsp.clone(),
                        so_mark,
                    ));
                }

                Err(Error::Operation("tun stopped unexpectedly 2".to_string()))
            };
            let fut_udp_dispatch = async || {
                handle_inbound_datagram(
                    udp_socket,
                    dispatcher.clone(),
                    resolver.clone(),
                    so_mark,
                    dns_hijack,
                )
                .await;
                Err(Error::Operation("tun stopped unexpectedly 3".to_string()))
            };

            match tokio::select! {
                res = fut_dispatcher_tun() => res,
                res = fut_tun_dispatcher() => res,
                res = fut_tcp_dispatch() => res,
                res = fut_udp_dispatch() => res,
                _ = cancellation_token.cancelled() => {
                    info!("tun stop signal received");
                    Ok(())
                },
            } {
                Ok(_) => {
                    info!("tun runner exited");
                    Ok(())
                }
                Err(e) => {
                    error!("tun runner error: {}", e);
                    Err(e)
                }
            }
        });
    }

    fn shutdown(&self) {
        info!("shutting down tun runner");
        match routes::maybe_routes_clean_up(&self.cfg) {
            Ok(_) => {}
            Err(e) => {
                error!("failed to clean up routes: {}", e);
            }
        }
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), Error>> {
        async move { Ok(()) }.boxed()
    }
}
