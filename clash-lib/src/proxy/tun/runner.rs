//! TUN inbound: moves IP packets between the TUN device and the userspace
//! netstack, and hands the netstack's TCP connections and UDP packets to the
//! dispatcher.
//!
//! ```text
//!            stack_to_tun                    accept_tcp ──► dispatcher
//!   TUN  ◄──────────────────  netstack  ──►
//!        ──────────────────►             ──► handle_inbound_datagram
//!            tun_to_stack
//! ```
//!
//! All four loops run in one task; whichever ends first (or cancellation)
//! stops the runner.

use std::sync::Arc;

use bytes::Bytes;
use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt, future::BoxFuture};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    Error,
    app::{
        dispatcher::Dispatcher, dns::ThreadSafeDNSResolver, net::OutboundInterface,
    },
    config::config::TunConfig,
    proxy::tun::{
        datagram::handle_inbound_datagram, device::open_device, routes,
        stream::handle_inbound_stream,
    },
    runner::Runner,
};

pub struct TunRunner {
    cfg: TunConfig,
    default_interface: Option<OutboundInterface>,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    cancellation_token: CancellationToken,
}

impl TunRunner {
    pub fn new(
        cfg: TunConfig,
        default_interface: Option<OutboundInterface>,
        dispatcher: Arc<Dispatcher>,
        resolver: ThreadSafeDNSResolver,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<TunRunner, Error> {
        Ok(Self {
            cfg,
            default_interface,
            dispatcher,
            resolver,
            cancellation_token: cancellation_token.unwrap_or_default(),
        })
    }
}

impl Runner for TunRunner {
    fn run_async(&self) {
        if !self.cfg.enable {
            info!("tun is disabled, skipping");
            return;
        }

        tokio::spawn(run(
            self.cfg.clone(),
            self.default_interface.clone(),
            self.dispatcher.clone(),
            self.resolver.clone(),
            self.cancellation_token.clone(),
        ));
    }

    fn shutdown(&self) {
        info!("shutting down tun runner");
        if let Err(e) = routes::maybe_routes_clean_up(&self.cfg) {
            error!("failed to clean up routes: {}", e);
        }
        self.cancellation_token.cancel();
    }

    fn join(&self) -> BoxFuture<'_, Result<(), Error>> {
        async move { Ok(()) }.boxed()
    }
}

async fn run(
    cfg: TunConfig,
    default_interface: Option<OutboundInterface>,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
    cancellation_token: CancellationToken,
) -> Result<(), Error> {
    let device = open_device(&cfg).await.inspect_err(log_init_error)?;
    let (stack, tcp_listener, udp_socket) = watfaq_netstack::NetStack::new();

    let framed = tun_rs::async_framed::DeviceFramed::new(
        device,
        tun_rs::async_framed::BytesCodec::new(),
    );
    let (tun_sink, tun_stream) = framed.split::<Bytes>();
    let (stack_sink, stack_stream) = stack.split();

    let res = tokio::select! {
        e = stack_to_tun(stack_stream, tun_sink) => Err(e),
        e = tun_to_stack(tun_stream, stack_sink) => Err(e),
        e = accept_tcp(
            tcp_listener,
            dispatcher.clone(),
            default_interface.clone(),
            cfg.so_mark,
        ) => Err(e),
        () = handle_inbound_datagram(
            udp_socket,
            dispatcher,
            resolver,
            default_interface,
            cfg.so_mark,
            cfg.dns_hijack,
        ) => Err(stopped("UDP handler")),
        () = cancellation_token.cancelled() => {
            info!("tun stop signal received");
            Ok(())
        }
    };

    match &res {
        Ok(()) => info!("tun runner exited"),
        Err(e) => error!("tun runner error: {}", e),
    }
    res
}

fn log_init_error(e: &Error) {
    match e {
        Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => error!(
            "tun initialization failed: permission denied. Please make sure the \
             program has the necessary permissions to create and manage TUN \
             interfaces."
        ),
        Error::Io(e) => error!("tun initialization I/O error: {}", e),
        e => error!("tun initialization error: {}", e),
    }
}

fn stopped(what: &str) -> Error {
    Error::Operation(format!("tun stopped unexpectedly: {what} ended"))
}

/// netstack -> TUN. Runs until the stack or the device fails.
async fn stack_to_tun(
    mut from_stack: impl Stream<Item = std::io::Result<watfaq_netstack::Packet>> + Unpin,
    mut to_tun: impl Sink<Bytes, Error = std::io::Error> + Unpin,
) -> Error {
    while let Some(pkt) = from_stack.next().await {
        let pkt = match pkt {
            Ok(pkt) => pkt,
            Err(e) => {
                error!("tun stack error: {}", e);
                break;
            }
        };
        match to_tun.send(pkt.into_bytes()).await {
            Ok(()) => {}
            // Packet loss is normal at the IP layer: TCP retransmits and UDP
            // is best-effort, so drop the packet and keep going.
            Err(e) if is_tun_backpressure(&e) => {
                warn!("tun send buffer full, dropping packet: {}", e);
            }
            Err(e) => {
                error!("failed to send pkt to tun: {}", e);
                break;
            }
        }
    }
    stopped("netstack -> tun")
}

/// TUN -> netstack. Runs until the device or the stack fails.
async fn tun_to_stack(
    mut from_tun: impl Stream<Item = std::io::Result<bytes::BytesMut>> + Unpin,
    mut to_stack: impl Sink<watfaq_netstack::Packet, Error = std::io::Error> + Unpin,
) -> Error {
    while let Some(pkt) = from_tun.next().await {
        let pkt = match pkt {
            Ok(pkt) => pkt,
            Err(e) => {
                error!("tun stream error: {}", e);
                break;
            }
        };
        if let Err(e) = to_stack.send(watfaq_netstack::Packet::new(pkt)).await {
            error!("failed to send pkt to stack: {}", e);
            break;
        }
    }
    stopped("tun -> netstack")
}

/// Hands every TCP connection the netstack accepts to the dispatcher.
async fn accept_tcp(
    mut listener: watfaq_netstack::TcpListener,
    dispatcher: Arc<Dispatcher>,
    default_interface: Option<OutboundInterface>,
    so_mark: Option<crate::app::net::SocketMark>,
) -> Error {
    while let Some(stream) = listener.next().await {
        debug!(
            "new tun TCP connection: {} -> {}",
            stream.local_addr(),
            stream.remote_addr()
        );
        tokio::spawn(handle_inbound_stream(
            stream,
            dispatcher.clone(),
            default_interface.clone(),
            so_mark,
        ));
    }
    stopped("TCP listener")
}

/// TimedOut/WouldBlock from a TUN write mean the driver's send buffer stayed
/// full (Wintun ring backpressure): the packet was dropped, the device is fine.
fn is_tun_backpressure(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}
