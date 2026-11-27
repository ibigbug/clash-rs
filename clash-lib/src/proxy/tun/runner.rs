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
//! stops the runner. Per-connection tasks they spawned (TCP streams, UDP
//! forwarding) are not joined or cancelled here; they run until their own
//! I/O ends.

use std::{
    sync::Arc,
    task::{Context, Poll},
};

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
///
/// Packets already queued are written as one batch: each is handed to the
/// sink once it is ready, then the batch is flushed once. With TUN offload
/// (Linux) the flush coalesces segments of the same flow into one write, so
/// the receiving app is woken once per batch instead of once per packet;
/// otherwise it is the same packets written back to back.
async fn stack_to_tun(
    from_stack: impl Stream<Item = std::io::Result<watfaq_netstack::Packet>> + Unpin,
    mut to_tun: impl Sink<Bytes, Error = std::io::Error> + Unpin,
) -> Error {
    /// Matches tun-rs's offload batch size, so a batch never forces a flush
    /// part-way through.
    const BATCH: usize = 128;

    let mut batches = from_stack.ready_chunks(BATCH);
    while let Some(batch) = batches.next().await {
        let mut stack_err = None;
        let mut res = Ok(());
        for pkt in batch {
            let pkt = match pkt {
                Ok(pkt) => pkt.into_bytes(),
                Err(e) => {
                    stack_err = Some(e);
                    break;
                }
            };
            // Nothing to write; with offload an empty packet would make the
            // coalescing step fail the whole flush.
            if pkt.is_empty() {
                continue;
            }
            // Take the packet only once the sink is ready, so a backpressure
            // error while it drains an earlier packet never costs this one.
            res = retry_on_backpressure(&mut to_tun, |s, cx| s.poll_ready_unpin(cx))
                .await
                .and_then(|()| to_tun.start_send_unpin(pkt));
            if res.is_err() {
                break;
            }
        }
        // Flush even after a stack error, so the packets already taken are
        // written; keep going past backpressure so none is left parked in
        // the sink waiting for the next batch.
        if res.is_ok() {
            res = retry_on_backpressure(&mut to_tun, |s, cx| s.poll_flush_unpin(cx))
                .await;
        }
        if let Err(e) = res {
            error!("failed to send pkt to tun: {}", e);
            break;
        }
        if let Some(e) = stack_err {
            error!("tun stack error: {}", e);
            break;
        }
    }
    stopped("netstack -> tun")
}

/// TUN -> netstack. Runs until the device or the stack fails.
async fn tun_to_stack(
    mut from_tun: impl Stream<Item = std::io::Result<bytes::BytesMut>> + Unpin,
    mut to_stack: impl Sink<watfaq_netstack::Packet, Error = std::io::Error> + Unpin,
) -> Error {
    /// With offload a single read can fail on its own (a malformed or
    /// oversized packet tun-rs cannot split); the next read starts clean, so
    /// skip it. Only a run of failures means the device itself is gone.
    const MAX_CONSECUTIVE_READ_ERRORS: u32 = 64;

    let mut read_errors = 0;
    while let Some(pkt) = from_tun.next().await {
        let pkt = match pkt {
            Ok(pkt) => {
                read_errors = 0;
                pkt
            }
            Err(e) => {
                read_errors += 1;
                if read_errors >= MAX_CONSECUTIVE_READ_ERRORS {
                    error!("tun stream error: {}", e);
                    break;
                }
                warn!("tun read failed, skipping packet: {}", e);
                continue;
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

/// Drive a sink operation (readiness or flush) past TUN backpressure.
///
/// Only the Windows drivers (Wintun, TAP) report it: a write that found the
/// send buffer full for too long returns TimedOut after the device gave up on
/// (dropped) that packet and moved on, so every retry makes progress and the
/// loop ends once the buffered packets are drained. On Unix the async fd turns
/// a full buffer into `Pending` and this is a plain poll.
async fn retry_on_backpressure<S>(
    sink: &mut S,
    mut op: impl FnMut(&mut S, &mut Context<'_>) -> Poll<std::io::Result<()>>,
) -> std::io::Result<()> {
    loop {
        match std::future::poll_fn(|cx| op(&mut *sink, cx)).await {
            Err(e) if is_tun_backpressure(&e) => {
                warn!("tun send buffer full, dropping packet: {}", e);
            }
            res => return res,
        }
    }
}

/// TimedOut/WouldBlock from a TUN write mean the driver's send buffer stayed
/// full: the packet was dropped, the device is fine.
fn is_tun_backpressure(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}
