use crate::{
    app::{
        dns::ClashResolver,
        net::get_interface_by_name,
        outbound::manager::ThreadSafeOutboundManager,
        router::{ArcRouter, RuleEntry},
    },
    common::io::copy_bidirectional,
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{
        AnyInboundDatagram, AnyOutboundHandler, OutboundHandler, ProxyStream,
        datagram::{UdpPacket, is_sink_closed},
        utils::ToCanonical,
    },
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, sync::RwLock, task::JoinHandle};
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};

use crate::app::dns::ThreadSafeDNSResolver;

use super::statistics_manager::Manager;

// SS2022 (AEAD-2022) MAX_PACKET_SIZE is 0xFFFF (65535 bytes). Using a relay
// buffer smaller than that forces the cipher to split every full packet into
// multiple smaller encrypted chunks, multiplying encrypt/decrypt overhead.
// Classic AEAD ciphers cap at 0x3FFF (16383 bytes) so they are unaffected.
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

pub struct Dispatcher {
    outbound_manager: ThreadSafeOutboundManager,
    router: ArcRouter,
    resolver: ThreadSafeDNSResolver,
    mode: Arc<RwLock<RunMode>>,
    manager: Arc<Manager>,
    tcp_buffer_size: usize,
}

impl Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

impl Dispatcher {
    pub fn new(
        outbound_manager: ThreadSafeOutboundManager,
        router: ArcRouter,
        resolver: ThreadSafeDNSResolver,
        mode: RunMode,
        statistics_manager: Arc<Manager>,
        tcp_buffer_size: Option<usize>,
    ) -> Self {
        Self {
            outbound_manager,
            router,
            resolver,
            mode: Arc::new(RwLock::new(mode)),
            manager: statistics_manager,
            tcp_buffer_size: tcp_buffer_size.unwrap_or(DEFAULT_BUFFER_SIZE),
        }
    }

    pub async fn set_mode(&self, mode: RunMode) {
        info!("run mode switched to {}", mode);

        *self.mode.write().await = mode;
    }

    pub async fn get_mode(&self) -> RunMode {
        *self.mode.read().await
    }

    #[instrument(skip(self, sess, lhs))]
    pub async fn dispatch_stream(&self, sess: Session, lhs: Box<dyn ProxyStream>) {
        self.dispatch_stream_to(sess, lhs, None).await;
    }

    pub(crate) async fn dispatch_stream_to(
        &self,
        mut sess: Session,
        mut lhs: Box<dyn ProxyStream>,
        proxy: Option<&str>,
    ) {
        let dest: SocksAddr =
            match reverse_lookup(&self.resolver, &sess.destination).await {
                Some(dest) => dest,
                None => {
                    warn!("failed to resolve destination {}", sess);
                    return;
                }
            };

        sess.destination = dest.clone();

        let mode = *self.mode.read().await;
        let Some((outbound_name, handler, rule)) = select_outbound(
            &mut sess,
            mode,
            &self.router,
            &self.outbound_manager,
            proxy,
        )
        .await
        else {
            return;
        };

        match handler
            .connect_stream(&sess, self.resolver.clone())
            .instrument(info_span!("connect_stream", outbound_name = outbound_name,))
            .await
        {
            Ok(mut rhs) => {
                debug!("remote connection established {}", sess);
                rhs.install_tracking(
                    self.manager.clone(),
                    sess.clone(),
                    rule.map(|r| r.matcher()),
                )
                .await;
                match copy_bidirectional(
                    lhs,
                    rhs,
                    self.tcp_buffer_size,
                    Duration::from_secs(10),
                    Duration::from_secs(10),
                )
                .instrument(info_span!(
                    "copy_bidirectional",
                    outbound_name = outbound_name,
                ))
                .await
                {
                    Ok((up, down)) => {
                        debug!(
                            "connection {} closed with {} bytes up, {} bytes down",
                            sess, up, down
                        );
                    }
                    Err(err) => match err {
                        crate::common::io::CopyBidirectionalError::LeftClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by local",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::RightClosed(
                            err,
                        ) => match err.kind() {
                            std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe => {
                                debug!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                            _ => {
                                warn!(
                                    "connection {} closed with error {} by remote",
                                    sess, err
                                );
                            }
                        },
                        crate::common::io::CopyBidirectionalError::Other(err) => {
                            match err.kind() {
                                std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe => {
                                    debug!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                                _ => {
                                    warn!(
                                        "connection {} closed with error {}",
                                        sess, err
                                    );
                                }
                            }
                        }
                    },
                }
            }
            Err(err) => {
                warn!(
                    "failed to establish remote connection {}, error: {}",
                    sess, err
                );
                if let Err(e) = lhs.shutdown().await {
                    warn!("error closing local connection {}: {}", sess, e)
                }
            }
        }
    }

    /// Dispatch a UDP packet to outbound handler
    /// returns the close sender
    #[instrument]
    #[must_use]
    pub async fn dispatch_datagram(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
    ) -> tokio::sync::oneshot::Sender<u8> {
        let forwarding = self.datagram_session(sess, udp_inbound, None);
        let (close_sender, close_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::pin!(forwarding);
            tokio::select! {
                () = &mut forwarding => {},
                signal = close_receiver => {
                    if signal.is_err() { forwarding.await; }
                }
            }
        });
        close_sender
    }

    pub(crate) fn datagram_session(
        &self,
        sess: Session,
        udp_inbound: AnyInboundDatagram,
        proxy: Option<String>,
    ) -> impl Future<Output = ()> + Send + use<> {
        let outbound_handle_guard = TimeoutUdpSessionManager::new();

        let router = self.router.clone();
        let outbound_manager = self.outbound_manager.clone();
        let resolver = self.resolver.clone();
        let mode = self.mode.clone();
        let manager = self.manager.clone();

        #[rustfmt::skip]
        /*
         *  implement details
         *
         *  data structure:
         *    local_r, local_w: stream/sink pair
         *    remote_r, remote_w: stream/sink pair
         *    remote_receiver_r, remote_receiver_w: channel pair
         *    remote_sender, remote_forwarder: channel pair
         *
         *  data flow:
         *    => local_r => init packet => connect_datagram => remote_sender     => remote_forwarder         => remote_w
         *    => local_w                                    <= remote_receiver_r <= NAT + remote_receiver_w  <= remote_r
         *
         *  notice:
         *    the NAT is binded to the session in the dispatch_datagram function arg and the closure
         *    so we need not to add a global NAT table and do the translation
         */
        let (mut local_w, mut local_r) = udp_inbound.split();
        let (remote_receiver_w, mut remote_receiver_r) =
            tokio::sync::mpsc::channel(256);

        let reply_session = sess.clone();
        let forward = async move {
            while let Some(mut packet) = local_r.next().await {
                let mut sess = sess.clone();

                // Canonicalize IPv4-mapped IPv6 addresses (e.g. SS2022 on a
                // dual-stack socket produces ::ffff:x.x.x.x); without this
                // new_udp_socket picks AF_INET6 with bind_addr 0.0.0.0 →
                // EINVAL.
                if let crate::session::SocksAddr::Ip(addr) = &mut packet.dst_addr {
                    *addr = addr.to_canonical();
                    sess.resolved_ip = Some(addr.ip());
                }

                let dest = match reverse_lookup(&resolver, &packet.dst_addr).await {
                    Some(dest) => dest,
                    None => {
                        warn!("failed to resolve destination {}", sess);
                        continue;
                    }
                };

                // Canonicalize IPv4-mapped IPv6 source addresses (e.g. a
                // client connecting via IPv4 on a dual-stack inbound socket
                // appears as ::ffff:x.x.x.x).  Without canonicalization,
                // direct/mod.rs sees sess.source.is_ipv4() == false and picks
                // bind_addr=:: while family_hint picks AF_INET for the
                // destination — binding an AF_INET socket to [::]:0 fails with
                // EAFNOSUPPORT (os error 97), silently dropping all UDP
                // replies.
                sess.source = packet
                    .src_addr
                    .clone()
                    .must_into_socket_addr()
                    .to_canonical();
                sess.destination = dest.clone();
                sess.inbound_user = packet.inbound_user.clone();

                let mode = *mode.read().await;

                let Some((outbound_name, handler, rule)) = select_outbound(
                    &mut sess,
                    mode,
                    &router,
                    &outbound_manager,
                    proxy.as_deref(),
                )
                .await
                else {
                    continue;
                };
                let remote_receiver_w = remote_receiver_w.clone();

                let active_proxy =
                    if let Some(group) = handler.try_as_group_handler() {
                        group.get_active_proxy().await
                    } else {
                        None
                    };
                let key = OutboundHandleKey {
                    outbound_name,
                    src_addr: packet.src_addr.clone().must_into_socket_addr(),
                };
                let handlers =
                    UdpSessionHandlers::new(&handler, active_proxy.as_ref());

                match outbound_handle_guard
                    .get_outbound_sender_mut(&key, &handlers)
                    .await
                {
                    None => {
                        debug!("building {} outbound datagram connecting", sess);
                        let mut outbound_datagram = match handler
                            .connect_datagram(&sess, resolver.clone())
                            .await
                        {
                            Ok(v) => v,
                            Err(err) => {
                                error!("failed to connect outbound: {}", err);
                                continue;
                            }
                        };

                        debug!("{} outbound datagram connected", sess);

                        outbound_datagram
                            .install_tracking(
                                manager.clone(),
                                sess.clone(),
                                rule.map(|r| r.matcher()),
                            )
                            .await;

                        let (remote_w, remote_r) = outbound_datagram.split();
                        let (remote_sender, remote_forwarder) =
                            tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(
                                256,
                            );

                        let rw_handle = tokio::spawn(relay_udp_session(
                            remote_w,
                            remote_r,
                            remote_forwarder,
                            remote_receiver_w,
                            sess,
                        ));

                        outbound_handle_guard
                            .insert(key, handlers, rw_handle, remote_sender.clone())
                            .await;

                        match remote_sender.send((packet, dest)).await {
                            Ok(_) => {}
                            Err(err) => {
                                error!("failed to send packet to remote: {}", err);
                            }
                        };
                    }
                    Some(sender) => match sender.send((packet, dest)).await {
                        Ok(_) => {
                            debug!("reusing {} sent to remote", sess);
                        }
                        Err(err) => {
                            error!("failed to send packet to remote: {}", err);
                        }
                    },
                };
            }

            trace!("UDP session local -> remote finished for {}", sess);
        };

        let replies = async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                match local_w.send(packet).await {
                    Ok(_) => {}
                    Err(err) if is_sink_closed(&err) => {
                        warn!(
                            "local udp sink closed for {}: {}",
                            reply_session, err
                        );
                        break;
                    }
                    Err(err) => {
                        error!("failed to send packet to local: {}", err);
                    }
                }
            }
            trace!("UDP session remote -> local finished for {}", reply_session);
        };
        async move {
            tokio::join!(forward, replies);
        }
    }
}

async fn select_outbound<'a>(
    sess: &mut Session,
    mode: RunMode,
    router: &'a ArcRouter,
    mgr: &ThreadSafeOutboundManager,
    proxy: Option<&str>,
) -> Option<(String, AnyOutboundHandler, Option<&'a RuleEntry>)> {
    let (outbound_name, rule) = match (proxy, mode) {
        (Some(name), _) => (name, None),
        (None, RunMode::Global) => (PROXY_GLOBAL, None),
        (None, RunMode::Rule) => router.match_route(sess).await,
        (None, RunMode::Direct) => (PROXY_DIRECT, None),
    };

    if let Some(interface) = rule.and_then(|rule| rule.interface()) {
        match get_interface_by_name(interface) {
            Some(iface) => sess.iface = Some(iface),
            None => warn!(
                "rule-selected interface `{}` was not found; using the default \
                 interface",
                interface
            ),
        }
    }
    let outbound_name = outbound_name.to_string();

    debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

    let handler = match mgr.get_outbound(&outbound_name).await {
        Some(h) => h,
        None if proxy.is_some() => {
            warn!("tunnel proxy {outbound_name} is unavailable");
            return None;
        }
        None => {
            debug!("unknown rule: {}, fallback to direct", outbound_name);
            mgr.get_outbound(PROXY_DIRECT).await?
        }
    };

    Some((outbound_name, handler, rule))
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve

/// Per-session relay task: owns orig_map and all dst_addr substitution logic.
/// The local -> remote arm rewrites dst_addr to the logical destination (from
/// reverse_lookup) and saves the original for src_addr restoration. Returns
/// when the outbound stream ends, the session's forwarder is closed, or the
/// outbound sink can never send again.
async fn relay_udp_session<W, R>(
    mut remote_w: W,
    mut remote_r: R,
    mut remote_forwarder: tokio::sync::mpsc::Receiver<(UdpPacket, SocksAddr)>,
    remote_receiver_w: tokio::sync::mpsc::Sender<UdpPacket>,
    sess: Session,
) where
    W: futures::Sink<UdpPacket, Error = std::io::Error> + Unpin + Send + 'static,
    R: futures::Stream<Item = UdpPacket> + Unpin,
{
    // Bound the reverse-mapping table to prevent unbounded memory growth on
    // long-lived sessions with many dests.
    const ORIG_MAP_MAX: usize = 256;
    let mut orig_map: HashMap<SocksAddr, SocksAddr> = HashMap::new();
    // Best-effort fallback for proxy outbounds that do not echo dst_addr as
    // src_addr in responses (e.g. Shadowsocks returns the real upstream IP).
    let mut last_orig_addr: Option<SocksAddr> = None;
    loop {
        tokio::select! {
            // local -> remote
            pkt = remote_forwarder.recv() => {
                let Some((mut packet, dest)) = pkt else { break };
                let orig = packet.dst_addr.clone();
                packet.dst_addr = dest;
                if orig != packet.dst_addr {
                    if orig_map.len() >= ORIG_MAP_MAX
                        && let Some(k) =
                            orig_map.keys().next().cloned()
                    {
                        orig_map.remove(&k);
                    }
                    orig_map.insert(packet.dst_addr.clone(), orig.clone());
                }
                last_orig_addr = Some(orig);
                match remote_w.send(packet).await {
                    Ok(_) => {}
                    // The outbound can never send
                    // again: end the session so the
                    // next packet reconnects instead
                    // of failing here until the NAT
                    // entry times out.
                    Err(err) if is_sink_closed(&err) => {
                        warn!(
                            "outbound udp sink closed, \
                             ending session {sess}: {err}"
                        );
                        break;
                    }
                    Err(err) => {
                        warn!(
                            "failed to send packet to \
                             remote: {err:?}"
                        );
                    }
                }
            }
            // remote -> local
            pkt = remote_r.next() => {
                let Some(mut packet) = pkt else { break };
                if let Some(orig) =
                    orig_map.get(&packet.src_addr).cloned()
                {
                    packet.src_addr = orig;
                } else if !orig_map.is_empty() {
                    // Proxy didn't echo dst_addr as src —
                    // best-effort for single-dest flows.
                    if let Some(ref fallback) = last_orig_addr {
                        packet.src_addr = fallback.clone();
                    }
                }
                packet.dst_addr = sess.source.into();
                debug!(
                    "UDP NAT for packet: {:?}, session: {}",
                    packet, sess
                );
                // The receiver only goes away with the inbound session,
                // so a failed send is final.
                if let Err(err) = remote_receiver_w.send(packet).await {
                    warn!("inbound udp session gone, ending {sess}: {err}");
                    break;
                }
            }
        }
    }
    // Close the sender side first, so the next packet for this flow sees the
    // session as dead and reconnects at once.
    drop(remote_forwarder);
    // Best effort: let stream-based outbounds send FIN / close_notify instead
    // of just dropping the connection. Detached, because the reconnect aborts
    // this task (and would cancel the close with it).
    tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(1), remote_w.close()).await;
    });
}

async fn reverse_lookup(
    resolver: &Arc<dyn ClashResolver>,
    dst: &SocksAddr,
) -> Option<SocksAddr> {
    let dst = match dst {
        crate::session::SocksAddr::Ip(socket_addr) => {
            if resolver.fake_ip_enabled() {
                let ip = socket_addr.ip();
                if resolver.is_fake_ip(ip).await {
                    trace!("looking up fake ip: {}", socket_addr.ip());
                    let host = resolver.reverse_lookup(ip).await;
                    match host {
                        Some(host) => match (host, socket_addr.port()).try_into() {
                            Ok(d) => d,
                            Err(e) => {
                                error!("invalid domain from reverse lookup: {e}");
                                return None;
                            }
                        },
                        None => {
                            error!("failed to reverse lookup fake ip: {}", ip);
                            return None;
                        }
                    }
                } else {
                    (*socket_addr).into()
                }
            } else {
                trace!("looking up resolve cache ip: {}", socket_addr.ip());
                match resolver.cached_for(socket_addr.ip()).await {
                    Some(resolved) => {
                        match (resolved, socket_addr.port()).try_into() {
                            Ok(d) => d,
                            Err(e) => {
                                error!("invalid domain from resolver cache: {e}");
                                return None;
                            }
                        }
                    }
                    _ => (*socket_addr).into(),
                }
            }
        }
        crate::session::SocksAddr::Domain(host, port) => {
            match (host.to_owned(), *port).try_into() {
                Ok(d) => d,
                Err(e) => {
                    error!("invalid domain in SocksAddr: {e}");
                    return None;
                }
            }
        }
    };
    Some(dst)
}

type OutboundPacketSender = tokio::sync::mpsc::Sender<(UdpPacket, SocksAddr)>;

struct TimeoutUdpSessionManager {
    map: Arc<RwLock<OutboundHandleMap>>,

    cleaner: Option<JoinHandle<()>>,
}

impl Drop for TimeoutUdpSessionManager {
    fn drop(&mut self) {
        trace!("dropping timeout udp session manager");
        if let Some(x) = self.cleaner.take() {
            x.abort()
        }
    }
}

impl TimeoutUdpSessionManager {
    fn new() -> Self {
        let map = Arc::new(RwLock::new(OutboundHandleMap::new()));
        let timeout = Duration::from_secs(10);

        let map_cloned = map.clone();

        let cleaner = tokio::spawn(async move {
            trace!("timeout udp session cleaner scanning");
            let mut interval = tokio::time::interval(timeout);

            loop {
                interval.tick().await;
                trace!("timeout udp session cleaner ticking");

                let mut g = map_cloned.write().await;
                let mut alived = 0;
                let mut expired = 0;
                g.0.retain(|k, val| {
                    let now = Instant::now();
                    let alive = now.duration_since(val.last_active) < timeout;
                    if !alive {
                        expired += 1;
                        trace!("udp session expired: {:?}", k);
                        val.rw_handle.abort();
                    } else {
                        alived += 1;
                    }
                    alive
                });
                trace!(
                    "timeout udp session cleaner finished, alived: {}, expired: {}",
                    alived, expired
                );
            }
        });

        Self {
            map,

            cleaner: Some(cleaner),
        }
    }

    async fn insert(
        &self,
        key: OutboundHandleKey,
        handlers: UdpSessionHandlers,
        rw_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        let mut map = self.map.write().await;
        map.insert(key, handlers, rw_handle, sender);
    }

    async fn get_outbound_sender_mut(
        &self,
        key: &OutboundHandleKey,
        handlers: &UdpSessionHandlers,
    ) -> Option<OutboundPacketSender> {
        let mut map = self.map.write().await;
        map.get_outbound_sender_mut(key, handlers)
    }
}

/// Key identifying a unique UDP NAT session.
/// Scoped to (outbound, client source) — one socket per client, full cone NAT.
#[derive(Debug, PartialEq, Eq, Hash)]
struct OutboundHandleKey {
    outbound_name: String,
    src_addr: SocketAddr,
}

// A provider refresh can replace an outbound or a group's active member under
// the same name. Weak references identify those instances without keeping them
// alive.
struct UdpSessionHandlers {
    outbound: Weak<dyn OutboundHandler>,
    active_proxy: Option<Weak<dyn OutboundHandler>>,
}

impl UdpSessionHandlers {
    fn new(
        outbound: &AnyOutboundHandler,
        active_proxy: Option<&AnyOutboundHandler>,
    ) -> Self {
        Self {
            outbound: Arc::downgrade(outbound),
            active_proxy: active_proxy.map(Arc::downgrade),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.outbound.ptr_eq(&other.outbound)
            && match (&self.active_proxy, &other.active_proxy) {
                (Some(a), Some(b)) => a.ptr_eq(b),
                (None, None) => true,
                _ => false,
            }
    }
}

struct OutboundHandleVal {
    handlers: UdpSessionHandlers,
    /// Handles both local→remote and remote→local, owns orig_map.
    rw_handle: JoinHandle<()>,
    sender: OutboundPacketSender,
    last_active: Instant,
}

struct OutboundHandleMap(HashMap<OutboundHandleKey, OutboundHandleVal>);

impl OutboundHandleMap {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn insert(
        &mut self,
        key: OutboundHandleKey,
        handlers: UdpSessionHandlers,
        rw_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        self.0.insert(
            key,
            OutboundHandleVal {
                handlers,
                rw_handle,
                sender,
                last_active: Instant::now(),
            },
        );
    }

    fn get_outbound_sender_mut(
        &mut self,
        key: &OutboundHandleKey,
        handlers: &UdpSessionHandlers,
    ) -> Option<OutboundPacketSender> {
        let val = self.0.get_mut(key)?;
        if !val.sender.is_closed() && val.handlers.matches(handlers) {
            trace!("updating last access time for outbound {key:?}");
            val.last_active = Instant::now();
            return Some(val.sender.clone());
        }
        trace!("evicting stale outbound udp session {key:?}");
        val.rw_handle.abort();
        self.0.remove(key);
        None
    }
}

impl Drop for OutboundHandleMap {
    fn drop(&mut self) {
        trace!(
            "dropping inner outbound handle map that has {} sessions",
            self.0.len()
        );
        for (_, val) in self.0.drain() {
            val.rw_handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    fn udp_key() -> OutboundHandleKey {
        OutboundHandleKey {
            outbound_name: "proxy".to_owned(),
            src_addr: src(),
        }
    }

    fn outbound(name: &str) -> AnyOutboundHandler {
        Arc::new(crate::proxy::direct::Handler::new(name))
    }

    #[tokio::test]
    async fn closed_udp_session_is_evicted_for_reconnect() {
        let mut map = OutboundHandleMap::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(4);
        let handle = tokio::spawn(async {});
        let handler = outbound("proxy");
        let route = || UdpSessionHandlers::new(&handler, None);
        map.insert(udp_key(), route(), handle, tx);

        // Receiver alive: the cached sender is reused.
        assert!(map.get_outbound_sender_mut(&udp_key(), &route()).is_some());

        // Receiver dropped (its rw_handle ended): the entry is evicted so the
        // caller rebuilds the association instead of writing to a dead channel.
        drop(rx);
        assert!(map.get_outbound_sender_mut(&udp_key(), &route()).is_none());
        // The entry is removed, not merely skipped.
        assert!(map.0.is_empty());
    }

    #[tokio::test]
    async fn live_udp_session_tracks_the_active_group_member() {
        let mut map = OutboundHandleMap::new();
        let (tx, _rx) = tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(4);
        let handle = tokio::spawn(async {});
        let group = outbound("group");
        let member = outbound("proxy");
        let route = |member: &AnyOutboundHandler| {
            UdpSessionHandlers::new(&group, Some(member))
        };
        map.insert(udp_key(), route(&member), handle, tx);

        assert!(
            map.get_outbound_sender_mut(&udp_key(), &route(&member))
                .is_some()
        );
        let replacement = outbound("proxy");
        assert!(
            map.get_outbound_sender_mut(&udp_key(), &route(&replacement))
                .is_none()
        );
        assert!(map.0.is_empty());
    }

    /// Sink that fails every send with `err` and counts close calls.
    struct FailingSink {
        closed_marker: bool,
        sends: usize,
        closes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl futures::Sink<UdpPacket> for FailingSink {
        type Error = std::io::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(
            mut self: std::pin::Pin<&mut Self>,
            _: UdpPacket,
        ) -> std::io::Result<()> {
            self.sends += 1;
            let kind = std::io::ErrorKind::ConnectionReset;
            Err(if self.closed_marker {
                crate::proxy::datagram::sink_closed(kind, "stream reset")
            } else {
                std::io::Error::new(kind, "transient")
            })
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.closes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn packet() -> (UdpPacket, SocksAddr) {
        let dst: SocksAddr = "1.1.1.1:53".parse().unwrap();
        (
            UdpPacket::new(b"q".to_vec(), src().into(), dst.clone()),
            dst,
        )
    }

    fn spawn_relay(
        closed_marker: bool,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::Sender<(UdpPacket, SocksAddr)>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = FailingSink {
            closed_marker,
            sends: 0,
            closes: closes.clone(),
        };
        let (fwd_tx, fwd_rx) = tokio::sync::mpsc::channel(4);
        let (local_tx, _local_rx) = tokio::sync::mpsc::channel(4);
        let sess = Session {
            source: src(),
            ..Default::default()
        };
        let handle = tokio::spawn(relay_udp_session(
            sink,
            futures::stream::pending::<UdpPacket>(),
            fwd_rx,
            local_tx,
            sess,
        ));
        (handle, fwd_tx, closes)
    }

    /// A sink that can never send again ends the session, so the next packet
    /// for the flow reconnects instead of failing until the NAT entry times
    /// out.
    #[tokio::test]
    async fn dead_outbound_sink_ends_udp_session() {
        let (handle, fwd_tx, closes) = spawn_relay(true);
        fwd_tx.send(packet()).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("session must end once the outbound sink is dead")
            .unwrap();
        assert!(
            fwd_tx.is_closed(),
            "dispatcher must see the session as dead"
        );
        // The close runs detached; give it a moment.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while closes.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("outbound sink closed after the session ended");
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Other send errors may be transient (one unreachable destination on a
    /// UDP socket); they must not tear the session down.
    #[tokio::test]
    async fn transient_send_error_keeps_udp_session() {
        let (handle, fwd_tx, _closes) = spawn_relay(false);
        fwd_tx.send(packet()).await.unwrap();
        fwd_tx.send(packet()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!handle.is_finished(), "transient error ended the session");
        assert!(!fwd_tx.is_closed());
        handle.abort();
    }
}
