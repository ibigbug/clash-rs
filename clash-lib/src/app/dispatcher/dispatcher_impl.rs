use crate::{
    app::{
        dns::ClashResolver, net::get_interface_by_name,
        outbound::manager::ThreadSafeOutboundManager, router::ArcRouter,
    },
    common::io::copy_bidirectional,
    config::{
        def::RunMode,
        internal::proxy::{PROXY_DIRECT, PROXY_GLOBAL},
    },
    proxy::{
        AnyInboundDatagram, ProxyStream, datagram::UdpPacket, utils::ToCanonical,
    },
    session::{Session, SocksAddr},
};
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    net::SocketAddr,
    sync::Arc,
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
    pub async fn dispatch_stream(
        &self,
        mut sess: Session,
        mut lhs: Box<dyn ProxyStream>,
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
        let (outbound_name, rule) = match mode {
            RunMode::Global => (PROXY_GLOBAL, None),
            RunMode::Rule => self.router.match_route(&mut sess).await,
            RunMode::Direct => (PROXY_DIRECT, None),
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

        let mgr = self.outbound_manager.clone();
        let handler = match mgr.get_outbound(&outbound_name).await {
            Some(h) => h,
            None => {
                debug!("unknown rule: {}, fallback to direct", outbound_name);
                mgr.get_outbound(PROXY_DIRECT).await.unwrap()
            }
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

        let s = sess.clone();
        let ss = sess.clone();
        let t1 = tokio::spawn(async move {
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

                let (outbound_name, rule) = match mode {
                    RunMode::Global => (PROXY_GLOBAL, None),
                    RunMode::Rule => router.match_route(&mut sess).await,
                    RunMode::Direct => (PROXY_DIRECT, None),
                };

                if let Some(interface) = rule.and_then(|rule| rule.interface()) {
                    match get_interface_by_name(interface) {
                        Some(iface) => sess.iface = Some(iface),
                        None => warn!(
                            "rule-selected interface `{}` was not found; using the \
                             default interface",
                            interface
                        ),
                    }
                }
                let outbound_name = outbound_name.to_string();

                debug!("dispatching {} to {}[{}]", sess, outbound_name, mode);

                let remote_receiver_w = remote_receiver_w.clone();

                let mgr = outbound_manager.clone();
                let handler = match mgr.get_outbound(&outbound_name).await {
                    Some(h) => h,
                    None => {
                        debug!(
                            "unknown rule: {}, fallback to direct",
                            outbound_name
                        );
                        mgr.get_outbound(PROXY_DIRECT).await.unwrap()
                    }
                };

                let outbound_name =
                    if let Some(group) = handler.try_as_group_handler() {
                        group
                            .get_active_proxy()
                            .await
                            .map(|x| x.name().to_owned())
                            .unwrap_or(outbound_name)
                    } else {
                        outbound_name
                    };

                match outbound_handle_guard
                    .get_outbound_sender_mut(
                        &outbound_name,
                        packet.src_addr.clone().must_into_socket_addr(), /* this is only
                                                                          * expected to be
                                                                          * socket addr as it's
                                                                          * from local
                                                                          * udp */
                    )
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

                        let (mut remote_w, mut remote_r) = outbound_datagram.split();
                        let (remote_sender, mut remote_forwarder) =
                            tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(
                                256,
                            );

                        // Per-session task: owns orig_map and all dst_addr
                        // substitution logic. Outgoing arm rewrites dst_addr
                        // to the logical destination (from reverse_lookup) and
                        // saves the original for src_addr restoration.
                        let rw_handle = tokio::spawn(async move {
                            // Bound the reverse-mapping table to prevent
                            // unbounded
                            // memory growth on long-lived sessions with many
                            // dests.
                            const ORIG_MAP_MAX: usize = 256;
                            let mut orig_map: HashMap<SocksAddr, SocksAddr> =
                                HashMap::new();
                            // Best-effort fallback for proxy outbounds that do
                            // not echo dst_addr as src_addr in responses (e.g.
                            // Shadowsocks returns the real upstream IP).
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
                                        match remote_receiver_w.send(packet).await {
                                            Ok(_) => {}
                                            Err(err) => {
                                                warn!(
                                                    "failed to send packet to \
                                                     local: {}",
                                                    err
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        });

                        outbound_handle_guard
                            .insert(
                                &outbound_name,
                                packet.src_addr.clone().must_into_socket_addr(),
                                rw_handle,
                                remote_sender.clone(),
                            )
                            .await;

                        match remote_sender.send((packet, dest)).await {
                            Ok(_) => {}
                            Err(err) => {
                                error!("failed to send packet to remote: {}", err);
                            }
                        };
                    }
                    Some(sender) => {
                        match sender.send((packet, dest)).await {
                            // TODO: need to reset when GLOBAL select is changed
                            Ok(_) => {
                                debug!("reusing {} sent to remote", sess);
                            }
                            Err(err) => {
                                error!("failed to send packet to remote: {}", err);
                            }
                        }
                    }
                };
            }

            trace!("UDP session local -> remote finished for {}", ss);
        });

        let ss = s.clone();
        let t2 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_r.recv().await {
                match local_w.send(packet).await {
                    Ok(_) => {}
                    Err(err) => {
                        error!("failed to send packet to local: {}", err);
                    }
                }
            }
            trace!("UDP session remote -> local finished for {}", ss);
        });

        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<u8>();

        tokio::spawn(async move {
            if close_receiver.await.is_ok() {
                trace!("UDP close signal for {} received", s);
                t1.abort();
                t2.abort();
            } else {
                error!("UDP close signal dropped!");
            }
        });

        close_sender
    }
}

// helper function to resolve the destination address
// if the destination is an IP address, check if it's a fake IP
// or look for cached IP
// if the destination is a domain name, don't resolve
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
        outbound_name: &str,
        src_addr: SocketAddr,
        rw_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        let mut map = self.map.write().await;
        map.insert(outbound_name, src_addr, rw_handle, sender);
    }

    async fn get_outbound_sender_mut(
        &self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<OutboundPacketSender> {
        let mut map = self.map.write().await;
        map.get_outbound_sender_mut(outbound_name, src_addr)
    }
}

/// Key identifying a unique UDP NAT session.
/// Scoped to (outbound, client source) — one socket per client, full cone NAT.
#[derive(Debug, PartialEq, Eq, Hash)]
struct OutboundHandleKey {
    outbound_name: String,
    src_addr: SocketAddr,
}

struct OutboundHandleVal {
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
        outbound_name: &str,
        src_addr: SocketAddr,
        rw_handle: JoinHandle<()>,
        sender: OutboundPacketSender,
    ) {
        self.0.insert(
            OutboundHandleKey {
                outbound_name: outbound_name.to_string(),
                src_addr,
            },
            OutboundHandleVal {
                rw_handle,
                sender,
                last_active: Instant::now(),
            },
        );
    }

    fn get_outbound_sender_mut(
        &mut self,
        outbound_name: &str,
        src_addr: SocketAddr,
    ) -> Option<OutboundPacketSender> {
        let key = OutboundHandleKey {
            outbound_name: outbound_name.to_owned(),
            src_addr,
        };
        // A closed sender means its `rw_handle` task ended and dropped the
        // receiver (e.g. the outbound datagram stream ended after a proxy
        // reconnect). Reusing it would silently drop every packet and, because
        // the lookup refreshes `last_active`, the timeout cleaner would never
        // evict it. Drop the dead session so the caller rebuilds the
        // association on the live connection.
        if self.0.get(&key).is_some_and(|val| val.sender.is_closed()) {
            if let Some(dead) = self.0.remove(&key) {
                dead.rw_handle.abort();
            }
            trace!(
                "evicting closed outbound udp session {:?}",
                (outbound_name, src_addr)
            );
            return None;
        }
        self.0.get_mut(&key).map(|val| {
            trace!(
                "updating last access time for outbound {:?}",
                (outbound_name, src_addr)
            );
            val.last_active = Instant::now();
            val.sender.clone()
        })
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

    #[tokio::test]
    async fn closed_udp_session_is_evicted_for_reconnect() {
        let mut map = OutboundHandleMap::new();
        let (tx, rx) = tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(4);
        let handle = tokio::spawn(async {});
        map.insert("proxy", src(), handle, tx);

        // Receiver alive: the cached sender is reused.
        assert!(map.get_outbound_sender_mut("proxy", src()).is_some());

        // Receiver dropped (its rw_handle ended): the entry is evicted so the
        // caller rebuilds the association instead of writing to a dead channel.
        drop(rx);
        assert!(map.get_outbound_sender_mut("proxy", src()).is_none());
        // The entry is removed, not merely skipped.
        assert!(map.0.is_empty());
    }

    #[tokio::test]
    async fn live_udp_session_is_retained() {
        let mut map = OutboundHandleMap::new();
        let (tx, _rx) = tokio::sync::mpsc::channel::<(UdpPacket, SocksAddr)>(4);
        let handle = tokio::spawn(async {});
        map.insert("proxy", src(), handle, tx);

        assert!(map.get_outbound_sender_mut("proxy", src()).is_some());
        assert_eq!(map.0.len(), 1);
    }
}
