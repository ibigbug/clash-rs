//! System TCP/IP-stack TUN backend, ported from leaf's system stack.
//!
//! TCP packets are source-NATed in place to a kernel TCP listener bound on
//! the TUN gateway address. The kernel owns TCP state (congestion control,
//! window scaling) and the accepted stream is dispatched with the original
//! five-tuple recovered from the NAT table.
//!
//! UDP packets are forwarded through `watfaq_netstack::UdpSocket` — a pure
//! IP packet codec — so the existing datagram path, including DNS hijack,
//! is reused unchanged. ICMP echo requests to the gateway are answered in
//! place; other ICMP traffic is dropped.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
#[cfg(not(target_os = "linux"))]
use futures::{SinkExt, StreamExt};
use socket2::{Domain, Protocol, SockAddr, Socket, Type as SocketType};
use tokio::{net::TcpListener, sync::mpsc, time};
use tracing::{debug, trace, warn};

use crate::{
    Error,
    app::{
        dispatcher::Dispatcher, dns::ThreadSafeDNSResolver,
        net::DEFAULT_OUTBOUND_INTERFACE,
    },
    config::config::TunConfig,
    proxy::tun::datagram::handle_inbound_datagram,
    session::{Network, Session, Type},
};

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_MIN_HEADER: usize = 20;
const TCP_NAT_SHARDS: usize = 64;
const FIRST_NAT_PORT: u16 = 10_000;
/// Depth of the queue feeding the single device writer on platforms without
/// the batched API.
#[cfg(not(target_os = "linux"))]
const SYSTEM_WRITE_QUEUE: usize = 1024;
/// Fallback when the config does not pin an MTU; matches the device default.
const DEFAULT_MTU: u16 = 1500;
/// Floor for the receive-buffer payload, so a nonsensical MTU cannot produce
/// buffers too short to hold one segment. Matches the IPv6 minimum MTU.
#[cfg(target_os = "linux")]
const MIN_BUFFER_PAYLOAD: usize = 1280;
const UDP_DOWNLINK_QUEUE: usize = 4096;
/// How long a NAT entry may stay un-accepted before it is reclaimed. The
/// kernel retries SYNs well within this window; anything older is a dead
/// half-open connection.
const TCP_HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const NAT_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
/// How long a mapping outlives its dispatched stream, so the kernel's
/// closing FIN and final ACK can still be translated.
const NAT_LINGER: Duration = Duration::from_secs(10);
/// Pause before retrying `accept` after a resource-exhaustion error, which
/// would otherwise recur immediately and spin the accept loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// Shorter pause for any other accept error, so a recurring one cannot spin
/// the loop while a one-off barely delays the next connection.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(1);
/// How many consecutive batched-read errors are tolerated before the read
/// loop gives up. A single bad GRO read is dropped; a persistent error means
/// the device is gone.
#[cfg(target_os = "linux")]
const MAX_CONSECUTIVE_READ_ERRORS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpKey {
    source: SocketAddr,
    destination: SocketAddr,
}

#[derive(Clone, Copy, Debug)]
struct TcpEntry {
    key: TcpKey,
    last_seen: Instant,
    accepted: bool,
    /// Bumped every time the port is accepted, so the linger task that owns a
    /// finished connection can tell whether the mapping is still *its* mapping
    /// or has since been taken over by a fresh connection reusing the same
    /// five-tuple.
    generation: u64,
}

/// Bidirectional map between an original TCP five-tuple and the NAT source
/// port that stands in for it.
///
/// Both directions are needed on the hot path: uplink packets look up by
/// five-tuple to find their NAT port, and downlink packets (plus `accept`)
/// look up by NAT port to recover the original tuple. Both maps are sharded
/// to keep concurrent flows off a single lock.
///
/// Lock order is **forward before reverse** — `lookup_or_insert` holds
/// forward while taking reverse, so anything that needs both must acquire
/// them in that order, or release one before taking the other.
struct TcpNat {
    forward: Box<[Mutex<HashMap<TcpKey, u16>>]>,
    reverse: Box<[Mutex<HashMap<u16, TcpEntry>>]>,
    next_port: AtomicU16,
    next_generation: AtomicU64,
}

/// Upper bound on how many ports `lookup_or_insert` probes before giving up.
///
/// When the table has room a free port is found in a handful of tries. The cap
/// matters only when the table is near full: without it a single packet to a
/// saturated table would scan the whole 55k-port space while holding a forward
/// shard lock, turning one uplink packet into tens of thousands of lock ops.
const NAT_PROBE_LIMIT: usize = 4096;

/// Ignore mutex poisoning: every critical section below is a plain map
/// operation that cannot leave the map in an inconsistent state.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl TcpNat {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            forward: (0..TCP_NAT_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            reverse: (0..TCP_NAT_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            next_port: AtomicU16::new(FIRST_NAT_PORT),
            next_generation: AtomicU64::new(0),
        })
    }

    #[inline]
    fn forward_shard(key: &TcpKey) -> usize {
        fn address_hash(address: SocketAddr) -> usize {
            match address {
                SocketAddr::V4(address) => u32::from(*address.ip()) as usize,
                SocketAddr::V6(address) => {
                    address.ip().segments().iter().fold(0usize, |hash, seg| {
                        hash.rotate_left(5) ^ *seg as usize
                    })
                }
            }
        }
        (address_hash(key.source)
            ^ address_hash(key.destination)
            ^ key.source.port() as usize
            ^ key.destination.port() as usize)
            & (TCP_NAT_SHARDS - 1)
    }

    #[inline]
    fn reverse_shard(port: u16) -> usize {
        (port as usize) & (TCP_NAT_SHARDS - 1)
    }

    fn lookup_or_insert(&self, key: TcpKey) -> io::Result<u16> {
        let forward = &self.forward[Self::forward_shard(&key)];
        let mut forward = lock(forward);
        if let Some(port) = forward.get(&key).copied() {
            if let Some(entry) =
                lock(&self.reverse[Self::reverse_shard(port)]).get_mut(&port)
                && entry.key == key
            {
                // The `entry.key == key` guard matters: the reverse entry can
                // have been reclaimed and the port handed to a *different*
                // flow between our forward read and this reverse read.
                // Returning it blindly would emit this flow under another
                // flow's NAT port and cross-deliver both.
                entry.last_seen = Instant::now();
                return Ok(port);
            }
            // The forward entry is stale — the port was reclaimed, or now
            // belongs to another flow. Drop it and allocate a fresh port.
            forward.remove(&key);
        }

        for _ in 0..NAT_PROBE_LIMIT {
            let mut port = self.next_port.fetch_add(1, Ordering::Relaxed);
            if port < FIRST_NAT_PORT {
                port = FIRST_NAT_PORT;
                self.next_port
                    .store(FIRST_NAT_PORT.wrapping_add(1), Ordering::Relaxed);
            }
            let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
            if reverse.contains_key(&port) {
                continue;
            }
            reverse.insert(
                port,
                TcpEntry {
                    key,
                    last_seen: Instant::now(),
                    accepted: false,
                    generation: 0,
                },
            );
            forward.insert(key, port);
            return Ok(port);
        }
        Err(io::Error::other("system TUN TCP NAT port space exhausted"))
    }

    fn lookup_back(&self, port: u16) -> Option<TcpEntry> {
        let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
        let entry = reverse.get_mut(&port)?;
        entry.last_seen = Instant::now();
        Some(*entry)
    }

    /// Marks a port accepted and returns the original tuple plus the fresh
    /// generation stamped on it, in one critical section.
    ///
    /// Folding the lookup and the mark together closes the window in which
    /// `cleanup` could reclaim the entry between a separate lookup and mark.
    /// The generation lets the caller's later teardown check the mapping is
    /// still the one it accepted.
    fn accept(&self, port: u16) -> Option<(TcpKey, u64)> {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
        let entry = reverse.get_mut(&port)?;
        entry.accepted = true;
        entry.last_seen = Instant::now();
        entry.generation = generation;
        Some((entry.key, generation))
    }

    /// Removes the forward index for `key`, but only if it still points at
    /// `port`. A bare `forward.remove(&key)` would delete a newer mapping that
    /// `lookup_or_insert` had since re-created for the same flow under a
    /// different port.
    fn remove_forward_if(&self, key: TcpKey, port: u16) {
        let mut forward = lock(&self.forward[Self::forward_shard(&key)]);
        if forward.get(&key) == Some(&port) {
            forward.remove(&key);
        }
    }

    /// Removes `port` only if it still carries `generation`, i.e. it has not
    /// been taken over by a newer accepted connection reusing the same tuple.
    fn remove_if_generation(&self, port: u16, generation: u64) {
        let key = {
            let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
            match reverse.get(&port) {
                Some(entry) if entry.generation == generation => {
                    reverse.remove(&port).map(|entry| entry.key)
                }
                _ => None,
            }
        };
        // Drop the reverse guard before taking forward: `lookup_or_insert`
        // takes forward first, so the reverse order could deadlock.
        if let Some(key) = key {
            self.remove_forward_if(key, port);
        }
    }

    /// Removes `port`, but only if it is *still* expired.
    ///
    /// `cleanup` collects candidates without holding the shard lock, and in
    /// that gap `lookup_or_insert` may have refreshed `last_seen` for a new
    /// packet of the same flow, or `accept` may have claimed the entry.
    /// Removing it regardless would blackhole a live connection: the downlink
    /// path would find no mapping and drop every kernel packet.
    fn remove_if_still_expired(&self, port: u16, timeout: Duration) {
        let key = {
            let mut reverse = lock(&self.reverse[Self::reverse_shard(port)]);
            match reverse.get(&port) {
                Some(entry)
                    if !entry.accepted && entry.last_seen.elapsed() >= timeout =>
                {
                    reverse.remove(&port).map(|entry| entry.key)
                }
                _ => None,
            }
        };
        // The reverse guard is dropped above before the forward lock is
        // taken: `lookup_or_insert` acquires forward first, so holding
        // reverse while waiting on forward could deadlock.
        if let Some(key) = key {
            self.remove_forward_if(key, port);
        }
    }

    fn cleanup(&self, timeout: Duration) {
        let now = Instant::now();
        let mut expired = Vec::new();
        for reverse in self.reverse.iter() {
            let reverse = lock(reverse);
            expired.extend(reverse.iter().filter_map(|(&port, entry)| {
                (!entry.accepted && now.duration_since(entry.last_seen) >= timeout)
                    .then_some(port)
            }));
        }
        for port in expired {
            self.remove_if_still_expired(port, timeout);
        }
    }
}

#[derive(Clone, Copy)]
struct Ipv4View {
    header_len: usize,
    total_len: usize,
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
}

/// Validates an IPv4 packet and locates its transport header.
///
/// Rejects fragments: this backend rewrites transport ports, which are only
/// present in the first fragment, so reassembly would be required to handle
/// them correctly.
fn parse_ipv4(packet: &[u8]) -> io::Result<Ipv4View> {
    if packet.len() < IPV4_MIN_HEADER || packet[0] >> 4 != 4 {
        return Err(io::Error::other("invalid IPv4 packet"));
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < IPV4_MIN_HEADER || header_len > packet.len() {
        return Err(io::Error::other("invalid IPv4 header length"));
    }
    let total_len = read_u16(packet, 2) as usize;
    if total_len < header_len || total_len > packet.len() {
        return Err(io::Error::other("truncated IPv4 packet"));
    }
    if read_u16(packet, 6) & 0x3fff != 0 {
        return Err(io::Error::other(
            "fragmented IPv4 packets are unsupported by system stack",
        ));
    }
    Ok(Ipv4View {
        header_len,
        total_len,
        protocol: packet[9],
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    })
}

#[derive(Clone, Copy)]
struct Ipv6View {
    transport_offset: usize,
    total_len: usize,
    protocol: u8,
    source: Ipv6Addr,
    destination: Ipv6Addr,
}

/// Validates an IPv6 packet and walks its extension-header chain to find the
/// transport header.
///
/// Rejects fragment (44) and ESP (50) headers: the former needs reassembly
/// before ports are visible, the latter hides them entirely.
fn parse_ipv6(packet: &[u8]) -> io::Result<Ipv6View> {
    if packet.len() < IPV6_HEADER || packet[0] >> 4 != 6 {
        return Err(io::Error::other("invalid IPv6 packet"));
    }
    let payload_len = read_u16(packet, 4) as usize;
    let total_len = IPV6_HEADER
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::other("IPv6 packet length overflow"))?;
    if total_len > packet.len() {
        return Err(io::Error::other("truncated IPv6 packet"));
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    let mut protocol = packet[6];
    let mut transport_offset = IPV6_HEADER;
    loop {
        match protocol {
            // Hop-by-hop, routing, and destination options carry a
            // next-header byte followed by an 8-octet-unit length.
            0 | 43 | 60 => {
                if transport_offset + 2 > total_len {
                    return Err(io::Error::other("truncated IPv6 extension header"));
                }
                let header_len = (packet[transport_offset + 1] as usize + 1) * 8;
                if transport_offset + header_len > total_len {
                    return Err(io::Error::other("truncated IPv6 extension header"));
                }
                protocol = packet[transport_offset];
                transport_offset += header_len;
            }
            51 => {
                if transport_offset + 2 > total_len {
                    return Err(io::Error::other(
                        "truncated IPv6 authentication header",
                    ));
                }
                let header_len = (packet[transport_offset + 1] as usize + 2) * 4;
                if transport_offset + header_len > total_len {
                    return Err(io::Error::other(
                        "truncated IPv6 authentication header",
                    ));
                }
                protocol = packet[transport_offset];
                transport_offset += header_len;
            }
            44 => {
                return Err(io::Error::other(
                    "fragmented IPv6 packets are unsupported by system stack",
                ));
            }
            50 => {
                return Err(io::Error::other(
                    "encrypted IPv6 payload is unsupported by system stack",
                ));
            }
            _ => break,
        }
    }
    Ok(Ipv6View {
        transport_offset,
        total_len,
        protocol,
        source,
        destination,
    })
}

#[inline]
fn read_u16(packet: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

#[inline]
fn write_u16(packet: &mut [u8], offset: usize, value: u16) {
    packet[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[inline]
fn checksum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// RFC 1624 incremental checksum update for a single 16-bit word.
#[inline]
fn checksum_replace(checksum: u16, old: u16, new: u16) -> u16 {
    let sum = (!checksum as u32) + (!old as u32) + new as u32;
    !checksum_fold(sum)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    !checksum_fold(sum)
}

/// Rewrites an IPv4 TCP packet's four-tuple in place.
///
/// Both the IP header checksum and the TCP checksum are updated
/// incrementally (RFC 1624) rather than recomputed, so cost is independent
/// of payload size. A TCP checksum that lands on zero is written as 0xffff,
/// since zero means "no checksum" and would be rejected.
fn rewrite_ipv4_tcp(
    packet: &mut [u8],
    header_len: usize,
    source: SocketAddrV4,
    destination: SocketAddrV4,
) -> io::Result<()> {
    if packet.len() < header_len + TCP_MIN_HEADER {
        return Err(io::Error::other("truncated TCP packet"));
    }
    let tcp_checksum_offset = header_len + 16;
    let mut ip_checksum = read_u16(packet, 10);
    let mut tcp_checksum = read_u16(packet, tcp_checksum_offset);
    for (offset, new_word) in [
        (
            12,
            u16::from_be_bytes(source.ip().octets()[..2].try_into().unwrap()),
        ),
        (
            14,
            u16::from_be_bytes(source.ip().octets()[2..].try_into().unwrap()),
        ),
        (
            16,
            u16::from_be_bytes(destination.ip().octets()[..2].try_into().unwrap()),
        ),
        (
            18,
            u16::from_be_bytes(destination.ip().octets()[2..].try_into().unwrap()),
        ),
    ] {
        let old_word = read_u16(packet, offset);
        ip_checksum = checksum_replace(ip_checksum, old_word, new_word);
        tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
        write_u16(packet, offset, new_word);
    }
    for (offset, new_word) in [
        (header_len, source.port()),
        (header_len + 2, destination.port()),
    ] {
        let old_word = read_u16(packet, offset);
        tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
        write_u16(packet, offset, new_word);
    }
    write_u16(packet, 10, ip_checksum);
    write_u16(
        packet,
        tcp_checksum_offset,
        if tcp_checksum == 0 {
            0xffff
        } else {
            tcp_checksum
        },
    );
    Ok(())
}

/// Rewrites an IPv6 TCP packet's four-tuple in place.
///
/// Like the IPv4 path this updates the TCP checksum incrementally; IPv6 has
/// no header checksum to maintain. Addresses are folded in word by word
/// because they participate in the TCP pseudo-header.
fn rewrite_ipv6_tcp(
    packet: &mut [u8],
    transport_offset: usize,
    source: SocketAddrV6,
    destination: SocketAddrV6,
) -> io::Result<()> {
    if packet.len() < transport_offset + TCP_MIN_HEADER {
        return Err(io::Error::other("truncated TCP packet"));
    }
    let tcp_checksum_offset = transport_offset + 16;
    let mut tcp_checksum = read_u16(packet, tcp_checksum_offset);
    for (offset, address) in [(8, source.ip()), (24, destination.ip())] {
        for (word_offset, new_word) in address
            .octets()
            .chunks_exact(2)
            .enumerate()
            .map(|(index, octets)| {
                (index * 2, u16::from_be_bytes([octets[0], octets[1]]))
            })
        {
            let offset = offset + word_offset;
            let old_word = read_u16(packet, offset);
            tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
            write_u16(packet, offset, new_word);
        }
    }
    for (offset, new_word) in [
        (transport_offset, source.port()),
        (transport_offset + 2, destination.port()),
    ] {
        let old_word = read_u16(packet, offset);
        tcp_checksum = checksum_replace(tcp_checksum, old_word, new_word);
        write_u16(packet, offset, new_word);
    }
    write_u16(
        packet,
        tcp_checksum_offset,
        if tcp_checksum == 0 {
            0xffff
        } else {
            tcp_checksum
        },
    );
    Ok(())
}

/// Computes an IPv6 transport checksum from scratch, over the RFC 2460
/// pseudo-header (source, destination, payload length, next header) followed
/// by the transport payload.
///
/// Used where no prior checksum exists to update incrementally: synthesized
/// UDP downlink packets and ICMPv6 echo replies.
fn checksum_ipv6_transport(
    packet: &[u8],
    transport_offset: usize,
    next_header: u8,
) -> u16 {
    let payload_len = packet.len() - transport_offset;
    let mut sum = 0u32;
    for chunk in packet[8..40].chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += ((payload_len >> 16) as u16) as u32;
    sum += (payload_len as u16) as u32;
    sum += next_header as u32;
    let mut chunks = packet[transport_offset..].chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    let checksum = !checksum_fold(sum);
    if checksum == 0 { 0xffff } else { checksum }
}

fn make_icmp_echo_reply(
    packet: &mut [u8],
    view: Ipv4View,
    tun_address: Ipv4Addr,
) -> bool {
    if view.destination != tun_address || view.total_len < view.header_len + 8 {
        return false;
    }
    let icmp = view.header_len;
    if packet[icmp] != 8 || packet[icmp + 1] != 0 {
        return false;
    }
    packet[12..16].copy_from_slice(&view.destination.octets());
    packet[16..20].copy_from_slice(&view.source.octets());
    write_u16(packet, 10, 0);
    write_u16(packet, 10, checksum(&packet[..view.header_len]));
    packet[icmp] = 0;
    write_u16(packet, icmp + 2, 0);
    write_u16(packet, icmp + 2, checksum(&packet[icmp..view.total_len]));
    true
}

fn make_icmpv6_echo_reply(
    packet: &mut [u8],
    view: Ipv6View,
    tun_address: Ipv6Addr,
) -> bool {
    if view.destination != tun_address || view.total_len < view.transport_offset + 8
    {
        return false;
    }
    let icmp = view.transport_offset;
    if packet[icmp] != 128 || packet[icmp + 1] != 0 {
        return false;
    }
    packet[8..24].copy_from_slice(&view.destination.octets());
    packet[24..40].copy_from_slice(&view.source.octets());
    packet[icmp] = 129;
    write_u16(packet, icmp + 2, 0);
    write_u16(
        packet,
        icmp + 2,
        checksum_ipv6_transport(&packet[..view.total_len], icmp, 58),
    );
    true
}

/// Derives the NAT source address as `gateway + 1`.
///
/// Uplink packets are rewritten to come *from* this address so the kernel
/// routes the listener's replies back out the TUN rather than to the real
/// client. It must therefore be inside the TUN prefix, and must not be the
/// network or broadcast address.
fn ipv4_nat_address(gateway: ipnet::Ipv4Net) -> Result<Ipv4Addr, Error> {
    let tun_address = gateway.addr();
    let netmask = gateway.netmask();
    let nat_address =
        Ipv4Addr::from(u32::from(tun_address).checked_add(1).ok_or_else(|| {
            Error::InvalidConfig(
                "system TUN requires an IPv4 gateway with one following address"
                    .to_string(),
            )
        })?);
    let mask = u32::from(netmask);
    if u32::from(tun_address) & mask != u32::from(nat_address) & mask {
        return Err(Error::InvalidConfig(
            "system TUN requires an IPv4 prefix with one adjacent NAT address"
                .to_string(),
        ));
    }
    let network = u32::from(tun_address) & mask;
    let broadcast = network | !mask;
    if u32::from(nat_address) == network || u32::from(nat_address) == broadcast {
        return Err(Error::InvalidConfig(
            "system TUN adjacent NAT address must not be the network or broadcast \
             address"
                .to_string(),
        ));
    }
    Ok(nat_address)
}

fn ipv6_adjacent_address(
    address: Ipv6Addr,
    prefix_len: u8,
) -> Result<Ipv6Addr, Error> {
    if prefix_len >= 128 {
        return Err(Error::InvalidConfig(
            "system TUN requires an IPv6 prefix shorter than /128 for its adjacent \
             NAT address"
                .to_string(),
        ));
    }
    let nat_address =
        Ipv6Addr::from(u128::from(address).checked_add(1).ok_or_else(|| {
            Error::InvalidConfig(
                "system TUN IPv6 gateway has no following NAT address".to_string(),
            )
        })?);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    if u128::from(address) & mask != u128::from(nat_address) & mask {
        return Err(Error::InvalidConfig(
            "system TUN requires an IPv6 prefix with one adjacent NAT address"
                .to_string(),
        ));
    }
    Ok(nat_address)
}

/// Accepts redirected connections and dispatches them under their original
/// five-tuple.
///
/// Only peers coming from `nat_ip` are ours; the listener is reachable by
/// other local traffic, so anything else is dropped rather than proxied.
async fn tcp_accept_loop(
    listener: TcpListener,
    nat_ip: IpAddr,
    nat: Arc<TcpNat>,
    dispatcher: Arc<Dispatcher>,
    so_mark: Option<u32>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Accept errors are per-connection or transient. Returning
                // here would resolve this future and, because `run` selects
                // over it, tear down the whole TUN backend — so a single
                // aborted handshake or file-descriptor shortage would kill
                // all TUN traffic.
                warn!("system TUN TCP accept failed: {e}");
                // Back off after every failure, not just the classified ones:
                // any error that recurs — including platform codes that do not
                // match these errnos — would otherwise spin the loop at full
                // CPU and flood the log. Resource exhaustion takes longer to
                // clear, so it waits longer.
                let backoff = if matches!(
                    e.raw_os_error(),
                    Some(libc::EMFILE)
                        | Some(libc::ENFILE)
                        | Some(libc::ENOBUFS)
                        | Some(libc::ENOMEM)
                ) {
                    ACCEPT_BACKOFF
                } else {
                    ACCEPT_RETRY_DELAY
                };
                time::sleep(backoff).await;
                continue;
            }
        };
        if peer.ip() != nat_ip {
            continue;
        }
        // One critical section recovers the tuple and stamps a generation, so
        // cleanup cannot reclaim the entry between the two. `None` means the
        // mapping was already gone — the connection cannot be translated, so
        // drop it.
        let Some((key, generation)) = nat.accept(peer.port()) else {
            continue;
        };
        let nat = Arc::clone(&nat);
        let dispatcher = Arc::clone(&dispatcher);
        tokio::spawn(async move {
            let sess = Session {
                network: Network::Tcp,
                typ: Type::Tun,
                source: key.source,
                destination: key.destination.into(),
                iface: DEFAULT_OUTBOUND_INTERFACE.read().await.clone().inspect(
                    |x| {
                        debug!(
                            "selecting outbound interface: {:?} for tun TCP \
                             connection",
                            x
                        );
                    },
                ),
                so_mark,
                ..Default::default()
            };
            debug!("new tun TCP session assigned: {}", sess);
            dispatcher.dispatch_stream(sess, Box::new(stream)).await;
            // The kernel closes the accepted socket only once it is dropped
            // here, and the FIN plus final ACK it then sends still have to
            // be translated back to the original five-tuple. Dropping the
            // mapping immediately would blackhole them, leaving the client
            // to wait out its own timeout while the kernel retransmits.
            time::sleep(NAT_LINGER).await;
            // Remove only if this is still the mapping we accepted: a new
            // connection reusing the same five-tuple within the linger window
            // takes over the port with a newer generation, and must not be
            // torn down by this finished connection's timer.
            nat.remove_if_generation(peer.port(), generation);
        });
    }
}

fn bind_v4_listener(address: Ipv4Addr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, SocketType::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SockAddr::from(SocketAddrV4::new(address, 0)))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

/// Binds the IPv6 listener to the TUN address.
///
/// The address can still be tentative (duplicate address detection) at this
/// point, which makes `bind` fail with `EADDRNOTAVAIL`. On Linux
/// `IPV6_FREEBIND` lifts that restriction; elsewhere we fall back to the
/// unspecified address, which works but leaves the port reachable on every
/// IPv6 interface until `tcp_accept_loop`'s peer filter rejects the
/// connection.
fn bind_v6_listener(address: Ipv6Addr) -> io::Result<TcpListener> {
    fn new_socket() -> io::Result<Socket> {
        let socket =
            Socket::new(Domain::IPV6, SocketType::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(true)?;
        Ok(socket)
    }

    fn listen(socket: Socket) -> io::Result<TcpListener> {
        socket.listen(1024)?;
        socket.set_nonblocking(true)?;
        TcpListener::from_std(socket.into())
    }

    let socket = new_socket()?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket.set_freebind_v6(true)?;
    match socket.bind(&SockAddr::from(SocketAddr::V6(SocketAddrV6::new(
        address, 0, 0, 0,
    )))) {
        Ok(()) => listen(socket),
        Err(e) => {
            warn!(
                "system TUN could not bind the IPv6 listener to {address}: {e}; \
                 falling back to the unspecified address"
            );
            let socket = new_socket()?;
            socket.bind(&SockAddr::from(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            ))))?;
            listen(socket)
        }
    }
}

/// What the I/O driver should do with a packet after processing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Disposition {
    /// Rewritten in place; hand it back to the TUN device.
    WriteBack,
    /// Consumed (forwarded to the UDP codec) or not ours; nothing to write.
    Done,
}

/// Everything the packet path needs, so the batched and per-packet I/O
/// drivers can share a single processing function.
struct PacketContext {
    tun_address: Ipv4Addr,
    nat_address: Ipv4Addr,
    listener_port: u16,
    /// `(tun address, NAT address, listener port)`, absent when IPv6 is off.
    ipv6: Option<(Ipv6Addr, Ipv6Addr, u16)>,
    nat: Arc<TcpNat>,
    udp_inbound: mpsc::UnboundedSender<watfaq_netstack::Packet>,
}

impl PacketContext {
    /// Rewrites one IP packet in place and says what to do with it.
    ///
    /// Synchronous on purpose: the UDP hand-off uses an unbounded channel, so
    /// nothing here needs to await, which lets a batched driver run a whole
    /// batch without yielding.
    fn process(&self, packet: &mut [u8]) -> Disposition {
        if packet.is_empty() {
            return Disposition::Done;
        }
        match packet[0] >> 4 {
            4 => self.process_v4(packet),
            6 => self.process_v6(packet),
            _ => {
                trace!("system TUN ignored packet with unknown IP version");
                Disposition::Done
            }
        }
    }

    fn process_v4(&self, packet: &mut [u8]) -> Disposition {
        let view = match parse_ipv4(packet) {
            Ok(view) => view,
            Err(e) => {
                trace!("system TUN ignored IPv4 packet: {e}");
                return Disposition::Done;
            }
        };
        match view.protocol {
            6 => {
                if process_tcp_v4(
                    packet,
                    view,
                    &self.nat,
                    self.tun_address,
                    self.nat_address,
                    self.listener_port,
                )
                .is_some()
                {
                    Disposition::WriteBack
                } else {
                    Disposition::Done
                }
            }
            17 => {
                // Handed over as a whole IP packet; the codec re-parses it and
                // passes the payload to the datagram path. This copies,
                // because a batched driver reuses its receive buffers.
                self.udp_inbound
                    .send(watfaq_netstack::Packet::new(Bytes::copy_from_slice(
                        packet,
                    )))
                    .ok();
                Disposition::Done
            }
            1 => {
                if make_icmp_echo_reply(packet, view, self.tun_address) {
                    Disposition::WriteBack
                } else {
                    Disposition::Done
                }
            }
            _ => Disposition::Done,
        }
    }

    fn process_v6(&self, packet: &mut [u8]) -> Disposition {
        let view = match parse_ipv6(packet) {
            Ok(view) => view,
            Err(e) => {
                trace!("system TUN ignored IPv6 packet: {e}");
                return Disposition::Done;
            }
        };
        let Some((tun_v6, nat_v6, v6_port)) = self.ipv6 else {
            return Disposition::Done;
        };
        match view.protocol {
            6 => {
                if process_tcp_v6(packet, view, &self.nat, tun_v6, nat_v6, v6_port)
                    .is_some()
                {
                    Disposition::WriteBack
                } else {
                    Disposition::Done
                }
            }
            17 => {
                // The UDP codec assumes a fixed 40-byte IPv6 header; packets
                // carrying extension headers would be parsed incorrectly.
                if view.transport_offset != IPV6_HEADER {
                    trace!(
                        "system TUN dropped IPv6 UDP packet with extension headers"
                    );
                    return Disposition::Done;
                }
                self.udp_inbound
                    .send(watfaq_netstack::Packet::new(Bytes::copy_from_slice(
                        packet,
                    )))
                    .ok();
                Disposition::Done
            }
            58 => {
                if make_icmpv6_echo_reply(packet, view, tun_v6) {
                    Disposition::WriteBack
                } else {
                    Disposition::Done
                }
            }
            _ => Disposition::Done,
        }
    }
}

/// Checks the device actually carries the configured gateway prefixes.
///
/// The listener binds `gateway` and the NAT source address is derived from its
/// prefix, so a device whose address or mask differs would leave us binding an
/// address it does not have. This is checked against the live interface rather
/// than the config alone, which covers all three ways a device gets here:
/// freshly created, an existing interface reused as-is, and `fd://`, where the
/// interface was configured by someone else entirely.
///
/// Enumeration failing is not treated as a mismatch — on some platforms it is
/// simply unavailable, and a genuinely wrong address still surfaces when the
/// listener bind fails.
fn verify_device_addresses(
    cfg: &TunConfig,
    device: &tun_rs::AsyncDevice,
) -> Result<(), Error> {
    use network_interface::NetworkInterfaceConfig;

    let Ok(name) = device.name() else {
        debug!("system TUN could not read the device name; skipping check");
        return Ok(());
    };
    let Ok(interfaces) = network_interface::NetworkInterface::show() else {
        debug!("system TUN could not enumerate interfaces; skipping check");
        return Ok(());
    };
    let Some(iface) = interfaces.into_iter().find(|x| x.name == name) else {
        debug!("system TUN device {name} not enumerable; skipping check");
        return Ok(());
    };

    let mismatch = |what: &str, want: String| {
        Error::InvalidConfig(format!(
            "tun device {name} does not have the configured {what} {want}; the \
             system stack derives its listener and NAT addresses from it, so they \
             must match. Either let clash-rs create the device or set {what} to \
             the interface's actual value."
        ))
    };

    // A matching address under a different mask still breaks us: the NAT
    // address is derived from the prefix and could fall outside the
    // interface's network. But an *absent* mask is not a mismatch — some
    // platforms simply do not report one, and rejecting on that would refuse
    // a perfectly good device.
    let mask_ok = |reported: Option<std::net::IpAddr>,
                   configured: std::net::IpAddr| {
        reported.is_none_or(|mask| mask == configured)
    };

    let has_v4 = iface.addr.iter().any(|addr| match addr {
        network_interface::Addr::V4(v4) => {
            v4.ip == cfg.gateway.addr()
                && mask_ok(
                    v4.netmask.map(std::net::IpAddr::V4),
                    std::net::IpAddr::V4(cfg.gateway.netmask()),
                )
        }
        network_interface::Addr::V6(_) => false,
    });
    if !has_v4 {
        return Err(mismatch("gateway", cfg.gateway.to_string()));
    }

    if let Some(gateway_v6) = cfg.gateway_v6 {
        let has_v6 = iface.addr.iter().any(|addr| match addr {
            network_interface::Addr::V6(v6) => {
                v6.ip == gateway_v6.addr()
                    && mask_ok(
                        v6.netmask.map(std::net::IpAddr::V6),
                        std::net::IpAddr::V6(gateway_v6.netmask()),
                    )
            }
            network_interface::Addr::V4(_) => false,
        });
        if !has_v6 {
            return Err(mismatch("gateway-v6", gateway_v6.to_string()));
        }
    }

    Ok(())
}

/// Runs the system stack until one of its tasks fails.
///
/// Drives the TUN I/O (batched on Linux, per-packet elsewhere), the IPv4 and
/// IPv6 accept loops, the datagram dispatcher, and the periodic NAT cleanup.
/// They are selected over, so the first failure tears the backend down and
/// surfaces the error.
pub(crate) async fn run(
    cfg: TunConfig,
    tun: tun_rs::AsyncDevice,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) -> Result<(), Error> {
    verify_device_addresses(&cfg, &tun)?;

    let tun_address = cfg.gateway.addr();
    let nat_address = ipv4_nat_address(cfg.gateway)?;

    let listener = bind_v4_listener(tun_address)?;
    let listener_port = listener.local_addr()?.port();

    let (ipv6_listener, ipv6_addresses) = match cfg.gateway_v6 {
        Some(gateway_v6) => {
            let tun_address = gateway_v6.addr();
            let nat_address =
                ipv6_adjacent_address(tun_address, gateway_v6.prefix_len())?;
            let listener = bind_v6_listener(tun_address)?;
            let port = listener.local_addr()?.port();
            (Some(listener), Some((tun_address, nat_address, port)))
        }
        None => (None, None),
    };

    // UDP reuses the userspace packet codec and the existing datagram path.
    //
    // The ingest queue is unbounded because `watfaq_netstack::UdpSocket` takes
    // an `UnboundedReceiver`, which the userspace stack relies on too. That
    // means a UDP flood arriving faster than `handle_inbound_datagram` drains
    // it grows memory without a limit; bounding it needs an API change in
    // clash-netstack and would alter the userspace stack's behaviour, so it is
    // left as-is here rather than changed for one backend only.
    let (udp_inbound_tx, udp_inbound_rx) =
        mpsc::unbounded_channel::<watfaq_netstack::Packet>();
    let (udp_outbound_tx, udp_outbound_rx) =
        mpsc::channel::<watfaq_netstack::Packet>(UDP_DOWNLINK_QUEUE);
    let udp_socket =
        watfaq_netstack::UdpSocket::new(udp_inbound_rx, udp_outbound_tx);

    let tcp_nat = TcpNat::new();

    let ctx = PacketContext {
        tun_address,
        nat_address,
        listener_port,
        ipv6: ipv6_addresses,
        nat: Arc::clone(&tcp_nat),
        udp_inbound: udp_inbound_tx,
    };

    // One task owns the device and drives both directions, so the packets a
    // batch receives are the same buffers it writes back — no channel hop and
    // no copy on the TCP path.
    let fut_tun_io = tun_io(tun, ctx, udp_outbound_rx, mtu(&cfg));

    let fut_accept_v4 = {
        let nat = Arc::clone(&tcp_nat);
        let dispatcher = Arc::clone(&dispatcher);
        async move {
            tcp_accept_loop(
                listener,
                IpAddr::V4(nat_address),
                nat,
                dispatcher,
                cfg.so_mark,
            )
            .await;
            Err(Error::Operation(
                "tun system stack TCP listener stopped unexpectedly".to_string(),
            ))
        }
    };

    let fut_accept_v6 = {
        let nat = Arc::clone(&tcp_nat);
        let dispatcher = Arc::clone(&dispatcher);
        async move {
            match (ipv6_listener, ipv6_addresses) {
                (Some(listener), Some((_, nat_address, _))) => {
                    tcp_accept_loop(
                        listener,
                        IpAddr::V6(nat_address),
                        nat,
                        dispatcher,
                        cfg.so_mark,
                    )
                    .await;
                    Err(Error::Operation(
                        "tun system stack TCP IPv6 listener stopped unexpectedly"
                            .to_string(),
                    ))
                }
                _ => std::future::pending().await,
            }
        }
    };

    let fut_nat_cleanup = {
        let nat = Arc::clone(&tcp_nat);
        async move {
            let mut interval = time::interval(NAT_CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                nat.cleanup(TCP_HALF_OPEN_TIMEOUT);
            }
        }
    };

    let fut_udp_dispatch = async move {
        handle_inbound_datagram(
            udp_socket,
            dispatcher,
            resolver,
            cfg.so_mark,
            cfg.dns_hijack,
        )
        .await;
        Err(Error::Operation(
            "tun system stack UDP dispatcher stopped unexpectedly".to_string(),
        ))
    };

    tokio::select! {
        res = fut_tun_io => res,
        res = fut_accept_v4 => res,
        res = fut_accept_v6 => res,
        _ = fut_nat_cleanup => Ok(()),
        res = fut_udp_dispatch => res,
    }
}

/// Effective MTU, which sizes the per-packet receive buffers.
fn mtu(cfg: &TunConfig) -> usize {
    cfg.mtu.unwrap_or(DEFAULT_MTU) as usize
}

/// How many receive buffers one batch needs.
///
/// `recv_multiple` splits a GRO read — up to 64 KiB — into one buffer per
/// segment, and returns `ErrTooManySegments` if it runs out. Crucially the
/// segment size is the flow's *MSS*, not our MTU: the kernel GSOs the listener
/// replies by the connection's MSS, which can be far below the MTU (an old
/// path, an `advmss` route, or a local `setsockopt(TCP_MAXSEG, …)`). So this
/// is sized from the segment floor, independent of MTU — a large MTU does not
/// make the count safe, and a tiny MTU must not inflate it (that once produced
/// tens of MB of buffers).
///
/// The batched read additionally treats `ErrTooManySegments` as a droppable
/// per-read error rather than a fatal one, so an adversarially tiny segment
/// size (e.g. UDP GSO with a 1-byte segment) degrades to packet loss instead
/// of tearing the backend down.
#[cfg(target_os = "linux")]
fn receive_batch_size() -> usize {
    use tun_rs::IDEAL_BATCH_SIZE;

    // Linux's `TCP_MIN_SND_MSS`. Covers every legitimate low-MTU flow; smaller
    // segments than this are handled by the non-fatal error path.
    const SEGMENT_FLOOR: usize = 48;
    let worst_case = (u16::MAX as usize).div_ceil(SEGMENT_FLOOR) + 1;
    worst_case.max(IDEAL_BATCH_SIZE)
}

/// Batched TUN I/O, available when the device was opened with offload.
///
/// The win is on the receive side: `recv_multiple` takes one large GRO read
/// from the kernel and splits it into individual packets, so a burst of
/// segments costs one syscall instead of one per packet. That is what this
/// backend is bound by — every payload crosses the TUN device twice (uplink
/// is re-injected for the kernel listener, and the listener's reply is read
/// back out again), roughly twice the device operations the userspace stack
/// does. `send_multiple` runs GRO coalescing on the way out too, though with
/// MTU-sized buffers most merges are skipped and it falls back to one write
/// per packet; enlarging the write buffers to enable it is a possible
/// follow-up.
///
/// Both helpers degrade to single-packet I/O when the device has no virtio
/// header, so this path is correct whether or not offload was negotiated.
#[cfg(target_os = "linux")]
async fn tun_io(
    device: tun_rs::AsyncDevice,
    ctx: PacketContext,
    udp_outbound_rx: mpsc::Receiver<watfaq_netstack::Packet>,
    mtu: usize,
) -> Result<(), Error> {
    let device = Arc::new(device);
    tokio::select! {
        res = batched_read_loop(Arc::clone(&device), ctx, mtu) => res,
        res = batched_udp_downlink(device, udp_outbound_rx, mtu) => res,
    }
}

/// Reads a batch, rewrites each packet, and writes back the ones that need it
/// — reusing the very buffers the batch was received into, so the TCP path
/// copies nothing.
///
/// Receive and send are inline in one loop rather than split across tasks with
/// a buffer hand-off. A ping-pong arrangement was measured and was clearly
/// slower: the per-batch channel round-trip (task wake-up, scheduler hop,
/// cross-thread hand-back) costs far more than the write stall it removes, and
/// with a bounded set count the reader ends up waiting on the writer anyway.
#[cfg(target_os = "linux")]
async fn batched_read_loop(
    device: Arc<tun_rs::AsyncDevice>,
    ctx: PacketContext,
    mtu: usize,
) -> Result<(), Error> {
    use tun_rs::{GROTable, VIRTIO_NET_HDR_LEN};

    // Prefer the device's own MTU: for `fd://` devices the interface was set up
    // by someone else and `cfg.mtu` may not describe it. The buffer *length*
    // is floored so a nonsensical MTU cannot yield buffers too short for one
    // segment; the buffer *count* is MTU-independent (see receive_batch_size).
    let mtu = device.mtu().map(usize::from).unwrap_or(mtu);
    let count = receive_batch_size();
    let buf_len = VIRTIO_NET_HDR_LEN + mtu.max(MIN_BUFFER_PAYLOAD);
    debug!("system TUN batched io: mtu {mtu}, {count} receive buffers");

    let mut original = vec![0u8; VIRTIO_NET_HDR_LEN + u16::MAX as usize];
    let mut bufs: Vec<BytesMut> =
        (0..count).map(|_| BytesMut::zeroed(buf_len)).collect();
    let mut sizes = vec![0usize; count];
    let mut gro = GROTable::new();
    let mut consecutive_read_errors = 0usize;

    loop {
        let received = match device
            .recv_multiple(&mut original, &mut bufs, &mut sizes, VIRTIO_NET_HDR_LEN)
            .await
        {
            Ok(received) => {
                consecutive_read_errors = 0;
                received
            }
            Err(e) => {
                // A GRO read that splits into more segments than the buffer
                // set holds (an adversarially tiny segment size) fails the
                // whole read. Treat it — and any other read error — as
                // droppable rather than fatal, so one bad read cannot tear
                // down all TUN traffic. Bail only if errors persist, which
                // signals the device is genuinely gone rather than fed a bad
                // packet.
                consecutive_read_errors += 1;
                warn!(
                    "system TUN batched read failed ({consecutive_read_errors}): \
                     {e}"
                );
                if consecutive_read_errors >= MAX_CONSECUTIVE_READ_ERRORS {
                    return Err(Error::Operation(format!(
                        "system TUN batched read failed {consecutive_read_errors} \
                         times, giving up: {e}"
                    )));
                }
                time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };

        // Compact the packets that need writing back into the front of the
        // buffer set: `send_multiple` writes every buffer handed to it, so it
        // needs a contiguous slice. Swapping moves buffer handles, not bytes.
        //
        // Invariant per iteration: `..write_back` holds trimmed write-backs,
        // `write_back..i` holds processed packets we are done with, and `i..`
        // still holds freshly received ones.
        let mut write_back = 0;
        for i in 0..received {
            let len = sizes[i];
            if len == 0 {
                continue;
            }
            let packet = &mut bufs[i][VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + len];
            if ctx.process(packet) == Disposition::WriteBack {
                // send_multiple takes each packet's length from the buffer's
                // length, so trim to exactly this packet.
                bufs[i].truncate(VIRTIO_NET_HDR_LEN + len);
                if write_back != i {
                    bufs.swap(write_back, i);
                }
                write_back += 1;
            }
        }

        if write_back == 0 {
            continue;
        }
        let sent = device
            .send_multiple(&mut gro, &mut bufs[..write_back], VIRTIO_NET_HDR_LEN)
            .await;
        // Restore the full length the next receive needs. Only the trimmed
        // buffers are touched, and a full-MTU packet leaves almost nothing to
        // re-zero.
        for buf in &mut bufs[..write_back] {
            buf.resize(buf_len, 0);
        }
        if let Err(e) = sent {
            // A full device queue is ordinary IP-layer loss: TCP retransmits.
            if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut
            {
                warn!("system TUN send queue full, dropping batch: {e}");
                continue;
            }
            return Err(Error::Operation(format!(
                "system TUN batched write failed: {e}"
            )));
        }
    }
}

/// Drains UDP downlink packets in batches and writes them with one coalesced
/// device operation per batch.
#[cfg(target_os = "linux")]
async fn batched_udp_downlink(
    device: Arc<tun_rs::AsyncDevice>,
    mut udp_outbound_rx: mpsc::Receiver<watfaq_netstack::Packet>,
    mtu: usize,
) -> Result<(), Error> {
    use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

    let mut gro = GROTable::new();
    let mut queued: Vec<watfaq_netstack::Packet> =
        Vec::with_capacity(IDEAL_BATCH_SIZE);
    let mut bufs: Vec<BytesMut> = Vec::with_capacity(IDEAL_BATCH_SIZE);

    loop {
        queued.clear();
        // recv_many blocks for the first packet, then takes whatever else is
        // already queued, so a quiet link still gets single-packet latency.
        if udp_outbound_rx
            .recv_many(&mut queued, IDEAL_BATCH_SIZE)
            .await
            == 0
        {
            return Err(Error::Operation(
                "tun system stack UDP downlink stopped unexpectedly".to_string(),
            ));
        }

        // Grow the buffer pool to this batch, then reuse the buffers rather
        // than reallocating one per packet: the pool settles at the largest
        // batch seen and stays allocated for the connection's lifetime.
        while bufs.len() < queued.len() {
            bufs.push(BytesMut::with_capacity(VIRTIO_NET_HDR_LEN + mtu));
        }
        for (buf, packet) in bufs.iter_mut().zip(&queued) {
            let data = packet.data();
            buf.clear();
            // The codec hands us a plain IP packet; give it the headroom
            // send_multiple needs for the virtio header.
            buf.resize(VIRTIO_NET_HDR_LEN, 0);
            buf.extend_from_slice(data);
        }

        if let Err(e) = device
            .send_multiple(&mut gro, &mut bufs[..queued.len()], VIRTIO_NET_HDR_LEN)
            .await
        {
            if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut
            {
                warn!("system TUN send queue full, dropping UDP batch: {e}");
                continue;
            }
            return Err(Error::Operation(format!(
                "system TUN UDP downlink write failed: {e}"
            )));
        }
    }
}

/// Per-packet TUN I/O for platforms without the batched offload API.
#[cfg(not(target_os = "linux"))]
async fn tun_io(
    device: tun_rs::AsyncDevice,
    ctx: PacketContext,
    mut udp_outbound_rx: mpsc::Receiver<watfaq_netstack::Packet>,
    _mtu: usize,
) -> Result<(), Error> {
    let framed = tun_rs::async_framed::DeviceFramed::new(
        device,
        tun_rs::async_framed::BytesCodec::new(),
    );
    let (mut tun_sink, mut tun_stream) = framed.split::<Bytes>();
    // The sink has a single owner, so both producers funnel through a queue.
    let (writer_tx, mut writer_rx) = mpsc::channel::<Bytes>(SYSTEM_WRITE_QUEUE);

    let fut_writer = async move {
        while let Some(packet) = writer_rx.recv().await {
            if let Err(e) = tun_sink.send(packet).await {
                // TimedOut means the Wintun/TUN send ring buffer was full for
                // too long (driver backpressure). Drop the packet and keep the
                // runner alive — packet loss is normal at the IP layer.
                if e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock
                {
                    warn!("tun send buffer full, dropping packet: {e}");
                    continue;
                }
                return Err(Error::Operation(format!(
                    "failed to send pkt to tun: {e}"
                )));
            }
        }
        Err(Error::Operation(
            "tun system stack writer stopped unexpectedly".to_string(),
        ))
    };

    let fut_udp_downlink = {
        let writer_tx = writer_tx.clone();
        async move {
            while let Some(packet) = udp_outbound_rx.recv().await {
                if writer_tx.send(packet.into_bytes()).await.is_err() {
                    break;
                }
            }
            Err(Error::Operation(
                "tun system stack UDP downlink stopped unexpectedly".to_string(),
            ))
        }
    };

    let fut_read = async move {
        while let Some(packet) = tun_stream.next().await {
            let mut packet: BytesMut = match packet {
                Ok(packet) => packet,
                Err(e) => {
                    return Err(Error::Operation(format!("tun stream error: {e}")));
                }
            };
            if ctx.process(&mut packet) == Disposition::WriteBack
                && writer_tx.send(packet.freeze()).await.is_err()
            {
                break;
            }
        }
        Err(Error::Operation(
            "tun system stack read loop stopped unexpectedly".to_string(),
        ))
    };

    tokio::select! {
        res = fut_writer => res,
        res = fut_udp_downlink => res,
        res = fut_read => res,
    }
}

/// Rewrites an uplink or downlink IPv4 TCP packet in place. Returns `None`
/// when the packet should be dropped.
fn process_tcp_v4(
    packet: &mut [u8],
    view: Ipv4View,
    nat: &TcpNat,
    tun_address: Ipv4Addr,
    nat_address: Ipv4Addr,
    listener_port: u16,
) -> Option<()> {
    let tcp = view.header_len;
    if view.total_len < tcp + TCP_MIN_HEADER {
        return None;
    }
    let source_port = read_u16(packet, tcp);
    let destination_port = read_u16(packet, tcp + 2);
    let rewritten = if view.source == tun_address && source_port == listener_port {
        // Downlink: a reply from the kernel listener back to the NAT
        // address; restore the original five-tuple.
        let entry = nat.lookup_back(destination_port)?;
        match (entry.key.destination, entry.key.source) {
            (SocketAddr::V4(destination), SocketAddr::V4(source)) => {
                rewrite_ipv4_tcp(packet, view.header_len, destination, source)
            }
            _ => Err(io::Error::other("IPv4 TCP NAT address family mismatch")),
        }
    } else {
        // Uplink: redirect the flow to the kernel listener, sourced from
        // the NAT address so replies come back through the TUN.
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(view.source, source_port)),
            destination: SocketAddr::V4(SocketAddrV4::new(
                view.destination,
                destination_port,
            )),
        };
        match nat.lookup_or_insert(key) {
            Ok(port) => rewrite_ipv4_tcp(
                packet,
                view.header_len,
                SocketAddrV4::new(nat_address, port),
                SocketAddrV4::new(tun_address, listener_port),
            ),
            Err(e) => Err(e),
        }
    };
    match rewritten {
        Ok(()) => Some(()),
        Err(e) => {
            trace!("system TUN IPv4 TCP rewrite failed: {}", e);
            None
        }
    }
}

/// Rewrites an uplink or downlink IPv6 TCP packet in place. Returns `None`
/// when the packet should be dropped.
fn process_tcp_v6(
    packet: &mut [u8],
    view: Ipv6View,
    nat: &TcpNat,
    tun_address: Ipv6Addr,
    nat_address: Ipv6Addr,
    listener_port: u16,
) -> Option<()> {
    let tcp = view.transport_offset;
    if view.total_len < tcp + TCP_MIN_HEADER {
        return None;
    }
    let source_port = read_u16(packet, tcp);
    let destination_port = read_u16(packet, tcp + 2);
    let rewritten = if view.source == tun_address && source_port == listener_port {
        let entry = nat.lookup_back(destination_port)?;
        match (entry.key.destination, entry.key.source) {
            (SocketAddr::V6(destination), SocketAddr::V6(source)) => {
                rewrite_ipv6_tcp(packet, tcp, destination, source)
            }
            _ => Err(io::Error::other("IPv6 TCP NAT address family mismatch")),
        }
    } else {
        let key = TcpKey {
            source: SocketAddr::V6(SocketAddrV6::new(
                view.source,
                source_port,
                0,
                0,
            )),
            destination: SocketAddr::V6(SocketAddrV6::new(
                view.destination,
                destination_port,
                0,
                0,
            )),
        };
        match nat.lookup_or_insert(key) {
            Ok(port) => rewrite_ipv6_tcp(
                packet,
                tcp,
                SocketAddrV6::new(nat_address, port, 0, 0),
                SocketAddrV6::new(tun_address, listener_port, 0, 0),
            ),
            Err(e) => Err(e),
        }
    };
    match rewritten {
        Ok(()) => Some(()),
        Err(e) => {
            trace!("system TUN IPv6 TCP rewrite failed: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_rewrite_updates_the_four_tuple_in_place() {
        let mut packet = [0u8; 40];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        write_u16(&mut packet, 2, packet_len);
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 9]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        write_u16(&mut packet, 20, 12345);
        write_u16(&mut packet, 22, 443);
        packet[32] = 0x50;
        let header_checksum = checksum(&packet[..20]);
        write_u16(&mut packet, 10, header_checksum);
        rewrite_ipv4_tcp(
            &mut packet,
            20,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 233, 3), 10000),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 233, 2), 20000),
        )
        .unwrap();
        assert_eq!(&packet[12..16], &[192, 168, 233, 3]);
        assert_eq!(&packet[16..20], &[192, 168, 233, 2]);
        assert_eq!(read_u16(&packet, 20), 10000);
        assert_eq!(read_u16(&packet, 22), 20000);
        // the incrementally updated IP checksum must match a full
        // recomputation
        let updated = read_u16(&packet, 10);
        write_u16(&mut packet, 10, 0);
        assert_eq!(updated, checksum(&packet[..20]));
    }

    #[test]
    fn tcp_nat_keeps_a_stable_port_and_removes_it() {
        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                34567,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let port = nat.lookup_or_insert(key).unwrap();
        assert_eq!(nat.lookup_or_insert(key).unwrap(), port);
        assert_eq!(nat.lookup_back(port).unwrap().key, key);
        let (_, generation) = nat.accept(port).unwrap();
        nat.remove_if_generation(port, generation);
        assert!(nat.lookup_back(port).is_none());
    }

    #[test]
    fn tcp_nat_cleanup_reclaims_unaccepted_entries() {
        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                34567,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let port = nat.lookup_or_insert(key).unwrap();
        let accepted_key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 3),
                34567,
            )),
            ..key
        };
        let accepted_port = nat.lookup_or_insert(accepted_key).unwrap();
        assert!(nat.accept(accepted_port).is_some());
        nat.cleanup(Duration::ZERO);
        assert!(nat.lookup_back(port).is_none());
        assert!(nat.lookup_back(accepted_port).is_some());
    }

    #[test]
    fn linger_removal_spares_a_reused_port() {
        // A finished connection's linger must not tear down a fresh
        // connection that reused the same five-tuple (and thus NAT port)
        // within the linger window.
        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                34567,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let port = nat.lookup_or_insert(key).unwrap();
        let (_, gen_a) = nat.accept(port).unwrap(); // connection A
        // A finishes; a new connection B reuses the same tuple → same port,
        // fresh generation.
        assert_eq!(nat.lookup_or_insert(key).unwrap(), port);
        let (_, gen_b) = nat.accept(port).unwrap();
        assert_ne!(gen_a, gen_b);
        // A's linger fires with the stale generation — must be a no-op.
        nat.remove_if_generation(port, gen_a);
        assert!(nat.lookup_back(port).is_some(), "B's mapping was torn down");
        // B's own linger removes it.
        nat.remove_if_generation(port, gen_b);
        assert!(nat.lookup_back(port).is_none());
    }

    #[test]
    fn lookup_or_insert_does_not_return_another_flows_port() {
        // Forcing a forward entry to point at a port owned by a different key
        // must not hand that port to this key.
        let nat = TcpNat::new();
        let key_a = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                1111,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let key_b = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 3),
                2222,
            )),
            ..key_a
        };
        let port_a = nat.lookup_or_insert(key_a).unwrap();
        let port_b = nat.lookup_or_insert(key_b).unwrap();
        assert_ne!(port_a, port_b);
        // Both flows keep their own distinct ports on re-lookup.
        assert_eq!(nat.lookup_or_insert(key_a).unwrap(), port_a);
        assert_eq!(nat.lookup_or_insert(key_b).unwrap(), port_b);
    }

    #[test]
    fn icmp_echo_for_tun_address_is_replied_in_place() {
        let mut packet = [0u8; 28];
        packet[0] = 0x45;
        write_u16(&mut packet, 2, 28);
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 9]);
        packet[16..20].copy_from_slice(&[192, 168, 233, 2]);
        packet[20] = 8;
        packet[24..28].copy_from_slice(b"ping");
        let icmp_checksum = checksum(&packet[20..]);
        write_u16(&mut packet, 22, icmp_checksum);
        let ip_checksum = checksum(&packet[..20]);
        write_u16(&mut packet, 10, ip_checksum);
        let view = parse_ipv4(&packet).unwrap();
        assert!(make_icmp_echo_reply(
            &mut packet,
            view,
            Ipv4Addr::new(192, 168, 233, 2),
        ));
        assert_eq!(packet[20], 0);
        assert_eq!(&packet[12..16], &[192, 168, 233, 2]);
        assert_eq!(&packet[16..20], &[10, 0, 0, 9]);
    }

    #[test]
    fn ipv6_tcp_rewrite_updates_the_four_tuple_in_place() {
        let mut packet = [0u8; 60];
        packet[0] = 0x60;
        write_u16(&mut packet, 4, 20);
        packet[6] = 6;
        packet[8..24]
            .copy_from_slice(&"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(
            &"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets(),
        );
        write_u16(&mut packet, 40, 12345);
        write_u16(&mut packet, 42, 443);
        packet[52] = 0x50;
        // Start from a correct checksum: an incremental update applied to a
        // zero checksum would look plausible while being wrong.
        let original = checksum_ipv6_transport(&packet, 40, 6);
        write_u16(&mut packet, 56, original);
        rewrite_ipv6_tcp(
            &mut packet,
            40,
            SocketAddrV6::new("2001:2::3".parse().unwrap(), 10000, 0, 0),
            SocketAddrV6::new("2001:2::2".parse().unwrap(), 20000, 0, 0),
        )
        .unwrap();
        assert_eq!(
            &packet[8..24],
            &"2001:2::3".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            &packet[24..40],
            &"2001:2::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(read_u16(&packet, 40), 10000);
        assert_eq!(read_u16(&packet, 42), 20000);
        // the incrementally updated checksum must match a full recomputation
        let updated = read_u16(&packet, 56);
        write_u16(&mut packet, 56, 0);
        assert_eq!(updated, checksum_ipv6_transport(&packet, 40, 6));
    }

    /// The downlink branch of `process_tcp_v4`: a reply from the kernel
    /// listener must be rewritten back to the original five-tuple.
    #[test]
    fn downlink_tcp_v4_is_restored_to_the_original_tuple() {
        let client = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 12345);
        let server = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443);
        let tun_address = Ipv4Addr::new(198, 18, 0, 1);
        let nat_address = Ipv4Addr::new(198, 18, 0, 2);
        let listener_port = 40000;

        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(client),
            destination: SocketAddr::V4(server),
        };
        let nat_port = nat.lookup_or_insert(key).unwrap();

        // a reply travelling tun_address:listener_port -> nat_address:nat_port
        let mut packet = BytesMut::zeroed(40);
        packet[0] = 0x45;
        write_u16(&mut packet, 2, 40);
        packet[9] = 6;
        packet[12..16].copy_from_slice(&tun_address.octets());
        packet[16..20].copy_from_slice(&nat_address.octets());
        write_u16(&mut packet, 20, listener_port);
        write_u16(&mut packet, 22, nat_port);
        packet[32] = 0x50;
        let ip_checksum = checksum(&packet[..20]);
        write_u16(&mut packet, 10, ip_checksum);

        let view = parse_ipv4(&packet).unwrap();
        assert!(
            process_tcp_v4(
                &mut packet,
                view,
                &nat,
                tun_address,
                nat_address,
                listener_port,
            )
            .is_some()
        );

        // the client must see the packet as coming straight from the server
        assert_eq!(&packet[12..16], &server.ip().octets());
        assert_eq!(&packet[16..20], &client.ip().octets());
        assert_eq!(read_u16(&packet, 20), server.port());
        assert_eq!(read_u16(&packet, 22), client.port());
        let updated = read_u16(&packet, 10);
        write_u16(&mut packet, 10, 0);
        assert_eq!(updated, checksum(&packet[..20]));
    }

    /// A downlink packet whose NAT port is unknown must be dropped rather
    /// than forwarded with a bogus tuple.
    #[test]
    fn downlink_tcp_v4_without_a_mapping_is_dropped() {
        let tun_address = Ipv4Addr::new(198, 18, 0, 1);
        let nat_address = Ipv4Addr::new(198, 18, 0, 2);
        let listener_port = 40000;
        let nat = TcpNat::new();

        let mut packet = BytesMut::zeroed(40);
        packet[0] = 0x45;
        write_u16(&mut packet, 2, 40);
        packet[9] = 6;
        packet[12..16].copy_from_slice(&tun_address.octets());
        packet[16..20].copy_from_slice(&nat_address.octets());
        write_u16(&mut packet, 20, listener_port);
        write_u16(&mut packet, 22, 55555); // never allocated
        packet[32] = 0x50;

        let view = parse_ipv4(&packet).unwrap();
        assert!(
            process_tcp_v4(
                &mut packet,
                view,
                &nat,
                tun_address,
                nat_address,
                listener_port,
            )
            .is_none()
        );
    }

    /// The buffer set must hold every segment a full 64 KiB GRO read can split
    /// into down to the MSS floor; otherwise `recv_multiple` errors. The count
    /// is MTU-independent — sized from the segment floor, not the MTU, since
    /// the flow's MSS (not our MTU) determines the segment size.
    #[cfg(target_os = "linux")]
    #[test]
    fn receive_batch_size_covers_the_segment_floor() {
        use tun_rs::IDEAL_BATCH_SIZE;

        let count = receive_batch_size();
        // Must cover a 64 KiB read split at the 48-byte TCP_MIN_SND_MSS floor.
        let needed = (u16::MAX as usize).div_ceil(48);
        assert!(
            count >= needed,
            "{count} buffers cannot hold {needed} floor-sized segments"
        );
        assert!(count >= IDEAL_BATCH_SIZE);
    }

    #[test]
    fn cleanup_keeps_an_entry_refreshed_after_the_scan() {
        let nat = TcpNat::new();
        let key = TcpKey {
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 2),
                34567,
            )),
            destination: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(1, 1, 1, 1),
                443,
            )),
        };
        let port = nat.lookup_or_insert(key).unwrap();
        // Simulates cleanup having already decided the port was expired,
        // with a packet for the same flow arriving before the removal.
        nat.lookup_or_insert(key).unwrap();
        nat.remove_if_still_expired(port, Duration::from_secs(30));
        assert!(
            nat.lookup_back(port).is_some(),
            "a refreshed mapping must survive cleanup"
        );
    }

    #[test]
    fn icmpv6_echo_for_tun_address_is_replied_in_place() {
        let source = "2001:db8::9".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:2::2".parse::<Ipv6Addr>().unwrap();
        let mut packet = [0u8; 48];
        packet[0] = 0x60;
        write_u16(&mut packet, 4, 8);
        packet[6] = 58;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40] = 128;
        let checksum = checksum_ipv6_transport(&packet, 40, 58);
        write_u16(&mut packet, 42, checksum);
        let view = parse_ipv6(&packet).unwrap();
        assert!(make_icmpv6_echo_reply(&mut packet, view, destination));
        assert_eq!(packet[40], 129);
        assert_eq!(&packet[8..24], &destination.octets());
        assert_eq!(&packet[24..40], &source.octets());
    }

    #[test]
    fn nat_address_derivation_validates_the_prefix() {
        assert_eq!(
            ipv4_nat_address("198.18.0.1/24".parse().unwrap()).unwrap(),
            Ipv4Addr::new(198, 18, 0, 2)
        );
        // /32 leaves no room for the adjacent NAT address
        assert!(ipv4_nat_address("198.18.0.1/32".parse().unwrap()).is_err());
        // gateway at the end of the prefix: NAT address would be broadcast
        assert!(ipv4_nat_address("198.18.0.254/24".parse().unwrap()).is_err());
        assert_eq!(
            ipv6_adjacent_address("2001:fac::1".parse().unwrap(), 64).unwrap(),
            "2001:fac::2".parse::<Ipv6Addr>().unwrap()
        );
        assert!(ipv6_adjacent_address("2001:fac::1".parse().unwrap(), 128).is_err());
    }
}
