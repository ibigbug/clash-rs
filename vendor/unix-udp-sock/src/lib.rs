//! Uniform interface to send/recv UDP packets with ECN information.
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

pub use crate::cmsg::{AsPtr, EcnCodepoint, Source, Transmit};
use tracing::warn;

mod cmsg;

#[path = "unix.rs"]
mod imp;

pub use imp::{sync, UdpSocket};
pub mod framed;

/// Number of UDP packets to send/receive at a time
pub const BATCH_SIZE: usize = imp::BATCH_SIZE;

/// The capabilities a UDP socket suppports on a certain platform
#[derive(Debug)]
pub struct UdpState {
    max_gso_segments: AtomicUsize,
    gro_segments: usize,
}

impl UdpState {
    pub fn new() -> Self {
        imp::udp_state()
    }

    /// The maximum amount of segments which can be transmitted if a platform
    /// supports Generic Send Offload (GSO).
    ///
    /// This is 1 if the platform doesn't support GSO. Subject to change if errors are detected
    /// while using GSO.
    #[inline]
    pub fn max_gso_segments(&self) -> usize {
        self.max_gso_segments.load(Ordering::Relaxed)
    }

    /// The number of segments to read when GRO is enabled. Used as a factor to
    /// compute the receive buffer size.
    ///
    /// Returns 1 if the platform doesn't support GRO.
    #[inline]
    pub fn gro_segments(&self) -> usize {
        self.gro_segments
    }
}

impl Default for UdpState {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata about received packet. Includes which address we
/// recv'd from, how many bytes, ecn codepoints, what the
/// destination IP used was and what interface index was used.
#[derive(Debug, Copy, Clone)]
pub struct RecvMeta {
    /// address we received datagram on
    pub addr: SocketAddr,
    /// length of datagram
    pub len: usize,
    /// received datagram stride
    pub stride: usize,
    /// ECN codepoint
    pub ecn: Option<EcnCodepoint>,
    /// The destination IP address for this datagram (ipi_addr)
    pub dst_ip: Option<IpAddr>,
    /// The destination local IP address for this datagram (ipi_spec_dst)
    pub dst_local_ip: Option<IpAddr>,
    /// interface index that datagram was received on
    pub ifindex: u32,
    pub orig_dst: Option<SocketAddr>,
}

impl Default for RecvMeta {
    /// Constructs a value with arbitrary fields, intended to be overwritten
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
            dst_local_ip: None,
            ifindex: 0,
            orig_dst: None,
        }
    }
}

/// Log at most 1 IO error per minute
const IO_ERROR_LOG_INTERVAL: Duration = std::time::Duration::from_secs(60);

/// Logs a warning message when sendmsg fails
///
/// Logging will only be performed if at least [`IO_ERROR_LOG_INTERVAL`]
/// has elapsed since the last error was logged.
fn log_sendmsg_error<B: AsPtr<u8>>(
    last_send_error: &mut Instant,
    err: impl core::fmt::Debug,
    transmit: &Transmit<B>,
) {
    let now = Instant::now();
    if now.saturating_duration_since(*last_send_error) > IO_ERROR_LOG_INTERVAL {
        *last_send_error = now;
        warn!(
        "sendmsg error: {:?}, Transmit: {{ destination: {:?}, src_ip: {:?}, enc: {:?}, len: {:?}, segment_size: {:?} }}",
            err, transmit.dst, transmit.src, transmit.ecn, transmit.contents.len(), transmit.segment_size);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_create() {
        let s = sync::UdpSocket::bind("0.0.0.0:9909");
        assert!(s.is_ok());
    }
    #[test]
    fn test_send_recv() {
        let saddr = "0.0.0.0:9901".parse().unwrap();
        let a = sync::UdpSocket::bind(saddr).unwrap();
        let b = sync::UdpSocket::bind("0.0.0.0:0").unwrap();
        let buf = b"hello world";
        b.send_to(&buf[..], saddr).unwrap();
        // recv
        let mut r = [0; 1024];
        a.recv_from(&mut r).unwrap();
        assert_eq!(buf[..], r[..11]);
    }
    #[test]
    fn test_send_recv_msg() {
        let saddr = "0.0.0.0:9902".parse().unwrap();
        let a = sync::UdpSocket::bind(saddr).unwrap();
        let b = sync::UdpSocket::bind("0.0.0.0:0").unwrap();
        let send_port = b.local_addr().unwrap().port();
        let send_addr = b.local_addr().unwrap().ip();
        let buf = b"hello world";
        let src = Source::Interface(1);
        let tr = Transmit::new(saddr, *buf).src_ip(src);
        b.send_msg(&UdpState::new(), tr).unwrap();
        // recv
        let mut r = [0; 1024];
        let meta = a.recv_msg(&mut r).unwrap();
        assert_eq!(buf[..], r[..11]);
        // dst addr and b addr matches!
        // meta.ifindex
        assert_eq!(send_port, meta.addr.port());
        assert_eq!(meta.ifindex, 1);
        assert!(matches!(
            meta.dst_local_ip,
            // dst_local_ip might be 127.0.0.1
            Some(addr) if addr == send_addr || addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }
    #[test]
    fn test_send_recv_msg_ip() {
        let saddr = "0.0.0.0:9903".parse().unwrap();
        let a = sync::UdpSocket::bind(saddr).unwrap();
        let b = sync::UdpSocket::bind("0.0.0.0:0").unwrap();
        let send_port = b.local_addr().unwrap().port();
        let send_addr = b.local_addr().unwrap().ip();
        let buf = b"hello world";
        let src = Source::Ip("0.0.0.0".parse().unwrap());
        let tr = Transmit::new(saddr, *buf).src_ip(src);
        b.send_msg(&UdpState::new(), tr).unwrap();
        // recv
        let mut r = [0; 1024];
        let meta = a.recv_msg(&mut r).unwrap();
        assert_eq!(buf[..], r[..11]);
        // dst addr and b addr matches!
        // meta.ifindex
        assert_eq!(send_port, meta.addr.port());
        assert_eq!(meta.ifindex, 1);
        assert!(matches!(
            meta.dst_local_ip,
            // dst_local_ip might be 127.0.0.1
            Some(addr) if addr == send_addr || addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
    }
}
