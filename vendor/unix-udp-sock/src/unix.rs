#![allow(clippy::unnecessary_cast)]
use std::{
    io,
    io::IoSliceMut,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::AsRawFd,
    sync::atomic::AtomicUsize,
    task::{Context, Poll},
    time::Instant,
};

use crate::cmsg::{AsPtr, EcnCodepoint, Source, Transmit};
use futures_core::ready;
use socket2::SockRef;
use tokio::{
    io::{Interest, ReadBuf},
    net::ToSocketAddrs,
};

use super::{cmsg, log_sendmsg_error, RecvMeta, UdpState, IO_ERROR_LOG_INTERVAL};

#[cfg(target_os = "freebsd")]
type IpTosTy = libc::c_uchar;
#[cfg(not(target_os = "freebsd"))]
type IpTosTy = libc::c_int;

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
#[derive(Debug)]
pub struct UdpSocket {
    io: tokio::net::UdpSocket,
    last_send_error: Instant,
}

impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.io.as_raw_fd()
    }
}

impl UdpSocket {
    /// Creates a new UDP socket from a previously created `std::net::UdpSocket`
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        socket.set_nonblocking(true)?;

        init(SockRef::from(&socket))?;
        let now = Instant::now();
        Ok(UdpSocket {
            io: tokio::net::UdpSocket::from_std(socket)?,
            last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),
        })
    }

    pub fn into_std(self) -> io::Result<std::net::UdpSocket> {
        self.io.into_std()
    }

    /// create a new UDP socket and attempt to bind to `addr`
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
        let io = tokio::net::UdpSocket::bind(addr).await?;
        init(SockRef::from(&io))?;
        let now = Instant::now();
        Ok(UdpSocket {
            io,
            last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),
        })
    }

    /// sets the value of SO_BROADCAST for this socket
    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        self.io.set_broadcast(broadcast)
    }

    pub async fn connect<A: ToSocketAddrs>(&self, addrs: A) -> io::Result<()> {
        self.io.connect(addrs).await
    }
    pub async fn join_multicast_v4(
        &self,
        multiaddr: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> io::Result<()> {
        self.io.join_multicast_v4(multiaddr, interface)
    }
    pub async fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.io.join_multicast_v6(multiaddr, interface)
    }
    pub async fn leave_multicast_v4(
        &self,
        multiaddr: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> io::Result<()> {
        self.io.leave_multicast_v4(multiaddr, interface)
    }
    pub async fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        self.io.leave_multicast_v6(multiaddr, interface)
    }
    pub async fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.io.set_multicast_loop_v4(on)
    }
    pub async fn set_multicast_loop_v6(&self, on: bool) -> io::Result<()> {
        self.io.set_multicast_loop_v6(on)
    }
    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    /// calls underlying tokio [`send_to`]
    ///
    /// [`send_to`]: method@tokio::net::UdpSocket::send_to
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.io.send_to(buf, target).await
    }
    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    /// calls underlying tokio [`poll_send_to`]
    ///
    /// [`poll_send_to`]: method@tokio::net::UdpSocket::poll_send_to
    pub fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.io.poll_send_to(cx, buf, target)
    }
    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    ///
    /// See tokio [`send`]
    ///
    /// [`send`]: method@tokio::net::UdpSocket::send
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.io.send(buf).await
    }
    /// Sends data on the socket to the remote address that the socket is
    /// connected to.
    ///
    /// See tokio [`poll_send`]
    ///
    /// [`poll_send`]: method@tokio::net::UdpSocket::poll_send
    pub async fn poll_send(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.io.poll_send(cx, buf)
    }
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    ///
    /// See tokio [`recv_from`]
    ///
    /// [`recv_from`]: method@tokio::net::UdpSocket::recv_from
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.io.recv_from(buf).await
    }
    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    ///
    /// See tokio [`poll_recv_from`]
    ///
    /// [`poll_recv_from`]: method@tokio::net::UdpSocket::poll_recv_from
    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.io.poll_recv_from(cx, buf)
    }
    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    /// See tokio [`recv`]
    ///
    /// [`recv`]: method@tokio::net::UdpSocket::recv
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.recv(buf).await
    }
    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    ///
    /// See tokio [`poll_recv`]
    ///
    /// [`poll_recv`]: method@tokio::net::UdpSocket::poll_recv
    pub fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.io.poll_recv(cx, buf)
    }

    /// Calls syscall [`sendmmsg`]. With a given `state` configured GSO and
    /// `transmits` with information on the data and metadata about outgoing packets.
    ///
    /// [`sendmmsg`]: https://linux.die.net/man/2/sendmmsg
    pub async fn send_mmsg<B: AsPtr<u8>>(
        &mut self,
        state: &UdpState,
        transmits: &[Transmit<B>],
    ) -> Result<usize, io::Error> {
        let n = loop {
            self.io.writable().await?;
            let last_send_error = &mut self.last_send_error;
            let io = &self.io;
            match io.try_io(Interest::WRITABLE, || {
                send(state, SockRef::from(io), last_send_error, transmits)
            }) {
                Ok(res) => break res,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        };
        // if n == transmits.len() {}
        Ok(n)
    }

    /// Calls syscall [`sendmsg`]. With a given `state` configured GSO and
    /// `transmit` with information on the data and metadata about outgoing packet.
    ///
    /// [`sendmsg`]: https://linux.die.net/man/2/sendmsg
    pub async fn send_msg<B: AsPtr<u8>>(
        &self,
        state: &UdpState,
        transmits: Transmit<B>,
    ) -> io::Result<usize> {
        let n = loop {
            self.io.writable().await?;
            let io = &self.io;
            match io.try_io(Interest::WRITABLE, || {
                send_msg(state, SockRef::from(io), &transmits)
            }) {
                Ok(res) => break res,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        };
        Ok(n)
    }

    /// async version of `recvmmsg`
    pub async fn recv_mmsg(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        debug_assert!(!bufs.is_empty());
        loop {
            self.io.readable().await?;
            let io = &self.io;
            match io.try_io(Interest::READABLE, || recv(SockRef::from(io), bufs, meta)) {
                Ok(res) => return Ok(res),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// `recv_msg` is similar to `recv_from` but returns extra information
    /// about the packet in [`RecvMeta`].
    ///
    /// [`RecvMeta`]: crate::RecvMeta
    pub async fn recv_msg(&self, buf: &mut [u8]) -> io::Result<RecvMeta> {
        let mut iov = IoSliceMut::new(buf);
        debug_assert!(!iov.is_empty());
        loop {
            self.io.readable().await?;
            let io = &self.io;
            match io.try_io(Interest::READABLE, || recv_msg(SockRef::from(io), &mut iov)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return result,
            }
        }
    }

    /// calls `sendmmsg`
    pub fn poll_send_mmsg<B: AsPtr<u8>>(
        &mut self,
        state: &UdpState,
        cx: &mut Context,
        transmits: &[Transmit<B>],
    ) -> Poll<io::Result<usize>> {
        loop {
            let last_send_error = &mut self.last_send_error;
            ready!(self.io.poll_send_ready(cx))?;
            let io = &self.io;
            match io.try_io(Interest::WRITABLE, || {
                send(state, SockRef::from(io), last_send_error, transmits)
            }) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
    /// calls `sendmsg`
    pub fn poll_send_msg<B: AsPtr<u8>>(
        &self,
        state: &UdpState,
        cx: &mut Context,
        transmits: Transmit<B>,
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_send_ready(cx))?;
            let io = &self.io;
            match io.try_io(Interest::WRITABLE, || {
                send_msg(state, SockRef::from(io), &transmits)
            }) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }

    /// calls `recvmsg`
    pub fn poll_recv_msg(
        &self,
        cx: &mut Context,
        buf: &mut IoSliceMut<'_>,
    ) -> Poll<io::Result<RecvMeta>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let io = &self.io;
            match io.try_io(Interest::READABLE, || recv_msg(SockRef::from(io), buf)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }

    /// calls `recvmmsg`
    pub fn poll_recv_mmsg(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let io = &self.io;
            match io.try_io(Interest::READABLE, || recv(SockRef::from(io), bufs, meta)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }

    /// Returns local address this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

pub mod sync {

    use std::os::unix::prelude::IntoRawFd;

    use super::*;

    #[derive(Debug)]
    pub struct UdpSocket {
        io: std::net::UdpSocket,
        last_send_error: Instant,
    }

    impl AsRawFd for UdpSocket {
        fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
            self.io.as_raw_fd()
        }
    }
    impl IntoRawFd for UdpSocket {
        fn into_raw_fd(self) -> std::os::unix::prelude::RawFd {
            self.io.into_raw_fd()
        }
    }

    impl UdpSocket {
        /// Creates a new UDP socket from a previously created `std::net::UdpSocket`
        pub fn from_std(socket: std::net::UdpSocket) -> io::Result<Self> {
            init(SockRef::from(&socket))?;
            socket.set_nonblocking(false)?;
            let now = Instant::now();
            Ok(Self {
                io: socket,
                last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),
            })
        }
        /// create a new UDP socket and attempt to bind to `addr`
        pub fn bind<A: std::net::ToSocketAddrs>(addr: A) -> io::Result<Self> {
            let io = std::net::UdpSocket::bind(addr)?;
            init(SockRef::from(&io))?;
            io.set_nonblocking(false)?;
            let now = Instant::now();
            Ok(Self {
                io,
                last_send_error: now.checked_sub(2 * IO_ERROR_LOG_INTERVAL).unwrap_or(now),
            })
        }
        /// sets nonblocking mode
        pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
            self.io.set_nonblocking(nonblocking)
        }
        /// sets the value of SO_BROADCAST for this socket
        pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
            self.io.set_broadcast(broadcast)
        }
        pub fn connect<A: std::net::ToSocketAddrs>(&self, addrs: A) -> io::Result<()> {
            self.io.connect(addrs)
        }
        pub fn join_multicast_v4(
            &self,
            multiaddr: Ipv4Addr,
            interface: Ipv4Addr,
        ) -> io::Result<()> {
            self.io.join_multicast_v4(&multiaddr, &interface)
        }
        pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
            self.io.join_multicast_v6(multiaddr, interface)
        }
        pub fn leave_multicast_v4(
            &self,
            multiaddr: Ipv4Addr,
            interface: Ipv4Addr,
        ) -> io::Result<()> {
            self.io.leave_multicast_v4(&multiaddr, &interface)
        }
        pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
            self.io.leave_multicast_v6(multiaddr, interface)
        }
        pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
            self.io.set_multicast_loop_v4(on)
        }
        pub fn set_multicast_loop_v6(&self, on: bool) -> io::Result<()> {
            self.io.set_multicast_loop_v6(on)
        }
        /// Sends data on the socket to the given address. On success, returns the
        /// number of bytes written.
        ///
        /// calls underlying tokio [`send_to`]
        ///
        /// [`send_to`]: method@tokio::net::UdpSocket::send_to
        pub fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
            self.io.send_to(buf, target)
        }
        /// Sends data on the socket to the remote address that the socket is
        /// connected to.
        ///
        /// See tokio [`send`]
        ///
        /// [`send`]: method@tokio::net::UdpSocket::send
        pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.io.send(buf)
        }
        /// Receives a single datagram message on the socket. On success, returns
        /// the number of bytes read and the origin.
        ///
        /// See tokio [`recv_from`]
        ///
        /// [`recv_from`]: method@tokio::net::UdpSocket::recv_from
        pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.io.recv_from(buf)
        }
        /// Receives a single datagram message on the socket from the remote address
        /// to which it is connected. On success, returns the number of bytes read.
        ///
        /// See tokio [`recv`]
        ///
        /// [`recv`]: method@tokio::net::UdpSocket::recv
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.io.recv(buf)
        }
        /// Calls syscall [`sendmmsg`]. With a given `state` configured GSO and
        /// `transmits` with information on the data and metadata about outgoing packets.
        ///
        /// [`sendmmsg`]: https://linux.die.net/man/2/sendmmsg
        pub fn send_mmsg<B: AsPtr<u8>>(
            &mut self,
            state: &UdpState,
            transmits: &[Transmit<B>],
        ) -> Result<usize, io::Error> {
            send(
                state,
                SockRef::from(&self.io),
                &mut self.last_send_error,
                transmits,
            )
        }
        /// Calls syscall [`sendmsg`]. With a given `state` configured GSO and
        /// `transmit` with information on the data and metadata about outgoing packet.
        ///
        /// [`sendmsg`]: https://linux.die.net/man/2/sendmsg
        pub fn send_msg<B: AsPtr<u8>>(
            &self,
            state: &UdpState,
            transmits: Transmit<B>,
        ) -> io::Result<usize> {
            send_msg(state, SockRef::from(&self.io), &transmits)
        }

        /// async version of `recvmmsg`
        pub fn recv_mmsg(
            &self,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> io::Result<usize> {
            debug_assert!(!bufs.is_empty());
            recv(SockRef::from(&self.io), bufs, meta)
        }

        /// `recv_msg` is similar to `recv_from` but returns extra information
        /// about the packet in [`RecvMeta`].
        ///
        /// [`RecvMeta`]: crate::RecvMeta
        pub fn recv_msg(&self, buf: &mut [u8]) -> io::Result<RecvMeta> {
            let mut iov = IoSliceMut::new(buf);
            debug_assert!(!iov.is_empty());

            recv_msg(SockRef::from(&self.io), &mut iov)
        }
        /// Returns local address this socket is bound to.
        pub fn local_addr(&self) -> io::Result<SocketAddr> {
            self.io.local_addr()
        }
    }
}

fn set_socket_option<Fd: AsRawFd>(
    socket: &Fd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> Result<(), io::Error> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as _,
            mem::size_of_val(&value) as _,
        )
    };

    if rc != -1 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

const OPTION_ON: libc::c_int = 1;

fn init(io: SockRef<'_>) -> io::Result<()> {
    let mut cmsg_platform_space = 0;
    if cfg!(any(target_os = "linux", target_os = "android"))
        || cfg!(target_os = "freebsd")
        || cfg!(target_os = "macos")
    {
        cmsg_platform_space +=
            unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as _) as usize };
    }

    assert!(
        CMSG_LEN
            >= unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) as usize }
                + cmsg_platform_space
    );
    assert!(
        mem::align_of::<libc::cmsghdr>() <= mem::align_of::<cmsg::Aligned<[u8; 0]>>(),
        "control message buffers will be misaligned"
    );

    io.set_nonblocking(true)?;

    let addr = io.local_addr()?;
    let is_ipv4 = addr.family() == libc::AF_INET as libc::sa_family_t;

    // macos and ios do not support IP_RECVTOS on dual-stack sockets :(
    if is_ipv4 || ((!cfg!(any(target_os = "macos", target_os = "ios"))) && !io.only_v6()?) {
        set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_RECVTOS, OPTION_ON)?;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // opportunistically try to enable GRO. See gro::gro_segments().
        let _ = set_socket_option(&*io, libc::SOL_UDP, libc::UDP_GRO, OPTION_ON);

        // Forbid IPv4 fragmentation. Set even for IPv6 to account for IPv6 mapped IPv4 addresses.
        set_socket_option(
            &*io,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_PROBE,
        )?;

        if is_ipv4 {
            set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON)?;
        } else {
            set_socket_option(
                &*io,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if is_ipv4 {
            set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_PKTINFO, OPTION_ON)?;
        }
    }
    #[cfg(target_os = "freebsd")]
    // IP_RECVDSTADDR == IP_SENDSRCADDR on FreeBSD
    // macOS uses only IP_RECVDSTADDR, no IP_SENDSRCADDR on macOS
    // macOS also supports IP_PKTINFO
    {
        if is_ipv4 {
            set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_RECVDSTADDR, OPTION_ON)?;
            set_socket_option(&*io, libc::IPPROTO_IP, libc::IP_RECVIF, OPTION_ON)?;
        }
    }

    // IPV6_RECVPKTINFO is standardized
    if !is_ipv4 {
        set_socket_option(&*io, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, OPTION_ON)?;
        set_socket_option(&*io, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, OPTION_ON)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn send_msg<B: AsPtr<u8>>(
    state: &UdpState,
    io: SockRef<'_>,
    transmit: &Transmit<B>,
) -> io::Result<usize> {
    let mut msg_hdr: libc::msghdr = unsafe { mem::zeroed() };
    let mut iovec: libc::iovec = unsafe { mem::zeroed() };
    let mut cmsg = cmsg::Aligned([0u8; CMSG_LEN]);

    let addr = socket2::SockAddr::from(transmit.dst);
    let dst_addr = &addr;
    prepare_msg(transmit, dst_addr, &mut msg_hdr, &mut iovec, &mut cmsg)?;

    loop {
        let n = unsafe { libc::sendmsg(io.as_raw_fd(), &msg_hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {
                    // Retry the transmission
                    continue;
                }
                io::ErrorKind::WouldBlock => return Err(e),
                _ => {
                    // Some network adapters do not support GSO. Unfortunately, Linux offers no easy way
                    // for us to detect this short of an I/O error when we try to actually send
                    // datagrams using it.
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    if e.raw_os_error() == Some(libc::EIO) {
                        // Prevent new transmits from being scheduled using GSO. Existing GSO transmits
                        // may already be in the pipeline, so we need to tolerate additional failures.
                        if state.max_gso_segments() > 1 {
                            tracing::error!("got EIO, halting segmentation offload");
                            state
                                .max_gso_segments
                                .store(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }

                    // Other errors are ignored, since they will ususally be handled
                    // by higher level retransmits and timeouts.
                    // - PermissionDenied errors have been observed due to iptable rules.
                    //   Those are not fatal errors, since the
                    //   configuration can be dynamically changed.
                    // - Destination unreachable errors have been observed for other
                    // log_sendmsg_error(last_send_error, e, &transmits[0]);

                    // The ERRORS section in https://man7.org/linux/man-pages/man2/sendmmsg.2.html
                    // describes that errors will only be returned if no message could be transmitted
                    // at all. Therefore drop the first (problematic) message,
                    // and retry the remaining ones.
                    return Ok(n as usize);
                }
            }
        }
        return Ok(n as usize);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn send<B: AsPtr<u8>>(
    state: &UdpState,
    io: SockRef<'_>,
    last_send_error: &mut Instant,
    transmits: &[Transmit<B>],
) -> io::Result<usize> {
    use std::ptr;

    let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { mem::zeroed() };
    let mut iovecs: [libc::iovec; BATCH_SIZE] = unsafe { mem::zeroed() };
    let mut cmsgs = [cmsg::Aligned([0u8; CMSG_LEN]); BATCH_SIZE];
    // This assume_init looks a bit weird because one might think it
    // assumes the SockAddr data to be initialized, but that call
    // refers to the whole array, which itself is made up of MaybeUninit
    // containers. Their presence protects the SockAddr inside from
    // being assumed as initialized by the assume_init call.
    // TODO: Replace this with uninit_array once it becomes MSRV-stable
    let mut addrs: [MaybeUninit<socket2::SockAddr>; BATCH_SIZE] =
        unsafe { MaybeUninit::uninit().assume_init() };
    for (i, transmit) in transmits.iter().enumerate().take(BATCH_SIZE) {
        let dst_addr = unsafe {
            ptr::write(addrs[i].as_mut_ptr(), socket2::SockAddr::from(transmit.dst));
            &*addrs[i].as_ptr()
        };
        prepare_msg(
            transmit,
            dst_addr,
            &mut msgs[i].msg_hdr,
            &mut iovecs[i],
            &mut cmsgs[i],
        )?;
    }
    let num_transmits = transmits.len().min(BATCH_SIZE);

    loop {
        let n =
            unsafe { libc::sendmmsg(io.as_raw_fd(), msgs.as_mut_ptr(), num_transmits as u32, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {
                    // Retry the transmission
                    continue;
                }
                io::ErrorKind::WouldBlock => return Err(e),
                _ => {
                    // Some network adapters do not support GSO. Unfortunately, Linux offers no easy way
                    // for us to detect this short of an I/O error when we try to actually send
                    // datagrams using it.
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    if e.raw_os_error() == Some(libc::EIO) {
                        // Prevent new transmits from being scheduled using GSO. Existing GSO transmits
                        // may already be in the pipeline, so we need to tolerate additional failures.
                        if state.max_gso_segments() > 1 {
                            tracing::error!("got EIO, halting segmentation offload");
                            state
                                .max_gso_segments
                                .store(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }

                    // Other errors are ignored, since they will ususally be handled
                    // by higher level retransmits and timeouts.
                    // - PermissionDenied errors have been observed due to iptable rules.
                    //   Those are not fatal errors, since the
                    //   configuration can be dynamically changed.
                    // - Destination unreachable errors have been observed for other
                    log_sendmsg_error(last_send_error, e, &transmits[0]);

                    // The ERRORS section in https://man7.org/linux/man-pages/man2/sendmmsg.2.html
                    // describes that errors will only be returned if no message could be transmitted
                    // at all. Therefore drop the first (problematic) message,
                    // and retry the remaining ones.
                    return Ok(num_transmits.min(1));
                }
            }
        }
        return Ok(n as usize);
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn send_msg<B: AsPtr<u8>>(
    _state: &UdpState,
    io: SockRef<'_>,
    transmit: &Transmit<B>,
) -> io::Result<usize> {
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    let mut iov: libc::iovec = unsafe { mem::zeroed() };
    let mut ctrl = cmsg::Aligned([0u8; CMSG_LEN]);

    let addr = socket2::SockAddr::from(transmit.dst);
    let dst_addr = &addr;
    prepare_msg(transmit, dst_addr, &mut hdr, &mut iov, &mut ctrl)?;

    loop {
        let n = unsafe { libc::sendmsg(io.as_raw_fd(), &hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {
                    // Retry the transmission
                    continue;
                }
                io::ErrorKind::WouldBlock => return Err(e),
                _ => {
                    // Other errors are ignored, since they will ususally be handled
                    // by higher level retransmits and timeouts.
                    // - PermissionDenied errors have been observed due to iptable rules.
                    //   Those are not fatal errors, since the
                    //   configuration can be dynamically changed.
                    // - Destination unreachable errors have been observed for other
                    return Ok(n as usize);
                }
            }
        }
        return Ok(n as usize);
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn send<B: AsPtr<u8>>(
    _state: &UdpState,
    io: SockRef<'_>,
    last_send_error: &mut Instant,
    transmits: &[Transmit<B>],
) -> io::Result<usize> {
    let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
    let mut iov: libc::iovec = unsafe { mem::zeroed() };
    let mut ctrl = cmsg::Aligned([0u8; CMSG_LEN]);
    let mut sent = 0;
    while sent < transmits.len() {
        let addr = socket2::SockAddr::from(transmits[sent].dst);
        prepare_msg(&transmits[sent], &addr, &mut hdr, &mut iov, &mut ctrl)?;
        let n = unsafe { libc::sendmsg(io.as_raw_fd(), &hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::Interrupted => {
                    // Retry the transmission
                }
                io::ErrorKind::WouldBlock if sent != 0 => return Ok(sent),
                io::ErrorKind::WouldBlock => return Err(e),
                _ => {
                    // Other errors are ignored, since they will ususally be handled
                    // by higher level retransmits and timeouts.
                    // - PermissionDenied errors have been observed due to iptable rules.
                    //   Those are not fatal errors, since the
                    //   configuration can be dynamically changed.
                    // - Destination unreachable errors have been observed for other
                    log_sendmsg_error(last_send_error, e, &transmits[sent]);
                    sent += 1;
                }
            }
        } else {
            sent += 1;
        }
    }
    Ok(sent)
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn recv(io: SockRef<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize> {
    use std::ptr;

    let mut names = [MaybeUninit::<libc::sockaddr_storage>::uninit(); BATCH_SIZE];
    let mut ctrls = [cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit()); BATCH_SIZE];
    let mut hdrs = unsafe { mem::zeroed::<[libc::mmsghdr; BATCH_SIZE]>() };
    let max_msg_count = bufs.len().min(BATCH_SIZE);
    for i in 0..max_msg_count {
        prepare_recv(
            &mut bufs[i],
            &mut names[i],
            &mut ctrls[i],
            &mut hdrs[i].msg_hdr,
        );
    }
    let msg_count = loop {
        let n = unsafe {
            libc::recvmmsg(
                io.as_raw_fd(),
                hdrs.as_mut_ptr(),
                bufs.len().min(BATCH_SIZE) as libc::c_uint,
                0,
                ptr::null_mut(),
            )
        };
        if n == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        break n;
    };
    for i in 0..(msg_count as usize) {
        meta[i] = decode_recv(&names[i], &hdrs[i].msg_hdr, hdrs[i].msg_len as usize);
    }
    Ok(msg_count as usize)
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn recv_msg(io: SockRef<'_>, bufs: &mut IoSliceMut<'_>) -> io::Result<RecvMeta> {
    let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
    let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };

    prepare_recv(bufs, &mut name, &mut ctrl, &mut hdr);

    let n = loop {
        let n = unsafe { libc::recvmsg(io.as_raw_fd(), &mut hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if hdr.msg_flags & libc::MSG_TRUNC != 0 {
            continue;
        }
        break n;
    };
    Ok(decode_recv(&name, &hdr, n as usize))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn recv(io: SockRef<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> io::Result<usize> {
    let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
    let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
    prepare_recv(&mut bufs[0], &mut name, &mut ctrl, &mut hdr);
    let n = loop {
        let n = unsafe { libc::recvmsg(io.as_raw_fd(), &mut hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if hdr.msg_flags & libc::MSG_TRUNC != 0 {
            continue;
        }
        break n;
    };
    meta[0] = decode_recv(&name, &hdr, n as usize);
    Ok(1)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn recv_msg(io: SockRef<'_>, bufs: &mut IoSliceMut<'_>) -> io::Result<RecvMeta> {
    let mut name = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut ctrl = cmsg::Aligned(MaybeUninit::<[u8; CMSG_LEN]>::uninit());
    let mut hdr = unsafe { mem::zeroed::<libc::msghdr>() };
    prepare_recv(bufs, &mut name, &mut ctrl, &mut hdr);
    let n = loop {
        let n = unsafe { libc::recvmsg(io.as_raw_fd(), &mut hdr, 0) };
        if n == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if hdr.msg_flags & libc::MSG_TRUNC != 0 {
            continue;
        }
        break n;
    };
    Ok(decode_recv(&name, &hdr, n as usize))
}

/// Returns the platforms UDP socket capabilities
pub fn udp_state() -> UdpState {
    UdpState {
        max_gso_segments: AtomicUsize::new(gso::max_gso_segments()),
        gro_segments: gro::gro_segments(),
    }
}

const CMSG_LEN: usize = 512;

fn prepare_msg<B: AsPtr<u8>>(
    transmit: &Transmit<B>,
    dst_addr: &socket2::SockAddr,
    hdr: &mut libc::msghdr,
    iov: &mut libc::iovec,
    ctrl: &mut cmsg::Aligned<[u8; CMSG_LEN]>,
) -> io::Result<()> {
    iov.iov_base = transmit.contents.as_ptr() as *const _ as *mut _;
    iov.iov_len = transmit.contents.len();

    // SAFETY: Casting the pointer to a mutable one is legal,
    // as sendmsg is guaranteed to not alter the mutable pointer
    // as per the POSIX spec. See the section on the sys/socket.h
    // header for details. The type is only mutable in the first
    // place because it is reused by recvmsg as well.
    let name = dst_addr.as_ptr() as *mut libc::c_void;
    let namelen = dst_addr.len();
    hdr.msg_name = name as *mut _;
    hdr.msg_namelen = namelen;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;

    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    let mut encoder = unsafe { cmsg::Encoder::new(hdr) };
    let ecn = transmit.ecn.map_or(0, |x| x as libc::c_int);
    if transmit.dst.is_ipv4() {
        encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
    } else {
        encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
    }

    if let Some(segment_size) = transmit.segment_size {
        gso::set_segment_size(&mut encoder, segment_size as u16);
    }

    if let Some(ip) = &transmit.src {
        match ip {
            Source::Ip(IpAddr::V4(v4)) => {
                #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
                {
                    let pktinfo = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(v4.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    encoder.push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo);
                }
                #[cfg(target_os = "freebsd")]
                {
                    let addr = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    };
                    encoder.push(libc::IPPROTO_IP, libc::IP_RECVDSTADDR, addr);
                }
            }
            Source::Ip(IpAddr::V6(v6)) => {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex: 0,
                    ipi6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                };
                encoder.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo);
            }
            Source::Interface(i) => {
                let pktinfo = libc::in_pktinfo {
                    ipi_ifindex: (*i).try_into().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "IPv4 interface index out of range",
                        )
                    })?,
                    ipi_spec_dst: libc::in_addr { s_addr: 0 },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                encoder.push(libc::IPPROTO_IP, libc::IP_PKTINFO, pktinfo);
            }
            Source::InterfaceV6(i, ip) => {
                let pktinfo = libc::in6_pktinfo {
                    ipi6_ifindex: (*i).try_into().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "IPv6 interface index out of range",
                        )
                    })?,
                    ipi6_addr: libc::in6_addr {
                        s6_addr: ip.octets(),
                    },
                };
                encoder.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, pktinfo);
            }
        }
    }

    encoder.finish();
    Ok(())
}

fn prepare_recv(
    buf: &mut IoSliceMut,
    name: &mut MaybeUninit<libc::sockaddr_storage>,
    ctrl: &mut cmsg::Aligned<MaybeUninit<[u8; CMSG_LEN]>>,
    hdr: &mut libc::msghdr,
) {
    hdr.msg_name = name.as_mut_ptr() as _;
    hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
    hdr.msg_iov = buf as *mut IoSliceMut as *mut libc::iovec;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrl.0.as_mut_ptr() as _;
    hdr.msg_controllen = CMSG_LEN as _;
    hdr.msg_flags = 0;
}

fn decode_recv(
    name: &MaybeUninit<libc::sockaddr_storage>,
    hdr: &libc::msghdr,
    len: usize,
) -> RecvMeta {
    let name = unsafe { name.assume_init() };
    let mut ecn_bits = 0;
    let mut dst_ip = None;
    let mut dst_local_ip = None;
    let mut ifindex = 0;
    #[allow(unused_mut)] // only mutable on Linux
    let mut stride = len;
    let mut orig_dst = None;

    let cmsg_iter = unsafe { cmsg::Iter::new(hdr) };
    for cmsg in cmsg_iter {
        match (cmsg.cmsg_level, cmsg.cmsg_type) {
            // FreeBSD uses IP_RECVTOS here, and we can be liberal because cmsgs are opt-in.
            (libc::IPPROTO_IP, libc::IP_TOS) | (libc::IPPROTO_IP, libc::IP_RECVTOS) => unsafe {
                ecn_bits = cmsg::decode::<u8>(cmsg);
            },
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => unsafe {
                // Temporary hack around broken macos ABI. Remove once upstream fixes it.
                // https://bugreport.apple.com/web/?problemID=48761855
                if cfg!(target_os = "macos")
                    && cmsg.cmsg_len as usize == libc::CMSG_LEN(mem::size_of::<u8>() as _) as usize
                {
                    ecn_bits = cmsg::decode::<u8>(cmsg);
                } else {
                    ecn_bits = cmsg::decode::<libc::c_int>(cmsg) as u8;
                }
            },
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                let pktinfo = unsafe { cmsg::decode::<libc::in_pktinfo>(cmsg) };
                dst_ip = Some(IpAddr::V4(Ipv4Addr::from(
                    pktinfo.ipi_addr.s_addr.to_ne_bytes(),
                )));
                dst_local_ip = Some(IpAddr::V4(Ipv4Addr::from(
                    pktinfo.ipi_spec_dst.s_addr.to_ne_bytes(),
                )));
                ifindex = u32::try_from(pktinfo.ipi_ifindex).unwrap_or_default();
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                let pktinfo = unsafe { cmsg::decode::<libc::in6_pktinfo>(cmsg) };
                dst_ip = Some(IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
                ifindex = u32::try_from(pktinfo.ipi6_ifindex).unwrap_or_default();
            }
            // freebsd doesn't have PKTINFO
            #[cfg(target_os = "freebsd")]
            (libc::IPPROTO_IP, libc::IP_RECVIF) => {
                let info = unsafe { cmsg::decode::<libc::sockaddr_dl>(cmsg) };
                ifindex = info.sdl_index as _;
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::SOL_UDP, libc::UDP_GRO) => unsafe {
                stride = cmsg::decode::<libc::c_int>(cmsg) as usize;
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::SOL_IP, libc::IP_ORIGDSTADDR) => unsafe {
                let addr_in = cmsg::decode::<libc::sockaddr_in>(cmsg);
                let addr = Ipv4Addr::from(addr_in.sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be(addr_in.sin_port);
                orig_dst = Some(SocketAddr::V4(SocketAddrV4::new(addr, port)));
            },
            #[cfg(any(target_os = "linux", target_os = "android"))]
            (libc::SOL_IPV6, libc::IPV6_ORIGDSTADDR) => unsafe {
                let addr_in = cmsg::decode::<libc::sockaddr_in6>(cmsg);
                let addr = Ipv6Addr::from(addr_in.sin6_addr.s6_addr);
                let port = u16::from_be(addr_in.sin6_port);
                let flowinfo = addr_in.sin6_flowinfo;
                let scope_id = addr_in.sin6_scope_id;
                orig_dst = Some(SocketAddr::V6(SocketAddrV6::new(
                    addr, port, flowinfo, scope_id,
                )));
            },
            _ => {}
        }
    }

    let addr = match libc::c_int::from(name.ss_family) {
        libc::AF_INET => {
            // Safety: if the ss_family field is AF_INET then storage must be a sockaddr_in.
            let addr = unsafe { &*(&name as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
            let port = u16::from_be(addr.sin_port);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        }
        libc::AF_INET6 => {
            // Safety: if the ss_family field is AF_INET6 then storage must be a sockaddr_in6.
            let addr = unsafe { &*(&name as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            ))
        }
        _ => unreachable!(),
    };

    RecvMeta {
        len,
        stride,
        addr,
        ecn: EcnCodepoint::from_bits(ecn_bits),
        dst_ip,
        dst_local_ip,
        ifindex,
        orig_dst,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
// Chosen somewhat arbitrarily; might benefit from additional tuning.
pub const BATCH_SIZE: usize = 32;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const BATCH_SIZE: usize = 1;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod gso {
    use super::*;

    /// Checks whether GSO support is available by setting the UDP_SEGMENT
    /// option on a socket
    pub fn max_gso_segments() -> usize {
        const GSO_SIZE: libc::c_int = 1500;

        let socket = match std::net::UdpSocket::bind("[::]:0")
            .or_else(|_| std::net::UdpSocket::bind("127.0.0.1:0"))
        {
            Ok(socket) => socket,
            Err(_) => return 1,
        };

        // As defined in linux/udp.h
        // #define UDP_MAX_SEGMENTS        (1 << 6UL)
        match set_socket_option(&socket, libc::SOL_UDP, libc::UDP_SEGMENT, GSO_SIZE) {
            Ok(()) => 64,
            Err(_) => 1,
        }
    }

    pub fn set_segment_size(encoder: &mut cmsg::Encoder, segment_size: u16) {
        encoder.push(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod gso {
    use super::*;

    pub fn max_gso_segments() -> usize {
        1
    }

    pub fn set_segment_size(_encoder: &mut cmsg::Encoder, _segment_size: u16) {
        panic!("Setting a segment size is not supported on current platform");
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod gro {
    use super::*;

    pub fn gro_segments() -> usize {
        let socket = match std::net::UdpSocket::bind("[::]:0") {
            Ok(socket) => socket,
            Err(_) => return 1,
        };

        let on: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_UDP,
                libc::UDP_GRO,
                &on as *const _ as _,
                mem::size_of_val(&on) as _,
            )
        };

        if rc != -1 {
            // As defined in net/ipv4/udp_offload.c
            // #define UDP_GRO_CNT_MAX 64
            //
            // NOTE: this MUST be set to UDP_GRO_CNT_MAX to ensure that the receive buffer size
            // (get_max_udp_payload_size() * gro_segments()) is large enough to hold the largest GRO
            // list the kernel might potentially produce. See
            // https://github.com/quinn-rs/quinn/pull/1354.
            64
        } else {
            1
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod gro {
    pub fn gro_segments() -> usize {
        1
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod original_destination_tests {
    use super::*;
    use std::{net::UdpSocket as StdSocket, time::Duration};

    fn check_original_destination(ip: IpAddr, level: i32, option: i32) -> io::Result<()> {
        let receiver = StdSocket::bind((ip, 0))?;
        receiver.set_read_timeout(Some(Duration::from_secs(3)))?;
        set_socket_option(&receiver, level, option, OPTION_ON)?;
        let receiver = sync::UdpSocket::from_std(receiver)?;
        let sender = StdSocket::bind((ip, 0))?;
        let dst = receiver.local_addr()?;
        sender.send_to(b"udp", dst)?;
        let mut buf = [0; 16];
        let meta = receiver.recv_msg(&mut buf)?;
        assert_eq!(meta.orig_dst, Some(dst));
        assert_eq!(meta.addr, sender.local_addr()?);
        assert_eq!(&buf[..meta.len], b"udp");
        Ok(())
    }

    #[test]
    fn ipv4_original_destination() -> io::Result<()> {
        check_original_destination(
            Ipv4Addr::LOCALHOST.into(),
            libc::IPPROTO_IP,
            libc::IP_RECVORIGDSTADDR,
        )
    }

    #[cfg(target_os = "android")]
    #[test]
    fn ipv6_interface_index_out_of_range() -> io::Result<()> {
        let socket = sync::UdpSocket::bind("[::1]:0")?;
        let tx = Transmit::new(socket.local_addr()?, *b"test")
            .src_ip(Source::InterfaceV6(u32::MAX, Ipv6Addr::LOCALHOST));
        assert_eq!(
            socket.send_msg(&UdpState::new(), tx).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    #[test]
    fn ipv6_original_destination() -> io::Result<()> {
        check_original_destination(
            Ipv6Addr::LOCALHOST.into(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVORIGDSTADDR,
        )
    }
}
