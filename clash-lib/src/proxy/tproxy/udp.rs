use std::{io, io::IoSliceMut, net::SocketAddr, os::fd::AsRawFd};

use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrLike, recvmsg,
    setsockopt, sockopt,
};
use tokio::{io::Interest, net::UdpSocket};
use tracing::trace;

pub(super) struct UdpReceiver {
    socket: UdpSocket,
    pub(super) local_addr: SocketAddr,
    control: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct RecvMeta {
    pub(super) addr: SocketAddr,
    pub(super) orig_dst: Option<SocketAddr>,
    pub(super) len: usize,
    pub(super) stride: usize,
}

impl UdpReceiver {
    pub(super) fn bind(
        socket: socket2::Socket,
        addr: SocketAddr,
        dual_stack: bool,
    ) -> io::Result<Self> {
        if dual_stack || addr.is_ipv4() {
            setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true)?;
        }
        if addr.is_ipv6() {
            setsockopt(&socket, sockopt::Ipv6OrigDstAddr, &true)?;
        }
        if let Err(err) = setsockopt(&socket, sockopt::UdpGroSegment, &true) {
            trace!("TPROXY UDP GRO unavailable: {err}");
        }
        socket.bind(&addr.into())?;
        let socket = UdpSocket::from_std(socket.into())?;
        Ok(Self {
            local_addr: socket.local_addr()?,
            socket,
            control: nix::cmsg_space!(
                libc::sockaddr_in,
                libc::sockaddr_in6,
                libc::c_int
            ),
        })
    }

    pub(super) async fn recv_msg(&mut self, buf: &mut [u8]) -> io::Result<RecvMeta> {
        loop {
            let meta = self
                .socket
                .async_io(Interest::READABLE, || {
                    let fd = self.socket.as_raw_fd();
                    // AF_INET6 sockets return IPv4 peers as IPv4-mapped
                    // sockaddr_in6.
                    if self.local_addr.is_ipv4() {
                        recv::<SockaddrIn>(fd, buf, &mut self.control)
                    } else {
                        recv::<SockaddrIn6>(fd, buf, &mut self.control)
                    }
                })
                .await;
            match meta {
                Ok(Some(meta)) => return Ok(meta),
                Ok(None) => continue,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
    }
}

fn recv<S: SockaddrLike + Into<SocketAddr> + Copy>(
    fd: std::os::fd::RawFd,
    buf: &mut [u8],
    control: &mut [u8],
) -> io::Result<Option<RecvMeta>> {
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<S>(fd, &mut iov, Some(control), MsgFlags::empty())?;
    if msg
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
    {
        trace!("discarding truncated TPROXY UDP datagram");
        return Ok(None);
    }
    let addr = msg.address.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing UDP peer address")
    })?;
    let mut meta = RecvMeta {
        addr: addr.into(),
        orig_dst: None,
        len: msg.bytes,
        stride: 0,
    };
    for cmsg in msg.cmsgs()? {
        match cmsg {
            ControlMessageOwned::Ipv4OrigDstAddr(dst) => {
                meta.orig_dst = Some(SockaddrIn::from(dst).into());
            }
            ControlMessageOwned::Ipv6OrigDstAddr(dst) => {
                meta.orig_dst = Some(SockaddrIn6::from(dst).into());
            }
            ControlMessageOwned::UdpGroSegments(size) => {
                meta.stride = usize::try_from(size).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "negative UDP GRO segment size",
                    )
                })?;
            }
            _ => {}
        }
    }
    Ok(Some(meta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    #[tokio::test]
    async fn receives_original_destination_and_discards_truncated_payloads()
    -> io::Result<()> {
        for bind_addr in [
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        ] {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(bind_addr),
                socket2::Type::DGRAM,
                None,
            )?;
            if bind_addr.is_ipv6() {
                socket.set_only_v6(false)?;
            }
            socket.set_nonblocking(true)?;
            let mut receiver =
                UdpReceiver::bind(socket, bind_addr, bind_addr.is_ipv6())?;
            let port = receiver.local_addr.port();
            for dst in [
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            ] {
                if bind_addr.is_ipv4() && dst.is_ipv6() {
                    continue;
                }
                let sender = UdpSocket::bind(SocketAddr::new(dst.ip(), 0)).await?;
                sender.send_to(b"oversized", dst).await?;
                sender.send_to(b"ok", dst).await?;
                let mut buf = [0; 4];
                let meta = tokio::time::timeout(
                    Duration::from_secs(5),
                    receiver.recv_msg(&mut buf),
                )
                .await??;
                assert_eq!(&buf[..meta.len], b"ok");
                assert_eq!(meta.addr.ip().to_canonical(), dst.ip());
                assert_eq!(meta.addr.port(), sender.local_addr()?.port());
                let orig_dst = meta.orig_dst.unwrap();
                assert_eq!(orig_dst.ip().to_canonical(), dst.ip());
                assert_eq!(orig_dst.port(), dst.port());
                assert_eq!(meta.stride, 0);
            }
        }
        Ok(())
    }
}
