use std::{io, os::windows::io::AsRawSocket};
use tracing::error;
use windows::{
    Win32::{
        Foundation::GetLastError,
        Networking::WinSock::{
            IP_MULTICAST_IF, IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6,
            IPV6_MULTICAST_IF, IPV6_UNICAST_IF, SO_TYPE, SOCK_DGRAM, SOCKET,
            SOL_SOCKET, WINSOCK_SOCKET_TYPE, getsockopt, setsockopt,
        },
    },
    core::PSTR,
};

use crate::{app::net::OutboundInterface, common::errors::new_io_error};

pub(crate) fn must_bind_socket_on_interface(
    socket: &socket2::Socket,
    iface: &OutboundInterface,
    family: socket2::Domain,
) -> io::Result<()> {
    let handle = SOCKET(socket.as_raw_socket().try_into().unwrap());
    let is_udp = is_udp_socket(handle)?;
    let idx = iface.index;

    let errno = match family {
        socket2::Domain::IPV4 => unsafe {
            setsockopt(
                handle,
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
                // a 4-byte IPv4 address in network byte order
                Some(idx.to_be_bytes().as_ref()),
            )
        },
        socket2::Domain::IPV6 => unsafe {
            setsockopt(
                handle,
                IPPROTO_IPV6.0,
                IPV6_UNICAST_IF,
                // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
                // 4-byte interface index of the desired outgoing interface in
                // host byte order
                // OMG Windows!
                Some(idx.to_ne_bytes().as_ref()),
            )
        },
        _ => return Err(io::Error::other("unsupported socket family")),
    };

    if errno != 0 {
        let err = unsafe { GetLastError().to_hresult().message() };
        error!("bind socket to interface failed: {}, errno: {}", err, errno);
        return Err(new_io_error(err));
    }

    // UDP supports multicast
    // MULTICAST must also be bound to an interface
    if is_udp {
        let errno = match family {
            socket2::Domain::IPV4 => unsafe {
                setsockopt(
                    handle,
                    IPPROTO_IP.0,
                    IP_MULTICAST_IF,
                    // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
                    // a 4-byte IPv4 address in network byte order
                    Some(idx.to_be_bytes().as_ref()),
                )
            },
            socket2::Domain::IPV6 => unsafe {
                setsockopt(
                    handle,
                    IPPROTO_IPV6.0,
                    IPV6_MULTICAST_IF,
                    // https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options
                    // 4-byte interface index of the desired outgoing interface
                    // in host byte order
                    // OMG Windows!
                    Some(idx.to_ne_bytes().as_ref()),
                )
            },
            _ => return Err(io::Error::other("unsupported socket family")),
        };

        if errno != 0 {
            let err = unsafe { GetLastError().to_hresult().message() };
            error!("bind socket to interface failed: {}, errno: {}", err, errno);
            return Err(new_io_error(err));
        }
    }
    if family == socket2::Domain::IPV6
        && let Err(x) =
            must_bind_socket_on_interface(socket, iface, socket2::Domain::IPV4)
    {
        tracing::warn!(
            "try bind dualstack socket on interface failed, it's ipv6 only:{x}"
        );
    }
    Ok(())
}

/// Return true if it's a udp socket
fn is_udp_socket(socket: SOCKET) -> io::Result<bool> {
    let mut optval = [0u8; 4];
    let mut optlen: i32 = 4;
    let ret = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_TYPE,
            PSTR::from_raw(optval.as_mut_ptr()),
            &mut optlen,
        )
    };
    if ret != 0 {
        let last_err = io::Error::last_os_error();
        tracing::warn!(
            "getsockopt failed when determining socket type: {:?}",
            last_err
        );
        return Err(last_err);
    }
    Ok(WINSOCK_SOCKET_TYPE(i32::from_ne_bytes(optval)) == SOCK_DGRAM)
}
