use std::{
    mem,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    ptr,
};

use bytes::{Bytes, BytesMut};

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<cmsghdr>
pub struct Aligned<T>(pub T);

/// Helper to encode a series of control messages ("cmsgs") to a buffer for use in `sendmsg`.
///
/// The operation must be "finished" for the msghdr to be usable, either by calling `finish`
/// explicitly or by dropping the `Encoder`.
pub struct Encoder<'a> {
    hdr: &'a mut libc::msghdr,
    cmsg: Option<&'a mut libc::cmsghdr>,
    len: usize,
}

impl<'a> Encoder<'a> {
    /// # Safety
    /// - `hdr.msg_control` must be a suitably aligned pointer to `hdr.msg_controllen` bytes that
    ///   can be safely written
    /// - The `Encoder` must be dropped before `hdr` is passed to a system call, and must not be leaked.
    pub unsafe fn new(hdr: &'a mut libc::msghdr) -> Self {
        Self {
            cmsg: libc::CMSG_FIRSTHDR(hdr).as_mut(),
            hdr,
            len: 0,
        }
    }

    /// Append a control message to the buffer.
    ///
    /// # Panics
    /// - If insufficient buffer space remains.
    /// - If `T` has stricter alignment requirements than `cmsghdr`
    #[allow(clippy::unnecessary_cast)]
    pub fn push<T: Copy + ?Sized>(&mut self, level: libc::c_int, ty: libc::c_int, value: T) {
        assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
        let space = unsafe { libc::CMSG_SPACE(mem::size_of_val(&value) as _) as usize };
        assert!(
            self.hdr.msg_controllen as usize >= self.len + space,
            "control message buffer too small. Required: {}, Available: {}",
            self.len + space,
            self.hdr.msg_controllen
        );
        let cmsg = self.cmsg.take().expect("no control buffer space remaining");
        cmsg.cmsg_level = level;
        cmsg.cmsg_type = ty;
        cmsg.cmsg_len = unsafe { libc::CMSG_LEN(mem::size_of_val(&value) as _) } as _;
        unsafe {
            ptr::write(libc::CMSG_DATA(cmsg) as *const T as *mut T, value);
        }
        self.len += space;
        self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, cmsg).as_mut() };
    }

    /// Finishes appending control messages to the buffer
    pub fn finish(self) {
        // Delegates to the `Drop` impl
    }
}

// Statically guarantees that the encoding operation is "finished" before the control buffer is read
// by `sendmsg`.
impl<'a> Drop for Encoder<'a> {
    fn drop(&mut self) {
        self.hdr.msg_controllen = self.len as _;
    }
}

/// # Safety
///
/// `cmsg` must refer to a cmsg containing a payload of type `T`
#[allow(clippy::unnecessary_cast)]
pub unsafe fn decode<T: Copy>(cmsg: &libc::cmsghdr) -> T {
    assert!(mem::align_of::<T>() <= mem::align_of::<libc::cmsghdr>());
    debug_assert_eq!(
        cmsg.cmsg_len as usize,
        libc::CMSG_LEN(mem::size_of::<T>() as _) as usize
    );
    ptr::read(libc::CMSG_DATA(cmsg) as *const T)
}

pub struct Iter<'a> {
    hdr: &'a libc::msghdr,
    cmsg: Option<&'a libc::cmsghdr>,
}

impl<'a> Iter<'a> {
    /// # Safety
    ///
    /// `hdr.msg_control` must point to memory outliving `'a` which can be soundly read for the
    /// lifetime of the constructed `Iter` and contains a buffer of cmsgs, i.e. is aligned for
    /// `cmsghdr`, is fully initialized, and has correct internal links.
    pub unsafe fn new(hdr: &'a libc::msghdr) -> Self {
        Self {
            hdr,
            cmsg: libc::CMSG_FIRSTHDR(hdr).as_ref(),
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a libc::cmsghdr;
    fn next(&mut self) -> Option<&'a libc::cmsghdr> {
        let current = self.cmsg.take()?;
        self.cmsg = unsafe { libc::CMSG_NXTHDR(self.hdr, current).as_ref() };
        Some(current)
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    #[doc(hidden)]
    Ect0 = 0b10,
    #[doc(hidden)]
    Ect1 = 0b01,
    #[doc(hidden)]
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use self::EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}

/// An outgoing packet
#[derive(Debug)]
pub struct Transmit<B> {
    /// The socket this datagram should be sent to
    pub dst: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
    /// Contents of the datagram
    pub contents: B,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub segment_size: Option<usize>,
    /// Optional source IP address for the datagram
    pub src: Option<Source>,
}

impl<B: AsPtr<u8>> Transmit<B> {
    pub fn new(dst: SocketAddr, contents: B) -> Self {
        Self {
            dst,
            contents,
            ecn: None,
            segment_size: None,
            src: None,
        }
    }
    pub fn src_ip(self, src_ip: Source) -> Self {
        Transmit {
            src: Some(src_ip),
            ..self
        }
    }
    pub fn segment_size(self, size: usize) -> Self {
        Transmit {
            segment_size: Some(size),
            ..self
        }
    }
    pub fn ecn(self, ecn: EcnCodepoint) -> Self {
        Transmit {
            ecn: Some(ecn),
            ..self
        }
    }
}

/// Select how to set the source IP - using either interface id or the IP itself
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub enum Source {
    /// Set source IP explicitly by IP
    Ip(IpAddr),
    /// Set via interface index, ipv4 only
    Interface(u32),
    /// Set v6 interface index and IP
    InterfaceV6(u32, Ipv6Addr),
}

/// A buffer that can be turned into a raw ptr and has a len.
/// Is used to be generic over Vec<u8>, [u8], Bytes, BytesMut
pub trait AsPtr<T> {
    fn as_ptr(&self) -> *const T;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T, const N: usize> AsPtr<T> for &[T; N] {
    fn as_ptr(&self) -> *const T {
        self.as_slice().as_ptr()
    }

    fn len(&self) -> usize {
        N
    }
}

impl<T, const N: usize> AsPtr<T> for [T; N] {
    fn as_ptr(&self) -> *const T {
        self.as_slice().as_ptr()
    }

    fn len(&self) -> usize {
        N
    }
}

impl<T> AsPtr<T> for Vec<T> {
    fn as_ptr(&self) -> *const T {
        <Vec<T>>::as_ptr(self)
    }
    fn len(&self) -> usize {
        <Vec<T>>::len(self)
    }
}

impl<T> AsPtr<T> for [T] {
    fn as_ptr(&self) -> *const T {
        <[T]>::as_ptr(self)
    }
    fn len(&self) -> usize {
        <[T]>::len(self)
    }
}

impl AsPtr<u8> for BytesMut {
    fn as_ptr(&self) -> *const u8 {
        <[u8]>::as_ptr(self.as_ref())
    }
    fn len(&self) -> usize {
        self.len()
    }
}

impl AsPtr<u8> for Bytes {
    fn as_ptr(&self) -> *const u8 {
        <[u8]>::as_ptr(self.as_ref())
    }
    fn len(&self) -> usize {
        self.len()
    }
}
