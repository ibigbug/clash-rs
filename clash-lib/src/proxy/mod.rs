use crate::{
    app::{
        dispatcher::{BoxedInstrumentedDatagram, BoxedInstrumentedStream},
        dns::ThreadSafeDNSResolver,
    },
    proxy::datagram::UdpPacket,
    session::Session,
};
use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use futures::{Sink, Stream};
use serde::{Deserialize, Serialize};
use tracing::error;

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    io,
    sync::Arc,
};

use tokio::io::{AsyncRead, AsyncWrite};

use self::utils::RemoteConnector;

pub mod direct;
pub mod reject;

pub mod http;
pub mod mixed;
#[cfg(all(target_os = "linux", feature = "tproxy"))]
pub mod tproxy;

#[cfg(all(target_os = "linux", feature = "redir"))]
pub mod redir;

pub(crate) mod datagram;

pub mod anytls;
pub mod converters;
pub mod hysteria2;
#[cfg(feature = "shadowquic")]
pub mod shadowquic;
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
pub mod socks;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "tailscale")]
pub mod tailscale;
#[cfg(feature = "onion")]
pub mod tor;
pub mod trojan;
#[cfg(feature = "tuic")]
pub mod tuic;
#[cfg(feature = "tun")]
pub mod tun;
pub mod utils;
pub mod vless;
pub mod vmess;
#[cfg(feature = "wireguard")]
pub mod wg;

pub mod group;
pub use group::{fallback, loadbalance, relay, selector, urltest};

mod common;
pub mod inbound;
mod options;
mod transport;
pub mod tunnel;

use crate::proxy::group::GroupProxyAPIResponse;
pub use options::HandlerCommonOptions;

#[cfg(test)]
pub mod mocks;

#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("proxy error: {0}")]
    General(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[allow(dead_code)]
    #[error("socks5 error: {0}")]
    Socks5(String),
}

/// A proxy stream: `AsyncRead + AsyncWrite`, plus an optional
/// `underlying_socket()` capability.
///
/// A stream that is a direct, single-hop passthrough to an OS socket returns
/// its raw fd (used by the splice/zero-copy path); everything with a transform
/// above the socket (TLS, framing, muxing) inherits the `None` default —
/// correct, since the fd would not carry the stream's payload bytes.
///
/// This trait is intentionally NOT blanket-implemented: the `underlying_socket`
/// capability requires `TcpStream` to override the default, which coherence
/// forbids under a blanket impl. Each concrete stream type impls it explicitly
/// (the impl is empty for everything except `TcpStream`).
///
/// `Send`/`Sync` are NOT trait bounds here — they are expressed at the boxed
/// use sites (`AnyStream = Box<dyn ProxyStream + Sync>`, `InstrumentedStream:
/// ProxyStream + Sync`) so inbound streams that are `Send` but not `Sync`
/// (e.g. `TokioIo<Upgraded>`) can still be `ProxyStream`.
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        None
    }
}
pub type AnyStream = Box<dyn ProxyStream + Sync>;

/// The one stream that IS a raw OS socket: overrides the capability to yield
/// its fd for the splice fast path.
impl ProxyStream for tokio::net::TcpStream {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        Some(self)
    }
}

/// Inbound-side streams with a transform/mux above the socket: inherit `None`.
impl ProxyStream for tokio::io::DuplexStream {}
#[cfg(feature = "tun")]
impl ProxyStream for watfaq_netstack::TcpStream {}
impl ProxyStream for hyper_util::rt::TokioIo<hyper::upgrade::Upgraded> {}

/// Boxed trait-object wrappers: delegate through the box.
impl ProxyStream for Box<dyn ProxyStream + Sync> {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        (**self).underlying_socket()
    }
}
impl ProxyStream for Box<dyn ProxyStream + Send + Sync> {
    #[cfg(all(target_os = "linux", feature = "zero_copy"))]
    fn underlying_socket(&mut self) -> Option<&mut tokio::net::TcpStream> {
        (**self).underlying_socket()
    }
}

/// Test helper: tokio_test::io::Mock used in unit tests.
#[cfg(test)]
impl ProxyStream for tokio_test::io::Mock {}

pub trait InboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + Debug
{
}
impl<T, U> InboundDatagram<U> for T where
    T: Stream<Item = U> + Sink<U, Error = io::Error> + Send + Sync + Unpin + Debug
{
}
pub type AnyInboundDatagram =
    Box<dyn InboundDatagram<UdpPacket, Error = io::Error, Item = UdpPacket>>;

pub trait OutboundDatagram<Item>:
    Stream<Item = Item> + Sink<Item, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

impl<T, U> OutboundDatagram<U> for T where
    T: Stream<Item = U> + Sink<U, Error = io::Error> + Send + Sync + Unpin + 'static
{
}

pub type AnyOutboundDatagram =
    Box<dyn OutboundDatagram<UdpPacket, Item = UdpPacket, Error = io::Error>>;

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum OutboundType {
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Anytls,
    WireGuard,
    Tor,
    Tuic,
    Socks5,
    Hysteria2,
    Ssh,
    Tailscale,
    ShadowQuic,

    #[serde(rename = "URLTest")]
    UrlTest,
    Selector,
    Relay,
    LoadBalance,
    Smart,
    Fallback,

    Direct,
    Reject,
}

impl Display for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundType::Shadowsocks => write!(f, "Shadowsocks"),
            OutboundType::Vmess => write!(f, "Vmess"),
            OutboundType::Vless => write!(f, "Vless"),
            OutboundType::Trojan => write!(f, "Trojan"),
            OutboundType::Anytls => write!(f, "AnyTLS"),
            OutboundType::WireGuard => write!(f, "WireGuard"),
            OutboundType::Tor => write!(f, "Tor"),
            OutboundType::Tuic => write!(f, "Tuic"),
            OutboundType::Socks5 => write!(f, "Socks5"),
            OutboundType::Hysteria2 => write!(f, "Hysteria2"),
            OutboundType::Ssh => write!(f, "Ssh"),
            OutboundType::Tailscale => write!(f, "Tailscale"),
            OutboundType::ShadowQuic => write!(f, "ShadowQuic"),

            OutboundType::UrlTest => write!(f, "URLTest"),
            OutboundType::Selector => write!(f, "Selector"),
            OutboundType::Relay => write!(f, "Relay"),
            OutboundType::LoadBalance => write!(f, "LoadBalance"),
            OutboundType::Smart => write!(f, "Smart"),
            OutboundType::Fallback => write!(f, "Fallback"),

            OutboundType::Direct => write!(f, "Direct"),
            OutboundType::Reject => write!(f, "Reject"),
        }
    }
}

pub enum ConnectorType {
    Tcp,
    All,
    None,
}

#[async_trait]
pub trait OutboundHandler: Sync + Send + Unpin + DialWithConnector + Debug {
    /// The name of the outbound handler
    fn name(&self) -> &str;

    /// The server name of the outbound handler, used for
    /// proxy-server-nameserver resolution
    fn server_name(&self) -> Option<&str> {
        None
    }

    /// The protocol of the outbound handler
    /// only contains Type information, do not rely on the underlying value
    fn proto(&self) -> OutboundType;

    /// whether the outbound handler support UDP
    async fn support_udp(&self) -> bool;

    /// connect to remote target via TCP
    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream>;

    /// connect to remote target via UDP
    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram>;

    /// relay related
    async fn support_connector(&self) -> ConnectorType;

    async fn connect_stream_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedStream> {
        error!("tcp relay not supported for {}", self.proto());
        Err(io::Error::other(format!(
            "tcp relay not supported for {}",
            self.proto()
        )))
    }

    async fn connect_datagram_with_connector(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
        _connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        Err(io::Error::other(format!(
            "udp relay not supported for {}",
            self.proto()
        )))
    }

    fn try_as_group_handler(&self) -> Option<&dyn GroupProxyAPIResponse> {
        None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        None
    }
}
pub type AnyOutboundHandler = Arc<dyn OutboundHandler>;

#[async_trait]
pub trait DialWithConnector {
    fn support_dialer(&self) -> Option<&str> {
        None
    }

    /// register a dialer for the outbound handler
    /// this must be called before the outbound handler is used
    async fn register_connector(&self, _: Arc<dyn RemoteConnector>) {}
}

/// Plain outbound implements this trait to serialize itself for rest API
/// response.
#[async_trait]
pub trait PlainProxyAPIResponse: OutboundHandler {
    /// used in the API responses.
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>>;
}
