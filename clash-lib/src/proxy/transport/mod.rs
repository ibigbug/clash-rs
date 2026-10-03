mod grpc;
mod h2;
mod reality;
#[cfg(feature = "shadowsocks")]
mod shadow_tls;
#[cfg(feature = "shadowsocks")]
mod simple_obfs;
pub mod splice_tls;
mod tls;
#[cfg(feature = "shadowsocks")]
mod v2ray;
mod ws;
mod xhttp;

pub use grpc::Client as GrpcClient;
pub use h2::Client as H2Client;
pub use reality::Client as RealityClient;
#[cfg(feature = "shadowsocks")]
pub use shadow_tls::Client as Shadowtls;
#[cfg(feature = "shadowsocks")]
pub use simple_obfs::{
    SimpleOBFSMode, SimpleOBFSOption, SimpleObfsHttp, SimpleObfsTLS,
};
pub use splice_tls::VisionOptions;
pub use tls::Client as TlsClient;
#[cfg(feature = "shadowsocks")]
pub use v2ray::{V2RayOBFSOption, V2rayWsClient};
pub use ws::Client as WsClient;
pub use xhttp::Client as XhttpClient;

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn proxy_stream(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream>;

    /// Like `proxy_stream`, but additionally returns a `VisionOptions` for
    /// transports that support XTLS-splice (Reality).  The default
    /// implementation delegates to `proxy_stream` and returns `None`,
    /// meaning no splice is available.
    async fn proxy_stream_spliced(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<(super::AnyStream, Option<VisionOptions>)> {
        Ok((self.proxy_stream(stream).await?, None))
    }
}

/// A closed set of transport layers.
///
/// Replaces `Box<dyn Transport>` storage: the transport set is small and
/// stable, so a closed enum gives static dispatch with no per-layer heap
/// allocation while keeping the same runtime, config-driven composition
/// (a handler holds an ordered stack of these and applies them in turn).
#[allow(clippy::large_enum_variant)]
pub enum TransportLayer {
    Tls(TlsClient),
    Reality(RealityClient),
    Grpc(GrpcClient),
    H2(H2Client),
    Ws(WsClient),
    Xhttp(XhttpClient),
    #[cfg(feature = "shadowsocks")]
    ShadowTls(Shadowtls),
    #[cfg(feature = "shadowsocks")]
    SimpleObfsHttp(SimpleObfsHttp),
    #[cfg(feature = "shadowsocks")]
    SimpleObfsTls(SimpleObfsTLS),
    #[cfg(feature = "shadowsocks")]
    V2rayWs(V2rayWsClient),
}

impl TransportLayer {
    pub async fn wrap(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<super::AnyStream> {
        match self {
            Self::Tls(t) => Transport::proxy_stream(t, stream).await,
            Self::Reality(t) => Transport::proxy_stream(t, stream).await,
            Self::Grpc(t) => Transport::proxy_stream(t, stream).await,
            Self::H2(t) => Transport::proxy_stream(t, stream).await,
            Self::Ws(t) => Transport::proxy_stream(t, stream).await,
            Self::Xhttp(t) => Transport::proxy_stream(t, stream).await,
            #[cfg(feature = "shadowsocks")]
            Self::ShadowTls(t) => Transport::proxy_stream(t, stream).await,
            #[cfg(feature = "shadowsocks")]
            Self::SimpleObfsHttp(t) => Transport::proxy_stream(t, stream).await,
            #[cfg(feature = "shadowsocks")]
            Self::SimpleObfsTls(t) => Transport::proxy_stream(t, stream).await,
            #[cfg(feature = "shadowsocks")]
            Self::V2rayWs(t) => Transport::proxy_stream(t, stream).await,
        }
    }

    pub async fn wrap_spliced(
        &self,
        stream: super::AnyStream,
    ) -> std::io::Result<(super::AnyStream, Option<VisionOptions>)> {
        match self {
            Self::Reality(t) => Transport::proxy_stream_spliced(t, stream).await,
            other => Ok((other.wrap(stream).await?, None)),
        }
    }
}
