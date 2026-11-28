use async_trait::async_trait;
use rustls::{
    ClientConfig, RootCertStore, client::RealityConfig, pki_types::ServerName,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use std::{
    io,
    ops::Deref,
    sync::{Arc, OnceLock, atomic::AtomicBool},
};

use crate::proxy::{
    AnyStream,
    transport::{
        Transport, VisionOptions,
        splice_tls::{RecordChunkIo, SplicableTlsStream},
    },
};

fn init_roots() -> Arc<RootCertStore> {
    Arc::new(webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect())
}

#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

impl Client {
    pub fn new(sni: String, public_key: [u8; 32], short_id: Vec<u8>) -> Self {
        Self(Arc::new(ClientInner {
            sni,
            public_key,
            short_id,
            roots: OnceLock::new(),
        }))
    }
}

impl Deref for Client {
    type Target = ClientInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Client {
    /// Connect with Reality TLS and return the concrete `TlsStream` (not
    /// boxed).  Used by XTLS-Vision splice mode so VisionStream can later
    /// bypass the TLS layer for raw-copy.
    pub async fn connect_tls(
        &self,
        stream: AnyStream,
    ) -> io::Result<TlsStream<AnyStream>> {
        let reality = RealityConfig::new(self.public_key, self.short_id.clone())
            .map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;

        let tls_config = ClientConfig::builder()
            .with_root_certificates(self.roots.get_or_init(init_roots).clone())
            .with_reality(reality)
            .with_no_client_auth();

        let sni: ServerName<'_> =
            ServerName::try_from(self.sni.clone()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;

        TlsConnector::from(std::sync::Arc::new(tls_config))
            .connect(sni, stream)
            .await
            .map_err(io::Error::other)
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.connect_tls(stream)
            .await
            .map(|x| Box::new(x) as AnyStream)
    }

    /// Establish a Reality TLS connection and return the stream together with
    /// `VisionOptions` (an `Arc<AtomicBool>` splice flag) that allow the upper
    /// `VisionStream` to signal this layer when the server switches its
    /// downlink to raw copy.
    ///
    /// ## Layer stack
    ///
    /// ```text
    ///  VisionStream          (owns VisionOptions – writes the flag)
    ///    └─ VlessStream      (VLESS framing)
    ///        └─ SplicableTlsStream  (reads the flag; reads raw when set)
    ///            └─ Reality TLS
    ///                └─ RecordChunkIo   (one TLS record per read until the flag)
    ///                    └─ TCP
    /// ```
    ///
    /// ## Handshake / splice sequence
    ///
    /// ```text
    ///  Client                                  Xray server
    ///    |                                          |
    ///    |---------- Reality TLS handshake -------->|
    ///    |<--------- Reality TLS handshake ---------|
    ///    |   (all traffic below is Reality-TLS encrypted on the wire)
    ///    |                                          |
    ///    |====== Vision framing (both directions) ==|
    ///    |--[UUID][CMD=0x00][inner TLS ClientHello]->|
    ///    |<-[UUID][CMD=0x00][inner TLS ServerHello]--|
    ///    |<-[CMD=0x00][inner TLS records]-----------|
    ///    |                                          |
    ///    |  server recognises inner TLS 1.3         |
    ///    |                                          |
    ///    |<--[CMD=0x02][inner TLS AppData]----------|  server leaves TLS
    ///    |      (everything after this is RAW)      |
    ///    |<==[raw inner-TLS records]================|  no outer TLS on downlink
    ///    |                                          |
    ///    |==[CMD=0x00 frames, inside Reality TLS]==>|  uplink stays framed
    ///    ```
    ///
    /// The client never sends `CMD_PADDING_DIRECT`: its uplink stays framed
    /// inside Reality TLS, and so does the server's uplink reader.
    async fn proxy_stream_spliced(
        &self,
        stream: AnyStream,
    ) -> io::Result<(AnyStream, Option<VisionOptions>)> {
        let read_flag = Arc::new(AtomicBool::new(false));
        let chunked: AnyStream =
            Box::new(RecordChunkIo::new(stream, Arc::clone(&read_flag)));
        let tls_stream = self.connect_tls(chunked).await?;
        let splicable = SplicableTlsStream::new(tls_stream, Arc::clone(&read_flag));
        let opts = VisionOptions { read_flag };
        Ok((Box::new(splicable), Some(opts)))
    }
}

pub struct ClientInner {
    sni: String,
    public_key: [u8; 32],
    short_id: Vec<u8>,
    // cached for performance
    roots: OnceLock<Arc<RootCertStore>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        crate::setup_default_crypto_provider();
    }

    fn make_stream() -> AnyStream {
        let (client, _server) = tokio::io::duplex(1024);
        Box::new(client)
    }

    #[test]
    fn test_new() {
        let c = Client::new("example.com".to_string(), [1u8; 32], vec![0xab, 0xcd]);
        assert_eq!(c.sni, "example.com");
        assert_eq!(c.public_key, [1u8; 32]);
        assert_eq!(c.short_id, vec![0xab, 0xcd]);
    }

    // short_id > 8 bytes → RealityConfig::new() fails → InvalidInput
    #[tokio::test]
    async fn test_short_id_too_long() {
        setup();
        let c = Client::new("example.com".to_string(), [0u8; 32], vec![0u8; 9]);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // Invalid SNI → ServerName::try_from fails → InvalidInput
    #[tokio::test]
    async fn test_invalid_sni() {
        setup();
        let c = Client::new("".to_string(), [0u8; 32], vec![0u8; 4]);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    // Valid params, server side dropped → TLS handshake error (not
    // InvalidInput)
    #[tokio::test]
    async fn test_handshake_error_on_closed_peer() {
        setup();
        let c = Client::new("example.com".to_string(), [0u8; 32], vec![0u8; 4]);
        let err = c.proxy_stream(make_stream()).await.err().unwrap();
        assert_ne!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
