use std::{fmt::Debug, pin::Pin};

use shadowsocks::ProxyClientStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::AnyStream;

/// Upper bound for the payload of the first write.
///
/// `ProxyClientStream` prepends the target address to the first write and
/// encrypts the result as one packet, but an AEAD packet carries at most
/// `0x3FFF` bytes. Anything beyond that is cut off while the call still
/// reports the whole `buf` as written, silently dropping data (a
/// `debug_assert!` catches it in debug builds). Leave room for the longest
/// address (1 + 1 + 255 + 2 bytes) plus the AEAD-2022 padding length field.
const MAX_FIRST_WRITE: usize = 0x3FFF - 259 - 2;

pub struct ShadowSocksStream {
    inner: ProxyClientStream<AnyStream>,
    first_write_done: bool,
}

impl ShadowSocksStream {
    pub fn new(inner: ProxyClientStream<AnyStream>) -> Self {
        Self {
            inner,
            first_write_done: false,
        }
    }
}

impl Debug for ShadowSocksStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ShadowSocksStream").finish()
    }
}

impl AsyncRead for ShadowSocksStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShadowSocksStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        let buf = if this.first_write_done {
            buf
        } else {
            &buf[..buf.len().min(MAX_FIRST_WRITE)]
        };
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if res.is_ready() {
            this.first_write_done = true;
        }
        res
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl crate::proxy::ProxyStream for ShadowSocksStream {}

#[cfg(test)]
mod tests {
    use shadowsocks::{
        ProxyClientStream,
        config::{ServerConfig, ServerType},
        context::Context,
        crypto::CipherKind,
        relay::{Address, tcprelay::ProxyServerStream},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::ShadowSocksStream;

    async fn first_write_is_delivered_intact(method: CipherKind, password: &str) {
        let cfg = ServerConfig::new(("127.0.0.1", 8388), password, method).unwrap();
        let (client_io, server_io) = tokio::io::duplex(1024 * 1024);

        let client = ProxyClientStream::from_stream(
            Context::new_shared(ServerType::Local),
            Box::new(client_io) as _,
            &cfg,
            Address::DomainNameAddress("example.org".to_owned(), 443),
        );
        let mut client = ShadowSocksStream::new(client);

        // Larger than one AEAD packet, as a relay copying 64 KiB at a time
        // would produce.
        let payload: Vec<u8> = (0..64 * 1024).map(|i| i as u8).collect();
        let writer = async {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            client
        };

        let reader = async {
            let mut server = ProxyServerStream::from_stream(
                Context::new_shared(ServerType::Server),
                server_io,
                method,
                cfg.key(),
            );
            server.handshake().await.unwrap();
            let mut received = vec![0u8; payload.len()];
            server.read_exact(&mut received).await.unwrap();
            received
        };

        let (_client, received) = tokio::join!(writer, reader);
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn first_write_larger_than_a_packet_aead() {
        first_write_is_delivered_intact(CipherKind::AES_256_GCM, "FzcLbKs2dY9mhL")
            .await;
    }

    #[tokio::test]
    async fn first_write_larger_than_a_packet_aead_2022() {
        first_write_is_delivered_intact(
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            "3SYJ/f8nmVuzKvKglykRQDSgg10e/ADilkdRWrrY9HU=",
        )
        .await;
    }
}
