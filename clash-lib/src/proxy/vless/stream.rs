use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

use crate::{proxy::AnyStream, session::SocksAddr};

const VLESS_VERSION: u8 = 0;
const VLESS_COMMAND_TCP: u8 = 1;
const VLESS_COMMAND_UDP: u8 = 2;

pub struct VlessStream {
    inner: AnyStream,
    handshake_done: bool,
    handshake_sent: bool,
    response_received: bool,
    uuid: uuid::Uuid,
    destination: SocksAddr,
    is_udp: bool,
    flow: Option<String>,
}

impl VlessStream {
    pub fn new(
        stream: AnyStream,
        uuid: &str,
        destination: &SocksAddr,
        is_udp: bool,
        flow: Option<String>,
    ) -> io::Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid UUID format")
        })?;

        debug!("VLESS stream created for destination: {}", destination);

        Ok(Self {
            inner: stream,
            handshake_done: false,
            handshake_sent: false,
            response_received: false,
            uuid,
            destination: destination.clone(),
            is_udp,
            flow,
        })
    }

    fn build_handshake_header(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // VLESS request header:
        // Version (1 byte) + UUID (16 bytes) + Addon length (1 byte)
        // + Addon bytes (variable) + Command (1 byte) + Port (2 bytes)
        // + Address type + Address
        buf.put_u8(VLESS_VERSION);
        buf.put_slice(self.uuid.as_bytes());

        if let Some(ref flow) = self.flow {
            let addon = build_addon_bytes(flow);
            buf.put_u8(addon.len() as u8);
            buf.extend_from_slice(&addon);
        } else {
            buf.put_u8(0); // No addon
        }

        if self.is_udp {
            buf.put_u8(VLESS_COMMAND_UDP);
        } else {
            buf.put_u8(VLESS_COMMAND_TCP);
        }

        self.destination.write_to_buf_vmess(&mut buf);
        buf
    }

    async fn send_handshake_with_data(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.handshake_sent {
            return Ok(0);
        }

        debug!(
            "VLESS handshake starting for destination: {}",
            self.destination
        );

        let mut buf = self.build_handshake_header();
        buf.put_slice(data);

        // Send handshake + first data
        tokio::io::AsyncWriteExt::write_all(&mut self.inner, &buf)
            .await
            .map_err(|e| {
                error!("Failed to send VLESS handshake: {}", e);
                e
            })?;

        self.handshake_sent = true;
        debug!("VLESS handshake sent with {} bytes of data", data.len());

        Ok(data.len())
    }

    async fn receive_response(&mut self) -> io::Result<()> {
        if self.response_received {
            return Ok(());
        }

        debug!("VLESS waiting for response");

        // Read response (VLESS response is just version + additional info
        // length + additional info)
        let mut response = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut self.inner, &mut response)
            .await
            .map_err(|e| {
                error!("Failed to read VLESS response: {}", e);
                e
            })?;

        if response[0] != VLESS_VERSION {
            error!("Invalid VLESS response version: {}", response[0]);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid VLESS response version: {}", response[0]),
            ));
        }

        let additional_info_len = response[1];

        if additional_info_len > 0 {
            let mut additional_info = vec![0u8; additional_info_len as usize];
            tokio::io::AsyncReadExt::read_exact(
                &mut self.inner,
                &mut additional_info,
            )
            .await
            .map_err(|e| {
                error!("Failed to read VLESS additional info: {}", e);
                e
            })?;
            debug!(
                "VLESS additional info received: {} bytes: {:02x?}",
                additional_info_len,
                &additional_info[..additional_info_len.min(32) as usize],
            );
        }

        self.response_received = true;
        self.handshake_done = true;
        debug!("VLESS handshake completed successfully");

        Ok(())
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Must receive response before reading
        if self.handshake_sent && !self.response_received {
            let fut = self.receive_response();
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // Send handshake with first write
        if !self.handshake_sent {
            let fut = self.send_handshake_with_data(buf);
            tokio::pin!(fut);
            match fut.poll(cx) {
                Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Encode the flow field as a Protobuf field-1 length-delimited value.
/// Format: [0x0A][varint len][bytes]
pub(crate) fn build_addon_bytes(flow: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + flow.len());
    buf.push(0x0A); // field 1, wire type 2 (length-delimited)
    buf.push(flow.len() as u8); // single-byte varint (flow strings are short)
    buf.extend_from_slice(flow.as_bytes());
    buf
}

impl crate::proxy::ProxyStream for VlessStream {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SocksAddr;

    fn dummy_stream() -> AnyStream {
        let (client, _server) = tokio::io::duplex(1024);
        Box::new(client)
    }

    fn tcp_dest() -> SocksAddr {
        "1.2.3.4:80".parse().unwrap()
    }

    // --- build_addon_bytes ---

    #[test]
    fn test_build_addon_bytes_empty_flow() {
        let addon = build_addon_bytes("");
        // tag(1) + len(0) = 2 bytes, no payload
        assert_eq!(addon, vec![0x0A, 0x00]);
    }

    #[test]
    fn test_build_addon_bytes_vision_flow() {
        let flow = "xtls-rprx-vision";
        let addon = build_addon_bytes(flow);
        assert_eq!(addon.len(), 2 + flow.len()); // 18 bytes
        assert_eq!(addon[0], 0x0A); // field-1, wire-type-2 tag
        assert_eq!(addon[1], flow.len() as u8); // 0x10 = 16
        assert_eq!(&addon[2..], flow.as_bytes());
    }

    // --- build_handshake_header ---

    #[test]
    fn test_handshake_header_no_flow() {
        let s = VlessStream::new(
            dummy_stream(),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            false,
            None,
        )
        .unwrap();
        let hdr = s.build_handshake_header();
        // byte 17 (0-indexed) is the addon-length byte
        assert_eq!(hdr[17], 0); // no addon
    }

    #[test]
    fn test_handshake_header_with_flow() {
        let flow = "xtls-rprx-vision";
        let s = VlessStream::new(
            dummy_stream(),
            "5415d8e0-df92-3655-afa4-b79de66413f5",
            &tcp_dest(),
            false,
            Some(flow.to_string()),
        )
        .unwrap();
        let hdr = s.build_handshake_header();
        let addon_len = hdr[17] as usize;
        assert_eq!(addon_len, 2 + flow.len()); // 18
        let addon = &hdr[18..18 + addon_len];
        assert_eq!(addon[0], 0x0A);
        assert_eq!(addon[1], flow.len() as u8);
        assert_eq!(&addon[2..], flow.as_bytes());
    }

    // --- new() ---

    #[test]
    fn test_new_invalid_uuid() {
        let result =
            VlessStream::new(dummy_stream(), "not-a-uuid", &tcp_dest(), false, None);
        assert!(result.is_err());
    }
}
