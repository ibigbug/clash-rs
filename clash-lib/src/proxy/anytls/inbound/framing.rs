//! AnyTLS frame codec — read/write the wire format and protocol constants.

use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// AnyTLS frame command bytes — same as outbound.
pub(crate) const CMD_WASTE: u8 = 0;
pub(crate) const CMD_SYN: u8 = 1;
pub(crate) const CMD_PSH: u8 = 2;
pub(crate) const CMD_FIN: u8 = 3;
pub(crate) const CMD_SETTINGS: u8 = 4;
pub(crate) const CMD_ALERT: u8 = 5;

/// The magic hostname used by the client for UDP-over-TCP v2 sessions.
pub(crate) const UDP_OVER_TCP_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";

/// Read one AnyTLS frame: `CMD(1) | StreamID(u32-BE) | DataLen(u16-BE) | Data`.
pub(crate) async fn read_frame(
    reader: &mut (impl AsyncRead + Unpin),
) -> std::io::Result<(u8, u32, Vec<u8>)> {
    let mut header = [0u8; 7];
    reader.read_exact(&mut header).await?;
    let command = header[0];
    let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let data_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        reader.read_exact(&mut data).await?;
    }
    Ok((command, stream_id, data))
}

/// Write one AnyTLS frame to `writer`.
pub(crate) async fn write_frame(
    writer: &mut (impl AsyncWrite + Unpin),
    command: u8,
    stream_id: u32,
    data: &[u8],
) -> std::io::Result<()> {
    if data.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "anytls frame payload exceeds 65535 bytes",
        ));
    }
    let mut buf = BytesMut::with_capacity(7 + data.len());
    buf.put_u8(command);
    buf.put_u32(stream_id);
    buf.put_u16(data.len() as u16);
    if !data.is_empty() {
        buf.put_slice(data);
    }
    writer.write_all(&buf).await
}
