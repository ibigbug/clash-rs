pub(crate) async fn connect(
    proxy_addr: std::net::SocketAddr,
    target_host: &str,
    target_port: u16,
) -> std::io::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(std::io::Error::other("SOCKS5 auth negotiation failed"));
    }
    let mut req = Vec::with_capacity(10 + target_host.len());
    if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
        req.extend_from_slice(&ip.octets());
    } else {
        let host_bytes = target_host.as_bytes();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[..3] != [5, 0, 0] {
        return Err(std::io::Error::other(format!(
            "invalid SOCKS5 CONNECT response: {:?}",
            &hdr[..3]
        )));
    }
    let addr_len = match hdr[3] {
        1 => 4,
        3 => stream.read_u8().await? as usize,
        4 => 16,
        atyp => {
            return Err(std::io::Error::other(format!(
                "unexpected SOCKS5 address type {atyp}"
            )));
        }
    };
    stream.read_exact(&mut vec![0; addr_len + 2]).await?;
    Ok(stream)
}
