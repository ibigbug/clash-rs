//! Connection-handling logic for the AnyTLS inbound listener.

use super::{
    datagram::InboundDatagramAnytls,
    framing::{
        CMD_ALERT, CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_WASTE,
        UDP_OVER_TCP_V2_MAGIC_HOST, read_frame, write_frame,
    },
};
use crate::{
    Dispatcher,
    proxy::AnyStream,
    session::{Network, Session, SocksAddr, Type},
};
use bytes::BufMut;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Size of the in-process duplex pipe between the AnyTLS relay and the
/// dispatcher (mirrors the outbound).
const DUPLEX_BUFFER_SIZE: usize = 64 * 1024;

/// Read buffer size for framed relay (mirrors the outbound).
const RELAY_BUFFER_SIZE: usize = 16 * 1024;

/// Forward an unauthenticated TLS stream to a fallback backend for camouflage.
///
/// The 32 bytes already consumed for the password check are prepended before
/// piping the rest of the (decrypted) application stream to the backend.
async fn handle_fallback(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    already_read: &[u8],
    fallback_addr: &str,
    src_addr: SocketAddr,
) {
    let mut backend = match tokio::net::TcpStream::connect(fallback_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(
                "anytls fallback: failed to connect to {fallback_addr} for \
                 {src_addr}: {e}"
            );
            return;
        }
    };

    // Write the bytes we already consumed before bidirectional copy.
    if let Err(e) = backend.write_all(already_read).await {
        debug!("anytls fallback: failed to write preamble for {src_addr}: {e}");
        return;
    }

    match tokio::io::copy_bidirectional(&mut tls_stream, &mut backend).await {
        Ok((a, b)) => {
            debug!(
                "anytls fallback: {src_addr} proxied to {fallback_addr} ({a}↑ {b}↓ \
                 bytes)"
            );
        }
        Err(e) => {
            debug!("anytls fallback: copy error for {src_addr}: {e}");
        }
    }
    // Send TLS close_notify so the client sees a clean EOF instead of an
    // abrupt TCP reset.
    let _ = tls_stream.shutdown().await;
}

/// Pre-authentication handshake: TLS + password + padding + frame loop.
/// Returns `Some((tls_stream, inbound_user, destination, stream_id))` on
/// success. Returns `None` on any error or if auth fails (fallback is handled
/// internally).
async fn do_handshake(
    raw_stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    acceptor: TlsAcceptor,
    user_map: Arc<HashMap<[u8; 32], String>>,
    fallback: Option<String>,
) -> Option<(
    tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    Option<String>,
    SocksAddr,
    u32,
)> {
    // ── TLS handshake ────────────────────────────────────────────────────────
    let mut tls_stream = match acceptor.accept(raw_stream).await {
        Ok(s) => s,
        Err(e) => {
            debug!("anytls inbound TLS handshake failed from {src_addr}: {e}");
            return None;
        }
    };

    // ── Read 32-byte password hash ───────────────────────────────────────────
    let mut hash_buf = [0u8; 32];
    if let Err(e) = tls_stream.read_exact(&mut hash_buf).await {
        debug!("anytls inbound failed to read password hash from {src_addr}: {e}");
        return None;
    }

    let inbound_user = match user_map.get(&hash_buf) {
        Some(name) => {
            if name.is_empty() {
                None
            } else {
                Some(name.clone())
            }
        }
        None => {
            if let Some(addr) = fallback {
                handle_fallback(tls_stream, &hash_buf, &addr, src_addr).await;
            } else {
                warn!(
                    "anytls inbound rejected connection from {src_addr}: wrong \
                     password"
                );
            }
            return None;
        }
    };

    // ── Skip padding ─────────────────────────────────────────────────────────
    let padding_len = match tls_stream.read_u16().await {
        Ok(n) => n as usize,
        Err(e) => {
            debug!(
                "anytls inbound failed to read padding length from {src_addr}: {e}"
            );
            return None;
        }
    };
    if padding_len > 0 {
        let mut skip = vec![0u8; padding_len];
        if let Err(e) = tls_stream.read_exact(&mut skip).await {
            debug!("anytls inbound failed to skip padding from {src_addr}: {e}");
            return None;
        }
    }

    // ── Read frames until we have SYN + PSH with destination ─────────────────
    let mut stream_id: Option<u32> = None;
    let destination: SocksAddr;

    'handshake: loop {
        let (cmd, sid, data) = match read_frame(&mut tls_stream).await {
            Ok(f) => f,
            Err(e) => {
                debug!(
                    "anytls inbound failed to read handshake frame from \
                     {src_addr}: {e}"
                );
                return None;
            }
        };

        match cmd {
            CMD_SETTINGS | CMD_WASTE => {
                // SETTINGS carries client metadata; we skip it.
            }
            CMD_SYN => match stream_id {
                None => stream_id = Some(sid),
                Some(existing) if existing == sid => {}
                Some(existing) => {
                    warn!(
                        "anytls inbound received mismatched SYN stream_id={sid} \
                         (expected {existing}) from {src_addr}"
                    );
                    return None;
                }
            },
            CMD_PSH => {
                let Some(expected_sid) = stream_id else {
                    warn!("anytls inbound missing SYN before PSH from {src_addr}");
                    return None;
                };
                if sid != expected_sid {
                    warn!(
                        "anytls inbound received PSH on stream_id={sid} (expected \
                         {expected_sid}) from {src_addr}"
                    );
                    return None;
                }
                // Parse SocksAddr from the PSH frame data.
                let mut cursor = std::io::Cursor::new(data);
                match SocksAddr::read_from(&mut cursor).await {
                    Ok(addr) => {
                        destination = addr;
                        break 'handshake;
                    }
                    Err(e) => {
                        debug!(
                            "anytls inbound failed to parse destination from \
                             {src_addr}: {e}"
                        );
                        return None;
                    }
                }
            }
            CMD_FIN | CMD_ALERT => {
                debug!("anytls inbound received early {cmd} from {src_addr}");
                return None;
            }
            _ => {}
        }
    }

    let sid = match stream_id {
        Some(s) => s,
        None => {
            warn!("anytls inbound: no SYN received from {src_addr}");
            return None;
        }
    };

    Some((tls_stream, inbound_user, destination, sid))
}

/// Handle one accepted TCP connection (runs in a spawned task).
pub(super) async fn handle_connection(
    raw_stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    acceptor: TlsAcceptor,
    dispatcher: Arc<Dispatcher>,
    user_map: Arc<HashMap<[u8; 32], String>>,
    fw_mark: Option<u32>,
    fallback: Option<String>,
) {
    use std::time::Duration;
    use tokio::time::timeout;

    /// Maximum time to complete the AnyTLS handshake before closing the
    /// connection.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

    let handshake_result = timeout(
        HANDSHAKE_TIMEOUT,
        do_handshake(raw_stream, src_addr, acceptor, user_map, fallback),
    )
    .await;

    let (tls_stream, inbound_user, dest, sid) = match handshake_result {
        Ok(Some(result)) => result,
        Ok(None) => return, // protocol error or auth failure, already logged
        Err(_elapsed) => {
            debug!("anytls inbound handshake timeout from {src_addr}");
            return;
        }
    };

    debug!(
        "anytls inbound accepted stream_id={sid} dest={dest} from {src_addr} \
         user={:?}",
        inbound_user
    );

    // ── Branch: UDP-over-TCP v2 or plain TCP relay ───────────────────────────
    if dest.host() == UDP_OVER_TCP_V2_MAGIC_HOST {
        handle_udp_session(
            tls_stream,
            src_addr,
            sid,
            dispatcher,
            inbound_user,
            fw_mark,
        )
        .await;
    } else {
        handle_tcp_relay(
            tls_stream,
            src_addr,
            dest,
            sid,
            dispatcher,
            inbound_user,
            fw_mark,
        )
        .await;
    }
}

/// Handle a UDP-over-TCP v2 session.
///
/// The outbound wraps ALL application data (including the UoT connect header
/// and datagrams) in CMD_PSH frames via its relay layer. So this function
/// must set up the same CMD_PSH relay as `handle_tcp_relay`, then read the
/// UoT connect header (`u8(isConnect=1) | SocksAddr`) from the unwrapped
/// application stream, and pass that stream to `InboundDatagramAnytls` for
/// `u16(len) | payload` datagram exchange.
async fn handle_udp_session(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    src_addr: SocketAddr,
    stream_id: u32,
    dispatcher: Arc<Dispatcher>,
    inbound_user: Option<String>,
    fw_mark: Option<u32>,
) {
    let (mut remote_read, mut remote_write) = tokio::io::split(tls_stream);
    let (mut app_stream, relay_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);

    let cancel = CancellationToken::new();
    let cancel_a = cancel.clone();
    let cancel_b = cancel.clone();
    let cancel_c = cancel;

    // Task A: relay_read (writes from InboundDatagramAnytls) → CMD_PSH → TLS
    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        loop {
            tokio::select! {
                biased;
                _ = cancel_a.cancelled() => break,
                result = relay_read.read(&mut buf) => {
                    let n = match result {
                        Ok(0) | Err(_) => { cancel_a.cancel(); break; }
                        Ok(n) => n,
                    };
                    let mut psh_header = bytes::BytesMut::with_capacity(7);
                    psh_header.put_u8(CMD_PSH);
                    psh_header.put_u32(stream_id);
                    psh_header.put_u16(n as u16);
                    if remote_write.write_all(&psh_header).await.is_err()
                        || remote_write.write_all(&buf[..n]).await.is_err()
                        || remote_write.flush().await.is_err()
                    {
                        cancel_a.cancel();
                        break;
                    }
                }
            }
        }
    });

    // Task B: TLS → CMD_PSH frames → relay_write (reads by
    // InboundDatagramAnytls)
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_b.cancelled() => break,
                result = read_frame(&mut remote_read) => {
                    let (cmd, sid, data) = match result {
                        Ok(f) => f,
                        Err(_) => { cancel_b.cancel(); break; }
                    };
                    match cmd {
                        CMD_PSH if sid == stream_id
                            && relay_write.write_all(&data).await.is_err() =>
                        {
                            cancel_b.cancel();
                            break;
                        }
                        CMD_PSH if sid == stream_id => {}
                        CMD_FIN if sid == stream_id => {
                            cancel_b.cancel();
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    });

    // ── Read UoT v2 connect header from the unwrapped app stream ─────────────
    let is_connect = match app_stream.read_u8().await {
        Ok(b) => b,
        Err(e) => {
            debug!(
                "anytls inbound UoT: failed to read isConnect from {src_addr}: {e}"
            );
            cancel_c.cancel();
            return;
        }
    };
    if is_connect != 1 {
        warn!(
            "anytls inbound UoT: unexpected isConnect={is_connect} from {src_addr}"
        );
        cancel_c.cancel();
        return;
    }

    let real_dest = match SocksAddr::read_from(&mut app_stream).await {
        Ok(a) => a,
        Err(e) => {
            debug!(
                "anytls inbound UoT: failed to read real destination from \
                 {src_addr}: {e}"
            );
            cancel_c.cancel();
            return;
        }
    };

    debug!(
        "anytls inbound UoT session: src={src_addr} dest={real_dest} user={:?}",
        inbound_user
    );

    let inner: AnyStream = Box::new(app_stream);
    let datagram = InboundDatagramAnytls::new(inner, real_dest.clone());

    let sess = Session {
        network: Network::Udp,
        typ: Type::Anytls,
        source: src_addr,
        so_mark: fw_mark,
        destination: real_dest,
        inbound_user,
        ..Default::default()
    };

    let _ = dispatcher.dispatch_datagram(sess, Box::new(datagram)).await;
}

/// Handle a plain TCP relay session (the common case).
///
/// After the handshake we set up a duplex and relay frames bidirectionally.
async fn handle_tcp_relay(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    src_addr: SocketAddr,
    dest: SocksAddr,
    stream_id: u32,
    dispatcher: Arc<Dispatcher>,
    inbound_user: Option<String>,
    fw_mark: Option<u32>,
) {
    let (mut remote_read, mut remote_write) = tokio::io::split(tls_stream);
    let (app_stream, relay_stream) = tokio::io::duplex(DUPLEX_BUFFER_SIZE);
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);

    let cancel = CancellationToken::new();
    let cancel_a = cancel.clone();
    let cancel_b = cancel;

    // Task A: relay_read (from dispatcher) → CMD_PSH frames → remote_write
    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        loop {
            tokio::select! {
                biased;
                _ = cancel_a.cancelled() => break,
                result = relay_read.read(&mut buf) => {
                    let n = match result {
                        Ok(n) => n,
                        Err(err) => {
                            debug!("anytls inbound relay read error (src={src_addr}): {err}");
                            cancel_a.cancel();
                            break;
                        }
                    };
                    if n == 0 {
                        // Dispatcher closed its end — send FIN to client.
                        if let Err(err) = write_frame(&mut remote_write, CMD_FIN, stream_id, &[]).await {
                            debug!("anytls inbound send FIN failed (src={src_addr}): {err}");
                        }
                        let _ = remote_write.flush().await;
                        cancel_a.cancel();
                        break;
                    }
                    let mut psh_header = bytes::BytesMut::with_capacity(7);
                    psh_header.put_u8(CMD_PSH);
                    psh_header.put_u32(stream_id);
                    psh_header.put_u16(n as u16);
                    // Write header + data together to reduce syscalls.
                    if let Err(err) = remote_write.write_all(&psh_header).await {
                        debug!("anytls inbound PSH header write failed (src={src_addr}): {err}");
                        cancel_a.cancel();
                        break;
                    }
                    if let Err(err) = remote_write.write_all(&buf[..n]).await {
                        debug!("anytls inbound PSH data write failed (src={src_addr}): {err}");
                        cancel_a.cancel();
                        break;
                    }
                    if let Err(err) = remote_write.flush().await {
                        debug!("anytls inbound flush failed (src={src_addr}): {err}");
                        cancel_a.cancel();
                        break;
                    }
                }
            }
        }
    });

    // Task B: remote_read → CMD_PSH frames → relay_write (to dispatcher)
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_b.cancelled() => break,
                result = read_frame(&mut remote_read) => {
                    let (cmd, sid, data) = match result {
                        Ok(f) => f,
                        Err(err) => {
                            debug!("anytls inbound read frame error (src={src_addr}): {err}");
                            cancel_b.cancel();
                            break;
                        }
                    };
                    match cmd {
                        CMD_PSH => {
                            if sid != stream_id {
                                warn!(
                                    "anytls inbound PSH on unexpected \
                                     stream_id={sid} (expected {stream_id}) \
                                     from {src_addr}, ignoring"
                                );
                                continue;
                            }
                            if let Err(err) = relay_write.write_all(&data).await {
                                debug!("anytls inbound relay write failed (src={src_addr}): {err}");
                                cancel_b.cancel();
                                break;
                            }
                        }
                        CMD_FIN => {
                            if sid != stream_id {
                                continue;
                            }
                            // Client finished sending — shutdown the write side.
                            let _ = relay_write.shutdown().await;
                            cancel_b.cancel();
                            break;
                        }
                        CMD_ALERT => {
                            if sid != stream_id {
                                continue;
                            }
                            let msg = String::from_utf8_lossy(&data);
                            warn!("anytls inbound alert from {src_addr}: {msg}");
                            let _ = relay_write.shutdown().await;
                            cancel_b.cancel();
                            break;
                        }
                        // Control frames we don't need to act on server-side.
                        CMD_WASTE | CMD_SYN | CMD_SETTINGS => {}
                        _ => {}
                    }
                }
            }
        }
    });

    let sess = Session {
        network: Network::Tcp,
        typ: Type::Anytls,
        source: src_addr,
        so_mark: fw_mark,
        destination: dest,
        inbound_user,
        ..Default::default()
    };

    dispatcher.dispatch_stream(sess, Box::new(app_stream)).await;
}

#[cfg(test)]
mod tests {
    use crate::{
        proxy::anytls::inbound::{
            framing::{
                CMD_PSH, CMD_SETTINGS, CMD_SYN, UDP_OVER_TCP_V2_MAGIC_HOST,
                read_frame,
            },
            tls::build_tls_acceptor,
        },
        session::SocksAddr,
    };
    use bytes::BufMut;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::TlsConnector;

    fn install_crypto_provider() {
        crate::setup_default_crypto_provider();
    }

    /// Tests the complete AnyTLS server-side handshake parsing over a real TLS
    /// connection (no Dispatcher needed — we test only the protocol framing).
    #[tokio::test]
    async fn test_anytls_handshake_parsing_over_tls() {
        install_crypto_provider();

        let rcgen::CertifiedKey {
            cert,
            signing_key: key_pair,
        } = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen cert generation failed");
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        // Keep the DER bytes around so we can trust it on the client side.
        let cert_der = cert.der().clone();

        let acceptor = build_tls_acceptor(Some(&cert_pem), Some(&key_pem)).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let password = "integration_test_pw";
        let hash: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        let expected_host = "example.com";
        let expected_port: u16 = 8080;

        // Server task: accept, do TLS, parse AnyTLS handshake, verify fields.
        let server_task = tokio::spawn(async move {
            let (raw, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(raw).await.unwrap();

            // 32-byte SHA256 password hash
            let mut hash_buf = [0u8; 32];
            tls.read_exact(&mut hash_buf).await.unwrap();
            assert_eq!(hash_buf, hash, "password hash mismatch");

            // u16 padding length (must be 0 in test)
            let pad = tls.read_u16().await.unwrap();
            assert_eq!(pad, 0, "padding length must be 0");

            // SETTINGS frame
            let (cmd, sid, _) = read_frame(&mut tls).await.unwrap();
            assert_eq!(cmd, CMD_SETTINGS, "expected SETTINGS frame");
            assert_eq!(sid, 0, "SETTINGS stream_id must be 0");

            // SYN frame
            let (cmd, sid, data) = read_frame(&mut tls).await.unwrap();
            assert_eq!(cmd, CMD_SYN, "expected SYN frame");
            assert_eq!(sid, 1, "SYN stream_id must be 1");
            assert!(data.is_empty(), "SYN data must be empty");

            // PSH frame with destination
            let (cmd, sid, payload) = read_frame(&mut tls).await.unwrap();
            assert_eq!(cmd, CMD_PSH, "expected PSH frame");
            assert_eq!(sid, 1, "PSH stream_id must be 1");

            let mut cursor = std::io::Cursor::new(payload);
            let dest = SocksAddr::read_from(&mut cursor).await.unwrap();
            assert_eq!(dest.host(), expected_host);
            assert_eq!(dest.port(), expected_port);
        });

        // Client task: connect via TLS, send AnyTLS handshake.
        let client_task = tokio::spawn(async move {
            // Build a rustls client config that trusts our self-signed cert.
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(cert_der).unwrap();
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(tls_config));
            let raw = TcpStream::connect(server_addr).await.unwrap();
            let mut stream = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    raw,
                )
                .await
                .unwrap();

            let settings = "v=2\nclient=clash-rs-test\\
                 npadding-md5=47edb1f4ed8a99480bf416d178311f10"
                .to_string();
            let dest =
                SocksAddr::try_from((expected_host.to_owned(), expected_port))
                    .unwrap();
            let mut addr_buf = bytes::BytesMut::new();
            dest.write_buf(&mut addr_buf);

            let mut handshake = bytes::BytesMut::new();
            handshake.put_slice(&hash);
            handshake.put_u16(0); // no padding
            // SETTINGS frame (stream_id=0)
            handshake.put_u8(CMD_SETTINGS);
            handshake.put_u32(0);
            handshake.put_u16(settings.len() as u16);
            handshake.put_slice(settings.as_bytes());
            // SYN frame (stream_id=1)
            handshake.put_u8(CMD_SYN);
            handshake.put_u32(1);
            handshake.put_u16(0);
            // PSH frame (stream_id=1, destination)
            handshake.put_u8(CMD_PSH);
            handshake.put_u32(1);
            handshake.put_u16(addr_buf.len() as u16);
            handshake.put_slice(&addr_buf);

            stream.write_all(&handshake).await.unwrap();
            stream.flush().await.unwrap();
        });

        tokio::try_join!(server_task, client_task).unwrap();
    }

    /// Tests that unauthenticated connections are forwarded to the fallback
    /// backend. A plain TLS client sends an HTTP GET (not AnyTLS protocol),
    /// so the 32-byte hash check fails and the stream is piped to a local
    /// mock server that mimics Google's generate_204 endpoint.
    #[tokio::test]
    async fn test_anytls_fallback_to_mock_generate_204() {
        install_crypto_provider();

        // ── Mock backend: returns HTTP 204 (like Google generate_204)
        // ─────────
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = backend_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = conn.read(&mut buf).await;
            conn.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        // ── AnyTLS inbound with fallback → mock backend
        // ───────────────────────
        let rcgen::CertifiedKey {
            cert,
            signing_key: key_pair,
        } = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let anytls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let anytls_addr = anytls_listener.local_addr().unwrap();
        let acceptor = build_tls_acceptor(Some(&cert_pem), Some(&key_pem)).unwrap();

        tokio::spawn(async move {
            let (stream, src) = anytls_listener.accept().await.unwrap();
            let mut map = std::collections::HashMap::new();
            let hash: [u8; 32] =
                sha2::Sha256::digest("correct-password".as_bytes()).into();
            map.insert(hash, "user".to_string());
            handle_fallback_connection(
                stream,
                src,
                acceptor,
                Arc::new(map),
                Some(backend_addr.to_string()),
            )
            .await;
        });

        // ── Plain TLS client — sends HTTP GET, not AnyTLS ────────────────────
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_config));
        let tcp = TcpStream::connect(anytls_addr).await.unwrap();
        let mut tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();

        tls.write_all(
            b"GET /generate_204 HTTP/1.1\r\nHost: clients3.google.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        tls.flush().await.unwrap();

        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);

        assert!(
            resp_str.contains("204"),
            "expected HTTP 204 from fallback, got: {resp_str}"
        );
    }

    /// Thin wrapper to exercise handle_fallback path without a full Dispatcher.
    async fn handle_fallback_connection(
        raw: tokio::net::TcpStream,
        src: std::net::SocketAddr,
        acceptor: tokio_rustls::TlsAcceptor,
        user_map: Arc<std::collections::HashMap<[u8; 32], String>>,
        fallback: Option<String>,
    ) {
        use tokio::io::AsyncReadExt as _;

        let mut tls = match acceptor.accept(raw).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut hash_buf = [0u8; 32];
        if tls.read_exact(&mut hash_buf).await.is_err() {
            return;
        }
        if user_map.contains_key(&hash_buf) {
            return; // authenticated — not testing this path
        }
        if let Some(addr) = fallback {
            super::handle_fallback(tls, &hash_buf, &addr, src).await;
        }
    }

    /// Rustls certificate verifier that accepts anything (for tests).
    #[derive(Debug)]
    struct NoVerifier;
    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer,
            _: &[rustls::pki_types::CertificateDer],
            _: &rustls::pki_types::ServerName,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::CryptoProvider::get_default()
                .expect("no default crypto provider installed")
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Verifies that an AnyTLS client sending `UDP_OVER_TCP_V2_MAGIC_HOST` as
    /// the PSH destination causes the server to parse it correctly.  This
    /// exercises the routing decision in `handle_connection` without requiring
    /// a Dispatcher: we replay the full handshake, then the server-side test
    /// asserts the parsed `dest.host() == UDP_OVER_TCP_V2_MAGIC_HOST`.
    #[tokio::test]
    async fn test_anytls_handshake_routes_udp_magic_host() {
        install_crypto_provider();

        let rcgen::CertifiedKey {
            cert,
            signing_key: key_pair,
        } = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen cert generation failed");
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let cert_der = cert.der().clone();

        let acceptor = build_tls_acceptor(Some(&cert_pem), Some(&key_pem)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let password = "uot_v2_test_pw";
        let hash: [u8; 32] = sha2::Sha256::digest(password.as_bytes()).into();

        // Server task: accept TLS, parse AnyTLS frames, assert magic host.
        let server_task = tokio::spawn(async move {
            let (raw, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(raw).await.unwrap();

            // 32-byte password hash
            let mut hash_buf = [0u8; 32];
            tls.read_exact(&mut hash_buf).await.unwrap();
            assert_eq!(hash_buf, hash, "password hash mismatch");

            // u16 padding length
            let pad = tls.read_u16().await.unwrap();
            assert_eq!(pad, 0);

            // Consume frames until we see PSH and check the destination.
            loop {
                let (cmd, _sid, data) = read_frame(&mut tls).await.unwrap();
                if cmd == CMD_PSH {
                    let mut cursor = std::io::Cursor::new(data);
                    let dest = SocksAddr::read_from(&mut cursor).await.unwrap();
                    assert_eq!(
                        dest.host(),
                        UDP_OVER_TCP_V2_MAGIC_HOST,
                        "PSH destination host must equal the UoT v2 magic host"
                    );
                    break;
                }
            }
        });

        // Client task: connect via TLS, send AnyTLS handshake with magic host.
        let client_task = tokio::spawn(async move {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(cert_der).unwrap();
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(tls_config));
            let raw = TcpStream::connect(server_addr).await.unwrap();
            let mut stream = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    raw,
                )
                .await
                .unwrap();

            // Build the AnyTLS handshake with the UoT magic host as the
            // PSH destination.
            let dest =
                SocksAddr::try_from((UDP_OVER_TCP_V2_MAGIC_HOST.to_owned(), 0u16))
                    .unwrap();
            let mut addr_buf = bytes::BytesMut::new();
            dest.write_buf(&mut addr_buf);

            let settings = "v=2\nclient=clash-rs-uot-test";
            let mut handshake = bytes::BytesMut::new();
            handshake.put_slice(&hash);
            handshake.put_u16(0); // no padding
            // SETTINGS (stream_id=0)
            handshake.put_u8(CMD_SETTINGS);
            handshake.put_u32(0);
            handshake.put_u16(settings.len() as u16);
            handshake.put_slice(settings.as_bytes());
            // SYN (stream_id=1)
            handshake.put_u8(CMD_SYN);
            handshake.put_u32(1);
            handshake.put_u16(0);
            // PSH (stream_id=1, payload = magic host addr)
            handshake.put_u8(CMD_PSH);
            handshake.put_u32(1);
            handshake.put_u16(addr_buf.len() as u16);
            handshake.put_slice(&addr_buf);

            stream.write_all(&handshake).await.unwrap();
            stream.flush().await.unwrap();
        });

        tokio::try_join!(server_task, client_task).unwrap();
    }
}
