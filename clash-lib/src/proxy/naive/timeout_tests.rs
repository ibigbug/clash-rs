use super::*;
use crate::{
    app::dns::SystemResolver, config::internal::proxy::OutboundNaive,
    session::SocksAddr,
};
use anyhow::{Context, Result, ensure};
use futures::{SinkExt, StreamExt};
use std::{future::poll_fn, time::Instant};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};

#[test]
#[cfg_attr(
    not(all(feature = "naive-static", not(feature = "naive-dynamic"))),
    ignore = "set CLASH_NAIVE_CRONET_LIB to an absolute path for dynamic builds"
)]
fn naive_request_timeout_cancels_pending_dial() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?
        .block_on(async {
            check_timeout(false).await?;
            check_timeout(true).await
        })
}

#[path = "../../../tests/common/cronet.rs"]
mod cronet;

async fn fixture() -> Result<(TcpListener, tokio_rustls::TlsAcceptor, Handler)> {
    fixture_for("127.0.0.1").await
}

async fn fixture_for(
    server: &str,
) -> Result<(TcpListener, tokio_rustls::TlsAcceptor, Handler)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![server.to_owned()])?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(1);
    let cert = params.self_signed(&key)?;
    crate::setup_default_crypto_provider();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
    tls.alpn_protocols.push(b"h2".to_vec());
    let cronet_lib = cronet::library_path()?;
    let config: OutboundNaive = serde_json::from_value(serde_json::json!({
        "name":"timeout-test", "server":server, "port":port,
        "username":"fixture", "password":"fixture", "ca-cert":cert.pem(),
        "request-timeout":1000, "udp":true,
        "cronet-lib-path":cronet_lib
    }))?;
    Ok((listener, Arc::new(tls).into(), Handler::try_from(config)?))
}

async fn check_timeout(udp: bool) -> Result<()> {
    let (listener, tls, handler) = fixture().await?;
    let (started, received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let tls = tls.accept(socket).await?;
        let mut connection = h2::server::handshake(tls).await?;
        let (request, mut response) =
            connection.accept().await.context("missing CONNECT")??;
        ensure!(request.method() == "CONNECT", "expected CONNECT");
        let _ = started.send(());
        // Withhold response headers and drive the connection until the client
        // cancels.
        tokio::select! {
            reset = poll_fn(|cx| response.poll_reset(cx)) => {
                ensure!(reset? == h2::Reason::CANCEL, "unexpected HTTP/2 reset");
            }
            _ = connection.accept() => anyhow::bail!("connection ended or another stream arrived before the reset"),
        }
        anyhow::Ok(Instant::now())
    });
    let session = Session {
        destination: SocksAddr::Ip("127.0.0.1:80".parse()?),
        ..Default::default()
    };
    let resolver: ThreadSafeDNSResolver = Arc::new(SystemResolver::new(false)?);
    handler.outbound(&session, &resolver).await?;
    let start = Instant::now();
    let dial = async {
        if udp {
            let mut datagram = handler.connect_datagram(&session, resolver).await?;
            datagram.send(Default::default()).await?;
            // Keep the association alive until the handshake timeout closes it.
            ensure!(
                timeout(Duration::from_secs(3), datagram.next())
                    .await?
                    .is_none()
            );
        } else {
            let dial = handler.connect_stream(&session, resolver).await;
            ensure!(
                dial.err().context("dial unexpectedly succeeded")?.kind()
                    == io::ErrorKind::TimedOut
            );
        }
        anyhow::Ok(())
    };
    let (dial, started) =
        tokio::join!(dial, timeout(Duration::from_secs(3), received));
    dial?;
    started.context("server did not receive CONNECT")??;
    let timed_out = Instant::now();
    eprintln!("request-timeout returned after {:?}", timed_out - start);
    // Keep the engine and peer alive: only this request should be canceled.
    let worker = tokio::task::spawn_blocking(Instant::now);
    let (worker, reset) = tokio::join!(
        timeout(Duration::from_secs(2), worker),
        timeout(Duration::from_secs(2), server),
    );
    let available =
        worker.context("blocking worker still occupied after request-timeout")??;
    let reset = reset
        .context("no native reset after request-timeout")?
        .context("HTTP/2 server task failed")??;
    eprintln!(
        "after request-timeout: blocking worker available in {:?}, peer observed \
         CANCEL in {:?}",
        available.saturating_duration_since(timed_out),
        reset.saturating_duration_since(timed_out)
    );
    Ok(())
}

#[tokio::test]
#[cfg_attr(
    not(all(feature = "naive-static", not(feature = "naive-dynamic"))),
    ignore = "set CLASH_NAIVE_CRONET_LIB to an absolute path for dynamic builds"
)]
async fn established_udp_survives_request_timeout() -> Result<()> {
    let (listener, tls, handler) = fixture().await?;
    let mut datagram = handler
        .connect_datagram(&Session::default(), Arc::new(SystemResolver::new(false)?))
        .await?;
    datagram.send(Default::default()).await?;
    timeout(Duration::from_secs(5), async {
        let (socket, _) = listener.accept().await?;
        let mut connection = h2::server::handshake(tls.accept(socket).await?).await?;
        let (request, mut response) = connection.accept().await.context("missing UDP CONNECT")??;
        let mut body = request.into_body();
        let mut stream = response.send_response(http::Response::new(()), false)?;
        let exchange = async {
            body.data().await.context("missing UoT request")??;
            tokio::time::sleep(handler.opts.request_timeout).await;
            // Naive padding header, then a UoT IPv4 packet from 127.0.0.1:53.
            let reply = bytes::Bytes::from_static(&[0, 10, 0, 0, 127, 0, 0, 1, 0, 53, 0, 1, 42]);
            stream.send_data(reply, false)?;
            let packet = datagram.next().await.context("established UDP association closed")?;
            ensure!(packet.data == [42] && packet.src_addr == SocksAddr::Ip("127.0.0.1:53".parse()?));
            anyhow::Ok(())
        };
        tokio::select! {
            _ = connection.accept() => anyhow::bail!("UDP CONNECT connection ended early"),
            result = exchange => result,
        }
    }).await?
}

#[tokio::test]
#[cfg_attr(
    not(all(feature = "naive-static", not(feature = "naive-dynamic"))),
    ignore = "set CLASH_NAIVE_CRONET_LIB to an absolute path for dynamic builds"
)]
async fn failed_dials_refresh_the_proxy_address_for_new_connections() -> Result<()> {
    use crate::app::dns::MockClashResolver;
    for udp in [false, true] {
        let (listener, tls, handler) = fixture_for("proxy.test").await?;
        let mut mock = MockClashResolver::new();
        let mut answers = ["127.0.0.2", "127.0.0.2", "127.0.0.1"].into_iter();
        mock.expect_resolve_all().times(3).returning(move |_, _| {
            Ok(vec![
                answers.next().context("unexpected DNS lookup")?.parse()?,
            ])
        });
        mock.expect_is_fake_ip().returning(|_| false);
        let resolver: ThreadSafeDNSResolver = Arc::new(mock);
        let session = Session {
            destination: SocksAddr::Ip("127.0.0.1:80".parse()?),
            ..Default::default()
        };
        let old = handler.outbound(&session, &resolver).await?;
        for _ in 0..2 {
            ensure!(Arc::ptr_eq(
                &old,
                &handler.outbound(&session, &resolver).await?
            ));
            if udp {
                let mut association =
                    handler.connect_datagram(&session, resolver.clone()).await?;
                association.send(Default::default()).await?;
                ensure!(
                    timeout(Duration::from_secs(5), association.next())
                        .await?
                        .is_none()
                );
            } else {
                ensure!(
                    handler
                        .connect_stream(&session, resolver.clone())
                        .await
                        .is_err()
                );
            }
        }

        let peer = async {
            let (socket, _) = listener.accept().await?;
            let mut h2 = h2::server::handshake(tls.accept(socket).await?).await?;
            let (_request, mut response) =
                h2.accept().await.context("missing CONNECT")??;
            let _stream = response.send_response(http::Response::new(()), false)?;
            let _ = h2.accept().await;
            anyhow::Ok(())
        };
        let dial = async {
            let stream = handler.connect_stream(&session, resolver.clone()).await?;
            let new = handler.outbound(&session, &resolver).await?;
            ensure!(!Arc::ptr_eq(&old, &new));
            // A later failure from the old generation cannot invalidate the new
            // one.
            old.dial_failed();
            ensure!(Arc::ptr_eq(
                &new,
                &handler.outbound(&session, &resolver).await?
            ));
            drop(stream);
            anyhow::Ok(())
        };
        tokio::select! {
            res = peer => { res?; anyhow::bail!("peer closed before the new tunnel was ready"); },
            res = dial => res?,
        }
    }
    Ok(())
}
