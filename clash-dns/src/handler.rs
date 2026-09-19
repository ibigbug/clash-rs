use crate::{
    DNSListenAddr, DnsMessageExchanger,
    utils::{
        load_cert_chain, load_default_cert, load_default_key, load_priv_key,
        new_io_error,
    },
};
use async_trait::async_trait;
use hickory_proto::{
    op::{
        Header, HeaderCounts, Message, MessageType, Metadata, OpCode, ResponseCode,
    },
    rr::RecordType,
};
use hickory_server::{
    Server,
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use rustls::{server::AlwaysResolvesServerRawPublicKeys, sign::CertifiedKey};
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

struct CertificateKeyPair {
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl From<CertificateKeyPair> for Arc<dyn rustls::server::ResolvesServerCert> {
    fn from(pair: CertificateKeyPair) -> Self {
        Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
            CertifiedKey::new(
                pair.certs,
                rustls::crypto::CryptoProvider::get_default()
                    .expect("no default crypto provider installed")
                    .key_provider
                    .load_private_key(pair.key)
                    .expect("unsupported private key type"),
            ),
        )))
    }
}

struct DnsListener<H: RequestHandler> {
    server: Server<H>,
}

struct DnsHandler<X> {
    exchanger: X,
}

#[derive(Error, Debug)]
pub enum DNSError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("invalid OP code: {0}")]
    InvalidOpQuery(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
}

impl<X> DnsHandler<X>
where
    X: DnsMessageExchanger,
{
    async fn handle<H: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: H,
    ) -> Result<ResponseInfo, DNSError> {
        if request.metadata.op_code != OpCode::Query {
            return Err(DNSError::InvalidOpQuery(format!(
                "invalid OP code: {}",
                request.metadata.op_code
            )));
        }

        if request.metadata.message_type != MessageType::Query {
            return Err(DNSError::InvalidOpQuery(format!(
                "invalid message type: {}",
                request.metadata.message_type
            )));
        }

        let mut metadata = Metadata::response_from_request(&request.metadata);

        let query = request
            .queries
            .queries()
            .first()
            .ok_or(DNSError::QueryFailed("no query".to_string()))?;

        if query.query_type() == RecordType::AAAA && !self.exchanger.ipv6() {
            metadata.authoritative = true;

            let resp = MessageResponseBuilder::from_message_request(request)
                .build_no_records(metadata);
            return response_handle
                .send_response(resp)
                .await
                .map_err(|e| DNSError::QueryFailed(e.to_string()));
        }

        let mut m = Message::new(
            request.metadata.id,
            request.metadata.message_type,
            request.metadata.op_code,
        );
        m.metadata.recursion_desired = request.metadata.recursion_desired;
        m.metadata.checking_disabled = request.metadata.checking_disabled;
        m.add_query(query.original().clone());
        m.add_additionals(request.additionals.iter().cloned());
        m.add_authorities(request.authorities.iter().cloned());
        if let Some(edns) = &request.edns {
            m.set_edns(edns.clone());
        }

        match self.exchanger.exchange(&m).await {
            Ok(m) => {
                metadata.recursion_available = m.metadata.recursion_available;
                metadata.response_code = m.metadata.response_code;
                metadata.authoritative = m.metadata.authoritative;
                metadata.truncation = m.metadata.truncation;
                metadata.authentic_data = m.metadata.authentic_data;
                metadata.checking_disabled = m.metadata.checking_disabled;

                let resp_edns = if request.edns.is_some() {
                    m.edns.clone()
                } else {
                    None
                };

                let rv = MessageResponseBuilder::new(
                    &request.queries,
                    resp_edns.as_ref(),
                )
                .build(
                    metadata,
                    m.answers.iter(),
                    m.authorities.iter(),
                    std::iter::empty(),
                    m.additionals.iter(),
                );

                debug!(
                    "answering dns query {} with answer {:?}",
                    query.name(),
                    &m.answers,
                );

                Ok(response_handle
                    .send_response(rv)
                    .await
                    .map_err(|e| DNSError::QueryFailed(e.to_string()))?)
            }
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(DNSError::QueryFailed(e.to_string()))
            }
        }
    }
}

#[async_trait]
impl<X> RequestHandler for DnsHandler<X>
where
    X: DnsMessageExchanger + Unpin + Send + Sync + 'static,
{
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        debug!(
            "got dns request [{}][{:?}][{:?}] from {}",
            request.protocol(),
            request.queries.queries().first().map(|x| x.query_type()),
            request.queries.queries().first().map(|x| x.name()),
            request.src()
        );

        self.handle(request, response_handle)
            .await
            .unwrap_or_else(|e| {
                debug!("dns request error: {}", e);
                let mut metadata =
                    Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::ServFail;
                Header {
                    metadata,
                    counts: HeaderCounts::default(),
                }
                .into()
            })
    }
}

static DEFAULT_DNS_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn get_dns_listener<X>(
    listen: DNSListenAddr,
    exchanger: X,
    cwd: &std::path::Path,
) -> Option<futures::future::BoxFuture<'static, Result<(), DNSError>>>
where
    X: DnsMessageExchanger + Sync + Send + Unpin + 'static,
{
    let handler = DnsHandler { exchanger };
    let mut s = Server::new(handler);

    let mut has_server = false;

    if let Some(addr) = listen.udp {
        has_server = UdpSocket::bind(addr)
            .await
            .map(|x| {
                info!("UDP dns server listening on: {}", addr);
                s.register_socket(x);
            })
            .inspect_err(|x| {
                error!("failed to listen UDP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(addr) = listen.tcp {
        has_server |= TcpListener::bind(addr)
            .await
            .map(|x| {
                info!("TCP dns server listening on: {}", addr);
                s.register_listener(x, DEFAULT_DNS_SERVER_TIMEOUT, 4096);
            })
            .inspect_err(|x| {
                error!("failed to listen TCP DNS server on {}: {}", addr, x);
            })
            .is_ok();
    }
    if let Some(c) = listen.doh {
        has_server |= TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoH: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_https_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                    c.hostname,
                    "/dns-query".to_string(),
                )?;
                info!("DoH server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoH server on {}: {}", c.addr, x);
            })
            .is_ok();
    }
    if let Some(c) = listen.dot {
        has_server |= TcpListener::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoT: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_tls_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                )?;
                info!("DoT dns server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoT DNS server on {}: {}", c.addr, x);
            })
            .is_ok();
    }

    if let Some(c) = listen.doh3 {
        has_server |= UdpSocket::bind(c.addr)
            .await
            .and_then(|x| {
                if let (Some(k), Some(c)) = (&c.ca_key, &c.ca_cert) {
                    debug!(
                        "using custom key and cert for DoH3: {:?}/{:?}",
                        cwd.join(k),
                        cwd.join(c)
                    );
                }

                let server_key = c
                    .ca_key
                    .map(|x| load_priv_key(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_key());
                let server_cert = c
                    .ca_cert
                    .map(|x| load_cert_chain(&cwd.join(x)))
                    .transpose()?
                    .unwrap_or(load_default_cert());
                s.register_h3_listener(
                    x,
                    DEFAULT_DNS_SERVER_TIMEOUT,
                    CertificateKeyPair {
                        certs: server_cert,
                        key: server_key,
                    }
                    .into(),
                    c.hostname,
                )?;
                info!("DoT3 dns server listening on: {}", c.addr);
                Ok(())
            })
            .inspect_err(|x| {
                error!("failed to listen DoH3 DNS server on {}: {}", c.addr, x);
            })
            .is_ok();
    }

    if !has_server {
        return None;
    }

    let mut l = DnsListener { server: s };

    Some(Box::pin(async move {
        info!("starting DNS server");
        l.server.block_until_done().await.map_err(|x| {
            warn!("dns server error: {}", x);
            DNSError::Io(new_io_error(format!("dns server error: {x}")))
        })
    }))
}

#[cfg(test)]
mod tests {
    use crate::{
        DNSListenAddr, DoH3Config, DoHConfig, DoTConfig, MockDnsMessageExchanger,
        tests::setup_default_crypto_provider,
        tls::{self, global_root_store},
    };
    use futures::FutureExt;
    use hickory_net::{
        client::{Client, ClientHandle},
        h2::HttpsClientStream,
        h3::H3ClientStream,
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        tls::tls_client_connect,
        udp::UdpClientStream,
    };
    use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
    use rustls::{ClientConfig, pki_types::ServerName};
    use std::{sync::Arc, time::Duration};
    use tokio::{
        net::{TcpListener, UdpSocket},
        task::JoinHandle,
    };

    async fn send_query(
        client: &mut Client<TokioRuntimeProvider>,
    ) -> anyhow::Result<()> {
        let name = Name::from_ascii("www.example.com.").unwrap();

        let mut retries = 3;
        let response = loop {
            match client
                .query(name.clone(), DNSClass::IN, RecordType::A)
                .await
            {
                Ok(v) => {
                    break v;
                }
                Err(e) => {
                    retries -= 1;
                    if retries == 0 {
                        anyhow::bail!(e)
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };

        let answers = &response.answers;

        if let RData::A(ip) = &answers[0].data {
            assert_eq!(ip.0, std::net::Ipv4Addr::new(93, 184, 215, 14))
        } else {
            unreachable!("unexpected result")
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_dns_server() -> anyhow::Result<()> {
        setup_default_crypto_provider();
        env_logger::init();

        let mut mock_exchanger = MockDnsMessageExchanger::new();
        mock_exchanger.expect_ipv6().returning(|| false);
        mock_exchanger.expect_exchange().returning(|_| {
            async {
                let mut m = hickory_proto::op::Message::response(
                    0,
                    hickory_proto::op::OpCode::Query,
                );
                m.add_answer(hickory_proto::rr::Record::from_rdata(
                    "www.example.com".parse().unwrap(),
                    60,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        std::net::Ipv4Addr::new(93, 184, 215, 14),
                    )),
                ));
                Ok(m)
            }
            .boxed()
        });

        // Bind to port 0 to get OS-assigned available ports
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_addr = udp_sock.local_addr()?;
        drop(udp_sock);

        let tcp_sock = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_sock.local_addr()?;
        drop(tcp_sock);

        let dot_sock = TcpListener::bind("127.0.0.1:0").await?;
        let dot_addr = dot_sock.local_addr()?;
        drop(dot_sock);

        let doh_sock = TcpListener::bind("127.0.0.1:0").await?;
        let doh_addr = doh_sock.local_addr()?;
        drop(doh_sock);

        let doh3_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let doh3_addr = doh3_sock.local_addr()?;
        drop(doh3_sock);

        eprintln!(
            "Test using ports - UDP:{}, TCP:{}, DoT:{}, DoH:{}, DoH3:{}",
            udp_addr.port(),
            tcp_addr.port(),
            dot_addr.port(),
            doh_addr.port(),
            doh3_addr.port()
        );

        let cfg = DNSListenAddr {
            udp: Some(udp_addr),
            tcp: Some(tcp_addr),
            dot: Some(DoTConfig {
                addr: dot_addr,
                ca_key: None,
                ca_cert: None,
            }),
            doh: Some(DoHConfig {
                addr: doh_addr,
                hostname: Some("dns.example.com".to_string()),
                ca_key: None,
                ca_cert: None,
            }),
            doh3: Some(DoH3Config {
                addr: doh3_addr,
                hostname: Some("dns.example.com".to_string()),
                ca_key: None,
                ca_cert: None,
            }),
        };

        let listener =
            super::get_dns_listener(cfg, mock_exchanger, std::path::Path::new("."))
                .await;

        assert!(listener.is_some());
        let _handle: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            listener.unwrap().await?;
            Ok(())
        });

        // Wait for servers to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        let stream =
            UdpClientStream::builder(udp_addr, TokioRuntimeProvider::new()).build();

        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);

        send_query(&mut client).await?;

        let (stream_future, sender) =
            TcpClientStream::new(tcp_addr, None, None, TokioRuntimeProvider::new());
        let stream = stream_future.await?;
        let (mut client, bg) = Client::<TokioRuntimeProvider>::new(stream, sender);
        tokio::spawn(bg);

        send_query(&mut client).await?;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store().clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["dot".into()];
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let server_name = ServerName::try_from("dns.example.com").unwrap();
        let (stream_future, sender) = tls_client_connect(
            dot_addr,
            server_name,
            Arc::new(tls_config),
            TokioRuntimeProvider::new(),
        );

        let stream = stream_future.await.inspect_err(|e| {
            panic!("Failed to connect to DoT server: {}", e);
        })?;
        let (mut client, bg) = Client::<TokioRuntimeProvider>::with_timeout(
            stream,
            sender,
            Duration::from_secs(5),
        );
        tokio::spawn(bg);

        send_query(&mut client).await?;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store().clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h2".into()];

        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream = HttpsClientStream::builder(
            Arc::new(tls_config),
            TokioRuntimeProvider::new(),
        )
        .build(doh_addr, "dns.example.com".into(), "/dns-query".into())
        .await?;

        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);

        send_query(&mut client).await?;

        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(global_root_store().clone())
            .with_no_client_auth();
        tls_config.alpn_protocols = vec!["h3".into()];

        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(tls::DummyTlsVerifier::new()));

        let stream = H3ClientStream::builder()
            .crypto_config(tls_config)
            .build(doh3_addr, "dns.example.com".into(), "/dns-query".into())
            .await?;

        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);

        send_query(&mut client).await?;
        Ok(())
    }
}
