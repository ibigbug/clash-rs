use crate::app::net::SocketMark;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use futures::{TryFutureExt, future::BoxFuture};

use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Method, Request, Response, Uri, body::Incoming, server::conn::http1};

use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use tracing::{instrument, warn};

use crate::{
    app::dispatcher::Dispatcher,
    common::{auth::ThreadSafeAuthenticator, errors::map_io_error},
    proxy::{AnyStream, ProxyError},
    session::{Network, Session, SocksAddr, Type},
};

use super::{auth::authenticate_req, connector::Connector};

pub fn maybe_socks_addr(r: &Uri) -> Option<SocksAddr> {
    let port = r.port_u16().unwrap_or(
        match r.scheme().map(|s| s.as_str()).unwrap_or("http") {
            "http" => 80 as _,
            "https" => 443 as _,
            _ => return None,
        },
    );

    r.host().map(|x| {
        if let Ok(ip) = x.parse::<IpAddr>() {
            SocksAddr::Ip((ip, port).into())
        } else {
            SocksAddr::Domain(x.to_string(), port)
        }
    })
}

async fn proxy(
    req: Request<hyper::body::Incoming>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<SocketMark>,
) -> Result<Response<BoxBody<Bytes, std::io::Error>>, ProxyError> {
    if authenticator.enabled()
        && let Some(res) = authenticate_req(&req, authenticator)
    {
        return Ok(res);
    }

    let client = Client::builder(TokioExecutor::new())
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build(Connector::new(src, dispatcher.clone(), fw_mark));

    // TODO: handle other upgrades: https://github.com/hyperium/hyper/blob/master/examples/upgrades.rs
    if req.method() == Method::CONNECT {
        match maybe_socks_addr(req.uri()) {
            Some(addr) => {
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            let sess = Session {
                                network: Network::Tcp,
                                typ: Type::HttpConnect,
                                source: src,
                                destination: addr,
                                so_mark: fw_mark,

                                ..Default::default()
                            };

                            dispatcher
                                .dispatch_stream(
                                    sess,
                                    Box::new(TokioIo::new(upgraded)),
                                )
                                .await
                        }
                        Err(e) => warn!("HTTP handshake failure, {}", e),
                    }
                });

                Ok(Response::new(Empty::new().map_err(map_io_error).boxed()))
            }
            _ => Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(
                    Full::new(format!("invalid request uri: {}", req.uri()).into())
                        .map_err(map_io_error)
                        .boxed(),
                )
                .unwrap()),
        }
    } else {
        match client
            .request(req)
            .map_err(|x| ProxyError::General(x.to_string()))
            .await
        {
            Ok(res) => Ok(res.map(|b| b.map_err(map_io_error).boxed())),
            Err(e) => {
                warn!("http proxy error: {}", e);
                Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_GATEWAY)
                    .body(Empty::new().map_err(map_io_error).boxed())
                    .unwrap())
            }
        }
    }
}

struct ProxyService {
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<SocketMark>,
}

impl hyper::service::Service<Request<hyper::body::Incoming>> for ProxyService {
    type Error = ProxyError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = Response<BoxBody<Bytes, std::io::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        Box::pin(proxy(
            req,
            self.src,
            self.dispatcher.clone(),
            self.authenticator.clone(),
            self.fw_mark,
        ))
    }
}

#[instrument(skip(stream, dispatcher, authenticator))]
pub async fn handle(
    stream: TokioIo<AnyStream>,
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    authenticator: ThreadSafeAuthenticator,
    fw_mark: Option<SocketMark>,
) {
    let result = http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            stream,
            ProxyService {
                src,
                dispatcher,
                authenticator,
                fw_mark,
            },
        )
        .with_upgrades()
        .await;

    if let Err(http_err) = result {
        warn!("Error while serving HTTP connection: {}", http_err);
    }
}
