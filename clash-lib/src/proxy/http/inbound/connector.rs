use crate::{
    Dispatcher,
    app::net::SocketMark,
    proxy::{AnyStream, ProxyError},
    session::{Network, Session, Type},
};
use futures::FutureExt;
use hyper::Uri;
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::duplex;

use super::proxy::maybe_socks_addr;

#[derive(Clone)]
pub struct Connector {
    src: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    fw_mark: Option<SocketMark>,
}

impl Connector {
    pub fn new(
        src: SocketAddr,
        dispatcher: Arc<Dispatcher>,
        fw_mark: Option<SocketMark>,
    ) -> Self {
        Self {
            src,
            dispatcher,
            fw_mark,
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for AnyStream {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl tower::Service<Uri> for Connector {
    type Error = ProxyError;
    type Future = Pin<
        Box<dyn Future<Output = Result<TokioIo<AnyStream>, Self::Error>> + Send>,
    >;
    type Response = TokioIo<AnyStream>;

    fn poll_ready(
        &mut self,
        #[allow(unused_variables)] cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, url: Uri) -> Self::Future {
        let src = self.src;
        let dispatcher = self.dispatcher.clone();

        let destination = maybe_socks_addr(&url);
        let fw_mark = self.fw_mark;
        async move {
            let (left, right) = duplex(1024 * 1024);

            let sess = Session {
                network: Network::Tcp,
                typ: Type::Http,
                source: src,
                destination: destination
                    .ok_or(ProxyError::InvalidUrl(url.to_string()))?,
                so_mark: fw_mark,
                ..Default::default()
            };

            tokio::spawn(async move {
                dispatcher.dispatch_stream(sess, Box::new(right)).await;
            });

            Ok(TokioIo::new(Box::new(left) as _))
        }
        .boxed()
    }
}
