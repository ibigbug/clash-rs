mod datagram;
mod stream;

use std::{collections::HashMap, io, sync::Arc, time::Duration};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use wind_core::{
    FlowContext, hooks::Protocol, rule::NetworkType, types::TargetAddr,
};
use wind_naive::{NaiveOutbound, NaiveOutboundOpts};

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    session::{Session, SocksAddr},
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};

pub struct HandlerOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub udp: bool,
    pub request_timeout: Duration,
    pub wind: NaiveOutboundOpts,
}

pub struct Handler {
    opts: HandlerOptions,
    outbound: OnceCell<Arc<NaiveOutbound>>,
    cancel: CancellationToken,
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            outbound: OnceCell::new(),
            cancel: CancellationToken::new(),
        }
    }

    async fn outbound(&self, sess: &Session) -> io::Result<Arc<NaiveOutbound>> {
        // Cronet owns its sockets. Refuse explicit policy instead of silently
        // bypassing a rule-selected interface or routing mark.
        if sess.iface.is_some() || sess.so_mark.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Naive does not support interface binding or routing marks",
            ));
        }
        self.outbound
            .get_or_try_init(|| async {
                NaiveOutbound::new(self.opts.wind.clone())
                    .await
                    .map(Arc::new)
                    .map_err(|error| {
                        io::Error::other(format!("Naive engine: {error}"))
                    })
            })
            .await
            .cloned()
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Naive")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Naive
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedStream> {
        let io = tokio::time::timeout(self.opts.request_timeout, async {
            let outbound = self.outbound(sess).await?;
            stream::connect(
                outbound,
                flow(sess, NetworkType::Tcp),
                self.cancel.child_token(),
            )
            .await
        })
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "Naive CONNECT timed out")
        })??;
        let stream = InstrumentedStreamWrapper::new(io);
        stream.append_to_chain(self.name()).await;
        Ok(Box::new(stream))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedInstrumentedDatagram> {
        if !self.opts.udp {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Naive UDP-over-TCP is disabled",
            ));
        }
        let outbound =
            tokio::time::timeout(self.opts.request_timeout, self.outbound(sess))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Naive engine initialization timed out",
                    )
                })??;
        let datagram = InstrumentedDatagramWrapper::new(datagram::Datagram::new(
            outbound,
            sess,
            self.cancel.child_token(),
        ));
        datagram.append_to_chain(self.name()).await;
        Ok(Box::new(datagram))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        // Do not expose authentication material or native library paths.
        let mut map: HashMap<String, Box<dyn ErasedSerialize + Send>> =
            HashMap::new();
        map.insert("server".into(), Box::new(self.opts.server.clone()));
        map.insert("port".into(), Box::new(self.opts.port));
        map.insert("quic".into(), Box::new(self.opts.wind.quic_enabled));
        map.insert("udp".into(), Box::new(self.opts.udp));
        map
    }
}

fn target(addr: &SocksAddr) -> TargetAddr {
    match addr {
        SocksAddr::Ip(std::net::SocketAddr::V4(addr)) => {
            TargetAddr::IPv4(*addr.ip(), addr.port())
        }
        SocksAddr::Ip(std::net::SocketAddr::V6(addr)) => {
            TargetAddr::IPv6(*addr.ip(), addr.port())
        }
        SocksAddr::Domain(host, port) => TargetAddr::Domain(host.clone(), *port),
    }
}

fn flow(sess: &Session, network: NetworkType) -> FlowContext {
    FlowContext {
        target: target(&sess.destination),
        network,
        source: Some(sess.source),
        inbound_tag: "naive".into(),
        protocol: Protocol::Naive,
        user: None,
        inbound_port: None,
        inbound_type: None,
    }
}
