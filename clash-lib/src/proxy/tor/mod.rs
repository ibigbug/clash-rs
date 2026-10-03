mod stream;

use arti_client::{StreamPrefs, TorClientConfig};
use async_trait::async_trait;

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    session::Session,
};

use self::stream::StreamWrapper;

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};
use erased_serde::Serialize as ErasedSerialize;
use std::collections::HashMap;

use tor_rtcompat::RuntimeSubstExt as _;

#[derive(Clone)]
struct CustomTcpProvider<T> {
    inner: T,
    iface: Option<crate::app::net::OutboundInterface>,
    #[allow(dead_code)]
    so_mark: Option<u32>,
}

#[async_trait]
impl<T> tor_rtcompat::NetStreamProvider for CustomTcpProvider<T>
where
    T: tor_rtcompat::NetStreamProvider,
    T::Stream: From<tokio::net::TcpStream>,
{
    type ConnectOptions = T::ConnectOptions;
    type ListenOptions = T::ListenOptions;
    type Listener = T::Listener;
    type Stream = T::Stream;

    async fn connect(
        &self,
        addr: &std::net::SocketAddr,
        _options: &Self::ConnectOptions,
    ) -> std::io::Result<Self::Stream> {
        let stream = crate::proxy::utils::new_tcp_stream(
            *addr,
            self.iface.as_ref(),
            #[cfg(target_os = "linux")]
            self.so_mark,
        )
        .await?;
        Ok(stream.into())
    }

    async fn listen(
        &self,
        addr: &std::net::SocketAddr,
        options: &Self::ListenOptions,
    ) -> std::io::Result<Self::Listener> {
        self.inner.listen(addr, options).await
    }
}

type TorRuntime = tor_rtcompat::CompoundRuntime<
    tor_rtcompat::PreferredRuntime,
    tor_rtcompat::PreferredRuntime,
    tor_rtcompat::PreferredRuntime,
    CustomTcpProvider<tor_rtcompat::PreferredRuntime>,
    tor_rtcompat::PreferredRuntime,
    tor_rtcompat::PreferredRuntime,
    tor_rtcompat::PreferredRuntime,
>;

pub struct HandlerOptions {
    pub name: String,
    pub interface: Option<String>,
    pub routing_mark: Option<u32>,
}

pub struct Handler {
    opts: HandlerOptions,

    client: std::sync::Arc<arti_client::TorClient<TorRuntime>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tor").finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Result<Self, crate::Error> {
        let rt =
            tor_rtcompat::PreferredRuntime::current().map_err(crate::Error::Io)?;
        let iface = match opts.interface.as_deref() {
            Some(name) => match crate::app::net::get_interface_by_name(name) {
                Some(iface) => Some(iface),
                None if cfg!(target_os = "android") => None,
                None => {
                    return Err(crate::Error::Operation(format!(
                        "tor: could not resolve interface `{name}`"
                    )));
                }
            },
            None => None,
        };
        let so_mark = opts.routing_mark;
        let tcp_rt = CustomTcpProvider {
            inner: rt.clone(),
            iface,
            so_mark,
        };
        let custom_rt = rt.with_tcp_provider(tcp_rt);

        let client = arti_client::TorClient::with_runtime(custom_rt)
            .config(TorClientConfig::default())
            .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand)
            .create_unbootstrapped()
            .map_err(|e| crate::Error::Operation(e.to_string()))?;

        Ok(Self { opts, client })
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tor
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedStream> {
        let s = self
            .client
            .connect_with_prefs(
                (sess.destination.host(), sess.destination.port()),
                #[cfg(feature = "onion")]
                StreamPrefs::new()
                    .any_exit_country()
                    .connect_to_onion_services(
                        arti_client::config::BoolOrAuto::Explicit(true),
                    ),
                #[cfg(not(feature = "onion"))]
                StreamPrefs::new().any_exit_country(),
            )
            .await
            .map_err(|x| new_io_error(x.to_string()))?;
        let s = InstrumentedStreamWrapper::new(StreamWrapper::new(s));
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        Err(new_io_error("Tor outbound handler does not support UDP"))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::None
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        HashMap::new()
    }
}
