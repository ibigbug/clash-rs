use crate::app::net::SocketMark;
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};

use crate::{
    app::{
        dispatcher::{BoxedInstrumentedDatagram, BoxedInstrumentedStream},
        dns::{RuleDispatch, ThreadSafeDNSResolver},
        net::{OutboundInterface, get_interface_by_name},
    },
    common::errors::new_io_error,
    proxy::{AnyOutboundHandler, datagram::UdpPacket},
    session::{Network, Session, Type},
};
use futures::{SinkExt, StreamExt};

use hickory_net::runtime::{
    DnsUdpSocket, RuntimeProvider, TokioHandle, TokioTime,
    iocompat::AsyncIoTokioAsStd,
};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct DnsRuntimeProvider {
    handle: TokioHandle,
    outbound: AnyOutboundHandler,
    dns_resolver: ThreadSafeDNSResolver,
    iface: Option<OutboundInterface>,
    so_mark: Option<SocketMark>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
}

impl DnsRuntimeProvider {
    pub fn new(
        outbound: AnyOutboundHandler,
        dns_resolver: ThreadSafeDNSResolver,
        iface: Option<OutboundInterface>,
        so_mark: Option<SocketMark>,
        rule_dispatch: Option<Arc<RuleDispatch>>,
    ) -> Self {
        Self {
            handle: TokioHandle::default(),
            outbound,
            dns_resolver,
            iface,
            so_mark,
            rule_dispatch,
        }
    }

    #[cfg(test)]
    pub fn new_direct(
        iface: Option<OutboundInterface>,
        so_mark: Option<SocketMark>,
    ) -> Self {
        use crate::{app::dns, config::proxy::PROXY_DIRECT, proxy::direct};
        use std::sync::Arc;

        let proxy = Arc::new(direct::Handler::new(PROXY_DIRECT));
        // SystemResolver::new us trivial,it always return Ok
        let dns_resolver = Arc::new(dns::SystemResolver::new(false).unwrap());
        Self::new(proxy, dns_resolver, iface, so_mark, None)
    }

    /// Pick the outbound handler for an upstream DNS dial. When
    /// `rule_dispatch` is set and both of its `OnceLock`s are populated, this
    /// asks the rule engine which outbound to use for `sess` (whose
    /// destination is always an IP — see `connect_tcp` / `bind_udp` — so
    /// `Router::match_route` never re-enters DNS). Otherwise, falls back to
    /// the static `outbound` (DIRECT or `#proxy=...`).
    async fn pick_outbound(&self, sess: &mut Session) -> AnyOutboundHandler {
        let Some(rd) = &self.rule_dispatch else {
            return self.outbound.clone();
        };
        let (Some(router), Some(mgr)) = (rd.router.get(), rd.outbound_manager.get())
        else {
            return self.outbound.clone();
        };
        let (name, rule) = router.match_route(sess).await;
        if let Some(interface) = rule.and_then(|rule| rule.interface())
            && let Some(iface) = get_interface_by_name(interface)
        {
            sess.iface = Some(iface);
        }
        mgr.get_outbound(name)
            .await
            .unwrap_or_else(|| self.outbound.clone())
    }
}

impl RuntimeProvider for DnsRuntimeProvider {
    type Handle = TokioHandle;
    type Tcp = AsyncIoTokioAsStd<BoxedInstrumentedStream>;
    type Timer = TokioTime;
    type Udp = DnsProxyUdpSocket;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        // ignored: self.iface is used
        _bind_addr: Option<SocketAddr>,
        _timeout: Option<Duration>,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>>
    {
        let src: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let provider = self.clone();
        let dns = self.dns_resolver.clone();
        let mut sess = Session {
            source: src,
            network: Network::Tcp,
            typ: Type::Ignore,
            destination: server_addr.into(),
            so_mark: self.so_mark,
            iface: self.iface.clone(),
            ..Default::default()
        };
        Box::pin(async move {
            let outbound = provider.pick_outbound(&mut sess).await;
            let stream = outbound.connect_stream(&sess, dns);
            stream.await.map(AsyncIoTokioAsStd)
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> std::pin::Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>>
    {
        let src: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let provider = self.clone();
        let dns = self.dns_resolver.clone();
        let mut sess = Session {
            source: src,
            network: Network::Udp,
            typ: Type::Ignore,
            destination: server_addr.into(),
            so_mark: self.so_mark,
            iface: self.iface.clone(),
            ..Default::default()
        };

        Box::pin(async move {
            let outbound = provider.pick_outbound(&mut sess).await;
            outbound
                .connect_datagram(&sess, dns)
                .await
                .map(|x| DnsProxyUdpSocket(Mutex::new(x)))
        })
    }
}

// Mutex could be inefficient
// But this is for DNS, it doesn't require high perf
// SocketAddr indicates the source address of the UDP socket
pub struct DnsProxyUdpSocket(Mutex<BoxedInstrumentedDatagram>);

impl DnsUdpSocket for DnsProxyUdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let inner = Box::pin(self.0.lock()).as_mut().poll(cx);
        let mut inner = ready!(inner);
        let out = ready!(inner.poll_next_unpin(cx))
            .ok_or(new_io_error("dns proxy outbound is closed"));

        let ret = out.map(|x: crate::proxy::datagram::UdpPacket| {
            let len = x.data.len().min(buf.len());
            buf[..len].copy_from_slice(&x.data[0..len]);
            (
                len,
                x.src_addr
                    .try_into_socket_addr()
                    .expect("packet source addr can't be a domain for dns proxy"),
            )
        });
        Poll::Ready(ret)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let inner = Box::pin(self.0.lock()).as_mut().poll(cx);
        let mut inner = ready!(inner);
        match inner.poll_ready_unpin(cx) {
            Poll::Ready(Ok(_)) => (),
            Poll::Pending => match ready!(inner.poll_flush_unpin(cx)) {
                Ok(_) => (),
                Err(e) => return Poll::Ready(Err(e)),
            },
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };
        let src = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let packet = UdpPacket {
            data: buf.to_vec(),
            src_addr: src,
            dst_addr: target.into(),
            inbound_user: None,
        };
        match inner.start_send_unpin(packet) {
            Ok(_) => (),
            Err(e) => return Poll::Ready(Err(e)),
        }

        let ret = match ready!(inner.poll_flush_unpin(cx)) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(e),
        };
        Poll::Ready(ret)
    }
}
