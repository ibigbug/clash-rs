use crate::{
    app::net::SocketMark,
    config::internal::proxy::PROXY_DIRECT,
    dns::{
        ClashResolver, EdnsClientSubnet, RuleDispatch, ThreadSafeDNSClient,
        dns_client::{DNSNetMode, DnsClient, Opts},
    },
    proxy::{
        self,
        utils::{OutboundHandlerRegistry, SharedOutboundHandler},
    },
};
use hickory_proto::rr::rdata::opt::EdnsCode;
use std::sync::Arc;
use tracing::{debug, warn};

use super::config::NameServer;

pub async fn make_clients(
    servers: Vec<NameServer>,
    resolver: Option<Arc<dyn ClashResolver>>,
    outbounds: OutboundHandlerRegistry,
    edns_client_subnet: Option<EdnsClientSubnet>,
    fw_mark: Option<SocketMark>,
    rule_dispatch: Option<Arc<RuleDispatch>>,
) -> Vec<ThreadSafeDNSClient> {
    let mut rv = Vec::new();

    for s in servers {
        debug!("building nameserver: {}", s);

        let proxy_name = s.proxy.clone().unwrap_or(PROXY_DIRECT.to_string());
        let proxy: Arc<dyn proxy::OutboundHandler> =
            Arc::new(SharedOutboundHandler::new(proxy_name, outbounds.clone()));

        // An explicit `#proxy=...` always wins — rule-engine routing is only
        // applied to nameservers that opted into the default DIRECT path.
        let rd = if s.proxy.is_none() {
            rule_dispatch.clone()
        } else {
            None
        };

        let port = if s.net == DNSNetMode::Dhcp { 0 } else { s.port };

        match DnsClient::new_client(Opts {
            father: resolver.as_ref().cloned(),
            host: s.host.clone(),
            port,
            net: s.net.to_owned(),
            iface: s
                .interface
                .clone()
                .inspect(|x| debug!("DNS client interface: {:?}", x)),
            proxy,
            ecs: edns_client_subnet.clone(),
            fw_mark,
            rule_dispatch: rd,
        })
        .await
        {
            Ok(c) => rv.push(c),
            Err(e) => warn!("initializing DNS client {} with error {}", &s, e),
        }
    }

    rv
}

pub fn build_dns_response_message(
    req: &hickory_proto::op::Message,
    recursive_available: bool,
    authoritative: bool,
) -> hickory_proto::op::Message {
    let mut res =
        hickory_proto::op::Message::response(req.metadata.id, req.metadata.op_code);

    res.metadata.recursion_available = recursive_available;
    res.metadata.authoritative = authoritative;
    res.metadata.recursion_desired = req.metadata.recursion_desired;
    res.metadata.checking_disabled = req.metadata.checking_disabled;

    res.add_queries(req.queries.iter().cloned());

    if let Some(edns) = req.edns.clone() {
        res.set_edns(edns);
    }

    if let Some(edns) = res.edns.as_mut() {
        // Remove only padding options, keep everything else
        edns.options_mut().remove(EdnsCode::Padding);
    }

    res
}
