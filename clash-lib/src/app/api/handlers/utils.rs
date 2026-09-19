use std::{io, time::Duration};

use http::{HeaderMap, header};
use serde::Deserialize;

use crate::{
    app::outbound::manager::ThreadSafeOutboundManager, proxy::AnyOutboundHandler,
};

/// Shared query-string parameters for all latency-test endpoints.
#[derive(Deserialize)]
pub struct DelayRequest {
    pub url: String,
    pub timeout: u16,
}

/// Run `url_test` over a group proxy and all its members, and if the group has
/// a latency test URL, use it as the test URL; otherwise, use the provided
/// fallback URL.
/// Returns the latency of the group active proxy if found, otherwise the
/// latency of the group itself.
pub async fn group_url_test(
    outbound_manager: &ThreadSafeOutboundManager,
    proxy: AnyOutboundHandler,
    fallback_url: &str,
    timeout: Duration,
) -> std::io::Result<(Duration, Duration)> {
    let group = proxy.try_as_group_handler().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "proxy is not a group")
    })?;
    let latency_test_url = group.get_latency_test_url();
    let members = group.get_proxies().await;
    let active_proxy = group.get_active_proxy().await;
    let active_idx = active_proxy
        .as_ref()
        .and_then(|active| members.iter().position(|p| p.name() == active.name()));

    // clone proxy 以便 url_test 之后仍能通过 group 借用调用 force_fastest
    // (proxy 是 Arc<dyn OutboundHandler>, clone 仅增加引用计数, 廉价)
    let proxy_for_test = proxy.clone();

    // 先执行测速, 更新 proxy_manager 中的延迟数据
    // force_fastest 必须在 url_test 完成后才调用, 否则测速期间并发的
    // connect_stream 调用会消费 force_switch 标志, 但此时延迟数据还是旧的,
    // 导致切换到旧数据中的"最快"节点而非刚测出的最快节点
    let results = outbound_manager
        .url_test(
            &[vec![proxy_for_test], members].concat(),
            latency_test_url.as_deref().unwrap_or(fallback_url),
            timeout,
            true,
        )
        .await;

    // 测速已完成, 延迟数据已更新到 proxy_manager, 现在设置 force_switch
    // 下次 fastest() 调用时将忽略 tolerance, 直接选择最低延迟节点
    group.force_fastest();

    // if found active proxy, return the latency of the active proxy, otherwise
    // return the latency of the first proxy (which is the latency of the
    // group).
    let result = if let Some(idx) = active_idx {
        results
            .get(idx + 1)
            .or_else(|| results.first())
            .ok_or_else(|| {
                io::Error::other("missing latency result for active proxy")
            })?
    } else {
        results
            .first()
            .ok_or_else(|| io::Error::other("no proxies in group"))?
    };

    match result {
        Ok(latency) => Ok(*latency),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

pub fn is_request_websocket(header: &HeaderMap) -> bool {
    header
        .get(header::CONNECTION)
        .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
        // Firefox sends "Connection: keep-alive, Upgrade"
        .is_some_and(|x| x.contains(&"upgrade".to_ascii_lowercase()))
        && header
            .get(header::UPGRADE)
            .and_then(|x| x.to_str().ok().map(|x| x.to_ascii_lowercase()))
            == Some("websocket".to_ascii_lowercase())
}
