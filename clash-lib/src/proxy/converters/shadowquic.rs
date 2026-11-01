use shadowquic::config::{
    default_alpn, default_blackhole_detection, default_congestion_control,
    default_gso, default_initial_mtu, default_keep_alive_interval, default_min_mtu,
    default_mtu_discovery, default_over_stream, default_zero_rtt,
};

use crate::{
    config::proxy::OutboundShadowQuic,
    proxy::shadowquic::{Handler, HandlerOptions},
    session::SocksAddr,
};

impl TryFrom<OutboundShadowQuic> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowQuic) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowQuic> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowQuic) -> Result<Self, Self::Error> {
        Ok(Handler::new(
            s.common_opts.name.clone(),
            HandlerOptions {
                addr: SocksAddr::try_from((
                    s.common_opts.server.clone(),
                    s.common_opts.port,
                ))?
                .to_string(),
                password: s.password.clone(),
                username: s.username.clone(),
                server_name: s.server_name.clone(),
                alpn: s.alpn.clone().unwrap_or(default_alpn()),
                initial_mtu: s.initial_mtu.unwrap_or(default_initial_mtu()),
                congestion_control: s
                    .congestion_control
                    .clone()
                    .unwrap_or(default_congestion_control()),
                zero_rtt: s.zero_rtt.unwrap_or(default_zero_rtt()),
                over_stream: s.over_stream.unwrap_or(default_over_stream()),
                min_mtu: s.min_mtu.unwrap_or(default_min_mtu()),
                keep_alive_interval: s
                    .keep_alive_interval
                    .unwrap_or(default_keep_alive_interval()),
                blackhole_detection: default_blackhole_detection(),

                protect_path: None,
                socket_opt: Default::default(),
                gso: s.gso.unwrap_or(default_gso()),
                mtu_discovery: s.mtu_discovery.unwrap_or(default_mtu_discovery()),
                cipher_suite_preference: None,
                ..Default::default()
            },
        ))
    }
}
