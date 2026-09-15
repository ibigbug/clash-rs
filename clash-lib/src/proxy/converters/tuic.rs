use std::time::Duration;

use wind_quinn::VarInt;

use crate::{
    config::internal::proxy::OutboundTuic,
    proxy::{
        HandlerCommonOptions,
        tuic::{Handler, HandlerOptions, types::CongestionControl},
    },
};

impl TryFrom<OutboundTuic> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTuic) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTuic> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTuic) -> Result<Self, Self::Error> {
        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            server: s.common_opts.server.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            port: s.common_opts.port,
            uuid: s.uuid.to_owned(),
            password: s.password.to_owned(),
            udp_relay_mode: s
                .udp_relay_mode
                .to_owned()
                .unwrap_or("native".to_string())
                .as_str()
                .into(),
            disable_sni: s.disable_sni.unwrap_or(false),
            alpn: s
                .alpn
                .clone()
                .unwrap_or_else(|| vec!["h3".to_string()])
                .into_iter()
                .map(|s| s.into_bytes())
                .collect(),
            heartbeat_interval: Duration::from_millis(
                s.heartbeat_interval.unwrap_or(3000),
            ),
            reduce_rtt: s.reduce_rtt.unwrap_or(false)
                || s.fast_open.unwrap_or(false),
            request_timeout: Duration::from_millis(
                s.request_timeout.unwrap_or(4000),
            ),
            idle_timeout: Duration::from_millis(s.request_timeout.unwrap_or(4000)),
            congestion_controller: s
                .congestion_controller
                .clone()
                .map(|v| CongestionControl::from(v.as_str()))
                .unwrap_or_default(),
            max_udp_relay_packet_size: s.max_udp_relay_packet_size.unwrap_or(1500),
            max_open_stream: VarInt::from_u64(s.max_open_stream.unwrap_or(32))
                .unwrap_or(VarInt::MAX),
            ip: s.ip.clone(),
            skip_cert_verify: s.skip_cert_verify.unwrap_or(false),
            sni: s.sni.clone(),
            gc_interval: Duration::from_millis(s.gc_interval.unwrap_or(3000)),
            gc_lifetime: Duration::from_millis(s.gc_lifetime.unwrap_or(15000)),
            send_window: s.send_window.unwrap_or(8 * 1024 * 1024 * 2),
            receive_window: VarInt::from_u64(
                s.receive_window.unwrap_or(8 * 1024 * 1024),
            )
            .unwrap_or(VarInt::MAX),
            tls_cert: s.tls_cert.clone(),
            tls_key: s.tls_key.clone(),
        }))
    }
}
