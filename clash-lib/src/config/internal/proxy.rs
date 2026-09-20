use crate::{Error, common::utils::default_bool_true, config::utils};
use serde::{Deserialize, Deserializer, de::value::MapDeserializer};
use serde_yaml::Value;
#[cfg(feature = "shadowquic")]
use shadowquic::config::CongestionControl as SQCongestionControl;
use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
};
use uuid::Uuid;

pub const PROXY_DIRECT: &str = "DIRECT";
pub const PROXY_REJECT: &str = "REJECT";
pub const PROXY_GLOBAL: &str = "GLOBAL";

#[allow(clippy::large_enum_variant)]
pub enum OutboundProxy {
    ProxyServer(OutboundProxyProtocol),
    ProxyGroup(OutboundGroupProtocol),
}

impl OutboundProxy {
    pub fn name(&self) -> String {
        match self {
            OutboundProxy::ProxyServer(s) => s.name().to_string(),
            OutboundProxy::ProxyGroup(g) => g.name().to_string(),
        }
    }
}

pub fn map_serde_error(
    name: String,
) -> impl FnOnce(serde_yaml::Error) -> crate::Error {
    move |x| {
        if let Some(loc) = x.location() {
            Error::InvalidConfig(format!(
                "invalid config for {} at line {}, column {} while parsing {}",
                name,
                loc.line(),
                loc.column(),
                name
            ))
        } else {
            Error::InvalidConfig(format!("error while parsing {name}: {x}"))
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum OutboundProxyProtocol {
    #[serde(rename = "direct")]
    Direct(OutboundDirect),
    #[serde(rename = "reject")]
    Reject(OutboundReject),
    #[cfg(feature = "shadowsocks")]
    #[serde(rename = "ss")]
    Ss(OutboundShadowsocks),
    #[serde(rename = "socks5")]
    Socks5(OutboundSocks5),
    #[serde(rename = "anytls")]
    Anytls(OutboundAnytls),
    #[serde(rename = "trojan")]
    Trojan(OutboundTrojan),
    #[serde(rename = "vmess")]
    Vmess(OutboundVmess),
    #[serde(rename = "vless")]
    Vless(OutboundVless),
    #[cfg(feature = "wireguard")]
    #[serde(rename = "wireguard")]
    Wireguard(OutboundWireguard),
    #[cfg(feature = "onion")]
    #[serde(rename = "tor")]
    Tor(OutboundTor),
    #[cfg(feature = "tuic")]
    #[serde(rename = "tuic")]
    Tuic(OutboundTuic),
    #[serde(rename = "hysteria2")]
    Hysteria2(OutboundHysteria2),
    #[serde(rename = "ssh")]
    #[cfg(feature = "ssh")]
    Ssh(OutboundSsh),
    #[serde(rename = "shadowquic")]
    #[cfg(feature = "shadowquic")]
    ShadowQuic(OutboundShadowQuic),
    #[serde(rename = "tailscale")]
    #[cfg(feature = "tailscale")]
    Tailscale(OutboundTailscale),
}

impl OutboundProxyProtocol {
    pub fn name(&self) -> &str {
        match &self {
            OutboundProxyProtocol::Direct(direct) => &direct.name,
            OutboundProxyProtocol::Reject(reject) => &reject.name,
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ss(ss) => &ss.common_opts.name,
            OutboundProxyProtocol::Socks5(socks5) => &socks5.common_opts.name,
            OutboundProxyProtocol::Anytls(anytls) => &anytls.common_opts.name,
            OutboundProxyProtocol::Trojan(trojan) => &trojan.common_opts.name,
            OutboundProxyProtocol::Vmess(vmess) => &vmess.common_opts.name,
            OutboundProxyProtocol::Vless(vless) => &vless.common_opts.name,
            #[cfg(feature = "wireguard")]
            OutboundProxyProtocol::Wireguard(wireguard) => {
                &wireguard.common_opts.name
            }
            #[cfg(feature = "onion")]
            OutboundProxyProtocol::Tor(tor) => &tor.name,
            #[cfg(feature = "tuic")]
            OutboundProxyProtocol::Tuic(tuic) => &tuic.common_opts.name,
            OutboundProxyProtocol::Hysteria2(hysteria2) => &hysteria2.name,
            #[cfg(feature = "ssh")]
            OutboundProxyProtocol::Ssh(ssh) => &ssh.common_opts.name,
            #[cfg(feature = "shadowquic")]
            OutboundProxyProtocol::ShadowQuic(sq) => &sq.common_opts.name,
            #[cfg(feature = "tailscale")]
            OutboundProxyProtocol::Tailscale(ts) => &ts.name,
        }
    }
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProtocol {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy protocol".to_owned(),
            ))?
            .to_owned();
        OutboundProxyProtocol::deserialize(MapDeserializer::new(mapping.into_iter()))
            .map_err(map_serde_error(name))
    }
}

impl Display for OutboundProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "shadowsocks")]
            OutboundProxyProtocol::Ss(_) => write!(f, "Shadowsocks"),
            OutboundProxyProtocol::Socks5(_) => write!(f, "Socks5"),
            OutboundProxyProtocol::Anytls(_) => write!(f, "AnyTLS"),
            OutboundProxyProtocol::Direct(_) => write!(f, "{PROXY_DIRECT}"),
            OutboundProxyProtocol::Reject(_) => write!(f, "{PROXY_REJECT}"),
            OutboundProxyProtocol::Trojan(_) => write!(f, "Trojan"),
            OutboundProxyProtocol::Vmess(_) => write!(f, "Vmess"),
            OutboundProxyProtocol::Vless(_) => write!(f, "Vless"),
            #[cfg(feature = "wireguard")]
            OutboundProxyProtocol::Wireguard(_) => write!(f, "Wireguard"),
            #[cfg(feature = "onion")]
            OutboundProxyProtocol::Tor(_) => write!(f, "Tor"),
            #[cfg(feature = "tuic")]
            OutboundProxyProtocol::Tuic(_) => write!(f, "Tuic"),
            OutboundProxyProtocol::Hysteria2(_) => write!(f, "Hysteria2"),
            #[cfg(feature = "ssh")]
            OutboundProxyProtocol::Ssh(_) => write!(f, "Ssh"),
            #[cfg(feature = "shadowquic")]
            OutboundProxyProtocol::ShadowQuic(_) => write!(f, "ShadowQUIC"),
            #[cfg(feature = "tailscale")]
            OutboundProxyProtocol::Tailscale(_) => write!(f, "Tailscale"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct CommonConfigOptions {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// this can be a proxy name or a group name
    /// can't be a name in a proxy provider
    /// only applies to raw proxy, i.e. applying this to a proxy group does
    /// nothing
    #[serde(alias = "dialer-proxy")]
    pub connect_via: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundDirect {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundReject {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundShadowsocks {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub cipher: String,
    pub password: String,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
    pub plugin: Option<String>,
    pub plugin_opts: Option<HashMap<String, serde_yaml::Value>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSocks5 {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "Default::default")]
    pub tls: bool,
    pub sni: Option<String>,
    #[serde(default = "Default::default")]
    pub skip_cert_verify: bool,
    #[serde(default = "default_bool_true")]
    pub udp: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct WsOpt {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub max_early_data: Option<i32>,
    pub early_data_header_name: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
pub struct H2Opt {
    pub host: Option<Vec<String>>,
    pub path: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct GrpcOpt {
    pub grpc_service_name: Option<String>,
}

fn deserialize_short_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct ShortIdVisitor;

    impl<'de> serde::de::Visitor<'de> for ShortIdVisitor {
        type Value = String;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "a hex string, null, or an empty sequence for reality short-id"
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.to_owned())
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(String::new())
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(String::new())
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if let Some(first) = seq.next_element::<String>()? {
                if seq.next_element::<String>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "reality short-id expects a single value, got a sequence",
                    ));
                }
                Ok(first)
            } else {
                Ok(String::new())
            }
        }
    }

    deserializer.deserialize_any(ShortIdVisitor)
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RealityOpt {
    pub public_key: String,
    #[serde(deserialize_with = "deserialize_short_id", default)]
    pub short_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundAnytls {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub fingerprint: Option<String>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub client_fingerprint: Option<String>,
    pub udp: Option<bool>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub idle_session_check_interval: Option<u64>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub idle_session_timeout: Option<u64>,
    /// Parsed for config compatibility; currently not applied by the runtime.
    pub min_idle_session: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    pub tls_key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTrojan {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub password: String,
    pub alpn: Option<Vec<String>>,
    pub sni: Option<String>,
    pub skip_cert_verify: Option<bool>,
    pub udp: Option<bool>,
    pub network: Option<String>,
    pub grpc_opts: Option<GrpcOpt>,
    pub ws_opts: Option<WsOpt>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    pub tls_key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundVmess {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: String,
    #[serde(alias = "alterId")]
    pub alter_id: u16,
    pub cipher: Option<String>,
    pub udp: Option<bool>,
    pub tls: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    #[serde(alias = "servername")]
    pub server_name: Option<String>,
    pub network: Option<String>,
    pub ws_opts: Option<WsOpt>,
    pub h2_opts: Option<H2Opt>,
    pub grpc_opts: Option<GrpcOpt>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    pub tls_key: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundVless {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: String,
    pub udp: Option<bool>,
    pub tls: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    #[serde(alias = "servername")]
    pub server_name: Option<String>,
    pub network: Option<String>,
    pub ws_opts: Option<WsOpt>,
    pub h2_opts: Option<H2Opt>,
    pub grpc_opts: Option<GrpcOpt>,
    pub reality_opts: Option<RealityOpt>,
    pub flow: Option<String>,
    pub client_fingerprint: Option<String>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    pub tls_key: Option<String>,
}

#[cfg(feature = "wireguard")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundWireguard {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub private_key: String,
    pub public_key: String,
    #[serde(alias = "preshared-key")]
    pub pre_shared_key: Option<String>,
    pub mtu: Option<u16>,
    pub udp: Option<bool>,
    pub ip: String,
    pub ipv6: Option<String>,
    pub remote_dns_resolve: Option<bool>,
    pub dns: Option<Vec<String>>,
    pub allowed_ips: Option<Vec<String>>,
    pub reserved_bits: Option<Vec<u8>>,
}

#[cfg(feature = "onion")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTor {
    pub name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTuic {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub uuid: Uuid,
    pub password: String,
    /// override field 'server' dns record
    pub ip: Option<String>,
    pub heartbeat_interval: Option<u64>,
    /// h3
    pub alpn: Option<Vec<String>>,
    pub disable_sni: Option<bool>,
    pub reduce_rtt: Option<bool>,
    /// millis
    pub request_timeout: Option<u64>,
    pub udp_relay_mode: Option<String>,
    pub congestion_controller: Option<String>,
    /// bytes
    pub max_udp_relay_packet_size: Option<u64>,
    pub fast_open: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    pub max_open_stream: Option<u64>,
    pub sni: Option<String>,
    /// millis
    pub gc_interval: Option<u64>,
    /// millis
    pub gc_lifetime: Option<u64>,
    pub send_window: Option<u64>,
    pub receive_window: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    pub tls_key: Option<String>,
}

#[cfg(feature = "shadowquic")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundShadowQuic {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    /// jls password, must be the same as the server
    pub password: String,
    /// jls username, must be the same as the server
    pub username: String,
    /// server name, must be the same as the server jls_upstream
    /// domain name
    pub server_name: String,
    /// alpn, default to "h3"
    pub alpn: Option<Vec<String>>,
    /// initial mtu, must be larger than min mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1300
    pub initial_mtu: Option<u16>,
    /// congestion control, default to "bbr"
    pub congestion_control: Option<SQCongestionControl>, // bbr, new-reno, cubic
    /// set to true to enable zero rtt, default to true
    pub zero_rtt: Option<bool>,
    /// if true, use quic stream to send UDP, otherwise use quic datagram
    /// extension, similar to native UDP in TUIC
    pub over_stream: Option<bool>,
    /// minimum mtu, must be smaller than initial mtu, at least to be 1200.
    /// 1400 is recommended for high packet loss network. default to be 1290
    pub min_mtu: Option<u16>,
    /// keep alive interval in milliseconds
    /// 0 means disable keep alive, should be smaller than 30_000(idle time)
    pub keep_alive_interval: Option<u32>,
    /// Generalized Segmentation Offload for QUIC udp connection, default to
    /// true.
    pub gso: Option<bool>,
    /// MTU discovery for QUIC connection, default to true. If false, will use
    /// initial mtu as fixed mtu. This is useful for network with stable MTU
    /// and high packet loss.
    pub mtu_discovery: Option<bool>,
}

#[cfg(feature = "ssh")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundSsh {
    #[serde(flatten)]
    pub common_opts: CommonConfigOptions,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    pub host_key: Option<Vec<String>>,
    pub host_key_algorithms: Option<Vec<String>>,
    pub totp_opt: Option<TotpOption>,
}

#[cfg(feature = "tailscale")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundTailscale {
    pub name: String,
    pub state_dir: Option<String>,
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    pub control_url: Option<String>,
    pub client_name: Option<String>,
    #[serde(default)]
    pub ephemeral: bool,
}

#[cfg(feature = "ssh")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum TotpOption {
    OtpAuth(String),
    Common(Totp),
}

#[cfg(feature = "ssh")]
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Totp {
    pub secret: String,
    pub screw: u8,
    pub step: u64,
    pub digits: usize,
    pub algorithm: totp_rs::Algorithm,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHysteria2 {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// port hopping
    pub ports: Option<String>,
    pub password: String,
    pub obfs: Option<Hysteria2Obfs>,
    pub obfs_password: Option<String>,
    pub alpn: Option<Vec<String>>,
    /// set brutal congestion control, need compare with tx which is received by
    /// auth request
    pub up: Option<u64>,
    /// receive_bps: send by auth request
    pub down: Option<u64>,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub ca: Option<String>,
    pub ca_str: Option<String>,
    pub fingerprint: Option<String>,
    pub udp_mtu: Option<u32>,
    pub disable_mtu_discovery: Option<bool>,
    /// bbr congestion control window
    pub cwnd: Option<u64>,
    /// File path or inline PEM client certificate for mTLS.
    /// Must be set together with `tls-key`.
    pub tls_cert: Option<String>,
    /// File path or inline PEM client private key for mTLS.
    /// Must be set together with `tls-cert`.
    pub tls_key: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Hysteria2Obfs {
    Salamander,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum OutboundGroupProtocol {
    #[serde(rename = "relay")]
    Relay(OutboundGroupRelay),
    #[serde(rename = "url-test")]
    UrlTest(OutboundGroupUrlTest),
    #[serde(rename = "fallback")]
    Fallback(OutboundGroupFallback),
    #[serde(rename = "load-balance")]
    LoadBalance(OutboundGroupLoadBalance),
    #[serde(rename = "smart")]
    Smart(OutboundGroupSmart),
    #[serde(rename = "select")]
    Select(OutboundGroupSelect),
}

/// Only used statically in config parsing.
/// Runtime access is done via the `try_as_group_handler`.
impl OutboundGroupProtocol {
    /// Returns the name of the group.
    pub fn name(&self) -> &str {
        match &self {
            OutboundGroupProtocol::Relay(g) => &g.name,
            OutboundGroupProtocol::UrlTest(g) => &g.name,
            OutboundGroupProtocol::Fallback(g) => &g.name,
            OutboundGroupProtocol::LoadBalance(g) => &g.name,
            OutboundGroupProtocol::Smart(g) => &g.name,
            OutboundGroupProtocol::Select(g) => &g.name,
        }
    }

    /// Returns the proxies in the group, if any.
    pub fn proxies(&self) -> Option<&Vec<String>> {
        match &self {
            OutboundGroupProtocol::Relay(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::UrlTest(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Fallback(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::LoadBalance(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Smart(g) => g.proxies.as_ref(),
            OutboundGroupProtocol::Select(g) => g.proxies.as_ref(),
        }
    }
}

impl Display for OutboundGroupProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundGroupProtocol::Relay(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::UrlTest(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Fallback(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::LoadBalance(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Select(g) => write!(f, "{}", g.name),
            OutboundGroupProtocol::Smart(g) => write!(f, "{}", g.name),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupRelay {
    pub name: String,
    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
    pub icon: Option<String>,
    pub url: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupUrlTest {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub tolerance: Option<u16>,
    pub icon: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupFallback {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupLoadBalance {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub url: String,
    #[serde(deserialize_with = "utils::deserialize_u64")]
    pub interval: u64,
    pub lazy: Option<bool>,
    pub strategy: Option<LoadBalanceStrategy>,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Default)]
pub enum LoadBalanceStrategy {
    #[default]
    #[serde(rename = "consistent-hashing")]
    ConsistentHashing,
    #[serde(rename = "round-robin")]
    RoundRobin,
    #[serde(rename = "sticky-session")]
    StickySession,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupSmart {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    pub udp: Option<bool>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,

    pub lazy: Option<bool>,
    pub icon: Option<String>,
    pub url: Option<String>,

    /// Maximum retries for failed connections (default: 3)
    #[serde(rename = "max-retries")]
    pub max_retries: Option<u32>,

    /// Site stickiness factor (0.0-1.0, default: 0.8)
    /// Higher values make the same site more likely to use the same proxy
    #[serde(rename = "site-stickiness")]
    pub site_stickiness: Option<f64>,

    /// Bandwidth consideration weight (default: 0.0 - disabled)
    /// When > 0, bandwidth metrics are included in selection algorithm
    #[serde(rename = "bandwidth-weight")]
    pub bandwidth_weight: Option<f64>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct OutboundGroupSelect {
    pub name: String,

    pub proxies: Option<Vec<String>>,
    #[serde(rename = "use")]
    pub use_provider: Option<Vec<String>>,
    pub udp: Option<bool>,

    pub url: Option<String>,
    pub icon: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum OutboundProxyProviderDef {
    Http(OutboundHttpProvider),
    File(OutboundFileProvider),
}

impl OutboundProxyProviderDef {
    pub fn set_name(&mut self, name: String) {
        match self {
            OutboundProxyProviderDef::Http(p) => p.name = name,
            OutboundProxyProviderDef::File(p) => p.name = name,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundHttpProvider {
    #[serde(skip)]
    pub name: String,
    pub url: String,
    pub interval: u64,
    pub path: String,
    pub health_check: HealthCheck,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundFileProvider {
    #[serde(skip)]
    pub name: String,
    pub path: String,
    pub interval: Option<u64>,
    pub health_check: HealthCheck,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct HealthCheck {
    pub enable: bool,
    pub url: String,
    pub interval: u64,
    pub lazy: Option<bool>,
}

impl TryFrom<HashMap<String, Value>> for OutboundProxyProviderDef {
    type Error = crate::Error;

    fn try_from(mapping: HashMap<String, Value>) -> Result<Self, Self::Error> {
        let name = mapping
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or(Error::InvalidConfig(
                "missing field `name` in outbound proxy provider".to_owned(),
            ))?
            .to_owned();
        OutboundProxyProviderDef::deserialize(MapDeserializer::new(
            mapping.into_iter(),
        ))
        .map_err(map_serde_error(name))
    }
}

#[cfg(all(test, feature = "tailscale"))]
mod tailscale_tests {
    use super::{OutboundProxyProtocol, OutboundTailscale};
    use serde_yaml::Value;
    use std::collections::HashMap;

    #[test]
    fn parse_tailscale_outbound_proxy_protocol() {
        let mapping = HashMap::from([
            ("name".to_owned(), Value::String("ts-out".to_owned())),
            ("type".to_owned(), Value::String("tailscale".to_owned())),
            ("state-dir".to_owned(), Value::String("/tmp/ts".to_owned())),
            (
                "auth-key".to_owned(),
                Value::String("tskey-auth-xxxx".to_owned()),
            ),
            ("hostname".to_owned(), Value::String("clash-rs".to_owned())),
            (
                "control-url".to_owned(),
                Value::String("https://controlplane.tailscale.com".to_owned()),
            ),
            ("ephemeral".to_owned(), Value::Bool(true)),
        ]);

        let protocol = OutboundProxyProtocol::try_from(mapping)
            .expect("tailscale proxy should parse");
        let OutboundProxyProtocol::Tailscale(OutboundTailscale {
            name,
            state_dir,
            auth_key,
            hostname,
            control_url,
            client_name: _,
            ephemeral,
        }) = protocol
        else {
            panic!("expected tailscale variant")
        };

        assert_eq!(name, "ts-out");
        assert_eq!(state_dir.as_deref(), Some("/tmp/ts"));
        assert_eq!(auth_key.as_deref(), Some("tskey-auth-xxxx"));
        assert_eq!(hostname.as_deref(), Some("clash-rs"));
        assert_eq!(
            control_url.as_deref(),
            Some("https://controlplane.tailscale.com")
        );
        assert!(ephemeral);
    }
}

#[cfg(all(test, feature = "wireguard"))]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_pre_shared_key_field_name() {
        // Test the new standard field name "pre-shared-key"
        let yaml_new = r#"
            name: wg-test
            type: wireguard
            server: example.com
            port: 51820
            private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
            public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
            pre-shared-key: +JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=
            ip: 10.0.0.2/32
        "#;

        let config: OutboundWireguard = serde_yaml::from_str(yaml_new)
            .expect("should parse with pre-shared-key");
        assert!(config.pre_shared_key.is_some());
        assert_eq!(
            config.pre_shared_key.unwrap(),
            "+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc="
        );
    }

    #[test]
    fn test_wireguard_preshared_key_legacy_alias() {
        // Test the legacy field name "preshared-key" for backward compatibility
        let yaml_legacy = r#"
            name: wg-test
            type: wireguard
            server: example.com
            port: 51820
            private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
            public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
            preshared-key: +JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc=
            ip: 10.0.0.2/32
        "#;

        let config: OutboundWireguard = serde_yaml::from_str(yaml_legacy)
            .expect("should parse with preshared-key (legacy)");
        assert!(config.pre_shared_key.is_some());
        assert_eq!(
            config.pre_shared_key.unwrap(),
            "+JmZErvtDT4ZfQequxWhZSydBV+ItqUcPMHUWY1j2yc="
        );
    }

    #[test]
    fn test_wireguard_without_pre_shared_key() {
        // Test config without pre-shared-key (should be optional)
        let yaml_no_psk = r#"
            name: wg-test
            type: wireguard
            server: example.com
            port: 51820
            private-key: KIlDUePHyYwzjgn18przw/ZwPioJhh2aEyhxb/dtCXI=
            public-key: INBZyvB715sA5zatkiX8Jn3Dh5tZZboZ09x4pkr66ig=
            ip: 10.0.0.2/32
        "#;

        let config: OutboundWireguard = serde_yaml::from_str(yaml_no_psk)
            .expect("should parse without pre-shared-key");
        assert!(config.pre_shared_key.is_none());
    }
}

#[cfg(test)]
mod anytls_tests {
    use super::{OutboundProxyProtocol, OutboundProxyProtocol::Anytls};

    #[test]
    fn test_anytls_deserialize() {
        let yaml = r#"
            name: anytls-test
            type: anytls
            server: example.com
            port: 443
            password: example-password
            sni: sni.example.com
            skip-cert-verify: true
            udp: true
            idle-session-check-interval: 30
            idle-session-timeout: 300
            min-idle-session: 2
        "#;

        let config: OutboundProxyProtocol =
            serde_yaml::from_str(yaml).expect("should parse anytls");

        let Anytls(config) = config else {
            panic!("expected anytls config");
        };

        assert_eq!(config.common_opts.name, "anytls-test");
        assert_eq!(config.common_opts.server, "example.com");
        assert_eq!(config.common_opts.port, 443);
        assert_eq!(config.password, "example-password");
        assert_eq!(config.sni.as_deref(), Some("sni.example.com"));
        assert_eq!(config.skip_cert_verify, Some(true));
        assert_eq!(config.udp, Some(true));
        assert_eq!(config.idle_session_check_interval, Some(30));
        assert_eq!(config.idle_session_timeout, Some(300));
        assert_eq!(config.min_idle_session, Some(2));
    }
}

#[cfg(test)]
mod short_id_tests {
    #[derive(serde::Deserialize, Debug)]
    struct ShortIdWrapper {
        #[serde(deserialize_with = "super::deserialize_short_id", default)]
        short_id: String,
    }

    #[test]
    fn deserialize_short_id_plain_string() {
        let yaml = "short_id: abc123";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "abc123");
    }

    #[test]
    fn deserialize_short_id_null() {
        let yaml = "short_id: null";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "");
    }

    #[test]
    fn deserialize_short_id_tilde_unit() {
        let yaml = "short_id: ~";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "");
    }

    #[test]
    fn deserialize_short_id_empty_string() {
        let yaml = "short_id: \"\"";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "");
    }

    #[test]
    fn deserialize_short_id_hex_string() {
        let yaml = "short_id: 0123456789abcdef";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "0123456789abcdef");
    }

    #[test]
    fn deserialize_short_id_empty_seq() {
        let yaml = "short_id: []";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "");
    }

    #[test]
    fn deserialize_short_id_single_value_seq() {
        let yaml = "short_id: [\"abc\"]";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "abc");
    }

    #[test]
    fn deserialize_short_id_single_empty_string_seq() {
        let yaml = "short_id: [\"\"]";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "");
    }

    #[test]
    fn deserialize_short_id_multi_value_seq_rejected() {
        let yaml = "short_id: [\"a\", \"b\"]";
        let err = serde_yaml::from_str::<ShortIdWrapper>(yaml)
            .expect_err("should reject multi-value sequence");
        let msg = err.to_string();
        assert!(
            msg.contains("reality short-id expects a single value"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn deserialize_short_id_triple_seq_rejected() {
        let yaml = "short_id: [\"a\", \"b\", \"c\"]";
        let err = serde_yaml::from_str::<ShortIdWrapper>(yaml)
            .expect_err("should reject triple-value sequence");
        let msg = err.to_string();
        assert!(
            msg.contains("reality short-id expects a single value"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn deserialize_short_id_missing_field() {
        let yaml = "other: value";
        let w: ShortIdWrapper = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(w.short_id, "");
    }

    // --- Integration tests: RealityOpt within OutboundVless ---

    #[test]
    fn vless_reality_opts_with_short_id_string() {
        let yaml = r#"
  type: vless
  name: test
  server: example.com
  port: 443
  uuid: test-uuid
  reality-opts:
    public-key: abc123
    short-id: deadbeef
"#;
        let v: super::OutboundVless = serde_yaml::from_str(yaml).unwrap();
        let reality = v.reality_opts.expect("reality_opts should be Some");
        assert_eq!(reality.public_key, "abc123");
        assert_eq!(reality.short_id, "deadbeef");
    }

    #[test]
    fn vless_reality_opts_with_null_short_id() {
        let yaml = r#"
  type: vless
  name: test
  server: example.com
  port: 443
  uuid: test-uuid
  reality-opts:
    public-key: abc123
    short-id: null
"#;
        let v: super::OutboundVless = serde_yaml::from_str(yaml).unwrap();
        let reality = v.reality_opts.expect("reality_opts should be Some");
        assert_eq!(reality.short_id, "");
    }

    #[test]
    fn vless_reality_opts_with_seq_short_id() {
        let yaml = r#"
  type: vless
  name: test
  server: example.com
  port: 443
  uuid: test-uuid
  reality-opts:
    public-key: abc123
    short-id: ["ff"]
"#;
        let v: super::OutboundVless = serde_yaml::from_str(yaml).unwrap();
        let reality = v.reality_opts.expect("reality_opts should be Some");
        assert_eq!(reality.short_id, "ff");
    }

    #[test]
    fn vless_reality_opts_without_short_id() {
        let yaml = r#"
  type: vless
  name: test
  server: example.com
  port: 443
  uuid: test-uuid
  reality-opts:
    public-key: abc123
"#;
        let v: super::OutboundVless = serde_yaml::from_str(yaml).unwrap();
        let reality = v.reality_opts.expect("reality_opts should be Some");
        assert_eq!(reality.short_id, "");
    }

    #[test]
    fn vless_without_reality_opts() {
        let yaml = r#"
  type: vless
  name: test
  server: example.com
  port: 443
  uuid: test-uuid
"#;
        let v: super::OutboundVless = serde_yaml::from_str(yaml).unwrap();
        assert!(v.reality_opts.is_none());
    }

    #[test]
    fn vless_reality_opts_multi_seq_rejected() {
        let yaml = r#"
  type: vless
  name: test
  server: example.com
  port: 443
  uuid: test-uuid
  reality-opts:
    public-key: abc123
    short-id: ["a", "b"]
"#;
        let err = serde_yaml::from_str::<super::OutboundVless>(yaml)
            .expect_err("should reject multi-value short-id sequence");
        let msg = err.to_string();
        assert!(
            msg.contains("reality short-id expects a single value"),
            "unexpected error: {msg}"
        );
    }
}
