use crate::{
    Error,
    app::remote_content_manager::providers::rule_provider::{
        RuleSetBehavior, RuleSetFormat,
    },
};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use serde_yaml::Value;
use std::{collections::HashMap, fmt::Display, path::PathBuf, str::FromStr};

const DEFAULT_ROUTE_TABLE: u32 = 2468;

use super::{
    config::BindAddress,
    internal::{
        listener::{InboundOpts, InboundProviderDef},
        proxy::{
            OutboundGroupProtocol, OutboundProxyProtocol, OutboundProxyProviderDef,
        },
    },
};

fn default_tun_device_id() -> String {
    "utun1989".to_string()
}

fn default_tun_address() -> String {
    "198.18.0.1/24".to_string()
}

fn default_route_table() -> u32 {
    DEFAULT_ROUTE_TABLE
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum DnsHijack {
    Switch(bool),
    List(Vec<String>),
}

impl Default for DnsHijack {
    fn default() -> Self {
        DnsHijack::Switch(false)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TunConfig {
    pub enable: bool,
    #[serde(alias = "device-url", alias = "device")]
    #[serde(default = "default_tun_device_id")]
    /// tun interface device id
    /// # Example:
    ///  * `dev://utun1989` on macOS
    ///  * `dev://tun0` on Linux
    ///  * `fd://3` if you want to use an existing file descriptor
    ///  * `utun1989` -> equivalent to `dev://utun1989`
    ///
    /// *Note*: macOS requires the `utun` prefix
    pub device_id: String,
    /// tun interface address
    #[serde(default = "default_tun_address")]
    pub gateway: String,
    /// tun interface address for IPv6
    /// # Note
    /// - set this to enable IPv6 support in the tun interface
    /// - Example: `2001:fac::1/64`
    #[serde(alias = "gateway-v6")]
    pub gateway_v6: Option<String>,
    pub routes: Option<Vec<String>>,
    #[serde(default)]
    pub route_all: bool,
    pub mtu: Option<u16>,
    /// fwmark on Linux only
    pub so_mark: Option<u32>,
    /// policy routing table on Linux only
    #[serde(default = "default_route_table")]
    pub route_table: u32,
    /// Will hijack UDP:53 DNS queries to the Clash DNS server if set to true
    /// setting to a list has the same effect as setting to true
    #[serde(default)]
    pub dns_hijack: DnsHijack,
}

#[derive(Serialize, Deserialize, Default, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[serde(alias = "Global")]
    Global,
    #[default]
    #[serde(alias = "Rule")]
    Rule,
    #[serde(alias = "Direct")]
    Direct,
}

impl Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::Global => write!(f, "global"),
            RunMode::Rule => write!(f, "rule"),
            RunMode::Direct => write!(f, "direct"),
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Default, Copy, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    #[serde(alias = "warn")]
    Warning,
    Error,
    #[serde(alias = "off")]
    Silent,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warning => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
            LogLevel::Silent => write!(f, "off"),
        }
    }
}

/// Example
/// ```yaml
/// ---
/// port: 8888
/// socks-port: 8889
/// mixed-port: 8899
///
/// tun:
///   enable: false
///   device-id: "dev://utun1989"
///
/// dns:
///   enable: true
///   listen: 127.0.0.1:53553
///   #   udp: 127.0.0.1:53553
///   #   tcp: 127.0.0.1:53553
///   #   dot: 127.0.0.1:53554
///   #   doh: 127.0.0.1:53555
///
///   # ipv6: false # when the false, response to AAAA questions will be empty
///
///   # These nameservers are used to resolve the DNS nameserver hostnames
/// below.   # Specify IP addresses only
///   default-nameserver:
///     - 114.114.114.114
///     - 8.8.8.8
///   enhanced-mode: fake-ip
///   fake-ip-range: 198.18.0.2/16 # Fake IP addresses pool CIDR
///   # use-hosts: true # lookup hosts and return IP record
///
///   # Hostnames in this list will not be resolved with fake IPs
///   # i.e. questions to these domain names will always be answered with their
///   # real IP addresses
///   # fake-ip-filter:
///   #   - '*.lan'
///   #   - localhost.ptlogin2.qq.com
///
///   # Supports UDP, TCP, DoT, DoH. You can specify the port to connect to.
///   # All DNS questions are sent directly to the nameserver, without proxies
///   # involved. Clash answers the DNS question with the first result gathered.
///   nameserver:
///     - 114.114.114.114 # default value
///     - 1.1.1.1 # default value
///     - tls://1.1.1.1:853 # DNS over TLS
///     - https://1.1.1.1/dns-query # DNS over HTTPS
/// #    - dhcp://en0 # dns from dhcp
///
/// allow-lan: true
/// mode: rule
/// log-level: debug
/// external-controller: 127.0.0.1:9090
/// external-ui: "public"
/// # secret: "clash-rs"
/// experimental:
///   ignore-resolve-fail: true
///
/// profile:
///   store-selected: true
///   store-fake-ip: false
///
/// proxy-groups:
///   - name: "relay"
///     type: relay
///     proxies:
///       - "plain-vmess"
///       - "ws-vmess"
///       - "auto"
///       - "fallback-auto"
///       - "load-balance"
///       - "select"
///       - DIRECT
///
///   - name: "relay-one"
///     type: relay
///     use:
///       - "file-provider"
///
///   - name: "auto"
///     type: url-test
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300
///
///   - name: "fallback-auto"
///     type: fallback
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300
///
///   - name: "load-balance"
///     type: load-balance
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     strategy: round-robin
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300
///
///   - name: select
///     type: select
///     use:
///       - "file-provider"
///
///   - name: test 🌏
///     type: select
///     use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///
/// proxies:
///   - name: plain-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 16823
///     uuid: b831381d-6324-4d53-ad4f-8cda48b30811
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///   - name: ws-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 16824
///     uuid: b831381d-6324-4d53-ad4f-8cda48b30811
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///     network: ws
///     ws-opts:
///         path: /api/v3/download.getFile
///         headers: Host: www.amazon.com
///
///   - name: tls-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 8443
///     uuid: 23ad6b10-8d1a-40f7-8ad0-e3e35cd38297
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///     tls: true
///
///   - name: h2-vmess
///     type: vmess
///     server: 10.0.0.13
///     port: 8444
///     uuid: b831381d-6324-4d53-ad4f-8cda48b30811
///     alterId: 0
///     cipher: auto
///     udp: true
///     skip-cert-verify: true
///     tls: true
///     network: h2
///     h2-opts:
///         path: /ray
///
///   - name: vmess-altid
///     type: vmess
///     server: tw-1.ac.laowanxiang.com
///     port: 153
///     uuid: 46dd0dd3-2cc0-3f55-907c-d94e54877687
///     alterId: 64
///     cipher: auto udp: true
///     network: ws
///     ws-opts:
///         path: /api/v3/download.getFile
///         headers:
///             Host: 5607b9d187e655736f563fee87d7283994721.laowanxiang.com
///   - name: "ss-simple"
///     type: ss
///     server: 10.0.0.13
///     port: 8388
///     cipher: aes-256-gcm
///     password: "password"
///     udp: true
///   - name: "trojan"
///     type: trojan
///     server: 10.0.0.13 p
///     ort: 9443
///     password: password1
///     udp: true
///     # sni: example.com # aka server name
///     alpn:
///       - h2
///       - http/1.1
///     skip-cert-verify: true
///
/// proxy-providers:
///   file-provider:
///     type: file
///     path: ./ss.yaml
///     interval: 300
///     health-check:
///       enable: true
///       url: http://www.gstatic.com/generate_204
///       interval: 300
///
/// rule-providers:
///   file-provider:
///     type: file
///     path: ./rule-set.yaml
///     interval: 300
///     behavior: domain
///
/// rules:
///   - DOMAIN,ipinfo.io,relay
///   - RULE-SET,file-provider,trojan
///   - GEOIP,CN,relay
///   - DOMAIN-SUFFIX,facebook.com,REJECT
///   - DOMAIN-KEYWORD,google,select
///   - DOMAIN,google.com,select
///   - SRC-IP-CIDR,192.168.1.1/24,DIRECT
///   - GEOIP,CN,DIRECT
///   - DST-PORT,53,trojan
///   - SRC-PORT,7777,DIRECT
///   - MATCH, DIRECT
/// ...
/// ```
#[derive(Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct Config {
    /// The HTTP proxy port
    #[serde(alias = "http_port")]
    pub port: Option<Port>,
    /// The SOCKS5 proxy port
    pub socks_port: Option<Port>,
    /// The redir port
    #[doc(hidden)]
    pub redir_port: Option<Port>,
    pub tproxy_port: Option<Port>,
    /// The HTTP/SOCKS5 mixed proxy port
    /// # Example
    /// ```yaml
    /// mixed-port: 7892
    /// ```
    pub mixed_port: Option<Port>,

    /// HTTP and SOCKS5 proxy authentication
    pub authentication: Vec<String>,
    /// Allow connections from IP addresses other than local listening address
    pub allow_lan: Option<bool>,
    /// The address that the inbound listens on
    /// # Note
    /// - setting this to `*` will listen on all interfaces, which is
    ///   essentially the same as setting it to `0.0.0.0`
    /// - setting this to non local IP will enable `allow_lan` automatically
    /// - and if you don't want `allow_lan` to be enabled, you should set this
    ///   to `localhost` or `127.1`
    pub bind_address: BindAddress,
    /// Clash router working mode
    /// Either `rule`, `global` or `direct`
    pub mode: RunMode,
    /// Log level
    /// Either `debug`, `info`, `warning`, `error` or `off`
    pub log_level: LogLevel,
    /// DNS client/server settings
    pub dns: DNS,
    /// Profile settings
    pub profile: Profile,
    /// Proxy settings
    #[serde(rename = "proxies")]
    pub proxy: Option<Vec<OutboundProxyProtocol>>,
    #[serde(rename = "proxy-groups")]
    /// Proxy group settings
    pub proxy_group: Option<Vec<OutboundGroupProtocol>>,
    #[serde(rename = "rules")]
    /// Rule settings
    pub rule: Option<Vec<String>>,
    /// Hosts
    pub hosts: HashMap<String, String>,
    /// Country database path relative to the $CWD
    pub mmdb: Option<String>,
    /// Country database download url
    pub mmdb_download_url: Option<String>,
    /// Optional ASN database path relative to the working dir
    pub asn_mmdb: Option<String>,
    /// Optional ASN database download url
    pub asn_mmdb_download_url: Option<String>,
    /// Geosite database path relative to the $CWD
    pub geosite: Option<String>,
    /// Geosite database download url
    pub geosite_download_url: Option<String>,

    // these options has default vals,
    // and needs extra processing
    /// whether your network environment supports IPv6
    /// this will affect the DNS server response to AAAA questions
    /// default is `false`
    pub ipv6: bool,
    /// external controller address
    pub external_controller: Option<String>,

    #[cfg_attr(not(unix), serde(alias = "external-controller-pipe"))]
    #[cfg_attr(unix, serde(alias = "external-controller-unix"))]
    pub external_controller_ipc: Option<String>,
    /// dashboard folder path relative to the $CWD
    pub external_ui: Option<String>,
    /// dashboard download url - when set together with `external-ui`, clash-rs
    /// will automatically download and extract the dashboard archive (zip or
    /// tgz) to the `external-ui` directory if it does not exist or is empty.
    /// Append `#force=true` to force re-download even if the directory already
    /// contains files. To route the download through a specific proxy outbound,
    /// append `#_clash_outbound=<name>` to the URL.
    pub external_ui_url: Option<String>,
    /// external controller secret
    pub secret: Option<String>,
    /// CORS allowed origins
    /// # examples
    /// ```yaml
    /// cors-allow-origins:
    ///   - "https://example.com"
    #[serde(rename = "cors-allow-origins")]
    pub cors_allow_origins: Option<Vec<String>>,
    /// outbound interface name
    /// # Note
    /// - not implemented yet
    pub interface: Option<String>,
    /// fwmark on Linux only
    /// # Note
    /// - traffics originated from clash will be marked with this value
    /// - so you can use this value to match the traffic in iptables to avoid
    ///   traffic loops
    pub routing_mark: Option<u32>,
    #[serde(rename = "proxy-providers")]
    /// proxy provider settings
    pub proxy_provider: Option<HashMap<String, OutboundProxyProviderDef>>,
    #[serde(rename = "rule-providers")]
    /// rule provider settings
    pub rule_provider: Option<HashMap<String, RuleProviderDef>>,
    /// experimental settings, if any
    pub experimental: Option<Experimental>,

    /// tun settings
    /// # Example
    /// ```yaml
    /// tun:
    ///   enable: true
    ///   device-id: "dev://utun1989"
    /// ```
    pub tun: Option<TunConfig>,

    /// Explicit inbound listener definitions. Each entry must have a unique
    /// `name` and `type` (`http`, `socks`, `mixed`, `tproxy`, `redir`,
    /// `tunnel`, `shadowsocks`, `anytls`). Takes precedence over the
    /// top-level port shortcuts when both are present.
    pub listeners: Option<Vec<InboundOpts>>,

    #[serde(rename = "inbound-providers")]
    /// Remote or file-based inbound listener providers. Keyed by provider name.
    pub inbound_provider: Option<HashMap<String, InboundProviderDef>>,
}

impl TryFrom<PathBuf> for Config {
    type Error = Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        let content = std::fs::read_to_string(value)?;
        let config = content.parse::<Config>()?;
        Ok(config)
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut val: Value = serde_yaml::from_str(s).map_err(|e| {
            Error::InvalidConfig(format!(
                "couldn't not parse config content {s}: {e}"
            ))
        })?;

        val.apply_merge().map_err(|e| {
            Error::InvalidConfig(format!(
                "failed to process anchors in config content {s}: {e}"
            ))
        })?;

        serde_yaml::from_value(val).map_err(|e| {
            Error::InvalidConfig(format!("could not parse config content: {e}"))
        })
    }
}

/// Strict-mode parse: deserialize the config and reject any unknown key at any
/// depth (via `serde_ignored`). Ordinary parsing ignores unknown keys since the
/// config structs no longer use `deny_unknown_fields`; `--strict-config` routes
/// through here to opt into rejection.
pub(crate) fn check_unknown_fields(s: &str) -> crate::Result<Config> {
    let mut val: Value = serde_yaml::from_str(s).map_err(|e| {
        Error::InvalidConfig(format!("couldn't parse config content: {e}"))
    })?;
    val.apply_merge().map_err(|e| {
        Error::InvalidConfig(format!(
            "failed to process anchors in config content: {e}"
        ))
    })?;

    let mut unknown: Vec<String> = Vec::new();
    let cfg = serde_ignored::deserialize::<_, _, Config>(val, |path| {
        unknown.push(path.to_string());
    })
    .map_err(|e| {
        Error::InvalidConfig(format!("could not parse config content: {e}"))
    })?;

    if unknown.is_empty() {
        Ok(cfg)
    } else {
        Err(Error::InvalidConfig(format!(
            "unknown field(s) in config: {}; omit --strict-config to suppress this \
             error",
            unknown.join(", ")
        )))
    }
}

/// Listen configuration for DoH (DNS over HTTPS) and DoH3 (DNS over HTTP/3).
/// Both protocols share the same wire format. For DoH3, `hostname` acts as the
/// QUIC SNI value presented to clients.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct DohListenDef {
    /// Address to listen on, e.g. `127.0.0.1:53555`.
    pub addr: String,
    /// Path to the PEM-encoded CA certificate used for TLS.
    pub ca_cert: Option<String>,
    /// Path to the PEM-encoded CA private key used for TLS.
    pub ca_key: Option<String>,
    /// TLS SNI hostname advertised to clients.
    pub hostname: Option<String>,
}

/// Listen configuration for DoT (DNS over TLS).
/// Unlike [`DohListenDef`], DoT does not expose a hostname/SNI override field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct DotListenDef {
    /// Address to listen on, e.g. `127.0.0.1:53554`.
    pub addr: String,
    /// Path to the PEM-encoded CA certificate used for TLS.
    pub ca_cert: Option<String>,
    /// Path to the PEM-encoded CA private key used for TLS.
    pub ca_key: Option<String>,
}

/// Multi-protocol DNS listener definition.
///
/// Used when `dns.listen` is a mapping rather than a plain UDP address string.
/// All fields are optional; only configured protocols will be started.
///
/// # Example
/// ```yaml
/// dns:
///   listen:
///     udp: 127.0.0.1:53
///     tcp: 127.0.0.1:53
///     doh:
///       addr: 127.0.0.1:443
///       ca-cert: /path/to/cert.pem
///       ca-key: /path/to/key.pem
///     dot:
///       addr: 127.0.0.1:853
///       ca-cert: /path/to/cert.pem
///       ca-key: /path/to/key.pem
/// ```
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DnsMultipleListenDef {
    /// Plain UDP listener address, e.g. `127.0.0.1:53`.
    pub udp: Option<String>,
    /// TCP listener address, e.g. `127.0.0.1:53`.
    pub tcp: Option<String>,
    /// DNS-over-HTTPS listener config.
    pub doh: Option<DohListenDef>,
    /// DNS-over-TLS listener config.
    pub dot: Option<DotListenDef>,
    /// DNS-over-HTTP/3 listener config. Uses the same fields as
    /// [`DohListenDef`].
    pub doh3: Option<DohListenDef>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum DNSListen {
    Udp(String),
    Multiple(Box<DnsMultipleListenDef>),
}

/// DNS client/server settings
/// This section is optional. When not present, the DNS server will be disabled
/// and system DNS config will be used # Example
/// ```yaml
/// dns:
///   enable: true
///   ipv6: false # when the false, response to AAAA questions will be empty
///   listen:
///     udp: 127.0.0.1:53553
///     tcp: 127.0.0.1:53553
///     dot:
///       addr: 127.0.0.1:53554
///       hostname: dns.clash
///       ca-cert: dns.crt
///       ca-key: dns.key
///     doh:
///       addr: 127.0.0.1:53555
///       ca-cert: dns.crt
///       ca-key: dns.key
///   # edns-client-subnet:
///   #   ipv4: 1.2.3.0/24
///   #   ipv6: 2001:db8::/56
/// ```

#[derive(Serialize, Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct DNS {
    /// When disabled, system DNS config will be used
    /// All other DNS related options will only be used when this is enabled
    pub enable: bool,
    /// When false, response to AAAA questions will be empty
    pub ipv6: bool,
    /// Whether to use `Config::hosts` when resolving hostnames
    #[educe(Default = true)]
    pub use_hosts: bool,
    /// DNS servers
    pub nameserver: Vec<String>,
    /// Fallback DNS servers
    pub fallback: Vec<String>,
    /// Fallback DNS filter
    pub fallback_filter: FallbackFilter,
    /// DNS server listening address. If not present, the DNS server will be
    /// disabled.
    pub listen: Option<DNSListen>,
    /// Whether to use fake IP addresses
    pub enhanced_mode: DNSMode,
    /// Fake IP addresses pool CIDR
    #[educe(Default = "198.18.0.1/16")]
    pub fake_ip_range: String,
    /// Fake IP addresses filter
    pub fake_ip_filter: Vec<String>,
    /// Default nameservers, used to resolve DoH hostnames
    #[educe(Default = vec![
      String::from("114.114.114.114"),
      String::from("8.8.8.8")]
    )]
    pub default_nameserver: Vec<String>,
    /// Proxy server nameservers, used to resolve proxy server hostnames
    pub proxy_server_nameserver: Vec<String>,
    /// Lookup domains via specific nameservers
    pub nameserver_policy: HashMap<String, String>,
    /// Configure EDNS Client Subnet information to send with upstream queries
    pub edns_client_subnet: Option<EdnsClientSubnet>,
    /// When true, upstream DNS queries from `nameserver`, `fallback` and
    /// `nameserver-policy` clients are dispatched through the rule engine
    /// instead of going DIRECT. `default-nameserver` and
    /// `proxy-server-nameserver` are not affected.
    pub respect_rules: bool,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DNSMode {
    #[default]
    Normal,
    FakeIp,
    RedirHost,
}

#[derive(Serialize, Deserialize, Clone, Educe)]
#[serde(default)]
#[educe(Default)]
pub struct FallbackFilter {
    #[serde(rename = "geoip")]
    #[educe(Default = true)]
    pub geo_ip: bool,

    #[serde(rename = "geoip-code")]
    #[educe(Default = "CN")]
    pub geo_ip_code: String,

    #[serde(rename = "ipcidr")]
    pub ip_cidr: Vec<String>,
    pub domain: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct EdnsClientSubnet {
    /// IPv4 subnet expressed in CIDR notation, e.g. `1.2.3.0/24`
    pub ipv4: Option<String>,
    /// IPv6 subnet expressed in CIDR notation, e.g. `2001:db8::/56`
    pub ipv6: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Experimental {
    /// buffer size for tcp stream bidirectional copy
    pub tcp_buffer_size: Option<usize>,
    /// max entries in the closed-flows ring buffer (default 50, lower saves
    /// RAM)
    pub closed_flows_cap: Option<usize>,
    #[serde(default)]
    pub ignore_resolve_fail: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
pub struct Profile {
    /// Store the `select` results in $CWD/cache.db
    pub store_selected: bool,
    /// persistence fakeip
    #[serde(rename = "store-fake-ip")]
    pub store_fake_ip: bool,
    /// Store smart proxy group statistics and preferences
    #[serde(rename = "store-smart-stats")]
    pub store_smart_stats: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            store_selected: true,
            store_fake_ip: false,
            store_smart_stats: true,
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Copy)]
pub struct Port(pub u16);

impl From<Port> for u16 {
    fn from(val: Port) -> Self {
        val.0
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StrOrNum {
            Str(String),
            Num(u64),
            Other,
        }

        let value = StrOrNum::deserialize(deserializer)?;

        match value {
            StrOrNum::Num(num) => u16::try_from(num)
                .map(Port)
                .map_err(|_| serde::de::Error::custom("Port number out of range")),

            StrOrNum::Str(s) => {
                s.parse::<u16>().map(Port).map_err(serde::de::Error::custom)
            }

            StrOrNum::Other => {
                Err(serde::de::Error::custom("Invalid type for port"))
            }
        }
    }
}

/// Rule provider definition as specified in user config.
///
/// The provider name is taken from the map key, not from within the body.
/// Converted to the internal
/// [`crate::config::internal::config::RuleProviderDef`] during config parsing.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum RuleProviderDef {
    /// Fetch rules from a remote HTTP(S) URL and cache them locally.
    Http(HttpRuleProviderDef),
    /// Load rules from a local file path.
    File(FileRuleProviderDef),
    /// Embed rules directly in the config under a `payload` key.
    Inline(InlineRuleProviderDef),
}

/// HTTP-based rule provider fetched from a remote URL.
///
/// When `path` is absent, a local cache path is automatically derived from
/// the MD5 hash of `url` during config conversion.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct HttpRuleProviderDef {
    /// Remote URL to fetch the rule set from.
    pub url: String,
    /// Refresh interval in seconds. `0` disables automatic refresh.
    #[serde(default)]
    pub interval: u64,
    /// How to interpret the rule entries: `domain`, `ipcidr`, or `classical`.
    pub behavior: RuleSetBehavior,
    /// Local cache path for the downloaded rule set.
    /// Derived from the URL's MD5 hash when absent.
    pub path: Option<String>,
    /// Rule set file format. Defaults to `yaml` when absent.
    pub format: Option<RuleSetFormat>,
    /// Inline rules embedded directly in the config (alias: `payload`).
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

/// File-based rule provider loaded from a local path.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct FileRuleProviderDef {
    /// Path to the rule set file, relative to the working directory.
    pub path: String,
    /// Optional polling interval in seconds. Local files are already
    /// live-reloaded via OS file-system events, so this is only an occasional
    /// fallback; `None` disables polling.
    pub interval: Option<u64>,
    /// How to interpret the rule entries: `domain`, `ipcidr`, or `classical`.
    pub behavior: RuleSetBehavior,
    /// Rule set file format. Defaults to `yaml` when absent.
    pub format: Option<RuleSetFormat>,
    /// Inline rules embedded directly in the config (alias: `payload`).
    #[serde(alias = "payload")]
    pub inline_rules: Option<Vec<String>>,
}

/// Inline rule provider — rules written directly in the config file.
///
/// When `path` is absent, a cache path is derived from the MD5 hash of the
/// provider name during config conversion.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InlineRuleProviderDef {
    /// Optional local cache path. Derived from the provider name's MD5 hash
    /// when absent.
    pub path: Option<String>,
    /// How to interpret the rule entries: `domain`, `ipcidr`, or `classical`.
    pub behavior: RuleSetBehavior,
    /// The inline rules (alias: `payload`).
    #[serde(alias = "payload")]
    pub inline_rules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::config::{
        def::Port,
        internal::proxy::{OutboundGroupProtocol, OutboundProxyProtocol},
    };

    use super::Config;

    #[test]
    fn parse_simple() {
        let cfg = r#"
        port: 9090
        "#;
        let c = cfg.parse::<Config>().expect("should parse");
        assert_eq!(c.port, Some(Port(9090)));
    }

    #[test]
    fn test_str_port() {
        let cfg = r#"
        port: "9090"
        "#;
        let c = cfg.parse::<Config>().expect("should parse");
        assert_eq!(c.port, Some(Port(9090)));
    }

    /// Verify that unknown proxy types (snell, ssr, bare http) now fail at YAML
    /// parse time rather than silently passing and failing later at conversion.
    #[test]
    fn parse_rejects_unknown_proxy_type() {
        let snell = "proxies:\n  - name: x\n    type: snell\n    server: s\n    \
                     port: 1\n    psk: p\n";
        assert!(snell.parse::<Config>().is_err(), "snell should be rejected");

        let ssr = "proxies:\n  - name: x\n    type: ssr\n    server: s\n    port: \
                   1\n    cipher: chacha20-ietf\n    password: p\n    obfs: \
                   plain\n    protocol: origin\n";
        assert!(ssr.parse::<Config>().is_err(), "ssr should be rejected");
    }

    #[test]
    fn parse_ignores_unknown_top_level_field() {
        let cfg = r#"
port: 9090
ports: 8080
"#;
        let parsed = cfg
            .parse::<Config>()
            .expect("unknown top-level fields should be ignored");
        assert_eq!(parsed.port.expect("port should be set"), Port(9090));
    }

    #[test]
    fn parse_ignores_unknown_nested_dns_field() {
        let cfg = r#"
dns:
  enable: true
  nameserver:
    - 8.8.8.8
  nonexistent-field: 198.18.0.1/16
"#;
        let parsed = cfg
            .parse::<Config>()
            .expect("unknown dns fields should be ignored");
        assert!(parsed.dns.enable);
    }

    #[test]
    fn parse_ignores_unknown_field_in_inner_struct() {
        // Unknown key in an inner struct is ignored; known fields still apply.
        let cfg = r#"
dns:
  fallback-filter:
    geoip: false
    some-future-option: 1
"#;
        let parsed = cfg
            .parse::<Config>()
            .expect("unknown inner-struct field should be ignored");
        assert!(!parsed.dns.fallback_filter.geo_ip);
    }

    #[test]
    fn check_unknown_fields_rejects_unknown_inner_struct_field() {
        // ...but strict mode still rejects it, at any depth.
        let cfg = r#"
dns:
  fallback-filter:
    some-future-option: 1
"#;
        assert!(
            super::check_unknown_fields(cfg).is_err(),
            "strict check should reject unknown inner-struct field"
        );
    }

    #[test]
    fn check_unknown_fields_rejects_unknown_top_level() {
        let cfg = r#"
port: 9090
ports: 8080
"#;
        assert!(
            super::check_unknown_fields(cfg).is_err(),
            "strict check should reject unknown top-level field"
        );
    }

    #[test]
    fn check_unknown_fields_rejects_unknown_dns_field() {
        let cfg = r#"
dns:
  enable: true
  nameserver:
    - 8.8.8.8
  nonexistent-field: 198.18.0.1/16
"#;
        assert!(
            super::check_unknown_fields(cfg).is_err(),
            "strict check should reject unknown dns field"
        );
    }

    #[test]
    fn check_unknown_fields_accepts_valid_config() {
        let cfg = r#"
port: 9090
dns:
  enable: true
  nameserver:
    - 8.8.8.8
"#;
        assert!(
            super::check_unknown_fields(cfg).is_ok(),
            "strict check should accept a fully valid config"
        );
    }

    /// Verify multi-protocol DNS listen config parses correctly.
    #[test]
    fn parse_dns_multiple_listen() {
        let cfg = r#"
dns:
  enable: true
  listen:
    udp: 127.0.0.1:53
    tcp: 127.0.0.1:53
    doh:
      addr: 127.0.0.1:443
      ca-cert: cert.pem
      ca-key: key.pem
      hostname: dns.example.com
    dot:
      addr: 127.0.0.1:853
      ca-cert: cert.pem
      ca-key: key.pem
    doh3:
      addr: 127.0.0.1:8443
      ca-cert: cert.pem
      ca-key: key.pem
  nameserver:
    - 8.8.8.8
"#;
        use crate::config::def::DNSListen;
        let c = cfg.parse::<Config>().expect("should parse");
        let listen = c.dns.listen.expect("listen should be set");
        if let DNSListen::Multiple(m) = listen {
            assert_eq!(m.udp.as_deref(), Some("127.0.0.1:53"));
            assert_eq!(m.tcp.as_deref(), Some("127.0.0.1:53"));
            let doh = m.doh.as_ref().expect("doh should be set");
            assert_eq!(doh.addr, "127.0.0.1:443");
            assert_eq!(doh.hostname.as_deref(), Some("dns.example.com"));
            let dot = m.dot.as_ref().expect("dot should be set");
            assert_eq!(dot.addr, "127.0.0.1:853");
            let doh3 = m.doh3.as_ref().expect("doh3 should be set");
            assert_eq!(doh3.addr, "127.0.0.1:8443");
        } else {
            panic!("expected Multiple DNS listen");
        }
    }

    /// Verify rule-providers with all three types parse correctly.
    #[test]
    fn parse_rule_providers() {
        use crate::config::def::RuleProviderDef;
        let cfg = r#"
rule-providers:
  http-rules:
    type: http
    url: "https://example.com/rules.yaml"
    interval: 3600
    behavior: domain
  file-rules:
    type: file
    path: ./rules.yaml
    behavior: ipcidr
  inline-rules:
    type: inline
    behavior: classical
    payload:
      - "DOMAIN,example.com"
"#;
        let c = cfg.parse::<Config>().expect("should parse");
        let providers = c.rule_provider.expect("rule_provider should be set");
        assert_eq!(providers.len(), 3);
        assert!(matches!(providers["http-rules"], RuleProviderDef::Http(_)));
        assert!(matches!(providers["file-rules"], RuleProviderDef::File(_)));
        assert!(matches!(
            providers["inline-rules"],
            RuleProviderDef::Inline(_)
        ));
        if let RuleProviderDef::Http(h) = &providers["http-rules"] {
            assert_eq!(h.url, "https://example.com/rules.yaml");
            assert_eq!(h.interval, 3600);
        }
        if let RuleProviderDef::Inline(i) = &providers["inline-rules"] {
            assert_eq!(i.inline_rules.len(), 1);
        }
    }

    #[test]
    fn parse_example() {
        let example_cfg = r###"
# Port of HTTP(S) proxy server on the local end
port: 7890

# Port of SOCKS5 proxy server on the local end
socks-port: 7891

allow-lan: false

tun:
  enable: true
  stack: system
  device-id: dev://clash0

bind-address: '*'
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090
external-ui: folder
interface: en0
routing-mark: 6666

hosts: {}

profile:
  store-selected: false
  store-fake-ip: true

dns:
  enable: false
  listen: 0.0.0.0:53
  default-nameserver:
    - 114.114.114.114
    - 8.8.8.8
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 114.114.114.114
    - 8.8.8.8
    - tls://dns.rubyfish.cn:853
    - https://1.1.1.1/dns-query
    - dhcp://en0

proxies:
  # Shadowsocks (feature-gated)
  - name: "ss1"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"

  - name: "ss2"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    plugin: obfs
    plugin-opts:
      mode: tls

  - name: "ss3"
    type: ss
    server: server
    port: 443
    cipher: chacha20-ietf-poly1305
    password: "password"
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket

  # vmess
  - name: "vmess"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto

  - name: "vmess-h2"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto
    network: h2
    tls: true
    h2-opts:
      host:
        - http.example.com
        - http-alt.example.com
      path: /

  - name: "vmess-http"
    type: vmess
    server: server
    port: 443
    uuid: uuid
    alterId: 32
    cipher: auto

  - name: vmess-grpc
    server: server
    port: 443
    type: vmess
    uuid: uuid
    alterId: 32
    cipher: auto
    network: grpc
    tls: true
    servername: example.com
    grpc-opts:
      grpc-service-name: "example"

  # socks5
  - name: "socks"
    type: socks5
    server: server
    port: 443
    username: user
    password: pass
    udp: true

  # Trojan
  - name: "trojan"
    type: trojan
    server: server
    port: 443
    password: yourpsk
    alpn:
      - h2
      - http/1.1
    skip-cert-verify: true

  - name: trojan-grpc
    server: server
    port: 443
    type: trojan
    password: "example"
    network: grpc
    sni: example.com
    udp: true
    grpc-opts:
      grpc-service-name: "example"

  - name: trojan-ws
    server: server
    port: 443
    type: trojan
    password: "example"
    network: ws
    sni: example.com
    udp: true
    ws-opts:
      path: /path
      headers:
        Host: example.com

  # vless
  - name: "vless"
    type: vless
    server: server
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vless

  # anytls
  - name: "anytls"
    type: anytls
    server: server
    port: 443
    password: "anytls-password"
    sni: example.com
    skip-cert-verify: true

  # hysteria2
  - name: "hy2"
    type: hysteria2
    server: server
    port: 443
    password: "hy2-password"
    skip-cert-verify: true
    up: 100
    down: 200

proxy-groups:
  - name: "relay"
    type: relay
    proxies:
      - vmess
      - ss1
      - ss2

  - name: "auto"
    type: url-test
    proxies:
      - ss1
      - ss2
      - vmess
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
    tolerance: 150
    lazy: true

  - name: "fallback-auto"
    type: fallback
    proxies:
      - ss1
      - ss2
      - vmess
    url: 'http://www.gstatic.com/generate_204'
    interval: 300

  - name: "load-balance"
    type: load-balance
    proxies:
      - ss1
      - ss2
      - vmess
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
    strategy: round-robin

  - name: "smart"
    type: smart
    proxies:
      - vmess
      - ss1
    url: http://www.gstatic.com/generate_204

  - name: Proxy
    type: select
    proxies:
      - ss1
      - ss2
      - vmess
      - auto

  - name: en1
    type: select
    proxies:
      - DIRECT

  - name: UseProvider
    type: select
    use:
      - provider1
    proxies:
      - Proxy
      - DIRECT

proxy-providers:
  provider1:
    type: http
    url: "url"
    interval: 3600
    path: ./provider1.yaml
    health-check:
      enable: true
      interval: 600
      url: http://www.gstatic.com/generate_204
  test:
    type: file
    path: /test.yaml
    health-check:
      enable: true
      interval: 36000
      url: http://www.gstatic.com/generate_204

rules:
  - DOMAIN-SUFFIX,google.com,auto
  - DOMAIN-KEYWORD,google,auto
  - DOMAIN,google.com,auto
  - DOMAIN-SUFFIX,ad.com,REJECT
  - SRC-IP-CIDR,192.168.1.201/32,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - GEOIP,CN,DIRECT
  - DST-PORT,80,DIRECT
  - SRC-PORT,7777,DIRECT
  - MATCH,auto
  "###;

        let des: Config =
            serde_yaml::from_str(example_cfg).expect("should parse yaml");
        assert_eq!(des.port.expect("invalid port"), Port(7890));
        assert_eq!(des.dns.fallback_filter.geo_ip_code, String::from("CN"));

        let proxies = des.proxy.as_ref().expect("proxies should be set");
        // 3 ss entries only counted when the shadowsocks feature is enabled
        #[cfg(feature = "shadowsocks")]
        assert_eq!(proxies.len(), 14);
        #[cfg(not(feature = "shadowsocks"))]
        assert_eq!(proxies.len(), 11);

        // vless parses with correct name
        let vless = proxies
            .iter()
            .find(|p| matches!(p, OutboundProxyProtocol::Vless(_)))
            .expect("vless proxy should be present");
        if let OutboundProxyProtocol::Vless(v) = vless {
            assert_eq!(v.common_opts.name, "vless");
            assert_eq!(v.tls, Some(true));
        }

        // anytls parses with correct name and password
        let anytls = proxies
            .iter()
            .find(|p| matches!(p, OutboundProxyProtocol::Anytls(_)))
            .expect("anytls proxy should be present");
        if let OutboundProxyProtocol::Anytls(a) = anytls {
            assert_eq!(a.common_opts.name, "anytls");
            assert_eq!(a.password, "anytls-password");
        }

        // hysteria2 parses with correct name and password
        let hy2 = proxies
            .iter()
            .find(|p| matches!(p, OutboundProxyProtocol::Hysteria2(_)))
            .expect("hysteria2 proxy should be present");
        if let OutboundProxyProtocol::Hysteria2(h) = hy2 {
            assert_eq!(h.name, "hy2");
            assert_eq!(h.password, "hy2-password");
        }

        #[cfg(feature = "shadowsocks")]
        {
            let proxy2 = &proxies[2];
            if let OutboundProxyProtocol::Ss(ss) = proxy2 {
                assert_eq!(ss.common_opts.name, "ss3");
                assert_eq!(
                    ss.plugin_opts
                        .as_ref()
                        .unwrap()
                        .get("mode")
                        .unwrap()
                        .as_str(),
                    Some("websocket")
                );
            } else {
                panic!("expected Ss proxy at index 2");
            }
        }

        // Verify all proxy group types parse
        let groups = des
            .proxy_group
            .as_ref()
            .expect("proxy-groups should be set");
        assert!(
            groups
                .iter()
                .any(|g| matches!(g, OutboundGroupProtocol::Relay(_))),
            "relay group missing"
        );
        assert!(
            groups
                .iter()
                .any(|g| matches!(g, OutboundGroupProtocol::UrlTest(_))),
            "url-test group missing"
        );
        assert!(
            groups
                .iter()
                .any(|g| matches!(g, OutboundGroupProtocol::Fallback(_))),
            "fallback group missing"
        );
        assert!(
            groups
                .iter()
                .any(|g| matches!(g, OutboundGroupProtocol::LoadBalance(_))),
            "load-balance group missing"
        );
        assert!(
            groups
                .iter()
                .any(|g| matches!(g, OutboundGroupProtocol::Smart(_))),
            "smart group missing"
        );
        assert!(
            groups
                .iter()
                .any(|g| matches!(g, OutboundGroupProtocol::Select(_))),
            "select group missing"
        );

        // Verify load-balance strategy field
        let lb = groups
            .iter()
            .find(|g| matches!(g, OutboundGroupProtocol::LoadBalance(_)))
            .unwrap();
        if let OutboundGroupProtocol::LoadBalance(l) = lb {
            use crate::config::internal::proxy::LoadBalanceStrategy;
            assert!(matches!(l.strategy, Some(LoadBalanceStrategy::RoundRobin)));
        }

        // Verify url-test tolerance and lazy fields
        let ut = groups
            .iter()
            .find(|g| matches!(g, OutboundGroupProtocol::UrlTest(_)))
            .unwrap();
        if let OutboundGroupProtocol::UrlTest(u) = ut {
            assert_eq!(u.tolerance, Some(150));
            assert_eq!(u.lazy, Some(true));
        }

        // Verify proxy providers
        let providers = des.proxy_provider.expect("proxy-providers should be set");
        assert_eq!(providers.len(), 2);
        assert!(providers.contains_key("provider1"));
        assert!(providers.contains_key("test"));
    }

    /// Feature-gated tests for TUIC proxy type parsing.
    #[cfg(feature = "tuic")]
    #[test]
    fn parse_tuic_proxy() {
        let cfg = r#"
proxies:
  - name: "tuic"
    type: tuic
    server: server
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    password: "tuic-password"
    alpn:
      - h3
    skip-cert-verify: true
    udp-relay-mode: native
    congestion-controller: bbr
"#;
        let c = cfg.parse::<Config>().expect("should parse tuic");
        let proxies = c.proxy.unwrap();
        assert_eq!(proxies.len(), 1);
        if let OutboundProxyProtocol::Tuic(t) = &proxies[0] {
            assert_eq!(t.common_opts.name, "tuic");
            assert_eq!(t.password, "tuic-password");
            assert_eq!(t.udp_relay_mode.as_deref(), Some("native"));
        } else {
            panic!("expected tuic proxy");
        }
    }

    /// Feature-gated tests for WireGuard proxy type parsing.
    #[cfg(feature = "wireguard")]
    #[test]
    fn parse_wireguard_proxy() {
        let cfg = r#"
proxies:
  - name: "wg"
    type: wireguard
    server: server
    port: 51820
    private-key: "base64privatekey"
    public-key: "base64publickey"
    ip: 10.0.0.2
    dns:
      - 1.1.1.1
"#;
        let c = cfg.parse::<Config>().expect("should parse wireguard");
        let proxies = c.proxy.unwrap();
        assert_eq!(proxies.len(), 1);
        if let OutboundProxyProtocol::Wireguard(w) = &proxies[0] {
            assert_eq!(w.common_opts.name, "wg");
            assert_eq!(w.ip, "10.0.0.2");
        } else {
            panic!("expected wireguard proxy");
        }
    }

    /// Feature-gated tests for SSH proxy type parsing.
    #[cfg(feature = "ssh")]
    #[test]
    fn parse_ssh_proxy() {
        let cfg = r#"
proxies:
  - name: "ssh"
    type: ssh
    server: server
    port: 22
    username: user
    password: "ssh-pass"
"#;
        let c = cfg.parse::<Config>().expect("should parse ssh");
        let proxies = c.proxy.unwrap();
        assert_eq!(proxies.len(), 1);
        if let OutboundProxyProtocol::Ssh(s) = &proxies[0] {
            assert_eq!(s.common_opts.name, "ssh");
            assert_eq!(s.username, "user");
        } else {
            panic!("expected ssh proxy");
        }
    }
}
