mod datagram;

use datagram::TailscaleDatagramOutbound;

use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use erased_serde::Serialize as ErasedSerialize;
use tailscale::config::{BadFormatBehavior, load_key_file};
use tokio::sync::Mutex;

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream,
            InstrumentedDatagram, InstrumentedDatagramWrapper, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::map_io_error,
    session::{Session, SocksAddr},
};

use super::{
    ConnectorType, DialWithConnector, OutboundHandler, OutboundType,
    PlainProxyAPIResponse,
};

const TAILSCALE_CLIENT_NAME: &str = "clash-rs";
const TAILSCALE_STATE_FILE_NAME: &str = "tailscale_state.json";
/// Upper bound on waiting for the first netmap when looking up a peer name.
const PEER_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Resolve `host` against the tailnet's peers, standing in for MagicDNS.
///
/// tailscale-rs has no MagicDNS resolver at 100.100.100.100, and the regular
/// DNS resolver doesn't know tailnet names, so peer hostnames (`nas`) and
/// FQDNs (`nas.tailnet.ts.net`) are looked up in the netmap instead. Other
/// names are skipped, since the lookup waits for the first netmap. Returns
/// `None` for names that aren't tailnet peers, so the caller can fall back to
/// the regular resolver.
pub(crate) async fn resolve_peer(
    device: &::tailscale::Device,
    host: &str,
) -> Option<IpAddr> {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    if !is_tailnet_name(&name) {
        return None;
    }
    match tokio::time::timeout(PEER_LOOKUP_TIMEOUT, device.peer_by_name(&name)).await
    {
        Ok(Ok(Some(node))) => {
            let v4 = node.tailnet_address.ipv4.addr();
            let v6 = node.tailnet_address.ipv6.addr();
            if !v4.is_unspecified() {
                Some(IpAddr::V4(v4))
            } else if !v6.is_unspecified() {
                Some(IpAddr::V6(v6))
            } else {
                None
            }
        }
        Ok(Ok(None)) => None,
        Ok(Err(e)) => {
            tracing::warn!("tailscale peer lookup for {name} failed: {e}");
            None
        }
        Err(_) => {
            tracing::warn!("tailscale peer lookup for {name} timed out");
            None
        }
    }
}

/// Whether a normalized (lowercase, no trailing dot) name can be a tailnet
/// peer: a bare hostname or a MagicDNS FQDN under `.ts.net`.
fn is_tailnet_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(':')
        && (!name.contains('.') || name.ends_with(".ts.net"))
}

#[derive(Clone)]
pub struct HandlerOptions {
    pub name: String,
    pub state_dir: Option<String>,
    pub auth_key: Option<String>,
    pub hostname: Option<String>,
    pub control_url: Option<String>,
    pub client_name: Option<String>,
    pub ephemeral: bool,
}

pub struct Handler {
    opts: HandlerOptions,
    device: Mutex<Option<Arc<::tailscale::Device>>>,
    /// Runtime state for the API, readable without waiting on `device`.
    status: Arc<StatusState>,
}

/// What the API reports about the device. Kept apart from `device`: that lock
/// is taken by every connection, so "can't lock it" says nothing about whether
/// the device is starting.
#[derive(Default)]
struct StatusState {
    /// The device once it has been created.
    device: std::sync::RwLock<Option<Arc<::tailscale::Device>>>,
    /// Set while `get_device` creates the device.
    starting: AtomicBool,
    /// Why the last attempt to create the device failed, until one succeeds.
    last_error: std::sync::Mutex<Option<String>>,
    /// The last answer from the device, refreshed in the background.
    cached: std::sync::Mutex<Option<serde_json::Value>>,
    /// The in-flight refresh, aborted when the handler is dropped (e.g. a
    /// config reload) so a probe still waiting on an unreachable control
    /// server doesn't keep the old device alive.
    probe: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
    /// When the last refresh started; refreshes are at most `REFRESH_INTERVAL`
    /// apart however often the API is polled.
    last_refresh: std::sync::Mutex<Option<std::time::Instant>>,
    /// Whether a background refresh is in flight. At most one is: the
    /// tailscale-rs queries wait for the control server and keep a reply slot
    /// until it answers, so they are never abandoned on a timeout.
    refreshing: AtomicBool,
}

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailscale")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            device: Mutex::new(None),
            status: Arc::default(),
        }
    }

    /// Lazily initialise and return the shared [`tailscale::Device`].
    ///
    /// **State persistence**: when `state_dir` is set the device identity is
    /// loaded from (and automatically written back to) a JSON file so it
    /// survives process restarts.  When `state_dir` is `None` the identity is
    /// held in memory only; the device will register a fresh node on every
    /// startup unless `ephemeral: true` is also set.
    async fn get_device(&self) -> io::Result<Arc<::tailscale::Device>> {
        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(Arc::clone(device));
        }

        // Cleared when this scope ends, including if the connection is dropped
        // (and this future with it) while the device is being created. The
        // outcome is recorded first, so a reader never sees "not starting"
        // without it.
        let _starting = ClearOnDrop::set(&self.status.starting);
        match self.create_device().await {
            Ok(device) => {
                *self.status.last_error.lock().unwrap() = None;
                *self.status.device.write().unwrap() = Some(Arc::clone(&device));
                *guard = Some(Arc::clone(&device));
                Ok(device)
            }
            Err(e) => {
                *self.status.last_error.lock().unwrap() =
                    Some(redact_urls(&e.to_string()));
                Err(e)
            }
        }
    }

    async fn create_device(&self) -> io::Result<Arc<::tailscale::Device>> {
        let key_state = if self.opts.ephemeral {
            Default::default()
        } else if let Some(state_dir) = self.opts.state_dir.as_ref() {
            // load_key_file reads persisted key material so the device keeps
            // the same Tailscale identity across restarts.  The tailscale-rs
            // crate writes updated state back to the file automatically while
            // the Device is alive; no explicit save step is required.
            let state_file =
                PathBuf::from(state_dir).join(TAILSCALE_STATE_FILE_NAME);
            load_key_file(state_file, BadFormatBehavior::Error)
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to initialize tailscale key state: {e}"
                    ))
                })?
        } else {
            // ephemeral: false but no state_dir — identity is in-memory only
            // and will be lost when the process exits.  Log so users are aware.
            tracing::warn!(
                name = %self.opts.name,
                "tailscale: ephemeral is false but no state-dir is configured; \
                 device identity will not be persisted across restarts"
            );
            Default::default()
        };

        let mut config = ::tailscale::Config {
            key_state,
            // Ephemeral nodes are automatically removed from the tailnet
            // when the device disconnects; mirror the outbound option.
            ephemeral: self.opts.ephemeral,
            ..Default::default()
        };
        config.client_name = Some(
            self.opts
                .client_name
                .as_deref()
                .unwrap_or(TAILSCALE_CLIENT_NAME)
                .to_owned(),
        );
        config.requested_hostname = self.opts.hostname.clone();

        if let Some(control_url) = self.opts.control_url.as_ref() {
            config.control_server_url = control_url.parse().map_err(|e| {
                io::Error::other(format!("invalid tailscale control-url: {e}"))
            })?;
        }

        // tailscale-rs requires this env var as an acknowledgement that the
        // crate is experimental.  Set it on behalf of the user so they don't
        // need to configure it themselves.
        // SAFETY: single-threaded point inside a Mutex-guarded lazy-init block;
        // no other thread is reading or writing this variable concurrently.
        unsafe {
            std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");
        }

        Ok(Arc::new(
            ::tailscale::Device::new(&config, self.opts.auth_key.clone())
                .await
                .map_err(|e| {
                    io::Error::other(format!(
                        "failed to initialize tailscale-rs device: {e}"
                    ))
                })?,
        ))
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        if let Some(probe) = self.status.probe.lock().unwrap().take() {
            probe.abort();
        }
    }
}

impl DialWithConnector for Handler {}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Tailscale
    }

    async fn support_udp(&self) -> bool {
        true
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedStream> {
        let device = self.get_device().await?;
        let remote_ip = match &sess.destination {
            SocksAddr::Ip(addr) => addr.ip(),
            SocksAddr::Domain(host, _) => match resolve_peer(&device, host).await {
                Some(ip) => ip,
                None => resolver
                    .resolve(host, false)
                    .await
                    .map_err(map_io_error)?
                    .ok_or_else(|| io::Error::other("no dns result"))?,
            },
        };
        let s = device
            .tcp_connect((remote_ip, sess.destination.port()).into())
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to connect over tailscale-rs to {}:{}: {e}",
                    remote_ip,
                    sess.destination.port()
                ))
            })?;

        let s = InstrumentedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        let device = self.get_device().await?;
        let local_ip: IpAddr = match &sess.destination {
            // Strict: IP literal family must match — fail fast rather than
            // binding wrong family
            SocksAddr::Ip(addr) if addr.is_ipv6() => {
                device.ipv6_addr().await.map(IpAddr::V6).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv6 address for ipv6 \
                         destination: {e}"
                    ))
                })?
            }
            SocksAddr::Ip(_) => {
                device.ipv4_addr().await.map(IpAddr::V4).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale ipv4 address for ipv4 \
                         destination: {e}"
                    ))
                })?
            }
            // Domain destination: v4-first with v6 fallback is appropriate
            SocksAddr::Domain(..) => match device.ipv4_addr().await {
                Ok(ip) => IpAddr::V4(ip),
                Err(_) => device.ipv6_addr().await.map(IpAddr::V6).map_err(|e| {
                    io::Error::other(format!(
                        "failed to fetch tailscale address: {e}"
                    ))
                })?,
            },
        };
        let port = rand::random_range(49152u16..=u16::MAX);
        let udp = device
            .udp_bind((local_ip, port).into())
            .await
            .map_err(|e| {
                io::Error::other(format!(
                    "failed to bind tailscale udp socket on {local_ip}: {e}"
                ))
            })?;

        let d = TailscaleDatagramOutbound::new(udp, device, resolver);
        let d = InstrumentedDatagramWrapper::new(d);
        d.append_to_chain(self.name()).await;
        Ok(Box::new(d))
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
        let mut m = HashMap::new();
        if let Some(state_dir) = &self.opts.state_dir {
            m.insert("state-dir".to_owned(), Box::new(state_dir.clone()) as _);
        }
        if let Some(hostname) = &self.opts.hostname {
            m.insert("hostname".to_owned(), Box::new(hostname.clone()) as _);
        }
        if let Some(control_url) = &self.opts.control_url {
            m.insert("control-url".to_owned(), Box::new(control_url.clone()) as _);
        }
        m.insert(
            "client-name".to_owned(),
            Box::new(
                self.opts
                    .client_name
                    .as_deref()
                    .unwrap_or(TAILSCALE_CLIENT_NAME)
                    .to_owned(),
            ) as _,
        );
        m.insert("ephemeral".to_owned(), Box::new(self.opts.ephemeral) as _);
        m.insert(
            "auth-key-set".to_owned(),
            Box::new(self.opts.auth_key.is_some()) as _,
        );
        // Cached runtime state: reading it never waits on the tailnet.
        m.insert("status".to_owned(), Box::new(self.status()) as _);
        m
    }
}

impl Handler {
    /// Runtime state for the API. Answers immediately and never starts the
    /// device (that happens on the first connection):
    /// - `idle`: not started yet, no connection has used this outbound;
    /// - `starting`: the device is being created;
    /// - `error`: creating it failed (`error` says why);
    /// - `connecting`: created, but the control server hasn't answered yet;
    /// - `needs-login`: the node isn't logged in: without a usable auth key it
    ///   would need an interactive login (whose URL is not exposed, as whoever
    ///   opens it adopts the node into their tailnet), or `reason:
    ///   auth-key-rejected` when the control server refused the auth key;
    /// - `running`: logged in, with the node's tailnet identity.
    ///
    /// The device's answer is cached and refreshed in the background, so
    /// `/proxies` never waits on the tailnet.
    fn status(&self) -> serde_json::Value {
        // Read `starting` first: it is cleared after the device is published,
        // so seeing it false guarantees the device (or error) is visible.
        let starting = self.status.starting.load(Ordering::Acquire);
        let device = self.status.device.read().unwrap().clone();
        let Some(device) = device else {
            if starting {
                return serde_json::json!({ "state": "starting" });
            }
            if let Some(error) = self.status.last_error.lock().unwrap().clone() {
                return serde_json::json!({ "state": "error", "error": error });
            }
            return serde_json::json!({ "state": "idle" });
        };

        self.refresh(device);
        self.status
            .cached
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| serde_json::json!({ "state": "connecting" }))
    }
}

/// Clears an `AtomicBool` when dropped, so a flag set for the length of some
/// work is cleared however the work ends (completion, error, cancellation or
/// panic).
struct ClearOnDrop<'a>(&'a AtomicBool);

impl<'a> ClearOnDrop<'a> {
    fn set(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Release);
        Self(flag)
    }
}

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Minimum time between status refreshes.
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

impl Handler {
    /// Starts a background refresh of the cached status, unless one is in
    /// flight, the last one started under `REFRESH_INTERVAL` ago, or there is
    /// no runtime to run it on.
    fn refresh(&self, device: Arc<::tailscale::Device>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        {
            let mut last = self.status.last_refresh.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < REFRESH_INTERVAL) {
                return;
            }
            if self.status.refreshing.swap(true, Ordering::AcqRel) {
                return;
            }
            *last = Some(std::time::Instant::now());
        }
        let state = Arc::clone(&self.status);
        let task = runtime.spawn(async move {
            // Cleared however the task ends, including when it is aborted.
            let _refreshing = ClearOnDropArc(Arc::clone(&state));
            let previous = state.cached.lock().unwrap().clone();
            let status = probe(&device, previous.as_ref()).await;
            // Log a failure once when it starts, not on every refresh.
            if status["state"] == "error"
                && previous.as_ref().map(|c| &c["state"]) != Some(&status["state"])
            {
                tracing::warn!("tailscale status: control server error");
            }
            *state.cached.lock().unwrap() = Some(status);
        });
        *self.status.probe.lock().unwrap() = Some(task.abort_handle());
    }
}

/// Clears `StatusState::refreshing` when the refresh task ends.
struct ClearOnDropArc(Arc<StatusState>);

impl Drop for ClearOnDropArc {
    fn drop(&mut self) {
        self.0.refreshing.store(false, Ordering::Release);
    }
}

/// Replaces URLs in an error message: tailscale-rs errors can carry the
/// interactive login URL, which must not reach the API.
fn redact_urls(message: &str) -> String {
    static URL: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"https?://\S+").unwrap());
    URL.replace_all(message, "<url>").into_owned()
}

/// Asks the device for its login state and, once logged in, its node. Waits
/// as long as the control server takes; the caller runs one at a time.
async fn probe(
    device: &::tailscale::Device,
    previous: Option<&serde_json::Value>,
) -> serde_json::Value {
    match device.is_authorized().await {
        Ok(::tailscale::AuthState::Authorized) => match device.self_node().await {
            Ok(node) => node_status(
                &node.hostname,
                node.tailnet.as_deref(),
                node.tailnet_address.ipv4.addr(),
                node.tailnet_address.ipv6.addr(),
                node.node_key_expiry,
                node.derp_region.map(|r| r.to_string()),
            ),
            // Keep the identity from the last answer rather than dropping it.
            Err(e) => {
                tracing::debug!("tailscale status: self node unavailable: {e}");
                match previous {
                    Some(p) if p["state"] == "running" => p.clone(),
                    _ => serde_json::json!({ "state": "running" }),
                }
            }
        },
        Ok(::tailscale::AuthState::NotAuthorized(url)) => {
            // Logged for the operator when the state starts (it is a
            // credential, so not on every refresh); never returned by the API.
            if previous.map(|p| &p["state"])
                != Some(&serde_json::json!("needs-login"))
            {
                tracing::info!("tailscale: node needs login, visit {url}");
            }
            serde_json::json!({ "state": "needs-login" })
        }
        Err(::tailscale::Error::AuthKeyRejected) => serde_json::json!({
            "state": "needs-login",
            "reason": "auth-key-rejected",
        }),
        // Control-server errors can carry the login URL, so they are not
        // returned; the refresh logs once that the control server failed.
        Err(e) => {
            tracing::debug!("tailscale status: control server error: {e}");
            serde_json::json!({ "state": "error", "error": "control server error" })
        }
    }
}

/// The `running` status for a node. Unspecified addresses are left out, and so
/// is a key expiry at or before the Unix epoch: the control server sends the
/// zero time ("0001-01-01") for keys that never expire.
fn node_status(
    hostname: &str,
    tailnet: Option<&str>,
    ipv4: std::net::Ipv4Addr,
    ipv6: std::net::Ipv6Addr,
    key_expiry: Option<chrono::DateTime<chrono::Utc>>,
    derp_region: Option<String>,
) -> serde_json::Value {
    let mut status = serde_json::Map::new();
    status.insert("state".into(), "running".into());
    status.insert("hostname".into(), hostname.into());
    if let Some(tailnet) = tailnet {
        status.insert("tailnet".into(), tailnet.into());
    }
    if !ipv4.is_unspecified() {
        status.insert("ipv4".into(), ipv4.to_string().into());
    }
    if !ipv6.is_unspecified() {
        status.insert("ipv6".into(), ipv6.to_string().into());
    }
    if let Some(expiry) = key_expiry.filter(|e| e.timestamp() > 0) {
        status.insert("key-expiry".into(), expiry.to_rfc3339().into());
    }
    if let Some(region) = derp_region {
        status.insert("derp-region".into(), region.into());
    }
    serde_json::Value::Object(status)
}

impl crate::proxy::ProxyStream for ::tailscale::netstack::TcpStream {}

#[cfg(test)]
mod tests {
    use super::{Handler, HandlerOptions};
    use crate::proxy::{OutboundHandler, PlainProxyAPIResponse};

    #[cfg(target_os = "linux")]
    use std::net::SocketAddr;
    #[cfg(target_os = "linux")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(target_os = "linux")]
    use {
        crate::{proxy::datagram::UdpPacket, session::SocksAddr},
        futures::{SinkExt, StreamExt},
    };

    #[cfg(target_os = "linux")]
    const DNS_TEST_TXID: u16 = 0xBEEF;

    #[cfg(target_os = "linux")]
    fn build_dns_query(host: &str, txid: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&txid.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        for label in host.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[test]
    fn tailnet_names_are_hostnames_or_ts_net() {
        assert!(super::is_tailnet_name("nas"));
        assert!(super::is_tailnet_name("nas.tail1234.ts.net"));
        assert!(!super::is_tailnet_name("example.com"));
        assert!(!super::is_tailnet_name("ts.net.example.com"));
        assert!(!super::is_tailnet_name(""));
        assert!(!super::is_tailnet_name("::1"));
    }

    fn handler() -> Handler {
        Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: None,
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: false,
        })
    }

    #[tokio::test]
    async fn status_is_idle_before_the_device_starts() {
        let h = handler();
        // Reading the status must not start the device.
        assert_eq!(h.status(), serde_json::json!({ "state": "idle" }));
        assert!(h.device.lock().await.is_none());

        let map = h.as_map().await;
        let status =
            serde_json::to_value(map.get("status").unwrap().as_ref()).unwrap();
        assert_eq!(status["state"], "idle");
    }

    #[tokio::test]
    async fn status_is_starting_only_while_the_device_is_created() {
        let h = handler();
        // A connection holding the device lock doesn't mean it is starting.
        {
            let _guard = h.device.lock().await;
            assert_eq!(h.status()["state"], "idle");
        }
        h.status
            .starting
            .store(true, std::sync::atomic::Ordering::Release);
        assert_eq!(h.status(), serde_json::json!({ "state": "starting" }));
    }

    #[test]
    fn starting_flag_clears_when_creation_is_cancelled() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        {
            let _starting = super::ClearOnDrop::set(&flag);
            assert!(flag.load(std::sync::atomic::Ordering::Acquire));
            // Dropping the get_device future here, mid-creation, drops the
            // guard.
        }
        assert!(!flag.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn error_messages_never_carry_urls() {
        assert_eq!(
            super::redact_urls(
                "not authorized: visit https://login.tailscale.com/a/abc123 to log \
                 in"
            ),
            "not authorized: visit <url> to log in"
        );
    }

    #[tokio::test]
    async fn status_reports_why_the_device_failed_to_start() {
        let h = handler();
        *h.status.last_error.lock().unwrap() = Some("bad key file".to_owned());
        assert_eq!(
            h.status(),
            serde_json::json!({ "state": "error", "error": "bad key file" })
        );
    }

    #[test]
    fn node_status_maps_identity_and_drops_zero_values() {
        let expiry = chrono::DateTime::parse_from_rfc3339("2027-05-09T04:52:18Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let status = super::node_status(
            "phone",
            Some("tail1234.ts.net"),
            "100.64.0.1".parse().unwrap(),
            std::net::Ipv6Addr::UNSPECIFIED,
            Some(expiry),
            Some("12".to_owned()),
        );
        assert_eq!(
            status,
            serde_json::json!({
                "state": "running",
                "hostname": "phone",
                "tailnet": "tail1234.ts.net",
                "ipv4": "100.64.0.1",
                "key-expiry": "2027-05-09T04:52:18+00:00",
                "derp-region": "12",
            })
        );

        // Keys that never expire come with the zero time.
        let never = chrono::DateTime::parse_from_rfc3339("0001-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let status = super::node_status(
            "phone",
            None,
            "100.64.0.1".parse().unwrap(),
            std::net::Ipv6Addr::UNSPECIFIED,
            Some(never),
            None,
        );
        assert!(status.get("key-expiry").is_none());
    }

    #[tokio::test]
    async fn tailscale_support_udp_is_enabled() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: None,
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: false,
        });
        assert!(h.support_udp().await);
    }

    #[tokio::test]
    async fn tailscale_api_response_redacts_auth_key() {
        let h = Handler::new(HandlerOptions {
            name: "ts".to_owned(),
            state_dir: None,
            auth_key: Some("tskey-auth-xxxx".to_owned()),
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: false,
        });
        let map = h.as_map().await;
        assert!(
            map.contains_key("auth-key-set"),
            "auth-key-set should be present"
        );
        assert!(
            !map.contains_key("auth-key"),
            "raw auth-key must not be present"
        );
    }

    // tailscale-rs's userspace runtime works on Linux only in CI; the macOS
    // GitHub Actions sandbox blocks the control-plane connections it needs.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn tailscale_live_auth_key_supports_real_tcp_and_udp_traffic() {
        crate::setup_default_crypto_provider();

        // Surface tailscale-rs internal logs so CI can show exactly why
        // the control actor fails if the test does not pass.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| {
                        "ts_control=debug,ts_runtime=debug".parse().unwrap()
                    }),
            )
            .try_init();

        let auth_key = match std::env::var("TS_AUTH_KEY") {
            Ok(v) if !v.is_empty() => v,
            _ => return,
        };

        // Homelab services reachable via tailnet subnet router.
        let tcp_addr: SocketAddr = "10.1.0.5:5380".parse().unwrap();
        let udp_addr: SocketAddr = "10.1.0.5:53".parse().unwrap();

        let h = Handler::new(HandlerOptions {
            name: "ts-live-auth".to_owned(),
            state_dir: None,
            auth_key: Some(auth_key),
            hostname: None,
            control_url: None,
            client_name: None,
            ephemeral: true,
        });

        let device = h.get_device().await.expect("tailscale device init failed");

        let addr = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            device.ipv4_addr(),
        )
        .await
        .expect("timed out waiting for tailscale IPv4 address")
        .expect("tailscale device failed to acquire IPv4 address");

        assert!(
            !addr.is_unspecified(),
            "tailscale device returned an unspecified IPv4 address"
        );

        // Wait for subnet routes from the netmap to propagate into the
        // smoltcp routing table. ipv4_addr() resolves as soon as self_node
        // is set, but the RouteUpdater processes routes asynchronously from
        // the same StateUpdate message, so a brief pause is required before
        // packets to subnet IPs (10.1.0.0/24 via the subnet router) can route.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // TCP: connect to homelab server via tailnet subnet router.
        let mut tcp_stream = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            device.tcp_connect(tcp_addr),
        )
        .await
        .expect("timed out connecting tcp over tailscale")
        .expect("tcp connect over tailscale failed");

        let req = "HEAD / HTTP/1.1\r\nHost: 10.1.0.5\r\nConnection: close\r\n\r\n";
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tcp_stream.write_all(req.as_bytes()),
        )
        .await
        .expect("timed out writing tcp request over tailscale")
        .expect("tcp write over tailscale failed");

        tcp_stream.flush().await.ok();

        let mut tcp_resp = [0u8; 256];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            tcp_stream.read(&mut tcp_resp),
        )
        .await
        .expect("timed out reading tcp response over tailscale")
        .expect("tcp read over tailscale failed");

        assert!(n > 0, "expected non-empty tcp response over tailscale");

        // UDP via TailscaleDatagramOutbound: exercise connect_datagram and the
        // Sink/Stream wrappers by sending a real DNS query to the homelab.
        let resolver =
            std::sync::Arc::new(crate::proxy::utils::test_utils::noop::NoopResolver);
        let sess = crate::session::Session {
            destination: SocksAddr::Ip(udp_addr),
            ..Default::default()
        };
        let mut dgram = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            h.connect_datagram(&sess, resolver),
        )
        .await
        .expect("timed out creating tailscale datagram outbound")
        .expect("connect_datagram over tailscale failed");

        let query = build_dns_query("login.tailscale.com", DNS_TEST_TXID);
        let pkt = UdpPacket {
            data: query,
            src_addr: SocksAddr::Ip(std::net::SocketAddr::new(addr.into(), 0)),
            dst_addr: SocksAddr::Ip(udp_addr),
            inbound_user: None,
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), dgram.send(pkt))
            .await
            .expect("timed out sending datagram over tailscale")
            .expect("datagram send over tailscale failed");

        let resp =
            tokio::time::timeout(std::time::Duration::from_secs(20), dgram.next())
                .await
                .expect("timed out receiving datagram over tailscale")
                .expect("datagram stream ended without a response");

        assert!(
            resp.data.len() >= 2,
            "expected non-empty datagram response over tailscale"
        );
        let resp_txid = u16::from_be_bytes([resp.data[0], resp.data[1]]);
        assert_eq!(
            resp_txid, DNS_TEST_TXID,
            "unexpected DNS transaction id in datagram response"
        );
    }
}
