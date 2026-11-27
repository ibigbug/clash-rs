//! Opening the TUN device named by `tun.device-id`.
//!
//! Two sources are supported:
//! * `fd://N` — an already-open descriptor (Unix only; this is the only option
//!   on Android/iOS/tvOS, where the VPN service hands the fd over);
//! * `dev://NAME`, or a bare `NAME` — a named interface. It is reused when it
//!   already exists; otherwise it is created and set up (addresses, routes).

use url::Url;

use crate::{Error, config::config::TunConfig};

/// Where the TUN device comes from, parsed from `tun.device-id`.
#[derive(Debug, PartialEq, Eq)]
enum DeviceSource {
    Fd(u32),
    Named(NamedDevice),
}

#[derive(Debug, PartialEq, Eq)]
struct NamedDevice {
    name: String,
    /// Wintun adapter GUID, from `dev://NAME?guid=...`.
    #[cfg(target_os = "windows")]
    guid: Option<u128>,
}

impl DeviceSource {
    fn parse(device_id: &str) -> Result<Self, Error> {
        let source = match Url::parse(device_id) {
            // Not a URL: the whole string is the interface name.
            Err(_) => Self::Named(NamedDevice {
                name: device_id.to_owned(),
                #[cfg(target_os = "windows")]
                guid: None,
            }),
            Ok(url) => {
                let host =
                    url.host_str().filter(|h| !h.is_empty()).ok_or_else(|| {
                        Error::InvalidConfig(format!(
                            "invalid device id: {device_id}. missing fd or device \
                             name"
                        ))
                    })?;
                match url.scheme() {
                    "fd" => {
                        Self::Fd(host.parse().map_err(|e| {
                            Error::InvalidConfig(format!("tun fd {e}"))
                        })?)
                    }
                    "dev" => Self::Named(NamedDevice {
                        name: host.to_owned(),
                        #[cfg(target_os = "windows")]
                        guid: parse_guid(&url)?,
                    }),
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "invalid device id: {device_id}"
                        )));
                    }
                }
            }
        };

        if let Self::Named(dev) = &source
            && cfg!(target_os = "macos")
            && !dev.name.starts_with("utun")
        {
            return Err(Error::InvalidConfig(format!(
                "invalid device id: {device_id}. tun name must be utunX"
            )));
        }
        Ok(source)
    }
}

#[cfg(target_os = "windows")]
fn parse_guid(url: &Url) -> Result<Option<u128>, Error> {
    url.query_pairs()
        .find(|(k, _)| k == "guid")
        .map(|(_, v)| {
            uuid::Uuid::parse_str(&v)
                .map(|g| g.as_u128())
                .map_err(|e| Error::InvalidConfig(format!("invalid guid: {e}")))
        })
        .transpose()
}

/// Open (or create and set up) the TUN device configured in `cfg`.
pub(super) async fn open_device(
    cfg: &TunConfig,
) -> Result<tun_rs::AsyncDevice, Error> {
    match DeviceSource::parse(&cfg.device_id)? {
        DeviceSource::Fd(fd) => open_fd(fd),
        DeviceSource::Named(dev) => open_named(cfg, &dev).await,
    }
}

#[cfg(unix)]
fn open_fd(fd: u32) -> Result<tun_rs::AsyncDevice, Error> {
    tracing::info!("tun started with fd {}", fd);
    // SAFETY: the fd comes from the configuration, whose owner (typically
    // the platform VPN service) hands it over to us for the device lifetime.
    Ok(unsafe { tun_rs::AsyncDevice::from_fd(fd as _)? })
}

#[cfg(not(unix))]
fn open_fd(fd: u32) -> Result<tun_rs::AsyncDevice, Error> {
    Err(Error::InvalidConfig(format!(
        "tun fd({fd}) is only supported on Unix-like systems"
    )))
}

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))]
async fn open_named(
    _cfg: &TunConfig,
    _dev: &NamedDevice,
) -> Result<tun_rs::AsyncDevice, Error> {
    Err(Error::InvalidConfig(
        "only fd is supported on mobile platforms".to_string(),
    ))
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "android")))]
use desktop::open_named;

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "android")))]
mod desktop {
    use std::time::Duration;

    use network_interface::{NetworkInterface, NetworkInterfaceConfig};
    use tracing::{debug, info};
    use tun_rs::DeviceBuilder;

    use super::NamedDevice;
    use crate::{
        Error, config::config::TunConfig, proxy::tun::routes::maybe_add_routes,
    };

    /// Reuse the interface if it exists; otherwise create it, wait for the OS
    /// to list it, and add the configured routes.
    pub(super) async fn open_named(
        cfg: &TunConfig,
        dev: &NamedDevice,
    ) -> Result<tun_rs::AsyncDevice, Error> {
        let name = dev.name.as_str();

        if interface_exists(name).unwrap_or_default() {
            info!("tun device {} already exists, using it.", name);
            let device = builder(cfg, dev, false).build_async()?;
            info!("skipping route setup for existing tun {}", name);
            return Ok(device);
        }

        info!("tun device {} does not exist, creating.", name);
        // Declared before the device so that, on an error below, the device
        // is closed first and the interface destroyed after it.
        let created = CreatedInterface::create(name)?;
        let device = builder(cfg, dev, true).build_async()?;
        wait_until_visible(name).await?;
        info!("setting up routes for tun {}", name);
        maybe_add_routes(cfg, name)?;
        created.keep();
        Ok(device)
    }

    /// Builder for `dev`. Addresses are only assigned to an interface we
    /// create; an existing one keeps its addresses. The MTU (`tun.mtu` or the
    /// platform default) is applied in both cases, as it always has been.
    fn builder(
        cfg: &TunConfig,
        dev: &NamedDevice,
        assign_addresses: bool,
    ) -> DeviceBuilder {
        let default_mtu = if cfg!(windows) { 65535 } else { 1500 };
        let mut builder = DeviceBuilder::new()
            .name(&dev.name)
            .mtu(cfg.mtu.unwrap_or(default_mtu));

        if assign_addresses {
            debug!("setting tun ipv4 addr: {:?}", cfg.gateway);
            builder = builder.ipv4(cfg.gateway.addr(), cfg.gateway.netmask(), None);
            if let Some(gateway_v6) = cfg.gateway_v6 {
                debug!("setting tun ipv6 addr: {:?}", gateway_v6);
                builder = builder.ipv6(gateway_v6.addr(), gateway_v6.netmask());
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Use the configured GUID, or derive a deterministic one from the
            // name so the same adapter is reused across restarts instead of
            // a new one being created every time.
            let guid = dev.guid.unwrap_or_else(|| {
                uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, dev.name.as_bytes())
                    .as_u128()
            });
            builder = builder.device_guid(guid);
        }

        builder
    }

    fn interface_exists(name: &str) -> Result<bool, String> {
        NetworkInterface::show()
            .map(|ifs| ifs.iter().any(|i| i.name == name))
            .map_err(|e| e.to_string())
    }

    /// A freshly created interface may not be listed by the OS right away;
    /// routes can only be added once it is.
    async fn wait_until_visible(name: &str) -> Result<(), Error> {
        const ATTEMPTS: u32 = 40;
        const INTERVAL: Duration = Duration::from_millis(50);

        let mut last_err = None;
        for attempt in 1..=ATTEMPTS {
            match interface_exists(name) {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(e) => last_err = Some(e),
            }
            if attempt < ATTEMPTS {
                tokio::time::sleep(INTERVAL).await;
            }
        }

        let mut msg = format!(
            "tun device {} not visible after waiting {}ms",
            name,
            (INTERVAL * ATTEMPTS).as_millis()
        );
        if let Some(e) = last_err {
            msg.push_str(&format!(" (last error: {e})"));
        }
        Err(Error::Operation(msg))
    }

    /// FreeBSD materialises `/dev/<name>` only while the interface exists,
    /// and tun-rs opens that node without creating the interface, so it is
    /// created up front. If setup fails before [`CreatedInterface::keep`],
    /// the guard destroys it again so no dangling interface is left behind.
    #[cfg(target_os = "freebsd")]
    struct CreatedInterface<'a>(Option<&'a str>);

    #[cfg(target_os = "freebsd")]
    impl<'a> CreatedInterface<'a> {
        fn create(name: &'a str) -> Result<Self, Error> {
            crate::proxy::tun::routes::ensure_tun_device(name)?;
            Ok(Self(Some(name)))
        }

        fn keep(mut self) {
            self.0 = None;
        }
    }

    #[cfg(target_os = "freebsd")]
    impl Drop for CreatedInterface<'_> {
        fn drop(&mut self) {
            if let Some(name) = self.0 {
                let _ = std::process::Command::new("ifconfig")
                    .arg(name)
                    .arg("destroy")
                    .output();
            }
        }
    }

    /// Other platforms create the interface as part of opening the device.
    #[cfg(not(target_os = "freebsd"))]
    struct CreatedInterface;

    #[cfg(not(target_os = "freebsd"))]
    impl CreatedInterface {
        fn create(_name: &str) -> Result<Self, Error> {
            Ok(Self)
        }

        fn keep(self) {}
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceSource, NamedDevice};

    fn named(name: &str) -> DeviceSource {
        DeviceSource::Named(NamedDevice {
            name: name.to_owned(),
            #[cfg(target_os = "windows")]
            guid: None,
        })
    }

    #[test]
    fn parses_fd() {
        assert_eq!(DeviceSource::parse("fd://3").unwrap(), DeviceSource::Fd(3));
        assert!(DeviceSource::parse("fd://abc").is_err());
    }

    #[test]
    fn rejects_unknown_scheme_and_missing_host() {
        assert!(DeviceSource::parse("tcp://tun0").is_err());
        // Used to try (and fail) to create a nameless interface.
        assert!(DeviceSource::parse("dev://").is_err());
        assert!(DeviceSource::parse("fd://").is_err());
        // No authority at all: used to panic on `host().expect(..)`.
        assert!(DeviceSource::parse("fd:3").is_err());
        assert!(DeviceSource::parse("dev:tun0").is_err());
        assert!(DeviceSource::parse("dev:").is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn parses_named() {
        assert_eq!(DeviceSource::parse("dev://tun0").unwrap(), named("tun0"));
        assert_eq!(DeviceSource::parse("tun0").unwrap(), named("tun0"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_requires_utun() {
        assert_eq!(DeviceSource::parse("dev://utun9").unwrap(), named("utun9"));
        assert_eq!(DeviceSource::parse("utun9").unwrap(), named("utun9"));
        assert!(DeviceSource::parse("dev://tun0").is_err());
        assert!(DeviceSource::parse("tun0").is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn parses_windows_guid() {
        let DeviceSource::Named(dev) = DeviceSource::parse(
            "dev://clash?guid=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        )
        .unwrap() else {
            panic!("expected a named device");
        };
        assert_eq!(dev.name, "clash");
        assert!(dev.guid.is_some());
        assert!(DeviceSource::parse("dev://clash?guid=nope").is_err());
    }
}
