use std::net::IpAddr;

use crate::{
    app::net::Interface,
    config::{
        config::{BindAddress, Controller, General},
        def,
    },
};

pub(super) fn convert(c: &def::Config) -> Result<General, crate::Error> {
    let bind_address = if c.bind_address == BindAddress::default() && c.ipv6 {
        BindAddress::dual_stack()
    } else {
        c.bind_address
    };
    Ok(General {
        authentication: c.authentication.clone(),
        controller: Controller {
            #[cfg(windows)]
            pipe_sddl: None,
            external_controller: c.external_controller.clone(),
            external_ui: c.external_ui.clone(),
            external_ui_download_url: c.external_ui_url.clone(),
            secret: c.secret.clone(),
            cors_allow_origins: c.cors_allow_origins.clone(),
            external_controller_ipc: c.external_controller_ipc.clone(),
        },
        mode: c.mode,
        log_level: c.log_level,
        unified_delay: c.unified_delay,
        ipv6: c.ipv6,
        interface: c.interface.as_ref().map(|iface| {
            if let Ok(addr) = iface.parse::<IpAddr>() {
                Interface::IpAddr(addr)
            } else {
                Interface::Name(iface.to_string())
            }
        }),
        routing_mask: c.routing_mark,
        mmdb: c.mmdb.to_owned(),
        mmdb_download_url: c.mmdb_download_url.to_owned(),
        asn_mmdb: c.asn_mmdb.to_owned(),
        asn_mmdb_download_url: c.asn_mmdb_download_url.to_owned(),
        geosite: c.geosite.to_owned(),
        geosite_download_url: c.geosite_download_url.to_owned(),
        bind_address,
    })
}
