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
            external_controller: c
                .external_controller
                .clone()
                .filter(|addr| !addr.is_empty()),
            external_ui: c.external_ui.clone(),
            external_ui_download_url: c.external_ui_url.clone(),
            secret: c.secret.clone(),
            cors_allow_origins: match &c.external_controller_cors {
                Some(cors) => Some(
                    cors.allow_origins
                        .as_ref()
                        .or(c.cors_allow_origins.as_ref())
                        .cloned()
                        .unwrap_or_default(),
                ),
                None => c.cors_allow_origins.clone(),
            },
            cors_allow_private_network: c
                .external_controller_cors
                .as_ref()
                .is_none_or(|cors| cors.allow_private_network),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_cors_config_precedence() {
        let legacy = "cors-allow-origins: ['https://legacy.example']";
        let origin = vec![String::from("https://legacy.example")];
        for (yaml, origins, private_network) in [
            (String::new(), None, true),
            (legacy.into(), Some(origin.clone()), true),
            (
                format!(
                    "{legacy}\nexternal-controller-cors: {{allow-private-network: \
                     false}}"
                ),
                Some(origin),
                false,
            ),
            (
                format!("{legacy}\nexternal-controller-cors: {{allow-origins: []}}"),
                Some(vec![]),
                true,
            ),
            (
                "external-controller-cors: {allow-private-network: true}".into(),
                Some(vec![]),
                true,
            ),
        ] {
            let config = def::check_unknown_fields(&yaml).unwrap();
            let controller = convert(&config).unwrap().controller;
            assert_eq!(controller.cors_allow_origins, origins, "{yaml}");
            assert_eq!(
                controller.cors_allow_private_network, private_network,
                "{yaml}"
            );
        }
    }
}
