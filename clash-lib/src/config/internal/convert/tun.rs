use crate::{
    Error,
    config::{config, def},
};

pub fn convert(
    before: Option<def::TunConfig>,
) -> Result<config::TunConfig, crate::Error> {
    match before {
        Some(t) => Ok(config::TunConfig {
            enable: t.enable,
            device_id: t.device_id,
            route_all: t.route_all,
            routes: t
                .routes
                .map(|r| {
                    r.into_iter()
                        .map(|x| x.parse())
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()
                .map_err(|x| Error::InvalidConfig(format!("parse tun routes: {x}")))?
                .unwrap_or_default(),
            gateway: t.gateway.parse().map_err(|x| {
                Error::InvalidConfig(format!("parse tun gateway: {x}"))
            })?,
            gateway_v6: t
                .gateway_v6
                .map(|x| {
                    x.parse().map_err(|x| {
                        Error::InvalidConfig(format!("parse tun gateway_v6: {x}"))
                    })
                })
                .transpose()?,
            mtu: t.mtu,
            so_mark: t.so_mark,
            route_table: t.route_table,
            dns_hijack: match t.dns_hijack {
                def::DnsHijack::Switch(b) => b,
                def::DnsHijack::List(_) => true,
            },
            stack: t.stack,
        }),
        None => Ok(config::TunConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use crate::config::def::{TunConfig, TunStack};

    #[test]
    fn tun_stack_parses_and_converts_names_and_aliases() {
        for (yaml, expected) in [
            ("enable: true", TunStack::Smoltcp),
            ("enable: true\nstack: smoltcp", TunStack::Smoltcp),
            ("enable: true\nstack: gvisor", TunStack::Smoltcp),
            ("enable: true\nstack: system", TunStack::System),
            ("enable: true\nstack: mixed", TunStack::System),
        ] {
            let parsed: TunConfig = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(parsed.stack, expected, "parse: {yaml}");
            let converted = super::convert(Some(parsed)).unwrap();
            assert_eq!(converted.stack, expected, "convert: {yaml}");
        }
    }

    #[test]
    fn absent_tun_config_defaults_to_smoltcp() {
        assert_eq!(super::convert(None).unwrap().stack, TunStack::Smoltcp);
    }
}
