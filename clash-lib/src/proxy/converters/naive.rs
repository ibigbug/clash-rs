use std::{net::IpAddr, path::Path, time::Duration};

use wind_naive::NaiveOutboundOpts;

use crate::{
    Error,
    config::internal::proxy::OutboundNaive,
    proxy::naive::{Handler, HandlerOptions},
};

impl OutboundNaive {
    pub(crate) fn resolve_paths(&mut self, cwd: &Path) {
        for value in [&mut self.ca_cert, &mut self.cronet_lib_path]
            .into_iter()
            .flatten()
        {
            if !value.contains("-----BEGIN") && Path::new(value).is_relative() {
                *value = cwd.join(&*value).to_string_lossy().into_owned();
            }
        }
    }
}

impl TryFrom<OutboundNaive> for Handler {
    type Error = Error;

    fn try_from(config: OutboundNaive) -> Result<Self, Self::Error> {
        Self::try_from(&config)
    }
}

impl TryFrom<&OutboundNaive> for Handler {
    type Error = Error;

    fn try_from(config: &OutboundNaive) -> Result<Self, Self::Error> {
        let invalid =
            |message: &str| Error::InvalidConfig(format!("naive: {message}"));
        if config.common_opts.connect_via.is_some() {
            return Err(invalid(
                "connect-via/dialer-proxy is not supported by Cronet",
            ));
        }
        if config.skip_cert_verify == Some(true) {
            return Err(invalid("skip-cert-verify is not supported; use ca-cert"));
        }
        let host = config.common_opts.server.trim_matches(['[', ']']);
        if config.sni.as_deref().is_some_and(|sni| sni != host) {
            return Err(invalid(
                "SNI must match server with the current Wind backend",
            ));
        }
        let authority = match host.parse::<IpAddr>() {
            Ok(ip) => {
                std::net::SocketAddr::new(ip, config.common_opts.port).to_string()
            }
            Err(_) => {
                rustls::pki_types::DnsName::try_from(host).map_err(|_| {
                    invalid("server must be an IP address or DNS name")
                })?;
                format!("{host}:{}", config.common_opts.port)
            }
        };
        if config.common_opts.port == 0 {
            return Err(invalid("port must be nonzero"));
        }
        if config.username.is_empty()
            || config.username.contains(':')
            || config.password.is_empty()
        {
            return Err(invalid(
                "credentials must be nonempty and username cannot contain ':'",
            ));
        }
        let concurrency = config.concurrency.unwrap_or(1);
        if concurrency == 0 {
            return Err(invalid("concurrency must be positive"));
        }
        let timeout = config.request_timeout.unwrap_or(10_000);
        if timeout == 0 {
            return Err(invalid("request-timeout must be positive"));
        }
        let congestion = wind_core::parse_congestion_control(
            config.congestion_controller.as_deref().unwrap_or("default"),
        )
        .map_err(|_| {
            invalid(
                "invalid congestion-controller (default, bbr, bbrv2, cubic, reno)",
            )
        })?;
        let ca = config
            .ca_cert
            .as_ref()
            .map(|value| {
                let pem = if value.contains("-----BEGIN") {
                    value.clone()
                } else {
                    std::fs::read_to_string(value)
                        .map_err(|_| invalid("could not read ca-cert"))?
                };
                let certs = rustls_pemfile::certs(&mut pem.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| invalid("invalid ca-cert PEM"))?;
                if certs.is_empty() {
                    return Err(invalid("ca-cert contains no certificates"));
                }
                let mut roots = rustls::RootCertStore::empty();
                for cert in certs {
                    roots
                        .add(cert)
                        .map_err(|_| invalid("invalid CA certificate"))?;
                }
                Ok(pem)
            })
            .transpose()?;

        Ok(Handler::new(HandlerOptions {
            name: config.common_opts.name.clone(),
            server: host.to_owned(),
            port: config.common_opts.port,
            udp: config.udp,
            request_timeout: Duration::from_millis(timeout),
            wind: NaiveOutboundOpts {
                server_address: authority.clone(),
                // cronet-rs builds the CONNECT URL from server_name verbatim.
                // Include the port here, otherwise every proxy uses port 443.
                server_name: Some(authority),
                username: Some(config.username.clone()),
                password: Some(config.password.clone()),
                concurrency,
                quic_enabled: config.quic,
                quic_congestion_control: congestion,
                trusted_root_certificates: ca,
                cronet_lib_path: config.cronet_lib_path.clone(),
                ..Default::default()
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::OutboundProxyProtocol;

    fn config(extra: &str) -> OutboundNaive {
        let yaml = format!(
            "type: naive\nname: test\nserver: localhost\nport: 8443\nusername: \
             synthetic-user\npassword: synthetic-secret\n{extra}"
        );
        let parsed: OutboundProxyProtocol = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.name(), "test");
        assert_eq!(parsed.to_string(), "Naive");
        let OutboundProxyProtocol::Naive(config) = parsed else {
            panic!("wrong protocol")
        };
        config
    }

    #[test]
    fn naive_config_validation() {
        assert!(Handler::try_from(config("")).is_ok());
        for extra in [
            "concurrency: 0",
            "request-timeout: 0",
            "skip-cert-verify: true",
            "sni: other.test",
            "connect-via: other",
            "congestion-controller: bad",
            "ca-cert: invalid",
        ] {
            assert!(Handler::try_from(config(extra)).is_err(), "{extra}");
        }
        let handler = Handler::try_from(config("")).unwrap();
        assert!(!format!("{handler:?}").contains("synthetic-secret"));
    }

    #[test]
    fn naive_paths_are_relative_to_config_directory() {
        let mut config = config("ca-cert: cert.pem\ncronet-lib-path: cronet.dll");
        config.resolve_paths(Path::new("config-root"));
        assert_eq!(
            Path::new(config.ca_cert.as_ref().unwrap()),
            Path::new("config-root/cert.pem")
        );
        assert_eq!(
            Path::new(config.cronet_lib_path.as_ref().unwrap()),
            Path::new("config-root/cronet.dll")
        );
    }
}
