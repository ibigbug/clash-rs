use std::{net::IpAddr, path::Path, time::Duration};

use wind_naive::NaiveOutboundOpts;

use crate::{
    Error,
    common::tls::{is_inline_pem, read_pem},
    config::internal::proxy::OutboundNaive,
    proxy::naive::{Handler, HandlerOptions},
};

impl OutboundNaive {
    pub(crate) fn validate_provider_options(&self) -> Result<(), Error> {
        if self.cronet_lib_path.is_some() {
            return Err(Error::InvalidConfig(
                "naive: cronet-lib-path is only allowed in the main configuration"
                    .into(),
            ));
        }
        if self.ca_cert.as_deref().is_some_and(|ca| !is_inline_pem(ca)) {
            return Err(Error::InvalidConfig(
                "naive: provider ca-cert must be an inline PEM certificate".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn resolve_paths(&mut self, cwd: &Path) {
        if let Some(ca) = &mut self.ca_cert
            && !is_inline_pem(ca)
            && Path::new(ca).is_relative()
        {
            *ca = cwd.join(&*ca).to_string_lossy().into_owned();
        }
        if let Some(lib) = &mut self.cronet_lib_path
            && lib.contains(std::path::is_separator)
            && Path::new(lib).is_relative()
        {
            *lib = cwd.join(&*lib).to_string_lossy().into_owned();
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
        let server = config.common_opts.server.as_str();
        let (host, ip) = if let Some(host) =
            server.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        {
            let ipv6 = host
                .parse()
                .map_err(|_| invalid("bracketed server must be an IPv6 address"))?;
            (host, Some(IpAddr::V6(ipv6)))
        } else {
            (server, server.parse().ok())
        };
        let authority = match ip {
            Some(ip) => {
                std::net::SocketAddr::new(ip, config.common_opts.port).to_string()
            }
            None => {
                rustls::pki_types::DnsName::try_from(host).map_err(|_| {
                    invalid("server must be an IP address or DNS name")
                })?;
                format!("{host}:{}", config.common_opts.port)
            }
        };
        if config
            .sni
            .as_deref()
            .is_some_and(|sni| !sni.eq_ignore_ascii_case(host))
        {
            return Err(invalid(
                "SNI must match server with the current Wind backend",
            ));
        }
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
                let pem = read_pem(value)
                    .map_err(|_| invalid("could not read ca-cert"))?;
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
                // Cronet uses the full authority for CONNECT and TLS.
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
    fn naive_sni_matches_server_ignoring_ascii_case() {
        let mut proxy = config("sni: proxy.example");
        proxy.common_opts.server = "Proxy.Example".into();
        assert!(Handler::try_from(&proxy).is_ok());

        proxy.sni = Some("other.example".into());
        assert!(Handler::try_from(&proxy).is_err());
    }

    #[test]
    fn naive_server_name_is_the_bare_host_for_dns() {
        use crate::proxy::OutboundHandler;

        let handler = Handler::try_from(config("")).unwrap();
        // The enhanced resolver matches this name against DNS queries to
        // keep proxy servers out of the fake-IP pool; a port or IPv6
        // brackets here would make that match fail.
        assert_eq!(handler.server_name(), Some("localhost"));
    }

    #[test]
    fn naive_server_brackets_are_only_for_ipv6_literals() {
        let mut proxy = config("");
        for host in ["[proxy.example]", "[127.0.0.1]", "[[::1]]", "[::1", "::1]"] {
            proxy.common_opts.server = host.into();
            assert!(Handler::try_from(&proxy).is_err(), "{host}");
        }
        for (host, sni) in [
            ("127.0.0.1", "127.0.0.1"),
            ("2001:db8::1", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
        ] {
            proxy.common_opts.server = host.into();
            proxy.sni = Some(sni.into());
            assert!(Handler::try_from(&proxy).is_ok(), "{host}");
        }
    }

    #[test]
    fn naive_bare_library_name_uses_system_search_path() {
        let mut config = config("ca-cert: cert.pem\ncronet-lib-path: libcronet.so");
        config.resolve_paths(Path::new("config-root"));
        assert_eq!(
            Path::new(config.ca_cert.as_ref().unwrap()),
            Path::new("config-root/cert.pem")
        );
        assert_eq!(config.cronet_lib_path.as_deref(), Some("libcronet.so"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn naive_warns_on_conflicting_library_paths() {
        let proxies = [
            ("default", None),
            ("first", Some("./cronet.dll")),
            ("same", Some("./cronet.dll")),
            ("search", Some("cronet.dll")),
        ]
        .map(|(name, path)| {
            let mut proxy = config("");
            proxy.common_opts.name = name.into();
            proxy.cronet_lib_path = path.map(String::from);
            OutboundProxyProtocol::Naive(proxy)
        });
        let handlers =
            crate::app::outbound::manager::OutboundManager::load_plain_outbounds(
                proxies.into(),
                Path::new("config-root"),
            );
        assert_eq!(handlers.len(), 4);
        assert!(logs_contain(
            "first and search specify different cronet-lib-path"
        ));
        assert!(!logs_contain("first and same"));
        assert!(!logs_contain("default and"));
    }

    #[test]
    fn naive_explicit_library_paths() {
        let cwd = std::env::temp_dir();
        let absolute = cwd.join("other/libcronet.so");
        let mut proxy = config("");
        for path in [
            "./libcronet.so",
            "lib/cronet.dll",
            #[cfg(windows)]
            r"lib\cronet.dll",
            absolute.to_str().unwrap(),
        ] {
            proxy.cronet_lib_path = Some(path.into());
            proxy.resolve_paths(&cwd);
            assert_eq!(
                Path::new(proxy.cronet_lib_path.as_ref().unwrap()),
                cwd.join(path)
            );
        }
    }
}
