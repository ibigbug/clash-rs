use tracing::warn;

use crate::{
    Error,
    config::internal::proxy::OutboundVmess,
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, H2Client, TlsClient, TransportLayer, WsClient, XhttpClient,
        },
        vmess::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVmess) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVmess> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVmess) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            alter_id: s.alter_id,
            security: s.cipher.clone().unwrap_or_default(),
            udp: s.udp.unwrap_or(true),
            transport: s
                .network
                .clone()
                .map(|x| match x.as_str() {
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws options");
                            TransportLayer::Ws(client)
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "h2" => s
                        .h2_opts
                        .as_ref()
                        .map(|x| {
                            let client: H2Client = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid h2 options");
                            TransportLayer::H2(client)
                        })
                        .ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client: GrpcClient =
                                (s.server_name.clone(), x, &s.common_opts)
                                    .try_into()
                                    .expect("invalid grpc options");
                            TransportLayer::Grpc(client)
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    "xhttp" | "splithttp" => {
                        let default_opts = Default::default();
                        let opts = s.xhttp_opts.as_ref().unwrap_or(&default_opts);
                        let client: XhttpClient =
                            (opts, &s.common_opts).try_into().map_err(|e| {
                                Error::InvalidConfig(format!(
                                    "invalid xhttp options: {e}"
                                ))
                            })?;
                        Ok(TransportLayer::Xhttp(client))
                    }
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?,
            tls: if s.tls.unwrap_or_default() {
                let client = TlsClient::new(
                    s.skip_cert_verify.unwrap_or_default(),
                    s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                        s.ws_opts
                            .as_ref()
                            .and_then(|x| {
                                x.headers.clone().and_then(|x| {
                                    let h = x.get("Host");
                                    h.cloned()
                                })
                            })
                            .or_else(|| {
                                s.xhttp_opts.as_ref().and_then(|x| {
                                    x.host.clone().or_else(|| {
                                        x.headers.as_ref().and_then(|h| {
                                            h.iter()
                                                .find(|(k, _)| {
                                                    k.eq_ignore_ascii_case("host")
                                                })
                                                .map(|(_, v)| v.clone())
                                        })
                                    })
                                })
                            })
                            .unwrap_or(s.common_opts.server.to_owned()),
                    ),
                    s.network
                        .as_ref()
                        .map(|x| match x.as_str() {
                            "ws" => Ok(vec!["http/1.1".to_owned()]),
                            "http" => Ok(vec![]),
                            "h2" | "grpc" | "xhttp" | "splithttp" => {
                                Ok(vec!["h2".to_owned()])
                            }
                            _ => Err(Error::InvalidConfig(format!(
                                "unsupported network: {x}"
                            ))),
                        })
                        .transpose()?,
                    None,
                    s.tls_cert.as_deref(),
                    s.tls_key.as_deref(),
                )?;
                Some(TransportLayer::Tls(client))
            } else {
                None
            },
        });
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::{CommonConfigOptions, XhttpOpt};

    #[test]
    fn test_vmess_network_xhttp() {
        crate::setup_default_crypto_provider();
        let config = OutboundVmess {
            common_opts: CommonConfigOptions {
                name: "test-vmess-xhttp".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            alter_id: 0,
            cipher: Some("auto".to_string()),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("xhttp".to_string()),
            xhttp_opts: Some(XhttpOpt {
                path: Some("/vmess-xhttp".to_string()),
                host: Some("example.com".to_string()),
                mode: Some("auto".to_string()),
                headers: None,
                x_padding_bytes: Some("50-100".to_string()),
            }),
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VMess handler with xhttp network should parse successfully"
        );
    }
}
