use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::uri::InvalidUri;

use crate::{
    Error,
    config::proxy::{CommonConfigOptions, GrpcOpt, H2Opt, WsOpt, XhttpOpt},
    proxy::transport::{self, GrpcClient, H2Client, WsClient, XhttpClient},
};

impl TryFrom<(&WsOpt, &CommonConfigOptions)> for WsClient {
    type Error = std::io::Error;

    fn try_from(pair: (&WsOpt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let path = x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let headers = x.headers.as_ref().map(|x| x.to_owned()).unwrap_or_default();
        let max_early_data = x.max_early_data.unwrap_or_default() as usize;
        let early_data_header_name = x
            .early_data_header_name
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or_default();

        let client = transport::WsClient::new(
            common.server.to_owned(),
            common.port,
            path,
            headers,
            None,
            max_early_data,
            early_data_header_name,
        );
        Ok(client)
    }
}

impl TryFrom<(Option<String>, &GrpcOpt, &CommonConfigOptions)> for GrpcClient {
    type Error = InvalidUri;

    fn try_from(
        opt: (Option<String>, &GrpcOpt, &CommonConfigOptions),
    ) -> Result<Self, Self::Error> {
        let (sni, x, common) = opt;
        let client = transport::GrpcClient::new(
            sni.as_ref().unwrap_or(&common.server).to_owned(),
            format!("/{}", x.grpc_service_name.as_deref().unwrap_or_default())
                .try_into()?,
        );
        Ok(client)
    }
}

impl TryFrom<(&H2Opt, &CommonConfigOptions)> for H2Client {
    type Error = InvalidUri;

    fn try_from(pair: (&H2Opt, &CommonConfigOptions)) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let host = x
            .host
            .as_ref()
            .map(|x| x.to_owned())
            .unwrap_or(vec![common.server.to_owned()]);
        let path = x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default();

        Ok(H2Client::new(
            host,
            std::collections::HashMap::new(),
            http::Method::GET,
            path.try_into()?,
        ))
    }
}

impl TryFrom<(&XhttpOpt, &CommonConfigOptions)> for XhttpClient {
    type Error = InvalidUri;

    fn try_from(
        pair: (&XhttpOpt, &CommonConfigOptions),
    ) -> Result<Self, Self::Error> {
        let (x, common) = pair;
        let host = x
            .host
            .clone()
            .or_else(|| {
                x.headers.as_ref().and_then(|h| {
                    h.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                        .map(|(_, v)| v.clone())
                })
            })
            .unwrap_or_else(|| common.server.clone());
        let path_str = x.path.as_deref().unwrap_or("/");
        let (path_part, query_part) = match path_str.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path_str, None),
        };
        let mut normalized = if path_part.starts_with('/') {
            path_part.to_string()
        } else {
            format!("/{path_part}")
        };
        if !normalized.ends_with('/') {
            normalized.push('/');
        }
        let path = if let Some(q) = query_part {
            format!("{normalized}?{q}")
        } else {
            normalized
        };
        let mode = x.mode.clone().unwrap_or_else(|| "auto".to_owned());
        let headers = x.headers.clone().unwrap_or_default();
        let x_padding_bytes = x.x_padding_bytes.clone();

        Ok(transport::XhttpClient::new(
            host,
            path.try_into()?,
            mode,
            headers,
            x_padding_bytes,
        ))
    }
}

pub fn decode_base64_public_key(base64_public_key: &str) -> Result<[u8; 32], Error> {
    URL_SAFE_NO_PAD
        .decode(base64_public_key)
        .map_err(|e| {
            Error::InvalidConfig(format!("reality public-key base64: {e}"))
        })?
        .try_into()
        .map_err(|_| {
            Error::InvalidConfig("reality public-key must decode to 32 bytes".into())
        })
}

pub fn decode_short_id(hex_short_id: &str) -> Result<Vec<u8>, Error> {
    hex::decode(hex_short_id)
        .map_err(|e| Error::InvalidConfig(format!("reality short-id hex: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xhttp_client_path_normalization() {
        let opt = XhttpOpt {
            path: Some("/xhttp".into()),
            host: Some("example.org".into()),
            mode: Some("auto".into()),
            headers: None,
            x_padding_bytes: None,
        };
        let common = CommonConfigOptions {
            server: "fallback.org".into(),
            ..Default::default()
        };

        let client =
            XhttpClient::try_from((&opt, &common)).expect("valid xhttp client");
        assert_eq!(client.path.as_str(), "/xhttp/");

        let opt_with_query = XhttpOpt {
            path: Some("xhttp?k=v".into()),
            ..opt
        };
        let client_query = XhttpClient::try_from((&opt_with_query, &common))
            .expect("valid xhttp client");
        assert_eq!(client_query.path.as_str(), "/xhttp/?k=v");
    }
}
