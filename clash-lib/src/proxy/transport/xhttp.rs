use async_trait::async_trait;
use http::Request;
use std::{collections::HashMap, fmt::Debug};
use tracing::error;

use super::{Transport, h2::Http2Stream};
use crate::{common::errors::map_io_error, proxy::AnyStream};

#[derive(Clone, Debug)]
pub struct Client {
    pub host: String,
    pub path: http::uri::PathAndQuery,
    #[allow(dead_code)]
    pub mode: String,
    pub headers: HashMap<String, String>,
    pub x_padding_bytes: Option<String>,
}

impl Client {
    pub fn new(
        host: String,
        path: http::uri::PathAndQuery,
        mode: String,
        headers: HashMap<String, String>,
        x_padding_bytes: Option<String>,
    ) -> Self {
        Self {
            host,
            path,
            mode,
            headers,
            x_padding_bytes,
        }
    }

    fn req(&self) -> std::io::Result<Request<()>> {
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(self.host.as_str())
            .path_and_query(self.path.clone())
            .build()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut request = Request::builder()
            .uri(uri)
            .method(http::Method::POST)
            .version(http::Version::HTTP_2)
            .header(http::header::CONTENT_TYPE, "application/octet-stream");

        for (k, v) in self.headers.iter() {
            if !k.eq_ignore_ascii_case("host") && !k.eq_ignore_ascii_case("referer")
            {
                request = request.header(k, v);
            }
        }

        let padding = get_padding(self.x_padding_bytes.as_deref());
        if let Some(ref pad) = padding {
            let base = self
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");

            let referer = if base.is_empty() {
                let path_str = self.path.as_str();
                let sep = if path_str.contains('?') { '&' } else { '?' };
                format!("https://{}{}{sep}x_padding={pad}", self.host, path_str)
            } else if !base.contains("x_padding=") {
                let sep = if base.contains('?') { '&' } else { '?' };
                format!("{base}{sep}x_padding={pad}")
            } else {
                base.to_string()
            };
            request = request.header(http::header::REFERER, referer);
        } else if let Some((_, v)) = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
        {
            request = request.header(http::header::REFERER, v);
        }

        if let Some(ref padding) = self.x_padding_bytes {
            request = request.header("X-Padding", padding);
        }

        request
            .body(())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

fn get_padding(x_padding_bytes: Option<&str>) -> Option<String> {
    match x_padding_bytes {
        None => {
            let len = crate::common::utils::rand_range(100..=1000);
            Some("X".repeat(len))
        }
        Some(s) => {
            let s = s.trim();
            if s == "0" || s == "0-0" {
                return None;
            }
            if let Some((start, end)) = s.split_once('-') {
                let start: usize = start.trim().parse().unwrap_or(0);
                let end: usize = end.trim().parse().unwrap_or(0);
                if start == 0 && end == 0 {
                    None
                } else if start <= end {
                    let len = crate::common::utils::rand_range(start..=end);
                    Some("X".repeat(len))
                } else {
                    Some("X".repeat(start))
                }
            } else if let Ok(n) = s.parse::<usize>() {
                if n == 0 { None } else { Some("X".repeat(n)) }
            } else {
                Some(s.to_string())
            }
        }
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let (mut client, h2) =
            h2::client::handshake(stream).await.map_err(map_io_error)?;
        let req = self.req()?;
        let (resp, send_stream) =
            client.send_request(req, false).map_err(map_io_error)?;

        tokio::spawn(async move {
            if let Err(e) = h2.await {
                error!("xhttp h2 error: {}", e);
            }
        });

        let response = resp.await.map_err(map_io_error)?;
        if !response.status().is_success() {
            return Err(std::io::Error::other(format!(
                "xhttp request failed with status: {}",
                response.status()
            )));
        }
        let recv_stream = response.into_body();

        Ok(Box::new(Http2Stream::new(recv_stream, send_stream)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xhttp_client_req_creation() {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".into(), "Mozilla/5.0".into());
        let client = Client::new(
            "example.com".into(),
            "/xhttp-test".try_into().unwrap(),
            "auto".into(),
            headers,
            Some("abcdef".into()),
        );

        let req = client.req().expect("request build succeeds");
        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(req.uri().path(), "/xhttp-test");
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/octet-stream"
        );
        assert_eq!(req.headers().get("user-agent").unwrap(), "Mozilla/5.0");
        assert_eq!(req.headers().get("x-padding").unwrap(), "abcdef");
        assert_eq!(
            req.headers().get("referer").unwrap(),
            "https://example.com/xhttp-test?x_padding=abcdef"
        );
    }

    #[test]
    fn test_xhttp_client_req_default_padding() {
        let client = Client::new(
            "example.com".into(),
            "/xhttp-test".try_into().unwrap(),
            "auto".into(),
            HashMap::new(),
            None,
        );

        let req = client.req().expect("request build succeeds");
        assert_eq!(req.method(), http::Method::POST);
        assert!(req.headers().get("x-padding").is_none());

        let referer = req.headers().get("referer").unwrap().to_str().unwrap();
        assert!(referer.starts_with("https://example.com/xhttp-test?x_padding="));
        let padding = referer
            .strip_prefix("https://example.com/xhttp-test?x_padding=")
            .unwrap();
        assert!(padding.len() >= 100 && padding.len() <= 1000);
        assert!(padding.chars().all(|c| c == 'X'));
    }

    #[test]
    fn test_xhttp_client_req_range_padding() {
        let client = Client::new(
            "example.com".into(),
            "/xhttp-test".try_into().unwrap(),
            "auto".into(),
            HashMap::new(),
            Some("150-250".into()),
        );

        let req = client.req().expect("request build succeeds");
        assert_eq!(req.headers().get("x-padding").unwrap(), "150-250");

        let referer = req.headers().get("referer").unwrap().to_str().unwrap();
        let padding = referer
            .strip_prefix("https://example.com/xhttp-test?x_padding=")
            .unwrap();
        assert!(padding.len() >= 150 && padding.len() <= 250);
        assert!(padding.chars().all(|c| c == 'X'));
    }

    #[test]
    fn test_xhttp_client_req_zero_padding() {
        let client = Client::new(
            "example.com".into(),
            "/xhttp-test".try_into().unwrap(),
            "auto".into(),
            HashMap::new(),
            Some("0-0".into()),
        );

        let req = client.req().expect("request build succeeds");
        assert!(req.headers().get("referer").is_none());
        assert_eq!(req.headers().get("x-padding").unwrap(), "0-0");
    }

    #[test]
    fn test_xhttp_client_req_existing_referer() {
        let mut headers = HashMap::new();
        headers.insert(
            "Referer".into(),
            "https://mycdn.net/prefix?existing=1".into(),
        );
        let client = Client::new(
            "example.com".into(),
            "/xhttp-test".try_into().unwrap(),
            "auto".into(),
            headers,
            Some("abc".into()),
        );

        let req = client.req().expect("request build succeeds");
        assert_eq!(
            req.headers().get("referer").unwrap(),
            "https://mycdn.net/prefix?existing=1&x_padding=abc"
        );
    }
}
