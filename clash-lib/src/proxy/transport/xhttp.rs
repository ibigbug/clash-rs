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
            if !k.eq_ignore_ascii_case("host") {
                request = request.header(k, v);
            }
        }

        if let Some(ref padding) = self.x_padding_bytes {
            request = request.header("X-Padding", padding);
        }

        request
            .body(())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    }
}
