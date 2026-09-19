use async_trait::async_trait;
use http::{Request, StatusCode};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::collections::HashMap;
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{handshake::client::generate_key, protocol::WebSocketConfig},
};

use super::Transport;
use crate::{common::errors::map_io_error, proxy::AnyStream};

mod websocket;
mod websocket_early_data;

pub use websocket::WebsocketConn;
pub use websocket_early_data::WebsocketEarlyDataConn;

const PATH_AND_QUERY_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub struct Client {
    server: String,
    port: u16,
    path: String,
    headers: HashMap<String, String>,
    ws_config: Option<WebSocketConfig>,
    max_early_data: usize,
    early_data_header_name: String,
}

impl Client {
    pub fn new(
        server: String,
        port: u16,
        path: String,
        headers: HashMap<String, String>,
        ws_config: Option<WebSocketConfig>,
        max_early_data: usize,
        early_data_header_name: String,
    ) -> Self {
        Self {
            server,
            port,
            path,
            headers,
            ws_config,
            max_early_data,
            early_data_header_name,
        }
    }

    fn req(&self) -> std::io::Result<Request<()>> {
        let path = utf8_percent_encode(&self.path, PATH_AND_QUERY_ENCODE_SET);
        let mut request = Request::builder()
            .method("GET")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .uri(format!("ws://{}:{}{}", self.server, self.port, path));
        for (k, v) in self.headers.iter() {
            request = request.header(k.as_str(), v.as_str());
        }
        if self.max_early_data > 0 {
            // we will replace this field later
            request = request.header(self.early_data_header_name.as_str(), "xxoo");
        }
        request.body(()).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
        })
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, stream: AnyStream) -> std::io::Result<AnyStream> {
        let req = self.req()?;
        if self.max_early_data > 0 {
            let early_data_conn = WebsocketEarlyDataConn::new(
                stream,
                req,
                self.ws_config,
                self.early_data_header_name.clone(),
                self.max_early_data,
            );
            Ok(Box::new(early_data_conn))
        } else {
            let (stream, resp) =
                client_async_with_config(req, stream, self.ws_config)
                    .await
                    .map_err(map_io_error)?;

            if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid response",
                ));
            }
            Ok(Box::new(WebsocketConn::from_websocket(stream)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, Transport};
    use std::{collections::HashMap, sync::Arc};
    use tokio::io::duplex;
    use tokio_tungstenite::{
        accept_hdr_async,
        tungstenite::handshake::server::{Request, Response},
    };

    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn websocket_request_target_is_encoded_without_normalization() {
        let client = Client::new(
            "example.com".to_owned(),
            443,
            "/a/./b/../already%20encoded/中文 path?ed=2048&name=中文%20value"
                .to_owned(),
            HashMap::from([("Host".to_owned(), "example.com".to_owned())]),
            None,
            0,
            String::new(),
        );
        let (client_stream, server_stream) = duplex(4096);
        let request_target = Arc::new(std::sync::Mutex::new(None));
        let captured_target = Arc::clone(&request_target);

        let client_task = tokio::spawn(async move {
            client.proxy_stream(Box::new(client_stream)).await
        });
        let server_task = accept_hdr_async(
            server_stream,
            move |request: &Request, response: Response| {
                *captured_target.lock().expect("request target lock") =
                    request.uri().path_and_query().map(ToString::to_string);
                Ok(response)
            },
        );

        let (client_result, server_result) = tokio::join!(client_task, server_task);

        assert_eq!(
            request_target
                .lock()
                .expect("request target lock")
                .as_deref(),
            Some(
                "/a/./b/../already%20encoded/%E4%B8%AD%E6%96%87%20path?ed=2048&\
                 name=%E4%B8%AD%E6%96%87%20value"
            )
        );
        client_result
            .expect("WebSocket client task should not panic")
            .expect("WebSocket client handshake should succeed");
        server_result.expect("WebSocket server handshake should succeed");
    }

    async fn assert_invalid_input_without_panic(client: Client) {
        let (client_stream, server_stream) = duplex(1024);
        drop(server_stream);

        let result = tokio::spawn(async move {
            client.proxy_stream(Box::new(client_stream)).await
        })
        .await
        .expect("WebSocket client task should not panic");

        let error = match result {
            Ok(_) => panic!("invalid request should fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn malformed_uri_returns_invalid_input() {
        let client = Client::new(
            "bad host".to_owned(),
            443,
            "/".to_owned(),
            HashMap::from([("Host".to_owned(), "example.com".to_owned())]),
            None,
            0,
            String::new(),
        );

        assert_invalid_input_without_panic(client).await;
    }

    #[tokio::test]
    async fn invalid_header_returns_invalid_input() {
        let client = Client::new(
            "example.com".to_owned(),
            443,
            "/".to_owned(),
            HashMap::from([("bad\nheader".to_owned(), "value".to_owned())]),
            None,
            0,
            String::new(),
        );

        assert_invalid_input_without_panic(client).await;
    }
}
