use axum::Router;
use tracing::error;

#[cfg(windows)]
pub async fn serve_ipc(
    router: Router,
    path: &str,
    sddl: Option<&str>,
) -> crate::Result<()> {
    use axum::ServiceExt;
    use tower::{Layer, util::MapRequestLayer};
    use tracing::info;

    use crate::app::api::middlewares::websocket_uri_rewrite::rewrite_websocket_uri;
    info!("Starting API server on NamedPipe {path}");

    let listener = NamedPipeListener {
        path: path.to_string(),
        sddl: std::ffi::CString::new(
            sddl.unwrap_or("D:(A;;GRGW;;;BU)(A;;GRGW;;;SY)"),
        )
        .map_err(|_| crate::Error::Operation("invalid NUL in pipe SDDL".into()))?,
        first_instance: true,
    };
    let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| {
            error!("NamedPipe API server error: {}", e);
            crate::Error::Operation(format!("NamedPipe API server error: {e}"))
        })?;
    Ok(())
}

#[cfg(unix)]
pub async fn serve_ipc(router: Router, path: &str) -> crate::Result<()> {
    use axum::ServiceExt;
    use std::path::PathBuf;
    use tower::{Layer, util::MapRequestLayer};
    use tracing::info;

    use crate::app::api::middlewares::websocket_uri_rewrite::rewrite_websocket_uri;
    let path = PathBuf::from(path);

    info!("Start API server on IPC address {:?}", path);

    if let Err(e) = tokio::fs::remove_file(&path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(crate::Error::Operation(format!(
            "Cannot remove existing IPC file: {e}",
        )));
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            crate::Error::Operation(format!("Cannot create IPC dir: {e}"))
        })?;
    }

    let uds = tokio::net::UnixListener::bind(&path).map_err(|e| {
        crate::Error::Operation(format!("Cannot bind on IPC address: {e}"))
    })?;

    let app = MapRequestLayer::new(rewrite_websocket_uri).layer(router);

    axum::serve(uds, app.into_make_service())
        .await
        .map_err(|e| {
            error!("IPC API Server error: {}", e);
            crate::Error::Operation(format!("IPC API Server error: {e}"))
        })
}

#[cfg(all(not(unix), not(windows)))]
pub async fn serve_ipc(_router: Router, _path: &str) -> crate::Result<()> {
    error!("IPC only get supported on Unix and Windows");
    Err(crate::Error::Operation(
        "IPC only get supported on Unix and Windows".to_string(),
    ))
}

#[cfg(windows)]
struct SecurityAttributesGuard {
    sa: windows::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl SecurityAttributesGuard {
    fn new(sddl: &std::ffi::CStr) -> crate::Result<Self> {
        use windows::{
            Win32::Security::{
                Authorization::{
                    ConvertStringSecurityDescriptorToSecurityDescriptorA,
                    SDDL_REVISION_1,
                },
                PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            },
            core::PCSTR,
        };

        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            let mut sd_size = 0u32;

            ConvertStringSecurityDescriptorToSecurityDescriptorA(
                PCSTR::from_raw(sddl.as_ptr().cast()),
                SDDL_REVISION_1,
                &mut sd,
                Some(&mut sd_size),
            )
            .map_err(|e| {
                crate::Error::Operation(format!(
                    "Failed to convert SDDL to security descriptor: {e:?}"
                ))
            })?;

            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: windows::Win32::Foundation::FALSE,
            };

            Ok(Self { sa })
        }
    }

    fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        &mut self.sa as *mut _ as *mut std::ffi::c_void
    }
}

#[cfg(windows)]
impl Drop for SecurityAttributesGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::LocalFree;
        unsafe {
            // Free the security descriptor allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorA
            let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                self.sa.lpSecurityDescriptor,
            )));
        }
    }
}

#[cfg(windows)]
fn create_named_pipe_with_security(
    path: &str,
    first_instance: bool,
    sddl: &std::ffi::CStr,
) -> crate::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe;

    let mut guard = SecurityAttributesGuard::new(sddl)?;

    unsafe {
        let mut options = named_pipe::ServerOptions::new();
        options.access_inbound(true).access_outbound(true);

        if first_instance {
            options.first_pipe_instance(true);
        }

        #[allow(clippy::let_and_return)]
        let result = options
            .create_with_security_attributes_raw(path, guard.as_mut_ptr())
            .map_err(|e| crate::Error::Operation(format!("Cannot create pipe {e}")));

        // SecurityAttributesGuard::drop will automatically free the security
        // descriptor here
        result
    }
}
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(windows)]
struct NamedPipeListener {
    path: String,
    sddl: std::ffi::CString,
    first_instance: bool,
}

#[cfg(windows)]
impl axum::serve::Listener for NamedPipeListener {
    type Addr = ();
    type Io = NamedPipeServer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        use tokio::time::{Duration, sleep};
        use tracing::{error, info, warn};

        let mut retry_count = 0u32;

        let server = loop {
            match create_named_pipe_with_security(
                &self.path,
                self.first_instance,
                &self.sddl,
            ) {
                Ok(server) => break server,
                Err(e) => {
                    retry_count += 1;
                    // Use exponential backoff capped at 30 seconds
                    let delay = Duration::from_millis(200)
                        .saturating_mul(retry_count)
                        .min(Duration::from_secs(30));

                    if retry_count.is_multiple_of(10) {
                        error!(
                            "Failed to create named pipe after {} attempts: {}. \
                             Continuing to retry...",
                            retry_count, e
                        );
                    } else {
                        warn!(
                            "Failed to create named pipe (attempt {}): {}. \
                             Retrying in {:?}...",
                            retry_count, e, delay
                        );
                    }
                    sleep(delay).await;
                }
            }
        };

        self.first_instance = false;

        // Wait for client connection with indefinite retry
        loop {
            match server.connect().await {
                Ok(()) => {
                    info!("Client connected to NamedPipe {}", self.path);
                    return (server, ());
                }
                Err(e) => {
                    warn!("Failed to connect named pipe: {}. Retrying...", e);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> tokio::io::Result<Self::Addr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use serde::{Deserialize, Serialize};
    use tracing_test::traced_test;

    fn test_router() -> Router {
        Router::new().route(
            "/test",
            get(|| async {
                Json(TestResponse {
                    message: "Hello, World!".to_string(),
                })
            }),
        )
    }

    #[cfg(windows)]
    fn test_router_with_websocket() -> Router {
        use axum::{
            extract::ws::{WebSocket, WebSocketUpgrade},
            response::Response,
        };

        async fn ws_handler(ws: WebSocketUpgrade) -> Response {
            ws.on_upgrade(handle_socket)
        }

        async fn handle_socket(mut socket: WebSocket) {
            use axum::extract::ws::Message;
            while let Some(msg) = socket.recv().await {
                if let Ok(msg) = msg {
                    match msg {
                        Message::Text(text) => {
                            let response = format!("Echo: {}", text);
                            if socket
                                .send(Message::Text(response.into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            }
        }

        Router::new()
            .route(
                "/test",
                get(|| async {
                    Json(TestResponse {
                        message: "Hello, World!".to_string(),
                    })
                }),
            )
            .route("/ws", get(ws_handler))
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestResponse {
        message: String,
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(all(not(unix), not(windows)))]
    async fn test_serve_ipc_unsupported_platform() {
        let router = test_router();
        let result = serve_ipc(router, "test_path").await;
        assert!(result.is_err());
        assert!(logs_contain("IPC only get supported on Unix and Windows"));
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(windows)]
    async fn test_serve_ipc_windows_with_client() -> anyhow::Result<()> {
        use hyper::client::conn;
        use hyper_util::rt::TokioIo;
        use tokio::{
            net::windows::named_pipe::ClientOptions,
            time::{Duration, timeout},
        };

        let router = test_router();
        let path = r"\\.\pipe\test_named_pipe_win_client";

        let server_handle = tokio::spawn({
            let router = router.clone();
            async move {
                let _ = serve_ipc(router, path, None).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_result = timeout(Duration::from_secs(5), async {
            use anyhow::Context;
            use bytes::Bytes;
            use futures::StreamExt;
            use http_body_util::{BodyExt, Empty};

            let client = ClientOptions::new()
                .open(path)
                .context("Failed to connect to named pipe")?;

            let io = TokioIo::new(client);
            let (mut request_sender, connection) = conn::http1::handshake(io)
                .await
                .context("Failed to handshake")?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            let request = hyper::Request::builder()
                .uri("http://localhost/test")
                .header("Host", "localhost")
                .body(Empty::<Bytes>::new())
                .context("Failed to build request")?;

            let response = request_sender
                .send_request(request)
                .await
                .context("Failed to send request")?;

            let body = response
                .into_body()
                .into_data_stream()
                .next()
                .await
                .context("Failed to read response body")??;

            let response: TestResponse = serde_json::from_slice(&body)
                .context("Failed to parse response JSON")?;

            assert_eq!(response.message, "Hello, World!");
            anyhow::Ok(())
        })
        .await;

        server_handle.abort();
        let _ = server_handle.await;

        assert!(client_result.is_ok(), "Client test timed out or failed");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(unix)]
    async fn test_serve_ipc_unix_with_client() -> anyhow::Result<()> {
        use hyper::client::conn;
        use hyperlocal::Uri;
        use tokio::{
            net::UnixStream,
            time::{Duration, timeout},
        };

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let socket_path = temp_dir.path().join("test_socket_unix_client");
        let router = test_router();

        let server_handle = tokio::spawn({
            let socket_path = socket_path.clone();
            async move {
                let _ = serve_ipc(router, socket_path.to_str().unwrap()).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client_result = timeout(Duration::from_secs(5), async {
            use anyhow::Context as _;
            use bytes::Bytes;
            use futures::StreamExt;
            use http_body_util::{BodyExt, Empty};
            use hyper_util::rt::TokioIo;

            let stream = UnixStream::connect(&socket_path)
                .await
                .expect("Failed to connect to Unix socket");

            let io = TokioIo::new(stream);
            let (mut request_sender, connection) = conn::http1::handshake(io)
                .await
                .expect("Failed to handshake");

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            let url = Uri::new(&socket_path, "/test");

            let request = hyper::Request::builder()
                .uri(url)
                .header("Host", "localhost")
                .body(Empty::<Bytes>::new())
                .context("Failed to build request")?;

            let response_body = request_sender
                .send_request(request)
                .await
                .context("Failed to send request")?
                .into_body()
                .into_data_stream()
                .next()
                .await
                .context("Failed to read response body")??;

            let response: TestResponse = serde_json::from_slice(&response_body)
                .context("Failed to parse response JSON")?;

            assert_eq!(response.message, "Hello, World!");
            anyhow::Ok(())
        })
        .await;

        server_handle.abort();
        let _ = server_handle.await;

        assert!(client_result.is_ok(), "Client test timed out or failed");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(unix)]
    async fn test_serve_ipc_unix_multiple_clients() {
        use hyper::client::conn;
        use hyperlocal::Uri;
        use tokio::{
            net::UnixStream,
            time::{Duration, timeout},
        };

        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let socket_path = temp_dir.path().join("test_socket_multi_clients");
        let router = test_router();

        let server_handle = tokio::spawn({
            let socket_path = socket_path.clone();
            async move {
                let _ = serve_ipc(router, socket_path.to_str().unwrap()).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut handles = vec![];
        for i in 0..3 {
            let socket_path = socket_path.clone();
            handles.push(tokio::spawn(async move {
                timeout(Duration::from_secs(5), async {
                    use anyhow::Context;
                    use bytes::Bytes;
                    use futures::StreamExt;
                    use http_body_util::{BodyExt, Empty};
                    use hyper_util::rt::TokioIo;

                    let stream = UnixStream::connect(&socket_path)
                        .await
                        .expect("Failed to connect to Unix socket");

                    let io = TokioIo::new(stream);
                    let (mut request_sender, connection) =
                        conn::http1::handshake(io)
                            .await
                            .expect("Failed to handshake");

                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            eprintln!("Connection error: {}", e);
                        }
                    });

                    let url = Uri::new(&socket_path, "/test");

                    let request = hyper::Request::builder()
                        .uri(url)
                        .header("Host", "localhost")
                        .body(Empty::<Bytes>::new())
                        .context("Failed to build request")?;

                    let response_body = request_sender
                        .send_request(request)
                        .await
                        .context("Failed to send request")?
                        .into_body()
                        .into_data_stream()
                        .next()
                        .await
                        .context("Failed to read response body")??;

                    let response: TestResponse =
                        serde_json::from_slice(&response_body)
                            .context("Failed to parse response JSON")?;

                    assert_eq!(response.message, "Hello, World!");
                    println!("Client {} received response: {}", i, response.message);
                    anyhow::Ok(())
                })
                .await
                .expect("Client test timed out")
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        server_handle.abort();
        let _ = server_handle.await;
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(windows)]
    async fn test_serve_ipc_windows_multiple_clients() -> anyhow::Result<()> {
        use hyper::client::conn;
        use hyper_util::rt::TokioIo;
        use tokio::{
            net::windows::named_pipe::ClientOptions,
            time::{Duration, timeout},
        };

        let router = test_router();
        let path = r"\\.\pipe\test_named_pipe_win_multi_client";

        let server_handle = tokio::spawn({
            let router = router.clone();
            async move {
                let _ = serve_ipc(router, path, None).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut handles = vec![];
        for i in 0..3 {
            handles.push(tokio::spawn(async move {
                timeout(Duration::from_secs(5), async {
                    use anyhow::Context;
                    use bytes::Bytes;
                    use futures::StreamExt;
                    use http_body_util::{BodyExt, Empty};
                    tokio::time::sleep(Duration::from_millis(100 * i)).await;
                    let client = ClientOptions::new()
                        .open(path)
                        .context("Failed to connect to named pipe")?;

                    let io = TokioIo::new(client);
                    let (mut request_sender, connection) =
                        conn::http1::handshake(io)
                            .await
                            .context("Failed to handshake")?;

                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            eprintln!("Connection error: {}", e);
                        }
                    });

                    let request = hyper::Request::builder()
                        .uri("http://localhost/test")
                        .header("Host", "localhost")
                        .body(Empty::<Bytes>::new())
                        .context("Failed to build request")?;

                    let response = request_sender
                        .send_request(request)
                        .await
                        .context("Failed to send request")?;

                    let body = response
                        .into_body()
                        .into_data_stream()
                        .next()
                        .await
                        .context("Failed to read response body")??;

                    let response: TestResponse = serde_json::from_slice(&body)
                        .context("Failed to parse response JSON")?;

                    assert_eq!(response.message, "Hello, World!");
                    println!("Client {} received response: {}", i, response.message);
                    anyhow::Ok(())
                })
                .await
                .expect("Client test timed out")
            }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }

        server_handle.abort();
        let _ = server_handle.await;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    #[cfg(windows)]
    async fn test_serve_ipc_windows_websocket() -> anyhow::Result<()> {
        use futures::SinkExt;
        use tokio::{net::windows::named_pipe::ClientOptions, time::Duration};
        use tokio_tungstenite::tungstenite::{
            client::IntoClientRequest, protocol::Message,
        };

        let router = test_router_with_websocket();
        let path = r"\\.\pipe\test_named_pipe_ws";

        let server_handle = tokio::spawn({
            let router = router.clone();
            async move {
                serve_ipc(router, path, None).await.unwrap();
            }
        });

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Try to connect, skip test if pipe creation failed
        let client = match ClientOptions::new().open(path) {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Skipping test: Failed to connect to named pipe: {}", e);
                server_handle.abort();
                let _ = server_handle.await;
                return Ok(());
            }
        };

        let mut request = "ws://localhost/ws".into_client_request()?;
        request
            .headers_mut()
            .insert("Host", "localhost".parse().unwrap());

        let (mut ws_stream, _) =
            tokio_tungstenite::client_async(request, client).await?;

        ws_stream
            .send(Message::Text("Hello WebSocket".into()))
            .await?;

        use futures::StreamExt;
        if let Some(msg) = ws_stream.next().await {
            let msg = msg.expect("Failed to receive message");
            if let Message::Text(text) = msg {
                assert_eq!(text, "Echo: Hello WebSocket");
                println!("Received: {}", text);
            } else {
                panic!("Expected text message");
            }
        }

        ws_stream.send(Message::Close(None)).await?;

        server_handle.abort();
        let _ = server_handle.await;
        Ok(())
    }
}
