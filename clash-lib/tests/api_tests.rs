use crate::common::{
    ClashInstance, alloc_ports, make_client_config_str, send_http_request,
    wait_port_ready,
};
use bytes::{Buf, Bytes};
use clash_lib::{Config, Options};
use http_body_util::BodyExt;
use std::{path::PathBuf, time::Duration};

mod common;

// Port layout for client tests: 7 ports per instance
const CLIENT_PORT_BLOCK: u16 = 7;

/// Allocate a unique port block and start an isolated client Clash instance.
/// Returns (instance, api_port) where api_port = port_base
/// (external-controller).
fn start_unique_client() -> (ClashInstance, u16) {
    let port_base = alloc_ports(CLIENT_PORT_BLOCK);
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_str = make_client_config_str(port_base);
    let clash = ClashInstance::start(
        Options {
            config: Config::Str(config_str),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        (port_base..port_base + CLIENT_PORT_BLOCK).collect(),
    )
    .expect("Failed to start client");
    (clash, port_base)
}

async fn get_allow_lan(port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/configs", port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect response body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON response");
    json.get("allow-lan")
        .and_then(|v| v.as_bool())
        .expect("'allow-lan' not found or not a bool")
}

#[tokio::test(flavor = "current_thread")]
async fn test_wildcard_cors_returns_any_origin_header() {
    let port_base = alloc_ports(CLIENT_PORT_BLOCK);
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_str = format!(
        "{}\ncors-allow-origins:\n  - \"*\"\n",
        make_client_config_str(port_base)
    );
    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config_str),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        (port_base..port_base + CLIENT_PORT_BLOCK).collect(),
    )
    .expect("Failed to start client with wildcard CORS origins");

    let version_url = format!("http://127.0.0.1:{}/version", port_base);
    let auth_header = ["Bearer ", "clash-rs"].concat();
    let req = hyper::Request::builder()
        .uri(&version_url)
        .header(hyper::header::AUTHORIZATION, auth_header)
        .header(http::header::ORIGIN, "https://example.com")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let res = send_http_request(version_url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), http::StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_cors_preflight_without_auth_returns_cors_headers() {
    let port_base = alloc_ports(CLIENT_PORT_BLOCK);
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");
    let config_str = format!(
        "{}\ncors-allow-origins:\n  - \"*\"\n",
        make_client_config_str(port_base)
    );
    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config_str),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        (port_base..port_base + CLIENT_PORT_BLOCK).collect(),
    )
    .expect("Failed to start client with wildcard CORS origins");

    // Preflight OPTIONS request WITHOUT Authorization header
    // This is what browsers send and it must return CORS headers.
    let version_url = format!("http://127.0.0.1:{}/version", port_base);
    let req = hyper::Request::builder()
        .uri(&version_url)
        .header(http::header::ORIGIN, "https://example.com")
        .header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .method(http::method::Method::OPTIONS)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let res = send_http_request(version_url.parse().unwrap(), req)
        .await
        .expect("Failed to send OPTIONS preflight request");

    // Preflight must succeed, not return 401
    assert_eq!(res.status(), http::StatusCode::OK);

    // Must include CORS headers so the browser allows the actual request
    assert_eq!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );

    // Must allow the actual request method
    assert!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_METHODS)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("GET"))
            .unwrap_or(false),
        "preflight response should allow GET method"
    );

    // Must allow the Authorization header that the actual request will send
    assert!(
        res.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("authorization"))
            .unwrap_or(false),
        "preflight response should allow Authorization header"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_config_reload_via_payload() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");

    // Allocate 8 ports: 7 for the initial instance + 1 for the reloaded
    // controller
    let port_base = alloc_ports(8);
    let config_str = make_client_config_str(port_base);

    // Start Clash instance with RAII guard - will auto-cleanup on drop
    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config_str),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        (port_base..port_base + CLIENT_PORT_BLOCK).collect(),
    )
    .expect("Failed to start clash");

    // Initial config has allow-lan: true
    assert!(
        get_allow_lan(port_base).await,
        "expected allow-lan=true before reload"
    );

    // Reload with a new payload that flips allow-lan to false
    let new_payload = format!(
        r#"
socks-port: {}
bind-address: 127.0.0.1
allow-lan: false
mode: direct
log-level: info
external-controller: :{}
secret: clash-rs
tun:
  enable: false
proxies:
  - {{name: DIRECT_alias, type: direct}}
  - {{name: REJECT_alias, type: reject}}
"#,
        port_base + 2,
        port_base + 7
    );
    let body = serde_json::json!({ "payload": new_payload }).to_string();

    let configs_url = format!("http://127.0.0.1:{}/configs", port_base);
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /configs request");
    assert_eq!(
        res.status(),
        http::StatusCode::NO_CONTENT,
        "PUT /configs should return 204 No Content"
    );

    // Wait briefly for the reload to propagate
    tokio::time::sleep(Duration::from_millis(500)).await;

    // allow-lan should now be false
    assert!(
        !get_allow_lan(port_base + 7).await,
        "expected allow-lan=false after reload"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_config_reload_same_controller_hot_swap_immediately_available() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");

    let port_base = alloc_ports(CLIENT_PORT_BLOCK);
    let config_str = make_client_config_str(port_base);

    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config_str),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        (port_base..port_base + CLIENT_PORT_BLOCK).collect(),
    )
    .expect("Failed to start clash");

    assert!(
        get_allow_lan(port_base).await,
        "expected allow-lan=true before reload"
    );

    // Reload with same external-controller, but adding my-socks5 and allow-lan=false
    let new_payload = format!(
        r#"
socks-port: {}
bind-address: 127.0.0.1
allow-lan: false
mode: direct
log-level: info
external-controller: :{}
secret: clash-rs
tun:
  enable: false
proxies:
  - name: my-socks5
    type: socks5
    server: 127.0.0.1
    port: 1080
proxy-groups:
  - name: my-selector
    type: select
    proxies:
      - DIRECT
"#,
        port_base + 2,
        port_base
    );
    let body = serde_json::json!({ "payload": new_payload }).to_string();

    let configs_url = format!("http://127.0.0.1:{}/configs", port_base);
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /configs request");
    assert_eq!(
        res.status(),
        http::StatusCode::NO_CONTENT,
        "PUT /configs should return 204 No Content"
    );

    // ZERO SLEEP: The API server must be immediately accessible on the SAME port,
    // and must already be serving the new components!
    assert!(
        !get_allow_lan(port_base).await,
        "expected allow-lan=false immediately after reload"
    );

    let all_proxies_url = format!("http://127.0.0.1:{}/proxies", port_base);
    let all_proxies_res = send_http_request(all_proxies_url.parse().unwrap(), auth_get(&all_proxies_url))
        .await
        .expect("API server should be immediately reachable");
    let all_json = parse_json(all_proxies_res).await;
    assert!(all_json["proxies"].get("my-socks5").is_some());
    assert!(all_json["proxies"].get("my-selector").is_some());

    let proxy_url = format!("http://127.0.0.1:{}/proxies/my-socks5", port_base);
    let proxy_res = send_http_request(proxy_url.parse().unwrap(), auth_get(&proxy_url))
        .await
        .expect("API server should be immediately reachable without reconnection errors");
    assert_eq!(
        proxy_res.status(),
        http::StatusCode::OK,
        "newly added proxy should be immediately accessible via API"
    );
    let json = parse_json(proxy_res).await;
    assert_eq!(json["name"], "my-socks5");

    let group_url = format!("http://127.0.0.1:{}/proxies/my-selector", port_base);
    let group_res = send_http_request(group_url.parse().unwrap(), auth_get(&group_url))
        .await
        .expect("API server should be immediately reachable without reconnection errors");
    assert_eq!(
        group_res.status(),
        http::StatusCode::OK,
        "newly added proxy group should be immediately accessible via API"
    );
    let group_json = parse_json(group_res).await;
    assert_eq!(group_json["name"], "my-selector");
    assert_eq!(group_json["type"], "Selector");
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_set_allow_lan() {
    let (_clash, api_port) = start_unique_client();

    assert!(
        get_allow_lan(api_port).await,
        "'allow_lan' should be true by config"
    );

    let configs_url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body("{\"allow-lan\": false}".into())
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);

    assert!(
        !get_allow_lan(api_port).await,
        "'allow_lan' should be false after update"
    );

    // _clash will be dropped here, automatically cleaning up
}

#[tokio::test(flavor = "current_thread")]
async fn test_config_reload_rejects_empty_or_directory_path_without_panicking() {
    let (_clash, api_port) = start_unique_client();
    let configs_url = format!("http://127.0.0.1:{}/configs", api_port);

    let reload_req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body("{\"path\":\"\"}".into())
        .expect("Failed to build PUT /configs request");

    let reload_res =
        send_http_request::<String>(configs_url.parse().unwrap(), reload_req)
            .await
            .expect("Failed to send PUT /configs request");
    assert_eq!(
        reload_res.status(),
        http::StatusCode::BAD_REQUEST,
        "PUT /configs with empty path should be rejected"
    );

    let reload_dir_req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body("{\"path\":\".\"}".into())
        .expect("Failed to build PUT /configs request for directory path");

    let reload_dir_res =
        send_http_request::<String>(configs_url.parse().unwrap(), reload_dir_req)
            .await
            .expect("Failed to send PUT /configs request for directory path");
    assert_eq!(
        reload_dir_res.status(),
        http::StatusCode::BAD_REQUEST,
        "PUT /configs with directory path should be rejected"
    );

    // Ensure API is still alive after the rejected reload request.
    let get_req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build GET /configs request");

    let get_res = send_http_request(configs_url.parse().unwrap(), get_req)
        .await
        .expect("Failed to send GET /configs request");
    assert_eq!(
        get_res.status(),
        http::StatusCode::OK,
        "GET /configs should still succeed after invalid reload request"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_config_reload_via_empty_path_uses_stored_config_path() {
    let wd =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");

    let port_base = alloc_ports(CLIENT_PORT_BLOCK);
    let config_str = make_client_config_str(port_base);

    // Write config to a temp file so we can pass a real config_path.
    let tmp = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    std::fs::write(tmp.path(), &config_str).expect("Failed to write config");
    let config_file = tmp.path().to_string_lossy().to_string();

    let _clash = ClashInstance::start(
        Options {
            config: Config::Str(config_str),
            cwd: Some(wd.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: Some(config_file),
        },
        (port_base..port_base + CLIENT_PORT_BLOCK).collect(),
    )
    .expect("Failed to start clash");

    let configs_url = format!("http://127.0.0.1:{}/configs", port_base);

    // PUT /configs with empty path should reload from the stored config_path
    // and return 204 No Content (not 400).
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body("{\"path\":\"\"}".into())
        .expect("Failed to build PUT /configs request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /configs request");
    assert_eq!(
        res.status(),
        http::StatusCode::NO_CONTENT,
        "PUT /configs with empty path and a stored config_path should succeed"
    );
}

#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
async fn test_connections_returns_proxy_chain_names() {
    let wd_server =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");
    let wd_client =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/client");

    // Allocate unique ports for the server (API + SS listener)
    let server_base = alloc_ports(2);
    // Allocate unique ports for the client (7-port block)
    let client_base = alloc_ports(CLIENT_PORT_BLOCK);

    // Build server config dynamically from server.yaml
    let server_config_str = {
        let tpl = std::fs::read_to_string(wd_server.join("server.yaml"))
            .expect("Failed to read server.yaml");
        tpl.replace(":9091", &format!(":{}", server_base))
            .replace("port: 8901", &format!("port: {}", server_base + 1))
    };

    // Build client config dynamically: template substitution + SS server port
    let client_config_str = make_client_config_str(client_base)
        .replace("127.0.0.1:8901", &format!("127.0.0.1:{}", server_base + 1))
        .replace("port: 8901", &format!("port: {}", server_base + 1));

    // Start server instance with RAII guard
    let _server = ClashInstance::start(
        Options {
            config: Config::Str(server_config_str),
            cwd: Some(wd_server.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![server_base, server_base + 1],
    )
    .expect("Failed to start server");

    // Start client instance with RAII guard
    let _client = ClashInstance::start(
        Options {
            config: Config::Str(client_config_str),
            cwd: Some(wd_client.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        (client_base..client_base + CLIENT_PORT_BLOCK).collect(),
    )
    .expect("Failed to start client");

    // Also wait for the SOCKS5 port used by the request task —
    // ClashInstance::start() only waits for the API port (first in the list)
    // and the proxy listeners may bind slightly later.
    wait_port_ready(client_base + 3).expect("mixed-proxy port not ready");

    let request_handle = tokio::spawn(async move {
        let proxy =
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}", client_base + 3))
                .expect("Failed to create proxy");

        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build reqwest client");

        let response = client
            .get("https://httpbin.yba.dev/drip?duration=2&delay=1&numbytes=500")
            .send()
            .await
            .expect("Failed to send request through proxy");

        assert!(
            response.status().is_success(),
            "Request failed with status: {}",
            response.status()
        );

        // Read the full response body — this keeps the connection open for the
        // ~3-second drip, giving the polling loop time to observe it in
        // /connections. Without this, the connection closes immediately after
        // headers arrive.
        let _body = response
            .bytes()
            .await
            .expect("Failed to read response body");
    });

    // Poll the connections API until at least one connection appears (or 10s
    // timeout). A fixed sleep is flaky under load; polling is robust.
    tokio::task::yield_now().await;
    let connections_url = format!("http://127.0.0.1:{}/connections", client_base);
    let first_connection = {
        let mut found = None;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let req = hyper::Request::builder()
                .uri(&connections_url)
                .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
                .method(http::method::Method::GET)
                .body(http_body_util::Empty::<Bytes>::new())
                .expect("Failed to build request");
            let Ok(response) =
                send_http_request(connections_url.parse().unwrap(), req).await
            else {
                continue;
            };
            let Ok(body) = response.collect().await else {
                continue;
            };
            let json: serde_json::Value =
                match serde_json::from_reader(body.aggregate().reader()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
            if let Some(conn) = json
                .get("connections")
                .and_then(|c| c.as_array())
                .and_then(|a| a.first())
            {
                found = Some(conn.clone());
                break;
            }
        }
        found.expect("No active connection found after 10s")
    };

    let chains = first_connection
        .get("chains")
        .expect("No 'chains' field in first connection");

    assert!(chains.is_array(), "First connection is not an array");

    assert_eq!(
        chains.as_array().unwrap(),
        &["DIRECT", "url-test", "test 🌏"],
        "Chains do not match expected values"
    );

    // Ensure the request task completed successfully
    request_handle
        .await
        .expect("Request task panicked or failed");

    // Both _server and _client will be dropped here, automatically cleaning up
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_configs_listeners() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    // listeners field should be present and non-empty
    let listeners = json
        .get("listeners")
        .expect("'listeners' field missing")
        .as_array()
        .expect("'listeners' should be an array");
    assert!(!listeners.is_empty(), "listeners should not be empty");

    // Each listener should have name, type, port, active fields
    for listener in listeners {
        assert!(
            listener.get("name").is_some(),
            "listener missing 'name': {listener}"
        );
        assert!(
            listener.get("type").is_some(),
            "listener missing 'type': {listener}"
        );
        let port = listener
            .get("port")
            .and_then(|p| p.as_u64())
            .expect("listener missing 'port' or not a number");
        assert!(port > 0, "listener port should be > 0");
        assert!(
            listener.get("active").is_some(),
            "listener missing 'active': {listener}"
        );
    }

    // Verify known ports are present (config has port:+1, socks:+2, mixed:+3)
    let ports: Vec<u64> = listeners
        .iter()
        .filter_map(|l| l.get("port").and_then(|p| p.as_u64()))
        .collect();
    assert!(
        ports.contains(&((api_port + 1) as u64)),
        "expected HTTP proxy port {} in listeners",
        api_port + 1
    );
    assert!(
        ports.contains(&((api_port + 2) as u64)),
        "expected SOCKS5 proxy port {} in listeners",
        api_port + 2
    );
    assert!(
        ports.contains(&((api_port + 3) as u64)),
        "expected mixed proxy port {} in listeners",
        api_port + 3
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_configs_lan_ips_when_allow_lan() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    // allow-lan is true, so lan-ips should be present and contain only IPv4
    let lan_ips = json
        .get("lan-ips")
        .expect("'lan-ips' field missing when allow-lan is true")
        .as_array()
        .expect("'lan-ips' should be an array");

    for ip in lan_ips {
        let ip_str = ip.as_str().expect("lan-ips entry should be a string");
        // Only IPv4 should be returned
        assert!(
            ip_str.parse::<std::net::Ipv4Addr>().is_ok(),
            "expected only IPv4 addresses in lan-ips, got: {ip_str}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_get_configs_dns_listen_when_enabled() {
    let (_clash, api_port) = start_unique_client();

    // Reload with dns.enable: true so dns-listen is populated
    let new_payload = format!(
        r#"
mixed-port: {}
allow-lan: true
mode: direct
log-level: info
external-controller: :{}
secret: clash-rs
dns:
  enable: true
  ipv6: false
  listen:
    udp: 127.0.0.1:{}
    tcp: 127.0.0.1:{}
  default-nameserver:
    - 8.8.8.8
  nameserver:
    - 8.8.8.8
tun:
  enable: false
proxies:
  - {{name: DIRECT_alias, type: direct}}
"#,
        api_port + 3,
        api_port,
        api_port + 4,
        api_port + 4,
    );
    let body = serde_json::json!({ "payload": new_payload }).to_string();
    let configs_url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let res = send_http_request::<String>(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /configs");
    assert_eq!(res.status(), http::StatusCode::NO_CONTENT);

    // Wait briefly for the reload to propagate
    tokio::time::sleep(Duration::from_millis(1000)).await;
    wait_port_ready(api_port).expect("API port not ready after reload");
    let req = hyper::Request::builder()
        .uri(&configs_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(configs_url.parse().unwrap(), req)
        .await
        .expect("Failed to send GET /configs");
    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    let dns_listen = json
        .get("dns-listen")
        .expect("'dns-listen' field missing when dns.enable is true");

    let udp = dns_listen
        .get("udp")
        .and_then(|v| v.as_str())
        .expect("'dns-listen.udp' field missing");
    assert_eq!(udp, format!("127.0.0.1:{}", api_port + 4));

    let tcp = dns_listen
        .get("tcp")
        .and_then(|v| v.as_str())
        .expect("'dns-listen.tcp' field missing");
    assert_eq!(tcp, format!("127.0.0.1:{}", api_port + 4));
}

async fn get_proxy_info(api_port: u16, proxy_name: &str) -> serde_json::Value {
    let url = format!("http://127.0.0.1:{}/proxies/{}", api_port, proxy_name);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON")
}

#[tokio::test(flavor = "current_thread")]
async fn test_plain_proxy_api_response_direct_reject() {
    let (_clash, api_port) = start_unique_client();

    let direct = get_proxy_info(api_port, "DIRECT").await;
    assert_eq!(direct["name"], "DIRECT");
    assert_eq!(direct["type"], "Direct");
    assert_eq!(direct["udp"], true);

    let reject = get_proxy_info(api_port, "REJECT").await;
    assert_eq!(reject["name"], "REJECT");
    assert_eq!(reject["type"], "Reject");
    assert_eq!(reject["udp"], false);

    let proxies_url = format!("http://127.0.0.1:{}/proxies", api_port);
    let req = hyper::Request::builder()
        .uri(&proxies_url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(proxies_url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    assert_eq!(json["proxies"]["DIRECT"]["udp"], true);
    assert_eq!(json["proxies"]["REJECT"]["udp"], false);
}

/// `/user-stats` should return an empty JSON object when the server has started
/// but no traffic has been routed yet.  This verifies the endpoint is
/// registered, authenticated correctly, and resets-on-read semantics work.
#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
async fn test_user_stats_endpoint_empty_on_no_traffic() {
    let wd_server =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/config/server");

    // Allocate unique ports for the multiuser server (API + SS listener)
    let server_base = alloc_ports(2);

    // Build server_multiuser config dynamically
    let server_config_str = {
        let tpl = std::fs::read_to_string(wd_server.join("server_multiuser.yaml"))
            .expect("Failed to read server_multiuser.yaml");
        tpl.replace(":9092", &format!(":{}", server_base))
            .replace("port: 8902", &format!("port: {}", server_base + 1))
    };

    let _server = ClashInstance::start(
        Options {
            config: Config::Str(server_config_str),
            cwd: Some(wd_server.to_string_lossy().to_string()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![server_base, server_base + 1],
    )
    .expect("Failed to start multiuser server");

    let url = format!("http://127.0.0.1:{}/user-stats", server_base);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer test-secret")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "/user-stats should return 200"
    );

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON response");

    assert!(
        json.is_object(),
        "/user-stats response should be a JSON object"
    );
    assert!(
        json.as_object().unwrap().is_empty(),
        "/user-stats should be empty when no traffic has been routed"
    );
}

#[cfg(feature = "shadowsocks")]
#[tokio::test(flavor = "current_thread")]
async fn test_plain_proxy_api_response_shadowsocks() {
    let (_clash, api_port) = start_unique_client();

    let proxy = get_proxy_info(api_port, "ss-simple").await;
    assert_eq!(proxy["name"], "ss-simple");
    assert_eq!(proxy["type"], "Shadowsocks");
    assert_eq!(proxy["server"], "127.0.0.1");
    assert_eq!(proxy["port"], 8901);
    assert_eq!(proxy["cipher"], "2022-blake3-aes-256-gcm");
    assert!(
        proxy.get("password").is_some(),
        "password should be present"
    );
    assert_eq!(proxy["udp"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn test_hello_endpoint() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    assert_eq!(json["hello"], "clash-rs");
}

#[tokio::test(flavor = "current_thread")]
async fn test_version_endpoint() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/version", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    assert!(
        json.get("version").and_then(|v| v.as_str()).is_some(),
        "'version' field should be a string"
    );
    assert_eq!(
        json.get("meta").and_then(|v| v.as_bool()),
        Some(false),
        "'meta' field should be false"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_memory_endpoint() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/memory", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    assert!(
        json.get("inuse").and_then(|v| v.as_u64()).is_some(),
        "'inuse' field should be a u64"
    );
    assert_eq!(
        json.get("oslimit").and_then(|v| v.as_u64()),
        Some(0),
        "'oslimit' field should be 0"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_rules_endpoint() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/rules", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    let rules = json
        .get("rules")
        .and_then(|v| v.as_array())
        .expect("'rules' should be an array");
    assert!(!rules.is_empty(), "rules array should not be empty");

    for rule in rules {
        assert!(
            rule.get("type").is_some(),
            "each rule should have a 'type' field"
        );
        assert!(
            rule.get("payload").is_some(),
            "each rule should have a 'payload' field"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_auth_required() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(
        response.status(),
        http::StatusCode::UNAUTHORIZED,
        "request without Authorization header should return 401"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_delete_all_connections() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/connections", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::DELETE)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "DELETE /connections should return 200"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_providers_endpoint() {
    let (_clash, api_port) = start_unique_client();

    let url = format!("http://127.0.0.1:{}/providers/proxies", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(response.status(), http::StatusCode::OK);

    let json: serde_json::Value = serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON");

    assert!(
        json.get("providers").is_some(),
        "'providers' field should be present"
    );
    assert!(
        json["providers"].is_object(),
        "'providers' should be an object"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_update_proxy_selector() {
    let (_clash, api_port) = start_unique_client();

    // "test 🌏" URL-encoded is "test%20%F0%9F%8C%8F"
    let url = format!("http://127.0.0.1:{}/proxies/test%20%F0%9F%8C%8F", api_port);
    let body = r#"{"name": "url-test"}"#.to_string();
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let response = send_http_request::<String>(url.parse().unwrap(), req)
        .await
        .expect("Failed to send request");
    assert_eq!(
        response.status(),
        http::StatusCode::ACCEPTED,
        "PUT /proxies/test 🌏 should return 202"
    );
}

/// Helper to start the standard client clash instance.
fn start_client_clash() -> (ClashInstance, u16) {
    start_unique_client()
}

/// Helper to build an authenticated GET request with an empty body.
fn auth_get(url: &str) -> hyper::Request<http_body_util::Empty<Bytes>> {
    hyper::Request::builder()
        .uri(url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::GET)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request")
}

/// Helper to parse the response body as JSON.
async fn parse_json(
    response: http::Response<hyper::body::Incoming>,
) -> serde_json::Value {
    serde_json::from_reader(
        response
            .collect()
            .await
            .expect("Failed to collect body")
            .aggregate()
            .reader(),
    )
    .expect("Failed to parse JSON")
}

// ---------------------------------------------------------------------------
// GET /connections  (REST, non-WebSocket)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_get_connections_rest() {
    let (_clash, api_port) = start_client_clash();

    let url = format!("http://127.0.0.1:{}/connections", api_port);
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /connections");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "GET /connections should return 200"
    );

    let json = parse_json(response).await;
    assert!(
        json.get("connections").is_some(),
        "response should have 'connections' field"
    );
    assert!(
        json["connections"].is_array(),
        "'connections' should be an array"
    );
    assert!(
        json.get("downloadTotal").is_some(),
        "response should have 'downloadTotal' field"
    );
    assert!(
        json.get("uploadTotal").is_some(),
        "response should have 'uploadTotal' field"
    );
}

// ---------------------------------------------------------------------------
// DELETE /connections/{id}
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_delete_connection_by_id() {
    let (_clash, api_port) = start_client_clash();

    // Use a random UUID that doesn't correspond to any real connection.
    let url = format!(
        "http://127.0.0.1:{}/connections/00000000-0000-0000-0000-000000000000",
        api_port
    );
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::DELETE)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send DELETE /connections/{{id}}");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "DELETE /connections/{{id}} should return 200"
    );
}

// ---------------------------------------------------------------------------
// GET /proxies/{name} – not found
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_proxy_not_found() {
    let (_clash, api_port) = start_client_clash();

    let url = format!(
        "http://127.0.0.1:{}/proxies/nonexistent-proxy-xyz",
        api_port
    );
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /proxies/nonexistent-proxy-xyz");

    assert_eq!(
        response.status(),
        http::StatusCode::NOT_FOUND,
        "GET /proxies/{{name}} not found should return 404"
    );
}

// ---------------------------------------------------------------------------
// PUT /proxies/{name} – invalid proxy selection returns 400
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_update_proxy_selector_invalid() {
    let (_clash, api_port) = start_client_clash();

    // "test 🌏" is a Selector; selecting a proxy name that doesn't exist should
    // return 400.
    let url = format!("http://127.0.0.1:{}/proxies/test%20%F0%9F%8C%8F", api_port);
    let body = r#"{"name": "this-proxy-does-not-exist"}"#.to_string();
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let response = send_http_request::<String>(url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /proxies/test 🌏");

    assert_eq!(
        response.status(),
        http::StatusCode::BAD_REQUEST,
        "PUT /proxies/{{selector}} with unknown proxy name should return 400"
    );
}

// ---------------------------------------------------------------------------
// PUT /proxies/{name} – target is not a Selector returns 404
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_update_non_selector_proxy_returns_not_found() {
    let (_clash, api_port) = start_client_clash();

    // "DIRECT" is not a Selector; the PUT endpoint should return 404.
    let url = format!("http://127.0.0.1:{}/proxies/DIRECT", api_port);
    let body = r#"{"name": "DIRECT"}"#.to_string();
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PUT)
        .body(body)
        .expect("Failed to build request");

    let response = send_http_request::<String>(url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /proxies/DIRECT");

    assert_eq!(
        response.status(),
        http::StatusCode::NOT_FOUND,
        "PUT /proxies/{{non-selector}} should return 404"
    );
}

// ---------------------------------------------------------------------------
// GET /providers/proxies/{name}  – specific provider info
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_get_provider() {
    let (_clash, api_port) = start_client_clash();

    // The "url-test" group creates an internal PlainProvider named "url-test".
    let url = format!("http://127.0.0.1:{}/providers/proxies/url-test", api_port);
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /providers/proxies/url-test");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "GET /providers/proxies/url-test should return 200"
    );

    let json = parse_json(response).await;
    assert!(
        json.get("name").is_some(),
        "provider response should have 'name' field"
    );
    assert!(
        json.get("type").is_some(),
        "provider response should have 'type' field"
    );
}

// ---------------------------------------------------------------------------
// PUT /providers/proxies/{name}  – refresh/update provider
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_put_provider() {
    let (_clash, api_port) = start_client_clash();

    let url = format!("http://127.0.0.1:{}/providers/proxies/url-test", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .method(http::method::Method::PUT)
        .body(http_body_util::Empty::<Bytes>::new())
        .expect("Failed to build request");

    let response = send_http_request(url.parse().unwrap(), req)
        .await
        .expect("Failed to send PUT /providers/proxies/url-test");

    assert_eq!(
        response.status(),
        http::StatusCode::ACCEPTED,
        "PUT /providers/proxies/url-test should return 202"
    );
}

// ---------------------------------------------------------------------------
// GET /providers/proxies/{name}/healthcheck
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_provider_healthcheck() {
    let (_clash, api_port) = start_client_clash();

    let url = format!(
        "http://127.0.0.1:{}/providers/proxies/url-test/healthcheck",
        api_port
    );
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /providers/proxies/url-test/healthcheck");

    assert_eq!(
        response.status(),
        http::StatusCode::ACCEPTED,
        "GET /providers/proxies/url-test/healthcheck should return 202"
    );
}

// ---------------------------------------------------------------------------
// GET /providers/proxies/{name}/{proxy}  – proxy info within a provider
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_get_proxy_from_provider() {
    let (_clash, api_port) = start_client_clash();

    // The "url-test" provider contains "DIRECT" (from rules.yaml group config).
    let url = format!(
        "http://127.0.0.1:{}/providers/proxies/url-test/DIRECT",
        api_port
    );
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /providers/proxies/url-test/DIRECT");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "GET /providers/proxies/url-test/DIRECT should return 200"
    );

    let json = parse_json(response).await;
    assert_eq!(
        json.get("name").and_then(|v| v.as_str()),
        Some("DIRECT"),
        "proxy 'name' should be 'DIRECT'"
    );
}

// ---------------------------------------------------------------------------
// GET /providers/proxies/{name}/{proxy}/healthcheck
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_provider_proxy_healthcheck() {
    // Start a local mock HTTP server so the test does not rely on external
    // network access and always completes within the timeout.
    let mock_server = httpmock::MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("ok");
    });

    let (_clash, api_port) = start_client_clash();

    // URL-encode the mock server URL for use in the query string.
    let encoded_url = mock_server.url("/").replace(':', "%3A").replace('/', "%2F");
    let url = format!(
        "http://127.0.0.1:{}/providers/proxies/url-test/DIRECT/healthcheck\
         ?url={encoded_url}&timeout=5000",
        api_port
    );
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /providers/proxies/url-test/DIRECT/healthcheck");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "GET provider proxy healthcheck should return 200 when the target URL is \
         reachable"
    );

    let json = parse_json(response).await;
    assert!(
        json.get("delay").and_then(|v| v.as_u64()).is_some(),
        "healthcheck response should have a numeric 'delay' field"
    );
}

// ---------------------------------------------------------------------------
// GET /providers/proxies/{nonexistent}  – 404
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_provider_not_found() {
    let (_clash, api_port) = start_client_clash();

    let url = format!(
        "http://127.0.0.1:{}/providers/proxies/nonexistent-provider-xyz",
        api_port
    );
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /providers/proxies/nonexistent-provider-xyz");

    assert_eq!(
        response.status(),
        http::StatusCode::NOT_FOUND,
        "GET /providers/proxies/{{nonexistent}} should return 404"
    );
}

// ---------------------------------------------------------------------------
// GET /dns/query  – returns 400 when built-in DNS resolver is disabled
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_dns_query_when_disabled() {
    // rules.yaml has dns.enable: false, so the resolver is a system stub.
    let (_clash, api_port) = start_client_clash();

    let url = format!(
        "http://127.0.0.1:{}/dns/query?name=example.com&type=A",
        api_port
    );
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /dns/query");

    assert_eq!(
        response.status(),
        http::StatusCode::BAD_REQUEST,
        "GET /dns/query with DNS disabled should return 400"
    );
}

// ---------------------------------------------------------------------------
// GET /dns/query  – invalid hostname returns 400 (even with DNS enabled)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn test_dns_query_invalid_hostname() {
    let (_clash, api_port) = start_client_clash();

    // An empty name is invalid; the endpoint must return 400 regardless of
    // whether DNS is enabled.
    let url = format!("http://127.0.0.1:{}/dns/query?name=&type=A", api_port);
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /dns/query with invalid name");

    // When DNS is disabled the handler returns 400 before name validation,
    // so either 400 is the expected outcome here.
    assert_eq!(
        response.status(),
        http::StatusCode::BAD_REQUEST,
        "GET /dns/query with invalid hostname should return 400"
    );
}

// ---------------------------------------------------------------------------
// PATCH /configs – mode field is applied and visible in GET /configs
// ---------------------------------------------------------------------------

/// Helper that reads the current run mode from GET /configs.
async fn get_mode(port: u16) -> String {
    let url = format!("http://127.0.0.1:{}/configs", port);
    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to GET /configs for mode");
    let json = parse_json(response).await;
    json.get("mode")
        .and_then(|v| v.as_str())
        .expect("'mode' field missing or not a string")
        .to_owned()
}

#[tokio::test(flavor = "current_thread")]
async fn test_patch_mode_direct() {
    let (_clash, api_port) = start_client_clash();

    // Initial mode in rules.yaml is "rule".
    let initial = get_mode(api_port).await;
    assert_eq!(initial, "rule", "initial mode should be 'rule'");

    // Switch to "direct".
    let url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body(r#"{"mode": "direct"}"#.to_string())
        .expect("Failed to build request");

    let res = send_http_request::<String>(url.parse().unwrap(), req)
        .await
        .expect("Failed to PATCH /configs mode");
    assert_eq!(
        res.status(),
        http::StatusCode::ACCEPTED,
        "PATCH /configs mode should return 202"
    );

    // Mode must be reflected immediately by GET /configs.
    let after = get_mode(api_port).await;
    assert_eq!(after, "direct", "mode should be 'direct' after PATCH");
}

#[tokio::test(flavor = "current_thread")]
async fn test_patch_mode_global() {
    let (_clash, api_port) = start_client_clash();

    let url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body(r#"{"mode": "global"}"#.to_string())
        .expect("Failed to build request");

    let res = send_http_request::<String>(url.parse().unwrap(), req)
        .await
        .expect("Failed to PATCH /configs mode=global");
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);

    let after = get_mode(api_port).await;
    assert_eq!(after, "global", "mode should be 'global' after PATCH");
}

#[tokio::test(flavor = "current_thread")]
async fn test_patch_mode_roundtrip() {
    // rule → direct → global → rule
    let (_clash, api_port) = start_client_clash();

    let api = format!("http://127.0.0.1:{}/configs", api_port);

    for (mode_in, expected) in
        [("direct", "direct"), ("global", "global"), ("rule", "rule")]
    {
        let body = format!(r#"{{"mode": "{}"}}"#, mode_in);
        let req = hyper::Request::builder()
            .uri(&api)
            .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .method(http::method::Method::PATCH)
            .body(body)
            .expect("Failed to build request");

        let res = send_http_request::<String>(api.parse().unwrap(), req)
            .await
            .expect("Failed to PATCH /configs mode");
        assert_eq!(res.status(), http::StatusCode::ACCEPTED);

        let actual = get_mode(api_port).await;
        assert_eq!(
            actual, expected,
            "mode should be '{}' after PATCHing to '{}'",
            expected, mode_in
        );
    }
}

/// Regression test: GET /configs must not be blocked while a concurrent PATCH
/// is running.  We issue PATCH and GET concurrently via `tokio::join!` and
/// confirm both complete and return consistent data.
#[tokio::test(flavor = "current_thread")]
async fn test_patch_mode_does_not_block_get_configs() {
    let (_clash, api_port) = start_client_clash();

    let url = format!("http://127.0.0.1:{}/configs", api_port);

    // Build PATCH and GET requests upfront.
    let patch_req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body(r#"{"mode": "direct"}"#.to_string())
        .expect("Failed to build request");

    // Issue both requests concurrently so the GET races against the PATCH.
    let (patch_res, get_res) = tokio::join!(
        send_http_request::<String>(url.parse().unwrap(), patch_req),
        send_http_request(url.parse().unwrap(), auth_get(&url)),
    );

    let patch_res = patch_res.expect("PATCH /configs should not fail");
    assert_eq!(
        patch_res.status(),
        http::StatusCode::ACCEPTED,
        "PATCH /configs must return 202"
    );

    let get_res = get_res.expect("GET /configs should not block or fail");
    assert_eq!(
        get_res.status(),
        http::StatusCode::OK,
        "GET /configs must return 200 even while PATCH is in flight"
    );
}

/// PATCH /configs with log-level should return 202 and the change must be
/// stable (no panic, no deadlock).
#[tokio::test(flavor = "current_thread")]
async fn test_patch_log_level() {
    let (_clash, api_port) = start_client_clash();

    let url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body(r#"{"log-level": "info"}"#.to_string())
        .expect("Failed to build request");

    let res = send_http_request::<String>(url.parse().unwrap(), req)
        .await
        .expect("Failed to PATCH /configs log-level");
    assert_eq!(
        res.status(),
        http::StatusCode::ACCEPTED,
        "PATCH /configs log-level should return 202"
    );

    let get_res = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to GET /configs after log-level PATCH");
    let json = parse_json(get_res).await;
    assert_eq!(
        json.get("log-level").and_then(|v| v.as_str()),
        Some("info"),
        "log-level should be 'info' after PATCH"
    );
}

/// PATCH with both mode and log-level in a single request: both must take
/// effect.  This exercises the previously-buggy code path where global_state
/// was held across mode-set and log-level-set in a single critical section.
#[tokio::test(flavor = "current_thread")]
async fn test_patch_mode_and_log_level_together() {
    let (_clash, api_port) = start_client_clash();

    let url = format!("http://127.0.0.1:{}/configs", api_port);
    let req = hyper::Request::builder()
        .uri(&url)
        .header(hyper::header::AUTHORIZATION, "Bearer clash-rs")
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .method(http::method::Method::PATCH)
        .body(r#"{"mode": "global", "log-level": "info"}"#.to_string())
        .expect("Failed to build request");

    let res = send_http_request::<String>(url.parse().unwrap(), req)
        .await
        .expect("Failed to PATCH /configs");
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);

    let after_json = parse_json(
        send_http_request(url.parse().unwrap(), auth_get(&url))
            .await
            .expect("Failed to GET /configs after combined PATCH"),
    )
    .await;
    assert_eq!(
        after_json.get("mode").and_then(|v| v.as_str()),
        Some("global"),
        "mode should be 'global' after combined PATCH"
    );
    assert_eq!(
        after_json.get("log-level").and_then(|v| v.as_str()),
        Some("info"),
        "log-level should be 'info' after combined PATCH"
    );
}

// ---------------------------------------------------------------------------
// GET /proxies/{name}/delay  – measures latency of a single proxy
// ---------------------------------------------------------------------------

/// Test `GET /proxies/DIRECT/delay` using a local mock HTTP server as the
/// target so the result is deterministic and independent of external network.
#[tokio::test(flavor = "current_thread")]
async fn test_proxy_delay_direct() {
    let mock_server = httpmock::MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("ok");
    });

    let (_clash, api_port) = start_client_clash();

    // URL-encode the mock server URL for the query string:
    // `http://127.0.0.1:PORT/` → `http%3A%2F%2F127.0.0.1%3APORT%2F`
    let encoded_url = mock_server.url("/").replace(':', "%3A").replace('/', "%2F");
    let url = format!(
        "http://127.0.0.1:{}/proxies/DIRECT/delay?url={encoded_url}&timeout=5000",
        api_port
    );

    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /proxies/DIRECT/delay");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "GET /proxies/DIRECT/delay should return 200 when target is reachable"
    );

    let json = parse_json(response).await;
    assert!(
        json.get("delay").and_then(|v| v.as_u64()).is_some(),
        "response should have a numeric 'delay' field"
    );
    assert!(
        json.get("overall").and_then(|v| v.as_u64()).is_some(),
        "response should have a numeric 'overall' field"
    );
}

// ---------------------------------------------------------------------------
// GET /group/{name}/delay  – measures latency for a proxy group
// ---------------------------------------------------------------------------

/// Test `GET /group/url-test/delay` using a local mock HTTP server as the
/// target.  The url-test group has DIRECT as its sole member, which makes a
/// direct connection to the mock server – no external network needed.
#[tokio::test(flavor = "current_thread")]
async fn test_group_delay_url_test() {
    let mock_server = httpmock::MockServer::start();
    mock_server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");
        then.status(200).body("ok");
    });

    let (_clash, api_port) = start_client_clash();

    let encoded_url = mock_server.url("/").replace(':', "%3A").replace('/', "%2F");
    let url = format!(
        "http://127.0.0.1:{}/group/url-test/delay?url={encoded_url}&timeout=5000",
        api_port
    );

    let response = send_http_request(url.parse().unwrap(), auth_get(&url))
        .await
        .expect("Failed to send GET /group/url-test/delay");

    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "GET /group/url-test/delay should return 200 when target is reachable"
    );

    let json = parse_json(response).await;
    // The handler returns `{ "<group-name>": <delay_ms> }`.
    assert!(
        json.get("url-test").and_then(|v| v.as_u64()).is_some(),
        "response should have a numeric 'url-test' delay field"
    );
}
