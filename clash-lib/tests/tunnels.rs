mod common;

use clash_lib::{Config, Options};
use common::{ClashInstance, send_http_request, wait_port_ready};
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

#[test]
fn parse_tunnels_alongside_native_listeners() {
    let config = Config::Str(r#"
listeners:
  - {name: native, type: tunnel, listen: 127.0.0.1, port: 8001, network: [tcp], target: localhost:80}
tunnels:
  - {network: [udp, tcp], address: "[::1]:8002", target: "[::1]:53", proxy: DIRECT}
  - "tcp,localhost:8003,example.org:443"
  - "udp,localhost:8003,example.org:53,REJECT"
"#.into()).try_parse_strict().unwrap();
    assert_eq!(config.listeners.len(), 4);
}

#[test]
fn reject_invalid_tunnels() {
    for entry in [
        "tcp,127.0.0.1:8080",
        "tcp,127.0.0.1:8080,example.org:80,DIRECT,extra",
        "icmp,127.0.0.1:8080,example.org:80",
        "tcp,127.0.0.1:99999,example.org:80",
        "udp,127.0.0.1:8080,:53",
        "tcp,127.0.0.1:8080,example.org/path:80",
        "udp,127.0.0.1:8080,[::1]:65536",
        "udp,127.0.0.1:8080,example.org:53,missing",
    ] {
        assert!(
            Config::Str(format!("tunnels: [{entry:?}]"))
                .try_parse_strict()
                .is_err(),
            "{entry}"
        );
    }
    for entries in [
        r#"["tcp/udp,127.0.0.1:8080,a:80", "udp,127.0.0.1:8080,b:53"]"#,
        r#"[{network: [], address: "127.0.0.1:8080", target: "a:80"}]"#,
        r#"[{network: [tcp], address: "127.0.0.1:8080", target: "a:80", typo: DIRECT}]"#,
    ] {
        assert!(
            Config::Str(format!("tunnels: {entries}"))
                .try_parse_strict()
                .is_err(),
            "{entries}"
        );
    }
}

const LOCAL: Ipv4Addr = Ipv4Addr::LOCALHOST;

// Reserve the same port on both transports before passing it to the core.
async fn reserve() -> (TcpListener, UdpSocket, u16) {
    loop {
        let tcp = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        if let Ok(udp) = UdpSocket::bind((LOCAL, port)).await {
            return (tcp, udp, port);
        }
    }
}

async fn tcp_echo(port: u16, message: &[u8]) -> std::io::Result<()> {
    let mut client = TcpStream::connect((LOCAL, port)).await?;
    client.write_all(message).await?;
    let mut reply = vec![0; message.len()];
    client.read_exact(&mut reply).await?;
    assert_eq!(reply, message);
    Ok(())
}

async fn udp_echo(port: u16, message: &[u8]) -> std::io::Result<()> {
    let client = UdpSocket::bind((LOCAL, 0)).await?;
    client.connect((LOCAL, port)).await?;
    client.send(message).await?;
    let mut reply = [0; 128];
    let len = client.recv(&mut reply).await?;
    assert_eq!(&reply[..len], message);
    Ok(())
}

async fn forwards(port: u16) {
    timeout(Duration::from_secs(5), async {
        tcp_echo(port, b"TCP forwarded").await.unwrap();
        udp_echo(port, b"UDP forwarded").await.unwrap();
    })
    .await
    .unwrap();
}

async fn rejects(port: u16) {
    // The inbound must still accept connections, even when its outbound rejects
    // them.
    wait_port_ready(port).unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(3), tcp_echo(port, b"rejected")).await,
        Ok(Err(_))
    ));
    let response =
        timeout(Duration::from_millis(400), udp_echo(port, b"rejected")).await;
    assert!(!matches!(response, Ok(Ok(()))));
}

async fn reload(api: u16, config: &str) {
    let uri = format!("http://{LOCAL}:{api}/configs");
    let req = hyper::Request::put(&uri)
        .header("content-type", "application/json")
        .body(serde_json::json!({"payload": config}).to_string())
        .unwrap();
    let res = send_http_request(uri.parse().unwrap(), req).await.unwrap();
    assert_eq!(res.status(), http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn forward_and_reload_tcp_and_udp() {
    let (tcp, udp, target) = reserve().await;
    let (_tcp_echo, _udp_echo) = (
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        }),
        tokio::spawn(async move {
            let mut buf = [0; 256];
            while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                udp.send_to(&buf[..len], peer).await.unwrap();
            }
        }),
    );
    let (api_tcp, api_udp, api) = reserve().await;
    let (pinned_tcp, pinned_udp, pinned) = reserve().await;
    let (routed_tcp, routed_udp, routed) = reserve().await;
    let base = format!(
        "external-controller: {LOCAL}:{api}\nproxy-groups: [{{name: outbound, \
         type: select, proxies: [DIRECT]}}]\n"
    );
    let config = |mode: &str, proxy: &str| {
        format!(
            r#"{base}
mode: {mode}
rules: ["MATCH,REJECT"]
tunnels:
  - {{ network: [tcp, udp], address: "{LOCAL}:{pinned}", target: "{LOCAL}:{target}", proxy: {proxy} }}
  - "tcp/udp,{LOCAL}:{routed},{LOCAL}:{target}"
"#
        )
    };
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("nodes.yaml"),
        "proxies: [{name: provider-node, type: direct}]",
    )
    .unwrap();
    drop((
        api_tcp, api_udp, pinned_tcp, pinned_udp, routed_tcp, routed_udp,
    ));
    let _instance = ClashInstance::start(
        Options {
            config: Config::Str(config("rule", "outbound")),
            cwd: Some(dir.path().to_string_lossy().into_owned()),
            rt: None,
            log_file: None,
            config_path: None,
        },
        vec![api, pinned, routed],
    )
    .unwrap();

    forwards(pinned).await;
    rejects(routed).await;
    reload(api, &config("direct", "REJECT")).await;
    forwards(routed).await;
    rejects(pinned).await;
    let with_provider = |mode, proxy| {
        format!(
            "{}\nproxy-providers: {{nodes: {{type: file, path: nodes.yaml, \
             health-check: {{enable: false}}}}}}",
            config(mode, proxy)
        )
    };
    reload(api, &with_provider("rule", "provider-node")).await;
    forwards(pinned).await;
    // Keep the source port and tunnel alive across a provider-only update.
    let client = UdpSocket::bind((LOCAL, 0)).await.unwrap();
    client.connect((LOCAL, pinned)).await.unwrap();
    let mut reply = [0; 32];
    client.send(b"before").await.unwrap();
    let n = timeout(Duration::from_secs(3), client.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..n], b"before");
    std::fs::write(
        dir.path().join("nodes.yaml"),
        "proxies: [{name: provider-node, type: reject}]",
    )
    .unwrap();
    let uri = format!("http://{LOCAL}:{api}/providers/proxies/nodes");
    let req = hyper::Request::put(&uri).body(String::new()).unwrap();
    let res = send_http_request(uri.parse().unwrap(), req).await.unwrap();
    assert_eq!(res.status(), http::StatusCode::ACCEPTED);
    client.send(b"after").await.unwrap();
    assert!(
        timeout(Duration::from_millis(400), client.recv(&mut reply))
            .await
            .is_err(),
        "first packet after provider replacement still used the direct association"
    );
    reload(api, &with_provider("direct", "removed-node")).await;
    rejects(pinned).await;
    reload(api, &base).await;
    for port in [pinned, routed] {
        TcpListener::bind((LOCAL, port)).await.unwrap();
        UdpSocket::bind((LOCAL, port)).await.unwrap();
    }
}
