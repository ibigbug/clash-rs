mod datagram;
mod routes;
pub mod runner;
pub use runner::TunRunner;
mod stream;
mod system;

#[cfg(target_os = "linux")] // for tproxy
pub use datagram::TunDatagram;

#[cfg(test)]
mod tests {
    use std::thread;

    use crate::{Config, Options, shutdown, start_scaffold};

    fn wait_port_open(port: u16) {
        let mut count = 0;
        while count < 30 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            count += 1;
            thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    #[test]
    #[ignore = "only run this test locally, to not deal with the tun device \
                permission"]
    fn test_individual_routes() {
        let conf = r#"
    socks-port: 7891
    bind-address: 127.0.0.1
    mmdb: "Country.mmdb"
    log-level: trace
    tun:
      enable: true
      device-id: "dev://utun1989"
      route-all: false
      routes:
        - 1.1.1.1/32
      gateway: "198.19.0.1/32"
      so-mark: 3389
    "#;

        let cwd = tempfile::tempdir()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string();

        let log_file = uuid::Uuid::new_v4().to_string() + ".log";

        let cwd_clone = cwd.clone();
        let log_file_clone = log_file.clone();

        let handle = thread::spawn(|| {
            start_scaffold(Options {
                config: Config::Str(conf.to_string()),
                cwd: Some(cwd_clone),
                rt: None,
                log_file: Some(log_file_clone),
                config_path: None,
            })
            .unwrap()
        });

        wait_port_open(7891);

        let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let req = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x62\x61\x69\x64\x75\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
        udp_socket
            .send_to(req, "1.1.1.1:53")
            .inspect_err(|x| {
                panic!("failed to send udp packet: {x:?}");
            })
            .unwrap();

        let mut buf = [0u8; 1024];
        udp_socket.recv_from(&mut buf).unwrap();

        assert_eq!(buf[0], req[0]);

        assert!(shutdown());

        thread::sleep(std::time::Duration::from_secs(1));

        let today = chrono::Utc::now().format("%Y-%m-%d");

        let log_path = cwd + "/" + &log_file + "." + &today.to_string();

        let logs = std::fs::read_to_string(&log_path)
            .unwrap_or_else(|_| panic!("failed to read log file: {}", log_path));

        assert!(logs.contains("1.1.1.1:53 to MATCH"));

        handle.join().unwrap();
    }

    #[test]
    #[ignore = "it's hard to test as altering the routing table can cause ssh \
                connection lost"]
    fn test_route_all() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "Country.mmdb"
        log-level: trace
        tun:
          enable: true
          device-id: "dev://utun1989"
          route-all: true
          gateway: "198.19.0.1/32"
          so-mark: 3389
        "#;

        let cwd = tempfile::tempdir()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .to_string();

        let log_file = uuid::Uuid::new_v4().to_string() + ".log";

        let cwd_clone = cwd.clone();
        let log_file_clone = log_file.clone();

        let handle = thread::spawn(|| {
            start_scaffold(Options {
                config: Config::Str(conf.to_string()),
                cwd: Some(cwd_clone),
                rt: None,
                log_file: Some(log_file_clone),
                config_path: None,
            })
            .unwrap()
        });

        wait_port_open(7891);

        let echo_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo_server.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                let (n, src) = echo_server.recv_from(&mut buf).unwrap();
                echo_server.send_to(&buf[..n], src).unwrap();
            }
        });

        let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp_socket.send_to(b"hello", echo_addr).unwrap();
        let mut buf = [0u8; 1024];
        udp_socket.recv_from(&mut buf).unwrap();

        assert_eq!(b"hello", &buf[..5]);

        assert!(shutdown());

        thread::sleep(std::time::Duration::from_secs(1));

        let today = chrono::Utc::now().format("%Y-%m-%d");

        let log_path = cwd + "/" + &log_file + "." + &today.to_string();

        let logs = std::fs::read_to_string(&log_path)
            .unwrap_or_else(|_| panic!("failed to read log file: {}", log_path));

        assert!(logs.contains("route_all is enabled"));
        assert!(logs.contains(format!("{} to MATCH", echo_addr).as_str()));

        handle.join().unwrap();
    }
}
