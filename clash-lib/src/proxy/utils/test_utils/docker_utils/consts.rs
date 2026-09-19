pub const LOCAL_ADDR: &str = "127.0.0.1";

#[allow(dead_code)]
pub const IMAGE_WG: &str = "docker.io/linuxserver/wireguard:1.0.20210914-legacy";
// image with v2ray-plugin pre-installed
#[cfg(feature = "shadowsocks")]
pub const IMAGE_SS_RUST: &str = "teddysun/shadowsocks-rust:alpine-1.22.0";
#[cfg(feature = "shadowsocks")]
pub const IMAGE_SHADOW_TLS: &str = "ghcr.io/ihciah/shadow-tls:latest";
#[cfg(feature = "shadowsocks")]
pub const IMAGE_OBFS: &str = "gists/simple-obfs:latest";
pub const IMAGE_TROJAN_GO: &str = "p4gefau1t/trojan-go:latest";
pub const IMAGE_VMESS: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_VLESS: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_XRAY: &str = "teddysun/xray:26.3.27";
pub const IMAGE_SOCKS5: &str = "v2fly/v2fly-core:v4.45.2";
#[cfg(all(feature = "ssh", docker_test))]
pub const IMAGE_OPENSSH: &str = "docker.io/linuxserver/openssh-server:latest";
pub const IMAGE_HYSTERIA: &str = "tobyxdd/hysteria:latest";
#[cfg(all(feature = "tuic", docker_test, throughput_test))]
pub const IMAGE_TUIC: &str = "ghcr.io/itsusinn/tuic-server:latest";
#[cfg(feature = "shadowquic")]
pub const IMAGE_SHADOWQUIC: &str = "ghcr.io/spongebob888/shadowquic:latest";
pub const IMAGE_SINGBOX: &str = "ghcr.io/sagernet/sing-box:v1.13.8";
#[cfg(all(docker_test, throughput_test))]
pub const IMAGE_NETEM: &str = "nicolaka/netshoot:latest";
