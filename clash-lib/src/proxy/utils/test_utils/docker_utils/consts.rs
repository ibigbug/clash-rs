pub const LOCAL_ADDR: &str = "127.0.0.1";

// Images without a stable version tag are pinned by digest so an upstream
// `:latest` push can't silently change test behaviour. The throughput workflow
// extracts and pre-pulls every `IMAGE_*` reference in this file.

#[allow(dead_code)]
pub const IMAGE_WG: &str = "docker.io/linuxserver/wireguard:1.0.20210914-legacy";
// image with v2ray-plugin pre-installed
#[cfg(feature = "shadowsocks")]
pub const IMAGE_SS_RUST: &str = "teddysun/shadowsocks-rust:alpine-1.22.0";
#[cfg(feature = "shadowsocks")]
pub const IMAGE_SHADOW_TLS: &str =
    "ghcr.io/ihciah/shadow-tls@sha256:\
     0fdc04e9da8a173da3ee7496fc337e5639ba73ad3a8d218367acfdc70b1eae87";
#[cfg(feature = "shadowsocks")]
pub const IMAGE_OBFS: &str =
    "gists/simple-obfs@sha256:\
     d0f6c467294cea2a3538bfe2d440b19e34e58650507dbcbf928955cfa10762af";
pub const IMAGE_TROJAN_GO: &str =
    "p4gefau1t/trojan-go@sha256:\
     05d55cda063b218aa968086ff91b68c425fa59db1a890391136c56af06374e66";
pub const IMAGE_VMESS: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_VLESS: &str = "v2fly/v2fly-core:v4.45.2";
pub const IMAGE_XRAY: &str = "teddysun/xray:26.3.27";
pub const IMAGE_SOCKS5: &str = "v2fly/v2fly-core:v4.45.2";
#[cfg(all(feature = "ssh", docker_test))]
pub const IMAGE_OPENSSH: &str =
    "docker.io/linuxserver/openssh-server@sha256:\
     b07414bb329b86a00525c9256711a7855fc3a369e9f62c36f1de8d1923197580";
pub const IMAGE_HYSTERIA: &str =
    "tobyxdd/hysteria@sha256:\
     92b06917b2abb940e90ea6dc9215c1b1ceea69fa7edc1374daf3cde36e422740";
#[cfg(all(feature = "tuic", docker_test, throughput_test))]
pub const IMAGE_TUIC: &str =
    "ghcr.io/itsusinn/tuic-server@sha256:\
     5b6e23be4b1ae2aee0e7e6b30ef477656d0bd257a024c9b176cd2d293ae9c07d";
#[cfg(feature = "shadowquic")]
pub const IMAGE_SHADOWQUIC: &str =
    "ghcr.io/spongebob888/shadowquic@sha256:\
     753e3993fc9b8d7b33ccf82be1ac889e9f63b77fb0b15af668ab4f5a5b6252ff";
#[cfg(feature = "naive")]
#[allow(dead_code)] // Also included by the standalone Naive integration tests.
pub const IMAGE_NAIVE_SINGBOX: &str = "ghcr.io/sagernet/sing-box:v1.14.4";
pub const IMAGE_SINGBOX: &str = "ghcr.io/sagernet/sing-box:v1.13.8";
#[cfg(all(docker_test, throughput_test))]
pub const IMAGE_NETEM: &str =
    "nicolaka/netshoot@sha256:\
     b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70";
