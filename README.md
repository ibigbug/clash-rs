<p align="center">
  <a href="https://github.com/Watfaq/clash-rs">
    <img width="200" src="https://github.com/ibigbug/clash-rs/assets/543405/76122ef1-eac8-478a-8ba4-ca5e54f8e272">
  </a>
</p>

<h1 align="center">ClashRS</h1>

<div align="center">

A custom protocol, rule based network proxy software.

[![CI](https://github.com/ibigbug/clash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Watfaq/clash-rs/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ibigbug/clash-rs/graph/badge.svg?token=ZQK5WB63KR)](https://codecov.io/gh/ibigbug/clash-rs)

</div>

## ✨ Features

- 🌈 Flexible traffic routing rules based off source/destination IP/Domain/GeoIP etc.
- 📦 Local anti spoofing DNS with support of UDP/TCP/DoH/DoT remote, and expose it as a local UDP/TCP/DoH/DoT server.
- ⚙️ AnyTLS/Hysteria2/Shadowquic/Shadowsocks/Socks5(TCP/UDP)/SSH/Tailscale/tor(onion)/Trojan/Tuic/VLess/Vmess/Wireguard(userspace) outbound support with different underlying transports(gRPC/TLS/H2/WebSocket/etc.).
- 🔀 Multiple inbound modes: HTTP, SOCKS5, Mixed, Shadowsocks, AnyTLS, Redir, TProxy, and TUN (utun) for transparent proxying.
- 🌍 Dynamic remote rule/proxy loader.
- 🎵 Tracing with Jaeger

## 📡 Protocol Support

### Inbounds

| Type | Description | Notes |
|------|-------------|-------|
| `http` | HTTP proxy | |
| `socks` | SOCKS5 (TCP + UDP) | |
| `mixed` | HTTP + SOCKS5 on a single port | |
| `shadowsocks` | Shadowsocks inbound with multi-user support | `shadowsocks` feature |
| `anytls` | AnyTLS inbound with multi-user support, GFW fallback camouflage | |
| `tun` | TUN device for transparent proxying | All platforms |
| `tproxy` | Transparent proxy (TCP + UDP) | Linux; `tproxy` feature |
| `redir` | TCP redirect | Linux; `redir` feature |
| `tunnel` | Routes all traffic to a fixed target | |

### Outbounds

| Protocol | Transports | Notes |
|----------|-----------|-------|
| `direct` | — | |
| `reject` | — | |
| `ss` | plain · obfs-http · obfs-tls · v2ray-plugin-ws · v2ray-plugin-ws-tls · shadow-tls | `shadowsocks` feature |
| `socks5` | plain TCP · TLS | |
| `anytls` | TLS | |
| `trojan` | TLS · WebSocket+TLS · gRPC+TLS | |
| `vmess` | TCP · TCP+TLS · WebSocket+TLS · H2+TLS · gRPC+TLS | |
| `vless` | TLS · WebSocket+TLS · H2+TLS · gRPC+TLS · REALITY | |
| `wireguard` | UDP (userspace) | `wireguard` feature |
| `hysteria2` | QUIC · obfs-salamander | |
| `tuic` | QUIC (bbr / cubic / new_reno) | `tuic` feature |
| `shadowquic` | QUIC · over-stream | `shadowquic` feature |
| `ssh` | SSH tunnel | `ssh` feature |
| `tor` | Onion routing | `onion` feature (`plus` build) |
| `tailscale` | Mesh VPN | `tailscale` feature (`plus` build) |

## 🖥 Environment Support

- Linux
- macOS
- Windows
  - You need to copy the [wintun.dll](https://wintun.net/) file which matches your architecture to the same directory as your executable and run your program as administrator.
- iOS
  - [![ChocLite App Store](https://developer.apple.com/app-store/marketing/guidelines/images/badge-example-preferred_2x.png)](https://apps.apple.com/by/app/choclite/id6467517938)
  - TestFlight Access: [TestFlight](https://testflight.apple.com/join/cLy4Ub5C)

## 💰 Sponsors
- [Fast Access Cloud](https://fast-access.cloud/)


## 📦 Install

### Use With GUI

https://github.com/LibNyanpasu/clash-nyanpasu

### Download Prebuilt Binary

Can be found at https://github.com/Watfaq/clash-rs/releases

### Docker Image

https://github.com/Watfaq/clash-rs/pkgs/container/clash-rs

### Local Build

Dependencies

* cmake (3.29 or newer)
* libclang([LLVM](https://github.com/llvm/llvm-project/releases/tag/llvmorg-16.0.4))
* [nasm](https://www.nasm.us/pub/nasm/releasebuilds/2.16/win64/) (Windows)
* protoc(for geodata proto generation)
* [pre-commit](https://pre-commit.com/) for managing git hooks

```
$ pipx install pre-commit
$ pre-commit install

$ cargo build
```

## 🔨 Usage

### Example Config

sample.yaml:

```yaml
port: 7890
```

### Run
```shell
-> % ./target/debug/clash-rs -c sample.yaml
```

### Help
```shell
-> % ./target/debug/clash-rs -h
Usage: clash-rs [OPTIONS]

Options:
  -d, --directory <DIRECTORY>      Set working directory (config-relative paths resolve from here)
  -c, --config <FILE>              Specify configuration file [default: config.yaml] [short aliases: f]
  -t, --test-config                Test configuration and exit
  -v, --version                    Print clash-rs version and exit [short aliases: V]
  -l, --log-file <LOG_FILE>        Additionally log to file
      --help-improve               Enable crash report to help improve clash
      --controller-ipc <IPC_PATH>  Specify the IPC path for the controller [aliases: --ext-ctl-pipe, --ext-ctl-unix]
      --compatibility              Enable compatibility mode for mihomo-consistent behavior
  -h, --help                       Print help
```

## FFI

### Compile for apple platforms

To create a framework for iOS and macOS platforms

```shell
git clone https://github.com/Watfaq/clash-rs.git
cd clash-rs
chmod +x scripts/build_apple.sh
./scripts/build_apple.sh
```

This command will generate a `clashrs.xcframework` file in the `build` directory.

## 🔗 Links

- [Documentation](https://watfaq.gitbook.io/clashrs-user-manual/)
- [Config Reference](https://watfaq.github.io/clash-rs/)
- [Roadmap](https://github.com/Watfaq/clash-rs/issues/59)


## 🤝 Contributing

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [Telegram User Group](https://t.me/thisisnotclash)

## ❤️ Inspired By
- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [eycorsican/leaf](https://github.com/eycorsican/leaf)
