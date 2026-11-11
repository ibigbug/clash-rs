# Naive outbound and end-to-end tests

The Naive outbound uses Chromium Cronet through `wind-naive` and supports HTTP/2, QUIC, and optional UDP-over-TCP v2. The `naive` feature is optional and is not included in default builds.

## Building and configuration

Run from the ClashRS repository root:

```sh
cargo build -p clash-rs --features naive --locked
```

On Windows and Linux, the runtime requires a platform-matching `libcronet` library, available from [cronet-binaries](https://github.com/rust-proxy/cronet-binaries/releases). Set its path with `cronet-lib-path`. Apple and Android targets use static linking and require the corresponding library through `CRONET_LIB_DIR`. Alternatively, enable `clash-lib/wind-naive/download` at build time to let the dependency download and verify a prebuilt library. Cross-compilation still requires the target platform's toolchain.

```yaml
proxies:
  - name: naive-out
    type: naive
    server: proxy.example.com
    port: 443
    username: example-user
    password: replace-me
    quic: false
    concurrency: 1
    congestion-controller: default
    request-timeout: 10000
    udp: false
    # ca-cert: ca.pem
    # cronet-lib-path: libcronet-windows-amd64.dll

rules:
  - MATCH,naive-out
```

- `quic` defaults to `false`, selecting HTTP/2. Set it to `true` to enable QUIC.
- `concurrency` defaults to `1` and must be greater than zero. `congestion-controller` accepts `default`, `bbr`, `bbrv2`, `cubic`, and `reno`.
- `request-timeout` is the TCP connection establishment timeout in milliseconds and defaults to `10000`. It also applies to UDP engine initialization. The UDP tunnel is established when the first datagram arrives, and its handshake uses Cronet's timeout.
- Server certificates are verified by default. `ca-cert` accepts a PEM string or a file path. Relative paths in `ca-cert` and `cronet-lib-path` are resolved against the ClashRS working directory.
- `udp: true` uses UoT v2 and requires a compatible server, such as a sing-box Naive inbound. Servers that only support ordinary CONNECT do not support UDP.
- Cronet resolves server addresses and creates sockets itself. `connect-via` / `dialer-proxy`, interface binding, routing marks, an `sni` different from `server`, and `skip-cert-verify: true` are currently unsupported; explicitly configuring these options produces an error. Clash DNS overrides for the server address do not apply to Cronet.

Wind and Cronet are fetched at pinned Git revisions. Normal builds do not depend on neighboring source checkouts.

## Running end-to-end tests

The tests exercise the full path: SOCKS5 client → ClashRS → Wind/Cronet → sing-box Naive inbound → local HTTP/UDP services. They generate short-lived certificates, credentials, and temporary configuration, and clean up child processes. Docker and public proxy servers are not required.

Prepare [sing-box v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) with QUIC support and a Cronet library for the target platform. Specify these dependencies through environment variables. The tests do not download missing dependencies or silently skip when dependencies are unavailable. Previously verified Windows artifacts and their SHA-256 hashes:

| File | SHA-256 |
| --- | --- |
| `sing-box-1.14.4-windows-amd64.zip` | `99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df` |
| `libcronet-windows-amd64.dll` | `cff72d7636b40be5253c04ab35655f5f21b08b0fa8706936150e753ea6964774` |

PowerShell, from the ClashRS repository root:

```powershell
$env:CLASH_NAIVE_SING_BOX = 'C:\tools\sing-box.exe'
$env:CLASH_NAIVE_CRONET_LIB = 'C:\tools\libcronet-windows-amd64.dll'
cargo test -p clash-lib --features naive --test naive_e2e --locked -- --ignored --nocapture
```

Use the same environment variables and Cargo command on Linux and macOS. On macOS, configure the static library first; `CLASH_NAIVE_CRONET_LIB` is not needed when statically linked. Runtime behavior on these platforms must be verified separately.

Test coverage:

1. Three concurrent HTTP/2 connections each round-trip 256 KiB, crossing the initial padding and adapter buffer boundaries. The tests also check the API type and ensure passwords are not exposed.
2. The same round trips over QUIC. The server listens only on UDP, so success cannot result from an HTTP/2 fallback.
3. Incorrect passwords and untrusted certificates are rejected, and the destination service receives no requests.
4. Two destination ports are accessed within one SOCKS5 UDP association, with response sources and 2048-byte payloads verified.

Normal test runs mark these external-binary tests as ignored. Run the adapter's configuration, handshake error propagation, and cancellation tests separately with:

```sh
cargo test -p clash-lib --features naive --lib naive_ --locked
```
