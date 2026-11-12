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

Like the other protocol tests, these tests use `DockerTestRunner` and are enabled by `CLASH_DOCKER_TEST=true`. They exercise the full path: SOCKS5 client → ClashRS → Wind/Cronet → a sing-box Naive inbound in Docker → HTTP/UDP echo services on the test host.

The shared runner pulls the official `ghcr.io/sagernet/sing-box:v1.14.4` image, mounts temporary configuration and short-lived TLS certificates, publishes TCP/UDP ports, waits for server readiness, and removes the container after each test. Container logs are printed during cleanup. No locally installed sing-box binary or public proxy server is required. The tests fail if Docker, the image, or Cronet is unavailable; they do not silently skip missing dependencies.

Start a Docker daemon running Linux containers and prepare the host platform's Cronet library as described above. Run from the ClashRS repository root:

```powershell
$env:CLASH_DOCKER_TEST = 'true'
$env:CLASH_NAIVE_CRONET_LIB = 'C:\tools\libcronet-windows-amd64.dll'
cargo test -p clash-lib --features naive --test naive_e2e --locked -- --nocapture
```

On Linux:

```sh
CLASH_DOCKER_TEST=true \
CLASH_NAIVE_CRONET_LIB=/absolute/path/to/libcronet.so \
cargo test -p clash-lib --features naive --test naive_e2e --locked -- --nocapture
```

Alternatively, add `wind-naive/download` to `--features` to download a verified prebuilt Cronet library during the build. Apple targets require the static library configured through `CRONET_LIB_DIR`; they do not use `CLASH_NAIVE_CRONET_LIB`.

For a remote Docker daemon, set `DOCKER_HOST` and `CLIENT_IP`. The shared runner uploads fixtures through the Docker API, and the client connects to the published port on the daemon's host. `CLIENT_IP` must be an IPv4 address of the test host reachable from the container. For local Docker, the tests use the bridge gateway on Linux and resolve `host.docker.internal` inside the container on Docker Desktop. Set `CLIENT_IP` explicitly for other network layouts. The HTTP/UDP echo services bind to all IPv4 interfaces so the container can reach them; host firewall rules must allow this traffic.

Test coverage:

1. Three concurrent HTTP/2 requests each round-trip 256 KiB, crossing the initial padding and adapter buffer boundaries. The tests also check the API type and ensure passwords are not exposed.
2. The same round trips over QUIC. The server listens only on UDP, so success cannot result from an HTTP/2 fallback.
3. A successful control request establishes connectivity before testing incorrect passwords and untrusted certificates. Rejected tunnels must deliver no requests to the destination service.
4. Two destination ports are accessed within one SOCKS5 UDP association, with response sources and 2048-byte payloads verified.

Without `CLASH_DOCKER_TEST`, the Docker tests are excluded at compile time, matching the other protocol modules. `--ignored` is not needed. Run the adapter's configuration, handshake error propagation, and cancellation tests separately with:

```sh
cargo test -p clash-lib --features naive --lib naive_ --locked
```
