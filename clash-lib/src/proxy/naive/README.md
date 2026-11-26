# Naive outbound

Use a ClashRS build with the `naive` feature. Add a proxy to your configuration:

```yaml
proxies:
  - name: naive
    type: naive
    server: proxy.example.com
    port: 443
    username: your-username
    password: your-password
```

HTTP/2 is the default. Set `quic: true` for QUIC or `udp: true` for UDP over TCP if your server supports it.

If your build uses a shared Cronet library, set `cronet-lib-path` in the main configuration to select it. All proxies in the process use the first library loaded. Restart ClashRS after changing the path.

To build ClashRS with Cronet included on a supported platform, run:

```sh
cargo build --locked -p clash-rs --features naive-static,naive-download
```

With TUN, Naive supports outbound interface selection on Linux, macOS and Windows. Routing marks are supported on Linux. Android ignores both settings.

If ClashRS cannot resolve the proxy hostname, set `dns.proxy-server-nameserver` or add the hostname to `dns.fake-ip-filter`. After a connection failure, the next connection checks for a new address.
