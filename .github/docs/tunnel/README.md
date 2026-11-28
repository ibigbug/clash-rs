# Tunnel inbound

Top-level `tunnels` forward TCP and UDP to a fixed target. Set `proxy` to a proxy
or group name to use that outbound in every mode. Provider nodes are looked up by
name when traffic arrives. If the named outbound is unavailable, the tunnel drops
the traffic. Omit `proxy` to use normal routing.

```yaml
tunnels:
  - network: [tcp, udp]
    address: 127.0.0.1:1053
    target: 192.0.2.53:53
    proxy: DIRECT
  - "tcp,127.0.0.1:8443,example.org:443"
```
