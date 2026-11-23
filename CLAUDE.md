# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ClashRS is a custom protocol, rule-based network proxy software written in Rust. It's a high-performance proxy with support for multiple protocols (Shadowsocks/SS2022, Trojan, VMess, VLESS, WireGuard, Tor, TUIC, Hysteria2, ShadowQUIC, AnyTLS, SSH, Tailscale, Socks5), flexible routing rules, DNS anti-spoofing, and cross-platform support.

## Workspace Structure

This is a Rust workspace with six main crates:
- `clash-bin/` - Main binary executable
- `clash-lib/` - Core library containing all proxy logic
- `clash-doc/` - Documentation generation
- `clash-ffi/` - FFI bindings for mobile platforms
- `clash-dns/` - DNS resolution components
- `clash-netstack/` - Network stack implementation

## Common Commands

### Build
```bash
cargo build                    # Debug build
cargo build --release          # Release build
cargo build --features plus    # Build with all features including Tor
```

### Testing
```bash
cargo test --all --all-features                    # Run all tests
CLASH_RS_CI=true cargo test --all --all-features  # Run tests in CI mode
make test-no-docker                                # Run tests without Docker
```

### Documentation
```bash
make docs                      # Generate documentation
cargo doc -p clash_doc --no-deps  # Generate config docs only
```

### Running
```bash
./target/debug/clash-rs -c config.yaml  # Run with config file
./target/debug/clash-rs -t               # Test configuration
./target/debug/clash-rs -h               # Show help
./target/debug/clash-rs -l logfile.log   # Additionally log to file
```

### Development Setup
```bash
# Install pre-commit hooks for code quality
pipx install pre-commit
pre-commit install

# Install required dependencies
# - cmake (3.29 or newer)
# - libclang (LLVM)
# - nasm (Windows only)
# - protoc (for geodata proto generation)
```

## Architecture

### Core Components

**clash_lib/src/app/** - Main application modules:
- `api/` - REST API handlers for web dashboard
- `dispatcher/` - Traffic routing and connection management
- `dns/` - DNS resolution with anti-spoofing
- `inbound/` - Inbound connection handling
- `outbound/` - Outbound proxy connections
- `router/` - Rule-based routing logic

**clash_lib/src/proxy/** - Protocol implementations:
- `shadowsocks/`, `trojan/`, `vmess/`, `vless/`, `socks/` - Core proxy protocols
- `hysteria2/`, `tuic/`, `shadowquic/` - QUIC-based protocols
- `anytls/` - AnyTLS protocol (inbound + outbound)
- `wg/` - WireGuard via boringtun
- `ssh/` - SSH tunneling
- `tailscale/` - Tailscale integration
- `tor/` - Tor onion routing
- `group/` - Proxy group types (selector, fallback, load balance)
- `transport/` - Underlying transports (TLS, WebSocket, gRPC, H2, ShadowTLS)
- `tun/`, `tproxy/`, `redir/` - Transparent proxy / TUN device support

**clash_lib/src/config/** - Configuration parsing and validation

### Key Design Patterns

- **Async/await**: Heavy use of Tokio for async networking
- **Trait-based**: Extensible proxy system using traits
- **Error handling**: Comprehensive error types with `thiserror`
- **Feature flags**: Conditional compilation for different protocols
- **Zero-copy**: Optimized data paths where possible
- **Workspace structure**: Uses Rust 2024 edition with resolver = "3"
- **Release optimization**: Configured for size optimization with LTO and strip

## Testing

Tests are located in `clash_lib/tests/` and include:
- `smoke_tests.rs` - Basic functionality tests
- `api_tests.rs` - API endpoint tests (run with `--all-features`; requires `shadowsocks` feature for SS proxies)
- Integration tests with Docker containers for various proxy protocols

Set `CLASH_RS_CI=true` environment variable when running tests to enable CI-specific behavior.

## Version Building

The version string is set at compile time via `CLASH_VERSION_OVERRIDE`:
- **Master branch builds**: `{cargo_version}-alpha+sha.{short_sha}` (e.g. `0.10.2-alpha+sha.abc1234`)
- **Tagged/release builds**: `{cargo_version}` (e.g. `0.10.2`)

The commit SHA is also emitted separately as `CLASH_GIT_SHA_SHORT` and exposed via the `/version` API endpoint as a `commit` field (present only when non-empty).

## Platform-Specific Notes

- **iOS/macOS**: Use `scripts/build_apple.sh` to build XCFramework
- **Windows**: Requires `wintun.dll` in same directory as executable
- **Linux**: Enhanced with platform-specific UDP socket optimizations

## Feature Flags

Key features that can be enabled:
- `shadowsocks` - Shadowsocks/SS2022 protocol support
- `tuic` - TUIC protocol support
- `ssh` - SSH tunnel support
- `onion` - Tor support
- `shadowquic` - ShadowQUIC protocol support
- `wireguard` - WireGuard support via boringtun
- `tailscale` - Tailscale integration
- `tun` - TUN device / transparent proxy
- `tproxy` - Linux and Android TPROXY support
- `redir` - TCP redirect support
- `telemetry` - OpenTelemetry tracing
- `dashboard` - Embedded web dashboard (default on)
- `tokio-console` - Tokio console debugging
- `bench` - Benchmarking tools

## Configuration

The project uses YAML configuration files. Sample configs are in `clash/tests/data/config/`.

Main configuration sections:
- `port` - HTTP/SOCKS proxy port
- `dns` - DNS server settings
- `rules` - Traffic routing rules
- `proxies` - Outbound proxy definitions
- `proxy-groups` - Proxy group configurations

## Git Workflow

**Never commit or push directly to `master`** — always create a PR branch and open a pull request.
