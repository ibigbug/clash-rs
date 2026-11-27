## Proxy E2E Throughput Tests

### Overview

Each supported proxy protocol and transport combination has an automated
end-to-end throughput test. Tests run against real Docker containers running
the proxy server and measure actual upload and download throughput through the
full clash-rs pipeline (outbound handler → proxy server → echo server).

### Architecture

```
┌─────────────────────────────────────────────────────┐
│ test process                                         │
│                                                      │
│  ┌─────────────┐   SOCKS5   ┌──────────────────┐    │
│  │ test client ├───────────►│ clash-rs process │    │
│  └─────────────┘            └────────┬─────────┘    │
│         ▲                            │ proxy proto   │
│         │ download                   ▼               │
│  ┌──────┴──────┐         ┌──────────────────────┐   │
│  │ echo server │◄────────┤ Docker proxy server  │   │
│  │  (Tokio)   │         │ (xray/v2fly/sing-box) │   │
│  └─────────────┘         └──────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

The echo server is a local Tokio TCP listener. The proxy server runs in a
Docker container. clash-rs is spawned as a subprocess with a SOCKS5 inbound.

### Measurement accuracy

A **sync byte** (`0xAC`) is used as an upload barrier:

1. Client sends `N` bytes (upload) through the proxy
2. Echo server receives all `N` bytes, then sends `0xAC`
3. Client reads `0xAC` → stops upload timer (true E2E delivery time)
4. Client starts download timer → echo server sends `N` bytes back
5. Client receives all bytes → stops download timer

Without the sync byte, fast protocols appear slower on download because the
download timer starts while upload bytes are still in transit.

Each test runs **3 times** and reports the **median ± stdev** across runs to
filter single-run noise.

### Netem tests (adverse network simulation)

Five representative protocols are also tested under a simulated bad network:
**50 ms one-way delay + 1% packet loss**. This shows QUIC-based protocols
(tuic, hysteria2, shadowquic) outperforming TCP-based ones under packet loss.

Network conditions are applied by a short-lived `nicolaka/netshoot` sidecar
container that shares the proxy container's network namespace and runs:

```
tc qdisc add dev eth0 root netem delay 50ms loss 1%
```

No changes are needed to the proxy server Docker images.

### Running locally

```bash
# build first (tests use the debug binary)
cargo build -p clash-rs --all-features

# run all throughput tests for one protocol (e.g. tuic)
CLASH_DOCKER_TEST=1 cargo test -p clash-lib --all-features \
  --test-threads=1 -- throughput_tuic

# run every throughput test
RUSTFLAGS="--cfg throughput_test" \
CLASH_DOCKER_TEST=1 cargo test -p clash-lib --all-features \
  -- --test-threads=1 throughput

# collect results to a JSON-lines file
THROUGHPUT_RESULTS_FILE=results.jsonl \
RUSTFLAGS="--cfg throughput_test" \
CLASH_DOCKER_TEST=1 cargo test -p clash-lib --all-features \
  -- --test-threads=1 throughput

# format results into Markdown tables
python3 bench/format_throughput.py results.jsonl
```

> **Note:** tests are gated on `#[cfg(all(test, docker_test, throughput_test))]`.
> Pass `--cfg throughput_test` via `RUSTFLAGS` (e.g. `RUSTFLAGS="--cfg throughput_test"`) to enable them — `cargo test` does not accept `--cfg` directly.

### CI workflow

The workflow (`.github/workflows/proxy-throughput.yml`) triggers on PRs that
touch proxy or transport code. It:

1. Pre-pulls all required Docker images
2. Builds clash-rs in debug mode
3. Runs all throughput tests (including netem variants)
4. Collects `THROUGHPUT_RESULTS_FILE` output
5. Posts grouped per-protocol Markdown tables as a PR comment

### Result format

Each completed test appends one JSON line to `THROUGHPUT_RESULTS_FILE`:

```json
{
  "label": "tuic-bbr",
  "upload_mbps": 9823.4,
  "download_mbps": 8901.2,
  "upload_stdev_mbps": 42.1,
  "download_stdev_mbps": 38.7,
  "runs": 3,
  "total_bytes": 33554432,
  "netem": null
}
```

`format_throughput.py` groups results by protocol (first hyphen-delimited
segment of the label) and renders one Markdown table per protocol, plus a
separate **Netem Tests** section for labels ending in `-netem`.

### Adding a new test

1. Add a `get_XXX_runner() -> anyhow::Result<DockerTestRunner>` helper that
   starts the proxy server Docker container.
2. Write the test function under `#[cfg(all(test, docker_test, throughput_test))]`:

```rust
#[tokio::test]
async fn e2e_throughput_my_proto_tcp() -> anyhow::Result<()> {
    initialize();
    let socks_port = alloc_port();
    let echo_port = alloc_port();
    let container = get_my_proto_runner().await?;
    let server = container.container_ip().unwrap_or(LOCAL_ADDR.to_owned());
    let gateway_ip = container.docker_gateway_ip();
    let binary = find_clash_rs_binary();
    let config = format!(r#"
socks-port: {socks_port}
...
"#);
    container.run_and_cleanup(async move {
        clash_process_e2e_throughput(
            &binary, &config, "my-proto-tcp",
            socks_port, echo_port, gateway_ip, E2E_PAYLOAD_BYTES,
        ).await.map(|_| ())
    }).await
}
```

3. Add the Docker image to the CI pre-pull step in
   `.github/workflows/proxy-throughput.yml`.
4. Add the protocol to `PROTOCOL_META` in `bench/format_throughput.py` so
   results appear in the correct table section.

---

## To get a flamegraph

```
cargo flamegraph --root -- -d ./clash/tests/data/config/ -f rules.yaml
```

_adjust args on your own_


## An example

### Environment

* client - Debian 12.5 running inside Hyper-V on i9-9900KF and 64GB mem
* server - DS1821+
* connection - 10 Gig cabled

### Direct connect

```
~ » iperf3 -c dsm
Connecting to host dsm, port 5201
[  5] local 10.0.0.14 port 40148 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.03 GBytes  8.87 Gbits/sec    0   3.09 MBytes
[  5]   1.00-2.00   sec  1.05 GBytes  9.06 Gbits/sec    0   3.09 MBytes
[  5]   2.00-3.00   sec  1.09 GBytes  9.37 Gbits/sec    0   3.09 MBytes
[  5]   3.00-4.00   sec  1.04 GBytes  8.90 Gbits/sec    0   3.09 MBytes
[  5]   4.00-5.00   sec  1.06 GBytes  9.07 Gbits/sec    0   3.09 MBytes
[  5]   5.00-6.00   sec  1.04 GBytes  8.93 Gbits/sec    0   3.09 MBytes
[  5]   6.00-7.00   sec  1.05 GBytes  9.00 Gbits/sec    0   3.09 MBytes
[  5]   7.00-8.00   sec  1.08 GBytes  9.24 Gbits/sec    0   3.09 MBytes
[  5]   8.00-9.00   sec  1.07 GBytes  9.15 Gbits/sec    0   3.09 MBytes
[  5]   9.00-10.00  sec  1.05 GBytes  9.02 Gbits/sec    0   3.09 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  10.5 GBytes  9.06 Gbits/sec    0             sender
[  5]   0.00-10.00  sec  10.5 GBytes  9.05 Gbits/sec                  receiver

iperf Done.
--------------
```

### Connect via tun


```
~ » iperf3 -c dsm
Connecting to host dsm, port 5201
[  5] local 10.0.0.14 port 41436 connected to 10.0.0.11 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   234 MBytes  1.96 Gbits/sec    1   47.1 KBytes
[  5]   1.00-2.00   sec   235 MBytes  1.97 Gbits/sec    0   47.1 KBytes
[  5]   2.00-3.00   sec   243 MBytes  2.04 Gbits/sec    0   47.1 KBytes
[  5]   3.00-4.00   sec   239 MBytes  2.00 Gbits/sec    0   47.1 KBytes
[  5]   4.00-5.00   sec   240 MBytes  2.02 Gbits/sec    0   47.1 KBytes
[  5]   5.00-6.00   sec   238 MBytes  1.99 Gbits/sec    0   47.1 KBytes
[  5]   6.00-7.00   sec   235 MBytes  1.97 Gbits/sec    0   47.1 KBytes
[  5]   7.00-8.00   sec   233 MBytes  1.95 Gbits/sec    0   47.1 KBytes
[  5]   8.00-9.00   sec   236 MBytes  1.98 Gbits/sec    0   47.1 KBytes
[  5]   9.00-10.00  sec   241 MBytes  2.03 Gbits/sec    0   47.1 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  2.32 GBytes  1.99 Gbits/sec    1             sender
[  5]   0.00-10.00  sec  2.32 GBytes  1.99 Gbits/sec                  receiver

iperf Done.
```

There should be room for the performance improve.

---

## Automated CI Benchmarking

### Overview

The project includes automated TUN throughput benchmarking that runs on every PR affecting TUN-related code. The benchmark results are automatically posted as comments on the PR.

### How It Works

1. **Trigger**: The benchmark workflow runs when PRs modify:
   - `clash-lib/src/proxy/tun/**`
   - `clash-netstack/**`
   - `bench/**`
   - `.github/workflows/benchmark.yml`

2. **Baseline Comparison**:
   - The repo includes a committed baseline file (`bench/baseline-tun-benchmark.json`)
   - This baseline represents the performance of the latest master branch
   - PRs are compared against this baseline (no need to rebuild master every time)
   - When a PR with good performance is merged, update the baseline for future comparisons

3. **Execution**:
   - Creates a veth pair (veth0 <-> veth1 @ namespace) with TEST-NET-1 IPs
   - Builds the PR code in release mode
   - Runs TUN benchmark with traffic routing through TUN device
   - Compares with committed baseline file
   - Posts results as a PR comment

4. **Results**: The workflow posts a comment showing:
   - Current PR throughput performance
   - Comparison with baseline (master branch)
   - Performance difference percentage
   - Warning if regression exceeds 10%
   - Clash-rs logs available as downloadable artifact

### Test Methodology

The benchmark uses **veth pairs with network namespaces** to ensure traffic actually goes through the TUN device:

- **Setup**: Creates veth pair using TEST-NET-1 range (192.0.2.1 <-> 192.0.2.2@namespace)
  - Uses RFC 5737 reserved range to avoid conflicts with real networks
  - veth1 placed in separate network namespace to prevent kernel local routing
- **Baseline**: Direct connection to 192.0.2.2 via veth (no TUN routing)
  - Expected: ~5-20 Gbps (virtual network interface speed)
- **TUN Test**:
  - Removes direct route to 192.0.2.2
  - Configures TUN to route 192.0.2.0/24
  - Traffic to 192.0.2.2 **must** go through TUN
  - Expected: ~1-3 Gbps (TUN adds overhead)
- **Comparison**: Shows TUN overhead as percentage difference

### Running Benchmarks Locally

```bash
# Build clash-rs (default features, same as CI; --all-features enables
# telemetry, which slows the data path far below normal)
cargo build --release --bin clash-rs

# Run the benchmark (includes baseline test)
python3 bench/run_tun_benchmark.py \
  --config bench/tun-benchmark.yaml \
  --duration 10 \
  --output results.json

# Run TUN-only benchmark (skip baseline, like CI)
python3 bench/run_tun_benchmark.py \
  --config bench/tun-benchmark.yaml \
  --duration 10 \
  --output results.json \
  --skip-baseline

# Compare with baseline
python3 bench/compare_results.py \
  --current results.json \
  --baseline bench/baseline-tun-benchmark.json \
  --output comment.md
```

### Updating the Baseline

When merging a PR that improves performance or after significant changes.
The baseline must come from the same build the workflow benchmarks — default
features, no `--all-features` (`telemetry` writes a Chrome trace and skews the
numbers) — and ideally from a CI runner: the simplest way is to download the
`benchmark-pr-results` artifact of a recent PR run (or a manual
`workflow_dispatch` run on master) and commit it as-is.

```bash
# Same build as CI: default features only
cargo build --release --bin clash-rs

# Run benchmark to generate new baseline
python3 bench/run_tun_benchmark.py \
  --config bench/tun-benchmark.yaml \
  --duration 10 \
  --output bench/baseline-tun-benchmark.json \
  --skip-baseline

# Commit the updated baseline
git add bench/baseline-tun-benchmark.json
git commit -m "chore: update TUN benchmark baseline"
```

The committed baseline becomes the reference point for all future PRs.

### Configuration

- **Benchmark config**: `bench/tun-benchmark.yaml` - Minimal TUN config for CI
- **Test duration**: Default 10 seconds (configurable via `--duration`)
- **Regression threshold**: 10% decrease triggers a warning
- **Server**: Uses localhost iperf3 server

### Requirements

- iperf3 (`apt-get install iperf3`)
- iproute2 (`apt-get install iproute2`)
- Python 3.x
- sudo/root access (required for creating network interfaces and TUN device)

### Files

- `run_tun_benchmark.py` - Main benchmark script
- `compare_results.py` - Results comparison and comment generation
- `tun-benchmark.yaml` - CI benchmark configuration
