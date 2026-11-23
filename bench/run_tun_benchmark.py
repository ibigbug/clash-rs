#!/usr/bin/env python3
"""
TUN throughput benchmark script for ClashRS.

This script measures TUN device overhead using veth pair:
- Baseline: iperf3 client -> veth pair -> iperf3 server (direct, no TUN)
- TUN: iperf3 client -> TUN device -> veth pair -> iperf3 server (via TUN)

By routing the same destination through TUN, we measure actual TUN overhead.
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import time


def collect_environment_info():
    """Collect system and network environment information."""
    env_info = {}

    # OS information
    env_info["os"] = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }

    # CPU information
    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read()
            # Get CPU model
            for line in cpuinfo.split("\n"):
                if "model name" in line:
                    env_info["cpu"] = line.split(":")[1].strip()
                    break
            # Count CPU cores
            env_info["cpu_cores"] = cpuinfo.count("processor")
    except:
        env_info["cpu"] = platform.processor()
        env_info["cpu_cores"] = os.cpu_count()

    # Memory information
    try:
        with open("/proc/meminfo") as f:
            meminfo = f.read()
            for line in meminfo.split("\n"):
                if "MemTotal" in line:
                    mem_kb = int(line.split()[1])
                    env_info["memory_gb"] = round(mem_kb / 1024 / 1024, 2)
                    break
    except:
        env_info["memory_gb"] = "unknown"

    # Network interface information
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            interfaces = []
            for line in result.stdout.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 2:
                    iface_name = parts[1].strip()
                    # Skip loopback and veth
                    if not iface_name.startswith(("lo", "veth")):
                        iface_info = {"name": iface_name}

                        # Try to get interface speed from sysfs
                        speed_path = f"/sys/class/net/{iface_name}/speed"
                        try:
                            with open(speed_path) as f:
                                speed = int(f.read().strip())
                                if speed > 0:
                                    iface_info["speed_mbps"] = speed
                                else:
                                    iface_info["speed_mbps"] = "unknown"
                        except (FileNotFoundError, ValueError, PermissionError):
                            iface_info["speed_mbps"] = "unknown"

                        interfaces.append(iface_info)
            env_info["interfaces"] = interfaces[:5]  # Limit to first 5
    except:
        env_info["interfaces"] = []

    # Kernel version
    try:
        result = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            env_info["kernel"] = result.stdout.strip()
    except:
        pass

    return env_info


def check_requirements():
    """Check if required tools are available."""
    required = ["iperf3", "ip"]
    missing = []

    for tool in required:
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            missing.append(tool)

    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}", file=sys.stderr)
        print("Install with: sudo apt-get install iperf3 iproute2", file=sys.stderr)
        sys.exit(1)

    # Check if TUN device support is available
    if not os.path.exists("/dev/net/tun"):
        print("Error: /dev/net/tun not found", file=sys.stderr)
        print("TUN support may not be available on this system", file=sys.stderr)
        print("Try: sudo modprobe tun", file=sys.stderr)
        sys.exit(1)
    else:
        print("✓ /dev/net/tun exists")


def cleanup_veth_pair():
    """Remove the veth pair and namespace."""
    # Deleting namespace automatically removes veth1
    subprocess.run(["sudo", "ip", "netns", "del", "benchns"], capture_output=True)
    # veth0 gets cleaned up when its peer is deleted
    subprocess.run(["sudo", "ip", "link", "del", "veth0"], capture_output=True)


def setup_veth_pair():
    """Create a veth pair with server end in network namespace."""
    # Clean up any existing setup
    cleanup_veth_pair()

    # Set rp_filter to 0 BEFORE creating veth interfaces
    # This ensures new interfaces inherit rp_filter=0 and fixes cross-network routing issues
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.conf.default.rp_filter=0"],
        capture_output=True,
    )

    # Small delay to ensure kernel settings take effect
    time.sleep(0.2)

    # Create namespace
    subprocess.run(["sudo", "ip", "netns", "add", "benchns"], capture_output=True)

    # Create veth pair
    subprocess.run(
        ["sudo", "ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"],
        capture_output=True,
    )

    # Move veth1 to namespace
    subprocess.run(
        ["sudo", "ip", "link", "set", "veth1", "netns", "benchns"],
        capture_output=True,
    )

    # Configure veth0 in default namespace (using /24 for proper routing)
    subprocess.run(
        ["sudo", "ip", "addr", "add", "192.0.2.1/24", "dev", "veth0"],
        capture_output=True,
    )
    subprocess.run(["sudo", "ip", "link", "set", "veth0", "up"], capture_output=True)

    # Disable reverse path filtering on veth0
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.conf.veth0.rp_filter=0"],
        capture_output=True,
    )

    # Small delay to ensure kernel settings take effect
    time.sleep(0.2)

    # Configure veth1 inside the namespace
    subprocess.run(
        [
            "sudo",
            "ip",
            "netns",
            "exec",
            "benchns",
            "ip",
            "addr",
            "add",
            "192.0.2.2/24",
            "dev",
            "veth1",
        ],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "ip", "netns", "exec", "benchns", "ip", "link", "set", "veth1", "up"],
        capture_output=True,
    )
    subprocess.run(
        ["sudo", "ip", "netns", "exec", "benchns", "ip", "link", "set", "lo", "up"],
        capture_output=True,
    )

    # Add route in namespace for return path to TUN network (198.19.0.0/24)
    subprocess.run(
        [
            "sudo",
            "ip",
            "netns",
            "exec",
            "benchns",
            "ip",
            "route",
            "add",
            "198.19.0.0/24",
            "via",
            "192.0.2.1",
        ],
        capture_output=True,
    )

    print("✓ Created veth pair: veth0 (192.0.2.1/24) <-> veth1@benchns (192.0.2.2)")
    print("✓ iperf server will run in namespace on 192.0.2.2")

    return True


def start_iperf_server(server_ip):
    """Start iperf3 server in namespace (single-shot mode, no daemon)."""
    print(f"Starting iperf3 server in namespace on {server_ip}...")

    # Run iperf3 in namespace, single connection mode (-1)
    # Don't use -D (daemon) or -B (bind) as they cause issues in namespace
    proc = subprocess.Popen(
        [
            "sudo",
            "ip",
            "netns",
            "exec",
            "benchns",
            "iperf3",
            "-s",
            "-1",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(2)  # Give server time to start

    print("✓ iperf3 server started")
    return proc


def stop_iperf_server():
    """Stop iperf3 server."""
    print("Stopping iperf3 server...")
    subprocess.run(["sudo", "pkill", "-9", "iperf3"], capture_output=True)
    time.sleep(1)


def run_clash_rs(config_path, log_file):
    """Start clash-rs with the given config."""
    clash_binary = os.environ.get("CLASH_BINARY", "./target/release/clash-rs")

    if not os.path.exists(clash_binary):
        print(f"Error: clash-rs binary not found at {clash_binary}", file=sys.stderr)
        return None

    print(f"Starting clash-rs with config: {config_path}")
    print(f"Logs will be written to: {log_file}")

    cmd = ["sudo", clash_binary, "-c", config_path]
    with open(log_file, "w") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)

    # Wait for clash-rs to initialize TUN device
    print("Waiting for TUN device initialization...")
    time.sleep(3)

    # Check if process is still running
    if proc.poll() is not None:
        print(f"✗ clash-rs failed to start; see {log_file}", file=sys.stderr)
        return None

    # Verify TUN device exists with retries
    max_retries = 5
    for attempt in range(max_retries):
        result = subprocess.run(
            ["ip", "link", "show", "clash-bench"],
            capture_output=True,
        )
        
        if result.returncode == 0:
            print("✓ TUN device detected: clash-bench")
            # Extra stabilization delay for CI environments
            time.sleep(2)
            return proc
        
        if attempt < max_retries - 1:
            print(f"  TUN device not ready yet, retry {attempt + 1}/{max_retries - 1}...")
            time.sleep(1)
    
    print("✗ TUN device not found after retries", file=sys.stderr)
    return None


def stop_clash_rs(proc):
    """Stop clash-rs process."""
    if proc:
        print("Stopping clash-rs...")
        subprocess.run(["sudo", "pkill", "-9", "clash-rs"], capture_output=True)
        time.sleep(1)


def run_iperf_test(server_ip, duration=10, bind_address=None, retries=2):
    """Run iperf3 client test and parse results."""
    for attempt in range(retries + 1):
        cmd = [
            "iperf3",
            "-c",
            server_ip,
            "-t",
            str(duration),
            "-J",  # JSON output
        ]

        if bind_address:
            cmd.extend(["-B", bind_address])
            if attempt == 0:
                print(f"  Binding client to source address: {bind_address}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 10)

            if result.returncode != 0:
                # With -J, iperf3 can report the error in JSON on stdout.
                error = result.stderr.strip() or result.stdout.strip()
                if attempt < retries:
                    print(f"  iperf3 attempt {attempt + 1} failed, retrying: {error}", file=sys.stderr)
                    time.sleep(2)
                    continue
                print(f"✗ iperf3 test failed after {retries + 1} attempts: {error}", file=sys.stderr)
                return None

            data = json.loads(result.stdout)

            # Extract relevant metrics
            end_data = data.get("end", {})
            sum_received = end_data.get("sum_received", {})

            throughput_bps = sum_received.get("bits_per_second", 0)
            bytes_transferred = sum_received.get("bytes", 0)
            retransmits = end_data.get("sum_sent", {}).get("retransmits", 0)
            duration_actual = sum_received.get("seconds", duration)

            return {
                "throughput_bps": throughput_bps,
                "throughput_gbps": throughput_bps / 1e9,
                "bytes_transferred": bytes_transferred,
                "retransmits": retransmits,
                "duration_seconds": duration_actual,
            }
        except subprocess.TimeoutExpired:
            if attempt < retries:
                print(f"  iperf3 attempt {attempt + 1} timed out, retrying...", file=sys.stderr)
                time.sleep(2)
                continue
            print(f"✗ iperf3 test timed out after {retries + 1} attempts", file=sys.stderr)
            return None
        except (json.JSONDecodeError, KeyError) as e:
            if attempt < retries:
                print(f"  iperf3 attempt {attempt + 1} parse error, retrying...", file=sys.stderr)
                time.sleep(2)
                continue
            print(f"✗ Failed to parse iperf3 output after {retries + 1} attempts: {e}", file=sys.stderr)
            return None
    
    return None


def run_baseline_test(server_ip, duration):
    """Run baseline test without TUN."""
    print("\n===  Baseline Test (direct via veth) ===")
    print(f"Testing direct connection to {server_ip} via veth pair (no TUN)")

    # Use the automatically created route for baseline
    print(f"Using automatically created route: 192.0.2.0/24 dev veth0")

    # Start iperf server
    iperf_proc = start_iperf_server(server_ip)

    try:
        print(f"Running iperf3 test to {server_ip} for {duration}s...")
        result = run_iperf_test(server_ip, duration)

        if result:
            print(f"✓ Baseline: {result['throughput_gbps']:.2f} Gbps")
        else:
            print("✗ Baseline test failed")

        return result
    finally:
        stop_iperf_server()


def run_tun_test(config_path, server_ip, duration):
    """Run test routing through TUN device to reach veth."""
    print("\n=== TUN Test (via TUN device) ===")
    print(f"Traffic to {server_ip} will be routed through TUN device")

    log_file = "./clash-rs-bench.log"
    clash_proc = None

    try:
        clash_proc = run_clash_rs(config_path, log_file)

        if not clash_proc:
            return None

        # Fwmark-based policy routing:
        # - Table 100: route through TUN (for unmarked client traffic)
        # - Main table: gateway route for clash-rs marked packets (fwmark 666)
        # - Rule: unmarked packets → table 100, marked (666) → main table

        print("Setting up fwmark-based policy routing...")

        # Disable reverse path filtering on veth0 (should already be 0, but double-check)
        rp_result = subprocess.run(
            ["sudo", "sysctl", "-w", "net.ipv4.conf.veth0.rp_filter=0"],
            capture_output=True,
            text=True,
        )
        if rp_result.returncode == 0:
            print(f"  rp_filter setting: {rp_result.stdout.strip()}")
        else:
            print(f" ! rp_filter warning: {rp_result.stderr.strip()}")

        # Small delay to ensure settings are propagated
        time.sleep(0.2)

        # Delete auto-created link route
        subprocess.run(
            [
                "sudo",
                "ip",
                "route",
                "del",
                "192.0.2.0/24",
                "dev",
                "veth0",
            ],
            capture_output=True,
        )

        # Add gateway route for clash-rs's marked packets
        subprocess.run(
            [
                "sudo",
                "ip",
                "route",
                "add",
                "192.0.2.0/24",
                "via",
                "192.0.2.1",
                "dev",
                "veth0",
            ],
            capture_output=True,
        )

        # Add policy routing rule (not from all with fwmark 666 → table 100)
        subprocess.run(
            [
                "sudo",
                "ip",
                "rule",
                "add",
                "not",
                "from",
                "all",
                "fwmark",
                "666",
                "table",
                "100",
                "priority",
                "100",
            ],
            capture_output=True,
        )

        # Add TUN route in table 100
        subprocess.run(
            [
                "sudo",
                "ip",
                "route",
                "add",
                "192.0.2.0/24",
                "dev",
                "clash-bench",
                "table",
                "100",
            ],
            capture_output=True,
        )

        print("✓ Fwmark policy routing configured")
        print("  → Unmarked traffic: table 100 → TUN device")
        print("  → Marked traffic (666): main table → direct veth0")

        # Allow routing to stabilize (important for CI environments)
        time.sleep(2)

        # Start iperf server
        iperf_proc = start_iperf_server(server_ip)

        try:
            print(f"Running iperf3 test to {server_ip} for {duration}s...")

            # Bind client to TUN gateway address to force traffic through TUN
            tun_gateway = "198.19.0.1"
            result = run_iperf_test(server_ip, duration, bind_address=tun_gateway)

            if result:
                print(f"✓ TUN: {result['throughput_gbps']:.2f} Gbps")
            else:
                print("✗ TUN test failed")

            return result
        finally:
            stop_iperf_server()

    except subprocess.TimeoutExpired:
        print("✗ iperf3 test timed out", file=sys.stderr)
        return None
    finally:
        # Cleanup policy routing
        print("Cleaning up policy routing...")
        subprocess.run(
            ["sudo", "ip", "rule", "del", "table", "100"],
            capture_output=True,
        )
        subprocess.run(
            ["sudo", "ip", "route", "del", "192.0.2.0/24", "table", "100"],
            capture_output=True,
        )

        stop_clash_rs(clash_proc)


def calculate_regression(baseline, tun):
    """Calculate performance regression."""
    baseline_gbps = baseline["throughput_gbps"]
    tun_gbps = tun["throughput_gbps"]

    regression_percent = ((baseline_gbps - tun_gbps) / baseline_gbps) * 100
    overhead_percent = regression_percent  # Same thing, different perspective

    return {
        "baseline_gbps": baseline_gbps,
        "tun_gbps": tun_gbps,
        "regression_percent": regression_percent,
        "overhead_percent": overhead_percent,
    }


def main():
    parser = argparse.ArgumentParser(description="Run TUN throughput benchmark")
    parser.add_argument(
        "--config",
        default="bench/tun-benchmark.yaml",
        help="Path to clash-rs config file with TUN enabled",
    )
    parser.add_argument(
        "--duration", type=int, default=10, help="Test duration in seconds"
    )
    parser.add_argument(
        "--output",
        default="benchmark-results.json",
        help="Output JSON file for results",
    )

    args = parser.parse_args()

    check_requirements()

    # Setup veth pair with namespace
    if not setup_veth_pair():
        print("Failed to setup veth pair", file=sys.stderr)
        sys.exit(1)

    server_ip = "192.0.2.2"  # iperf server in namespace

    try:
        results = {
            "timestamp": time.time(),
            "config": args.config,
            "duration": args.duration,
            "environment": collect_environment_info(),
        }

        # Run baseline test
        baseline = run_baseline_test(server_ip, args.duration)
        results["baseline"] = baseline

        if not baseline:
            print("Baseline test failed, cannot continue", file=sys.stderr)
            return 1

        # Run TUN benchmark
        tun_result = run_tun_test(args.config, server_ip, args.duration)
        results["tun"] = tun_result

        # Calculate regression
        if baseline and tun_result:
            results["comparison"] = calculate_regression(baseline, tun_result)

        # Write results
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

        print(f"\n=== Results written to {args.output} ===")
        print(json.dumps(results, indent=2))

        # Return exit code based on results
        if tun_result:
            return 0
        else:
            return 1

    finally:
        cleanup_veth_pair()


if __name__ == "__main__":
    sys.exit(main())
