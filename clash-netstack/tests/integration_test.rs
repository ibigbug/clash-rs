use futures::{SinkExt, StreamExt};
use watfaq_netstack::{NetStack, Packet};

mod common;
mod mock_tun;

use common::{
    build_tcp_ack, build_tcp_syn_packet, build_tcp_syn_packet_with_port,
    build_udp_packet, init, is_rst, is_syn_ack, parse_server_isn, parse_tcp_data,
    tcp_dst_port,
};
use mock_tun::MockTun;

#[tokio::test]
async fn test_stack_with_mock_tun_real_tcp_udp() {
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from mock_tun to stack_sink (TUN -> NetStack)
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            let packet = Packet::new(pkt);
            stack_sink.send(packet).await.unwrap();
        }
    });

    // Send a TCP SYN packet
    let tcp_syn = build_tcp_syn_packet();
    tun_in.send(tcp_syn.clone()).unwrap();

    log::info!("Sent TCP SYN and UDP packets to mock TUN");

    let Some(Ok(reply)) = stack_stream.next().await else {
        panic!("No packets received from stack");
    };

    assert!(is_syn_ack(reply.data()));
    log::info!("Received TCP SYN-ACK packet from stack");

    let stream = tcp_listener.next().await.unwrap();
    log::info!("Accepted TCP stream: {:?}", stream);
    assert_eq!(stream.local_addr(), "1.1.1.1:1024".parse().unwrap());
    assert_eq!(stream.remote_addr(), "2.2.2.2:80".parse().unwrap());

    // Send a UDP packet
    let udp_pkt = build_udp_packet();
    tun_in.send(udp_pkt.clone()).unwrap();

    log::info!("Sent UDP packet to mock TUN");
    let (mut udp_read, _) = udp_socket.split();
    let Some(udp_packet) = udp_read.recv().await else {
        panic!("No UDP packet received");
    };
    assert_eq!(udp_packet.local_addr, "1.1.1.1:5000".parse().unwrap());
    assert_eq!(udp_packet.remote_addr, "2.2.2.2:5001".parse().unwrap());
}

/// Verifies that a relay can sustain a 16 MB bulk TCP transfer through the
/// netstack without stalling. A relay task writes into the netstack TcpStream
/// while a simulated client reads segments from StackSplitStream and sends
/// cumulative ACKs back. The test fails if throughput stalls for more than
/// 5 seconds or the whole transfer exceeds 30 s.
///
/// This catches the regression where poll_sockets runs in a tight loop and
/// starves StackSplitStream, blocking the consumer from draining the tx channel
/// and sending ACKs — which fills smoltcp's send window and triggers RTO.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_speedtest_bulk_download() {
    init();

    const TRANSFER_BYTES: usize = 16 * 1024 * 1024; // 16 MB

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from the mock TUN into the netstack.
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // Client simulation task: performs the TCP handshake, reads data segments
    // from StackSplitStream, and sends cumulative ACKs back through the mock
    // TUN. Spawned BEFORE awaiting tcp_listener so its SYN is in-flight
    // while we wait.
    let client = tokio::spawn(async move {
        // --- TCP handshake: SYN → SYN-ACK → ACK ---
        tun_in.send(build_tcp_syn_packet()).unwrap();

        let server_isn = loop {
            let pkt = stack_stream
                .next()
                .await
                .expect("stack_stream closed")
                .expect("stack_stream error");
            if is_syn_ack(pkt.data()) {
                break parse_server_isn(pkt.data());
            }
        };

        // SYN consumed client seq=0, so client_seq after handshake = 1.
        let client_seq: u32 = 1;
        // cumulative_ack tracks the highest contiguous byte acknowledged from
        // the server, starting just past the SYN-ACK's sequence number.
        let mut cumulative_ack = server_isn.wrapping_add(1);

        tun_in
            .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
            .unwrap();

        // --- Receive bulk data and ACK each segment ---
        let mut received = 0usize;
        let start = std::time::Instant::now();
        let mut last_check = start;
        let mut bytes_since_check = 0usize;

        while received < TRANSFER_BYTES {
            let pkt = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stack_stream.next(),
            )
            .await
            .expect("STALL: no TCP segment received for 5 s")
            .expect("stack_stream closed")
            .expect("stack_stream error");

            if let Some((seq, payload_len)) = parse_tcp_data(pkt.data()) {
                if payload_len > 0 {
                    let end_seq = seq.wrapping_add(payload_len as u32);
                    let advance = end_seq.wrapping_sub(cumulative_ack);
                    if advance > 0 && advance < (1u32 << 31) {
                        received += advance as usize;
                        bytes_since_check += advance as usize;
                        cumulative_ack = end_seq;
                    }
                    tun_in
                        .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
                        .unwrap();
                }
            } else {
                let _ = pkt;
            }

            let now = std::time::Instant::now();
            if now.duration_since(last_check) >= std::time::Duration::from_secs(1) {
                let mb = bytes_since_check as f64 / (1024.0 * 1024.0);
                eprintln!(
                    "[bulk] {:.1} MB/s  ({}/{} KB)",
                    mb,
                    received / 1024,
                    TRANSFER_BYTES / 1024,
                );
                bytes_since_check = 0;
                last_check = now;
            }
        }

        let elapsed = start.elapsed();
        let throughput = received as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!(
            "[bulk] done: {} KB in {:.2}s = {:.1} MB/s",
            received / 1024,
            elapsed.as_secs_f64(),
            throughput,
        );
        received
    });

    // Await the TcpStream HERE (in the main test body), NOT inside the relay
    // task. This keeps tcp_listener alive until after join!() completes,
    // preventing TcpListener::Drop from aborting the netstack task while
    // data is still in-flight. The client task already sent the SYN
    // concurrently above, so next() returns quickly.
    let stream = tcp_listener.next().await.expect("no TcpStream");

    // Relay task: writes TRANSFER_BYTES into the TcpStream.
    // Owns only the TcpStream (not the TcpListener).
    let relay = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = stream;
        let chunk = vec![0xABu8; 16 * 1024]; // 16 KB chunks
        let mut written = 0usize;
        while written < TRANSFER_BYTES {
            let n = (TRANSFER_BYTES - written).min(chunk.len());
            stream
                .write_all(&chunk[..n])
                .await
                .expect("write_all failed");
            written += n;
        }
        written
    });

    let (relay_res, client_res) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::join!(relay, client)
        })
        .await
        .expect("Test timed out (30 s) — likely a stall in the netstack");

    // tcp_listener is dropped here, AFTER relay and client both complete.
    // This ensures the netstack task outlives all data delivery.
    drop(tcp_listener);

    assert_eq!(relay_res.unwrap(), TRANSFER_BYTES);
    assert_eq!(client_res.unwrap(), TRANSFER_BYTES);
}

/// Verifies that a new TCP connection gets a SYN-ACK (not RST) while another
/// connection is actively bulk-transferring data.
///
/// **Bug B root cause**: `poll_sockets` only drained `notifier_rx` in the
/// `else` branch, which was skipped whenever `should_poll_now = true`.  During
/// an active download `poll_delay` ≈ 0 keeps `should_poll_now = true`
/// permanently, so new `IfaceEvent::TcpStream` events were never consumed
/// before `iface.poll()` ran.  smoltcp saw the incoming SYN with no matching
/// socket in the `SocketSet` and replied with RST.
///
/// **Fix**: drain `notifier_rx` with `try_recv()` before every `iface.poll()`
/// call, regardless of `should_poll_now`.
///
/// **How to observe the failure**: remove the `loop { notifier_rx.try_recv() …
/// }` block in `poll_sockets` (tcp_listener.rs ~line 327).  The test will then
/// either panic with "Got RST" or time out at the 5-second SYN-ACK deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_new_connection_during_active_transfer() {
    init();

    use tokio::sync::mpsc;

    const CONN1_BYTES: usize = 4 * 1024 * 1024; // 4 MB — keeps smoltcp in hot-path

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward mock TUN packets into the netstack.
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // Per-connection demultiplexer: routes outbound smoltcp packets to each
    // simulated client by TCP destination port (= client's source port).
    let (tx1, mut rx1) = mpsc::unbounded_channel::<Packet>();
    let (tx2, mut rx2) = mpsc::unbounded_channel::<Packet>();
    tokio::spawn(async move {
        while let Some(Ok(pkt)) = stack_stream.next().await {
            match tcp_dst_port(pkt.data()) {
                Some(1024) => {
                    let _ = tx1.send(pkt);
                }
                Some(1025) => {
                    let _ = tx2.send(pkt);
                }
                _ => {}
            }
        }
    });

    // Oneshot: conn1 client signals conn2 client once data is flowing.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let tun_in2 = tun_in.clone();

    // Client 1 (port 1024): handshake + receive CONN1_BYTES, ACKing each
    // segment. Fires `ready_tx` as soon as the first data segment arrives
    // (smoltcp hot-path).
    let client1 = tokio::spawn(async move {
        tun_in.send(build_tcp_syn_packet()).unwrap();

        let server_isn = loop {
            let pkt = rx1.recv().await.expect("rx1 closed before SYN-ACK");
            if is_syn_ack(pkt.data()) {
                break parse_server_isn(pkt.data());
            }
        };
        let client_seq: u32 = 1;
        let mut cumulative_ack = server_isn.wrapping_add(1);
        tun_in
            .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
            .unwrap();

        let mut received = 0usize;
        let mut signalled = false;
        let mut ready_tx = Some(ready_tx);

        while received < CONN1_BYTES {
            let pkt =
                tokio::time::timeout(std::time::Duration::from_secs(5), rx1.recv())
                    .await
                    .expect("conn1 stalled for 5 s")
                    .expect("rx1 closed");

            if let Some((seq, payload_len)) = parse_tcp_data(pkt.data())
                && payload_len > 0
            {
                let end_seq = seq.wrapping_add(payload_len as u32);
                let advance = end_seq.wrapping_sub(cumulative_ack);
                if advance > 0 && advance < (1u32 << 31) {
                    received += advance as usize;
                    cumulative_ack = end_seq;
                }
                tun_in
                    .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
                    .unwrap();
                // Signal conn2 client on the first received data segment.
                if !signalled {
                    signalled = true;
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
            }
        }
        received
    });

    // Client 2 (port 1025): waits until conn1 is actively transferring, then
    // sends a SYN and asserts it receives a SYN-ACK (not RST, not timeout).
    let client2 = tokio::spawn(async move {
        ready_rx
            .await
            .expect("ready signal lost — conn1 relay never started");

        tun_in2.send(build_tcp_syn_packet_with_port(1025)).unwrap();

        // Expect SYN-ACK within 5 s.  Without the drain-loop fix smoltcp
        // responds with RST (or the packet is silently dropped) instead.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let pkt = rx2.recv().await.expect("rx2 closed before SYN-ACK");
                if is_syn_ack(pkt.data()) {
                    return;
                }
                if is_rst(pkt.data()) {
                    panic!(
                        "connection 2 received RST — Bug B not fixed (drain \
                         notifier_rx before iface.poll() is missing)"
                    );
                }
            }
        })
        .await
        .expect("timed out waiting for SYN-ACK on connection 2 — Bug B not fixed");
    });

    // Accept conn1 (SYN already in-flight from client1 task above).
    let stream1 = tcp_listener.next().await.expect("no stream for conn1");

    // Relay 1: write CONN1_BYTES so smoltcp stays in the hot-path long enough
    // for conn2's SYN to arrive while poll_delay ≈ 0.
    let relay1 = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut stream = stream1;
        let chunk = vec![0u8; 16 * 1024];
        let mut written = 0usize;
        while written < CONN1_BYTES {
            let n = (CONN1_BYTES - written).min(chunk.len());
            stream
                .write_all(&chunk[..n])
                .await
                .expect("relay1 write failed");
            written += n;
        }
        written
    });

    // Accept conn2 (SYN sent by client2 after ready signal, which fires only
    // once relay1 has written at least one segment — so this blocks briefly).
    let stream2 = tcp_listener.next().await.expect("no stream for conn2");
    drop(stream2); // conn2 handshake complete; no data transfer needed.

    let (relay1_res, client1_res, client2_res) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::join!(relay1, client1, client2)
        })
        .await
        .expect("test timed out (30 s)");

    drop(tcp_listener);

    assert_eq!(relay1_res.unwrap(), CONN1_BYTES, "relay1 bytes mismatch");
    assert_eq!(client1_res.unwrap(), CONN1_BYTES, "client1 bytes mismatch");
    client2_res.unwrap(); // panics if client2 saw RST or timed out
}
