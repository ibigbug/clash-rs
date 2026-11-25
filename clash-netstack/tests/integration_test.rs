use futures::{SinkExt, StreamExt};
use watfaq_netstack::{NetStack, Packet};

mod common;
mod mock_tun;

use common::{
    build_icmpv4_echo_request, build_icmpv6_echo_request, build_tcp_ack,
    build_tcp_segment, build_tcp_syn_packet, build_tcp_syn_packet_with_port,
    build_udp_packet, init, is_icmpv4_echo_reply, is_icmpv6_echo_reply, is_rst,
    is_syn_ack, parse_server_isn, parse_tcp_data, parse_tcp_header, tcp_dst_port,
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

#[tokio::test]
async fn test_stack_icmpv4_echo_reply() {
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, _tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from mock_tun to stack_sink (TUN -> NetStack)
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            let packet = Packet::new(pkt);
            if stack_sink.send(packet).await.is_err() {
                break;
            }
        }
    });

    // Send an ICMPv4 Echo Request packet to any IP
    let icmp_req = build_icmpv4_echo_request(
        [192, 168, 1, 100],
        [1, 1, 1, 1],
        0x1234,
        0x0001,
        b"ping test payload 1234",
    );
    tun_in.send(icmp_req).unwrap();

    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        stack_stream.next().await
    })
    .await
    .expect("timed out waiting for ICMPv4 Echo Reply")
    .expect("no packet received from stack")
    .expect("error receiving packet");

    assert!(
        is_icmpv4_echo_reply(reply.data(), 0x1234, 0x0001),
        "Expected ICMPv4 Echo Reply"
    );
}

#[tokio::test]
async fn test_stack_icmpv6_echo_reply() {
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, _tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from mock_tun to stack_sink (TUN -> NetStack)
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            let packet = Packet::new(pkt);
            if stack_sink.send(packet).await.is_err() {
                break;
            }
        }
    });

    let src_ip: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let dst_ip: [u8; 16] = [
        0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
    ];

    // Send an ICMPv6 Echo Request packet
    let icmp_req = build_icmpv6_echo_request(
        src_ip,
        dst_ip,
        0x5678,
        0x0002,
        b"ping v6 test payload",
    );
    tun_in.send(icmp_req).unwrap();

    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        stack_stream.next().await
    })
    .await
    .expect("timed out waiting for ICMPv6 Echo Reply")
    .expect("no packet received from stack")
    .expect("error receiving packet");

    assert!(
        is_icmpv6_echo_reply(reply.data(), 0x5678, 0x0002),
        "Expected ICMPv6 Echo Reply"
    );
}

/// Data the peer sends after we half-closed must all reach the app, even when
/// the peer's FIN moves the socket to TimeWait while part of that data is
/// still in smoltcp's receive buffer (because the app-side ring is full).
///
/// Previously the socket was removed as soon as `is_active()` went false
/// (TimeWait counts as inactive) and the bytes left in smoltcp were dropped:
/// the app read exactly one ring's worth and then got EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_no_tail_loss_when_peer_fin_lands_in_time_wait() {
    tail_loss_after_peer_fin(std::time::Duration::from_millis(200)).await;
}

/// Same, but the app does not read until smoltcp's TimeWait timer (10 s)
/// has expired, which resets the socket and clears its RX buffer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_no_tail_loss_when_reader_outlives_time_wait() {
    tail_loss_after_peer_fin(std::time::Duration::from_secs(11)).await;
}

async fn tail_loss_after_peer_fin(read_delay: std::time::Duration) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    init();

    const RING: usize = 256 * 1024;
    const TOTAL: usize = RING + 40 * 1024;
    const MSS: usize = 1400;
    const ACK: u8 = 0x10;
    const FIN: u8 = 0x01;

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    tun_in.send(build_tcp_syn_packet()).unwrap();
    let server_isn = loop {
        let pkt = stack_stream.next().await.unwrap().unwrap();
        if is_syn_ack(pkt.data()) {
            break parse_server_isn(pkt.data());
        }
    };
    let mut seq: u32 = 1;
    tun_in
        .send(build_tcp_ack(seq, server_isn.wrapping_add(1), u16::MAX))
        .unwrap();
    let mut stream = tcp_listener.next().await.expect("no TcpStream");

    // Half-close our side, then acknowledge the FIN: socket -> FinWait2.
    stream.shutdown().await.unwrap();
    let (our_fin_end, fin_window) = loop {
        let pkt = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stack_stream.next(),
        )
        .await
        .expect("no FIN from stack")
        .unwrap()
        .unwrap();
        if let Some((s, _, flags, w)) = parse_tcp_header(pkt.data())
            && flags & FIN != 0
        {
            break (s.wrapping_add(1), w as u32);
        }
    };
    tun_in
        .send(build_tcp_segment(seq, our_fin_end, ACK, u16::MAX, &[]))
        .unwrap();

    // Send TOTAL bytes without the app reading, honouring the stack's window.
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
    let mut acked: u32 = 1;
    let mut window = fin_window;
    let mut sent = 0usize;
    let end = 1u32.wrapping_add(TOTAL as u32);
    while acked != end {
        while sent < TOTAL {
            let room = window.saturating_sub(seq.wrapping_sub(acked)) as usize;
            let n = MSS.min(TOTAL - sent).min(room);
            if n == 0 {
                break;
            }
            tun_in
                .send(build_tcp_segment(
                    seq,
                    our_fin_end,
                    ACK,
                    u16::MAX,
                    &payload[sent..sent + n],
                ))
                .unwrap();
            seq = seq.wrapping_add(n as u32);
            sent += n;
        }
        let pkt = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stack_stream.next(),
        )
        .await
        .expect("stack stopped acknowledging data")
        .unwrap()
        .unwrap();
        if let Some((_, a, flags, w)) = parse_tcp_header(pkt.data())
            && flags & ACK != 0
        {
            let adv = a.wrapping_sub(acked);
            if adv < (1 << 31) {
                acked = a;
                window = w as u32;
            }
        }
    }

    // Peer FIN: FinWait2 -> TimeWait with the tail still inside smoltcp.
    tun_in
        .send(build_tcp_segment(
            seq,
            our_fin_end,
            ACK | FIN,
            u16::MAX,
            &[],
        ))
        .unwrap();
    let fin_acked = seq.wrapping_add(1);
    loop {
        let pkt = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stack_stream.next(),
        )
        .await
        .expect("peer FIN never acknowledged")
        .unwrap()
        .unwrap();
        if parse_tcp_header(pkt.data()).is_some_and(|(_, a, ..)| a == fin_acked) {
            break;
        }
    }
    // Let the stack run its socket cleanup (and possibly TimeWait expiry).
    tokio::time::sleep(read_delay).await;

    let mut got = Vec::with_capacity(TOTAL);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut got),
    )
    .await
    .expect("read hung")
    .unwrap();
    assert_eq!(got.len(), TOTAL, "bytes lost after FIN in TimeWait");
    assert!(got == payload, "data corrupted");
    drop(tcp_listener);
}

/// With the outbound TCP channel full (the TUN writer is slow), a new SYN
/// cannot be processed yet. Its socket is still in Listen, which smoltcp
/// reports as inactive; it must not be reaped (the app already holds its
/// TcpStream and would see EOF), and once the channel drains the SYN must be
/// handled promptly rather than waiting for an unrelated socket timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_syn_survives_full_tx_channel() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::with_tcp_tx_capacity(1);
    let (mut stack_sink, mut stack_stream) = stack.split();
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // Connection A: its SYN-ACK fills the 1-slot channel; nobody drains it.
    tun_in.send(build_tcp_syn_packet()).unwrap();
    let _a = tcp_listener.next().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connection B arrives while the channel is full.
    tun_in.send(build_tcp_syn_packet_with_port(2000)).unwrap();
    let mut b = tcp_listener.next().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // B's stream must still be alive (no data yet), not at EOF.
    let mut byte = [0u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), b.read(&mut byte))
            .await
            .is_err(),
        "stream for a SYN queued behind TX backpressure was torn down"
    );

    // Drain A's SYN-ACK; B's SYN-ACK must follow without waiting ~1 s for
    // A's retransmit timer to poll the stack.
    let first = stack_stream.next().await.unwrap().unwrap();
    assert_eq!(tcp_dst_port(first.data()), Some(1024));
    let syn_ack_b = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            let pkt = stack_stream.next().await.unwrap().unwrap();
            if tcp_dst_port(pkt.data()) == Some(2000) {
                break pkt;
            }
        }
    })
    .await
    .expect("SYN for B not processed after the TX channel drained");
    assert!(is_syn_ack(syn_ack_b.data()), "B got RST instead of SYN-ACK");
}

/// With no TCP sockets and a full outbound channel, a queued ICMP request
/// must be answered once the channel drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_icmp_reply_after_full_tx_channel_drains() {
    use std::time::Duration;
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, _tcp_listener, _udp) = NetStack::with_tcp_tx_capacity(1);
    let (mut stack_sink, mut stack_stream) = stack.split();
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            if stack_sink.send(Packet::new(pkt)).await.is_err() {
                break;
            }
        }
    });

    for seq in [1u16, 2] {
        tun_in
            .send(build_icmpv4_echo_request(
                [192, 168, 1, 100],
                [1, 1, 1, 1],
                0x1234,
                seq,
                b"ping",
            ))
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    for seq in [1u16, 2] {
        let reply =
            tokio::time::timeout(Duration::from_millis(500), stack_stream.next())
                .await
                .unwrap_or_else(|_| {
                    panic!("no echo reply {seq} after channel drained")
                })
                .unwrap()
                .unwrap();
        assert!(is_icmpv4_echo_reply(reply.data(), 0x1234, seq));
    }
}

/// A socket whose SYN smoltcp never accepts (here: bad checksum) must not
/// linger in Listen past the grace period on an otherwise idle stack: the
/// app's stream has to see EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_unmatched_syn_socket_is_reaped_after_grace() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            if stack_sink.send(Packet::new(pkt)).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move { while stack_stream.next().await.is_some() {} });

    let mut syn = build_tcp_syn_packet().to_vec();
    let tcp_checksum = 20 + 16;
    syn[tcp_checksum] ^= 0xff;
    tun_in.send(syn.into()).unwrap();

    let mut s = tcp_listener.next().await.unwrap();
    let mut byte = [0u8; 1];
    // Still open well inside the grace period...
    assert!(
        tokio::time::timeout(Duration::from_secs(5), s.read(&mut byte))
            .await
            .is_err(),
        "Listen socket reaped before its grace period"
    );
    // ...and closed (clean EOF) shortly after it ends.
    let n = tokio::time::timeout(Duration::from_secs(8), s.read(&mut byte))
        .await
        .expect("stream for a never-accepted SYN hung past the grace period")
        .expect("expected EOF, not an error");
    assert_eq!(n, 0);
}
