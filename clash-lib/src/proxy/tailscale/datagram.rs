use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt, Stream};
use tokio_util::sync::{CancellationToken, PollSender};

use crate::{
    app::dns::ThreadSafeDNSResolver,
    common::errors::{map_io_error, new_io_error},
    proxy::datagram::UdpPacket,
    session::SocksAddr,
};

#[derive(Debug)]
pub struct TailscaleDatagramOutbound {
    send_tx: PollSender<UdpPacket>,
    recv_rx: tokio::sync::mpsc::Receiver<UdpPacket>,
    cancel: CancellationToken,
    _send_task: tokio::task::JoinHandle<()>,
    _recv_task: tokio::task::JoinHandle<()>,
}

impl TailscaleDatagramOutbound {
    pub fn new(
        socket: ::tailscale::netstack::UdpSocket,
        device: Arc<::tailscale::Device>,
        resolver: ThreadSafeDNSResolver,
    ) -> Self {
        let local_addr = socket.local_addr();
        let local_addr_socks: SocksAddr = local_addr.into();
        let socket = Arc::new(socket);
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let (recv_tx, recv_rx) = tokio::sync::mpsc::channel::<UdpPacket>(32);
        let cancel = CancellationToken::new();

        let send_task = {
            let socket = Arc::clone(&socket);
            let resolver = resolver.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let pkt = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        pkt = send_rx.recv() => match pkt {
                            Some(p) => p,
                            None => break,
                        },
                    };

                    let dst = match pkt.dst_addr {
                        SocksAddr::Ip(addr) => addr,
                        SocksAddr::Domain(domain, port) => {
                            // Tailnet peers first, then v4 with v6 fallback.
                            let peer_ip =
                                super::resolve_peer(&device, &domain).await;
                            let ip = match peer_ip {
                                Some(ip) => ip,
                                None => match resolver
                                    .resolve_v4(&domain, false)
                                    .await
                                    .map_err(map_io_error)
                                {
                                    Ok(Some(ip)) => IpAddr::V4(ip),
                                    _ => match resolver
                                        .resolve_v6(&domain, false)
                                        .await
                                        .map_err(map_io_error)
                                    {
                                        Ok(Some(ip)) => IpAddr::V6(ip),
                                        Ok(None) => {
                                            tracing::warn!(
                                                "tailscale udp resolve returned no \
                                                 result for {domain}"
                                            );
                                            continue;
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                "tailscale udp resolve failed for \
                                                 {domain}: {err}"
                                            );
                                            continue;
                                        }
                                    },
                                },
                            };
                            (ip, port).into()
                        }
                    };

                    if let Err(err) = socket.send_to(dst, &pkt.data).await {
                        tracing::warn!(
                            "tailscale udp send_to failed for {dst}: {err}"
                        );
                        continue;
                    }
                }
            })
        };

        let recv_task = {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let recv = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => break,
                        r = socket.recv_from_bytes() => r,
                    };
                    let (remote, data) = match recv {
                        Ok(recv) => recv,
                        Err(err) => {
                            tracing::warn!("tailscale udp recv_from failed: {err}");
                            break;
                        }
                    };

                    if recv_tx
                        .send(UdpPacket {
                            data: data.into(),
                            src_addr: remote.into(),
                            dst_addr: local_addr_socks.clone(),
                            inbound_user: None,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            })
        };

        Self {
            send_tx: PollSender::new(send_tx),
            recv_rx,
            cancel,
            _send_task: send_task,
            _recv_task: recv_task,
        }
    }
}

impl Drop for TailscaleDatagramOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
        self._send_task.abort();
        self._recv_task.abort();
    }
}

impl Sink<UdpPacket> for TailscaleDatagramOutbound {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_ready_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel not ready"))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: UdpPacket,
    ) -> Result<(), Self::Error> {
        self.send_tx
            .start_send_unpin(item)
            .map_err(|_| new_io_error("tailscale udp send channel closed"))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_flush_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel flush failed"))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.send_tx
            .poll_close_unpin(cx)
            .map_err(|_| new_io_error("tailscale udp send channel close failed"))
    }
}

impl Stream for TailscaleDatagramOutbound {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.recv_rx.poll_recv(cx)
    }
}
