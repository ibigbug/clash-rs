use crate::{Packet, stack::IfaceEvent};
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc;

pub struct NetstackDevice {
    rx_sender: mpsc::UnboundedSender<Packet>,
    rx_queue: mpsc::UnboundedReceiver<Packet>,

    tx_sender: mpsc::Sender<Packet>,
    capabilities: DeviceCapabilities,

    iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
}

impl NetstackDevice {
    pub fn new(
        tx_sender: mpsc::Sender<Packet>,
        iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
    ) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 1500;
        capabilities.medium = Medium::Ip;

        let (rx_sender, rx_queue) = mpsc::unbounded_channel::<Packet>();

        Self {
            rx_sender,
            rx_queue,
            tx_sender,
            capabilities,
            iface_notifier,
        }
    }

    pub fn create_injector(&self) -> mpsc::UnboundedSender<Packet> {
        self.rx_sender.clone()
    }
}

impl Device for NetstackDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(
        &mut self,
        _timestamp: Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve a tx slot FIRST before touching rx_queue.
        // If we checked rx_queue first, a successful try_recv() would consume
        // the inbound packet even when try_reserve() subsequently fails,
        // silently dropping ACKs and preventing smoltcp from advancing
        // its send window.
        let permit = self.tx_sender.try_reserve().ok()?;
        let packet = self.rx_queue.try_recv().ok()?;

        let rx_token = RxTokenImpl { packet };
        let tx_token = TxTokenImpl { tx_sender: permit };
        self.iface_notifier
            .send(IfaceEvent::DeviceReady)
            .expect("Failed to notify iface event");
        Some((rx_token, tx_token))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.tx_sender
            .try_reserve()
            .map(|permit| TxTokenImpl { tx_sender: permit })
            .ok()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

pub struct RxTokenImpl {
    packet: Packet,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.data())
    }
}

pub struct TxTokenImpl<'a> {
    tx_sender: mpsc::Permit<'a, Packet>,
}

impl<'a> TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        let packet = Packet::new(buffer);
        self.tx_sender.send(packet);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::Device;

    /// Reproduces the ACK-drop bug: when the outbound tx channel is full
    /// (simulating a slow consumer), `receive()` calls `try_recv()`
    /// unconditionally, consuming the inbound ACK from the queue, then
    /// `try_reserve()` fails because the tx channel is at capacity → the ACK
    /// is silently dropped.
    ///
    /// Without ACKs, smoltcp never advances its send window and the download
    /// stalls.
    #[tokio::test]
    async fn test_receive_drops_inbound_packet_when_tx_channel_full() {
        let (tx_sender, mut tx_receiver) = tokio::sync::mpsc::channel::<Packet>(1);
        let (iface_notifier, _iface_rx) =
            tokio::sync::mpsc::unbounded_channel::<IfaceEvent<'static>>();
        let mut device = NetstackDevice::new(tx_sender, iface_notifier);
        let injector = device.create_injector();

        // Fill the tx channel to its capacity of 1
        device
            .tx_sender
            .try_send(Packet::new(vec![0u8; 60]))
            .expect("should fit in empty channel");
        // tx channel: FULL (capacity = 1)

        // Simulate an inbound ACK entering rx_queue
        injector
            .send(Packet::new(vec![0u8; 60]))
            .expect("unbounded, should not fail");
        // rx_queue: [ack_packet]

        // Call receive() while tx is full.
        // Due to the bug: try_recv() pops the ACK, then try_reserve() fails,
        // and the ACK is dropped (never returned, never processed by smoltcp).
        {
            let result = device.receive(smoltcp::time::Instant::now());
            assert!(
                result.is_none(),
                "receive() must return None when tx channel is full"
            );
        } // result dropped here — releasing the borrow on device

        // Drain the tx channel to make space
        tx_receiver.recv().await.expect("should have a packet");

        // Now try to receive again — with the bug the ACK is gone forever.
        // After the fix (check try_reserve first), the packet stays in rx_queue
        // and receive() can process it once tx space is available.
        let result2 = device.receive(smoltcp::time::Instant::now());
        assert!(
            result2.is_some(),
            "BUG: inbound ACK was silently dropped when tx channel was full; \
             smoltcp will never advance its send window → download stalls to 0"
        );
    }
}
