//! Close/shutdown state shared between an app-side [`TcpStream`] and the
//! stack's `poll_sockets` loop.
//!
//! The state is a set of one-way flags packed into a single `AtomicU8`. The
//! read half and the write half close independently (TCP half-close), so the
//! flags combine rather than forming a linear sequence, but every flag only
//! ever goes from unset to set. Transitions that imply other flags set them in
//! the same `fetch_or`, so no observer can see e.g. "app dropped" without also
//! seeing both halves closed.
//!
//! ```text
//!                 set by           implies              effect
//! READ_CLOSED     peer FIN         -                    poll_read → EOF once drained
//! WRITE_SHUTDOWN  poll_shutdown    -                    stack FINs once send_buffer drains;
//!                                                       poll_write → BrokenPipe
//! WRITE_CLOSED    !may_send()      -                    poll_write → BrokenPipe
//! APP_DROPPED     TcpStream::drop  READ_ + WRITE_CLOSED stack drains send_buffer then FINs
//! SOCKET_GONE     socket removed   WRITE_CLOSED         poll_read → EOF once drained
//! ```
//!
//! [`TcpStream`]: crate::TcpStream

use std::sync::atomic::{AtomicU8, Ordering};

const READ_CLOSED: u8 = 1 << 0;
const WRITE_SHUTDOWN: u8 = 1 << 1;
const WRITE_CLOSED: u8 = 1 << 2;
const APP_DROPPED: u8 = 1 << 3;
const SOCKET_GONE: u8 = 1 << 4;

#[derive(Debug, Default)]
pub(crate) struct TcpCloseState(AtomicU8);

impl TcpCloseState {
    pub(crate) const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    fn load(&self) -> u8 {
        self.0.load(Ordering::Acquire)
    }

    /// Set `bits`; returns true if any of them was newly set.
    fn set(&self, bits: u8) -> bool {
        self.0.fetch_or(bits, Ordering::AcqRel) & bits != bits
    }

    // --- transitions -----------------------------------------------------

    /// Peer sent FIN (smoltcp `!may_recv()`). Returns true the first time.
    pub(crate) fn peer_fin(&self) -> bool {
        self.set(READ_CLOSED)
    }

    /// Our send path can no longer transmit (smoltcp `!may_send()`).
    /// Returns true the first time.
    pub(crate) fn send_closed(&self) -> bool {
        self.set(WRITE_CLOSED)
    }

    /// App called `poll_shutdown`: FIN once buffered data is sent.
    pub(crate) fn shutdown_requested(&self) {
        self.set(WRITE_SHUTDOWN);
    }

    /// App-side `TcpStream` dropped: both halves are closed to the app and
    /// the stack should drain then FIN.
    pub(crate) fn app_dropped(&self) {
        self.set(APP_DROPPED | READ_CLOSED | WRITE_CLOSED);
    }

    /// smoltcp socket became inactive and was removed (FIN complete, RST or
    /// timeout).
    pub(crate) fn socket_gone(&self) {
        self.set(SOCKET_GONE | WRITE_CLOSED);
    }

    // --- queries ---------------------------------------------------------

    /// No more data will arrive: `poll_read` returns EOF once the receive
    /// buffer is empty.
    pub(crate) fn read_eof(&self) -> bool {
        self.load() & (READ_CLOSED | SOCKET_GONE) != 0
    }

    /// `poll_write` must fail with `BrokenPipe`.
    pub(crate) fn write_refused(&self) -> bool {
        self.load() & (WRITE_CLOSED | WRITE_SHUTDOWN) != 0
    }

    /// App asked for a graceful write shutdown.
    pub(crate) fn is_shutdown_requested(&self) -> bool {
        self.load() & WRITE_SHUTDOWN != 0
    }

    /// App-side stream is gone; the stack owns the close.
    pub(crate) fn is_app_dropped(&self) -> bool {
        self.load() & APP_DROPPED != 0
    }
}

#[cfg(test)]
mod tests {
    use super::TcpCloseState;

    #[test]
    fn starts_open() {
        let s = TcpCloseState::new();
        assert!(!s.read_eof());
        assert!(!s.write_refused());
        assert!(!s.is_shutdown_requested());
        assert!(!s.is_app_dropped());
    }

    #[test]
    fn half_close_is_independent() {
        let s = TcpCloseState::new();
        assert!(s.peer_fin());
        assert!(s.read_eof());
        assert!(!s.write_refused(), "peer FIN must not close our write half");

        let s = TcpCloseState::new();
        s.shutdown_requested();
        assert!(s.write_refused());
        assert!(!s.read_eof(), "our shutdown must not close our read half");
    }

    #[test]
    fn transitions_report_first_time_only() {
        let s = TcpCloseState::new();
        assert!(s.peer_fin());
        assert!(!s.peer_fin());
        assert!(s.send_closed());
        assert!(!s.send_closed());
    }

    #[test]
    fn app_drop_closes_both_halves() {
        let s = TcpCloseState::new();
        s.app_dropped();
        assert!(s.is_app_dropped());
        assert!(s.read_eof());
        assert!(s.write_refused());
        // Data path observing FIN/!may_send afterwards is not a new event.
        assert!(!s.peer_fin());
        assert!(!s.send_closed());
    }

    #[test]
    fn socket_gone_implies_eof_and_write_refused() {
        let s = TcpCloseState::new();
        s.socket_gone();
        assert!(s.read_eof());
        assert!(s.write_refused());
        assert!(!s.is_app_dropped());
    }
}
