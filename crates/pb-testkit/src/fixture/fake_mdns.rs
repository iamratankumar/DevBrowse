//! `fixture::fake_mdns` — programmable mDNS announce + browse stream.
//!
//! Subtask 2 of Module 0.5. Pre-empts the Phase 11.5 Module 86 retrofit:
//! sync-pairing tests need a way to script "peer X announced service Y"
//! without binding a real multicast socket. Each `FakeMdns` instance is
//! a single, isolated bus — instantiate one per test for guaranteed
//! parallel-test isolation.
//!
//! The fixture is shaped around two operations:
//!   * `announce` — a peer broadcasts a service tuple onto the bus.
//!   * `browse_stream` — a subscriber receives an async stream of every
//!     announce that lands on the bus from this point forward.
//!
//! When Module 86 ships, the production mDNS trait will likely be very
//! close to this shape; at that point this file should be reworked to
//! implement the real trait directly. Keeping the public types small
//! and clearly named makes that swap mechanical.
//
// TODO(Module 86): replace the standalone shape with an impl of the
//   production mDNS trait once it lands. Coordinate the rename of
//   `MdnsAnnounce` / `MdnsEvent` if the production names differ.

use std::sync::Mutex;
use tokio::sync::broadcast;

/// One mDNS announce: peer's service-instance name + service type +
/// hostname:port to reach it. Modeled after the RFC 6762 PTR + SRV pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsAnnounce {
    pub instance: String,
    pub service_type: String,
    pub host: String,
    pub port: u16,
}

/// Bus event delivered to browsers. Currently only `Announce`; future
/// additions (Goodbye = TTL=0 announce, etc.) extend this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsEvent {
    Announce(MdnsAnnounce),
}

/// In-process mDNS bus. Cheap to clone; the underlying `broadcast::Sender`
/// is shared, so all clones see the same announce stream.
#[derive(Clone)]
pub struct FakeMdns {
    tx: broadcast::Sender<MdnsEvent>,
    history: std::sync::Arc<Mutex<Vec<MdnsAnnounce>>>,
}

impl FakeMdns {
    /// Capacity of the broadcast channel. Sized so a slow subscriber
    /// receives a `Lagged(_)` rather than blocking the announcer.
    pub const CAPACITY: usize = 64;

    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(Self::CAPACITY);
        Self {
            tx,
            history: std::sync::Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Broadcast an announce to every active subscriber. Records the
    /// announce in the history log for post-hoc assertions.
    pub fn announce(&self, a: MdnsAnnounce) {
        self.history.lock().unwrap().push(a.clone());
        // Send errors only when there are no subscribers; that is fine.
        let _ = self.tx.send(MdnsEvent::Announce(a));
    }

    /// Subscribe to the bus. Returns a `broadcast::Receiver` that yields
    /// every event sent after the call.
    pub fn browse_stream(&self) -> broadcast::Receiver<MdnsEvent> {
        self.tx.subscribe()
    }

    /// Snapshot of every announce that has crossed this bus since
    /// construction. Use for "the announcer announced exactly these"
    /// assertions; for "the browser received exactly these" assertions
    /// drain the `browse_stream` directly.
    pub fn history(&self) -> Vec<MdnsAnnounce> {
        self.history.lock().unwrap().clone()
    }
}

impl Default for FakeMdns {
    fn default() -> Self {
        Self::new()
    }
}

/// Free-function form, mirroring the `fixture::fake_mdns()` shape called
/// out in the phase file.
pub fn fake_mdns() -> FakeMdns {
    FakeMdns::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(instance: &str) -> MdnsAnnounce {
        MdnsAnnounce {
            instance: instance.into(),
            service_type: "_devbrowse-sync._tcp.local.".into(),
            host: "peer.local.".into(),
            port: 9999,
        }
    }

    #[tokio::test]
    async fn subscriber_receives_subsequent_announce() {
        let bus = fake_mdns();
        let mut rx = bus.browse_stream();
        bus.announce(sample("peer-A"));
        let evt = rx.recv().await.unwrap();
        assert_eq!(evt, MdnsEvent::Announce(sample("peer-A")));
    }

    #[test]
    fn history_records_all_announces_even_without_subscribers() {
        let bus = fake_mdns();
        bus.announce(sample("peer-A"));
        bus.announce(sample("peer-B"));
        let h = bus.history();
        assert_eq!(h, vec![sample("peer-A"), sample("peer-B")]);
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_announce() {
        let bus = fake_mdns();
        let mut r1 = bus.browse_stream();
        let mut r2 = bus.browse_stream();
        bus.announce(sample("peer-A"));
        assert_eq!(
            r1.recv().await.unwrap(),
            MdnsEvent::Announce(sample("peer-A"))
        );
        assert_eq!(
            r2.recv().await.unwrap(),
            MdnsEvent::Announce(sample("peer-A"))
        );
    }
}
