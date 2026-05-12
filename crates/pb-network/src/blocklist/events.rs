//! Block-event surface, Module 21.
//!
//! Architecture L26: every blocked request emits a classified event
//! the Network Viewer (Module 60) can render. Counters are
//! **in-process, never persisted, never network-shipped**, so the
//! sink trait carries the [`PartitionKey`] only for in-process
//! aggregation; subscribers MUST NOT serialize it (per L27 + L26).
//!
//! v1 ships:
//!   * [`BlockedEvent`] value type
//!   * [`BlockEventSink`] trait
//!   * [`NoopSink`] — production default until Module 60 wires its
//!     subscriber in
//!   * [`CapturingSink`] — `#[cfg(test)]`-style capturing impl, but
//!     also available in non-test builds for integration harnesses
//
// TODO(Module 60): wire the network-viewer-side subscriber and route
//   per-tab counters through it. Until then the broker emits to
//   `NoopSink` by default; tests inject `CapturingSink` directly.

use crate::blocklist::rule::BlockKind;
use crate::partition_key::PartitionKey;
use std::fmt;
use std::sync::Mutex;

/// Classified block event. Includes the [`BlockKind`] so the viewer
/// can break out per-kind counts and the [`PartitionKey`] so the
/// per-tab counter slot is unambiguous.
///
/// `Debug` redacts the partition key (it falls back on
/// `PartitionKey`'s own redacted Debug); the kind is small and not
/// sensitive on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockedEvent {
    pub kind: BlockKind,
    pub partition_key: PartitionKey,
}

/// Subscriber for [`BlockedEvent`]s. Implementations MUST NOT block
/// (the route path calls `on_block` synchronously). Implementations
/// also MUST NOT panic — a panic here aborts the route task.
pub trait BlockEventSink: Send + Sync + fmt::Debug {
    fn on_block(&self, event: BlockedEvent);
}

/// Default sink — drops every event. Used until Module 60 wires its
/// real subscriber.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSink;

impl BlockEventSink for NoopSink {
    fn on_block(&self, _event: BlockedEvent) {}
}

/// Capturing sink used by tests + integration harnesses. Stores
/// every event in an in-memory `Vec` for later assertion. Locks
/// internally; safe to share across threads.
#[derive(Debug, Default)]
pub struct CapturingSink {
    events: Mutex<Vec<BlockedEvent>>,
}

impl CapturingSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.events.lock().expect("capturing sink lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn drain(&self) -> Vec<BlockedEvent> {
        let mut g = self.events.lock().expect("capturing sink lock");
        std::mem::take(&mut *g)
    }

    pub fn snapshot(&self) -> Vec<BlockedEvent> {
        self.events.lock().expect("capturing sink lock").clone()
    }
}

impl BlockEventSink for CapturingSink {
    fn on_block(&self, event: BlockedEvent) {
        self.events.lock().expect("capturing sink lock").push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition_key;
    use uuid::Uuid;

    fn pk() -> PartitionKey {
        partition_key::derive("example.com", Uuid::from_u128(1), Uuid::from_u128(2))
    }

    #[test]
    fn noop_sink_drops_events_without_panic() {
        let s = NoopSink;
        s.on_block(BlockedEvent {
            kind: BlockKind::Ad,
            partition_key: pk(),
        });
    }

    #[test]
    fn capturing_sink_records_events() {
        let s = CapturingSink::new();
        assert!(s.is_empty());
        s.on_block(BlockedEvent {
            kind: BlockKind::Ad,
            partition_key: pk(),
        });
        s.on_block(BlockedEvent {
            kind: BlockKind::Tracker,
            partition_key: pk(),
        });
        assert_eq!(s.len(), 2);
        let snap = s.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].kind, BlockKind::Ad);
        assert_eq!(snap[1].kind, BlockKind::Tracker);
    }

    #[test]
    fn drain_returns_and_clears() {
        let s = CapturingSink::new();
        s.on_block(BlockedEvent {
            kind: BlockKind::Ad,
            partition_key: pk(),
        });
        let out = s.drain();
        assert_eq!(out.len(), 1);
        assert!(s.is_empty());
    }

    #[test]
    fn debug_does_not_leak_partition_key_full_hex() {
        // BlockedEvent's PartitionKey field has a redacted Debug.
        // Confirm the event's Debug inherits that redaction.
        let ev = BlockedEvent {
            kind: BlockKind::Ad,
            partition_key: pk(),
        };
        let dbg = format!("{ev:?}");
        let full_hex = pk().to_hex();
        assert!(
            !dbg.contains(&full_hex),
            "BlockedEvent Debug must not leak the full key, got: {dbg}"
        );
    }
}
