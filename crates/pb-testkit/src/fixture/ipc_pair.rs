//! `fixture::ipc_pair` — duplex-backed IPC connection pair.
//!
//! Subtask 2 of Module 0.5. Returns a connected
//! `(DuplexConnection, DuplexConnection)` so tests do not spawn a Unix
//! socket per case. The duplex backend uses the same length-prefixed
//! framing as the production Unix backend (see `pb_ipc::transport`), so
//! a test that passes here covers the same wire format.

use pb_ipc::testkit::{DuplexConnection, DEFAULT_DUPLEX_CAPACITY};

/// Default-capacity in-memory IPC pair. Both ends speak the production
/// framing. `MAX_MESSAGE_BYTES` payloads round-trip without blocking.
pub fn ipc_pair() -> (DuplexConnection, DuplexConnection) {
    DuplexConnection::pair_with_capacity(DEFAULT_DUPLEX_CAPACITY)
}

/// Explicit-capacity in-memory IPC pair. Use this when a test wants to
/// exercise back-pressure (capacity smaller than `payload + 4` causes
/// `send` to await the peer's `recv`).
pub fn ipc_pair_with_capacity(capacity: usize) -> (DuplexConnection, DuplexConnection) {
    DuplexConnection::pair_with_capacity(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_via_fixture() {
        let (mut a, mut b) = ipc_pair();
        a.send(b"hello").await.unwrap();
        assert_eq!(b.recv().await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn back_pressure_via_small_capacity() {
        // 8-byte buffer cannot hold a 100-byte payload + 4-byte prefix
        // without the peer reading. The send completes only because the
        // recv runs concurrently.
        let (mut a, mut b) = ipc_pair_with_capacity(8);
        let payload = vec![0xAB; 100];
        let send_handle = tokio::spawn(async move { a.send(&payload).await });
        let recv_handle = tokio::spawn(async move { b.recv().await });
        send_handle.await.unwrap().unwrap();
        let got = recv_handle.await.unwrap().unwrap();
        assert_eq!(got.len(), 100);
    }
}
