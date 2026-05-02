//! Sync log — Module 84.
//!
//! Per-record append-only operation log. Vector clocks identify each
//! op's source device. Each entry is signed by the originating device's
//! Ed25519 key so a hub-peer cannot tamper with the log, only forward it.
//!
//! TODO(Module 84):
//!   * Op-log entry shape: { record_id, device_id, lamport_seq,
//!     vector_clock, op (insert/update/delete), payload_ciphertext,
//!     ed25519_signature }.
//!   * Per-record vector clocks for conflict detection.
//!   * LWW (last-writer-wins) reconciliation for tabs / history /
//!     bookmarks where overwriting is acceptable.
//!   * Per-record conflict surfacing for credentials: if two devices
//!     edited the same password since last sync, surface both versions
//!     in the UI and let the user pick. No silent overwrite.
//!   * Periodic compaction: collapse a sequence of edits to one record
//!     into a single op once every cluster member has acknowledged the
//!     resulting state.
//!   * Anti-replay: per-pair monotonic sequence numbers + 5-minute
//!     timestamp window enforced at transport (Module 88) AND log
//!     ingestion here, so a captured-and-replayed log entry is rejected.
//!   * Each entry signed by originating device's Ed25519 key. Verification
//!     happens before apply, not after, so a forged entry never touches
//!     the vault.
