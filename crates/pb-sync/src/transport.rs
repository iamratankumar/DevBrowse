//! LAN transport — Module 88.
//!
//! QUIC over UDP, mTLS authenticated by pinned Ed25519 identity keys.
//! No CA trust. Per-pair monotonic sequence numbers + 5-minute timestamp
//! window block replay. Forward secrecy comes from the QUIC handshake.
//!
//! TODO(Module 88):
//!   * QUIC transport via the `quinn` crate. UDP makes NAT and mobile
//!     network handovers easier than TCP.
//!   * mTLS inside QUIC: each device presents a self-signed certificate
//!     whose public key matches its long-term Ed25519 identity (Module
//!     87). Peer accepts only if the cert pubkey matches the pinned
//!     pubkey from the pair record. Reject anything else.
//!   * No CA root store. We are not on the public Web here; using
//!     webpki/rustls roots would weaken the model.
//!   * Per-pair sequence numbers: every payload carries a monotonically
//!     increasing u64. Receiver tracks the last accepted seq per
//!     remote device; out-of-window or repeated seqs are rejected.
//!   * 5-minute timestamp window: receiver rejects payloads whose
//!     timestamp differs from local clock by more than 5 min in either
//!     direction. Captured-and-replayed blobs become useless after the
//!     window closes.
//!   * Forward secrecy: each new QUIC connection negotiates fresh
//!     session keys. A long-term identity key compromise does not
//!     decrypt past traffic.
//!   * Multiplexed streams over one connection: control stream,
//!     sync_log stream, send_tab stream, hub-peer stream. QUIC's
//!     stream multiplexing avoids head-of-line blocking when one
//!     payload is large (vault export) and another small (a tab push).
//!   * Connection re-establishment policy: when a paired device
//!     re-appears (Module 86), reuse the cached identity binding
//!     and start a new QUIC handshake. No interactive re-auth.
