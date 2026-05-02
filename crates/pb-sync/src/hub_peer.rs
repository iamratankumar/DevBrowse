//! Hub-peer forwarding — Module 89.
//!
//! Any paired device can opt in as a hub-peer for the cluster. A hub-peer
//! holds encrypted blobs for offline cluster members and forwards them
//! when the recipient comes online. The hub is NOT a server; it's just
//! one of the user's devices acting as a forwarder. DevBrowse runs no
//! infrastructure for this.
//!
//! Direct-message blobs (e.g. send-tab, Module 90) are encrypted to the
//! recipient device's X25519 key, so the hub holds opaque ciphertext.
//! Vault sync blobs are encrypted under the cluster key, which the hub
//! also has (the hub is one of the user's devices). That is the same
//! security posture as Apple's iCloud Keychain - any device in the
//! trusted set can decrypt cluster data.
//!
//! TODO(Module 89):
//!   * Per-device toggle in settings: "Allow this device to forward
//!     sync data for the cluster." Off by default. User enables on
//!     their always-on device (typically the laptop).
//!   * Storage shape: append-only queue keyed by recipient device_id.
//!     Each entry has a TTL (default 7 days) so abandoned blobs don't
//!     accumulate. After a successful forward, the entry is deleted
//!     immediately.
//!   * Forward protocol: when a paired device connects, the hub
//!     iterates that device's queue and pushes each blob over the
//!     existing QUIC stream. Receiver acks; hub deletes on ack.
//!   * Per-recipient X25519 envelopes for direct-message blobs:
//!     sender encrypts payload to recipient's pubkey; hub cannot
//!     decrypt even though it sees the ciphertext flow through.
//!   * Cluster-key blobs (vault sync) are NOT additionally enveloped
//!     because the hub already has the cluster key. Adding an extra
//!     layer would buy nothing.
//!   * Capacity limits: bound the queue size per recipient (default
//!     500 MB) and overall (default 5 GB). Refuse new blobs past the
//!     limit and surface the error to the sender so the user can
//!     manually trigger a sync or unpair the offline device.
//!   * Hub-peer blobs are signed by the originating device (Ed25519
//!     signature on the inner sync-log entry, Module 84). A
//!     compromised hub cannot forge new entries, only forward or drop.
