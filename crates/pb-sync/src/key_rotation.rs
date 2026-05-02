//! Cluster key rotation — Module 91.
//!
//! Rotates the cluster's shared symmetric key. Triggered by:
//!   * Unpair: when a device leaves the cluster, the remaining members
//!     rotate so the removed device's stored copy of the cluster key
//!     becomes useless.
//!   * Schedule: every 90 days by default, configurable.
//!   * User request: explicit "rotate keys now" action in settings.
//!
//! After rotation:
//!   * Vault is re-encrypted under the new cluster key on each member.
//!   * Sync log entries get a new signing-key fingerprint moving forward.
//!     Old entries remain verifiable under their original signing key.
//!   * Pending hub-peer blobs encrypted under the old key are flushed
//!     (or re-encrypted by the originating device on next contact).
//!
//! TODO(Module 91):
//!   * Coordinated rotation protocol: one device proposes a new
//!     cluster key, broadcasts it to other paired devices via Module
//!     88, each acks; on quorum (default: all paired devices online
//!     within 24h, otherwise user must confirm partial rotation),
//!     the new key is committed.
//!   * Edge case: device offline during rotation. On its next sync,
//!     it receives the new cluster key encrypted under its X25519
//!     identity key (the only thing the cluster knows about it that
//!     it still has access to via OS keystore).
//!   * Edge case: unpair while target device is offline. The target
//!     device, when it reconnects, will fail to authenticate (its
//!     pair record was removed) and is treated as a new pairing
//!     attempt. Architecture L21 contract upheld.
//!   * Audit trail: each rotation records (timestamp, trigger,
//!     committed_by_device, ack_set) so the user can review past
//!     rotations in a settings panel.
