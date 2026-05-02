//! Self-hosted relay (WebDAV) — Module 92.
//!
//! Last-resort cross-network transport. Off by default. Same
//! encrypted-blob protocol as the hub-peer (Module 89): the relay sees
//! ciphertext only.
//!
//! Use case: the user wants their phone (4G, away from home) to sync
//! with their laptop (home WiFi). LAN discovery cannot find the phone
//! across networks. Hub-peer can hold the blob if either device is on
//! the home LAN periodically. WebDAV bridges the gap by giving the
//! cluster a meeting point that the user runs themselves (Nextcloud,
//! self-hosted DAV server, Fastmail Files, etc.).
//!
//! A hosted DevBrowse-run relay is explicitly NOT in scope. If we ran
//! one we would still need infrastructure, billing, and a privacy
//! posture for it. The architecture's "no DevBrowse server" lock holds.
//!
//! TODO(Module 92):
//!   * `RelayAdapter` trait that the WebDAV implementation satisfies.
//!     Future relays (e.g. user-runnable WireGuard mesh, see §11
//!     "Push-based sync over WAN") plug in behind the same trait.
//!   * WebDAV impl: configurable URL + credentials (stored in OS
//!     keystore, never disk-plain). The relay is treated as a dumb
//!     blob store: PUT new blobs, LIST recipient queue, GET, DELETE.
//!   * The relay never sees plaintext. Same per-recipient X25519
//!     envelopes as hub-peer for direct messages; cluster-key
//!     ciphertext for vault sync. Relay metadata (filenames, sizes,
//!     timing) is the only thing leaked - document this clearly to
//!     the user when they enable WebDAV.
//!   * Conflict with hub-peer: when both T1 (LAN) and T2 (hub-peer)
//!     are unavailable, T3 (this module) is used. When T1 or T2 are
//!     available again, T3 is skipped. Single-priority resolution
//!     prevents duplicate delivery.
//!   * Off by default. User must explicitly enable in settings, with
//!     a one-time consent dialog explaining the metadata leak and
//!     that they are responsible for the relay's availability.
