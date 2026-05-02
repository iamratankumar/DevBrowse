//! Sync subsystem — Phase 11.5 (Modules 83-92).
//!
//! End-to-end encrypted, LAN-first cluster sync. No DevBrowse server, no
//! SaaS cloud backends. Three transport tiers in priority order:
//!
//!   T1: Direct LAN  — mDNS discovery + QUIC + Ed25519 mTLS (default)
//!   T2: Hub-peer    — store-and-forward via a paired device that opted in
//!   T3: WebDAV      — optional, off by default, user runs the relay
//!
//! Initial pairing requires both devices on the same WiFi (LAN-only by
//! design). Sync is foreground-only; mobile background sync is out of
//! scope. Password manager UI is a separate future phase, not part of
//! this crate.
//!
//! Module map (architecture §6, Phase 11.5):
//!
//!   * Module 83 — `vault`        Argon2id + HKDF + XChaCha20-Poly1305
//!   * Module 84 — `sync_log`     per-record op log + vector clocks
//!   * Module 85 — `backup`       export/import a single user-controlled file
//!   * Module 86 — `discovery`    mDNS service announce + browse
//!   * Module 87 — `pairing`      SPAKE2 6-digit + 4-emoji fingerprint
//!   * Module 88 — `transport`    QUIC + Ed25519 mTLS, replay window
//!   * Module 89 — `hub_peer`     opt-in store-and-forward
//!   * Module 90 — `send_tab`     one-shot tab push to a named device
//!   * Module 91 — `key_rotation` cluster-key rotation on unpair / schedule
//!   * Module 92 — `relay`        optional self-hosted WebDAV
//!
//! Threat model boundaries (architecture L21):
//!   * One paired device compromised  -> full vault read (same as Apple
//!     Keychain / Bitwarden). Mitigation: per-device unpair triggers
//!     cluster-key rotation (Module 91).
//!   * Hub-peer compromise            -> ciphertext only. Direct messages
//!     use per-recipient X25519 envelopes the hub cannot decrypt.
//!   * LAN attacker                   -> cannot pair (PAKE), cannot read
//!     (mTLS over QUIC), cannot impersonate (Ed25519 pinning).
//!   * Pairing-time MITM              -> mandatory 4-emoji fingerprint
//!     compare on both screens. No skip button.

#![forbid(unsafe_code)]

pub mod backup;
pub mod discovery;
pub mod hub_peer;
pub mod key_rotation;
pub mod pairing;
pub mod relay;
pub mod send_tab;
pub mod sync_log;
pub mod transport;
pub mod vault;
