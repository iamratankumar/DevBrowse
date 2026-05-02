//! LAN pairing — Module 87.
//!
//! SPAKE2 PAKE bootstrapped from a 6-digit code, mandatory 4-emoji
//! fingerprint compare on both screens, then Ed25519 long-term identity
//! key exchange. Identity keys persisted via OS keystore.
//!
//! Two equivalent UX flows reach the same cryptographic outcome:
//!
//!   1. mDNS-list flow:
//!      Device A enters pairing mode, announces a temporary slot
//!      (Module 86), shows a 6-digit code on screen. Device B sees
//!      Device A in its discovery list, taps it, types the code.
//!
//!   2. QR-scan flow:
//!      Device A shows a QR encoding (6-digit code, pairing nonce,
//!      ephemeral public key). Device B scans with the camera. No code
//!      typing required. Best for laptop <-> phone pairing.
//!
//! Both flows end with the 4-emoji fingerprint compare. NOT skippable.
//!
//! TODO(Module 87):
//!   * SPAKE2 (or magic-wormhole-style construction) over the 6-digit
//!     code. Derives a strong session key without ever sending the code
//!     in cleartext on the wire.
//!   * Code rules: 6 digits (1M space), 90-second TTL, max 5 wrong
//!     attempts then code burns and a fresh code must be generated.
//!     Rate limit defeats online brute force.
//!   * 4-emoji (or 6-word) fingerprint derived from the established
//!     session key. Both devices show the same emojis; user confirms
//!     match before either device commits the pair record. Defeats
//!     active MITM at pair time.
//!   * After fingerprint confirm: each device generates a long-term
//!     Ed25519 identity keypair (if it doesn't already have one),
//!     exchanges public keys signed under the session key, persists
//!     pair record + remote pubkey.
//!   * Identity keys live in OS keystore: macOS Keychain, iOS Keychain,
//!     Win DPAPI, Android Keystore, libsecret on Linux. Never flat file
//!     on disk. `keyring` crate (or platform-specific bindings) wraps
//!     all five.
//!   * Pair record includes: remote_device_id, remote_pubkey, name,
//!     device_type (laptop/phone/tablet/desktop), paired_at, last_seen,
//!     hub_peer_role (bool, off by default).
//!   * Unpair flow: user removes a device from settings; pair record
//!     deleted; cluster-key rotation triggered (Module 91); other
//!     cluster members notified at next sync.
//!   * QR encoding format documented + versioned so future scanners
//!     can detect incompatible versions.
