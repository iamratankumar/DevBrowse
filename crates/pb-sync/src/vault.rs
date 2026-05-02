//! Vault crypto — Module 83.
//!
//! Versioned encrypted-vault format that backs every other module in
//! this crate. Passphrase derives a master key via Argon2id; HKDF
//! produces per-purpose subkeys; each blob is sealed with
//! XChaCha20-Poly1305. In-memory secrets use `zeroize` on drop.
//!
//! TODO(Module 83):
//!   * Argon2id parameters (memory, iterations, parallelism) chosen
//!     from a benchmark at first launch; persist alongside the vault
//!     so re-derivation is identical across devices.
//!   * HKDF key ladder: master -> (cluster_key, sync_log_signing_key,
//!     per_device_x25519_seed). Each branch labelled with a domain
//!     separator to prevent cross-purpose key reuse.
//!   * Versioned vault format (L24): magic bytes + format_version + KDF
//!     params + ciphertext. Bump format_version for any incompatible
//!     change so backups can be detected and rejected cleanly.
//!   * `zeroize::Zeroize` for every in-memory secret (master key,
//!     cluster key, ephemeral PAKE keys, X25519 private keys).
//!   * Auto-lock (architecture L21): master key wiped on any of (a) OS
//!     suspend / sleep notification, (b) lid-close on laptops, (c)
//!     configurable inactivity timeout (default 15 min). All three paths
//!     converge on the same `lock()` routine; re-prompt passphrase to
//!     unlock. Subscribe to OS suspend signals via `pb-platform`
//!     (Linux: logind, macOS: NSWorkspaceWillSleepNotification,
//!     iOS/Android: app lifecycle - Phase 12).
//!   * Post-quantum migration path: format_version v2+ allows
//!     ML-KEM-768 / ML-DSA-65 alongside the v1 primitives (Future
//!     Improvements section, architecture §11).
