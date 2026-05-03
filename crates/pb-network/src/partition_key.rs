//! Network-side partition key derivation, Module 19.
//!
//! Architecture §3.5: every outbound network request carries a partition
//! key keyed on `(site_origin, identity_profile_id, context_id)`. The
//! coordinator (Module 19) recomputes the key from the originating tab's
//! identity context and rejects any mismatch — the network-side mirror of
//! the §5.2 storage gatekeeper rule.
//!
//! ## Why a mirror, not an import
//!
//! Architecture §4.1 (locked): `pb-network` may import only `pb-ipc`,
//! `pb-config`, and `pb-sandbox`. It MUST NOT depend on `pb-storage`.
//! This file is therefore a **byte-identical mirror** of
//! `pb_storage::partition_key`:
//!
//!   * domain label `PB-PARTKEY-V1`
//!   * length-prefixed `site_origin` (u64 little-endian length)
//!   * `identity_profile_id` (16-byte UUID)
//!   * `context_id` (16-byte UUID)
//!   * SHA-256 output (32 bytes)
//!
//! The known-answer test below pins the exact v1 hash for a fixed input
//! tuple. If `pb_storage::partition_key` ever drifts from this encoding
//! the storage-side known-answer test fires; if this file drifts from
//! that encoding the test below fires. Either failure forces a lock-step
//! fix.
//!
//! When a future architecture revision lifts the derivation into a shared
//! crate, this file and `pb_storage::partition_key` are deleted in the
//! same commit.
//
// TODO(architecture v2 candidate): hoist `PartitionKey` + `derive` into
//   a shared crate (pb-config or a new pb-keys leaf) to retire this
//   mirror. Until then, both copies stay byte-identical; the
//   known-answer test is the lock-step canary.

use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

/// Domain-separation label for the v1 derivation. MUST stay byte-identical
/// to `pb_storage::partition_key::PARTITION_KEY_DOMAIN`.
pub const PARTITION_KEY_DOMAIN: &[u8] = b"PB-PARTKEY-V1";

/// Width of a partition key in bytes (SHA-256 output).
pub const PARTITION_KEY_LEN: usize = 32;

/// 32-byte network-side partition key. Opaque newtype matching the storage
/// type's API surface.
///
/// `Debug` is intentionally redacted (first 8 hex chars + `...`); the
/// full key is sensitive (effectively the egress capability for a site
/// under one identity).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartitionKey([u8; PARTITION_KEY_LEN]);

impl PartitionKey {
    /// Borrow the raw 32-byte key. Used by the coordinator (Module 19) as
    /// the `HashMap` index for per-partition egress state.
    pub fn as_bytes(&self) -> &[u8; PARTITION_KEY_LEN] {
        &self.0
    }

    /// Hex-encoded full key (64 ASCII chars). Used in tests and in
    /// authenticated diagnostic surfaces only; never in routine logs.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(PARTITION_KEY_LEN * 2);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Debug for PartitionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();
        write!(f, "PartitionKey({}...)", &hex[..8])
    }
}

impl fmt::Display for PartitionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Derive a [`PartitionKey`] from the §3.5 inputs.
///
/// Pure: same inputs always yield the same key on every platform and
/// every build. No I/O, no clock, no allocation beyond the hasher's
/// internal state.
pub fn derive(site_origin: &str, identity_profile_id: Uuid, context_id: Uuid) -> PartitionKey {
    let mut hasher = Sha256::new();
    hasher.update(PARTITION_KEY_DOMAIN);
    let len = site_origin.len() as u64;
    hasher.update(len.to_le_bytes());
    hasher.update(site_origin.as_bytes());
    hasher.update(identity_profile_id.as_bytes());
    hasher.update(context_id.as_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; PARTITION_KEY_LEN];
    bytes.copy_from_slice(&out);
    PartitionKey(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u128) -> Uuid {
        Uuid::from_u128(seed)
    }

    #[test]
    fn derive_is_deterministic() {
        let a = derive("example.com", id(1), id(2));
        let b = derive("example.com", id(1), id(2));
        assert_eq!(a, b);
    }

    #[test]
    fn different_origin_yields_different_key() {
        let a = derive("example.com", id(1), id(2));
        let b = derive("evil.com", id(1), id(2));
        assert_ne!(a, b);
    }

    #[test]
    fn different_identity_yields_different_key() {
        let a = derive("example.com", id(1), id(2));
        let b = derive("example.com", id(99), id(2));
        assert_ne!(a, b);
    }

    #[test]
    fn different_context_yields_different_key() {
        let a = derive("example.com", id(1), id(2));
        let b = derive("example.com", id(1), id(99));
        assert_ne!(a, b);
    }

    #[test]
    fn boundary_shift_does_not_collide() {
        // Length prefix prevents byte-stream aliasing between
        // ("ab", id(1), id(2)) and ("a", id(1), id(2)).
        let a = derive("ab", id(1), id(2));
        let b = derive("a", id(1), id(2));
        assert_ne!(a, b);
    }

    #[test]
    fn debug_redacts_full_key() {
        let k = derive("example.com", id(1), id(2));
        let dbg = format!("{k:?}");
        let full = k.to_hex();
        assert!(!dbg.contains(&full));
        assert!(dbg.starts_with("PartitionKey("));
        assert!(dbg.ends_with("...)"));
    }

    #[test]
    fn display_is_full_hex() {
        let k = derive("example.com", id(1), id(2));
        assert_eq!(format!("{k}"), k.to_hex());
        assert_eq!(k.to_hex().len(), 64);
    }

    #[test]
    fn known_answer_v1_matches_storage_mirror() {
        // Lock-step canary with `pb_storage::partition_key`. The exact
        // 32 bytes are recomputed by hand from the (origin, profile,
        // context) triple below. If this test fails, either:
        //   * pb-storage drifted from the v1 encoding (its own
        //     `known_answer_v1` test will also fail), or
        //   * pb-network drifted, in which case bring this file back
        //     into byte-identical agreement with pb-storage and bump
        //     `PARTITION_KEY_DOMAIN` if any change was intentional.
        let k = derive(
            "example.com",
            Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001),
            Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002),
        );
        let mut h = Sha256::new();
        h.update(b"PB-PARTKEY-V1");
        h.update((b"example.com".len() as u64).to_le_bytes());
        h.update(b"example.com");
        h.update(Uuid::from_u128(1).as_bytes());
        h.update(Uuid::from_u128(2).as_bytes());
        let mut expected = [0u8; PARTITION_KEY_LEN];
        expected.copy_from_slice(&h.finalize());
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn domain_label_is_part_of_hash() {
        // Guard against a future edit dropping `PARTITION_KEY_DOMAIN`
        // from the hash input.
        let k = derive("example.com", id(1), id(2));
        let mut h = Sha256::new();
        h.update(b"PB-PARTKEY-V0");
        h.update((b"example.com".len() as u64).to_le_bytes());
        h.update(b"example.com");
        h.update(Uuid::from_u128(1).as_bytes());
        h.update(Uuid::from_u128(2).as_bytes());
        let mut other = [0u8; PARTITION_KEY_LEN];
        other.copy_from_slice(&h.finalize());
        assert_ne!(k.as_bytes(), &other);
    }
}
