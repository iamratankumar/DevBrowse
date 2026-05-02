//! Partition key derivation, Module 14.
//!
//! Architecture §5.2: every storage cell carries a partition key
//!   key = sha256( site_origin || identity_profile_id || context_id )
//! and the gatekeeper (Module 15) checks it on every read and write
//! without exception.
//!
//! Inputs:
//!   * `site_origin`: eTLD+1 origin string. Validated by callers (Module
//!     16 enforces lowercased, scheme-stripped form); this module accepts
//!     `&str` and trusts upstream normalization.
//!   * `identity_profile_id`: UUID, immutable per IdentityProfile (§3.1).
//!   * `context_id`: UUID. Per architecture §3.5, stable per Standard
//!     profile and fresh per Strict tab (the cookie/session firewall,
//!     §3.6).
//!
//! Encoding is domain-separated and length-prefixed:
//!
//!   PB-PARTKEY-V1
//!   || u64_le( len(site_origin) )
//!   || site_origin bytes
//!   || identity_profile_id (16 byte UUID)
//!   || context_id          (16 byte UUID)
//!
//! The version label is part of the hash input. Any future scheme change
//! (e.g. adding a fourth field) MUST bump the label so old and new keys
//! cannot collide. The length prefix on the only variable-width field
//! prevents an attacker from shifting bytes across the field boundary
//! without changing the hash.
//!
//! SHA-256 comes from `sha2` (L7: audited primitives only). Any future
//! scheme change must bump [`PARTITION_KEY_DOMAIN`] so old and new keys
//! cannot collide; the gatekeeper (Module 15) is the sole consumer and
//! must be migrated in lockstep.

use sha2::{Digest, Sha256};
use std::fmt;
use uuid::Uuid;

/// Domain-separation label for the v1 derivation. Versioned so a future
/// scheme change produces disjoint keys from v1 by construction.
pub const PARTITION_KEY_DOMAIN: &[u8] = b"PB-PARTKEY-V1";

/// Width of a partition key in bytes (SHA-256 output).
pub const PARTITION_KEY_LEN: usize = 32;

/// A 32-byte partition key. Opaque newtype so callers cannot construct
/// one without going through [`derive`] and cannot accidentally consume
/// a partial key as the gatekeeper input.
///
/// `Debug` is intentionally redacted (first 8 hex chars + "..."): the
/// full key is sensitive (it is effectively the storage capability for a
/// site under one identity), so it must not land in logs verbatim. Use
/// [`PartitionKey::to_hex`] when an explicit full-form is needed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartitionKey([u8; PARTITION_KEY_LEN]);

impl PartitionKey {
    /// Borrow the raw 32-byte key. Used by the gatekeeper (Module 15) as
    /// the column value on every storage row.
    pub fn as_bytes(&self) -> &[u8; PARTITION_KEY_LEN] {
        &self.0
    }

    /// Hex-encoded full key (64 ASCII chars). Used in tests and in
    /// authenticated diagnostic surfaces only; never in routine logs.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(PARTITION_KEY_LEN * 2);
        for b in self.0 {
            // Manual hex avoids pulling in another dep just for this.
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Debug for PartitionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print only the leading 8 hex chars: enough to disambiguate
        // keys in a trace without revealing the full capability.
        let hex = self.to_hex();
        write!(f, "PartitionKey({}...)", &hex[..8])
    }
}

impl fmt::Display for PartitionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Derive a [`PartitionKey`] from the §5.2 inputs.
///
/// Pure function: same inputs always yield the same key on every
/// platform and every build. No I/O, no clock, no allocation beyond
/// the hasher's internal state.
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
        // Deterministic UUIDs for tests; we only need stable distinct
        // 16-byte values here, not v4 randomness.
        Uuid::from_u128(seed)
    }

    #[test]
    fn derive_is_deterministic() {
        let a = derive("example.com", id(1), id(2));
        let b = derive("example.com", id(1), id(2));
        assert_eq!(a, b, "same inputs must yield same key");
    }

    #[test]
    fn different_site_origin_yields_different_key() {
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
        // Without the length prefix, ("ab", "c") and ("a", "bc") would
        // serialize to the same byte stream. The length prefix on
        // site_origin must keep these disjoint.
        //
        // Here we vary only site_origin; the UUIDs are equal so the
        // suffix bytes match. The site_origin "ab" + later UUIDs vs
        // "a" + later UUIDs differ only by where the boundary is, plus
        // the length prefix. That length prefix is what we are testing.
        let a = derive("ab", id(1), id(2));
        let b = derive("a", id(1), id(2));
        assert_ne!(a, b);
    }

    #[test]
    fn empty_site_origin_is_distinct_from_short_one() {
        let a = derive("", id(1), id(2));
        let b = derive("x", id(1), id(2));
        assert_ne!(a, b);
    }

    #[test]
    fn hex_is_64_chars() {
        let k = derive("example.com", id(1), id(2));
        let h = k.to_hex();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn debug_redacts_full_key() {
        let k = derive("example.com", id(1), id(2));
        let dbg = format!("{k:?}");
        let full = k.to_hex();
        assert!(
            !dbg.contains(&full),
            "Debug must not print the full key, got: {dbg}"
        );
        assert!(dbg.starts_with("PartitionKey("));
        assert!(dbg.ends_with("...)"));
    }

    #[test]
    fn display_is_full_hex() {
        let k = derive("example.com", id(1), id(2));
        assert_eq!(format!("{k}"), k.to_hex());
    }

    #[test]
    fn as_bytes_round_trips_via_hex() {
        let k = derive("example.com", id(1), id(2));
        let bytes = *k.as_bytes();
        let hex = k.to_hex();
        // Reconstruct bytes from hex and compare.
        let mut roundtrip = [0u8; PARTITION_KEY_LEN];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).unwrap();
            roundtrip[i] = u8::from_str_radix(s, 16).unwrap();
        }
        assert_eq!(bytes, roundtrip);
    }

    #[test]
    fn known_answer_v1() {
        // Pin the v1 derivation. If this hash ever changes, the
        // PARTITION_KEY_DOMAIN MUST be bumped (e.g. PB-PARTKEY-V2),
        // because changing v1 silently would invalidate every row
        // already on disk.
        let k = derive(
            "example.com",
            Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001),
            Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0002),
        );
        // Recompute by hand to verify the encoding without trusting
        // the implementation under test.
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
        // Recompute the same inputs but with a different domain label
        // and confirm the keys are disjoint. Guards against a future
        // edit that drops `PARTITION_KEY_DOMAIN` from the hash input.
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
