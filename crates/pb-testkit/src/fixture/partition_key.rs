//! `fixture::partition_key` — deterministic partition-key derivation
//! and gatekeeper-passing StorageRequest builder.
//!
//! Subtask 2 of Module 0.5.

use pb_storage::{derive_partition_key, PartitionKey, StorageRequest};
use uuid::Uuid;

/// A partition triple plus the canonical key derived from it. Useful
/// when a test needs to reference both the inputs (to mint variants
/// that *should* fail gatekeeper) and the matching key.
#[derive(Debug, Clone)]
pub struct FixturePartition {
    pub site_origin: String,
    pub identity_profile_id: Uuid,
    pub context_id: Uuid,
    pub key: PartitionKey,
}

impl FixturePartition {
    /// Build a `StorageRequest` whose `declared_key` matches the triple,
    /// so `Gatekeeper::authorize` accepts it.
    pub fn request(&self) -> StorageRequest {
        StorageRequest {
            site_origin: self.site_origin.clone(),
            identity_profile_id: self.identity_profile_id,
            context_id: self.context_id,
            declared_key: self.key,
        }
    }

    /// Build a `StorageRequest` whose `declared_key` is a *foreign* key
    /// (derived from a different triple), so `Gatekeeper::authorize`
    /// rejects it with `KeyMismatch`. Used by negative-path tests that
    /// want to assert §5.2 enforcement without re-deriving a foreign key
    /// inline.
    pub fn tampered_request(&self, foreign_origin: &str) -> StorageRequest {
        let foreign_key =
            derive_partition_key(foreign_origin, self.identity_profile_id, self.context_id);
        StorageRequest {
            site_origin: self.site_origin.clone(),
            identity_profile_id: self.identity_profile_id,
            context_id: self.context_id,
            declared_key: foreign_key,
        }
    }
}

/// Derive a partition key from fixed canonical inputs. Use this when a
/// test needs *some* valid key and does not care which one.
pub fn partition_key() -> FixturePartition {
    fixture_partition_for("example.test", 0xABCD_0001, 0xABCD_0002)
}

/// Build a `StorageRequest` from the canonical fixed triple. Equivalent
/// to `partition_key().request()`, separated so the call site reads
/// naturally where only the request is needed.
pub fn partition_key_request() -> StorageRequest {
    partition_key().request()
}

/// Derive a `FixturePartition` from explicit (origin, profile-seed,
/// context-seed) inputs. Use this when a test needs distinct partitions
/// (e.g. cross-partition isolation tests).
pub fn fixture_partition_for(
    origin: &str,
    profile_seed: u128,
    context_seed: u128,
) -> FixturePartition {
    let identity_profile_id = Uuid::from_u128(profile_seed);
    let context_id = Uuid::from_u128(context_seed);
    let key = derive_partition_key(origin, identity_profile_id, context_id);
    FixturePartition {
        site_origin: origin.to_string(),
        identity_profile_id,
        context_id,
        key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_storage::Gatekeeper;

    #[test]
    fn canonical_request_passes_gatekeeper() {
        let gk = Gatekeeper::new();
        let r = partition_key_request();
        assert!(gk.authorize(&r).is_ok());
    }

    #[test]
    fn tampered_request_fails_gatekeeper() {
        let gk = Gatekeeper::new();
        let p = partition_key();
        let r = p.tampered_request("evil.test");
        assert!(gk.authorize(&r).is_err());
    }

    #[test]
    fn distinct_partitions_have_distinct_keys() {
        let a = fixture_partition_for("a.test", 1, 1);
        let b = fixture_partition_for("b.test", 1, 1);
        assert_ne!(a.key.as_bytes(), b.key.as_bytes());
    }
}
