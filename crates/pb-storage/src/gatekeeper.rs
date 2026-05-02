//! Storage gatekeeper, Module 15.
//!
//! Architecture §5.2: every storage operation in pb-storage passes
//! through the gatekeeper. The gatekeeper recomputes the expected
//! partition key from the request context and rejects any read or
//! write whose declared key differs. There is no fast path, no admin
//! override, no test bypass.
//!
//! v1 contract:
//!   * The gatekeeper is the sole site in pb-storage that derives a
//!     partition key from a request triple. Module 16 (primitives) MUST
//!     route every read and write through `Gatekeeper::authorize` and
//!     MUST NOT call `partition_key::derive` directly.
//!   * On match the gatekeeper returns the canonical `PartitionKey`;
//!     callers should use that returned value (not the declared one)
//!     when issuing SQL, so a single source-of-truth flows downstream.
//!
//! v1 design notes:
//!   * The gatekeeper is stateless. The struct shape exists so future
//!     hooks (audit log, metrics, rate limit) can attach without
//!     changing call sites.
//!   * Comparison uses byte equality. pb-storage runs in the trusted
//!     storage broker process; there is no remote attacker observing
//!     timing here, so constant-time comparison is not warranted in v1.
//!     If the gatekeeper is ever lifted onto an untrusted path, switch
//!     to `subtle::ConstantTimeEq`.
//!
//! TODO(Module 80): orchestrator owns a single `Gatekeeper` instance
//!   alongside the `StorageProcess`; do not construct ad-hoc
//!   gatekeepers per request.

use crate::partition_key::{self, PartitionKey};
use thiserror::Error;
use uuid::Uuid;

/// Storage request envelope crossing the gatekeeper.
///
/// The `(site_origin, identity_profile_id, context_id)` triple is the
/// partition context. `declared_key` is the key the caller claims
/// corresponds to that triple; the gatekeeper recomputes and verifies.
#[derive(Debug, Clone)]
pub struct StorageRequest {
    /// eTLD+1 origin string. Validated by upstream callers; the
    /// gatekeeper trusts this normalization (same contract as
    /// `partition_key::derive`).
    pub site_origin: String,
    /// Immutable identity profile id (architecture §3.1).
    pub identity_profile_id: Uuid,
    /// Context id (architecture §3.5: stable per Standard profile,
    /// fresh per Strict tab).
    pub context_id: Uuid,
    /// Partition key the caller claims this request belongs to.
    pub declared_key: PartitionKey,
}

/// Errors produced by the gatekeeper. `KeyMismatch` is the §5.2 hard
/// rejection; other variants are reserved for future hook kinds (rate
/// limit, suspended identity, etc.) but produce no false positives in
/// v1.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatekeeperError {
    /// Declared partition key did not match the key derived from the
    /// (origin, profile, context) triple. §5.2 rejection.
    #[error("partition key mismatch: declared key does not match request context")]
    KeyMismatch,
}

/// Stateless v1 gatekeeper. Future versions may carry audit / metrics
/// state; the type stays the same so call sites do not change.
#[derive(Debug, Default, Clone, Copy)]
pub struct Gatekeeper;

impl Gatekeeper {
    pub fn new() -> Self {
        Self
    }

    /// Verify a storage request and return the canonical partition key
    /// to use downstream. On success the returned key is byte-identical
    /// to `req.declared_key`; callers should still prefer the returned
    /// value as the single source of truth.
    pub fn authorize(&self, req: &StorageRequest) -> Result<PartitionKey, GatekeeperError> {
        let expected =
            partition_key::derive(&req.site_origin, req.identity_profile_id, req.context_id);
        if expected == req.declared_key {
            Ok(expected)
        } else {
            Err(GatekeeperError::KeyMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition_key::derive;

    fn id(seed: u128) -> Uuid {
        Uuid::from_u128(seed)
    }

    fn req(origin: &str, profile: Uuid, context: Uuid, declared: PartitionKey) -> StorageRequest {
        StorageRequest {
            site_origin: origin.to_string(),
            identity_profile_id: profile,
            context_id: context,
            declared_key: declared,
        }
    }

    #[test]
    fn authorize_accepts_matching_key() {
        let gk = Gatekeeper::new();
        let key = derive("example.com", id(1), id(2));
        let r = req("example.com", id(1), id(2), key);
        assert_eq!(gk.authorize(&r), Ok(key));
    }

    #[test]
    fn authorize_returns_canonical_key_byte_identical_to_declared() {
        // Single-source-of-truth contract: success path returns the
        // exact same bytes as the declared key, no transformation.
        let gk = Gatekeeper::new();
        let key = derive("example.com", id(1), id(2));
        let r = req("example.com", id(1), id(2), key);
        let returned = gk.authorize(&r).unwrap();
        assert_eq!(returned.as_bytes(), key.as_bytes());
    }

    #[test]
    fn authorize_rejects_when_origin_tampered() {
        // Caller declared a key derived from "example.com" but the
        // request claims the context is "evil.com". The gatekeeper
        // recomputes from "evil.com" and rejects.
        let gk = Gatekeeper::new();
        let truthful_key = derive("example.com", id(1), id(2));
        let r = req("evil.com", id(1), id(2), truthful_key);
        assert_eq!(gk.authorize(&r), Err(GatekeeperError::KeyMismatch));
    }

    #[test]
    fn authorize_rejects_when_identity_profile_tampered() {
        let gk = Gatekeeper::new();
        let truthful_key = derive("example.com", id(1), id(2));
        let r = req("example.com", id(99), id(2), truthful_key);
        assert_eq!(gk.authorize(&r), Err(GatekeeperError::KeyMismatch));
    }

    #[test]
    fn authorize_rejects_when_context_tampered() {
        let gk = Gatekeeper::new();
        let truthful_key = derive("example.com", id(1), id(2));
        let r = req("example.com", id(1), id(99), truthful_key);
        assert_eq!(gk.authorize(&r), Err(GatekeeperError::KeyMismatch));
    }

    #[test]
    fn authorize_rejects_when_declared_key_is_for_different_triple() {
        // The triple is internally consistent but the declared_key was
        // derived from a different triple entirely.
        let gk = Gatekeeper::new();
        let foreign_key = derive("other.com", id(7), id(8));
        let r = req("example.com", id(1), id(2), foreign_key);
        assert_eq!(gk.authorize(&r), Err(GatekeeperError::KeyMismatch));
    }

    #[test]
    fn authorize_is_deterministic() {
        let gk = Gatekeeper::new();
        let key = derive("example.com", id(1), id(2));
        let r = req("example.com", id(1), id(2), key);
        let a = gk.authorize(&r).unwrap();
        let b = gk.authorize(&r).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn default_constructor_matches_new() {
        let a = Gatekeeper::new();
        let b = Gatekeeper;
        let key = derive("example.com", id(1), id(2));
        let r = req("example.com", id(1), id(2), key);
        assert_eq!(a.authorize(&r), b.authorize(&r));
    }

    #[test]
    fn key_mismatch_error_message_does_not_leak_keys() {
        // L27: error messages that bubble up to logs must not contain
        // the full partition key (it is effectively a capability).
        let gk = Gatekeeper::new();
        let truthful_key = derive("example.com", id(1), id(2));
        let r = req("evil.com", id(1), id(2), truthful_key);
        let err = gk.authorize(&r).unwrap_err();
        let msg = format!("{err}");
        let declared_hex = truthful_key.to_hex();
        assert!(
            !msg.contains(&declared_hex),
            "error message leaked the declared key: {msg}"
        );
    }
}
