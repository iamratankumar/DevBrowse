//! Per-primitive storage adapters, Module 16.
//!
//! Each primitive (cookies, localStorage, sessionStorage, cache) is a
//! thin SQLite-backed adapter sitting behind the gatekeeper (§5.2).
//! Every public read/write function in every primitive begins with
//!
//!   let key = gatekeeper.authorize(req)?;
//!
//! and uses `key.as_bytes()` as the partition predicate. No primitive
//! calls `partition_key::derive` directly — the gatekeeper is the sole
//! derivation site.
//!
//! Uniform shape across primitives:
//!
//!   * One unit struct per primitive (`Cookies`, `LocalStorage`, etc.).
//!   * Free CRUD functions taking `&Gatekeeper`, `&Connection`,
//!     `&StorageRequest`, plus op-specific arguments.
//!   * Each unit struct implements [`StorageStore`], whose
//!     `wipe_partition` method is the seed for Module 18 (strict-wipe).
//!
//! The trait shape exists now (one module ahead of its consumer)
//! because the consumer (Module 18) is short and well-defined; designing
//! it speculatively is cheaper than retrofitting four primitives later.
//!
//! IndexedDB (`indexed_db.rs`) is intentionally NOT a [`StorageStore`]
//! in v1: the IDB surface is a versioned object database whose v1
//! semantics are deferred to a dedicated future module/phase. The file
//! exists as a marker; do not implement primitives there until the
//! deferral is lifted.

pub mod cache;
pub mod cookies;
pub mod indexed_db;
pub mod local_storage;
pub mod service_worker;
pub mod session_storage;

use crate::gatekeeper::GatekeeperError;
use crate::partition_key::PartitionKey;
use rusqlite::Connection;
use thiserror::Error;

/// Error type shared across all primitives. The first variant is the
/// §5.2 hard rejection; the others are routine SQL / validation errors.
///
/// L27 redaction: `Display` for `Sqlite` returns a generic phrase only.
/// The underlying `rusqlite::Error` is reachable via [`std::error::Error::source`]
/// for in-process tracing only (subscribers must respect L27 — never write
/// the source to disk or wire without redaction). Embedding rusqlite's text
/// in the `Display` output would let SQL fragments and table/column names
/// leak through any error path that crosses an IPC or log boundary.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Gatekeeper rejected the request (§5.2). Always check this first.
    #[error("gatekeeper rejected: {0}")]
    Gatekeeper(#[from] GatekeeperError),

    /// Underlying SQLite error. `Display` is opaque (L27); use
    /// [`std::error::Error::source`] in-process for the rusqlite text.
    #[error("storage backend error")]
    Sqlite(#[source] rusqlite::Error),

    /// Caller-supplied data failed primitive-level validation
    /// (e.g. cookie SameSite string outside the allowed set).
    #[error("validation error: {0}")]
    Validation(String),
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Sqlite(e)
    }
}

/// Uniform contract every primitive implements. v1 carries one method
/// (wipe a single partition); Module 60 (Network viewer) will add a
/// `summary()` here when there is a real consumer asking for it.
///
/// Implementors must scope every SQL statement they issue to a single
/// `partition_key` value. Cross-partition writes via this trait are a
/// §5.2 violation by definition.
pub trait StorageStore {
    /// Stable, lowercase, ASCII identifier used in logs and metrics.
    /// Must match the SQLite table name to keep audit grepping trivial.
    fn name(&self) -> &'static str;

    /// Delete every row in this primitive whose `partition_key` matches
    /// `key`. Returns the number of rows actually removed.
    ///
    /// Caller contract: `key` must be a partition key the caller is
    /// already authorized to wipe (Module 18 holds the per-tab list of
    /// touched partitions; the gatekeeper is the only path that
    /// produces such keys for non-internal callers).
    fn wipe_partition(&self, conn: &Connection, key: &PartitionKey) -> Result<u64, StoreError>;
}

#[cfg(test)]
mod cross_primitive_tests {
    //! Cross-primitive invariants. These tests prove the §5.2 contract
    //! holds across the primitives as a SUBSYSTEM, not just inside any
    //! one of them. They are the strongest guarantee Module 16 produces
    //! in v1.

    use super::*;
    use crate::gatekeeper::{Gatekeeper, StorageRequest};
    use crate::partition_key::derive;
    use crate::primitives::{cache, cookies, local_storage, service_worker, session_storage};
    use crate::process::bootstrap;
    use pb_config::StorageConfig;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn unique_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "pb-storage-cross-{}-{tag}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        p
    }

    fn cfg_at(dir: &Path) -> StorageConfig {
        StorageConfig {
            data_dir: Some(dir.to_path_buf()),
            ..StorageConfig::default()
        }
    }

    fn req(origin: &str, profile: u128, context: u128) -> StorageRequest {
        let pid = Uuid::from_u128(profile);
        let cid = Uuid::from_u128(context);
        StorageRequest {
            site_origin: origin.to_string(),
            identity_profile_id: pid,
            context_id: cid,
            declared_key: derive(origin, pid, cid),
        }
    }

    #[test]
    fn wipe_in_one_store_does_not_touch_others_at_same_partition() {
        // The strongest guarantee Module 16 produces: wiping cookies for
        // partition A removes ONLY cookie rows. local_storage,
        // session_storage, and cache rows for the same partition stay.
        let dir = unique_dir("wipe-iso");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);

        cookies::put(
            &gk,
            sp.conn(),
            &r,
            &cookies::CookieRecord {
                name: "c".into(),
                value: "v".into(),
                expires_at: None,
                http_only: false,
                secure: false,
                same_site: cookies::SameSite::Lax,
            },
        )
        .unwrap();
        local_storage::put(&gk, sp.conn(), &r, "lk", "lv").unwrap();
        session_storage::put(&gk, sp.conn(), &r, "sk", "sv").unwrap();
        cache::put(
            &gk,
            sp.conn(),
            &r,
            &cache::CacheEntry {
                url: "u".into(),
                body: b"b".to_vec(),
                content_type: None,
                fetched_at: 0,
            },
        )
        .unwrap();
        service_worker::register(
            &gk,
            sp.conn(),
            &r,
            &service_worker::ServiceWorkerRegistration {
                scope_url: "s".into(),
                script_url: "u".into(),
                state: "installed".into(),
                registered_at: 0,
            },
        )
        .unwrap();

        let n = cookies::Cookies
            .wipe_partition(sp.conn(), &r.declared_key)
            .unwrap();
        assert_eq!(n, 1);

        // Cookies gone:
        assert!(cookies::get(&gk, sp.conn(), &r, "c").unwrap().is_none());
        // Other stores untouched:
        assert_eq!(
            local_storage::get(&gk, sp.conn(), &r, "lk").unwrap(),
            Some("lv".to_string())
        );
        assert_eq!(
            session_storage::get(&gk, sp.conn(), &r, "sk").unwrap(),
            Some("sv".to_string())
        );
        assert!(cache::get(&gk, sp.conn(), &r, "u").unwrap().is_some());
        assert!(service_worker::get(&gk, sp.conn(), &r, "s")
            .unwrap()
            .is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_in_one_partition_does_not_touch_other_partitions_in_same_store() {
        // Already covered per-primitive, but pinned here as a
        // subsystem-level invariant for future maintainers grepping
        // `cross_primitive_tests`.
        let dir = unique_dir("wipe-part");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);

        local_storage::put(&gk, sp.conn(), &a, "k", "va").unwrap();
        local_storage::put(&gk, sp.conn(), &b, "k", "vb").unwrap();
        let n = local_storage::LocalStorage
            .wipe_partition(sp.conn(), &a.declared_key)
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(local_storage::get(&gk, sp.conn(), &a, "k").unwrap(), None);
        assert_eq!(
            local_storage::get(&gk, sp.conn(), &b, "k").unwrap(),
            Some("vb".to_string())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_store_rejects_tampered_request_uniformly() {
        // §5.2: every primitive's write path must reject a tampered
        // request through the SAME error variant. This is the
        // subsystem-level proof of uniform gating.
        let dir = unique_dir("uniform-gate");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let mut r = req("example.com", 1, 2);
        // Tamper: declared key derived from a different origin.
        r.declared_key = derive("evil.com", Uuid::from_u128(1), Uuid::from_u128(2));

        let e1 = cookies::put(
            &gk,
            sp.conn(),
            &r,
            &cookies::CookieRecord {
                name: "c".into(),
                value: "v".into(),
                expires_at: None,
                http_only: false,
                secure: false,
                same_site: cookies::SameSite::Lax,
            },
        )
        .unwrap_err();
        let e2 = local_storage::put(&gk, sp.conn(), &r, "k", "v").unwrap_err();
        let e3 = session_storage::put(&gk, sp.conn(), &r, "k", "v").unwrap_err();
        let e4 = cache::put(
            &gk,
            sp.conn(),
            &r,
            &cache::CacheEntry {
                url: "u".into(),
                body: b"b".to_vec(),
                content_type: None,
                fetched_at: 0,
            },
        )
        .unwrap_err();
        let e5 = service_worker::register(
            &gk,
            sp.conn(),
            &r,
            &service_worker::ServiceWorkerRegistration {
                scope_url: "s".into(),
                script_url: "u".into(),
                state: "installed".into(),
                registered_at: 0,
            },
        )
        .unwrap_err();

        for e in [e1, e2, e3, e4, e5] {
            assert!(
                matches!(e, StoreError::Gatekeeper(_)),
                "expected Gatekeeper rejection, got {e:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_store_reports_its_own_table_name() {
        // The `name()` method must match the SQL table name so audit
        // grepping by table name finds the corresponding code path.
        assert_eq!(cookies::Cookies.name(), "cookies");
        assert_eq!(local_storage::LocalStorage.name(), "local_storage");
        assert_eq!(session_storage::SessionStorage.name(), "session_storage");
        assert_eq!(cache::Cache.name(), "cache");
        assert_eq!(service_worker::ServiceWorker.name(), "service_workers");
    }
}
