//! Strict-mode partition wipe, Module 18.
//!
//! Strict-mode tabs (architecture §3.4 and L36) wipe all storage that
//! the tab touched when the tab closes. This module is the storage-side
//! primitive: given a set of partition keys and a list of StorageStore
//! implementors, delete every row across every store for every key,
//! atomically, and return a per-store tally for audit logging.
//!
//! Atomicity: the work runs inside one SQLite transaction. A failure
//! mid-wipe rolls back the whole batch rather than leaving the database
//! half-wiped (which could leak from-which-identity information by the
//! pattern of which rows survived).
//!
//! Boundary: this module owns "wipe these partitions across these
//! stores". It does NOT own "decide which partitions a strict tab has
//! touched". That bookkeeping lives in pb-browser (Phase 6+), which
//! holds the per-tab partition-key set during the tab's lifetime and
//! calls into here on close.

use crate::partition_key::PartitionKey;
use crate::primitives::cache::Cache;
use crate::primitives::cookies::Cookies;
use crate::primitives::local_storage::LocalStorage;
use crate::primitives::service_worker::ServiceWorker;
use crate::primitives::session_storage::SessionStorage;
use crate::primitives::{StorageStore, StoreError};
use rusqlite::Connection;
use std::collections::BTreeMap;

/// Outcome of one wipe call. `BTreeMap` keeps the audit log line
/// deterministic across runs (insertion-order maps would not).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WipeReport {
    /// Number of distinct partition keys the call processed.
    pub keys_processed: usize,
    /// Rows removed, keyed by store name (`StorageStore::name`).
    pub per_store: BTreeMap<&'static str, u64>,
}

impl WipeReport {
    /// Sum of rows removed across every store. Convenience for the
    /// "wiped N rows" log line; per-store breakdown is the audit trail.
    pub fn total_rows(&self) -> u64 {
        self.per_store.values().sum()
    }
}

/// The canonical store set Module 18 wipes when the caller does not
/// provide its own. Add new primitives here when they implement
/// `StorageStore`. The static instances are zero-sized; the array is
/// effectively a compile-time constant.
pub fn default_stores() -> [&'static dyn StorageStore; 5] {
    static COOKIES: Cookies = Cookies;
    static LOCAL: LocalStorage = LocalStorage;
    static SESSION: SessionStorage = SessionStorage;
    static CACHE: Cache = Cache;
    static SW: ServiceWorker = ServiceWorker;
    [&COOKIES, &LOCAL, &SESSION, &CACHE, &SW]
}

/// Wipe every row in every `store` for every key in `keys`, atomically.
///
/// Empty `keys` or empty `stores` is a successful no-op.
///
/// On any per-store error, the whole transaction rolls back: callers
/// should treat the error as "nothing was wiped" and surface it to the
/// audit channel. The partition keys remain valid; the caller may retry.
pub fn wipe_partitions(
    conn: &Connection,
    keys: &[PartitionKey],
    stores: &[&dyn StorageStore],
) -> Result<WipeReport, StoreError> {
    let mut report = WipeReport::default();
    if keys.is_empty() || stores.is_empty() {
        return Ok(report);
    }
    let tx = conn.unchecked_transaction()?;
    for key in keys {
        for store in stores {
            let n = store.wipe_partition(&tx, key)?;
            *report.per_store.entry(store.name()).or_insert(0) += n;
        }
    }
    tx.commit()?;
    report.keys_processed = keys.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
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
            "pb-storage-wipe-{}-{tag}-{}",
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

    /// Seed every primitive with one row at the given request's partition.
    fn seed_all(gk: &Gatekeeper, conn: &Connection, r: &StorageRequest) {
        cookies::put(
            gk,
            conn,
            r,
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
        local_storage::put(gk, conn, r, "lk", "lv").unwrap();
        session_storage::put(gk, conn, r, "sk", "sv").unwrap();
        cache::put(
            gk,
            conn,
            r,
            &cache::CacheEntry {
                url: "u".into(),
                body: b"b".to_vec(),
                content_type: None,
                fetched_at: 0,
            },
        )
        .unwrap();
        service_worker::register(
            gk,
            conn,
            r,
            &service_worker::ServiceWorkerRegistration {
                scope_url: "s".into(),
                script_url: "u".into(),
                state: "installed".into(),
                registered_at: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn empty_keys_is_noop() {
        let dir = unique_dir("empty-keys");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let stores = default_stores();
        let report = wipe_partitions(sp.conn(), &[], &stores).unwrap();
        assert_eq!(report, WipeReport::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_stores_is_noop() {
        let dir = unique_dir("empty-stores");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let r = req("example.com", 1, 2);
        let report = wipe_partitions(sp.conn(), &[r.declared_key], &[]).unwrap();
        assert_eq!(report, WipeReport::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_clears_target_partition_across_all_stores() {
        // The Module 18 invariant: one call removes every row in every
        // primitive belonging to the target partition.
        let dir = unique_dir("clear-all");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        seed_all(&gk, sp.conn(), &r);

        let stores = default_stores();
        let report = wipe_partitions(sp.conn(), &[r.declared_key], &stores).unwrap();
        assert_eq!(report.keys_processed, 1);
        assert_eq!(report.total_rows(), 5);
        assert_eq!(report.per_store["cookies"], 1);
        assert_eq!(report.per_store["local_storage"], 1);
        assert_eq!(report.per_store["session_storage"], 1);
        assert_eq!(report.per_store["cache"], 1);
        assert_eq!(report.per_store["service_workers"], 1);

        // Every store now empty for r:
        assert!(cookies::get(&gk, sp.conn(), &r, "c").unwrap().is_none());
        assert!(local_storage::get(&gk, sp.conn(), &r, "lk")
            .unwrap()
            .is_none());
        assert!(session_storage::get(&gk, sp.conn(), &r, "sk")
            .unwrap()
            .is_none());
        assert!(cache::get(&gk, sp.conn(), &r, "u").unwrap().is_none());
        assert!(service_worker::get(&gk, sp.conn(), &r, "s")
            .unwrap()
            .is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_does_not_touch_other_partitions() {
        // The other half of the contract: rows in unrelated partitions
        // must survive untouched.
        let dir = unique_dir("isolation");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let target = req("a.example", 1, 2);
        let bystander = req("b.example", 1, 2);
        seed_all(&gk, sp.conn(), &target);
        seed_all(&gk, sp.conn(), &bystander);

        let stores = default_stores();
        let _ = wipe_partitions(sp.conn(), &[target.declared_key], &stores).unwrap();

        // Bystander untouched everywhere:
        assert!(cookies::get(&gk, sp.conn(), &bystander, "c")
            .unwrap()
            .is_some());
        assert!(local_storage::get(&gk, sp.conn(), &bystander, "lk")
            .unwrap()
            .is_some());
        assert!(session_storage::get(&gk, sp.conn(), &bystander, "sk")
            .unwrap()
            .is_some());
        assert!(cache::get(&gk, sp.conn(), &bystander, "u")
            .unwrap()
            .is_some());
        assert!(service_worker::get(&gk, sp.conn(), &bystander, "s")
            .unwrap()
            .is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_handles_multiple_partitions_in_one_call() {
        let dir = unique_dir("multi");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        let c = req("c.example", 1, 2);
        seed_all(&gk, sp.conn(), &a);
        seed_all(&gk, sp.conn(), &b);
        seed_all(&gk, sp.conn(), &c);

        let stores = default_stores();
        let report =
            wipe_partitions(sp.conn(), &[a.declared_key, b.declared_key], &stores).unwrap();

        assert_eq!(report.keys_processed, 2);
        // 5 stores * 2 partitions = 10 rows wiped.
        assert_eq!(report.total_rows(), 10);
        // Bystander c survives.
        assert!(cookies::get(&gk, sp.conn(), &c, "c").unwrap().is_some());
        // a and b are gone.
        assert!(cookies::get(&gk, sp.conn(), &a, "c").unwrap().is_none());
        assert!(cookies::get(&gk, sp.conn(), &b, "c").unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_stores_includes_every_primitive() {
        // Future-proofing: if someone adds a new StorageStore primitive
        // without wiring it into default_stores(), this test still
        // passes silently. The cross-primitive `every_store_reports_its
        // _own_table_name` test in primitives/mod.rs is the authoritative
        // catalog. This test only checks that the canonical 5 are
        // present and unique.
        let stores = default_stores();
        let mut names: Vec<&'static str> = stores.iter().map(|s| s.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 5);
        assert!(names.contains(&"cookies"));
        assert!(names.contains(&"local_storage"));
        assert!(names.contains(&"session_storage"));
        assert!(names.contains(&"cache"));
        assert!(names.contains(&"service_workers"));
    }

    #[test]
    fn wipe_with_no_existing_rows_returns_zero_counts() {
        // Wiping a partition that has nothing in it is a successful
        // no-op with all-zero counts and keys_processed == 1.
        let dir = unique_dir("nothing");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let r = req("empty.example", 1, 2);
        let stores = default_stores();
        let report = wipe_partitions(sp.conn(), &[r.declared_key], &stores).unwrap();
        assert_eq!(report.keys_processed, 1);
        assert_eq!(report.total_rows(), 0);
        for s in stores.iter() {
            assert_eq!(report.per_store.get(s.name()), Some(&0));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
