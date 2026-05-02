//! Service worker registration adapter, Module 17.
//!
//! Schema (`initialize_schema` v3):
//!
//!   service_workers(partition_key BLOB, scope_url TEXT, script_url TEXT,
//!                   state TEXT, registered_at INTEGER,
//!                   PRIMARY KEY (partition_key, scope_url)) WITHOUT ROWID
//!
//! Scope of v1: storage-side isolation only. A service worker
//! registration is one row, partition-keyed by (origin, profile,
//! context). The same origin under two identities sees two distinct
//! registrations because the partition key differs. Engine-side
//! execution (running the JS, fetch event interception, push, periodic
//! sync) is a Gecko concern and lives outside `pb-storage` entirely.
//!
//! Why this is a separate primitive instead of a flag on cookies or
//! cache: a service worker is a long-lived background context that can
//! outlive the document that registered it. Treating it as just another
//! storage primitive forces it through the same gatekeeper gate as
//! every other origin-scoped state, which is exactly the §5.2 contract
//! we want for cross-identity isolation.

use crate::gatekeeper::{Gatekeeper, StorageRequest};
use crate::partition_key::PartitionKey;
use crate::primitives::{StorageStore, StoreError};
use rusqlite::{params, Connection, OptionalExtension};

/// Service-worker lifecycle state, as exposed by the storage layer.
/// The full Service Worker spec carries more states (`parsed`,
/// `installing`, `installed`, `activating`, `activated`, `redundant`);
/// v1 stores them as opaque text and only validates non-emptiness.
/// Stricter parsing is deferred to whichever module wires Gecko's
/// service-worker manager into this row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceWorkerRegistration {
    /// URL prefix this service worker controls (e.g.
    /// `https://example.com/app/`). Per-origin uniqueness is enforced by
    /// the (partition_key, scope_url) primary key.
    pub scope_url: String,
    /// URL of the worker script itself.
    pub script_url: String,
    /// Lifecycle state string. v1 treats this as opaque text.
    pub state: String,
    /// Unix seconds when the registration was first recorded.
    pub registered_at: i64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ServiceWorker;

impl StorageStore for ServiceWorker {
    fn name(&self) -> &'static str {
        "service_workers"
    }

    fn wipe_partition(&self, conn: &Connection, key: &PartitionKey) -> Result<u64, StoreError> {
        let n = conn.execute(
            "DELETE FROM service_workers WHERE partition_key = ?1",
            params![key.as_bytes().as_slice()],
        )?;
        Ok(n as u64)
    }
}

/// Insert or replace a service worker registration for the verified
/// partition. Replacing on (partition_key, scope_url) is the spec
/// behavior: re-registering at the same scope updates the script.
pub fn register(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    reg: &ServiceWorkerRegistration,
) -> Result<(), StoreError> {
    let key = gk.authorize(req)?;
    if reg.scope_url.is_empty() {
        return Err(StoreError::Validation(
            "service worker scope_url must not be empty".into(),
        ));
    }
    if reg.script_url.is_empty() {
        return Err(StoreError::Validation(
            "service worker script_url must not be empty".into(),
        ));
    }
    if reg.state.is_empty() {
        return Err(StoreError::Validation(
            "service worker state must not be empty".into(),
        ));
    }
    conn.execute(
        "INSERT OR REPLACE INTO service_workers \
            (partition_key, scope_url, script_url, state, registered_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key.as_bytes().as_slice(),
            reg.scope_url,
            reg.script_url,
            reg.state,
            reg.registered_at,
        ],
    )?;
    Ok(())
}

/// Look up a registration by scope URL within the verified partition.
pub fn get(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    scope_url: &str,
) -> Result<Option<ServiceWorkerRegistration>, StoreError> {
    let key = gk.authorize(req)?;
    let row = conn
        .query_row(
            "SELECT scope_url, script_url, state, registered_at \
             FROM service_workers WHERE partition_key = ?1 AND scope_url = ?2",
            params![key.as_bytes().as_slice(), scope_url],
            |r| {
                Ok(ServiceWorkerRegistration {
                    scope_url: r.get(0)?,
                    script_url: r.get(1)?,
                    state: r.get(2)?,
                    registered_at: r.get(3)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// List every registration in the verified partition, ordered by scope
/// URL for determinism. v1 returns the full struct; if a future caller
/// only needs scope URLs, add a `list_scopes` variant rather than
/// changing this signature.
pub fn list(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
) -> Result<Vec<ServiceWorkerRegistration>, StoreError> {
    let key = gk.authorize(req)?;
    let mut stmt = conn.prepare(
        "SELECT scope_url, script_url, state, registered_at \
         FROM service_workers WHERE partition_key = ?1 \
         ORDER BY scope_url",
    )?;
    let rows = stmt.query_map(params![key.as_bytes().as_slice()], |r| {
        Ok(ServiceWorkerRegistration {
            scope_url: r.get(0)?,
            script_url: r.get(1)?,
            state: r.get(2)?,
            registered_at: r.get(3)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Remove a registration by scope URL. Returns whether a row was deleted.
pub fn unregister(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    scope_url: &str,
) -> Result<bool, StoreError> {
    let key = gk.authorize(req)?;
    let n = conn.execute(
        "DELETE FROM service_workers WHERE partition_key = ?1 AND scope_url = ?2",
        params![key.as_bytes().as_slice(), scope_url],
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition_key::derive;
    use crate::process::bootstrap;
    use pb_config::StorageConfig;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn unique_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "pb-storage-sw-{}-{tag}-{}",
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

    fn reg(scope: &str, script: &str) -> ServiceWorkerRegistration {
        ServiceWorkerRegistration {
            scope_url: scope.to_string(),
            script_url: script.to_string(),
            state: "installed".to_string(),
            registered_at: 1_700_000_000,
        }
    }

    #[test]
    fn register_then_get_round_trip() {
        let dir = unique_dir("rt");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        let want = reg("https://example.com/app/", "https://example.com/sw.js");
        register(&gk, sp.conn(), &r, &want).unwrap();
        let got = get(&gk, sp.conn(), &r, "https://example.com/app/")
            .unwrap()
            .unwrap();
        assert_eq!(got, want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_rejects_when_gatekeeper_rejects() {
        let dir = unique_dir("gk");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let mut r = req("example.com", 1, 2);
        r.declared_key = derive("evil.com", Uuid::from_u128(1), Uuid::from_u128(2));
        let err = register(&gk, sp.conn(), &r, &reg("s", "u")).unwrap_err();
        assert!(matches!(err, StoreError::Gatekeeper(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_rejects_empty_fields() {
        let dir = unique_dir("empty");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        let bad_scope = ServiceWorkerRegistration {
            scope_url: "".into(),
            ..reg("s", "u")
        };
        let bad_script = ServiceWorkerRegistration {
            script_url: "".into(),
            ..reg("s", "u")
        };
        let bad_state = ServiceWorkerRegistration {
            state: "".into(),
            ..reg("s", "u")
        };
        for bad in [bad_scope, bad_script, bad_state] {
            let err = register(&gk, sp.conn(), &r, &bad).unwrap_err();
            assert!(matches!(err, StoreError::Validation(_)));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_replaces_on_same_scope() {
        let dir = unique_dir("replace");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        register(&gk, sp.conn(), &r, &reg("s", "v1")).unwrap();
        register(&gk, sp.conn(), &r, &reg("s", "v2")).unwrap();
        let got = get(&gk, sp.conn(), &r, "s").unwrap().unwrap();
        assert_eq!(got.script_url, "v2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_identity_isolation_at_same_origin() {
        // The Module 17 invariant. Same origin, two identities, two
        // independent service-worker registrations. This is the property
        // the partition key buys us.
        let dir = unique_dir("iso-id");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let alice = req("example.com", 1, 99);
        let bob = req("example.com", 2, 99);
        register(&gk, sp.conn(), &alice, &reg("s", "alice.js")).unwrap();
        register(&gk, sp.conn(), &bob, &reg("s", "bob.js")).unwrap();
        let a = get(&gk, sp.conn(), &alice, "s").unwrap().unwrap();
        let b = get(&gk, sp.conn(), &bob, "s").unwrap().unwrap();
        assert_eq!(a.script_url, "alice.js");
        assert_eq!(b.script_url, "bob.js");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_origin_isolation() {
        let dir = unique_dir("iso-org");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        register(&gk, sp.conn(), &a, &reg("s", "a.js")).unwrap();
        assert!(get(&gk, sp.conn(), &b, "s").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_orders_by_scope_partition_scoped() {
        let dir = unique_dir("list");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        register(&gk, sp.conn(), &a, &reg("/z/", "z.js")).unwrap();
        register(&gk, sp.conn(), &a, &reg("/a/", "a.js")).unwrap();
        register(&gk, sp.conn(), &b, &reg("/x/", "x.js")).unwrap();
        let la = list(&gk, sp.conn(), &a).unwrap();
        let scopes_a: Vec<_> = la.iter().map(|r| r.scope_url.as_str()).collect();
        assert_eq!(scopes_a, vec!["/a/", "/z/"]);
        let lb = list(&gk, sp.conn(), &b).unwrap();
        assert_eq!(lb.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unregister_reports_existence() {
        let dir = unique_dir("unreg");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        register(&gk, sp.conn(), &r, &reg("s", "u")).unwrap();
        assert!(unregister(&gk, sp.conn(), &r, "s").unwrap());
        assert!(!unregister(&gk, sp.conn(), &r, "s").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_partition_only_touches_target() {
        let dir = unique_dir("wipe");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        register(&gk, sp.conn(), &a, &reg("/1/", "u")).unwrap();
        register(&gk, sp.conn(), &a, &reg("/2/", "u")).unwrap();
        register(&gk, sp.conn(), &b, &reg("/1/", "u")).unwrap();
        let n = ServiceWorker
            .wipe_partition(sp.conn(), &a.declared_key)
            .unwrap();
        assert_eq!(n, 2);
        assert!(list(&gk, sp.conn(), &a).unwrap().is_empty());
        assert_eq!(list(&gk, sp.conn(), &b).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
