//! sessionStorage adapter, Module 16.
//!
//! Schema (`initialize_schema` v2):
//!
//!   session_storage(partition_key BLOB, key TEXT, value TEXT,
//!                   PRIMARY KEY (partition_key, key)) WITHOUT ROWID
//!
//! sessionStorage is per-tab and tab-lifetime by web spec. The storage
//! layer treats it identically to localStorage at rest; the per-tab
//! semantics are produced by the (origin, identity_profile_id,
//! context_id) triple — `context_id` is fresh per Strict tab (§3.5,
//! §3.6) so two Strict tabs of the same site yield disjoint partition
//! keys and therefore disjoint session_storage rows.
//!
//! Lifetime / cleanup: this module does NOT auto-expire rows. Module 9
//! (lifecycle) signals tab close, and Module 18 (strict-wipe) calls
//! [`SessionStorage::wipe_partition`] for every partition the tab
//! touched. Standard mode keeps sessionStorage alive across page
//! navigations within the tab; that contract is also Module 9's, not
//! ours.

use crate::gatekeeper::{Gatekeeper, StorageRequest};
use crate::partition_key::PartitionKey;
use crate::primitives::{StorageStore, StoreError};
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Default, Clone, Copy)]
pub struct SessionStorage;

impl StorageStore for SessionStorage {
    fn name(&self) -> &'static str {
        "session_storage"
    }

    fn wipe_partition(&self, conn: &Connection, key: &PartitionKey) -> Result<u64, StoreError> {
        let n = conn.execute(
            "DELETE FROM session_storage WHERE partition_key = ?1",
            params![key.as_bytes().as_slice()],
        )?;
        Ok(n as u64)
    }
}

pub fn put(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    key: &str,
    value: &str,
) -> Result<(), StoreError> {
    let pk = gk.authorize(req)?;
    if key.is_empty() {
        return Err(StoreError::Validation(
            "sessionStorage key must not be empty".into(),
        ));
    }
    conn.execute(
        "INSERT OR REPLACE INTO session_storage (partition_key, key, value) VALUES (?1, ?2, ?3)",
        params![pk.as_bytes().as_slice(), key, value],
    )?;
    Ok(())
}

pub fn get(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    key: &str,
) -> Result<Option<String>, StoreError> {
    let pk = gk.authorize(req)?;
    let v: Option<String> = conn
        .query_row(
            "SELECT value FROM session_storage WHERE partition_key = ?1 AND key = ?2",
            params![pk.as_bytes().as_slice(), key],
            |r| r.get(0),
        )
        .optional()?;
    Ok(v)
}

pub fn list_keys(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
) -> Result<Vec<String>, StoreError> {
    let pk = gk.authorize(req)?;
    let mut stmt =
        conn.prepare("SELECT key FROM session_storage WHERE partition_key = ?1 ORDER BY key")?;
    let rows = stmt.query_map(params![pk.as_bytes().as_slice()], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub fn delete(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    key: &str,
) -> Result<bool, StoreError> {
    let pk = gk.authorize(req)?;
    let n = conn.execute(
        "DELETE FROM session_storage WHERE partition_key = ?1 AND key = ?2",
        params![pk.as_bytes().as_slice(), key],
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
            "pb-storage-ss-{}-{tag}-{}",
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
    fn put_then_get_round_trip() {
        let dir = unique_dir("rt");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        put(&gk, sp.conn(), &r, "k", "v").unwrap();
        assert_eq!(get(&gk, sp.conn(), &r, "k").unwrap(), Some("v".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_rejects_when_gatekeeper_rejects() {
        let dir = unique_dir("gk");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let mut r = req("example.com", 1, 2);
        r.declared_key = derive("evil.com", Uuid::from_u128(1), Uuid::from_u128(2));
        let err = put(&gk, sp.conn(), &r, "k", "v").unwrap_err();
        assert!(matches!(err, StoreError::Gatekeeper(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_rejects_empty_key() {
        let dir = unique_dir("empty");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        let err = put(&gk, sp.conn(), &r, "", "v").unwrap_err();
        assert!(matches!(err, StoreError::Validation(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn distinct_contexts_yield_distinct_storage() {
        // §3.5/§3.6: fresh context_id per Strict tab. Two tabs of the
        // same origin under the same identity but with different
        // context_ids must see disjoint sessionStorage.
        let dir = unique_dir("ctx");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let tab1 = req("example.com", 1, 100);
        let tab2 = req("example.com", 1, 200);
        put(&gk, sp.conn(), &tab1, "k", "tab1-value").unwrap();
        put(&gk, sp.conn(), &tab2, "k", "tab2-value").unwrap();
        assert_eq!(
            get(&gk, sp.conn(), &tab1, "k").unwrap(),
            Some("tab1-value".into())
        );
        assert_eq!(
            get(&gk, sp.conn(), &tab2, "k").unwrap(),
            Some("tab2-value".into())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_reports_existence() {
        let dir = unique_dir("del");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        put(&gk, sp.conn(), &r, "k", "v").unwrap();
        assert!(delete(&gk, sp.conn(), &r, "k").unwrap());
        assert!(!delete(&gk, sp.conn(), &r, "k").unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_partition_only_touches_target() {
        let dir = unique_dir("wipe");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, "k1", "v1").unwrap();
        put(&gk, sp.conn(), &b, "k", "v").unwrap();
        let n = SessionStorage
            .wipe_partition(sp.conn(), &a.declared_key)
            .unwrap();
        assert_eq!(n, 1);
        assert!(list_keys(&gk, sp.conn(), &a).unwrap().is_empty());
        assert_eq!(list_keys(&gk, sp.conn(), &b).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
