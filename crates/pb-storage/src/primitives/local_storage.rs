//! localStorage adapter, Module 16.
//!
//! Schema (`initialize_schema` v2):
//!
//!   local_storage(partition_key BLOB, key TEXT, value TEXT,
//!                 PRIMARY KEY (partition_key, key)) WITHOUT ROWID
//!
//! localStorage is per-origin and persistent. The partition_key carries
//! the (origin, identity, context) triple so per-identity isolation is
//! automatic.

use crate::gatekeeper::{Gatekeeper, StorageRequest};
use crate::partition_key::PartitionKey;
use crate::primitives::{StorageStore, StoreError};
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalStorage;

impl StorageStore for LocalStorage {
    fn name(&self) -> &'static str {
        "local_storage"
    }

    fn wipe_partition(&self, conn: &Connection, key: &PartitionKey) -> Result<u64, StoreError> {
        let n = conn.execute(
            "DELETE FROM local_storage WHERE partition_key = ?1",
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
            "localStorage key must not be empty".into(),
        ));
    }
    conn.execute(
        "INSERT OR REPLACE INTO local_storage (partition_key, key, value) VALUES (?1, ?2, ?3)",
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
            "SELECT value FROM local_storage WHERE partition_key = ?1 AND key = ?2",
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
        conn.prepare("SELECT key FROM local_storage WHERE partition_key = ?1 ORDER BY key")?;
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
        "DELETE FROM local_storage WHERE partition_key = ?1 AND key = ?2",
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
            "pb-storage-ls-{}-{tag}-{}",
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
        put(&gk, sp.conn(), &r, "k1", "v1").unwrap();
        assert_eq!(
            get(&gk, sp.conn(), &r, "k1").unwrap(),
            Some("v1".to_string())
        );
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
    fn partition_isolation() {
        let dir = unique_dir("scope");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, "shared", "from-a").unwrap();
        put(&gk, sp.conn(), &b, "shared", "from-b").unwrap();
        assert_eq!(
            get(&gk, sp.conn(), &a, "shared").unwrap(),
            Some("from-a".into())
        );
        assert_eq!(
            get(&gk, sp.conn(), &b, "shared").unwrap(),
            Some("from-b".into())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_replaces_existing_value() {
        let dir = unique_dir("replace");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        put(&gk, sp.conn(), &r, "k", "first").unwrap();
        put(&gk, sp.conn(), &r, "k", "second").unwrap();
        assert_eq!(get(&gk, sp.conn(), &r, "k").unwrap(), Some("second".into()));
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
    fn list_keys_orders_alphabetically_and_partition_scoped() {
        let dir = unique_dir("list");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, "z", "1").unwrap();
        put(&gk, sp.conn(), &a, "a", "1").unwrap();
        put(&gk, sp.conn(), &b, "from-b", "1").unwrap();
        let keys_a = list_keys(&gk, sp.conn(), &a).unwrap();
        assert_eq!(keys_a, vec!["a".to_string(), "z".to_string()]);
        let keys_b = list_keys(&gk, sp.conn(), &b).unwrap();
        assert_eq!(keys_b, vec!["from-b".to_string()]);
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
        put(&gk, sp.conn(), &a, "k2", "v2").unwrap();
        put(&gk, sp.conn(), &b, "k", "v").unwrap();
        let n = LocalStorage
            .wipe_partition(sp.conn(), &a.declared_key)
            .unwrap();
        assert_eq!(n, 2);
        assert!(list_keys(&gk, sp.conn(), &a).unwrap().is_empty());
        assert_eq!(list_keys(&gk, sp.conn(), &b).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
