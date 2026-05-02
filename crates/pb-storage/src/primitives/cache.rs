//! HTTP / JS / image cache adapter, Module 16.
//!
//! Schema (`initialize_schema` v2):
//!
//!   cache(partition_key BLOB, url TEXT, body BLOB,
//!         content_type TEXT NULL, fetched_at INTEGER,
//!         PRIMARY KEY (partition_key, url)) WITHOUT ROWID
//!
//! v1 scope: minimal partition-keyed blob cache. CRUD + total-bytes +
//! per-partition wipe. **Full RFC 7234 freshness, Vary header handling,
//! cache-control directive parsing, and eviction policy are deferred to
//! Phase 4** (network broker), which is the natural owner of cache
//! lifetime decisions because it sees response headers first.
//!
//! Strict-mode 50 MB-per-identity cap (existing arch comment) is also a
//! Phase 4 concern (eviction is a network/UX decision); the storage
//! layer just stores. Module 60 (Network viewer) will consume
//! [`Cache::wipe_partition`] for the user-facing "clear cache" action.

use crate::gatekeeper::{Gatekeeper, StorageRequest};
use crate::partition_key::PartitionKey;
use crate::primitives::{StorageStore, StoreError};
use rusqlite::{params, Connection, OptionalExtension};

/// One cached response. `partition_key` is implicit at the API surface
/// (the gatekeeper carries it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub url: String,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    /// Unix seconds at which the response was stored.
    pub fetched_at: i64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Cache;

impl StorageStore for Cache {
    fn name(&self) -> &'static str {
        "cache"
    }

    fn wipe_partition(&self, conn: &Connection, key: &PartitionKey) -> Result<u64, StoreError> {
        let n = conn.execute(
            "DELETE FROM cache WHERE partition_key = ?1",
            params![key.as_bytes().as_slice()],
        )?;
        Ok(n as u64)
    }
}

/// Insert or replace a cache entry for the verified partition.
pub fn put(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    entry: &CacheEntry,
) -> Result<(), StoreError> {
    let key = gk.authorize(req)?;
    if entry.url.is_empty() {
        return Err(StoreError::Validation("cache url must not be empty".into()));
    }
    conn.execute(
        "INSERT OR REPLACE INTO cache \
            (partition_key, url, body, content_type, fetched_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            key.as_bytes().as_slice(),
            entry.url,
            entry.body,
            entry.content_type,
            entry.fetched_at,
        ],
    )?;
    Ok(())
}

/// Fetch a cache entry by url within the verified partition.
pub fn get(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    url: &str,
) -> Result<Option<CacheEntry>, StoreError> {
    let key = gk.authorize(req)?;
    let row = conn
        .query_row(
            "SELECT url, body, content_type, fetched_at \
             FROM cache WHERE partition_key = ?1 AND url = ?2",
            params![key.as_bytes().as_slice(), url],
            |r| {
                Ok(CacheEntry {
                    url: r.get(0)?,
                    body: r.get(1)?,
                    content_type: r.get(2)?,
                    fetched_at: r.get(3)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

/// Delete a cache entry by url. Returns whether a row was removed.
pub fn delete(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    url: &str,
) -> Result<bool, StoreError> {
    let key = gk.authorize(req)?;
    let n = conn.execute(
        "DELETE FROM cache WHERE partition_key = ?1 AND url = ?2",
        params![key.as_bytes().as_slice(), url],
    )?;
    Ok(n > 0)
}

/// Total stored body bytes for the verified partition. Module 60
/// (Network viewer) will use this for the per-partition "X cached"
/// number; Phase 4 cap-enforcement code will use it for eviction
/// decisions.
pub fn total_bytes(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
) -> Result<u64, StoreError> {
    let key = gk.authorize(req)?;
    let total: Option<i64> = conn
        .query_row(
            "SELECT SUM(LENGTH(body)) FROM cache WHERE partition_key = ?1",
            params![key.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    Ok(total.unwrap_or(0).max(0) as u64)
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
            "pb-storage-cache-{}-{tag}-{}",
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

    fn entry(url: &str, body: &[u8], ct: Option<&str>) -> CacheEntry {
        CacheEntry {
            url: url.to_string(),
            body: body.to_vec(),
            content_type: ct.map(str::to_string),
            fetched_at: 1_700_000_000,
        }
    }

    #[test]
    fn put_then_get_round_trip() {
        let dir = unique_dir("rt");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        let e = entry("https://x/y", b"hello", Some("text/plain"));
        put(&gk, sp.conn(), &r, &e).unwrap();
        assert_eq!(get(&gk, sp.conn(), &r, "https://x/y").unwrap(), Some(e));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_rejects_when_gatekeeper_rejects() {
        let dir = unique_dir("gk");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let mut r = req("example.com", 1, 2);
        r.declared_key = derive("evil.com", Uuid::from_u128(1), Uuid::from_u128(2));
        let err = put(&gk, sp.conn(), &r, &entry("u", b"b", None)).unwrap_err();
        assert!(matches!(err, StoreError::Gatekeeper(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_rejects_empty_url() {
        let dir = unique_dir("empty");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        let err = put(&gk, sp.conn(), &r, &entry("", b"b", None)).unwrap_err();
        assert!(matches!(err, StoreError::Validation(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_replaces_on_duplicate_url() {
        let dir = unique_dir("replace");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        put(&gk, sp.conn(), &r, &entry("u", b"first", None)).unwrap();
        put(&gk, sp.conn(), &r, &entry("u", b"second", None)).unwrap();
        let got = get(&gk, sp.conn(), &r, "u").unwrap().unwrap();
        assert_eq!(got.body, b"second");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partition_isolation() {
        let dir = unique_dir("scope");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, &entry("u", b"a-body", None)).unwrap();
        assert!(get(&gk, sp.conn(), &b, "u").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn total_bytes_empty_is_zero() {
        let dir = unique_dir("zero");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        assert_eq!(total_bytes(&gk, sp.conn(), &r).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn total_bytes_sums_body_sizes_partition_scoped() {
        let dir = unique_dir("sum");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, &entry("u1", b"hello", None)).unwrap();
        put(&gk, sp.conn(), &a, &entry("u2", b"world!", None)).unwrap();
        put(&gk, sp.conn(), &b, &entry("u", b"otherp", None)).unwrap();
        assert_eq!(total_bytes(&gk, sp.conn(), &a).unwrap(), 11);
        assert_eq!(total_bytes(&gk, sp.conn(), &b).unwrap(), 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_partition_only_touches_target() {
        let dir = unique_dir("wipe");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, &entry("u", b"a", None)).unwrap();
        put(&gk, sp.conn(), &b, &entry("u", b"b", None)).unwrap();
        let n = Cache.wipe_partition(sp.conn(), &a.declared_key).unwrap();
        assert_eq!(n, 1);
        assert!(get(&gk, sp.conn(), &a, "u").unwrap().is_none());
        assert!(get(&gk, sp.conn(), &b, "u").unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
