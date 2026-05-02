//! Cookie storage adapter, Module 16.
//!
//! Schema (created in Module 13's `initialize_schema` at v2):
//!
//!   cookies(partition_key BLOB, name TEXT, value TEXT,
//!           expires_at INTEGER NULL, http_only INTEGER,
//!           secure INTEGER, same_site TEXT,
//!           PRIMARY KEY (partition_key, name)) WITHOUT ROWID
//!
//! `expires_at` is unix seconds; NULL means a session cookie (lifetime
//! managed by Module 18 strict-wipe / tab close, not by us).
//!
//! `same_site` is one of `"strict" | "lax" | "none"`. Anything else is
//! a validation error rejected at write time.
//!
//! The `value` column is plain text per the cookie spec; encryption at
//! rest is provided by the OS user-profile permission posture (0700/0600
//! on Unix) plus the storage-process sandbox (§5.8). DB-level encryption
//! is deferred (open question in §7).

use crate::gatekeeper::{Gatekeeper, StorageRequest};
use crate::partition_key::PartitionKey;
use crate::primitives::{StorageStore, StoreError};
use rusqlite::{params, Connection, OptionalExtension};

/// SameSite attribute. Matches the three values the cookie spec allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    fn as_db_str(self) -> &'static str {
        match self {
            SameSite::Strict => "strict",
            SameSite::Lax => "lax",
            SameSite::None => "none",
        }
    }

    fn from_db_str(s: &str) -> Result<Self, StoreError> {
        match s {
            "strict" => Ok(SameSite::Strict),
            "lax" => Ok(SameSite::Lax),
            "none" => Ok(SameSite::None),
            other => Err(StoreError::Validation(format!(
                "unknown same_site value in cookies row: {other:?}"
            ))),
        }
    }
}

/// Cookie record as stored. `partition_key` is implicit at the API
/// surface (it is verified by the gatekeeper) and not duplicated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieRecord {
    pub name: String,
    pub value: String,
    /// Unix seconds. None = session cookie.
    pub expires_at: Option<i64>,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
}

/// Unit struct used as the [`StorageStore`] handle for cookies.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cookies;

impl StorageStore for Cookies {
    fn name(&self) -> &'static str {
        "cookies"
    }

    fn wipe_partition(&self, conn: &Connection, key: &PartitionKey) -> Result<u64, StoreError> {
        let n = conn.execute(
            "DELETE FROM cookies WHERE partition_key = ?1",
            params![key.as_bytes().as_slice()],
        )?;
        Ok(n as u64)
    }
}

/// Insert or replace a cookie for the verified partition.
pub fn put(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    cookie: &CookieRecord,
) -> Result<(), StoreError> {
    let key = gk.authorize(req)?;
    if cookie.name.is_empty() {
        return Err(StoreError::Validation(
            "cookie name must not be empty".into(),
        ));
    }
    conn.execute(
        "INSERT OR REPLACE INTO cookies \
            (partition_key, name, value, expires_at, http_only, secure, same_site) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            key.as_bytes().as_slice(),
            cookie.name,
            cookie.value,
            cookie.expires_at,
            cookie.http_only as i64,
            cookie.secure as i64,
            cookie.same_site.as_db_str(),
        ],
    )?;
    Ok(())
}

/// Fetch a single cookie by name within the verified partition.
pub fn get(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    name: &str,
) -> Result<Option<CookieRecord>, StoreError> {
    let key = gk.authorize(req)?;
    let row = conn
        .query_row(
            "SELECT name, value, expires_at, http_only, secure, same_site \
             FROM cookies WHERE partition_key = ?1 AND name = ?2",
            params![key.as_bytes().as_slice(), name],
            row_to_cookie,
        )
        .optional()?;
    row.transpose()
}

/// List every cookie in the verified partition.
pub fn list(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
) -> Result<Vec<CookieRecord>, StoreError> {
    let key = gk.authorize(req)?;
    let mut stmt = conn.prepare(
        "SELECT name, value, expires_at, http_only, secure, same_site \
         FROM cookies WHERE partition_key = ?1 ORDER BY name",
    )?;
    let rows = stmt.query_map(params![key.as_bytes().as_slice()], row_to_cookie)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r??);
    }
    Ok(out)
}

/// Delete a single cookie by name. Returns whether a row was removed.
pub fn delete(
    gk: &Gatekeeper,
    conn: &Connection,
    req: &StorageRequest,
    name: &str,
) -> Result<bool, StoreError> {
    let key = gk.authorize(req)?;
    let n = conn.execute(
        "DELETE FROM cookies WHERE partition_key = ?1 AND name = ?2",
        params![key.as_bytes().as_slice(), name],
    )?;
    Ok(n > 0)
}

fn row_to_cookie(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<CookieRecord, StoreError>> {
    let name: String = row.get(0)?;
    let value: String = row.get(1)?;
    let expires_at: Option<i64> = row.get(2)?;
    let http_only_i: i64 = row.get(3)?;
    let secure_i: i64 = row.get(4)?;
    let same_site_s: String = row.get(5)?;
    Ok(
        SameSite::from_db_str(&same_site_s).map(|same_site| CookieRecord {
            name,
            value,
            expires_at,
            http_only: http_only_i != 0,
            secure: secure_i != 0,
            same_site,
        }),
    )
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
        let pid = std::process::id();
        p.push(format!(
            "pb-storage-cookies-{pid}-{tag}-{}",
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

    fn sample(name: &str) -> CookieRecord {
        CookieRecord {
            name: name.to_string(),
            value: "v".to_string(),
            expires_at: Some(1_700_000_000),
            http_only: true,
            secure: true,
            same_site: SameSite::Lax,
        }
    }

    #[test]
    fn put_then_get_round_trip() {
        let dir = unique_dir("rt");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        put(&gk, sp.conn(), &r, &sample("session")).unwrap();
        let fetched = get(&gk, sp.conn(), &r, "session").unwrap().unwrap();
        assert_eq!(fetched, sample("session"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_rejects_when_gatekeeper_rejects() {
        let dir = unique_dir("gk-reject");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let mut r = req("example.com", 1, 2);
        r.declared_key = derive("evil.com", Uuid::from_u128(1), Uuid::from_u128(2));
        let err = put(&gk, sp.conn(), &r, &sample("c")).unwrap_err();
        assert!(matches!(err, StoreError::Gatekeeper(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_rejects_empty_name() {
        let dir = unique_dir("empty-name");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        let mut c = sample("x");
        c.name.clear();
        let err = put(&gk, sp.conn(), &r, &c).unwrap_err();
        assert!(matches!(err, StoreError::Validation(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_returns_none_for_missing() {
        let dir = unique_dir("miss");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        assert!(get(&gk, sp.conn(), &r, "nope").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_is_partition_scoped() {
        // Cross-partition isolation: a cookie written under partition A
        // must not be visible to a list() call on partition B.
        let dir = unique_dir("scope");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, &sample("a-cookie")).unwrap();
        put(&gk, sp.conn(), &b, &sample("b-cookie")).unwrap();
        let in_a = list(&gk, sp.conn(), &a).unwrap();
        let in_b = list(&gk, sp.conn(), &b).unwrap();
        assert_eq!(in_a.len(), 1);
        assert_eq!(in_a[0].name, "a-cookie");
        assert_eq!(in_b.len(), 1);
        assert_eq!(in_b[0].name, "b-cookie");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_one_and_reports() {
        let dir = unique_dir("del");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        put(&gk, sp.conn(), &r, &sample("k")).unwrap();
        assert!(delete(&gk, sp.conn(), &r, "k").unwrap());
        assert!(!delete(&gk, sp.conn(), &r, "k").unwrap());
        assert!(get(&gk, sp.conn(), &r, "k").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wipe_partition_only_touches_target() {
        let dir = unique_dir("wipe");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let a = req("a.example", 1, 2);
        let b = req("b.example", 1, 2);
        put(&gk, sp.conn(), &a, &sample("a1")).unwrap();
        put(&gk, sp.conn(), &a, &sample("a2")).unwrap();
        put(&gk, sp.conn(), &b, &sample("b1")).unwrap();
        let n = Cookies.wipe_partition(sp.conn(), &a.declared_key).unwrap();
        assert_eq!(n, 2);
        assert!(list(&gk, sp.conn(), &a).unwrap().is_empty());
        assert_eq!(list(&gk, sp.conn(), &b).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_replaces_on_duplicate_name() {
        let dir = unique_dir("replace");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        let mut c = sample("dup");
        c.value = "first".into();
        put(&gk, sp.conn(), &r, &c).unwrap();
        c.value = "second".into();
        put(&gk, sp.conn(), &r, &c).unwrap();
        let fetched = get(&gk, sp.conn(), &r, "dup").unwrap().unwrap();
        assert_eq!(fetched.value, "second");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_site_round_trips_for_all_variants() {
        let dir = unique_dir("ss");
        let sp = bootstrap(&cfg_at(&dir)).unwrap();
        let gk = Gatekeeper::new();
        let r = req("example.com", 1, 2);
        for (n, ss) in [
            ("strict", SameSite::Strict),
            ("lax", SameSite::Lax),
            ("none", SameSite::None),
        ] {
            let mut c = sample(n);
            c.same_site = ss;
            put(&gk, sp.conn(), &r, &c).unwrap();
            let got = get(&gk, sp.conn(), &r, n).unwrap().unwrap();
            assert_eq!(got.same_site, ss);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
