//! Storage process bootstrap, Module 13.
//!
//! Resolves the data directory, creates it with owner-only permissions,
//! opens the SQLite database in WAL mode (L5), runs the v1 schema
//! migration, and applies the storage broker sandbox profile
//! (`pb_sandbox::SandboxProfile::strict_storage`) before returning the
//! handle.
//!
//! SECURITY INVARIANTS:
//!   * The database file is opened only by the storage process. Other
//!     processes (renderer, network broker) have no fs access to it
//!     because the sandbox profile (§5.8) denies it. Renderers reach
//!     storage exclusively through pb-ipc (§5.1).
//!   * The data directory is locked to mode 0700 on Unix; the database
//!     file to mode 0600. Windows ACL enforcement is deferred to
//!     Phase 11.9 — Module 94 (file ACLs / DPAPI).
//!   * Schema version is checked on every bootstrap. A version mismatch
//!     triggers `migrate(conn, from, to)`; v1.9 ships only a scaffold
//!     with explicit `unimplemented!()` arms — a real migration must
//!     land alongside any subsequent `STORAGE_SCHEMA_VERSION` bump.
//!   * `bootstrap` is the SOLE entry point for opening the live storage
//!     database in v1. Tests use it; the orchestrator (Module 80) will
//!     use it; no other call site may open `storage.sqlite` directly.
//!
//! Cross-platform data dir defaults (when `StorageConfig.data_dir` is None):
//!   * Linux: `$XDG_DATA_HOME/devbrowse` if set, else
//!     `$HOME/.local/share/devbrowse`.
//!   * macOS: `$HOME/Library/Application Support/DevBrowse`.
//!   * Windows: deferred to Phase 11.9 — Module 94. Until then, callers
//!     on Windows must provide `StorageConfig.data_dir` explicitly; the
//!     default-resolution path is gated to Unix.
//!   * iOS / Android: deferred to Phase 12 (engine adapter resolves the
//!     mobile-equivalent container path). Calling `bootstrap` on those
//!     targets without `StorageConfig.data_dir` set returns
//!     `StorageError::Validation`.

use pb_config::StorageConfig;
use pb_sandbox::{SandboxError, SandboxProfile};
use rusqlite::{params, Connection, OptionalExtension};
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Bump when the SQLite schema changes incompatibly. Migration policy
/// (forward / backward) is deferred to Module 13.x.
///
/// History:
///   * v1 (Module 13): meta table only.
///   * v2 (Module 16): adds cookies, local_storage, session_storage,
///     cache tables, all keyed by partition_key BLOB. No data migration
///     from v1 because the only persisted v1 row was schema_version
///     itself.
///   * v3 (Module 17): adds service_workers table for service-worker
///     registration metadata, partition-keyed like every other primitive.
///     Engine-side execution lives outside this crate; v3 stores only
///     the registration record.
pub const STORAGE_SCHEMA_VERSION: u32 = 3;

/// Filename of the storage database inside the data directory. Constant so
/// tests and the orchestrator agree without re-deriving it.
pub const STORAGE_DB_FILENAME: &str = "storage.sqlite";

/// Storage-process bootstrap errors.
///
/// L27 redaction: `Sqlite` and `Io` `Display` outputs are opaque. The
/// underlying `rusqlite::Error` / `io::Error` is reachable via
/// [`std::error::Error::source`] for in-process tracing only — subscribers
/// must respect L27 (never write source text to disk / wire without
/// redaction). The schema-version variant carries only integers, not
/// SQL text, so it stays explicit.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage I/O error")]
    Io(#[source] io::Error),

    #[error("storage backend error")]
    Sqlite(#[source] rusqlite::Error),

    #[error("storage schema version mismatch: file has {found}, this binary expects {expected}")]
    SchemaVersion { found: u32, expected: u32 },

    #[error("sandbox apply failed: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("storage permission error: {0}")]
    Permission(String),

    #[error("storage validation error: {0}")]
    Validation(String),
}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        StorageError::Io(e)
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        StorageError::Sqlite(e)
    }
}

/// Live storage broker handle. Owns the SQLite connection plus the
/// resolved on-disk paths.
///
/// Held in v1 as a single sync struct. Module 80 will wrap this in
/// `Arc<tokio::sync::Mutex<_>>` for async dispatch.
#[derive(Debug)]
pub struct StorageProcess {
    // Module 14+ (gatekeeper, primitives) consume this; the field is
    // intentionally held even before its first reader lands.
    #[allow(dead_code)]
    conn: Connection,
    data_dir: PathBuf,
    db_path: PathBuf,
}

impl StorageProcess {
    /// Resolved data directory (either the explicit
    /// `StorageConfig.data_dir` or the OS default).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Path to the SQLite database file.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Borrow the SQLite connection. Crate-internal: Modules 14-18 use
    /// this; renderers never reach it (they go through pb-ipc).
    /// rusqlite's `Connection::execute` takes `&self`, so all primitive
    /// CRUD ops fit through this shared borrow.
    ///
    /// `dead_code` allow stays until Module 80 (orchestrator) wires the
    /// non-test caller; tests already exercise this accessor.
    #[allow(dead_code)]
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }
}

/// Boot the storage process: resolve the data directory, open the
/// database, enable WAL, run the v1 schema migration, and apply the
/// strict-storage sandbox profile.
///
/// Idempotent: calling `bootstrap` twice with the same `data_dir` produces
/// two valid `StorageProcess` handles pointing at the same on-disk file.
/// The OS file lock (SQLite's own) prevents concurrent writers; the test
/// suite never holds two handles simultaneously.
pub fn bootstrap(cfg: &StorageConfig) -> Result<StorageProcess, StorageError> {
    let data_dir = resolve_data_dir(cfg)?;
    ensure_dir_owner_only(&data_dir)?;
    let db_path = data_dir.join(STORAGE_DB_FILENAME);
    let conn = Connection::open(&db_path)?;
    enable_wal(&conn)?;
    lock_db_owner_only(&db_path)?;
    initialize_schema(&conn)?;
    SandboxProfile::strict_storage().apply()?;
    Ok(StorageProcess {
        conn,
        data_dir,
        db_path,
    })
}

fn resolve_data_dir(cfg: &StorageConfig) -> Result<PathBuf, StorageError> {
    if let Some(p) = &cfg.data_dir {
        return Ok(p.clone());
    }
    default_data_dir()
}

fn default_data_dir() -> Result<PathBuf, StorageError> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return Ok(PathBuf::from(xdg).join("devbrowse"));
            }
        }
        let home = std::env::var("HOME").map_err(|_| {
            StorageError::Validation("HOME env var is not set on Linux".to_string())
        })?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("devbrowse"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").map_err(|_| {
            StorageError::Validation("HOME env var is not set on macOS".to_string())
        })?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("DevBrowse"))
    }
    #[cfg(target_os = "ios")]
    {
        Err(StorageError::Validation(
            "iOS data dir defaults are deferred to Phase 12; pass StorageConfig.data_dir explicitly"
                .to_string(),
        ))
    }
    #[cfg(target_os = "android")]
    {
        Err(StorageError::Validation(
            "Android data dir defaults are deferred to Phase 12; pass StorageConfig.data_dir explicitly"
                .to_string(),
        ))
    }
}

fn ensure_dir_owner_only(dir: &Path) -> Result<(), StorageError> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    } else if !dir.is_dir() {
        return Err(StorageError::Validation(format!(
            "data dir path exists but is not a directory: {}",
            dir.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| StorageError::Permission(e.to_string()))?;
    }
    Ok(())
}

fn lock_db_owner_only(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| StorageError::Permission(e.to_string()))?;
    }
    // Windows DACL enforcement deferred to Phase 11.9 — Module 94.
    // No no-op fallback: a Windows build will fail to compile because
    // `default_data_dir` is gated to Unix targets.
    Ok(())
}

fn enable_wal(conn: &Connection) -> Result<(), StorageError> {
    // Defense in depth: rusqlite's pragma_update silently accepts the input;
    // we round-trip the actual mode SQLite chose to confirm WAL is active.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StorageError::Validation(format!(
            "PRAGMA journal_mode set returned {mode:?}, expected wal (L5)"
        )));
    }
    Ok(())
}

fn initialize_schema(conn: &Connection) -> Result<(), StorageError> {
    // All Module 16 tables prefix the primary key with `partition_key
    // BLOB NOT NULL`, which is the §5.2 contract: every row carries the
    // partition key it belongs to, and the gatekeeper recomputes that
    // key on every read/write. WITHOUT ROWID is a SQLite storage
    // optimization for composite-PK k/v tables.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (\n\
            key   TEXT PRIMARY KEY,\n\
            value TEXT NOT NULL\n\
         );\n\
         CREATE TABLE IF NOT EXISTS cookies (\n\
            partition_key BLOB    NOT NULL,\n\
            name          TEXT    NOT NULL,\n\
            value         TEXT    NOT NULL,\n\
            expires_at    INTEGER,\n\
            http_only     INTEGER NOT NULL DEFAULT 0,\n\
            secure        INTEGER NOT NULL DEFAULT 0,\n\
            same_site     TEXT    NOT NULL DEFAULT 'lax',\n\
            PRIMARY KEY (partition_key, name)\n\
         ) WITHOUT ROWID;\n\
         CREATE TABLE IF NOT EXISTS local_storage (\n\
            partition_key BLOB NOT NULL,\n\
            key           TEXT NOT NULL,\n\
            value         TEXT NOT NULL,\n\
            PRIMARY KEY (partition_key, key)\n\
         ) WITHOUT ROWID;\n\
         CREATE TABLE IF NOT EXISTS session_storage (\n\
            partition_key BLOB NOT NULL,\n\
            key           TEXT NOT NULL,\n\
            value         TEXT NOT NULL,\n\
            PRIMARY KEY (partition_key, key)\n\
         ) WITHOUT ROWID;\n\
         CREATE TABLE IF NOT EXISTS cache (\n\
            partition_key BLOB    NOT NULL,\n\
            url           TEXT    NOT NULL,\n\
            body          BLOB    NOT NULL,\n\
            content_type  TEXT,\n\
            fetched_at    INTEGER NOT NULL,\n\
            PRIMARY KEY (partition_key, url)\n\
         ) WITHOUT ROWID;\n\
         CREATE TABLE IF NOT EXISTS service_workers (\n\
            partition_key BLOB    NOT NULL,\n\
            scope_url     TEXT    NOT NULL,\n\
            script_url    TEXT    NOT NULL,\n\
            state         TEXT    NOT NULL DEFAULT 'installed',\n\
            registered_at INTEGER NOT NULL,\n\
            PRIMARY KEY (partition_key, scope_url)\n\
         ) WITHOUT ROWID;",
    )?;
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    match existing {
        Some(v) => {
            let parsed: u32 = v.parse().map_err(|_| {
                StorageError::Validation(format!("non-numeric schema_version on disk: {v:?}"))
            })?;
            if parsed != STORAGE_SCHEMA_VERSION {
                migrate(conn, parsed, STORAGE_SCHEMA_VERSION)?;
            }
        }
        None => {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                params![STORAGE_SCHEMA_VERSION.to_string()],
            )?;
        }
    }
    Ok(())
}

/// Schema migration scaffold.
///
/// v1.9 ships only the dispatch table — every (`from`, `to`) pair returns
/// [`StorageError::SchemaVersion`] until a real migration is written. The
/// scaffold exists so any future `STORAGE_SCHEMA_VERSION` bump cannot
/// silently destroy data: the bumper is forced to add an explicit arm
/// here, write the SQL transform, and update the meta row inside a single
/// transaction.
///
/// Migration contract (when arms land):
///   * `from` is the on-disk version, `to` is `STORAGE_SCHEMA_VERSION`.
///   * Run inside `conn.unchecked_transaction()`; rollback on any error.
///   * Update the `schema_version` meta row to `to` as the final statement.
///   * Migrations are forward-only; downgrades are not supported.
#[allow(clippy::match_single_binding)] // Scaffold: future version arms land above the `_` catch-all.
pub(crate) fn migrate(conn: &Connection, from: u32, to: u32) -> Result<(), StorageError> {
    let _ = conn;
    match (from, to) {
        // Add concrete arms here per future version bump:
        // (1, 2) => migrate_v1_to_v2(conn),
        // (2, 3) => migrate_v2_to_v3(conn),
        _ => Err(StorageError::SchemaVersion {
            found: from,
            expected: to,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn unique_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        p.push(format!(
            "pb-storage-test-{pid}-{tag}-{}",
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

    #[test]
    fn bootstrap_creates_directory_and_db() {
        let dir = unique_dir("create");
        let sp = bootstrap(&cfg_at(&dir)).expect("bootstrap");
        assert!(sp.data_dir().exists());
        assert!(sp.db_path().exists());
        assert_eq!(sp.db_path(), dir.join(STORAGE_DB_FILENAME));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_enables_wal_journal_mode() {
        // L5: WAL is the locked journal mode. Bootstrap must round-trip it.
        let dir = unique_dir("wal");
        let sp = bootstrap(&cfg_at(&dir)).expect("bootstrap");
        let mode: String = sp
            .conn()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_persists_schema_version() {
        let dir = unique_dir("schema");
        let sp = bootstrap(&cfg_at(&dir)).expect("bootstrap");
        let v: String = sp
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, STORAGE_SCHEMA_VERSION.to_string());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_round_trips_re_open() {
        let dir = unique_dir("reopen");
        {
            let _sp1 = bootstrap(&cfg_at(&dir)).expect("first bootstrap");
            // Drop closes the SQLite connection.
        }
        let sp2 = bootstrap(&cfg_at(&dir)).expect("second bootstrap");
        let v: String = sp2
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, STORAGE_SCHEMA_VERSION.to_string());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_rejects_schema_version_mismatch() {
        let dir = unique_dir("mismatch");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join(STORAGE_DB_FILENAME);
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);\n\
             INSERT INTO meta (key, value) VALUES ('schema_version', '9999');",
        )
        .unwrap();
        drop(conn);
        match bootstrap(&cfg_at(&dir)) {
            Err(StorageError::SchemaVersion {
                found: 9999,
                expected,
            }) => {
                assert_eq!(expected, STORAGE_SCHEMA_VERSION);
            }
            other => panic!("expected SchemaVersion error, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_uses_explicit_data_dir() {
        let dir = unique_dir("explicit");
        let sp = bootstrap(&cfg_at(&dir)).expect("bootstrap");
        assert_eq!(sp.data_dir(), dir.as_path());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_rejects_non_directory_data_path() {
        let dir = unique_dir("notdir");
        std::fs::write(&dir, b"not a dir").unwrap();
        match bootstrap(&cfg_at(&dir)) {
            Err(StorageError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_locks_directory_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("perm_dir");
        let sp = bootstrap(&cfg_at(&dir)).expect("bootstrap");
        let mode = std::fs::metadata(sp.data_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "data dir must be owner-only on Unix");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_locks_db_file_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir("perm_db");
        let sp = bootstrap(&cfg_at(&dir)).expect("bootstrap");
        let mode = std::fs::metadata(sp.db_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "db file must be owner-only on Unix");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn default_data_dir_resolves_on_desktop() {
        let p = default_data_dir().expect("default data dir");
        assert!(p.is_absolute(), "default data dir must be absolute: {p:?}");
    }
}
