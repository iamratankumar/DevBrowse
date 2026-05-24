//! Profile registry + persistence wiring, Module 7.
//!
//! In-memory store of `IdentityProfile` keyed by `profile_id`, with
//! TOML-backed persistence using the same atomic-write + 0600 pattern
//! pb-config established. Persistence lives in this module (not pb-storage)
//! because L12 forbids pb-identity from importing pb-storage; the registry
//! file is a small structured TOML, not a partitioned data store.
//!
//! Concurrency: the registry is a plain sync struct. Module 9 (lifecycle)
//! wraps it in `Arc<tokio::sync::Mutex<ProfileRegistry>>` at the integration
//! boundary. Keeping this module sync makes it testable without a runtime.
//!
//! Duplicate policy:
//!   * Duplicate `profile_id`: rejected (the UUID is the key).
//!   * Duplicate `name`: ALLOWED. Two profiles may share a label (e.g.
//!     "Personal" Standard and "Personal" Strict). Disambiguation is the
//!     UI's job; the security boundary is `profile_id`, not `name`.
//!
//! Permission posture: the registry file MUST be owner-only on Unix (0600).
//! pb-config already owns the permission helpers; we reuse them via
//! `pb_config::permissions` rather than duplicating the logic.
//!
//! TODO(L27 forensic-redaction invariant + Module 82 crash containment,
//!   Phase 11): registry path itself is non-secret, but the file contents
//!   (profile names) ARE secret per L27. Never log the path's contents;
//!   only log the path string. (Original wording "Module 27 / 82"
//!   conflated L27 — the architecture invariant — with Module 27 which
//!   is Canvas readback normalization; corrected on 2026-05-21.)

use crate::profile::{IdentityProfile, MAX_NAME_LEN};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Bump when the on-disk registry schema changes incompatibly.
pub const REGISTRY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry file I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("registry TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("registry TOML serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("registry schema version mismatch: file has {found}, this binary expects {expected}")]
    SchemaVersion { found: u32, expected: u32 },

    #[error("duplicate profile_id {0}")]
    DuplicateProfileId(Uuid),

    #[error("registry file permission error: {0}")]
    Permission(String),

    #[error("registry validation error: {0}")]
    Validation(String),
}

/// On-disk wire format. Kept private; callers operate on `ProfileRegistry`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    version: u32,
    #[serde(default)]
    profiles: Vec<IdentityProfile>,
}

/// Identity profile registry.
///
/// `path` is `None` for in-memory registries (tests and ephemeral cases).
/// When `path` is `Some`, `save()` writes there atomically and `load()`
/// reads from there.
#[derive(Debug)]
pub struct ProfileRegistry {
    profiles: HashMap<Uuid, IdentityProfile>,
    path: Option<PathBuf>,
}

impl ProfileRegistry {
    /// In-memory registry with no backing file. Useful for tests and for
    /// short-lived contexts that never persist.
    pub fn new_in_memory() -> Self {
        Self {
            profiles: HashMap::new(),
            path: None,
        }
    }

    /// Empty registry bound to a path. The file is NOT created until
    /// `save()` is called; if the path already exists, prefer `load`.
    pub fn new_at(path: impl Into<PathBuf>) -> Self {
        Self {
            profiles: HashMap::new(),
            path: Some(path.into()),
        }
    }

    /// Load + validate from disk, enforcing owner-only file permissions.
    /// Returns an empty registry bound to `path` if the file does not exist.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self {
                profiles: HashMap::new(),
                path: Some(path),
            });
        }
        pb_config::permissions::ensure_owner_only(&path)
            .map_err(|e| RegistryError::Permission(e.to_string()))?;
        let bytes = std::fs::read_to_string(&path)?;
        let file: RegistryFile = toml::from_str(&bytes)?;
        if file.version != REGISTRY_SCHEMA_VERSION {
            return Err(RegistryError::SchemaVersion {
                found: file.version,
                expected: REGISTRY_SCHEMA_VERSION,
            });
        }
        let mut profiles = HashMap::with_capacity(file.profiles.len());
        for p in file.profiles {
            // Defense in depth: schema-level checks the on-disk file may
            // have been edited by hand; reject anything that violates the
            // builder's invariants. MAX_NAME_LEN is the only structural
            // rule we can re-check without rebuilding the profile.
            if p.name().is_empty() {
                return Err(RegistryError::Validation(
                    "profile with empty name in registry file".to_string(),
                ));
            }
            if p.name().len() > MAX_NAME_LEN {
                return Err(RegistryError::Validation(format!(
                    "profile name exceeds {MAX_NAME_LEN} bytes in registry file"
                )));
            }
            if profiles.insert(p.profile_id(), p).is_some() {
                // The HashMap dedup hides this, so check explicitly:
                return Err(RegistryError::Validation(
                    "duplicate profile_id in registry file".to_string(),
                ));
            }
        }
        Ok(Self {
            profiles,
            path: Some(path),
        })
    }

    /// Insert a profile. Rejects duplicate `profile_id`.
    pub fn insert(&mut self, profile: IdentityProfile) -> Result<(), RegistryError> {
        if self.profiles.contains_key(&profile.profile_id()) {
            return Err(RegistryError::DuplicateProfileId(profile.profile_id()));
        }
        self.profiles.insert(profile.profile_id(), profile);
        Ok(())
    }

    pub fn get(&self, id: &Uuid) -> Option<&IdentityProfile> {
        self.profiles.get(id)
    }

    /// Remove a profile by id. Lifecycle (Module 9) is responsible for
    /// tearing down any tabs bound to this profile BEFORE calling remove.
    pub fn remove(&mut self, id: &Uuid) -> Option<IdentityProfile> {
        self.profiles.remove(id)
    }

    pub fn list(&self) -> impl Iterator<Item = &IdentityProfile> {
        self.profiles.values()
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Atomically write the registry to its bound path with 0600 permissions.
    /// Returns an error if the registry has no bound path (in-memory only).
    pub fn save(&self) -> Result<(), RegistryError> {
        let path = self
            .path
            .as_deref()
            .ok_or_else(|| RegistryError::Validation("registry has no bound path".to_string()))?;
        let mut profiles: Vec<IdentityProfile> = self.profiles.values().cloned().collect();
        // Stable on-disk ordering keyed by profile_id, so file diffs are
        // deterministic across saves on the same content.
        profiles.sort_by_key(|p| p.profile_id());
        let file = RegistryFile {
            version: REGISTRY_SCHEMA_VERSION,
            profiles,
        };
        let s = toml::to_string_pretty(&file)?;
        let tmp = tmp_path(path);
        std::fs::write(&tmp, s)?;
        pb_config::permissions::lock_owner_only(&tmp)
            .map_err(|e| RegistryError::Permission(e.to_string()))?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    s.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{IdentityProfile, Mode};

    fn make(name: &str, mode: Mode) -> IdentityProfile {
        IdentityProfile::builder()
            .name(name)
            .mode(mode)
            .build()
            .expect("valid profile")
    }

    fn tmpfile(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        p.push(format!(
            "pb-identity-registry-test-{pid}-{tag}-{}.toml",
            Uuid::new_v4().simple()
        ));
        p
    }

    #[test]
    fn in_memory_insert_get_remove() {
        let mut r = ProfileRegistry::new_in_memory();
        let a = make("Personal", Mode::Standard);
        let id = a.profile_id();
        r.insert(a.clone()).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.get(&id).unwrap().name(), "Personal");
        let removed = r.remove(&id).unwrap();
        assert_eq!(removed.profile_id(), id);
        assert!(r.is_empty());
    }

    #[test]
    fn duplicate_profile_id_rejected() {
        let mut r = ProfileRegistry::new_in_memory();
        let a = make("Personal", Mode::Standard);
        let same_id = a.clone();
        r.insert(a).unwrap();
        let err = r.insert(same_id).unwrap_err();
        assert!(matches!(err, RegistryError::DuplicateProfileId(_)));
    }

    #[test]
    fn duplicate_name_allowed() {
        // "Personal" Standard and "Personal" Strict must coexist;
        // disambiguation is the UI's job, not the registry's.
        let mut r = ProfileRegistry::new_in_memory();
        r.insert(make("Personal", Mode::Standard)).unwrap();
        r.insert(make("Personal", Mode::Strict)).unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn list_yields_all_profiles() {
        let mut r = ProfileRegistry::new_in_memory();
        r.insert(make("A", Mode::Standard)).unwrap();
        r.insert(make("B", Mode::Strict)).unwrap();
        let names: std::collections::HashSet<&str> = r.list().map(|p| p.name()).collect();
        assert!(names.contains("A"));
        assert!(names.contains("B"));
    }

    #[test]
    fn save_without_path_errors() {
        let r = ProfileRegistry::new_in_memory();
        match r.save() {
            Err(RegistryError::Validation(_)) => {}
            other => panic!("expected Validation error for unbound save, got {other:?}"),
        }
    }

    #[test]
    fn save_then_load_round_trip() {
        let path = tmpfile("round_trip");
        let _ = std::fs::remove_file(&path);

        let mut r = ProfileRegistry::new_at(&path);
        let a = make("Personal", Mode::Standard);
        let b = make("Work", Mode::Strict);
        let a_id = a.profile_id();
        let b_id = b.profile_id();
        r.insert(a).unwrap();
        r.insert(b).unwrap();
        r.save().unwrap();

        let loaded = ProfileRegistry::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get(&a_id).unwrap().name(), "Personal");
        assert_eq!(loaded.get(&b_id).unwrap().mode(), Mode::Strict);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_returns_empty_registry() {
        let path = tmpfile("missing");
        let _ = std::fs::remove_file(&path);
        let r = ProfileRegistry::load(&path).unwrap();
        assert!(r.is_empty());
        assert_eq!(r.path().unwrap(), path.as_path());
    }

    #[test]
    fn load_rejects_wrong_schema_version() {
        let path = tmpfile("bad_version");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "version = 9999\nprofiles = []\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        match ProfileRegistry::load(&path) {
            Err(RegistryError::SchemaVersion {
                found: 9999,
                expected,
            }) => assert_eq!(expected, REGISTRY_SCHEMA_VERSION),
            other => panic!("expected SchemaVersion error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn save_locks_file_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmpfile("perm_lock");
        let _ = std::fs::remove_file(&path);

        let mut r = ProfileRegistry::new_at(&path);
        r.insert(make("Personal", Mode::Standard)).unwrap();
        r.save().unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "registry file must be owner-only on Unix");

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_group_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmpfile("group_readable");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "version = 1\nprofiles = []\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        match ProfileRegistry::load(&path) {
            Err(RegistryError::Permission(_)) => {}
            other => panic!("expected Permission error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_rejects_unknown_top_level_field() {
        let path = tmpfile("unknown_field");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "version = 1\nprofiles = []\nmystery = true\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        match ProfileRegistry::load(&path) {
            Err(RegistryError::Parse(_)) => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn save_is_deterministic_across_calls() {
        let path = tmpfile("deterministic");
        let _ = std::fs::remove_file(&path);

        let mut r = ProfileRegistry::new_at(&path);
        r.insert(make("A", Mode::Standard)).unwrap();
        r.insert(make("B", Mode::Strict)).unwrap();
        r.save().unwrap();
        let first = std::fs::read_to_string(&path).unwrap();

        r.save().unwrap();
        let second = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            first, second,
            "two saves of the same content must produce identical bytes"
        );

        let _ = std::fs::remove_file(&path);
    }
}
