//! Config file permission locking — folded into Module 3.
//!
//! On Unix the config file MUST be owner-only (mode 0600). A group- or
//! world-writable config file would let another local process redirect, for
//! example, our DoH endpoint to a tracking resolver, or flip
//! `telemetry.enabled` true. Failing closed at load time is the right call.
//!
//! Windows ACL-equivalent enforcement is **deferred to Phase 11.9 — Module
//! 94 (Windows file ACLs)**. The previous v1.4 `#[cfg(not(unix))]` no-op
//! stubs were removed in v1.9 because a silent no-op was strictly worse
//! than a clean compile failure: callers on Windows now refer to undefined
//! functions, surfacing the missing platform support immediately. Phase
//! 11.9 will land an explicit DACL pass restricting the ACL to the current
//! user SID with inheritance disabled (mirrors the Unix 0600 contract).

use std::io;
use std::path::Path;

/// Reject if the file at `path` has any permission bits for group or world.
/// Unix only; on Windows this function does not exist (Phase 11.9 defers).
#[cfg(unix)]
pub fn ensure_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path)?;
    let mode = md.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "config file {} has unsafe permissions {mode:o}; expected owner-only (0600)",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Set the file's mode to 0600 on Unix. Unix only; on Windows this function
/// does not exist (Phase 11.9 defers).
#[cfg(unix)]
pub fn lock_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn tmpfile(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        p.push(format!("pb-config-perm-test-{pid}-{tag}"));
        p
    }

    #[test]
    fn rejects_group_writable() {
        let p = tmpfile("group_writable");
        fs::write(&p, "x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o660)).unwrap();
        let err = ensure_owner_only(&p).expect_err("0660 must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn rejects_world_readable() {
        let p = tmpfile("world_readable");
        fs::write(&p, "x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o604)).unwrap();
        let err = ensure_owner_only(&p).expect_err("0604 must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn accepts_owner_only() {
        let p = tmpfile("owner_only");
        fs::write(&p, "x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        ensure_owner_only(&p).expect("0600 must be accepted");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn lock_sets_mode_0600() {
        let p = tmpfile("lock_sets_0600");
        fs::write(&p, "x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        lock_owner_only(&p).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_file(&p);
    }
}
