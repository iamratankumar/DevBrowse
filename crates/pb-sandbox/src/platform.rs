//! Runtime platform detection for [`crate::SandboxProfile::apply`].
//!
//! Splits desktop (DevBrowse owns the kernel sandbox) from mobile (the OS
//! app sandbox already isolates the process — architecture §3 mobile table).
//! The classification is platform-only, not target-arch.
//!
//! `PlatformKind::Windows` and its `current()` arm are kept as type-level
//! reservations so Phase 11.9 (Module 95 — Windows kernel sandbox via
//! AppContainer + Job Objects) can plug in without an enum reshape.
//! Windows binaries cannot be produced in v1.9: the `pb-ipc` Windows
//! backend `compile_error!`s, blocking the workspace build.

use serde::{Deserialize, Serialize};

/// Platform identity at runtime. Used by [`crate::SandboxProfile::apply`] to
/// decide whether this process is responsible for installing a kernel
/// sandbox or whether the OS app sandbox already covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    Linux,
    MacOs,
    Windows,
    Ios,
    Android,
}

impl PlatformKind {
    /// Resolves the current target via cfg. Compiles to a single constant
    /// per build.
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            PlatformKind::Linux
        }
        #[cfg(target_os = "macos")]
        {
            PlatformKind::MacOs
        }
        #[cfg(target_os = "windows")]
        {
            PlatformKind::Windows
        }
        #[cfg(target_os = "ios")]
        {
            PlatformKind::Ios
        }
        #[cfg(target_os = "android")]
        {
            PlatformKind::Android
        }
    }

    /// True on platforms where DevBrowse owns the kernel sandbox setup
    /// (Linux, macOS, Windows). False on iOS / Android, where the OS
    /// app sandbox already isolates the process and Module 12 is a
    /// no-op (architecture §3 mobile table).
    pub fn is_kernel_sandbox_owner(self) -> bool {
        matches!(
            self,
            PlatformKind::Linux | PlatformKind::MacOs | PlatformKind::Windows
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_current_classification_is_consistent() {
        let p = PlatformKind::current();
        let owner = p.is_kernel_sandbox_owner();
        match p {
            PlatformKind::Linux | PlatformKind::MacOs | PlatformKind::Windows => {
                assert!(owner, "{p:?} must own its kernel sandbox");
            }
            PlatformKind::Ios | PlatformKind::Android => {
                assert!(!owner, "{p:?} delegates to OS app sandbox");
            }
        }
    }
}
