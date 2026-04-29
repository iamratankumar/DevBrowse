//! Sandbox profile shape + the [`SandboxProfile::apply`] interface.
//!
//! v1 = TYPES AND INTERFACE ONLY. Real kernel-level enforcement lands in
//! Module 12.1 / Phase 11 (`enforce` submodule, deferred — see crate-level
//! TODO in `lib.rs`). Until then, `apply()` succeeds on every platform with
//! a tracing warning on desktop and a debug log on mobile; this is
//! intentional so call sites are already wired and Module 12.1 is a swap,
//! not a plumbing change.

use crate::platform::PlatformKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Process role this profile applies to. Each class has a different
/// default surface (a renderer needs no fs writes; the storage process
/// does, but only inside its capability root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxClass {
    /// Untrusted Gecko renderer. Tightest profile; no network, no fs
    /// writes, no subprocess.
    Renderer,
    /// Network broker (Module 19+). Allows outbound network; no fs.
    Network,
    /// Storage broker (Module 13+). Allows fs writes inside the
    /// capability root only; no network.
    Storage,
    /// Filesystem capability broker (Module 38+). Talks to the OS file
    /// picker; never opens paths itself.
    Filesystem,
}

/// Sandbox profile for a single process. Strict by default: any field set
/// to `true` is an explicit relaxation that the spawning code must
/// justify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProfile {
    pub class: SandboxClass,
    /// Allow direct outbound network from this process. Renderers MUST
    /// keep this `false`; network goes through pb-network IPC.
    pub allow_network: bool,
    /// Allow filesystem writes (read or write outside cwd). Renderers
    /// MUST keep this `false`; file IO goes through capability handles.
    pub allow_filesystem_writes: bool,
    /// Allow `fork` / `CreateProcess` from this process. Renderers MUST
    /// keep this `false`; the orchestrator owns process spawning.
    pub allow_subprocess: bool,
    /// Hard memory cap in bytes. `None` means no hard cap; orchestrator
    /// may still apply a per-mode soft cap above this layer.
    pub max_memory_bytes: Option<u64>,
}

impl SandboxProfile {
    /// Recommended defaults for an untrusted Gecko renderer (§5.8).
    /// Every relaxation is denied by default.
    pub fn strict_renderer() -> Self {
        Self {
            class: SandboxClass::Renderer,
            allow_network: false,
            allow_filesystem_writes: false,
            allow_subprocess: false,
            max_memory_bytes: None,
        }
    }

    /// Recommended defaults for the network broker.
    pub fn strict_network() -> Self {
        Self {
            class: SandboxClass::Network,
            allow_network: true,
            allow_filesystem_writes: false,
            allow_subprocess: false,
            max_memory_bytes: None,
        }
    }

    /// Recommended defaults for the storage broker. Filesystem writes are
    /// permitted but the storage broker is itself responsible for
    /// confining them to its capability root.
    pub fn strict_storage() -> Self {
        Self {
            class: SandboxClass::Storage,
            allow_network: false,
            allow_filesystem_writes: true,
            allow_subprocess: false,
            max_memory_bytes: None,
        }
    }

    /// Recommended defaults for the filesystem capability broker. Talks
    /// to the OS file picker via the platform layer; never opens paths
    /// itself.
    pub fn strict_filesystem() -> Self {
        Self {
            class: SandboxClass::Filesystem,
            allow_network: false,
            allow_filesystem_writes: false,
            allow_subprocess: false,
            max_memory_bytes: None,
        }
    }

    /// Install this profile on the current process.
    ///
    /// v1 contract:
    /// - On iOS / Android: succeeds silently. The OS app sandbox already
    ///   isolates the process; Module 12 has nothing to do.
    /// - On Linux / macOS / Windows: succeeds with a `tracing::warn!`.
    ///   Real enforcement is deferred to Module 12.1 (`enforce` submodule).
    ///
    /// Call sites should already wire `.apply()` at every spawn so that
    /// when Module 12.1 lands, no plumbing changes are needed.
    pub fn apply(&self) -> Result<(), SandboxError> {
        let platform = PlatformKind::current();
        if !platform.is_kernel_sandbox_owner() {
            tracing::debug!(
                class = ?self.class,
                platform = ?platform,
                "sandbox delegated to OS app sandbox"
            );
            return Ok(());
        }
        tracing::warn!(
            class = ?self.class,
            platform = ?platform,
            "kernel sandbox not yet enforced (Module 12 v1 = types only)"
        );
        Ok(())
    }
}

/// Errors raised by sandbox application. Variants are reserved for the
/// real enforcement layer (Module 12.1); v1 never returns `Err`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SandboxError {
    /// Profile fails internal validation (e.g., contradictory flags).
    /// Reserved; not produced by v1.
    #[error("sandbox profile invalid: {0}")]
    InvalidProfile(String),
    /// Requested feature is not implementable on this platform.
    /// Reserved; not produced by v1.
    #[error("sandbox feature not supported on this platform")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_renderer_denies_everything() {
        let p = SandboxProfile::strict_renderer();
        assert_eq!(p.class, SandboxClass::Renderer);
        assert!(!p.allow_network, "renderer must not have direct network");
        assert!(
            !p.allow_filesystem_writes,
            "renderer must not have direct filesystem writes"
        );
        assert!(!p.allow_subprocess, "renderer must not spawn subprocesses");
        assert_eq!(p.max_memory_bytes, None);
    }

    #[test]
    fn strict_network_allows_only_network() {
        let p = SandboxProfile::strict_network();
        assert_eq!(p.class, SandboxClass::Network);
        assert!(p.allow_network);
        assert!(!p.allow_filesystem_writes);
        assert!(!p.allow_subprocess);
    }

    #[test]
    fn strict_storage_allows_only_filesystem_writes() {
        let p = SandboxProfile::strict_storage();
        assert_eq!(p.class, SandboxClass::Storage);
        assert!(!p.allow_network);
        assert!(p.allow_filesystem_writes);
        assert!(!p.allow_subprocess);
    }

    #[test]
    fn strict_filesystem_denies_everything() {
        let p = SandboxProfile::strict_filesystem();
        assert_eq!(p.class, SandboxClass::Filesystem);
        assert!(!p.allow_network);
        assert!(!p.allow_filesystem_writes);
        assert!(!p.allow_subprocess);
    }

    #[test]
    fn apply_succeeds_on_current_platform() {
        // v1 contract: apply never errors on any supported target.
        let p = SandboxProfile::strict_renderer();
        assert!(p.apply().is_ok());
    }

    #[test]
    fn profile_round_trips_via_toml() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            p: SandboxProfile,
        }
        let w = W {
            p: SandboxProfile {
                class: SandboxClass::Storage,
                allow_network: false,
                allow_filesystem_writes: true,
                allow_subprocess: false,
                max_memory_bytes: Some(512 * 1024 * 1024),
            },
        };
        let s = toml::to_string(&w).unwrap();
        let w2: W = toml::from_str(&s).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn sandbox_class_serializes_snake_case() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            c: SandboxClass,
        }
        let w = W {
            c: SandboxClass::Filesystem,
        };
        let s = toml::to_string(&w).unwrap();
        assert!(
            s.contains("c = \"filesystem\""),
            "expected snake_case serialization, got:\n{s}"
        );
        let w2: W = toml::from_str(&s).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn deny_unknown_fields_rejects_extras() {
        // Forward compat: a future addition that the current version
        // does not understand must error rather than silently drop the
        // unknown field.
        let bad = "class = \"renderer\"\n\
                   allow_network = false\n\
                   allow_filesystem_writes = false\n\
                   allow_subprocess = false\n\
                   max_memory_bytes = 0\n\
                   ghost_field = true\n";
        let r: Result<SandboxProfile, _> = toml::from_str(bad);
        assert!(r.is_err(), "deny_unknown_fields must reject ghost_field");
    }
}
