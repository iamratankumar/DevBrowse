//! OS sandbox profile, Module 12.
//!
//! Per architecture §5.8: every renderer runs under an OS-level sandbox
//! profile (seccomp on Linux, AppArmor on Linux, sandbox.plist on macOS,
//! job objects on Windows). This crate defines the typed profile shape
//! and the [`SandboxProfile::apply`] interface. iOS and Android delegate
//! to the OS app sandbox (architecture §3 mobile table) so apply is a
//! no-op there.
//!
//! pb-sandbox is in the "anyone may import" dependency tier alongside
//! pb-ipc and pb-config (architecture §4, v1.5). Spawn sites in pb-storage
//! / pb-network / the renderer harness construct or receive a
//! [`SandboxProfile`] and call `.apply()` on themselves at startup. The
//! crate has zero pb-* imports so it stays a leaf in the dep graph.
//!
//! Layout:
//!   * `platform` — runtime OS classification (kernel-sandbox owner vs
//!     OS-app-sandbox delegate).
//!   * `profile`  — `SandboxClass`, `SandboxProfile`, `SandboxError`, and
//!     the `apply()` interface (v1 = types only).
//!   * (deferred) `enforce` — Module 12.1 lands the real seccomp /
//!     AppArmor / sandbox_init / Job Object code here behind
//!     `#[allow(unsafe_code)]` per L13.
//!
//! Mirrors pb-identity Module 10's pattern: typed profile here, dispatch
//! at the orchestrator (Module 80, deferred).
//!
//! TODO(Module 12.1, deferred): wire `apply()` to the real enforcement
//!   code in this crate. Until then, `apply()` succeeds on every platform
//!   with a tracing warning on desktop; this is intentional so call sites
//!   are already in place. DO NOT remove the warn or change the contract
//!   without updating §5.8.
//! TODO(L15): the chosen seccomp / AppArmor / sandbox crate (or the raw
//!   syscall surface) must pass `cargo-deny` (advisories + bans) before
//!   being introduced.

#![forbid(unsafe_code)]

pub mod platform;
pub mod profile;

pub use platform::PlatformKind;
pub use profile::{SandboxClass, SandboxError, SandboxProfile};
