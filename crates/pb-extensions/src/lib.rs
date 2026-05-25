//! pb-extensions — curated allowlist + Strict blocker (Phase 7, Modules 40-41).
//!
//! Architecture v1.10 §3.2 / §3.3 / L9 / L40 / L41:
//!
//! * **Standard mode (Module 41 — pending)** — extensions load only
//!   from a curated, signed allowlist shipped via Module 65 update
//!   channel. No AMO, no bundled store, no manual `.xpi` side-load.
//!   No `webRequest`-style hook into pb-network (locked v1.10); the
//!   network broker has no extension hook surface in either mode.
//! * **Strict mode (Module 40)** — every extension API surface is
//!   dark regardless of allowlist membership. `browser.*` (Mozilla-
//!   native, Gecko-primary) and `chrome.*` (the Chrome-compat shim
//!   Gecko ships for portability) are both absent globals; content
//!   scripts never inject; background contexts are never spawned;
//!   declarative net request rules are dropped at manifest parse;
//!   legacy bootstrap manifests are refused. L41-locked: no user
//!   setting can re-enable extensions in Strict.

#![forbid(unsafe_code)]

pub mod allowlist;
pub mod blocker;
pub mod controller;
