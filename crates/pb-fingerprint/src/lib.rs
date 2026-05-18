//! Fingerprint normalization — Phase 5 (Modules 26-35).
//!
//! Architecture invariants enforced at this crate boundary:
//!   * **L8** — Gecko WebIDL override points only; no JS prototype
//!     patching. Workers and iframes inherit automatically because
//!     the override lives below the JS surface.
//!   * **L9 / §3.1** — every override is keyed on the Mode that was
//!     locked at IdentityProfile creation; this crate never mutates Mode.
//!   * **§5.5** — central fingerprint surface bucketing: every per-
//!     surface module routes through the [`interface`] trait so the
//!     plumbing list stays in one place.
//!   * **L7 / L27** — `profile_id` is the UUID v4 from Module 6 and
//!     is opaque to overrides; never log it.
//!
//! Unsafe policy: this crate currently forbids unsafe. When Gecko
//! WebIDL FFI lands (post Module 1 libxul tag), downgrade the lint to
//! `#![deny(unsafe_code)]` and require an explicit
//! `#[allow(unsafe_code)]` annotation on the FFI module so unsafe
//! blocks remain visible in code review.

#![forbid(unsafe_code)]

pub mod gecko;
pub mod interface;
pub mod webkit_stub;

pub use interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
