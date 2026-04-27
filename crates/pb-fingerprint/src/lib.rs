//! Fingerprint normalization — Layer 2, Phase 5 (Modules 24–32).
//!
//! Implementation strategy: Gecko WebIDL override points — NOT JS prototype patching.
//! Workers and iframes inherit automatically. Zero internal Gecko patches.
//!
//! Unsafe policy: this crate currently forbids unsafe. When Gecko WebIDL FFI
//! lands (Phase 4 area), downgrade the lint to `#![deny(unsafe_code)]` and
//! require an explicit `#[allow(unsafe_code)]` annotation on the FFI module.
//! That keeps unsafe blocks visible in code review.

#![forbid(unsafe_code)]

pub mod gecko;
pub mod interface;
pub mod webkit_stub;
