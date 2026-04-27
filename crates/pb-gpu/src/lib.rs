//! GPU process — Layer 2, Phase 6 (Modules 33–36).
//!
//! Shared GPU instance with per-identity isolation mitigations.
//!
//! Unsafe policy: this crate currently forbids unsafe. When low-level GPU
//! bridge code lands, downgrade to `#![deny(unsafe_code)]` and require
//! `#[allow(unsafe_code)]` on the specific FFI module so unsafe blocks
//! remain visible in code review.

#![forbid(unsafe_code)]

pub mod coordinator;
pub mod memory_budget;
pub mod queue;
pub mod timing;
