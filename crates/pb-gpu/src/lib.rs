//! GPU process — Layer 2, Phase 6 (Modules 36-39).
//!
//! Shared GPU instance with per-identity isolation mitigations.
//!
//! Modules:
//!   * 36 [`coordinator`] — owns the WebGPU / WebGL adapter
//!     handle; issues per-identity scope tokens; survives
//!     adapter loss via monotonic epoch.
//!   * 37 [`memory_budget`] — per-identity GPU memory cap with
//!     LRU eviction within an identity (never across); paired
//!     with Module 36 via [`memory_budget::MemoryBudget::on_recovery`].
//!   * 38 [`queue`] — per-identity command queue scheduler with
//!     round-robin fairness; no buffer crosses identities;
//!     paired with Module 36 via [`queue::QueueScheduler::on_recovery`].
//!   * 39 [`timing`] — 2 ms GPU timer-query quantization
//!     (mode-invariant; mirrors Module 32 for the GPU domain;
//!     paired with `pb_fingerprint::gecko::timers::GPU_QUANTUM_NS`
//!     by byte-equal literal-value assertions per L12).
//!
//! Unsafe policy: this crate currently forbids unsafe. When low-level GPU
//! bridge code lands (Phase 11 / Module 80, libxul GPU FFI), downgrade
//! to `#![deny(unsafe_code)]` and require `#[allow(unsafe_code)]` on
//! the specific FFI module so unsafe blocks remain visible in code review.

#![forbid(unsafe_code)]

pub mod coordinator;
pub mod memory_budget;
pub mod queue;
pub mod timing;
