//! Strict-mode hardening (Phase 5.5, Modules 35.1-35.4, 35.10).
//!
//! Layers Mullvad-class Strict-mode locks on top of the Phase-5
//! cohort base:
//!   * **Module 35.1** ([`letterbox`]) — window / screen dimension
//!     letterboxing per L42 (200 × 100 grid).
//!   * Module 35.2 ([`timers`]) — Strict 100 ms timer quantum (L43).
//!   * Module 35.3 ([`disabled_apis`]) — Disabled-by-default L44
//!     API surface.
//!   * Module 35.4 ([`settings_lock`]) — Settings-lock enforcement
//!     (L41).
//!   * Module 35.10 ([`display`]) — Display capabilities (DPR /
//!     colorDepth / orientation cohort lock).
//!   * Module 35.10 ([`touch`]) — Touch surface cohort lock
//!     (maxTouchPoints / pointer / hover; v1.23 amiunique-generic
//!     desktop unification).
//!
//! Other Phase 5.5 modules live under `gecko/*` rather than here
//! (35.5 farbling, 35.6 WebGPU, 35.7 Speech + MediaCapabilities,
//! 35.8 NetworkInformation, 35.9 Permissions + StorageEstimate).
//! The `strict/` directory is reserved for L41/L42/L43/L44
//! desktop-cohort hardening; the `gecko/` directory hosts the
//! W3C-surface-specific overrides.
//!
//! Each sub-module's API is structurally non-loosenable in Strict
//! per L41 — `for_mode(Mode::Strict)` always resolves to the locked
//! cohort value, with no `with_user_override`-style escape hatch.

pub mod disabled_apis;
pub mod display;
pub mod letterbox;
pub mod settings_lock;
pub mod timers;
pub mod touch;
