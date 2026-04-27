//! Extension control — Layer 2, Phase 7 (Modules 37–38).
//!
//! Standard mode: normal Gecko extension API passthrough.
//! Strict mode: blocked at identity context level — no workaround.

#![forbid(unsafe_code)]

pub mod blocker;
pub mod controller;
