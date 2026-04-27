//! Fingerprint normalization — Layer 2, Phase 5 (Modules 24–32).
//!
//! Implementation strategy: Gecko WebIDL override points — NOT JS prototype patching.
//! Workers and iframes inherit automatically. Zero internal Gecko patches.

pub mod gecko;
pub mod interface;
pub mod webkit_stub;
