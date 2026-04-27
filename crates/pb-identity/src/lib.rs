//! Identity system — Layer 2, Phase 2 (Modules 6–11).
//!
//! Every tab's IdentityProfile is created here, locked at spawn,
//! and immutable for the tab's lifetime.

#![forbid(unsafe_code)]

pub mod lifecycle;
pub mod profile;
pub mod registry;
pub mod scheduler;
pub mod suspension;
pub mod warnings;
