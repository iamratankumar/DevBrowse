//! Update pipeline — Phase 9 (Modules 55–59).
//!
//! Two independent tracks:
//!   Track 1 — Blocklist: plain text, signed, 1-hour randomized delay.
//!   Track 2 — Wrapper compatibility manifest: TOML, separate offline HSM key.

pub mod blocklist_fetcher;
pub mod canary;
pub mod manifest;
pub mod signing;
pub mod wrapper_checker;
