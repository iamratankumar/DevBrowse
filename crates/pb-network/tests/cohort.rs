//! Phase 4 cohort-drift integration tests.
//!
//! Module 24.2 — entry point for the cohort sub-suite. Each submodule
//! pins one cohort-relevant property of the production network stack so
//! a silent rustls / quinn / dependency bump that would split the
//! cohort fails CI before merge.

mod cohort {
    pub mod ja3;
}
