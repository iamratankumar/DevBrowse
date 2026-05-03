//! pb-testkit — Module 0.5, Phase 1.5.
//!
//! Shared test-fixture crate consumed by every other pb-* crate's tests.
//!
//! Architecture invariants this crate enforces:
//!   * **L12** — pb-testkit is dev-only and never appears in a release
//!     binary. Production crates list it under `[dev-dependencies]`. The
//!     dependency-direction rule still applies *as if* this crate did not
//!     exist when leaf-crate audits run (`cargo tree -p pb-platform | grep
//!     pb-` must not match anything). Because pb-testkit is a dev-dep, it
//!     is invisible to that audit by construction.
//!   * **L13** — `#![forbid(unsafe_code)]` like every other pb-* crate.
//!   * **L27** — the [`assert_redacted`] macro (re-exported below) checks
//!     that error `Display` outputs do not leak paths, UUIDs, domains, or
//!     emails. The tests of every pb-* crate use it instead of re-rolling
//!     redaction lints.
//!
//! Strict-mode invariant (phase-1_5-test-harness.md):
//!   Fixtures NEVER mock around an anti-fingerprint normalization. A test
//!   for a fingerprint surface must exercise the real normalization path;
//!   fixtures only stub *upstream* dependencies (platform adapters, IPC
//!   peer), never the surface under test.
//!
//! Cross-phase contract:
//!   Every Phase from 4 onward extends this crate with the fixtures its
//!   modules expose to later phases. The Phase exit gate (README §"Phase
//!   exit — cumulative test gate") fails if a later phase cannot
//!   integration-test against the prior phase using only public
//!   pb-testkit fixtures.

#![forbid(unsafe_code)]
// Public surface compiles only when consumers opt in. The default feature
// turns `testkit` on so `cargo test -p pb-testkit` works without flags.
#![cfg(any(test, feature = "testkit"))]

pub mod fixture;
pub mod macros;
pub mod proptest_strategies;

// Re-export the macros at the crate root so `pb_testkit::assert_redacted!`
// reads naturally at call sites. The macros themselves live in
// `macros.rs`; `#[macro_export]` puts them at the crate root regardless.

// Re-export common test types so consumers do not have to depend on every
// underlying crate's path themselves.
pub use pb_ipc::testkit::{DuplexConnection, DuplexReadHalf, DuplexWriteHalf};
