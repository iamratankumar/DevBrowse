//! Fixture surface, Module 0.5 subtask 2.
//!
//! Each submodule wraps the public surface of one production pb-* crate
//! with builders and mocks tuned for tests. Every fixture must:
//!   * be cheap to construct (no I/O on the happy path)
//!   * produce reproducible values when given a seed (so flake-mode
//!     bisects work)
//!   * NEVER mock around an anti-fingerprint normalization (Phase 1.5
//!     Strict-mode invariant)

pub mod fake_doh;
pub mod fake_mdns;
pub mod ipc_pair;
pub mod ja3_probe;
pub mod mock_platform;
pub mod partition_key;
pub mod profile;

// Convenience re-exports so call sites read `fixture::profile()` instead of
// `fixture::profile::profile()`. The free-function variants are the public
// API shape the phase file calls out.
pub use fake_doh::{fake_doh, FakeDohResolver, ScriptedDohResponse};
pub use fake_mdns::{fake_mdns, FakeMdns, MdnsAnnounce, MdnsEvent};
pub use ipc_pair::{ipc_pair, ipc_pair_with_capacity};
pub use ja3_probe::{Ja3, Ja3Probe, ProbeError as Ja3ProbeError};
pub use mock_platform::{
    mock_platform, MockFileSystemAdapter, MockInputAdapter, MockNetworkAdapter,
    MockNotificationAdapter, MockPlatformBundle, MockWindowAdapter,
};
pub use partition_key::{partition_key, partition_key_request, FixturePartition};
pub use profile::{profile, profile_strict, profile_with_seed};
