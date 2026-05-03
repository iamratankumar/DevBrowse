//! `fixture::profile` — canonical IdentityProfile builders.
//!
//! Subtask 2 of Module 0.5. Wraps `pb_identity::IdentityProfile::builder`
//! with sensible defaults so every test does not have to remember the
//! valid name / mode shape.

use pb_identity::profile::{IdentityProfile, Mode};

/// Build a Standard-mode IdentityProfile with a fixed name. The
/// `profile_id` is freshly minted via `Uuid::new_v4()` per the
/// production builder; tests that need a deterministic id should call
/// [`profile_with_seed`] instead.
pub fn profile() -> IdentityProfile {
    IdentityProfile::builder()
        .name("testkit-standard")
        .mode(Mode::Standard)
        .build()
        .expect("testkit Standard profile must build")
}

/// Build a Strict-mode IdentityProfile. Use this for tests that exercise
/// §3.3 rules (per-tab renderer, no extensions, DoH-only, max
/// fingerprint normalization, strict-wipe on close).
pub fn profile_strict() -> IdentityProfile {
    IdentityProfile::builder()
        .name("testkit-strict")
        .mode(Mode::Strict)
        .build()
        .expect("testkit Strict profile must build")
}

/// Build an IdentityProfile-shaped pair with a deterministic profile-id.
///
/// The production builder always mints a fresh v4 UUID. Tests that need
/// stable cross-run identity (e.g. partition-key snapshot tests) cannot
/// use that. This fixture returns the (uuid, name, mode) triple so the
/// caller can reconstruct any data structure that needs the id directly,
/// alongside a real `IdentityProfile` whose own `profile_id` is fresh.
///
/// Callers compute partition keys with the *seed* uuid, not the
/// profile's own id, when they want determinism.
pub fn profile_with_seed(seed: u128, mode: Mode) -> (uuid::Uuid, IdentityProfile) {
    let id = uuid::Uuid::from_u128(seed);
    let profile = IdentityProfile::builder()
        .name(format!("testkit-{:08x}", seed as u32))
        .mode(mode)
        .build()
        .expect("testkit seeded profile must build");
    (id, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_default_is_standard() {
        assert_eq!(profile().mode(), Mode::Standard);
    }

    #[test]
    fn strict_default_is_strict() {
        assert_eq!(profile_strict().mode(), Mode::Strict);
    }

    #[test]
    fn seeded_returns_stable_uuid() {
        let (a, _) = profile_with_seed(42, Mode::Standard);
        let (b, _) = profile_with_seed(42, Mode::Standard);
        assert_eq!(a, b);
    }
}
