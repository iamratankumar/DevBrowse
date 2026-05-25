//! Phase 7 cross-phase fixture — `extensions_bundle()`.
//!
//! Wraps the Module 40 + Module 41 surface into a single shareable
//! bundle so Phase 8+ tests can drive end-to-end
//! "Strict tab + allowlisted extension = chrome undefined" without
//! re-deriving the seed-manifest + verifier wiring every time.
//!
//! The bundle exposes:
//!   * the Module 40 `BlockerPolicy` resolver via convenience method
//!     (`policy_for`)
//!   * the Module 41 `ExtensionController` (seed manifest pre-loaded)
//!   * the `InMemoryTrustedVerifier` pre-trusted to accept the seed
//!     entry's `(pubkey, xpi_bytes, sig)` triple
//!
//! Phase 8 tests (Module 64 wizard, Module 59 permission center) can
//! call `extensions_bundle()` and immediately exercise the install /
//! manifest-swap / recall paths without copying the test scaffolding.
//!
//! ## Cross-phase contract (CLAUDE.md §"Cross-phase test contract")
//!
//! Phase 7 ships this fixture into pb-testkit so the structural
//! Strict-darks-vs-Standard-gating disjointness is exercised at the
//! cross-phase fixture level. The contract test at the bottom of
//! this file pins the load-bearing invariants:
//!   * `policy_for(Strict) == AllBlocked` regardless of what's
//!     installed under the controller — Strict-darks override the
//!     entire allowlist.
//!   * `policy_for(Standard) == StandardSubjectToAllowlist` and
//!     the controller's install gate is the only place per-extension
//!     decisions happen in Standard.

#![cfg(any(test, feature = "testkit"))]

use std::sync::Arc;

use pb_config::Mode;
use pb_extensions::allowlist::{
    AllowlistEntry, AllowlistManifest, Ed25519PubKeyBytes, Ed25519SigBytes, ExtensionId,
    InMemoryTrustedVerifier, Sha256Hash, Version, VersionConstraint, ALLOWLIST_FORMAT_VERSION,
};
use pb_extensions::blocker::{block_for_mode, BlockerPolicy};
use pb_extensions::controller::ExtensionController;

/// Default seed extension id used by [`extensions_bundle`]. Tests
/// that want a different id construct the bundle manually via
/// [`ExtensionsBundle::with_seed_entry`].
pub const SEED_EXTENSION_ID: &str = "uBlock0@raymondhill.net";

/// Default seed `.xpi` bytes (placeholder; the fixture treats these
/// as opaque). Tests that need realistic xpi shape supply their own.
pub const SEED_XPI_BYTES: &[u8] = b"<<testkit-seed-xpi-bytes>>";

const SEED_PUBKEY: Ed25519PubKeyBytes = Ed25519PubKeyBytes([0x11; 32]);
const SEED_SIG: Ed25519SigBytes = Ed25519SigBytes([0xAA; 64]);

/// Shareable Phase 7 extensions bundle.
///
/// Holds an `Arc<ExtensionController>` + a pre-trusted verifier +
/// the seed manifest's `(pubkey, sig)` so call sites can drive
/// install attempts in one line.
#[derive(Clone)]
pub struct ExtensionsBundle {
    pub controller: Arc<ExtensionController>,
    pub verifier: Arc<InMemoryTrustedVerifier>,
    pub seed_pubkey: Ed25519PubKeyBytes,
    pub seed_sig: Ed25519SigBytes,
}

impl ExtensionsBundle {
    /// Mode-resolved Module 40 policy. Convenience wrapper so
    /// callers do not need to import the blocker symbols.
    pub fn policy_for(&self, mode: Mode) -> BlockerPolicy {
        block_for_mode(mode)
    }

    /// Construct a bundle from a custom seed entry. Used by tests
    /// that need a non-default extension id or version constraint.
    /// The returned verifier pre-trusts the `(pubkey, xpi_bytes,
    /// sig)` triple so install attempts against this seed succeed
    /// at gate (d).
    pub fn with_seed_entry(
        entry: AllowlistEntry,
        xpi_bytes: Vec<u8>,
        sig: Ed25519SigBytes,
    ) -> Self {
        let pubkey = entry.signing_pubkey;
        let manifest = AllowlistManifest {
            format_version: ALLOWLIST_FORMAT_VERSION,
            manifest_version: 1,
            entries: vec![entry],
        };
        let controller = ExtensionController::new(manifest);
        let verifier = Arc::new(InMemoryTrustedVerifier::new().trust(pubkey, xpi_bytes, sig));
        Self {
            controller,
            verifier,
            seed_pubkey: pubkey,
            seed_sig: sig,
        }
    }
}

/// Construct a Phase 7 extensions bundle with the default seed
/// entry (`uBlock0@raymondhill.net`, constraint `>=1.50.0`, xpi
/// bytes = [`SEED_XPI_BYTES`]). The returned controller is
/// fresh (no extensions installed yet); call
/// `bundle.controller.install(...)` to record an install.
pub fn extensions_bundle() -> ExtensionsBundle {
    let entry = AllowlistEntry {
        extension_id: ExtensionId::new(SEED_EXTENSION_ID),
        version_constraint: VersionConstraint::AtLeast(Version::new(1, 50, 0)),
        sha256_of_xpi: Sha256Hash::of(SEED_XPI_BYTES),
        signing_pubkey: SEED_PUBKEY,
    };
    ExtensionsBundle::with_seed_entry(entry, SEED_XPI_BYTES.to_vec(), SEED_SIG)
}

// ── Cross-phase contract tests ───────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pb_extensions::allowlist::InstallCandidate;
    use pb_extensions::controller::InstallOutcome;

    #[test]
    fn cross_phase_contract_strict_blocks_all_regardless_of_installed_state() {
        // Load-bearing invariant the Phase 11 orchestrator (Module
        // 80) relies on: a Strict tab MUST see `AllBlocked` from
        // Module 40 and never consult the Module 41 controller,
        // even if the controller has allowlisted extensions
        // installed and enabled. The Strict darks override.
        let bundle = extensions_bundle();
        let install = bundle.controller.install(
            InstallCandidate {
                extension_id: ExtensionId::new(SEED_EXTENSION_ID),
                version: Version::new(1, 51, 0),
                xpi_bytes: SEED_XPI_BYTES,
                xpi_signature: bundle.seed_sig,
            },
            &*bundle.verifier,
        );
        assert!(matches!(install, InstallOutcome::Installed));

        // With an extension enabled in the controller, Strict
        // policy is STILL AllBlocked. Module 40 does not consult
        // Module 41 state.
        assert_eq!(bundle.policy_for(Mode::Strict), BlockerPolicy::AllBlocked);
    }

    #[test]
    fn cross_phase_contract_standard_delegates_to_controller_gating() {
        let bundle = extensions_bundle();
        // Module 40 policy in Standard: delegated.
        assert_eq!(
            bundle.policy_for(Mode::Standard),
            BlockerPolicy::StandardSubjectToAllowlist,
        );
        // Module 41 install gate is the only per-extension
        // decision point in Standard: an off-allowlist install
        // is rejected here.
        let out = bundle.controller.install(
            InstallCandidate {
                extension_id: ExtensionId::new("malicious@nowhere.test"),
                version: Version::new(1, 0, 0),
                xpi_bytes: b"<<other>>",
                xpi_signature: bundle.seed_sig,
            },
            &*bundle.verifier,
        );
        assert!(matches!(out, InstallOutcome::Rejected(_)));
    }

    #[test]
    fn cross_phase_contract_module_40_resolver_is_pure_on_mode_only() {
        // Tripwire: if a future Module 40 edit adds a parameter to
        // `block_for_mode`, this fixture stops compiling and
        // forces a cross-module audit. The pairing with Module
        // 41 (this fixture) is part of the L41 lock surface.
        let bundle = extensions_bundle();
        for _ in 0..8 {
            assert_eq!(bundle.policy_for(Mode::Strict), BlockerPolicy::AllBlocked);
        }
    }
}
