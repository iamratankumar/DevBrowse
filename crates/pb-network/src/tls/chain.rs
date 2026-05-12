//! TLS 1.3 chain validation policy, Module 23.1.
//!
//! Architecture references:
//!   * **L7** — audited primitives only. `rustls` is the locked TLS
//!     stack (no OpenSSL). The chain validation walk itself is
//!     rustls's job; this module only assembles the trust anchors
//!     and provides the `ClientConfig` factory.
//!   * **L25** — Trust anchor set is `webpki-roots`. The system
//!     keystore is wizard-opt-in only (Module 64) and ships in v1
//!     as a reserved [`TrustAnchorChoice::System`] variant.
//!   * **L33** — one [`rustls::ClientConfig`] per process, locked
//!     across all DevBrowse users so the cohort-watch posture
//!     does not split. Standard and Strict modes share the same
//!     ClientConfig (see Module 24.1 invariant: identical
//!     ClientHello on the wire across modes).
//!   * **L27** — TLS error Display strings are opaque. Any rustls
//!     error reaches the [`crate::NetworkError::Tls`] variant
//!     without echoing the SNI / chain bytes.
//!
//! ## Cohort-watch (README §Adaptation)
//!
//! `rustls` is on the cohort-watch dependency list. A 0.23.x bump
//! triggers a review under the Adaptation protocol; a 0.24 bump is a
//! hold. The Cargo.toml pin `rustls = "0.23"` enforces the lower
//! bound; the upper bound is the next major (0.24) per Cargo's
//! semver rules.
//!
//! ## Self-signed certificate handling
//!
//! Per spec edge-case: "self-signed cert prompt = never silently
//! accepted; one-time per-site grant via Module 59 permission
//! center." v1 ships [`SelfSignedGrants`] as the trait surface +
//! [`DenyAllGrants`] as the default — the production behaviour until
//! Module 59 wires the permission-center grant minting.
//!
//! v1 does NOT yet plug a custom `ServerCertVerifier` into rustls
//! that consults `SelfSignedGrants` on chain failure. That wiring
//! lands when Module 59 ships; the trait is in place so the surface
//! is forward-compatible.
//!
//! ## What 23.1 does NOT do (sibling sub-modules)
//!
//!   * Certificate Transparency (SCT extraction + Merkle proofs) —
//!     Module 23.2 (`tls::ct`). Policy + verifier surface shipped;
//!     production verifier is the v1 follow-up.
//!   * Encrypted Client Hello (HPKE seal of `ClientHelloInner` +
//!     `ech_required` retry loop) — Module 23.3 (`tls::ech`).
//!     Policy + verifier surface shipped; production verifier is
//!     the v1 follow-up.
//!   * HSTS preload + pin store — Module 23.4 (deferred).
//!   * JA3-pinned ClientHello cipher suite / kx group / version pin
//!     — Module 24.1 (`crate::client_hello`). Shipped; this module
//!     consumes [`ClientHelloPin::pinned_client_config_with_roots`]
//!     so every TLS site flows through the same pinned ClientHello.
//
// TODO(Module 23.2 follow-up): chain validation walks SCT inclusion
//   proofs here once the production verifier lands inside CtVerifier.
// TODO(Module 23.3 follow-up): the rustls ECH client API leaves
//   experimental and the `EchVerifier` impl drives a real HPKE seal +
//   `ech_required` retry loop here.
// TODO(Module 59): wire SelfSignedGrants into a custom
//   `ServerCertVerifier` so a wizard-granted leaf SPKI is honored
//   without silently accepting any self-signed chain.

use crate::client_hello::ClientHelloPin;
use crate::tls::ct::CtPolicyBundle;
use crate::tls::ech::EchPolicyBundle;
use rustls::ClientConfig;
use std::fmt;
use std::sync::Arc;

/// Trust anchor source for the chain validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustAnchorChoice {
    /// L25 default: hermetic [`webpki-roots`] anchor set bundled
    /// into the binary. Identical across every DevBrowse user, so
    /// the chain-validation cohort cannot split.
    WebpkiRoots,
    /// Wizard-opt-in (Module 64): use the OS-managed system root
    /// store. Reserved in v1; the [`ChainValidator::build_client_config`]
    /// implementation returns the same config as `WebpkiRoots` until
    /// Module 64 lands the system-keystore loading path.
    System,
}

/// Hook for one-time per-site self-signed certificate grants
/// (Module 59 permission center). Implementations MUST be
/// `Send + Sync` so the chain validator can hold them inside an
/// `Arc<dyn SelfSignedGrants>`.
///
/// The hook returns `true` only when the user has explicitly
/// approved this specific (host, leaf SPKI) pair through the
/// permission center; the grant is per-leaf, not per-CA. Callers
/// (the future `ServerCertVerifier` impl in Module 59) MUST treat
/// any grant lookup miss as "deny" and surface a chain-validation
/// error.
pub trait SelfSignedGrants: Send + Sync + fmt::Debug {
    /// True iff the user has granted a one-time exception for
    /// `(host, leaf_spki_sha256)`. The hash is the SHA-256 of the
    /// leaf certificate's SubjectPublicKeyInfo — the same value
    /// Module 23.1 will compare against [`ResolverEndpoint::spki_pin`]
    /// once cert pinning enforcement lands.
    fn is_granted(&self, host: &str, leaf_spki_sha256: &[u8; 32]) -> bool;
}

/// Default grants impl — denies every host. Used in v1 + tests
/// that want to confirm the default-deny posture.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllGrants;

impl SelfSignedGrants for DenyAllGrants {
    fn is_granted(&self, _host: &str, _leaf_spki_sha256: &[u8; 32]) -> bool {
        false
    }
}

/// Capturing test grants impl. Records every lookup; allows tests
/// to assert that the future `ServerCertVerifier` consults the
/// hook with the right arguments.
#[derive(Debug, Default)]
pub struct CapturingGrants {
    lookups: std::sync::Mutex<Vec<(String, [u8; 32])>>,
}

impl CapturingGrants {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookups(&self) -> Vec<(String, [u8; 32])> {
        self.lookups.lock().expect("grants lock").clone()
    }
}

impl SelfSignedGrants for CapturingGrants {
    fn is_granted(&self, host: &str, leaf_spki_sha256: &[u8; 32]) -> bool {
        self.lookups
            .lock()
            .expect("grants lock")
            .push((host.to_string(), *leaf_spki_sha256));
        false
    }
}

/// TLS chain validator. Holds the trust anchor choice + the
/// self-signed-grant hook; produces a [`rustls::ClientConfig`] via
/// [`ChainValidator::build_client_config`].
///
/// One validator per process is the typical usage; the orchestrator
/// (Module 80) constructs the validator at boot and shares the
/// `Arc<ClientConfig>` across the DoH client (Module 20), the
/// production HTTPS dispatch path, and any future TLS handshake
/// site.
#[derive(Clone)]
pub struct ChainValidator {
    anchors: TrustAnchorChoice,
    grants: Arc<dyn SelfSignedGrants>,
    ct: CtPolicyBundle,
    ech: EchPolicyBundle,
}

impl ChainValidator {
    /// Construct with the locked default: webpki-roots + DenyAll
    /// grants + the no-op CT bundle (Module 23.2 v1) + the no-op
    /// ECH bundle (Module 23.3 v1).
    pub fn webpki_roots() -> Self {
        Self {
            anchors: TrustAnchorChoice::WebpkiRoots,
            grants: Arc::new(DenyAllGrants),
            ct: CtPolicyBundle::default_bundle(),
            ech: EchPolicyBundle::default_bundle(),
        }
    }

    /// Construct with the wizard-opt-in system-roots variant. v1
    /// behaves identically to [`webpki_roots`] until Module 64 wires
    /// the system keystore loading path. The variant tag is recorded
    /// so future revisions can pick up the wizard's choice without
    /// changing the call site.
    pub fn system_roots() -> Self {
        Self {
            anchors: TrustAnchorChoice::System,
            grants: Arc::new(DenyAllGrants),
            ct: CtPolicyBundle::default_bundle(),
            ech: EchPolicyBundle::default_bundle(),
        }
    }

    pub fn anchors(&self) -> TrustAnchorChoice {
        self.anchors
    }

    /// Replace the SelfSignedGrants hook. Used by the orchestrator
    /// (Module 80) when wiring Module 59's permission-center grants.
    pub fn with_grants(mut self, grants: Arc<dyn SelfSignedGrants>) -> Self {
        self.grants = grants;
        self
    }

    /// Replace the CT policy bundle (Module 23.2). The orchestrator
    /// wires its production [`crate::tls::CtVerifier`] in here at boot.
    pub fn with_ct(mut self, ct: CtPolicyBundle) -> Self {
        self.ct = ct;
        self
    }

    /// Replace the ECH policy bundle (Module 23.3). The orchestrator
    /// wires its production [`crate::tls::EchVerifier`] in here at boot,
    /// alongside the L34 Standard-mode settings-toggle override (via
    /// [`EchPolicyBundle::with_standard_disabled`]).
    pub fn with_ech(mut self, ech: EchPolicyBundle) -> Self {
        self.ech = ech;
        self
    }

    /// Snapshot of the wired SelfSignedGrants hook. Useful for tests
    /// that want to confirm grant dispatch.
    pub fn grants(&self) -> &Arc<dyn SelfSignedGrants> {
        &self.grants
    }

    /// Snapshot of the wired CT policy bundle.
    pub fn ct(&self) -> &CtPolicyBundle {
        &self.ct
    }

    /// Snapshot of the wired ECH policy bundle.
    pub fn ech(&self) -> &EchPolicyBundle {
        &self.ech
    }

    /// Build a `rustls::ClientConfig` that:
    ///
    ///   * uses the chosen trust anchor set
    ///   * advertises the cohort-locked ClientHello from
    ///     [`ClientHelloPin`] (Module 24.1) — pinned cipher-suite
    ///     ordering, kx groups, and protocol versions (TLS 1.3 + TLS
    ///     1.2). The pin is Mode-agnostic by construction (§3.4).
    ///   * declines client authentication (DevBrowse never sends a
    ///     client cert; site-side mTLS via user-supplied client certs
    ///     is a future enterprise-managed feature)
    ///
    /// The returned `Arc<ClientConfig>` is cheap to clone and is
    /// designed to be shared across the entire process so connection
    /// reuse stays scoped to a single ClientConfig identity.
    pub fn build_client_config(&self) -> Arc<ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        match self.anchors {
            TrustAnchorChoice::WebpkiRoots | TrustAnchorChoice::System => {
                // v1: both variants resolve to webpki-roots. Module 64
                // will branch on `System` to load the OS keystore.
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
        }
        let config = ClientHelloPin::pinned_client_config_with_roots(roots).with_no_client_auth();
        Arc::new(config)
    }
}

impl Default for ChainValidator {
    fn default() -> Self {
        Self::webpki_roots()
    }
}

impl fmt::Debug for ChainValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainValidator")
            .field("anchors", &self.anchors)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_webpki_roots() {
        let v = ChainValidator::default();
        assert_eq!(v.anchors(), TrustAnchorChoice::WebpkiRoots);
    }

    #[test]
    fn webpki_roots_constructor() {
        let v = ChainValidator::webpki_roots();
        assert_eq!(v.anchors(), TrustAnchorChoice::WebpkiRoots);
    }

    #[test]
    fn system_roots_variant_is_recorded() {
        let v = ChainValidator::system_roots();
        assert_eq!(v.anchors(), TrustAnchorChoice::System);
    }

    #[test]
    fn build_client_config_returns_a_usable_arc() {
        // Smoke test: the produced ClientConfig has no client auth,
        // is non-empty (at least one cipher suite + at least one
        // protocol version), and clones cheaply.
        let v = ChainValidator::default();
        let cfg = v.build_client_config();
        // Sanity on the rustls-side fields we depend on. We do not
        // assert on the raw counts (those move with rustls minor
        // bumps) but `crypto_provider().cipher_suites` must be
        // non-empty for the config to be usable.
        assert!(
            !cfg.crypto_provider().cipher_suites.is_empty(),
            "ClientConfig must carry at least one cipher suite"
        );
        // Cheap clone (Arc bump).
        let _clone = cfg.clone();
    }

    #[test]
    fn webpki_roots_anchor_set_is_non_empty() {
        // The cohort-locking property only holds if webpki-roots
        // ships *some* anchors. Without them every chain validation
        // would fail closed — which is sound but useless.
        let v = ChainValidator::webpki_roots();
        let cfg = v.build_client_config();
        // Defensive: extract the root store via debug surface. rustls
        // does not expose a public "count anchors" accessor on
        // ClientConfig, so we rely on the underlying constant.
        assert!(
            !webpki_roots::TLS_SERVER_ROOTS.is_empty(),
            "webpki-roots must ship at least one trust anchor"
        );
        // Producing a config with the root set succeeds.
        let _ = cfg;
    }

    #[test]
    fn deny_all_grants_rejects_every_host() {
        let g = DenyAllGrants;
        let zero = [0u8; 32];
        assert!(!g.is_granted("example.com", &zero));
        assert!(!g.is_granted("evil.com", &[0xFFu8; 32]));
    }

    #[test]
    fn capturing_grants_records_lookups() {
        let g = CapturingGrants::new();
        let spki = [0x42u8; 32];
        let granted = g.is_granted("example.com", &spki);
        assert!(!granted, "CapturingGrants always denies");
        let log = g.lookups();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, "example.com");
        assert_eq!(log[0].1, spki);
    }

    #[test]
    fn with_grants_replaces_default_hook() {
        let v = ChainValidator::default();
        let cap = Arc::new(CapturingGrants::new());
        let v_with = v.with_grants(cap.clone());
        // Round-trip via the hook surface.
        let _ = v_with.grants().is_granted("h", &[0u8; 32]);
        assert_eq!(cap.lookups().len(), 1);
    }

    #[test]
    fn validator_is_send_sync() {
        // ChainValidator is held inside Arc<Mutex<NetworkCoordinator>>
        // (Send + Sync via the Mutex), but having ChainValidator
        // itself Send + Sync simplifies orchestrator wiring.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ChainValidator>();
    }

    // -- Module 23.2 CT integration tests --

    #[test]
    fn default_validator_carries_default_ct_bundle() {
        use crate::tls::ct::{CtPolicy, CtVerificationOutcome};
        use crate::Mode;
        let v = ChainValidator::default();
        let ct = v.ct();
        assert_eq!(ct.policy_for(Mode::Standard), CtPolicy::WarnAndOffer);
        assert_eq!(ct.policy_for(Mode::Strict), CtPolicy::HardFail);
        // NoOp verifier is the v1 default.
        assert_eq!(
            ct.verifier().verify(&[]),
            CtVerificationOutcome::NotEnforced
        );
    }

    #[test]
    fn with_ct_replaces_bundle() {
        use crate::tls::ct::{CapturingVerifier, CtPolicyBundle, CtVerificationOutcome};
        let cap = Arc::new(CapturingVerifier::new(CtVerificationOutcome::Verified));
        let bundle = CtPolicyBundle::with_verifier(cap.clone());
        let v = ChainValidator::default().with_ct(bundle);
        let outcome = v.ct().verifier().verify(&[&b"x"[..]]);
        assert_eq!(outcome, CtVerificationOutcome::Verified);
        assert_eq!(cap.observed_calls().len(), 1);
    }

    // -- Module 23.3 ECH integration tests --

    #[test]
    fn default_validator_carries_default_ech_bundle() {
        use crate::tls::ech::{EchPolicy, EchVerificationOutcome};
        use crate::Mode;
        let v = ChainValidator::default();
        let ech = v.ech();
        // Mode locks: Strict=Mandatory, Standard=Preferred.
        assert_eq!(ech.policy_for(Mode::Standard), EchPolicy::Preferred);
        assert_eq!(ech.policy_for(Mode::Strict), EchPolicy::Mandatory);
        // NoOp verifier is the v1 default.
        assert_eq!(
            ech.verifier().verify("example.com"),
            EchVerificationOutcome::NotAttempted
        );
    }

    #[test]
    fn with_ech_replaces_bundle() {
        use crate::tls::ech::{CapturingEchVerifier, EchPolicyBundle, EchVerificationOutcome};
        let cap = Arc::new(CapturingEchVerifier::new(EchVerificationOutcome::Encrypted));
        let bundle = EchPolicyBundle::with_verifier(cap.clone());
        let v = ChainValidator::default().with_ech(bundle);
        let outcome = v.ech().verifier().verify("example.com");
        assert_eq!(outcome, EchVerificationOutcome::Encrypted);
        assert_eq!(cap.observed_hosts().len(), 1);
        assert_eq!(cap.observed_hosts()[0], "example.com");
    }

    #[test]
    fn with_ech_carries_standard_disabled_toggle() {
        // L34 settings toggle reaches the validator through the
        // bundle so the orchestrator can wire it once at boot.
        use crate::tls::ech::{EchPolicy, EchPolicyBundle};
        use crate::Mode;
        let bundle = EchPolicyBundle::default().with_standard_disabled();
        let v = ChainValidator::default().with_ech(bundle);
        assert_eq!(v.ech().policy_for(Mode::Standard), EchPolicy::Disabled);
        assert_eq!(v.ech().policy_for(Mode::Strict), EchPolicy::Mandatory);
    }
}
