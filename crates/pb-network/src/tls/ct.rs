//! Certificate Transparency policy + verification surface, Module 23.2.
//!
//! Architecture references:
//!   * **L7 / L22** — audited primitives: SCT signature verification
//!     uses `rustls::pki_types` + `ring` crypto exclusively.
//!   * **L25** — CT log set ships through Module 67's signed update
//!     channel (deferred). v1 ships a [`KNOWN_CT_LOG_NAMES`]
//!     reference list (names only, no public keys yet) so the
//!     subsystem surface is forward-compatible.
//!   * **L27** — every error / Display string is opaque. Failure
//!     reasons surface through the typed [`CtFailureKind`] enum;
//!     SCT bytes / cert bytes never reach Display.
//!   * **§3.2 / §3.3** — Mode-locked policy: Strict hard-fails on
//!     any CT failure; Standard warns + offers-to-block (the UI
//!     surface for "offer to block" lands in Module 51 / pb-ui).
//!
//! ## v1 scope (deliberately narrow)
//!
//! v1 ships **policy + types + a no-op verifier**. The actual SCT
//! extraction, signature verification, and Merkle inclusion-proof
//! validation is a follow-up commit (it is the bulk of the
//! sub-module's eventual code volume — Chrome's CT subsystem is
//! several thousand lines). The architectural slot is in place so
//! when the verifier lands:
//!
//!   1. The Cargo.toml gains a CT-specific dep (e.g. `ct-trees-rs`
//!      or a hand-rolled subset of RFC 6962).
//!   2. A new [`CtVerifier`] impl replaces [`NoOpVerifier`].
//!   3. [`ChainValidator`]'s `ct_verifier` slot starts returning
//!      `Verified` / `Failed` for real chains.
//!   4. The Phase 10 fingerprint suite asserts
//!      `cohort-locked` behaviour against a probe site.
//!
//! Until then, v1 returns [`CtVerificationOutcome::NotEnforced`] for
//! every chain. The decision table below treats `NotEnforced` as
//! `Allow` under every policy, which matches "v1 does not break
//! navigation by failing CT" — the security-positive side of the
//! contract is enabled when the verifier wires in.
//!
//! ## SCT extraction sources (per spec)
//!
//! Three SCT delivery channels exist in TLS:
//!   1. **Embedded SCT extension in the certificate** — the most
//!      common path. SCTs are signed over the precertificate.
//!   2. **OCSP staple** with `signed_certificate_timestamp`
//!      extension. Server delivers SCTs out-of-band.
//!   3. **TLS extension** `signed_certificate_timestamp` (RFC 6962
//!      §3.3) — on the handshake. SCTs signed over the final cert.
//!
//! The pre-cert vs final-cert distinction is the "pre-cert SCT vs
//! final SCT mismatch" edge case the spec calls out: a hostile
//! intermediary that issues SCTs for a precert cannot use the same
//! signature on the final cert.
//
// TODO(Module 23.2 follow-up): real SCT extraction + signature
//   verification + Merkle inclusion proof against `KNOWN_CT_LOGS`.
//   The implementation will plug into rustls's `ServerCertVerifier`
//   alongside Module 23.1's chain validation.
// TODO(Module 67): replace `KNOWN_CT_LOG_NAMES` with the signed-
//   manifest CT log feed (same channel as the blocklist).
// TODO(Module 51 pb-ui): wire the "offer to block" UX for the
//   Standard-mode `Warn` decision.

use crate::Mode;
use std::fmt;
use std::sync::Arc;

// ── Reference CT log set (names only in v1) ───────────────────────────────

/// Reference list of CT logs DevBrowse intends to verify against
/// when the production verifier lands. Names only in v1; the
/// signed-manifest feed (Module 67) ships the public keys + log
/// IDs needed for signature verification.
///
/// The list mirrors Chrome's "qualified CT logs" set as of v1.
/// Cohort-watch (README §Adaptation): a log being added or
/// distrusted shifts the verification cohort and therefore needs
/// review under the protocol before merging.
pub const KNOWN_CT_LOG_NAMES: &[&str] = &[
    "Google 'Argon2025h1'",
    "Google 'Argon2025h2'",
    "Google 'Xenon2025h1'",
    "Google 'Xenon2025h2'",
    "Cloudflare 'Nimbus2025'",
    "DigiCert 'Wyvern2025h1'",
    "DigiCert 'Wyvern2025h2'",
    "Sectigo 'Sabre2025h1'",
    "Sectigo 'Sabre2025h2'",
    "Let's Encrypt 'Oak2025h1'",
    "Let's Encrypt 'Oak2025h2'",
];

// ── Policy ────────────────────────────────────────────────────────────────

/// Per-mode CT enforcement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtPolicy {
    /// Strict mode: any CT failure (no SCTs, all SCTs invalid,
    /// log down) is a hard chain rejection. The TLS handshake
    /// fails with [`crate::NetworkError::TlsCtFailed`].
    HardFail,
    /// Standard mode: emit a warning + offer the user a one-click
    /// block; the request still completes if the user does not
    /// intervene before the response window closes.
    WarnAndOffer,
    /// Reserved: CT enforcement disabled entirely. Not used by
    /// either Mode in v1; held for enterprise-managed deployments
    /// where the operator owns the trust posture explicitly.
    Disabled,
}

impl CtPolicy {
    /// Locked snapshot for `mode`. Strict = HardFail, Standard =
    /// WarnAndOffer (per spec). Mode never resolves to `Disabled`
    /// in v1; that variant is a managed-deployment override.
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::WarnAndOffer,
            Mode::Strict => Self::HardFail,
        }
    }

    /// Apply the policy to a verification outcome and return the
    /// dispatch decision. Pure function — no I/O.
    pub fn decide(self, outcome: &CtVerificationOutcome) -> CtDecision {
        match (self, outcome) {
            (Self::Disabled, _) => CtDecision::Allow,
            // NotEnforced means the verifier opted out (e.g. v1 stub,
            // or a chain type the verifier doesn't yet handle). Both
            // policies allow under NotEnforced — fail-open is the
            // documented v1 behaviour until the verifier is wired.
            (_, CtVerificationOutcome::NotEnforced) => CtDecision::Allow,
            (_, CtVerificationOutcome::Verified) => CtDecision::Allow,
            (Self::HardFail, CtVerificationOutcome::Failed { reason }) => {
                CtDecision::Block(*reason)
            }
            (Self::WarnAndOffer, CtVerificationOutcome::Failed { reason }) => {
                CtDecision::Warn(*reason)
            }
        }
    }
}

// ── Verification outcome + failure shape ──────────────────────────────────

/// Outcome of a CT verification attempt against a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtVerificationOutcome {
    /// At least the policy-required number of valid SCTs were
    /// extracted, signature-verified against [`KNOWN_CT_LOG_NAMES`]'
    /// keys, and (where the verifier supports it) Merkle-inclusion
    /// proven.
    Verified,
    /// The verifier opted out of evaluating this chain — typical
    /// v1 case where [`NoOpVerifier`] is the only impl. Also used
    /// for chains where CT does not apply (e.g. a leaf cert from
    /// before the CT mandate's effective date).
    NotEnforced,
    /// Verification failed; [`CtFailureKind`] discriminates the
    /// failure shape so the policy decision can react accordingly.
    Failed { reason: CtFailureKind },
}

/// Why a CT verification attempt failed. Display strings are
/// opaque; reasons carry no PEM / certificate bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtFailureKind {
    /// No SCTs were found across cert / OCSP staple / TLS
    /// extension delivery channels.
    NoSctsFound,
    /// SCTs were found but every signature verification failed.
    AllSctsInvalid,
    /// SCT count below the policy minimum (Chrome's policy is
    /// 1-3 SCTs depending on chain age + log diversity).
    InsufficientSctCount,
    /// CT log Merkle proof fetch failed (log down, network
    /// outage). Per spec edge case: graceful soft-fail with a
    /// warning regardless of mode — but Strict still hard-rejects
    /// because we cannot prove the chain is in a public log.
    LogUnavailable,
    /// Pre-cert SCT signed something that does not chain to the
    /// final cert. Per spec edge case.
    PrecertSctMismatch,
    /// SCT was issued by a log not in the trusted set. Likely a
    /// new log we haven't picked up yet (Module 67 lag) or a
    /// distrusted log.
    UnknownLog,
}

impl fmt::Display for CtFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L27: opaque labels only; never echo cert / SCT bytes.
        let label = match self {
            Self::NoSctsFound => "ct: no scts found",
            Self::AllSctsInvalid => "ct: all scts invalid",
            Self::InsufficientSctCount => "ct: insufficient sct count",
            Self::LogUnavailable => "ct: log unavailable",
            Self::PrecertSctMismatch => "ct: precert / final cert mismatch",
            Self::UnknownLog => "ct: sct from unknown log",
        };
        f.write_str(label)
    }
}

// ── Decision ──────────────────────────────────────────────────────────────

/// What the policy decided to do with a verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtDecision {
    /// Allow the connection; no action required.
    Allow,
    /// Connection completes but a warning fires (Standard mode).
    /// The UI side surfaces an "offer to block" affordance with
    /// the included [`CtFailureKind`] for telemetry-safe display.
    Warn(CtFailureKind),
    /// Block the connection; the chain is rejected and the TLS
    /// handshake aborts. Caller maps this to
    /// [`crate::NetworkError::TlsCtFailed`].
    Block(CtFailureKind),
}

// ── Verifier surface ──────────────────────────────────────────────────────

/// CT verifier trait. Implementations are wired into the chain
/// validator so the rustls `ServerCertVerifier` consults them
/// after the standard chain walk completes.
///
/// Implementations MUST be `Send + Sync` so the verifier can be
/// shared across handshake tasks via `Arc<dyn CtVerifier>`.
///
/// L27: implementations MUST NOT echo certificate bytes or SCT
/// bytes in any returned error / Display surface. The discriminant
/// alone (via [`CtFailureKind`]) is the maximum information the
/// trait surfaces.
pub trait CtVerifier: Send + Sync + fmt::Debug {
    /// Evaluate `chain` (DER-encoded leaf at index 0, intermediates
    /// after) and return the verification outcome. v1 stub
    /// implementations may ignore the chain entirely and return
    /// [`CtVerificationOutcome::NotEnforced`].
    fn verify(&self, chain: &[&[u8]]) -> CtVerificationOutcome;
}

/// v1 default — never enforces CT. Returns
/// [`CtVerificationOutcome::NotEnforced`] for every chain.
/// Callers who want CT enforcement must wire a real verifier in
/// via [`ChainValidator::with_ct_verifier`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpVerifier;

impl CtVerifier for NoOpVerifier {
    fn verify(&self, _chain: &[&[u8]]) -> CtVerificationOutcome {
        CtVerificationOutcome::NotEnforced
    }
}

/// Capturing test verifier. Records every chain-byte-length the
/// caller passed in (so tests can assert that the future rustls
/// hook calls verify with the right args) and returns whatever
/// outcome the test staged.
#[derive(Debug)]
pub struct CapturingVerifier {
    staged: std::sync::Mutex<CtVerificationOutcome>,
    chain_lengths: std::sync::Mutex<Vec<Vec<usize>>>,
}

impl CapturingVerifier {
    pub fn new(staged: CtVerificationOutcome) -> Self {
        Self {
            staged: std::sync::Mutex::new(staged),
            chain_lengths: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn set_outcome(&self, outcome: CtVerificationOutcome) {
        *self.staged.lock().expect("staged lock") = outcome;
    }

    pub fn observed_calls(&self) -> Vec<Vec<usize>> {
        self.chain_lengths.lock().expect("calls lock").clone()
    }
}

impl CtVerifier for CapturingVerifier {
    fn verify(&self, chain: &[&[u8]]) -> CtVerificationOutcome {
        let lengths: Vec<usize> = chain.iter().map(|c| c.len()).collect();
        self.chain_lengths.lock().expect("calls lock").push(lengths);
        *self.staged.lock().expect("staged lock")
    }
}

/// Bundle of verifier + per-mode policy table. The orchestrator
/// (Module 80) constructs one of these at boot from the wired
/// [`CtVerifier`] impl + the locked per-mode policy snapshots and
/// hands it to [`ChainValidator::with_ct`].
#[derive(Clone)]
pub struct CtPolicyBundle {
    verifier: Arc<dyn CtVerifier>,
    standard: CtPolicy,
    strict: CtPolicy,
}

impl CtPolicyBundle {
    /// Locked-default bundle: NoOpVerifier + per-mode policy from
    /// [`CtPolicy::for_mode`].
    pub fn default_bundle() -> Self {
        Self {
            verifier: Arc::new(NoOpVerifier),
            standard: CtPolicy::for_mode(Mode::Standard),
            strict: CtPolicy::for_mode(Mode::Strict),
        }
    }

    /// Build with a custom verifier (production wiring path).
    pub fn with_verifier(verifier: Arc<dyn CtVerifier>) -> Self {
        Self {
            verifier,
            standard: CtPolicy::for_mode(Mode::Standard),
            strict: CtPolicy::for_mode(Mode::Strict),
        }
    }

    pub fn verifier(&self) -> Arc<dyn CtVerifier> {
        self.verifier.clone()
    }

    pub fn policy_for(&self, mode: Mode) -> CtPolicy {
        match mode {
            Mode::Standard => self.standard,
            Mode::Strict => self.strict,
        }
    }
}

impl fmt::Debug for CtPolicyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtPolicyBundle")
            .field("standard", &self.standard)
            .field("strict", &self.strict)
            .finish_non_exhaustive()
    }
}

impl Default for CtPolicyBundle {
    fn default() -> Self {
        Self::default_bundle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- CtPolicy::for_mode --

    #[test]
    fn standard_mode_is_warn_and_offer() {
        assert_eq!(CtPolicy::for_mode(Mode::Standard), CtPolicy::WarnAndOffer);
    }

    #[test]
    fn strict_mode_is_hard_fail() {
        assert_eq!(CtPolicy::for_mode(Mode::Strict), CtPolicy::HardFail);
    }

    // -- Decision table --

    #[test]
    fn disabled_policy_always_allows() {
        let p = CtPolicy::Disabled;
        for outcome in [
            CtVerificationOutcome::Verified,
            CtVerificationOutcome::NotEnforced,
            CtVerificationOutcome::Failed {
                reason: CtFailureKind::NoSctsFound,
            },
        ] {
            assert_eq!(p.decide(&outcome), CtDecision::Allow);
        }
    }

    #[test]
    fn not_enforced_outcome_always_allows_under_any_policy() {
        for p in [
            CtPolicy::HardFail,
            CtPolicy::WarnAndOffer,
            CtPolicy::Disabled,
        ] {
            assert_eq!(
                p.decide(&CtVerificationOutcome::NotEnforced),
                CtDecision::Allow
            );
        }
    }

    #[test]
    fn verified_outcome_always_allows() {
        for p in [
            CtPolicy::HardFail,
            CtPolicy::WarnAndOffer,
            CtPolicy::Disabled,
        ] {
            assert_eq!(
                p.decide(&CtVerificationOutcome::Verified),
                CtDecision::Allow
            );
        }
    }

    #[test]
    fn hard_fail_blocks_on_failure() {
        let p = CtPolicy::HardFail;
        let outcome = CtVerificationOutcome::Failed {
            reason: CtFailureKind::AllSctsInvalid,
        };
        assert_eq!(
            p.decide(&outcome),
            CtDecision::Block(CtFailureKind::AllSctsInvalid)
        );
    }

    #[test]
    fn warn_and_offer_warns_on_failure() {
        let p = CtPolicy::WarnAndOffer;
        let outcome = CtVerificationOutcome::Failed {
            reason: CtFailureKind::LogUnavailable,
        };
        assert_eq!(
            p.decide(&outcome),
            CtDecision::Warn(CtFailureKind::LogUnavailable)
        );
    }

    #[test]
    fn decision_carries_failure_kind() {
        // Block / Warn always include the discriminant so the
        // telemetry surface (Module 60) can break out by reason.
        let p = CtPolicy::HardFail;
        for kind in [
            CtFailureKind::NoSctsFound,
            CtFailureKind::AllSctsInvalid,
            CtFailureKind::InsufficientSctCount,
            CtFailureKind::LogUnavailable,
            CtFailureKind::PrecertSctMismatch,
            CtFailureKind::UnknownLog,
        ] {
            let d = p.decide(&CtVerificationOutcome::Failed { reason: kind });
            assert_eq!(d, CtDecision::Block(kind));
        }
    }

    // -- NoOpVerifier --

    #[test]
    fn noop_verifier_returns_not_enforced() {
        let v = NoOpVerifier;
        assert_eq!(v.verify(&[]), CtVerificationOutcome::NotEnforced);
        let chain = [&b"fake-leaf"[..], &b"fake-intermediate"[..]];
        assert_eq!(v.verify(&chain), CtVerificationOutcome::NotEnforced);
    }

    // -- CapturingVerifier --

    #[test]
    fn capturing_verifier_records_chain_lengths() {
        let v = CapturingVerifier::new(CtVerificationOutcome::Verified);
        let chain = [&b"abc"[..], &b"defghi"[..]];
        let outcome = v.verify(&chain);
        assert_eq!(outcome, CtVerificationOutcome::Verified);
        let calls = v.observed_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], vec![3, 6]);
    }

    #[test]
    fn capturing_verifier_set_outcome_replaces_staged() {
        let v = CapturingVerifier::new(CtVerificationOutcome::Verified);
        v.set_outcome(CtVerificationOutcome::Failed {
            reason: CtFailureKind::NoSctsFound,
        });
        let outcome = v.verify(&[]);
        assert!(matches!(
            outcome,
            CtVerificationOutcome::Failed {
                reason: CtFailureKind::NoSctsFound
            }
        ));
    }

    // -- CtPolicyBundle --

    #[test]
    fn default_bundle_uses_noop_and_locked_policies() {
        let b = CtPolicyBundle::default();
        assert_eq!(b.policy_for(Mode::Standard), CtPolicy::WarnAndOffer);
        assert_eq!(b.policy_for(Mode::Strict), CtPolicy::HardFail);
        // Verifier is NoOp -> always NotEnforced.
        let outcome = b.verifier().verify(&[]);
        assert_eq!(outcome, CtVerificationOutcome::NotEnforced);
    }

    #[test]
    fn bundle_with_verifier_holds_custom_impl() {
        let cap = Arc::new(CapturingVerifier::new(CtVerificationOutcome::Verified));
        let b = CtPolicyBundle::with_verifier(cap.clone());
        let outcome = b.verifier().verify(&[&b"x"[..]]);
        assert_eq!(outcome, CtVerificationOutcome::Verified);
        assert_eq!(cap.observed_calls().len(), 1);
    }

    // -- L27 / Display opacity --

    #[test]
    fn ct_failure_kind_display_is_opaque() {
        for (kind, expected) in [
            (CtFailureKind::NoSctsFound, "ct: no scts found"),
            (CtFailureKind::AllSctsInvalid, "ct: all scts invalid"),
            (
                CtFailureKind::InsufficientSctCount,
                "ct: insufficient sct count",
            ),
            (CtFailureKind::LogUnavailable, "ct: log unavailable"),
            (
                CtFailureKind::PrecertSctMismatch,
                "ct: precert / final cert mismatch",
            ),
            (CtFailureKind::UnknownLog, "ct: sct from unknown log"),
        ] {
            assert_eq!(format!("{kind}"), expected);
        }
    }

    // -- KNOWN_CT_LOG_NAMES --

    #[test]
    fn known_ct_log_list_is_non_empty() {
        // Cohort-locking property: when the verifier wires in,
        // the trusted log set must already be defined. v1 ships
        // the names; Module 67 ships the keys.
        assert!(!KNOWN_CT_LOG_NAMES.is_empty());
        for name in KNOWN_CT_LOG_NAMES {
            assert!(!name.is_empty());
        }
    }

    // -- Type / trait shape --

    #[test]
    fn verifier_trait_is_object_safe() {
        let _: Arc<dyn CtVerifier> = Arc::new(NoOpVerifier);
    }

    #[test]
    fn bundle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CtPolicyBundle>();
    }
}
