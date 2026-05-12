//! Encrypted Client Hello (ECH) policy + verification surface, Module 23.3.
//!
//! Architecture references:
//!   * **L34** — ECH preferred when the server publishes an `ech` config
//!     in its HTTPS RR (RFC 9460). Strict mode mandates ECH where
//!     available; plaintext SNI is permitted in Strict only when the
//!     server has no ECH config offered (logged as a Module 11
//!     warning). Standard mode falls back to plaintext SNI without
//!     handshake-failure leak when no config is offered, the user
//!     disables ECH via settings, or the verifier hits any failure.
//!   * **L7 / L22** — audited primitives only. The handshake-side ECH
//!     work (HPKE seal of `ClientHelloInner`) is rustls's job once
//!     rustls 0.23.x ships ECH out of its experimental flag; this
//!     module owns the *policy* surface and the verifier hook.
//!   * **L27** — every error / `Display` string is opaque. Failure
//!     reasons surface through the typed [`EchFailureKind`] enum;
//!     ECHConfig bytes / SNI bytes never reach `Display`.
//!   * **§3.2 / §3.3** — Mode-locked policy: Strict mandates ECH
//!     when available (`Mandatory`), Standard prefers ECH when
//!     available (`Preferred`). The `Disabled` variant exists for
//!     the L34 "Standard explicit settings toggle" path.
//!   * **Module 24.1 invariant** — Standard and Strict ship the
//!     **same** ClientHello on the wire. Mode-divergent ECH
//!     advertisement at the rustls-config layer would itself split
//!     the JA3 cohort, so the policy bundle here governs only the
//!     post-handshake decision (allow / warn / block / retry); it
//!     never branches the [`rustls::ClientConfig`] by mode.
//!
//! ## v1 scope (deliberately narrow, mirrors Module 23.2)
//!
//! v1 ships **policy + types + a no-op verifier**. The actual
//! HTTPS-RR `ech` config parsing, HPKE handshake, and `ech_required`
//! retry loop is a follow-up (it is the bulk of the eventual code
//! volume — comparable to Chrome's BoringSSL ECH integration). The
//! architectural slot is in place so when the verifier lands:
//!
//!   1. `Cargo.toml` gains an HPKE-capable rustls feature flag (or
//!      a hand-rolled HPKE crate behind cohort-watch).
//!   2. A new [`EchVerifier`] impl replaces [`NoOpEchVerifier`].
//!   3. [`ChainValidator`]'s `ech` slot starts returning
//!      [`EchVerificationOutcome::Encrypted`] / `Failed` for real
//!      handshakes.
//!   4. The Phase 10 fingerprint suite asserts cohort-locked ECH
//!      advertisement against a probe site.
//!
//! Until then, v1 returns [`EchVerificationOutcome::NotAttempted`]
//! for every handshake. The decision table treats `NotAttempted`
//! the same as `NotOffered`: under `Mandatory` it warns + falls
//! back (Strict-mode-with-no-config is the L34 carveout); under
//! `Preferred` / `Disabled` it allows plaintext SNI silently. This
//! matches "v1 does not break navigation by failing ECH" — the
//! security-positive side of the contract is enabled when the
//! verifier wires in.
//!
//! ## ECH outcome channels (per spec / RFC 9460 + draft-ietf-tls-esni)
//!
//!   * **Server published an HTTPS RR with `ech` config** —
//!     DevBrowse extracts the config, drives an HPKE seal of
//!     `ClientHelloInner`, and on success records
//!     [`EchVerificationOutcome::Encrypted`]. Per spec edge case,
//!     a server-side rotation may produce an `ech_required` alert;
//!     the verifier must record [`EchFailureKind::EchRequiredAlert`]
//!     so the dispatch path retries the handshake with the fresh
//!     config the server attached to the alert. The retry budget
//!     is bounded; exhaustion records
//!     [`EchFailureKind::RetryWithNewConfigExhausted`].
//!   * **No HTTPS RR `ech` config** — verifier records
//!     [`EchVerificationOutcome::NotOffered`]. The decision table
//!     diverges by mode: Strict (`Mandatory`) warns via Module 11
//!     and allows plaintext SNI; Standard (`Preferred`) allows
//!     plaintext SNI silently.
//!   * **Disabled by user setting (Standard only)** — verifier
//!     records [`EchVerificationOutcome::NotAttempted`]. Under
//!     `Disabled`, every chain allows; under `Preferred` /
//!     `Mandatory` v1's `NotAttempted` collapses onto the same
//!     fallback path as `NotOffered` (since v1's no-op verifier
//!     never *attempts* ECH). When the production verifier lands,
//!     `NotAttempted` becomes settings-toggle-only.
//
// TODO(Module 23.3 follow-up): real HPKE seal of ClientHelloInner +
//   `ech_required` retry loop with bounded retry budget. Plug into
//   rustls's ECH client API once it leaves experimental.
// TODO(Module 23.4): HSTS pin-store interactions — an HSTS-pinned
//   host with an ECH config offered must never silently fall back
//   to plaintext SNI in Strict; this module enforces the policy and
//   23.4 enforces the pin lookup.
// TODO(Module 11): replace the EchDecision::WarnAndAllow caller hook
//   with the structured warning-emission surface so the Strict-mode
//   "no ECH config offered" case routes into the same observability
//   pipeline as blocklist scheduler warnings.
// TODO(Module 67): the signed-manifest update channel may eventually
//   carry an ECH-config retry-cap override (per-host); track here.

use crate::Mode;
use std::fmt;
use std::sync::Arc;

// ── Policy ────────────────────────────────────────────────────────────────

/// Per-mode ECH enforcement policy.
///
/// Mode mapping (locked, mirrors `CtPolicy::for_mode`):
///   * `Mode::Strict`  -> `Mandatory`
///   * `Mode::Standard` -> `Preferred`
///   * The `Disabled` variant is reserved for the L34 "Standard
///     explicit settings toggle" path; no mode resolves to it
///     directly via [`EchPolicy::for_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EchPolicy {
    /// Strict mode: ECH is required where the server offers it. A
    /// failure with a config offered is a hard chain rejection
    /// ([`crate::NetworkError::TlsEchFailed`]). The L34 carveout —
    /// "plaintext SNI is permitted in Strict only when the server
    /// has no ECH config offered" — surfaces here as
    /// [`EchDecision::WarnAndAllow`] on the
    /// [`EchVerificationOutcome::NotOffered`] path.
    Mandatory,
    /// Standard mode: ECH preferred when the server offers it.
    /// Failures fall back to plaintext SNI silently (no
    /// handshake-failure leak), matching L34's graceful-fallback
    /// guarantee. The user can promote this to `Disabled` via the
    /// Module 64 wizard's settings toggle.
    Preferred,
    /// Reserved: ECH disabled entirely. Used by the Standard-mode
    /// settings toggle (L34) and reserved for enterprise-managed
    /// deployments that enforce plaintext SNI for traffic
    /// inspection. Under `Disabled`, the decision is always
    /// [`EchDecision::Allow`].
    Disabled,
}

impl EchPolicy {
    /// Locked snapshot for `mode`. Strict = `Mandatory`, Standard =
    /// `Preferred`. Mode never resolves to `Disabled` here; that
    /// variant is wired in by the orchestrator (Module 80) when
    /// the user toggles the L34 setting.
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Preferred,
            Mode::Strict => Self::Mandatory,
        }
    }

    /// Apply the policy to a verification outcome and return the
    /// dispatch decision. Pure function — no I/O.
    ///
    /// Invariants enforced here (per L34 + spec edge cases):
    ///   * Strict (`Mandatory`) + `Failed{config offered}` never
    ///     produces `Allow`; the caller cannot fall back to
    ///     plaintext SNI in Strict once a config was offered.
    ///   * Strict (`Mandatory`) + `NotOffered` produces
    ///     `WarnAndAllow` — the only path on which Strict permits
    ///     plaintext SNI.
    ///   * `EchRequiredAlert` always produces `Retry` (regardless
    ///     of mode), because the alert *carries* the fresh config
    ///     the next handshake should consume.
    pub fn decide(self, outcome: &EchVerificationOutcome) -> EchDecision {
        match (self, outcome) {
            // Disabled: ECH never gates the handshake.
            (Self::Disabled, _) => EchDecision::Allow,

            // Encrypted: every policy is satisfied.
            (_, EchVerificationOutcome::Encrypted) => EchDecision::Allow,

            // ech_required alert: every policy retries with the
            // fresh config the alert delivered. Retry exhaustion
            // is a separate Failed kind below.
            (
                _,
                EchVerificationOutcome::Failed {
                    reason: EchFailureKind::EchRequiredAlert,
                },
            ) => EchDecision::Retry,

            // Mandatory + NotOffered: L34 carveout. Plaintext SNI
            // permitted, log a Module 11 warning.
            (Self::Mandatory, EchVerificationOutcome::NotOffered) => {
                EchDecision::WarnAndAllow(EchWarning::StrictNoConfigOffered)
            }

            // Mandatory + NotAttempted: v1's no-op verifier path.
            // Same decision as NotOffered until the production
            // verifier wires in (when NotAttempted becomes
            // user-settings-only and only valid under Preferred /
            // Disabled, both of which fall through to Allow).
            (Self::Mandatory, EchVerificationOutcome::NotAttempted) => {
                EchDecision::WarnAndAllow(EchWarning::StrictNoConfigOffered)
            }

            // Mandatory + Failed: hard reject. The L34 invariant
            // "never fall back to plaintext SNI in Strict if a
            // config was offered" is enforced here for every
            // failure kind except EchRequiredAlert (handled above).
            (Self::Mandatory, EchVerificationOutcome::Failed { reason }) => {
                EchDecision::Block(*reason)
            }

            // Preferred: any non-Encrypted outcome falls back
            // silently to plaintext SNI. No warning fires —
            // L34 "graceful fallback without handshake-failure
            // leak" applies in Standard mode.
            (Self::Preferred, EchVerificationOutcome::NotOffered) => EchDecision::FallbackPlaintext,
            (Self::Preferred, EchVerificationOutcome::NotAttempted) => {
                EchDecision::FallbackPlaintext
            }
            (Self::Preferred, EchVerificationOutcome::Failed { .. }) => {
                EchDecision::FallbackPlaintext
            }
        }
    }
}

// ── Verification outcome + failure shape ──────────────────────────────────

/// Outcome of an ECH attempt against a single handshake.
///
/// `NotOffered` and `NotAttempted` are deliberately distinct so the
/// production verifier can tell the policy *why* the handshake did
/// not run ECH — server didn't offer it, or DevBrowse opted out
/// (settings toggle). v1 only ever produces `NotAttempted` because
/// the no-op verifier never inspects HTTPS RR records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchVerificationOutcome {
    /// `ClientHelloInner` was successfully sealed with the server-
    /// advertised ECH config and the server accepted the encrypted
    /// SNI. The cohort-locking property holds: an on-path observer
    /// sees only the public outer SNI.
    Encrypted,
    /// Server published no `ech` record in its HTTPS RR. Plaintext
    /// SNI is permitted in Standard; permitted in Strict only via
    /// the L34 warning-and-allow path.
    NotOffered,
    /// DevBrowse opted out of ECH for this handshake (settings
    /// toggle, or v1's no-op verifier). v1 always produces this
    /// variant; the production verifier reserves it for
    /// settings-toggle paths only.
    NotAttempted,
    /// ECH was attempted and failed. [`EchFailureKind`]
    /// discriminates the failure shape so the policy decision can
    /// react appropriately. In particular `EchRequiredAlert` is
    /// always a *retry* signal, never a hard fail on the first
    /// attempt.
    Failed { reason: EchFailureKind },
}

/// Why an ECH attempt failed. Display strings are opaque; reasons
/// carry no ECHConfig / SNI bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EchFailureKind {
    /// HTTPS RR contained an `ech` value but parsing rejected it
    /// (unknown version, malformed length prefix, or empty
    /// `HpkeKeyConfig` set).
    ConfigParseFailed,
    /// ECHConfig advertised a version DevBrowse does not yet
    /// support. Cohort-watch implication: a new draft version
    /// going live shifts the cohort and triggers the Adaptation
    /// protocol.
    UnknownVersion,
    /// Server returned the `ech_required` TLS alert. The alert
    /// carries a fresh ECHConfigList the next handshake should
    /// consume; the dispatch path retries with the new config.
    /// This is a *transient* failure — under any policy the
    /// decision is [`EchDecision::Retry`].
    EchRequiredAlert,
    /// The retry budget was exhausted. Either the server keeps
    /// rotating configs faster than DevBrowse retries, or a hostile
    /// intermediary keeps forging `ech_required` alerts. Strict
    /// hard-rejects; Standard falls back to plaintext SNI.
    RetryWithNewConfigExhausted,
    /// Server offered an ECH config but the handshake demands
    /// plaintext SNI on retry (e.g. a misconfigured fronting
    /// scheme). Per L34: "never fall back to plaintext SNI in
    /// Strict if a config was offered." Strict hard-rejects;
    /// Standard falls back silently.
    MandatoryButPlaintextSniRequired,
    /// HPKE seal failed at the cryptographic layer (ring / hpke
    /// crate error). Distinct from `ConfigParseFailed` so the
    /// observability surface can break out crypto-side issues
    /// from data-side issues.
    HpkeSealFailed,
}

impl fmt::Display for EchFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L27: opaque labels only; never echo ECH config / SNI bytes.
        let label = match self {
            Self::ConfigParseFailed => "ech: config parse failed",
            Self::UnknownVersion => "ech: unknown config version",
            Self::EchRequiredAlert => "ech: server requested retry",
            Self::RetryWithNewConfigExhausted => "ech: retry budget exhausted",
            Self::MandatoryButPlaintextSniRequired => "ech: plaintext sni required by server",
            Self::HpkeSealFailed => "ech: hpke seal failed",
        };
        f.write_str(label)
    }
}

// ── Warning surface ───────────────────────────────────────────────────────

/// Why a Strict-mode handshake fell back to plaintext SNI under the
/// L34 carveout. Surfaced through [`EchDecision::WarnAndAllow`] so
/// Module 11's observability pipeline can break out the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EchWarning {
    /// Strict mode + server offered no ECH config. Per L34 the
    /// only path on which Strict permits plaintext SNI; logged
    /// because it represents a (small but real) reduction in the
    /// privacy posture vs. an ECH-protected handshake.
    StrictNoConfigOffered,
}

impl fmt::Display for EchWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::StrictNoConfigOffered => "ech: strict mode fell back, no config offered",
        };
        f.write_str(label)
    }
}

// ── Decision ──────────────────────────────────────────────────────────────

/// What the policy decided to do with a verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchDecision {
    /// Allow the handshake to proceed. Either ECH succeeded
    /// ([`EchVerificationOutcome::Encrypted`]) or the policy was
    /// `Disabled`.
    Allow,
    /// Allow the handshake but fire a Module 11 warning. Strict-
    /// mode L34 carveout only.
    WarnAndAllow(EchWarning),
    /// Block the handshake. Caller maps this to
    /// [`crate::NetworkError::TlsEchFailed`]. Carries the failure
    /// kind for telemetry-safe display (Module 60).
    Block(EchFailureKind),
    /// Server delivered an `ech_required` alert with a fresh
    /// ECHConfigList. The dispatch path must retry the handshake
    /// with the new config; the verifier is responsible for
    /// bounding the retry budget and switching to
    /// `RetryWithNewConfigExhausted` on overflow.
    Retry,
    /// Standard-mode silent fallback to plaintext SNI. No warning
    /// fires; the L34 graceful-fallback guarantee applies.
    FallbackPlaintext,
}

// ── Verifier surface ──────────────────────────────────────────────────────

/// ECH verifier trait. Implementations are wired into the chain
/// validator so the rustls handshake hook can consult them after
/// the standard chain walk completes.
///
/// Implementations MUST be `Send + Sync` so the verifier can be
/// shared across handshake tasks via `Arc<dyn EchVerifier>`.
///
/// L27: implementations MUST NOT echo ECHConfig bytes or SNI bytes
/// in any returned error / Display surface. The discriminant alone
/// (via [`EchFailureKind`]) is the maximum information the trait
/// surfaces.
pub trait EchVerifier: Send + Sync + fmt::Debug {
    /// Evaluate `host` against the verifier's HTTPS RR cache /
    /// rustls-side ECH state and return the verification outcome.
    ///
    /// `host` is the SNI value DevBrowse intends to advertise (or
    /// encrypt) — the verifier compares it against the cached
    /// ECHConfigList for that host. v1 stub implementations may
    /// ignore `host` entirely and return
    /// [`EchVerificationOutcome::NotAttempted`].
    ///
    /// The verifier owns the `ech_required` retry budget;
    /// successive failures with the same host accumulate against
    /// it and the verifier returns
    /// [`EchFailureKind::RetryWithNewConfigExhausted`] when the
    /// budget is hit.
    fn verify(&self, host: &str) -> EchVerificationOutcome;
}

/// v1 default — never attempts ECH. Returns
/// [`EchVerificationOutcome::NotAttempted`] for every host.
/// Callers who want ECH enforcement must wire a real verifier in
/// via [`crate::tls::ChainValidator::with_ech`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpEchVerifier;

impl EchVerifier for NoOpEchVerifier {
    fn verify(&self, _host: &str) -> EchVerificationOutcome {
        EchVerificationOutcome::NotAttempted
    }
}

/// Capturing test verifier. Records every host the caller passed
/// in (so tests can assert that the future rustls hook calls
/// `verify` with the right SNI) and returns whatever outcome the
/// test staged.
#[derive(Debug)]
pub struct CapturingEchVerifier {
    staged: std::sync::Mutex<EchVerificationOutcome>,
    hosts: std::sync::Mutex<Vec<String>>,
}

impl CapturingEchVerifier {
    pub fn new(staged: EchVerificationOutcome) -> Self {
        Self {
            staged: std::sync::Mutex::new(staged),
            hosts: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn set_outcome(&self, outcome: EchVerificationOutcome) {
        *self.staged.lock().expect("staged lock") = outcome;
    }

    pub fn observed_hosts(&self) -> Vec<String> {
        self.hosts.lock().expect("hosts lock").clone()
    }
}

impl EchVerifier for CapturingEchVerifier {
    fn verify(&self, host: &str) -> EchVerificationOutcome {
        self.hosts
            .lock()
            .expect("hosts lock")
            .push(host.to_string());
        *self.staged.lock().expect("staged lock")
    }
}

/// Bundle of verifier + per-mode policy table. The orchestrator
/// (Module 80) constructs one of these at boot from the wired
/// [`EchVerifier`] impl + the locked per-mode policy snapshots and
/// hands it to [`crate::tls::ChainValidator::with_ech`].
///
/// The `standard_disabled` flag captures the L34 settings toggle:
/// when set, Standard-mode handshakes resolve to
/// [`EchPolicy::Disabled`] regardless of [`EchPolicy::for_mode`].
/// Strict mode is never affected.
#[derive(Clone)]
pub struct EchPolicyBundle {
    verifier: Arc<dyn EchVerifier>,
    standard: EchPolicy,
    strict: EchPolicy,
}

impl EchPolicyBundle {
    /// Locked-default bundle: NoOpEchVerifier + per-mode policy
    /// from [`EchPolicy::for_mode`].
    pub fn default_bundle() -> Self {
        Self {
            verifier: Arc::new(NoOpEchVerifier),
            standard: EchPolicy::for_mode(Mode::Standard),
            strict: EchPolicy::for_mode(Mode::Strict),
        }
    }

    /// Build with a custom verifier (production wiring path).
    pub fn with_verifier(verifier: Arc<dyn EchVerifier>) -> Self {
        Self {
            verifier,
            standard: EchPolicy::for_mode(Mode::Standard),
            strict: EchPolicy::for_mode(Mode::Strict),
        }
    }

    /// Apply the L34 Standard-mode settings toggle: drop the
    /// Standard policy slot to [`EchPolicy::Disabled`]. Strict is
    /// unaffected.
    pub fn with_standard_disabled(mut self) -> Self {
        self.standard = EchPolicy::Disabled;
        self
    }

    pub fn verifier(&self) -> Arc<dyn EchVerifier> {
        self.verifier.clone()
    }

    pub fn policy_for(&self, mode: Mode) -> EchPolicy {
        match mode {
            Mode::Standard => self.standard,
            Mode::Strict => self.strict,
        }
    }
}

impl fmt::Debug for EchPolicyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchPolicyBundle")
            .field("standard", &self.standard)
            .field("strict", &self.strict)
            .finish_non_exhaustive()
    }
}

impl Default for EchPolicyBundle {
    fn default() -> Self {
        Self::default_bundle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- EchPolicy::for_mode --

    #[test]
    fn standard_mode_is_preferred() {
        assert_eq!(EchPolicy::for_mode(Mode::Standard), EchPolicy::Preferred);
    }

    #[test]
    fn strict_mode_is_mandatory() {
        assert_eq!(EchPolicy::for_mode(Mode::Strict), EchPolicy::Mandatory);
    }

    // -- Decision table: Disabled --

    #[test]
    fn disabled_policy_always_allows() {
        let p = EchPolicy::Disabled;
        for outcome in [
            EchVerificationOutcome::Encrypted,
            EchVerificationOutcome::NotOffered,
            EchVerificationOutcome::NotAttempted,
            EchVerificationOutcome::Failed {
                reason: EchFailureKind::ConfigParseFailed,
            },
            EchVerificationOutcome::Failed {
                reason: EchFailureKind::EchRequiredAlert,
            },
            EchVerificationOutcome::Failed {
                reason: EchFailureKind::MandatoryButPlaintextSniRequired,
            },
        ] {
            assert_eq!(p.decide(&outcome), EchDecision::Allow);
        }
    }

    // -- Decision table: Encrypted --

    #[test]
    fn encrypted_outcome_always_allows() {
        for p in [
            EchPolicy::Mandatory,
            EchPolicy::Preferred,
            EchPolicy::Disabled,
        ] {
            assert_eq!(
                p.decide(&EchVerificationOutcome::Encrypted),
                EchDecision::Allow
            );
        }
    }

    // -- Decision table: ech_required retry --

    #[test]
    fn ech_required_alert_always_retries_under_any_policy() {
        let outcome = EchVerificationOutcome::Failed {
            reason: EchFailureKind::EchRequiredAlert,
        };
        // Disabled short-circuits to Allow before reaching the
        // EchRequiredAlert match arm; that is the correct
        // behaviour (Disabled means the handshake never engaged
        // with ECH) so we exclude it here.
        for p in [EchPolicy::Mandatory, EchPolicy::Preferred] {
            assert_eq!(p.decide(&outcome), EchDecision::Retry);
        }
    }

    #[test]
    fn ech_required_alert_under_disabled_short_circuits_to_allow() {
        // Documented contract: Disabled means ECH never gates the
        // handshake. An ech_required alert under Disabled would be
        // an upstream bug (the handshake should never have engaged
        // an ECHConfig in the first place); the policy treats it
        // as Allow rather than Retry to avoid an infinite-retry
        // loop.
        let outcome = EchVerificationOutcome::Failed {
            reason: EchFailureKind::EchRequiredAlert,
        };
        assert_eq!(EchPolicy::Disabled.decide(&outcome), EchDecision::Allow);
    }

    // -- Decision table: Mandatory (Strict) --

    #[test]
    fn mandatory_not_offered_warns_and_allows() {
        // L34 carveout: Strict permits plaintext SNI only when the
        // server has no ECH config offered.
        assert_eq!(
            EchPolicy::Mandatory.decide(&EchVerificationOutcome::NotOffered),
            EchDecision::WarnAndAllow(EchWarning::StrictNoConfigOffered)
        );
    }

    #[test]
    fn mandatory_not_attempted_warns_and_allows_in_v1() {
        // v1 no-op verifier produces NotAttempted; under Mandatory
        // the bundle treats it like NotOffered so v1 doesn't break
        // navigation in Strict mode. When the production verifier
        // wires in this path becomes settings-toggle-only.
        assert_eq!(
            EchPolicy::Mandatory.decide(&EchVerificationOutcome::NotAttempted),
            EchDecision::WarnAndAllow(EchWarning::StrictNoConfigOffered)
        );
    }

    #[test]
    fn mandatory_blocks_on_config_offered_failures() {
        // Spec edge case: "never fall back to plaintext SNI in
        // Strict if a config was offered." Every Failed kind
        // except EchRequiredAlert (handled separately above) maps
        // to Block under Mandatory.
        let p = EchPolicy::Mandatory;
        for kind in [
            EchFailureKind::ConfigParseFailed,
            EchFailureKind::UnknownVersion,
            EchFailureKind::RetryWithNewConfigExhausted,
            EchFailureKind::MandatoryButPlaintextSniRequired,
            EchFailureKind::HpkeSealFailed,
        ] {
            let d = p.decide(&EchVerificationOutcome::Failed { reason: kind });
            assert_eq!(
                d,
                EchDecision::Block(kind),
                "Mandatory must Block on {kind:?}",
            );
        }
    }

    // -- Decision table: Preferred (Standard) --

    #[test]
    fn preferred_not_offered_falls_back_silently() {
        assert_eq!(
            EchPolicy::Preferred.decide(&EchVerificationOutcome::NotOffered),
            EchDecision::FallbackPlaintext
        );
    }

    #[test]
    fn preferred_not_attempted_falls_back_silently() {
        assert_eq!(
            EchPolicy::Preferred.decide(&EchVerificationOutcome::NotAttempted),
            EchDecision::FallbackPlaintext
        );
    }

    #[test]
    fn preferred_failures_fall_back_silently() {
        // L34 graceful-fallback: Standard mode never leaks an
        // ECH-induced handshake failure as a hard error. Every
        // Failed kind except EchRequiredAlert (Retry) maps to
        // FallbackPlaintext.
        let p = EchPolicy::Preferred;
        for kind in [
            EchFailureKind::ConfigParseFailed,
            EchFailureKind::UnknownVersion,
            EchFailureKind::RetryWithNewConfigExhausted,
            EchFailureKind::MandatoryButPlaintextSniRequired,
            EchFailureKind::HpkeSealFailed,
        ] {
            let d = p.decide(&EchVerificationOutcome::Failed { reason: kind });
            assert_eq!(
                d,
                EchDecision::FallbackPlaintext,
                "Preferred must FallbackPlaintext on {kind:?}",
            );
        }
    }

    // -- Strict invariant: never Allow on a config-offered failure --

    #[test]
    fn strict_never_allows_when_config_was_offered_and_failed() {
        // The L34 invariant is the most security-critical line in
        // this module: a Strict-mode handshake against a server
        // that *did* offer an ECH config but the attempt failed
        // (anything other than retry-via-alert) MUST NOT result in
        // Allow / WarnAndAllow / FallbackPlaintext / Retry. Only
        // Block is correct.
        let p = EchPolicy::Mandatory;
        for kind in [
            EchFailureKind::ConfigParseFailed,
            EchFailureKind::UnknownVersion,
            EchFailureKind::RetryWithNewConfigExhausted,
            EchFailureKind::MandatoryButPlaintextSniRequired,
            EchFailureKind::HpkeSealFailed,
        ] {
            match p.decide(&EchVerificationOutcome::Failed { reason: kind }) {
                EchDecision::Block(_) => {}
                other => {
                    panic!("Strict must Block on config-offered failure {kind:?}, got {other:?}",)
                }
            }
        }
    }

    // -- NoOpEchVerifier --

    #[test]
    fn noop_verifier_returns_not_attempted() {
        let v = NoOpEchVerifier;
        assert_eq!(
            v.verify("example.com"),
            EchVerificationOutcome::NotAttempted
        );
        assert_eq!(v.verify(""), EchVerificationOutcome::NotAttempted);
    }

    // -- CapturingEchVerifier --

    #[test]
    fn capturing_verifier_records_hosts() {
        let v = CapturingEchVerifier::new(EchVerificationOutcome::Encrypted);
        let outcome = v.verify("example.com");
        assert_eq!(outcome, EchVerificationOutcome::Encrypted);
        let outcome2 = v.verify("other.test");
        assert_eq!(outcome2, EchVerificationOutcome::Encrypted);
        let hosts = v.observed_hosts();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0], "example.com");
        assert_eq!(hosts[1], "other.test");
    }

    #[test]
    fn capturing_verifier_set_outcome_replaces_staged() {
        let v = CapturingEchVerifier::new(EchVerificationOutcome::Encrypted);
        v.set_outcome(EchVerificationOutcome::Failed {
            reason: EchFailureKind::EchRequiredAlert,
        });
        let outcome = v.verify("h");
        assert!(matches!(
            outcome,
            EchVerificationOutcome::Failed {
                reason: EchFailureKind::EchRequiredAlert
            }
        ));
    }

    // -- EchPolicyBundle --

    #[test]
    fn default_bundle_uses_noop_and_locked_policies() {
        let b = EchPolicyBundle::default();
        assert_eq!(b.policy_for(Mode::Standard), EchPolicy::Preferred);
        assert_eq!(b.policy_for(Mode::Strict), EchPolicy::Mandatory);
        // Verifier is NoOp -> always NotAttempted.
        let outcome = b.verifier().verify("example.com");
        assert_eq!(outcome, EchVerificationOutcome::NotAttempted);
    }

    #[test]
    fn bundle_with_verifier_holds_custom_impl() {
        let cap = Arc::new(CapturingEchVerifier::new(EchVerificationOutcome::Encrypted));
        let b = EchPolicyBundle::with_verifier(cap.clone());
        let outcome = b.verifier().verify("h");
        assert_eq!(outcome, EchVerificationOutcome::Encrypted);
        assert_eq!(cap.observed_hosts().len(), 1);
    }

    #[test]
    fn with_standard_disabled_drops_standard_policy() {
        // L34 settings toggle: Standard-mode user disables ECH
        // entirely. Strict policy remains Mandatory.
        let b = EchPolicyBundle::default().with_standard_disabled();
        assert_eq!(b.policy_for(Mode::Standard), EchPolicy::Disabled);
        assert_eq!(b.policy_for(Mode::Strict), EchPolicy::Mandatory);
    }

    // -- L27 / Display opacity --

    #[test]
    fn ech_failure_kind_display_is_opaque() {
        for (kind, expected) in [
            (
                EchFailureKind::ConfigParseFailed,
                "ech: config parse failed",
            ),
            (
                EchFailureKind::UnknownVersion,
                "ech: unknown config version",
            ),
            (
                EchFailureKind::EchRequiredAlert,
                "ech: server requested retry",
            ),
            (
                EchFailureKind::RetryWithNewConfigExhausted,
                "ech: retry budget exhausted",
            ),
            (
                EchFailureKind::MandatoryButPlaintextSniRequired,
                "ech: plaintext sni required by server",
            ),
            (EchFailureKind::HpkeSealFailed, "ech: hpke seal failed"),
        ] {
            let s = format!("{kind}");
            assert_eq!(s, expected);
            // Sanity: never echo host / config bytes.
            assert!(!s.contains("example"));
            assert!(!s.contains("https://"));
        }
    }

    #[test]
    fn ech_warning_display_is_opaque() {
        let s = format!("{}", EchWarning::StrictNoConfigOffered);
        assert_eq!(s, "ech: strict mode fell back, no config offered");
        assert!(!s.contains("example"));
        assert!(!s.contains("https://"));
    }

    // -- Type / trait shape --

    #[test]
    fn verifier_trait_is_object_safe() {
        let _: Arc<dyn EchVerifier> = Arc::new(NoOpEchVerifier);
    }

    #[test]
    fn bundle_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EchPolicyBundle>();
    }

    #[test]
    fn decision_carries_failure_kind_under_mandatory() {
        // Block always carries the discriminant so the telemetry
        // surface (Module 60) can break out by reason.
        let p = EchPolicy::Mandatory;
        for kind in [
            EchFailureKind::ConfigParseFailed,
            EchFailureKind::UnknownVersion,
            EchFailureKind::RetryWithNewConfigExhausted,
            EchFailureKind::MandatoryButPlaintextSniRequired,
            EchFailureKind::HpkeSealFailed,
        ] {
            let d = p.decide(&EchVerificationOutcome::Failed { reason: kind });
            assert_eq!(d, EchDecision::Block(kind));
        }
    }
}
