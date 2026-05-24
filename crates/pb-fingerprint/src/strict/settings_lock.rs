//! Module 35.4 — L41 settings-lock audit + conformance.
//!
//! L41 is the "Strict-mode settings lock" invariant: no user
//! setting, no per-site permission grant, no extension can loosen
//! the Strict cohort lock on any L9 / L16 / L25 / L29 / L30 / L31
//! / L34 / L35 / L42 / L43 / L44 surface.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * A **cross-module audit list** ([`LockedInvariant`]) of every
//!     L-invariant that participates in the Strict-mode settings
//!     lock, with per-invariant pointer ([`LockOwner`]) to the
//!     module / policy type that ALREADY owns the structural
//!     enforcement.
//!   * A **small generic `for_mode<T>` helper** for FUTURE
//!     settings-consuming sites that don't have a typed policy
//!     resolver yet. The canonical L41 pattern: "Strict ignores
//!     the user setting and returns the locked value; Standard
//!     honours the setting."
//!   * **Conformance tests** that invoke each pb-fingerprint-owned
//!     `for_mode(Mode::Strict)` resolver and assert the Strict
//!     result is the locked singleton — regression coverage that
//!     catches a future change loosening any of them.
//!
//! It IS NOT:
//!   * A refactor of the existing typed resolvers
//!     ([`LetterboxPolicy::for_mode`],
//!     [`TimerQuantizationPolicy::for_mode`],
//!     [`disabled_for_mode`], [`BatteryApiPolicy::for_mode`],
//!     etc.). Each one already encodes the L41 semantics
//!     structurally; replacing them with the generic helper would
//!     be exactly the duplication the cohort-cohesion discipline
//!     forbids. The generic helper exists for sites that do NOT
//!     yet have a typed surface.
//!   * A replacement for pb-network's own L41 conformance.
//!     pb-fingerprint and pb-network are L12 sibling leaves;
//!     pb-fingerprint cannot import pb-network. The audit list
//!     names pb-network policies (`HeaderPolicy`, `WebRtcPolicy`,
//!     `EchPolicy`) as documentation; pb-network ships its own
//!     conformance tests for those policies.
//!
//! Architecture references:
//!   * **L41** — Strict-mode settings lock. This module IS the
//!     cross-module audit.
//!   * **§3.1** — Mode locked at IdentityProfile creation;
//!     switching modes is teardown + respawn, not a config-time
//!     toggle. The L41 lock holds even if the persisted config
//!     would suggest a loosening (the lock is at read-time AND
//!     at write-time per the phase-file edge case).
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire every libxul-side
//   settings read through the typed for_mode resolvers in the
//   audit list. Where a new settings-consuming site lacks a
//   typed resolver, route it through this module's generic
//   `for_mode<T>` helper. Module 35.4's audit list is the
//   bridge's ground truth for which L-invariants are locked.
// TODO(Phase 8 / Module 64 first-launch wizard): wizard reads
//   pb-config to apply user opt-ins. Each opt-in that touches an
//   L-invariant in `LockedInvariant::ALL` MUST short-circuit on
//   Mode::Strict — either via the existing typed resolver, or
//   via this module's `for_mode<T>` helper. The wizard SHOULD
//   reject (not just ignore) a write that would loosen a Strict
//   lock so the persisted config never suggests a loosened
//   Strict posture (phase-file edge case).
// TODO(Phase 8 / Module 59 permission center): Module 59's
//   per-site grants MUST NOT re-enable any L44 API in Strict
//   (Module 35.3 already structurally enforces this — Strict's
//   `disabled_for_mode` does not consult Module 59 — but the
//   audit cross-couples here so a future Module 59 wiring path
//   that ignores the structural lock is caught).
// TODO(Phase 10 / Module 71+): adversarial-fingerprint tests
//   toggle every loosening setting in a Strict tab and assert
//   zero observable effect on the cohort surface. Module 35.4's
//   audit list is the ground truth Phase 10 iterates.
// TODO(pb-extensions Module 41): extension settings reads for
//   the curated allowlist + manifest signing — Strict blocks all
//   extensions regardless of settings (the Extensions allowlist
//   memory lock); audit cross-coupling test lives in pb-extensions.
// TODO(pb-network L25 / L30 / L31 / L34 / L35 audit): pb-network's
//   own L41 conformance tests cover HeaderPolicy / WebRtcPolicy /
//   EchPolicy / CtPolicy / FallbackPolicy. Module 35.4 lists them
//   in the audit by name; pb-network's tests run alongside the
//   pb-fingerprint conformance tests here at workspace test time.

use pb_config::Mode;

// ── Generic L41 helper for sites without a typed resolver ─────────────

/// Generic L41 settings-lock helper.
///
/// Returns `locked` when `mode == Mode::Strict`, otherwise
/// `user_setting`. Use this at a settings-consuming site that
/// does NOT have a dedicated typed policy resolver — every
/// existing Phase 5 / Phase 4 module already has a typed
/// `for_mode` (see [`LockedInvariant::owner`] for the mapping)
/// and should NOT be refactored to use this helper. Two sources
/// of truth for the same per-Mode lock is the cohort-drift
/// surface the Adaptation protocol exists to prevent.
///
/// The helper is move-by-value over `T`; callers pass `Copy`
/// types (numbers, enum variants, `&'static` references) for
/// zero-cost dispatch. For larger settings, prefer constructing
/// a typed policy enum mirroring the per-module pattern.
///
/// **L41 invariant under composition:** for any `T`, `for_mode(
/// Mode::Strict, user_setting, locked) == locked` independent of
/// `user_setting`. The Strict branch never depends on the user
/// input. This is the structural property all existing typed
/// resolvers also satisfy.
pub fn for_mode<T>(mode: Mode, user_setting: T, locked: T) -> T {
    match mode {
        Mode::Standard => user_setting,
        Mode::Strict => locked,
    }
}

// ── Audit enumeration ────────────────────────────────────────────────

/// Every L-invariant participating in the Strict-mode settings
/// lock.
///
/// Each variant carries a pointer ([`LockOwner`]) to the module
/// / policy that ALREADY owns the structural enforcement.
/// Module 35.4 does NOT duplicate the per-module enforcement;
/// the audit is the cross-module index, the conformance tests
/// pin the existing enforcement against regression.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockedInvariant {
    /// **L9** — Identity-grouped process model; Mode is locked
    /// at `IdentityProfile` creation. Switching modes is
    /// teardown + respawn (§3.1), not a config toggle.
    L9ProcessModel,
    /// **L16** — DevTools blocked entirely in Strict.
    L16DevTools,
    /// **L25** — DoH whitelist (Quad9 / NextDNS / Cloudflare /
    /// custom HTTPS); system-DNS fallback Standard-only.
    L25DohWhitelist,
    /// **L29** — History retention (Strict never writes history).
    L29HistoryRetention,
    /// **L30** — HTTPS-Only mode; Strict disallows downgrade
    /// entirely.
    L30HttpsOnlyDowngrade,
    /// **L31** — Referer policy
    /// (`strict-origin-when-cross-origin` Standard /
    /// `no-referrer` Strict).
    L31RefererPolicy,
    /// **L34** — Encrypted Client Hello (preferred Standard,
    /// mandatory Strict when offered).
    L34Ech,
    /// **L35** — WebRTC (per-site permission Standard, fully
    /// disabled Strict).
    L35WebRtc,
    /// **L42** — Window dimension letterboxing (200 × 100 grid
    /// in Strict).
    L42WindowLetterbox,
    /// **L43** — Timer quantization (1 ms Standard, 100 ms Strict
    /// JS; mode-invariant 2 ms GPU via pb-gpu).
    L43TimerQuantum,
    /// **L44** — Disabled-by-default API surface in Strict (16
    /// owned families + Battery delegated to Module 31 + WebRTC
    /// delegated to Module 25).
    L44DisabledApis,
}

impl LockedInvariant {
    /// Every L41-participating L-invariant.
    pub const ALL: &'static [LockedInvariant] = &[
        Self::L9ProcessModel,
        Self::L16DevTools,
        Self::L25DohWhitelist,
        Self::L29HistoryRetention,
        Self::L30HttpsOnlyDowngrade,
        Self::L31RefererPolicy,
        Self::L34Ech,
        Self::L35WebRtc,
        Self::L42WindowLetterbox,
        Self::L43TimerQuantum,
        Self::L44DisabledApis,
    ];

    /// The architecture L-number (e.g. `"L42"`).
    pub const fn l_number(self) -> &'static str {
        match self {
            Self::L9ProcessModel => "L9",
            Self::L16DevTools => "L16",
            Self::L25DohWhitelist => "L25",
            Self::L29HistoryRetention => "L29",
            Self::L30HttpsOnlyDowngrade => "L30",
            Self::L31RefererPolicy => "L31",
            Self::L34Ech => "L34",
            Self::L35WebRtc => "L35",
            Self::L42WindowLetterbox => "L42",
            Self::L43TimerQuantum => "L43",
            Self::L44DisabledApis => "L44",
        }
    }

    /// The module / policy that owns the structural enforcement
    /// for this invariant.
    pub const fn owner(self) -> LockOwner {
        match self {
            Self::L9ProcessModel => LockOwner::IdentityProfileMode,
            Self::L16DevTools => LockOwner::PendingPhase8 {
                module: "pb-ui DevTools gate (Phase 8)",
            },
            Self::L25DohWhitelist => LockOwner::PbNetworkPolicy {
                policy: "pb_network::doh::FallbackPolicy",
                module: "pb-network Module 20",
            },
            Self::L29HistoryRetention => LockOwner::PendingPhase8 {
                module: "pb-storage history retention gate (Phase 8 UI)",
            },
            Self::L30HttpsOnlyDowngrade => LockOwner::PbNetworkPolicy {
                policy: "pb_network::coordinator HTTPS-Only enforcement",
                module: "pb-network Module 19",
            },
            Self::L31RefererPolicy => LockOwner::PbNetworkPolicy {
                policy: "pb_network::headers::HeaderPolicy",
                module: "pb-network Module 22",
            },
            Self::L34Ech => LockOwner::PbNetworkPolicy {
                policy: "pb_network::tls::ech::EchPolicy",
                module: "pb-network Module 23.3",
            },
            Self::L35WebRtc => LockOwner::PbNetworkPolicy {
                policy: "pb_network::webrtc::WebRtcPolicy",
                module: "pb-network Module 25",
            },
            Self::L42WindowLetterbox => LockOwner::PbFingerprintPolicy {
                policy: "pb_fingerprint::strict::letterbox::LetterboxPolicy",
                module: "Module 35.1",
            },
            Self::L43TimerQuantum => LockOwner::PbFingerprintPolicy {
                policy: "pb_fingerprint::gecko::timers::TimerQuantizationPolicy",
                module: "Module 32 + Module 35.2",
            },
            Self::L44DisabledApis => LockOwner::PbFingerprintPolicy {
                policy: "pb_fingerprint::strict::disabled_apis::disabled_for_mode + gecko::battery::BatteryApiPolicy",
                module: "Module 35.3 + Module 31",
            },
        }
    }
}

/// Who owns the structural enforcement of a [`LockedInvariant`].
///
/// Distinct variants for pb-fingerprint vs pb-network because
/// the two crates are L12 sibling leaves: pb-fingerprint cannot
/// import pb-network, so cross-crate conformance is handled by
/// the owning crate's own tests. Module 35.4's conformance tests
/// run only against [`LockOwner::PbFingerprintPolicy`] +
/// [`LockOwner::IdentityProfileMode`] in-crate; pb-network
/// owners are documented here for audit completeness.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LockOwner {
    /// Mode is locked at IdentityProfile creation (`pb-identity`
    /// Module 6); no runtime resolver exists because there is no
    /// setting to override.
    IdentityProfileMode,
    /// A pb-fingerprint policy type with a `for_mode(Mode)`
    /// resolver. Module 35.4's conformance tests invoke this in
    /// the same crate.
    PbFingerprintPolicy {
        /// Fully-qualified policy path for audit / grep.
        policy: &'static str,
        /// Owning module identifier (e.g. `"Module 35.1"`).
        module: &'static str,
    },
    /// A pb-network policy type with a `for_mode(Mode)` resolver.
    /// Documented here for audit completeness; conformance is
    /// verified by pb-network's own tests (L12 sibling-leaf
    /// dependency rule prevents direct cross-crate invocation).
    PbNetworkPolicy {
        policy: &'static str,
        module: &'static str,
    },
    /// Phase 8+ UI surface not yet built; tracked here so the
    /// audit list stays complete and a future implementation has
    /// the L-invariant pointer ready.
    PendingPhase8 { module: &'static str },
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gecko::battery::BatteryApiPolicy;
    use crate::gecko::timers::{TimerQuantizationPolicy, STRICT_TIMER_PROFILE};
    use crate::strict::disabled_apis::{disabled_for_mode, DisabledApi};
    use crate::strict::letterbox::{LetterboxPolicy, STRICT_LETTERBOX};

    // ── Generic helper ───────────────────────────────────────────────

    #[test]
    fn for_mode_strict_always_returns_locked_value() {
        // L41 invariant under composition: Strict ignores the
        // user input.
        assert!(!for_mode(Mode::Strict, true, false));
        assert_eq!(for_mode(Mode::Strict, "user", "locked"), "locked");
        assert_eq!(for_mode(Mode::Strict, 1_u32, 100), 100);
    }

    #[test]
    fn for_mode_standard_returns_user_setting() {
        assert!(for_mode(Mode::Standard, true, false));
        assert_eq!(for_mode(Mode::Standard, "user", "locked"), "user");
        assert_eq!(for_mode(Mode::Standard, 1_u32, 100), 1);
    }

    #[test]
    fn for_mode_strict_is_idempotent_and_user_input_independent() {
        // L41 lock under property sweep: for many user inputs,
        // Strict result equals the locked value.
        for user in [0_u32, 1, 100, 999, u32::MAX] {
            assert_eq!(for_mode(Mode::Strict, user, 42), 42);
        }
    }

    // ── Audit list ───────────────────────────────────────────────────

    #[test]
    fn all_covers_eleven_l41_participating_invariants() {
        // Phase-file Module 35.4 enumerates L9 / L16 / L25 / L29 /
        // L30 / L31 / L34 / L35 / L42 / L43 / L44 = 11 invariants.
        assert_eq!(LockedInvariant::ALL.len(), 11);
    }

    #[test]
    fn every_audit_variant_has_unique_l_number() {
        // Sanity: no two variants share an L-number (would
        // suggest an enum bug).
        let mut seen = std::collections::HashSet::new();
        for v in LockedInvariant::ALL {
            let n = v.l_number();
            assert!(seen.insert(n), "duplicate L-number: {}", n);
        }
        assert_eq!(seen.len(), 11);
    }

    #[test]
    fn every_audit_variant_has_a_defined_owner() {
        // No `PendingPhase8` slot can be silently dropped on the
        // floor — explicit doc string required so the future
        // Phase 8 implementer knows what to wire.
        for v in LockedInvariant::ALL {
            match v.owner() {
                LockOwner::IdentityProfileMode => {}
                LockOwner::PbFingerprintPolicy { policy, module } => {
                    assert!(!policy.is_empty(), "{:?} has empty policy path", v);
                    assert!(!module.is_empty(), "{:?} has empty module label", v);
                }
                LockOwner::PbNetworkPolicy { policy, module } => {
                    assert!(!policy.is_empty(), "{:?} has empty policy path", v);
                    assert!(!module.is_empty(), "{:?} has empty module label", v);
                }
                LockOwner::PendingPhase8 { module } => {
                    assert!(!module.is_empty(), "{:?} has empty pending label", v);
                }
            }
        }
    }

    #[test]
    fn audit_dispatch_is_exhaustive_friendly() {
        // Adding a LockedInvariant variant without updating this
        // match (and the bridge / audit list) is a silent gap in
        // L41 coverage. The match has no `_` arm — compile fail
        // catches the omission.
        fn route(v: LockedInvariant) -> &'static str {
            match v {
                LockedInvariant::L9ProcessModel => "L9",
                LockedInvariant::L16DevTools => "L16",
                LockedInvariant::L25DohWhitelist => "L25",
                LockedInvariant::L29HistoryRetention => "L29",
                LockedInvariant::L30HttpsOnlyDowngrade => "L30",
                LockedInvariant::L31RefererPolicy => "L31",
                LockedInvariant::L34Ech => "L34",
                LockedInvariant::L35WebRtc => "L35",
                LockedInvariant::L42WindowLetterbox => "L42",
                LockedInvariant::L43TimerQuantum => "L43",
                LockedInvariant::L44DisabledApis => "L44",
            }
        }
        for v in LockedInvariant::ALL {
            assert_eq!(route(*v), v.l_number());
        }
    }

    // ── In-crate conformance: pb-fingerprint-owned resolvers ─────────

    #[test]
    fn l42_letterbox_for_mode_strict_returns_locked_grid() {
        // Module 35.1 conformance — Strict resolves to
        // Quantize(&STRICT_LETTERBOX); two resolutions are
        // identical.
        let a = LetterboxPolicy::for_mode(Mode::Strict);
        let b = LetterboxPolicy::for_mode(Mode::Strict);
        assert_eq!(a, b);
        match a {
            LetterboxPolicy::Quantize(lb) => {
                assert!(std::ptr::eq(lb, &STRICT_LETTERBOX));
            }
            other => panic!("expected Quantize, got {:?}", other),
        }
    }

    #[test]
    fn l43_timer_for_mode_strict_returns_locked_100ms_profile() {
        // Module 32 + Module 35.2 conformance — Strict resolves
        // to Quantized(&STRICT_TIMER_PROFILE) with 100 ms quantum.
        let p = TimerQuantizationPolicy::for_mode(Mode::Strict);
        assert!(std::ptr::eq(p.profile(), &STRICT_TIMER_PROFILE));
        assert_eq!(p.profile().js_quantum_ns, 100_000_000);
    }

    #[test]
    fn l44_disabled_apis_for_mode_strict_returns_locked_list() {
        // Module 35.3 conformance — Strict resolves to the
        // 16-variant DisabledApi::ALL list; Standard resolves to
        // the empty slice.
        let strict = disabled_for_mode(Mode::Strict);
        let standard = disabled_for_mode(Mode::Standard);
        assert_eq!(strict, DisabledApi::ALL);
        assert_eq!(standard.len(), 0);
    }

    #[test]
    fn l44_battery_for_mode_is_mode_invariant_removed() {
        // Module 31 conformance — Battery is mode-invariant
        // Removed (the delegation Module 35.3 relies on).
        assert_eq!(
            BatteryApiPolicy::for_mode(Mode::Strict),
            BatteryApiPolicy::Removed,
        );
        assert_eq!(
            BatteryApiPolicy::for_mode(Mode::Standard),
            BatteryApiPolicy::Removed,
        );
    }

    #[test]
    fn pb_fingerprint_resolvers_are_idempotent_under_strict() {
        // Sweep: every pb-fingerprint-owned for_mode resolver
        // listed in the audit returns the same value on repeated
        // Strict invocations. (Sanity for the L41 idempotence
        // property — a future change to ANY resolver that
        // introduces hidden state breaks this test.)
        assert_eq!(
            LetterboxPolicy::for_mode(Mode::Strict),
            LetterboxPolicy::for_mode(Mode::Strict),
        );
        assert_eq!(
            TimerQuantizationPolicy::for_mode(Mode::Strict),
            TimerQuantizationPolicy::for_mode(Mode::Strict),
        );
        assert_eq!(
            disabled_for_mode(Mode::Strict),
            disabled_for_mode(Mode::Strict),
        );
        assert_eq!(
            BatteryApiPolicy::for_mode(Mode::Strict),
            BatteryApiPolicy::for_mode(Mode::Strict),
        );
    }

    #[test]
    fn audit_lists_pb_fingerprint_owners_for_l42_l43_l44() {
        // The three pb-fingerprint-owned L-invariants have
        // PbFingerprintPolicy ownership in the audit list. A
        // regression here would mean the audit drifted from the
        // actual code ownership.
        for v in [
            LockedInvariant::L42WindowLetterbox,
            LockedInvariant::L43TimerQuantum,
            LockedInvariant::L44DisabledApis,
        ] {
            match v.owner() {
                LockOwner::PbFingerprintPolicy { .. } => {}
                other => panic!(
                    "{:?} expected PbFingerprintPolicy ownership, got {:?}",
                    v, other,
                ),
            }
        }
    }

    #[test]
    fn audit_lists_pb_network_owners_for_l25_l30_l31_l34_l35() {
        // pb-network owns these 5; conformance is verified by
        // pb-network's own tests (L12 dependency rule).
        for v in [
            LockedInvariant::L25DohWhitelist,
            LockedInvariant::L30HttpsOnlyDowngrade,
            LockedInvariant::L31RefererPolicy,
            LockedInvariant::L34Ech,
            LockedInvariant::L35WebRtc,
        ] {
            match v.owner() {
                LockOwner::PbNetworkPolicy { .. } => {}
                other => panic!(
                    "{:?} expected PbNetworkPolicy ownership, got {:?}",
                    v, other,
                ),
            }
        }
    }

    #[test]
    fn audit_marks_phase_8_pending_for_l16_l29() {
        // DevTools (L16) and history-retention (L29) wait on
        // Phase 8 UI; the audit slot is reserved.
        for v in [
            LockedInvariant::L16DevTools,
            LockedInvariant::L29HistoryRetention,
        ] {
            match v.owner() {
                LockOwner::PendingPhase8 { .. } => {}
                other => panic!("{:?} expected PendingPhase8 ownership, got {:?}", v, other,),
            }
        }
    }

    #[test]
    fn settings_lock_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LockedInvariant>();
        assert_send_sync::<LockOwner>();
    }
}
