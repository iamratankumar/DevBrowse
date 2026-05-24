//! Module 35.9 (part 2) — Storage estimate cohort lock.
//!
//! Locks `navigator.storage.estimate()` so the per-host disk size
//! and per-origin actual usage do not leak. Tor returns
//! `{quota: 0, usage: 0}` (achieving cohort cohesion at the cost of
//! breaking quota-aware sites); DevBrowse Strict matches Tor's
//! `{0, 0}` posture, while Standard pins a `{1 GiB, 0}` cohort so
//! quota-aware sites have a useful answer that is identical across
//! every Standard DevBrowse user.
//!
//! ## Mode-applicability (locked v1.23)
//!
//!   * **Strict** — `Locked(&STRICT_STORAGE_ESTIMATE)`:
//!     `{quota: 0, usage: 0}`. Tor parity. Sites that need
//!     storage discover quota-exceeded errors at write time, not
//!     from `estimate()`. The `{0, 0}` cohort eliminates both the
//!     disk-size signal (no per-host variation) and the per-origin
//!     usage signal (no probe of own state).
//!   * **Standard** — `Locked(&STANDARD_STORAGE_ESTIMATE)`:
//!     `{quota: 1_073_741_824 (1 GiB), usage: 0}`. Every Standard
//!     DevBrowse user reports the same 1 GiB ceiling regardless
//!     of host disk capacity. The actual storage broker (Module
//!     14 / pb-storage) returns quota-exceeded errors at write
//!     time when real-disk pressure hits; `estimate()` is decoupled
//!     from the broker's per-origin accounting so sites cannot
//!     probe their own real usage through this surface.
//!
//! ## Architecture references
//!
//!   * **L8** — Gecko WebIDL override; `navigator.storage.estimate()`
//!     is patched below the JS surface so workers / iframes /
//!     service workers all see the same answer.
//!   * **L9 / §3.2 / §3.3** — per-Mode normalization. The policy
//!     is single-variant (`Locked`) and resolves to different
//!     statics per mode (the convention shared with Module 31
//!     Battery's `BatteryApiPolicy::Removed` mode-invariant shape,
//!     except here the policy IS mode-aware via static selection).
//!   * **L33** — partition-key gating: the actual per-origin usage
//!     accounting lives in pb-storage (Module 14) which keys
//!     storage on `(origin, identity_profile_id)`. Module 35.9
//!     does NOT consult pb-storage's accounting; the `{quota,
//!     usage}` answer is cohort-locked. Sites that need a real
//!     usage signal must surface it through a separate per-site
//!     UX (Module 59 / Phase 8).
//!   * **L41** — Strict's `{0, 0}` is non-loosenable; Standard's
//!     1 GiB is non-loosenable. Module 35.4 settings-lock audit
//!     re-asserts.
//!   * **§5.5** — central fingerprint surface bucketing.
//!   * **threat-model A1** — disk size + per-origin usage are
//!     classical passive fingerprint surfaces (CreepJS / FPStandard
//!     storage probes); the cohort lock closes both.
//!
//! ## Edge cases (phase-file lock)
//!
//!   * **Sites with actual large data** still get the cohort
//!     1 GiB quota answer; quota-exceeded errors are surfaced at
//!     write time by pb-storage, not predictable from `estimate()`.
//!   * **PWAs probing quota before install** get the cohort 1 GiB
//!     answer; PWAs requiring larger quota fall back to a runtime
//!     quota-grant prompt routed through Module 59 (Phase 8).
//!   * **`navigator.storage.persist()` / `persisted()`** — out of
//!     scope for Module 35.9. The W3C IDL exposes these but they
//!     return per-origin persistent-storage state which is a
//!     separate fingerprint surface; the phase file scopes 35.9
//!     to `estimate()` only. A future module (or 35.9 extension)
//!     covers persist / persisted with a cohort-locked `false`
//!     answer.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire
//   `StorageManager.estimate()` to resolve a Promise populated
//   from `StorageEstimatePolicy::for_mode(ctx.mode())`'s referenced
//   profile. Worker / SharedWorker / ServiceWorker
//   `navigator.storage` surfaces get the same treatment for every
//   `JsContext::ALL` variant.
// TODO(persist / persisted coverage, future): the W3C
//   StorageManager IDL exposes `persist()` and `persisted()` which
//   reveal whether the origin's storage is "persistent" (not
//   eligible for eviction). Phase file scopes Module 35.9 to
//   `estimate()` only; a future module locks the persist surface
//   to a cohort-locked `false` answer. Owner unclaimed.
// TODO(Phase 10 / Module 71+): adversarial probes assert (a)
//   Strict observes `{quota: 0, usage: 0}` in every renderer
//   regardless of host disk size; (b) Standard observes
//   `{quota: 1 GiB, usage: 0}` regardless of actual per-origin
//   usage; (c) the answer is identical across Worker / iframe /
//   service-worker scopes.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Storage estimate profile ─────────────────────────────────────────────

/// One cohort snapshot of `StorageManager.estimate()`. Maps 1:1 to
/// the W3C [`StorageEstimate`] IDL fields read by sites.
///
/// `Copy` is intentional — the libxul bridge reads it on every
/// `estimate()` invocation; never a handle.
///
/// [`StorageEstimate`]: https://storage.spec.whatwg.org/#storage-estimate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StorageEstimateProfile {
    /// `StorageEstimate.quota` — total bytes the origin is allowed
    /// to consume. Cohort-locked per mode (0 Strict; 1 GiB
    /// Standard); does NOT reflect host disk capacity.
    pub quota_bytes: u64,
    /// `StorageEstimate.usage` — bytes the origin currently
    /// consumes. Cohort-locked to 0 in both modes; does NOT
    /// reflect actual per-origin usage (which lives in pb-storage
    /// Module 14 behind the partition-key boundary).
    pub usage_bytes: u64,
}

// ── Locked profiles ──────────────────────────────────────────────────────

/// Strict cohort: `{quota: 0, usage: 0}` (Tor parity).
///
/// Sites that need storage discover quota-exceeded errors at write
/// time, not from `estimate()`. The `{0, 0}` cohort eliminates
/// both the disk-size signal and the per-origin usage signal —
/// no per-host or per-origin variation reaches content JS.
pub static STRICT_STORAGE_ESTIMATE: StorageEstimateProfile = StorageEstimateProfile {
    quota_bytes: 0,
    usage_bytes: 0,
};

/// Standard cohort: `{quota: 1 GiB, usage: 0}`.
///
/// Every Standard DevBrowse user reports the same 1 GiB ceiling
/// regardless of host disk capacity. The actual storage broker
/// (Module 14 / pb-storage) returns quota-exceeded errors at
/// write time when real disk pressure hits; `estimate()` is
/// decoupled from the broker's per-origin accounting.
///
/// 1 GiB = 2^30 bytes = 1_073_741_824. Chosen because:
///   * Large enough to satisfy typical site needs (PWAs / IndexedDB
///     applications) without immediately tripping quota errors.
///   * Round power-of-two so the value itself is cohort-unique
///     (no per-host disk-derivation can produce this exact number).
///   * Matches the Brave-style "fixed-quota cohort" approach
///     without inheriting Brave's per-session reshuffle.
pub static STANDARD_STORAGE_ESTIMATE: StorageEstimateProfile = StorageEstimateProfile {
    quota_bytes: 1_073_741_824,
    usage_bytes: 0,
};

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode policy for `navigator.storage.estimate()`.
///
/// Single-variant enum (`Locked(&profile)`) — the mode-dispatch
/// happens at construction time via static selection, mirroring
/// the Module 35.6 `WebGpuReadbackPolicy` and the Module 35.7
/// `MediaCapabilitiesPolicy::Locked` shape. The variant is
/// `#[non_exhaustive]` so a future per-Mode carve-out (e.g.
/// Phase-12 mobile lower-quota cohort) is a second variant, not
/// a mutation of the existing one.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageEstimatePolicy {
    /// Both modes go through the same enum variant; the referenced
    /// profile differs per mode.
    Locked(&'static StorageEstimateProfile),
}

impl StorageEstimatePolicy {
    /// Locked snapshot for `mode`:
    ///   * `Mode::Standard` -> `Locked(&STANDARD_STORAGE_ESTIMATE)`
    ///   * `Mode::Strict`   -> `Locked(&STRICT_STORAGE_ESTIMATE)`
    ///
    /// Both variants reference static profiles by address;
    /// the libxul bridge can compare references without value
    /// re-derivation.
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Locked(&STANDARD_STORAGE_ESTIMATE),
            Mode::Strict => Self::Locked(&STRICT_STORAGE_ESTIMATE),
        }
    }

    /// Returns the static profile this policy references.
    pub fn profile(&self) -> &'static StorageEstimateProfile {
        match self {
            Self::Locked(p) => p,
        }
    }
}

// ── Surface enumeration ──────────────────────────────────────────────────

/// Every JS pathway through which `navigator.storage` estimate
/// surfaces.
///
/// **Scope**: Module 35.9 covers `estimate()` only per the
/// phase-file lock. `persist()` and `persisted()` are documented
/// as out-of-scope in the module-level doc; a future module will
/// add them.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageEstimateSurface {
    /// `navigator.storage.estimate()` — Promise<StorageEstimate>
    /// resolved from the locked profile's `quota_bytes` /
    /// `usage_bytes`.
    Estimate,
}

impl StorageEstimateSurface {
    pub const ALL: &'static [StorageEstimateSurface] = &[Self::Estimate];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::StorageEstimate`.
///
/// Construct with `StorageEstimateOverride::new(mode)`. The policy
/// carries the per-mode static reference; the libxul bridge reads
/// `quota_bytes` / `usage_bytes` at `estimate()` resolution time.
#[derive(Debug, Clone, Copy)]
pub struct StorageEstimateOverride {
    policy: StorageEstimatePolicy,
}

impl StorageEstimateOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: StorageEstimatePolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> StorageEstimatePolicy {
        self.policy
    }
}

impl FingerprintOverride for StorageEstimateOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::StorageEstimate
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. When the libxul FFI lands (pb-browser
        // Phase 11 / Module 80), the bridge installs a per-mode
        // `StorageManager.estimate()` handler that resolves to the
        // locked profile's `{quota, usage}` for every variant of
        // `StorageEstimateSurface::ALL` × `JsContext::ALL`.
        let _ = (self.policy, JsContext::ALL, StorageEstimateSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_matches_tor_zero_zero_posture() {
        // Phase-file Strict cohort: {quota: 0, usage: 0}.
        // Matches Tor's posture; eliminates disk-size + per-origin
        // usage signals.
        assert_eq!(STRICT_STORAGE_ESTIMATE.quota_bytes, 0);
        assert_eq!(STRICT_STORAGE_ESTIMATE.usage_bytes, 0);
    }

    #[test]
    fn standard_profile_matches_1_gib_cohort() {
        // Phase-file Standard cohort: {quota: 1 GiB, usage: 0}.
        // 1 GiB = 2^30 bytes.
        assert_eq!(STANDARD_STORAGE_ESTIMATE.quota_bytes, 1_073_741_824);
        assert_eq!(STANDARD_STORAGE_ESTIMATE.quota_bytes, 1 << 30);
        assert_eq!(STANDARD_STORAGE_ESTIMATE.usage_bytes, 0);
    }

    #[test]
    fn both_modes_report_zero_usage_for_per_origin_safety() {
        // Usage = 0 in both modes — sites cannot probe their own
        // per-origin actual storage usage through estimate().
        // The actual accounting (when needed) lives in pb-storage
        // Module 14 behind the partition-key boundary.
        assert_eq!(STRICT_STORAGE_ESTIMATE.usage_bytes, 0);
        assert_eq!(STANDARD_STORAGE_ESTIMATE.usage_bytes, 0);
    }

    #[test]
    fn strict_resolves_to_strict_static_by_address() {
        let p = StorageEstimatePolicy::for_mode(Mode::Strict);
        match p {
            StorageEstimatePolicy::Locked(profile) => {
                assert!(
                    std::ptr::eq(profile, &STRICT_STORAGE_ESTIMATE),
                    "Strict Locked must point at STRICT_STORAGE_ESTIMATE by address",
                );
            }
        }
    }

    #[test]
    fn standard_resolves_to_standard_static_by_address() {
        let p = StorageEstimatePolicy::for_mode(Mode::Standard);
        match p {
            StorageEstimatePolicy::Locked(profile) => {
                assert!(
                    std::ptr::eq(profile, &STANDARD_STORAGE_ESTIMATE),
                    "Standard Locked must point at STANDARD_STORAGE_ESTIMATE by address",
                );
            }
        }
    }

    #[test]
    fn modes_resolve_to_distinct_profiles() {
        // Strict and Standard MUST point at DIFFERENT statics. A
        // future mode-invariant collapse (e.g. returning the same
        // profile for both modes) would silently weaken the
        // Strict cohort.
        let strict = StorageEstimatePolicy::for_mode(Mode::Strict);
        let standard = StorageEstimatePolicy::for_mode(Mode::Standard);
        assert_ne!(strict.profile(), standard.profile());
        assert!(!std::ptr::eq(strict.profile(), standard.profile()));
    }

    #[test]
    fn strict_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock — no with_user_override constructor exists. Two
        // Strict resolutions return identical content; no settings
        // path can flip Strict to the Standard cohort. Module 35.4
        // settings-lock audit pins this against call sites.
        let a = StorageEstimatePolicy::for_mode(Mode::Strict);
        let b = StorageEstimatePolicy::for_mode(Mode::Strict);
        assert_eq!(a, b);
        assert_eq!(*a.profile(), STRICT_STORAGE_ESTIMATE);
    }

    #[test]
    fn standard_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock holds for Standard too: no settings path can
        // change the 1 GiB cohort value.
        let a = StorageEstimatePolicy::for_mode(Mode::Standard);
        let b = StorageEstimatePolicy::for_mode(Mode::Standard);
        assert_eq!(a, b);
        assert_eq!(*a.profile(), STANDARD_STORAGE_ESTIMATE);
    }

    #[test]
    fn storage_estimate_surface_all_covers_phase_file_scope() {
        // Module 35.9 scopes the StorageManager surface to
        // estimate() only. persist() / persisted() are out of
        // scope per the phase-file lock (documented in the
        // crate-level TODO).
        assert_eq!(StorageEstimateSurface::ALL.len(), 1);
        assert!(StorageEstimateSurface::ALL.contains(&StorageEstimateSurface::Estimate));
    }

    #[test]
    fn override_reports_storage_estimate_surface_in_both_modes() {
        assert_eq!(
            StorageEstimateOverride::new(Mode::Standard).surface(),
            WebIdlSurface::StorageEstimate,
        );
        assert_eq!(
            StorageEstimateOverride::new(Mode::Strict).surface(),
            WebIdlSurface::StorageEstimate,
        );
    }

    #[test]
    fn override_carries_per_mode_policy() {
        let standard = StorageEstimateOverride::new(Mode::Standard);
        let strict = StorageEstimateOverride::new(Mode::Strict);
        assert_ne!(standard.policy(), strict.policy());
        assert_eq!(standard.policy().profile(), &STANDARD_STORAGE_ESTIMATE);
        assert_eq!(strict.policy().profile(), &STRICT_STORAGE_ESTIMATE);
    }

    #[test]
    fn override_install_is_context_inert() {
        // Module 26 context-inert obligation: every install sees
        // the same per-Mode policy regardless of JsContext.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035092").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = StorageEstimateOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::StorageEstimate);
        }
    }

    #[test]
    fn storage_estimate_types_are_send_sync() {
        // Module 26 trait obligation.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StorageEstimateOverride>();
        assert_send_sync::<StorageEstimatePolicy>();
        assert_send_sync::<StorageEstimateProfile>();
        assert_send_sync::<StorageEstimateSurface>();
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // Lock in the exhaustive-match contract so a future
        // variant (e.g. a Phase-12 mobile carve-out) cannot be
        // silently routed through the existing arm.
        fn arm(p: StorageEstimatePolicy) -> &'static str {
            match p {
                StorageEstimatePolicy::Locked(_) => "locked",
            }
        }
        assert_eq!(arm(StorageEstimatePolicy::for_mode(Mode::Strict)), "locked");
        assert_eq!(
            arm(StorageEstimatePolicy::for_mode(Mode::Standard)),
            "locked",
        );
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: StorageEstimateSurface) -> &'static str {
            match s {
                StorageEstimateSurface::Estimate => "estimate",
            }
        }
        for s in StorageEstimateSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }
}
