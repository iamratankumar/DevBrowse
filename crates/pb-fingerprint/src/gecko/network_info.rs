//! Module 35.8 — Network Information API lock.
//!
//! Locks `navigator.connection` (Network Information API) under
//! both modes. The API surface — `effectiveType`, `downlink`,
//! `rtt`, `saveData`, `type` — leaks connection class which
//! strongly correlates with geographic location, especially on
//! mobile (Phase 12). Tor returns a `"4g"` stub but still exposes
//! the API surface so the existence of `navigator.connection`
//! itself is a 1-bit fingerprint signal. DevBrowse goes
//! structurally ahead by **removing** `navigator.connection`
//! entirely in Strict (the property is undefined on the navigator
//! prototype — `'connection' in navigator === false`).
//!
//! Standard cohort-locks to broadband values so every Standard
//! DevBrowse user reports the same connection class regardless of
//! the actual host network.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override; the
//!     `navigator.connection` accessor is removed in Strict and
//!     pinned to `LOCKED_NETWORK_INFORMATION_PROFILE` in Standard
//!     below the JS surface, so workers and iframes inherit the
//!     lock automatically.
//!   * **L9 / §3.2 / §3.3** — per-Mode normalization. Strict
//!     `Removed`; Standard `LockedCohort`.
//!   * **L41** — Strict's removal is structurally non-loosenable:
//!     no `with_user_override` constructor exists. Module 35.4
//!     settings-lock audit re-asserts.
//!   * **L44** — Network Information joins the L44 disabled-API
//!     surface for Strict. Module 35.3 owns the cross-API L44
//!     enumeration but **delegates the per-API removal to this
//!     module** (mirroring the Module 31 Battery delegation
//!     precedent): re-enumerating `NetworkInformation` in
//!     `DisabledApi::ALL` would be a second source of truth, the
//!     cohort-drift surface the no-redundant-state lock forbids.
//!     The libxul bridge unions Module 35.3's `DisabledApi::ALL`
//!     with this module's Strict `Removed` policy + Module 31's
//!     `BatterySurface::ALL` to get the complete Strict L44 lock.
//!   * **§5.5** — central fingerprint surface bucketing.
//!   * **threat-model A1** — connection class is a strong
//!     geographic correlate (mobile carrier deployment maps to
//!     country/region); removing the API in Strict and locking
//!     the cohort in Standard closes the per-host signal.
//!
//! ## Mode-applicability (locked v1.23)
//!
//!   * **Strict** — `NetworkInformationPolicy::Removed`.
//!     `navigator.connection` is deleted from the `Navigator`
//!     prototype (so `'connection' in navigator === false`,
//!     mirroring Module 35.3's
//!     [`DisableMechanism::NavigatorPropertyDeleted`] family).
//!     Every property (`effectiveType`, `downlink`, `rtt`,
//!     `saveData`, `type`) and the `change` event listener slot
//!     are unreachable.
//!   * **Standard** — `NetworkInformationPolicy::LockedCohort(
//!     &LOCKED_NETWORK_INFORMATION_PROFILE)`. Every Standard
//!     renderer reports the same broadband cohort regardless of
//!     the actual host network: `effectiveType = "4g"`,
//!     `downlink = 10` Mbps, `rtt = 50` ms, `saveData = false`,
//!     `type = "wifi"`. The `change` event never fires (the
//!     cohort never mutates).
//!
//! ## Edge cases (phase-file lock)
//!
//!   * **Adaptive-bitrate sites** (YouTube, Netflix) may
//!     over-quality on actual slow connections because Standard
//!     reports `"4g"`. Documented tradeoff; every major streaming
//!     site exposes a user-controlled quality override that
//!     mitigates.
//!   * **`navigator.connection.change` event handlers.** In
//!     Standard the locked cohort values never change so the
//!     event never fires; in Strict the event listener slot does
//!     not exist because the `connection` property is removed
//!     from the prototype.
//!   * **`saveData` lock to `false`** is the cohort-safe answer.
//!     A `saveData = true` cohort would itself be a fingerprint
//!     signal (suggesting the user enabled data-saver mode).
//!     Sites that need a data-saver hint must obtain it through
//!     an explicit user setting rather than the API.
//!   * **`downlinkMax` deprecated.** The W3C NetworkInformation
//!     IDL still exposes the deprecated `downlinkMax` property
//!     on some platforms; `NetworkInformationSurface::ALL`
//!     enumerates it so the libxul bridge knows to lock or remove
//!     it alongside the supported fields.
//!
//! ## Delegation contract with Module 35.3
//!
//! Module 35.3's [`DisabledApi`] enumeration is the cross-API L44
//! enforcement layer; this module owns the per-API policy for
//! `navigator.connection`. Module 35.3 does NOT list
//! `NetworkInformation` as a variant — the assertion
//! `network_information_is_delegated_to_module_35_8_not_duplicated_here`
//! in `strict/disabled_apis.rs` pins this boundary, mirroring the
//! identical assertion for the Module 31 Battery delegation. The
//! libxul bridge consults BOTH modules' lists at startup and
//! unions the disables; the no-redundant-state lock holds because
//! the two modules' enumerations are disjoint by construction.
//!
//! [`DisabledApi`]: crate::strict::disabled_apis::DisabledApi
//! [`DisableMechanism::NavigatorPropertyDeleted`]: crate::strict::disabled_apis::DisableMechanism::NavigatorPropertyDeleted
//
// TODO(libxul FFI bridge — landing in pb-browser orchestrator at
//   Phase 11 / Module 80 startup; verified against the libxul ABI
//   on every tag bump by Module 69 in Phase 9): wire the
//   `Navigator.connection` accessor. There is no dedicated
//   "libxul bridge" module — pb-browser at startup iterates
//   `WebIdlSurface::ALL × JsContext::ALL` and installs each
//   override against the Gecko WebIDL prototypes via cbindgen
//   exports. Strict removes the property from the Navigator
//   prototype (so `'connection' in navigator === false`, matching
//   Module 35.3's NavigatorPropertyDeleted family). Standard
//   installs a getter that returns a frozen NetworkInformation
//   object populated from LOCKED_NETWORK_INFORMATION_PROFILE; the
//   object's `change` event-target never dispatches. Worker /
//   SharedWorker / ServiceWorker Navigator surfaces get the same
//   treatment for every `JsContext::ALL` variant.
// Module 35.4 (settings-lock audit) has shipped: no user setting
//   can loosen Strict's `Removed` to expose `navigator.connection`,
//   and no setting can loosen Standard's `LockedCohort` to expose
//   the actual host network class (asserted by the L41/L44
//   conformance tests in `strict/settings_lock.rs`). Structural
//   lock — no `with_user_override` constructor exists.
// TODO(Phase 10 / Module 71+): adversarial probes assert (a)
//   Strict observes `'connection' in navigator === false` in
//   every renderer + worker; (b) Standard observes the locked
//   cohort values across every renderer + worker regardless of
//   host network; (c) the `change` event never fires in either
//   mode for the lifetime of the renderer.
// TODO(Phase 12 mobile): mobile carriers expose much richer
//   connection-class signals (Cellular 5G NR sub-band, carrier
//   mcc/mnc via `connection.type === "cellular"` on Android).
//   The mode-applicability matrix above is the desktop posture;
//   Phase 12 reviews whether mobile carries the same
//   `LockedCohort = "wifi"` lie or a different carve-out. Until
//   Phase 12, mobile platforms inherit this desktop lock per
//   pb-platform Module 4 platform detection.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Network information profile (Standard cohort) ────────────────────────

/// One cohort snapshot of `navigator.connection`. Maps 1:1 to the
/// W3C [`NetworkInformation`] IDL properties read by sites; the
/// libxul bridge populates a frozen JS object from this struct
/// when a Standard renderer accesses `navigator.connection`.
///
/// `Copy` is intentional — the libxul bridge reads it on every
/// property access; never a handle.
///
/// `Eq` / `Hash` are dropped because of the `downlink` /
/// `downlink_max` `f64` fields; matches the existing
/// `AudioReadbackPolicy` / `CanvasReadbackPolicy` /
/// `WebGlReadbackPolicy` convention from Module 35.5 where a
/// policy carrying an `f32` / `f64` cannot be `Eq` + `Hash` but
/// stays `PartialEq` for tests.
///
/// [`NetworkInformation`]: https://wicg.github.io/netinfo/
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NetworkInformationProfile {
    /// `NetworkInformation.effectiveType` — round-trip-time +
    /// downlink combined into one of `"slow-2g" | "2g" | "3g" |
    /// "4g"`. The cohort lock value is `"4g"` (broadband baseline);
    /// every Standard DevBrowse user reports identical effective
    /// type regardless of host network.
    pub effective_type: &'static str,
    /// `NetworkInformation.downlink` — downlink Mbps (W3C spec:
    /// rounded to nearest 25 kbps to limit fingerprint entropy).
    /// The cohort lock value is `10.0` Mbps (broadband baseline).
    pub downlink: f64,
    /// `NetworkInformation.rtt` — round-trip time ms (W3C spec:
    /// rounded to nearest 25 ms to limit fingerprint entropy).
    /// The cohort lock value is `50` ms (broadband baseline).
    pub rtt: u32,
    /// `NetworkInformation.saveData` — boolean. The cohort lock
    /// value is `false`; a `true` cohort would itself be a
    /// fingerprint signal (suggesting the user enabled data-saver
    /// mode).
    pub save_data: bool,
    /// `NetworkInformation.type` — one of `"bluetooth" |
    /// "cellular" | "ethernet" | "mixed" | "none" | "other" |
    /// "unknown" | "wifi" | "wimax"`. The cohort lock value is
    /// `"wifi"` (broadband-adjacent baseline that does not
    /// correlate with mobile carrier deployment). Field is named
    /// `connection_type` in Rust because `type` is a reserved
    /// word; the libxul bridge exposes it as `type` on the JS
    /// object.
    pub connection_type: &'static str,
    /// `NetworkInformation.downlinkMax` — Mbps theoretical
    /// downlink based on the underlying connection technology.
    /// The W3C spec deprecates this property but Gecko still
    /// exposes it on some platforms; the cohort lock value is
    /// `10.0` Mbps so the deprecated surface does not leak a
    /// separate channel.
    pub downlink_max: f64,
}

// ── Locked profile (Standard cohort) ─────────────────────────────────────

/// The Network Information cohort returned to every
/// Standard-mode renderer.
///
/// Cohort baseline (broadband Wi-Fi) chosen so:
///   * `effectiveType = "4g"` matches Tor's stub and the majority
///     of consumer connections (the cohort cannot be smaller than
///     "majority residential broadband" without splitting the
///     cohort along geographic lines).
///   * `type = "wifi"` rather than `"ethernet"` because the
///     mobile / Phase-12 default should not require a carve-out;
///     `"wifi"` is the cross-platform cohort-safe answer.
///   * `downlink = 10` Mbps + `rtt = 50` ms are W3C
///     rounding-grid-aligned values (multiples of 25 kbps and
///     25 ms respectively).
///   * `saveData = false` — see field doc.
///
/// Ordering of bumps: a future cohort shift (e.g. moving to
/// `effectiveType = "5g"` if/when the W3C spec adds it) is a
/// cohort-shift under the Adaptation protocol; the architecture
/// revision log gets a one-line entry naming the version delta.
pub static LOCKED_NETWORK_INFORMATION_PROFILE: NetworkInformationProfile =
    NetworkInformationProfile {
        effective_type: "4g",
        downlink: 10.0,
        rtt: 50,
        save_data: false,
        connection_type: "wifi",
        downlink_max: 10.0,
    };

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode policy for the Network Information API.
///
/// Two variants with semantically distinct libxul-side behavior
/// (not a redundant divergence — `Removed` deletes the
/// `connection` property from the Navigator prototype;
/// `LockedCohort` installs a frozen-object getter):
///
///   * **Strict** — [`Self::Removed`]: the libxul bridge deletes
///     `connection` from the Navigator prototype so
///     `'connection' in navigator === false`. Matches Module 35.3's
///     [`DisableMechanism::NavigatorPropertyDeleted`] family.
///   * **Standard** — [`Self::LockedCohort`]: the libxul bridge
///     installs a getter returning a frozen `NetworkInformation`
///     object populated from
///     `LOCKED_NETWORK_INFORMATION_PROFILE`; the object's `change`
///     event-target never dispatches.
///
/// The enum is `#[non_exhaustive]` so a future per-Mode carve-out
/// (e.g. Phase-12 mobile-platform `LockedCohort` with different
/// cohort values) is a third variant, not a mutation of the
/// existing two. The libxul bridge MUST match exhaustively so a
/// new variant cannot silently fall through to the wrong
/// behavior.
///
/// `Eq` / `Hash` are dropped because the embedded
/// `NetworkInformationProfile` carries `f64` fields; matches the
/// Module 35.5 convention. `PartialEq` is retained for test
/// assertions.
///
/// [`DisableMechanism::NavigatorPropertyDeleted`]: crate::strict::disabled_apis::DisableMechanism::NavigatorPropertyDeleted
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkInformationPolicy {
    /// Strict: the `connection` property is removed from the
    /// `Navigator` prototype. `navigator.connection` is undefined;
    /// `'connection' in navigator === false`.
    Removed,
    /// Standard: the libxul bridge returns a frozen
    /// `NetworkInformation` object populated from the referenced
    /// profile. Both modes go through the same WebIDL plumb-in;
    /// the policy variant selects the libxul-side behavior.
    LockedCohort(&'static NetworkInformationProfile),
}

impl NetworkInformationPolicy {
    /// Locked snapshot for `mode`:
    ///   * `Mode::Standard` -> `LockedCohort(&LOCKED_NETWORK_INFORMATION_PROFILE)`
    ///   * `Mode::Strict`   -> `Removed`
    ///
    /// L41 lock — no `with_user_override` constructor exists.
    /// Module 35.4 settings-lock audit asserts no settings path
    /// can flip Strict to `LockedCohort` or Standard to a
    /// different-valued `LockedCohort`.
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::LockedCohort(&LOCKED_NETWORK_INFORMATION_PROFILE),
            Mode::Strict => Self::Removed,
        }
    }

    /// True iff the policy removes `navigator.connection` from
    /// the Navigator prototype (Strict).
    pub fn is_removed(&self) -> bool {
        matches!(self, Self::Removed)
    }
}

// ── Surface enumeration ──────────────────────────────────────────────────

/// Every JS pathway through which the Network Information API
/// surfaces.
///
/// The libxul bridge MUST handle every variant — under Strict
/// each is unreachable through the deleted `connection` property
/// but the enumeration is exhaustive so a hypothetical future
/// carve-out that exposes a single property without the full
/// object cannot accidentally bypass the lock. Under Standard
/// each variant reads from `LOCKED_NETWORK_INFORMATION_PROFILE`.
///
/// `JsContext::ALL` × this set is the full plumbing matrix the
/// bridge iterates at renderer startup.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkInformationSurface {
    /// `navigator.connection` — the entry-point accessor. Deleted
    /// from the Navigator prototype in Strict; returns a frozen
    /// object in Standard.
    NavigatorConnection,
    /// `NetworkInformation.effectiveType`.
    EffectiveType,
    /// `NetworkInformation.downlink`.
    Downlink,
    /// `NetworkInformation.rtt`.
    Rtt,
    /// `NetworkInformation.saveData`.
    SaveData,
    /// `NetworkInformation.type` (named to match the JS surface,
    /// not the Rust field `connection_type`).
    Type,
    /// `NetworkInformation.downlinkMax` (W3C-deprecated, still
    /// exposed by Gecko on some platforms).
    DownlinkMax,
    /// `NetworkInformation.onchange` event handler + `change`
    /// event dispatch. Under both modes the event never fires
    /// (Strict has no object; Standard's cohort never mutates).
    OnChange,
}

impl NetworkInformationSurface {
    /// Every surface the bridge must wire. Asserted against the
    /// W3C NetworkInformation IDL by
    /// `tests::network_information_surface_all_covers_spec_idl`.
    pub const ALL: &'static [NetworkInformationSurface] = &[
        Self::NavigatorConnection,
        Self::EffectiveType,
        Self::Downlink,
        Self::Rtt,
        Self::SaveData,
        Self::Type,
        Self::DownlinkMax,
        Self::OnChange,
    ];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for
/// `WebIdlSurface::NetworkInformation`.
///
/// Construct with `NetworkInformationOverride::new(mode)` for
/// symmetry with the other Phase-5 / Phase-5.5 overrides. The
/// constructor accepts a `Mode` and stores the resolved policy;
/// the trait dispatch is uniform across modes (the libxul bridge
/// dispatches on the stored policy variant).
///
/// Context-inert per Module 26: the policy carries no
/// per-`JsContext` state — every worker / iframe / SW renderer
/// resolves to the same per-Mode policy.
#[derive(Debug, Clone, Copy)]
pub struct NetworkInformationOverride {
    policy: NetworkInformationPolicy,
}

impl NetworkInformationOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: NetworkInformationPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> NetworkInformationPolicy {
        self.policy
    }
}

impl FingerprintOverride for NetworkInformationOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::NetworkInformation
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul WebIDL accessor wiring is
        // not yet plumbed — it lands when pb-browser is built in
        // Phase 11 / Module 80 (the orchestrator iterates
        // `WebIdlSurface::ALL × JsContext::ALL` at startup and
        // installs each `FingerprintOverride` against the Gecko
        // WebIDL prototypes via cbindgen exports). Module 69 in
        // Phase 9 verifies the libxul build retains the contract
        // on every tag bump. When the FFI lands, Strict registers
        // a "delete property from Navigator prototype" callback
        // and Standard registers a "return frozen
        // NetworkInformation object" getter, each for every
        // variant of `NetworkInformationSurface::ALL` ×
        // `JsContext::ALL`.
        let _ = (self.policy, JsContext::ALL, NetworkInformationSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_profile_matches_phase_file_cohort_values() {
        // Phase-file Standard cohort (v1.23): effectiveType = "4g",
        // downlink = 10 Mbps, rtt = 50 ms, saveData = false,
        // type = "wifi". These values are the cohort lock; a
        // future change is a cohort shift under the Adaptation
        // protocol.
        assert_eq!(LOCKED_NETWORK_INFORMATION_PROFILE.effective_type, "4g");
        assert_eq!(LOCKED_NETWORK_INFORMATION_PROFILE.downlink, 10.0);
        assert_eq!(LOCKED_NETWORK_INFORMATION_PROFILE.rtt, 50);
        assert!(!LOCKED_NETWORK_INFORMATION_PROFILE.save_data);
        assert_eq!(LOCKED_NETWORK_INFORMATION_PROFILE.connection_type, "wifi");
        assert_eq!(LOCKED_NETWORK_INFORMATION_PROFILE.downlink_max, 10.0);
    }

    #[test]
    fn locked_profile_downlink_aligns_with_w3c_25kbps_grid() {
        // W3C NetworkInformation: downlink is rounded to the
        // nearest 25 kbps multiple to limit fingerprint entropy.
        // 10.0 Mbps == 10000 kbps == 400 × 25 kbps; multiple of
        // the rounding grid by construction.
        let downlink_kbps = LOCKED_NETWORK_INFORMATION_PROFILE.downlink * 1000.0;
        assert!(
            (downlink_kbps % 25.0).abs() < f64::EPSILON,
            "downlink {} Mbps is not a multiple of 25 kbps",
            LOCKED_NETWORK_INFORMATION_PROFILE.downlink,
        );
    }

    #[test]
    fn locked_profile_rtt_aligns_with_w3c_25ms_grid() {
        // W3C NetworkInformation: rtt is rounded to the nearest
        // 25 ms multiple. 50 ms is the second non-zero bucket.
        assert_eq!(LOCKED_NETWORK_INFORMATION_PROFILE.rtt % 25, 0);
    }

    #[test]
    fn locked_profile_effective_type_is_w3c_enum_value() {
        // W3C EffectiveConnectionType enum: "slow-2g" | "2g" |
        // "3g" | "4g". Cohort lock value must match one.
        let allowed = ["slow-2g", "2g", "3g", "4g"];
        assert!(
            allowed.contains(&LOCKED_NETWORK_INFORMATION_PROFILE.effective_type),
            "effective_type {:?} is not a W3C EffectiveConnectionType",
            LOCKED_NETWORK_INFORMATION_PROFILE.effective_type,
        );
    }

    #[test]
    fn locked_profile_connection_type_is_w3c_enum_value() {
        // W3C ConnectionType enum: bluetooth, cellular, ethernet,
        // mixed, none, other, unknown, wifi, wimax. Cohort lock
        // value must match one.
        let allowed = [
            "bluetooth",
            "cellular",
            "ethernet",
            "mixed",
            "none",
            "other",
            "unknown",
            "wifi",
            "wimax",
        ];
        assert!(
            allowed.contains(&LOCKED_NETWORK_INFORMATION_PROFILE.connection_type),
            "connection_type {:?} is not a W3C ConnectionType",
            LOCKED_NETWORK_INFORMATION_PROFILE.connection_type,
        );
    }

    #[test]
    fn locked_profile_save_data_is_false_for_cohort_safety() {
        // saveData = true would itself be a fingerprint signal
        // (suggesting the user enabled data-saver mode). The
        // cohort posture is "every user does NOT save data".
        assert!(!LOCKED_NETWORK_INFORMATION_PROFILE.save_data);
    }

    #[test]
    fn strict_resolves_to_removed() {
        let p = NetworkInformationPolicy::for_mode(Mode::Strict);
        assert_eq!(p, NetworkInformationPolicy::Removed);
        assert!(p.is_removed());
    }

    #[test]
    fn standard_resolves_to_locked_cohort_address_identity() {
        // Standard returns LockedCohort referring to the
        // LOCKED_NETWORK_INFORMATION_PROFILE static by address —
        // the cohort base is unified by pointer identity, so the
        // libxul bridge can compare references without value
        // re-derivation.
        let p = NetworkInformationPolicy::for_mode(Mode::Standard);
        match p {
            NetworkInformationPolicy::LockedCohort(profile) => {
                assert!(
                    std::ptr::eq(profile, &LOCKED_NETWORK_INFORMATION_PROFILE),
                    "Standard LockedCohort must point at LOCKED_NETWORK_INFORMATION_PROFILE",
                );
            }
            other => panic!("expected LockedCohort, got {:?}", other),
        }
        assert!(!p.is_removed());
    }

    #[test]
    fn strict_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock — no with_user_override constructor exists.
        // Two Strict resolutions return identical content; no
        // settings path can flip to LockedCohort. Module 35.4
        // settings-lock audit pins this against call sites.
        let a = NetworkInformationPolicy::for_mode(Mode::Strict);
        let b = NetworkInformationPolicy::for_mode(Mode::Strict);
        assert_eq!(a, b);
        assert_eq!(a, NetworkInformationPolicy::Removed);
    }

    #[test]
    fn standard_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock holds for Standard too: no settings path can
        // change the cohort values. Two resolutions return the
        // same address-identity LockedCohort variant.
        let a = NetworkInformationPolicy::for_mode(Mode::Standard);
        let b = NetworkInformationPolicy::for_mode(Mode::Standard);
        assert_eq!(a, b);
    }

    #[test]
    fn network_information_surface_all_covers_spec_idl() {
        // W3C NetworkInformation IDL: 1 entry point + 5 supported
        // properties (effectiveType, downlink, rtt, saveData,
        // type) + 1 deprecated property (downlinkMax) + 1 event
        // handler (onchange). Eight variants total.
        assert_eq!(NetworkInformationSurface::ALL.len(), 8);
        for v in [
            NetworkInformationSurface::NavigatorConnection,
            NetworkInformationSurface::EffectiveType,
            NetworkInformationSurface::Downlink,
            NetworkInformationSurface::Rtt,
            NetworkInformationSurface::SaveData,
            NetworkInformationSurface::Type,
            NetworkInformationSurface::DownlinkMax,
            NetworkInformationSurface::OnChange,
        ] {
            assert!(
                NetworkInformationSurface::ALL.contains(&v),
                "missing surface: {:?}",
                v,
            );
        }
    }

    #[test]
    fn override_reports_network_information_surface_in_both_modes() {
        assert_eq!(
            NetworkInformationOverride::new(Mode::Standard).surface(),
            WebIdlSurface::NetworkInformation,
        );
        assert_eq!(
            NetworkInformationOverride::new(Mode::Strict).surface(),
            WebIdlSurface::NetworkInformation,
        );
    }

    #[test]
    fn override_carries_per_mode_policy() {
        let standard = NetworkInformationOverride::new(Mode::Standard);
        let strict = NetworkInformationOverride::new(Mode::Strict);
        assert!(matches!(
            standard.policy(),
            NetworkInformationPolicy::LockedCohort(_),
        ));
        assert_eq!(strict.policy(), NetworkInformationPolicy::Removed);
        // Strict and Standard policies are observationally
        // distinct — the two overrides MUST diverge so a future
        // mode-invariant collapse (e.g. accidentally returning
        // LockedCohort under Strict) is caught here.
        assert_ne!(standard.policy(), strict.policy());
    }

    #[test]
    fn override_install_is_context_inert() {
        // Edge case: override must be inert in iframe / worker /
        // service-worker / dedicated-worker scopes. Module 26
        // context-inert obligation: every install sees the same
        // per-Mode policy regardless of JsContext.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035080").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = NetworkInformationOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::NetworkInformation);
        }
    }

    #[test]
    fn network_information_types_are_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetworkInformationOverride>();
        assert_send_sync::<NetworkInformationPolicy>();
        assert_send_sync::<NetworkInformationProfile>();
        assert_send_sync::<NetworkInformationSurface>();
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // The libxul bridge matches NetworkInformationPolicy to
        // decide whether to register the property-deletion
        // callback (Strict) or the frozen-getter callback
        // (Standard). Lock in the exhaustive-match contract so a
        // future variant (e.g. a Phase-12 mobile-platform
        // LockedCohort with different values) cannot be silently
        // routed through an existing arm.
        fn arm(p: NetworkInformationPolicy) -> &'static str {
            match p {
                NetworkInformationPolicy::Removed => "removed",
                NetworkInformationPolicy::LockedCohort(_) => "locked-cohort",
            }
        }
        assert_eq!(
            arm(NetworkInformationPolicy::for_mode(Mode::Strict)),
            "removed",
        );
        assert_eq!(
            arm(NetworkInformationPolicy::for_mode(Mode::Standard)),
            "locked-cohort",
        );
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // The bridge MUST match without a `_` arm so a new variant
        // (e.g. a future `Saturated` property the W3C spec adds)
        // fails compilation until the bridge wires it.
        fn route(s: NetworkInformationSurface) -> &'static str {
            match s {
                NetworkInformationSurface::NavigatorConnection => "navigator-connection",
                NetworkInformationSurface::EffectiveType => "effective-type",
                NetworkInformationSurface::Downlink => "downlink",
                NetworkInformationSurface::Rtt => "rtt",
                NetworkInformationSurface::SaveData => "save-data",
                NetworkInformationSurface::Type => "type",
                NetworkInformationSurface::DownlinkMax => "downlink-max",
                NetworkInformationSurface::OnChange => "on-change",
            }
        }
        for s in NetworkInformationSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }
}
