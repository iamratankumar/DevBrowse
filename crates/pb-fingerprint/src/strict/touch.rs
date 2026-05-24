//! Module 35.10 (part 2) — Touch surface cohort lock.
//!
//! Locks `navigator.maxTouchPoints`, `ontouchstart`, and pointer /
//! hover media queries so the per-device touch hardware signal does
//! not leak. Both modes on desktop share `maxTouchPoints=0` +
//! `pointer=fine` + `hover=hover` — the **v1.23 amiunique-generic
//! cohort lock**: Standard desktop joins the Strict desktop cohort
//! instead of reporting native touch hardware (refactor from the
//! pre-v1.23 "Standard pass-through" stance documented in the
//! Phase 5.5 v1.23 audit). Mobile platforms (Phase 12) carve out
//! via [`PlatformClass`] detection so mobile-responsive sites
//! still see real touch values; v1 ships Linux + macOS desktop
//! only and the mobile path is unreachable.
//!
//! ## Mode-applicability (locked v1.23)
//!
//!   * **Strict + Desktop** -> `LockedDesktop(&DESKTOP_TOUCH_PROFILE)`:
//!     `maxTouchPoints=0`, `ontouchstart=undefined`,
//!     `pointer=fine`, `hover=hover`. Locked desktop cohort. Tor
//!     parity for the touch-API removal; the pointer/hover lock
//!     additionally closes the media-query side channel.
//!   * **Strict + Mobile (Phase 12)** -> `MobilePassThrough`. The
//!     carve-out preserves mobile-responsive site compatibility;
//!     v1 does not ship mobile so this branch is unreachable in
//!     production.
//!   * **Standard + Desktop** -> `LockedDesktop(&DESKTOP_TOUCH_PROFILE)`.
//!     **Same as Strict desktop** by construction — asserted by
//!     address-identity test. This is the v1.23 amiunique-generic
//!     refactor: Standard desktop no longer reports the host's
//!     actual `maxTouchPoints` (which would split the cohort
//!     along touchscreen-vs-non-touchscreen lines).
//!   * **Standard + Mobile (Phase 12)** -> `MobilePassThrough`.
//!     Mobile carve-out preserves real touch values for mobile
//!     site compatibility.
//!
//! ## Cross-coupling with Module 34 (Navigator)
//!
//! `maxTouchPoints` is **NOT** in `NavigatorSurface::ALL` even
//! though it lives under `navigator.*`; this module owns it. The
//! Module 34 file documents the boundary in its own
//! cross-coupling note. The libxul bridge dispatches by
//! `WebIdlSurface` variant — Module 34's bridge code handles UA /
//! platform / languages / hardwareConcurrency; Module 35.10's
//! bridge code handles `maxTouchPoints` + the touch-event +
//! pointer / hover media-query surface.
//!
//! ## Architecture references
//!
//!   * **L8** — Gecko WebIDL override; the touch accessors are
//!     patched below the JS surface so workers / iframes / service
//!     workers all see the same answer.
//!   * **L9 / §3.2 / §3.3** — per-Mode normalization. Desktop
//!     mode-distinction is intentionally collapsed (same cohort
//!     for both modes) per v1.23 amiunique-generic.
//!   * **L41** — Strict non-loosenable on desktop. Mobile carve-out
//!     is a Phase 12 design decision (not L41 violation; Phase 12
//!     is reserved scope per the architecture).
//!   * **L12** — pb-fingerprint cannot import pb-platform
//!     (sibling-leaf rule); the platform class is passed in by
//!     the orchestrator (pb-browser at Phase 11 / Module 80) which
//!     maps pb-platform's identification to [`PlatformClass`].
//!   * **§5.5** — central fingerprint surface bucketing.
//!   * **threat-model A1** — touch hardware is one of the
//!     highest-entropy passive fingerprint surfaces (CreepJS
//!     reports `maxTouchPoints` + pointer media queries together
//!     identify a device-class within ~3-4 bits); the desktop
//!     cohort lock closes both signals jointly.
//!
//! ## Edge cases (phase-file lock)
//!
//!   * **`matchMedia("(pointer: fine)")` sizing.** Strict and
//!     Standard desktop both report `fine` pointer; touch-class
//!     hybrid devices (Surface, touchscreen laptops, hybrid 2-in-1
//!     models) lose the larger click-target sizing they would get
//!     from a `coarse` pointer media match. Acceptable tradeoff
//!     for cohort cohesion — the alternative (host pass-through)
//!     splits the cohort along touch-availability lines.
//!   * **`ontouchstart` defined vs undefined.** Some sites feature-
//!     detect touch via `'ontouchstart' in window`. Setting the
//!     property to `undefined` is not enough — `in` reflection
//!     still returns true. The libxul bridge must DELETE the
//!     property from `window` and `Element.prototype` (matches
//!     Module 35.3's `NavigatorPropertyDeleted` family
//!     convention). The `ontouchstart_defined: false` field on
//!     [`TouchSurfaceProfile`] encodes the contract.
//!   * **Mobile site compat in Phase 12.** Actual touch values
//!     preserved via [`PlatformClass::Mobile`] carve-out; mobile-
//!     responsive layouts unaffected. Strict's L41 lock does NOT
//!     extend to mobile because Phase 12 is reserved-scope.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire each `TouchPathway`.
//   `navigator.maxTouchPoints` getter returns
//   `policy.profile().max_touch_points`; `ontouchstart` is
//   removed from `window` and `Element.prototype` when
//   `ontouchstart_defined == false`; `matchMedia("(pointer: ...)")`
//   and `matchMedia("(hover: ...)")` consult the profile's
//   pointer / hover fields. Worker / SharedWorker / ServiceWorker
//   global Navigator surfaces get the same treatment for every
//   `JsContext::ALL` variant.
// TODO(pb-platform Module 4 cross-coupling, Phase 11
//   orchestrator): pb-browser passes the platform class into
//   `TouchSurfaceOverride::new(mode, platform)` at renderer
//   startup. pb-platform Module 4's platform identification is
//   the source. v1 ships desktop-only; the Mobile branch is
//   unreachable in production but pinned by tests.
// TODO(Phase 12 mobile carve-out implementation): replace
//   `MobilePassThrough` with a real `LockedMobile(&profile)`
//   variant carrying the mobile-cohort touch / pointer values.
//   The Phase 12 design decision will likely report
//   `maxTouchPoints=5` (W3C-recommended max) + `pointer=coarse`
//   + `hover=none` for the mobile cohort.
// TODO(Phase 10 / Module 71+): adversarial probes assert (a)
//   Strict + Standard desktop both observe `maxTouchPoints === 0`
//   regardless of host hardware; (b) `'ontouchstart' in window
//   === false` in both modes on desktop; (c)
//   `matchMedia("(pointer: fine)").matches === true` in both
//   modes on desktop; (d) Standard desktop profile is
//   address-identical to Strict desktop profile (cross-cohort
//   anti-contradiction).

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Platform class ───────────────────────────────────────────────────────

/// Coarse platform class supplied by the orchestrator
/// (pb-browser at Phase 11 / Module 80) so this module can carve
/// out mobile pass-through without importing pb-platform (L12
/// sibling-leaf rule).
///
/// pb-platform Module 4 owns the canonical platform identification;
/// pb-browser maps that identification to one of these variants at
/// renderer startup and passes it into
/// [`TouchSurfaceOverride::new`].
///
/// v1 ships Linux + macOS desktop; only [`Self::Desktop`] is
/// reachable in production. Phase 12 mobile work enables
/// [`Self::Mobile`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformClass {
    /// Linux / macOS / Windows desktop. Both modes lock to the
    /// desktop touch cohort.
    Desktop,
    /// iOS / Android mobile (Phase 12 reserved scope). Touch
    /// values pass through so mobile-responsive sites work.
    Mobile,
}

// ── Touch surface profile ────────────────────────────────────────────────

/// One cohort snapshot of the touch / pointer / hover surface.
///
/// `Copy` is intentional — the libxul bridge reads it on every
/// `maxTouchPoints` access or `matchMedia` query.
///
/// All fields are non-float so `Eq` + `Hash` derive cleanly
/// (unlike the display surface which carries `f64` for DPR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TouchSurfaceProfile {
    /// `navigator.maxTouchPoints` — number of simultaneous touch
    /// points the surface supports. Desktop cohort locks to 0
    /// regardless of host (touchscreen laptops report 0 too).
    pub max_touch_points: u32,
    /// Whether `'ontouchstart' in window` returns `true`. Desktop
    /// cohort locks to `false`; libxul DELETES the property from
    /// `window` and `Element.prototype` (matches Module 35.3
    /// `NavigatorPropertyDeleted` family convention — setting to
    /// `undefined` is insufficient because `in` reflection still
    /// returns true).
    pub ontouchstart_defined: bool,
    /// `matchMedia("(pointer: <value>)")` answer — one of
    /// `"none" | "coarse" | "fine"`. Desktop cohort: `"fine"`.
    pub pointer_capability: &'static str,
    /// `matchMedia("(hover: <value>)")` answer — one of
    /// `"none" | "hover"`. Desktop cohort: `"hover"`.
    pub hover_capability: &'static str,
}

// ── Locked desktop profile ───────────────────────────────────────────────

/// The desktop touch cohort returned by both Strict and Standard
/// on desktop platforms. Single static shared by both modes —
/// the v1.23 amiunique-generic cohort unification.
///
/// `maxTouchPoints=0` + `ontouchstart` deleted + `pointer=fine` +
/// `hover=hover` is the desktop signature that touchscreen laptops
/// and conventional desktops both report. Touchscreen laptops
/// lose larger click-target sizing (acceptable tradeoff per the
/// phase-file edge-case lock); the cohort cohesion is the goal.
pub static DESKTOP_TOUCH_PROFILE: TouchSurfaceProfile = TouchSurfaceProfile {
    max_touch_points: 0,
    ontouchstart_defined: false,
    pointer_capability: "fine",
    hover_capability: "hover",
};

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode + per-platform policy for the touch surface.
///
/// Desktop is mode-invariant by design (v1.23 amiunique-generic):
/// both Strict and Standard return `LockedDesktop(&DESKTOP_TOUCH_PROFILE)`.
/// The mode parameter is taken for API symmetry with other
/// per-Mode resolvers; the platform parameter is what changes the
/// answer.
///
/// Mobile (Phase 12) returns [`MobilePassThrough`]; v1 ignores
/// this branch in production.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TouchSurfacePolicy {
    /// Desktop cohort: both modes lock to the same profile.
    LockedDesktop(&'static TouchSurfaceProfile),
    /// Phase 12 mobile carve-out: actual touch values pass
    /// through to JS. The libxul bridge reads the host's
    /// `maxTouchPoints` etc. and forwards them.
    MobilePassThrough,
}

impl TouchSurfacePolicy {
    /// Resolution keyed on `mode` + `platform`.
    ///
    /// **Desktop is mode-invariant**: both Strict and Standard
    /// resolve to `LockedDesktop(&DESKTOP_TOUCH_PROFILE)`. This
    /// is the v1.23 amiunique-generic cohort unification —
    /// Standard desktop joins the Strict desktop cohort instead
    /// of reporting native touch hardware.
    ///
    /// Mobile carve-out: both modes return `MobilePassThrough`
    /// regardless of `mode`. Phase 12 reserved-scope design.
    pub fn for_mode_and_platform(mode: Mode, platform: PlatformClass) -> Self {
        // `mode` is taken for API symmetry but does NOT influence
        // the desktop answer — the v1.23 amiunique-generic
        // unification ties Standard desktop to Strict desktop.
        // Encoded explicitly here so a future reader sees the
        // unification is intentional, not an oversight.
        let _ = mode;
        match platform {
            PlatformClass::Desktop => Self::LockedDesktop(&DESKTOP_TOUCH_PROFILE),
            PlatformClass::Mobile => Self::MobilePassThrough,
        }
    }
}

// ── Pathway enumeration ──────────────────────────────────────────────────

/// Every JS pathway through which touch / pointer / hover surface.
///
/// Named `TouchPathway` (not `TouchSurface`) to avoid collision
/// with [`WebIdlSurface::TouchSurface`]; the convention for sister
/// modules is `<Module>Surface` but this module's `WebIdlSurface`
/// variant already carries the "Surface" suffix so the pathway
/// enum uses "Pathway" instead.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TouchPathway {
    /// `navigator.maxTouchPoints` getter. Desktop cohort: 0.
    /// **NOT in `NavigatorSurface::ALL`** (Module 34 boundary —
    /// this module owns the surface).
    NavigatorMaxTouchPoints,
    /// `'ontouchstart' in window` reflection. Desktop cohort:
    /// false (property DELETED from `window`).
    WindowOnTouchStart,
    /// `'ontouchstart' in Element.prototype` reflection. Same
    /// treatment as `WindowOnTouchStart` — deleted, not set to
    /// undefined.
    ElementOnTouchStart,
    /// `matchMedia("(pointer: ...)")` query. Desktop cohort:
    /// matches `"fine"` only.
    PointerMediaQuery,
    /// `matchMedia("(hover: ...)")` query. Desktop cohort:
    /// matches `"hover"` only.
    HoverMediaQuery,
}

impl TouchPathway {
    pub const ALL: &'static [TouchPathway] = &[
        Self::NavigatorMaxTouchPoints,
        Self::WindowOnTouchStart,
        Self::ElementOnTouchStart,
        Self::PointerMediaQuery,
        Self::HoverMediaQuery,
    ];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::TouchSurface`.
///
/// Construct with `TouchSurfaceOverride::new(mode, platform)`. The
/// platform argument is supplied by the orchestrator (pb-browser
/// at Phase 11 / Module 80) which maps pb-platform Module 4's
/// platform identification to [`PlatformClass`]. v1 ships
/// desktop-only.
#[derive(Debug, Clone, Copy)]
pub struct TouchSurfaceOverride {
    policy: TouchSurfacePolicy,
}

impl TouchSurfaceOverride {
    pub fn new(mode: Mode, platform: PlatformClass) -> Self {
        Self {
            policy: TouchSurfacePolicy::for_mode_and_platform(mode, platform),
        }
    }

    /// Convenience constructor for desktop (v1 default). Equivalent
    /// to `new(mode, PlatformClass::Desktop)`.
    pub fn new_desktop(mode: Mode) -> Self {
        Self::new(mode, PlatformClass::Desktop)
    }

    pub fn policy(&self) -> TouchSurfacePolicy {
        self.policy
    }
}

impl FingerprintOverride for TouchSurfaceOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::TouchSurface
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. When the libxul FFI lands, the
        // bridge installs per-pathway handlers reading from
        // `self.policy` for every variant of `TouchPathway::ALL`
        // × `JsContext::ALL`.
        let _ = (self.policy, JsContext::ALL, TouchPathway::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_profile_matches_phase_file_cohort() {
        // Phase-file desktop cohort: maxTouchPoints=0,
        // ontouchstart undefined, pointer=fine, hover=hover.
        assert_eq!(DESKTOP_TOUCH_PROFILE.max_touch_points, 0);
        assert!(!DESKTOP_TOUCH_PROFILE.ontouchstart_defined);
        assert_eq!(DESKTOP_TOUCH_PROFILE.pointer_capability, "fine");
        assert_eq!(DESKTOP_TOUCH_PROFILE.hover_capability, "hover");
    }

    #[test]
    fn platform_class_has_desktop_and_mobile() {
        // 2 variants today; Phase 12 may add a third (e.g.
        // tablet) which the libxul bridge must handle.
        for v in [PlatformClass::Desktop, PlatformClass::Mobile] {
            // Exhaustive match check via dispatch.
            let _ = match v {
                PlatformClass::Desktop => "desktop",
                PlatformClass::Mobile => "mobile",
            };
        }
    }

    #[test]
    fn strict_desktop_resolves_to_desktop_static_by_address() {
        let p = TouchSurfacePolicy::for_mode_and_platform(Mode::Strict, PlatformClass::Desktop);
        match p {
            TouchSurfacePolicy::LockedDesktop(profile) => {
                assert!(
                    std::ptr::eq(profile, &DESKTOP_TOUCH_PROFILE),
                    "Strict desktop must point at DESKTOP_TOUCH_PROFILE by address",
                );
            }
            other => panic!("expected LockedDesktop, got {:?}", other),
        }
    }

    #[test]
    fn standard_desktop_resolves_to_same_static_as_strict_desktop() {
        // **v1.23 amiunique-generic cohort unification.** Standard
        // desktop MUST point at the SAME static as Strict desktop.
        // Asserted by address-identity check via `std::ptr::eq`.
        let strict =
            TouchSurfacePolicy::for_mode_and_platform(Mode::Strict, PlatformClass::Desktop);
        let standard =
            TouchSurfacePolicy::for_mode_and_platform(Mode::Standard, PlatformClass::Desktop);

        let (strict_profile, standard_profile) = match (strict, standard) {
            (TouchSurfacePolicy::LockedDesktop(a), TouchSurfacePolicy::LockedDesktop(b)) => (a, b),
            _ => panic!("both desktop modes must be LockedDesktop"),
        };

        assert!(
            std::ptr::eq(strict_profile, standard_profile),
            "v1.23 amiunique-generic: Standard desktop must address-equal Strict desktop",
        );
        assert!(std::ptr::eq(strict_profile, &DESKTOP_TOUCH_PROFILE));
    }

    #[test]
    fn both_modes_resolve_to_mobile_pass_through_on_mobile() {
        // Phase 12 carve-out: both modes return MobilePassThrough
        // regardless of mode. The mobile path is unreachable in
        // v1 production but pinned by tests so the Phase 12
        // implementer cannot accidentally lock mobile.
        for mode in [Mode::Strict, Mode::Standard] {
            let p = TouchSurfacePolicy::for_mode_and_platform(mode, PlatformClass::Mobile);
            assert_eq!(
                p,
                TouchSurfacePolicy::MobilePassThrough,
                "mode {:?} + mobile must pass through",
                mode,
            );
        }
    }

    #[test]
    fn desktop_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock — no with_user_override constructor exists.
        let a = TouchSurfacePolicy::for_mode_and_platform(Mode::Strict, PlatformClass::Desktop);
        let b = TouchSurfacePolicy::for_mode_and_platform(Mode::Strict, PlatformClass::Desktop);
        assert_eq!(a, b);
        let c = TouchSurfacePolicy::for_mode_and_platform(Mode::Standard, PlatformClass::Desktop);
        let d = TouchSurfacePolicy::for_mode_and_platform(Mode::Standard, PlatformClass::Desktop);
        assert_eq!(c, d);
        // Cross-mode equality (the unification).
        assert_eq!(a, c);
    }

    #[test]
    fn touch_pathway_all_covers_five_surfaces() {
        // 1 maxTouchPoints + 2 ontouchstart sites (window +
        // Element.prototype) + 2 media queries (pointer + hover)
        // = 5 pathways.
        assert_eq!(TouchPathway::ALL.len(), 5);
        for v in [
            TouchPathway::NavigatorMaxTouchPoints,
            TouchPathway::WindowOnTouchStart,
            TouchPathway::ElementOnTouchStart,
            TouchPathway::PointerMediaQuery,
            TouchPathway::HoverMediaQuery,
        ] {
            assert!(TouchPathway::ALL.contains(&v), "missing pathway: {:?}", v,);
        }
    }

    #[test]
    fn max_touch_points_is_owned_by_this_module_not_navigator() {
        // Phase-file cross-module lock: `maxTouchPoints` is NOT
        // in `NavigatorSurface::ALL`; the new `TouchSurface`
        // variant owns it. This module's pathway enum lists it
        // by name so the regression surfaces at compile time
        // (the pathway exists, lockstep maintained).
        let has_max_touch = TouchPathway::ALL.contains(&TouchPathway::NavigatorMaxTouchPoints);
        assert!(
            has_max_touch,
            "NavigatorMaxTouchPoints must be in TouchPathway::ALL (Module 34 boundary lock)",
        );
    }

    #[test]
    fn override_reports_touch_surface_in_both_modes() {
        assert_eq!(
            TouchSurfaceOverride::new_desktop(Mode::Standard).surface(),
            WebIdlSurface::TouchSurface,
        );
        assert_eq!(
            TouchSurfaceOverride::new_desktop(Mode::Strict).surface(),
            WebIdlSurface::TouchSurface,
        );
    }

    #[test]
    fn override_desktop_policies_are_indistinguishable_across_modes() {
        // v1.23 amiunique-generic: Strict desktop and Standard
        // desktop overrides MUST carry equal policies.
        let standard = TouchSurfaceOverride::new_desktop(Mode::Standard);
        let strict = TouchSurfaceOverride::new_desktop(Mode::Strict);
        assert_eq!(standard.policy(), strict.policy());
    }

    #[test]
    fn override_mobile_constructor_passes_through() {
        let ovr = TouchSurfaceOverride::new(Mode::Strict, PlatformClass::Mobile);
        assert_eq!(ovr.policy(), TouchSurfacePolicy::MobilePassThrough);
    }

    #[test]
    fn override_install_is_context_inert() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035102").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = TouchSurfaceOverride::new_desktop(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::TouchSurface);
        }
    }

    #[test]
    fn touch_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TouchSurfaceOverride>();
        assert_send_sync::<TouchSurfacePolicy>();
        assert_send_sync::<TouchSurfaceProfile>();
        assert_send_sync::<TouchPathway>();
        assert_send_sync::<PlatformClass>();
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // The libxul bridge matches the policy to decide whether
        // to install the desktop-cohort handlers or wire through
        // to host touch values (mobile). A future Phase 12 third
        // variant (e.g. tablet carve-out) must compile-error here.
        fn arm(p: TouchSurfacePolicy) -> &'static str {
            match p {
                TouchSurfacePolicy::LockedDesktop(_) => "locked-desktop",
                TouchSurfacePolicy::MobilePassThrough => "mobile-pass-through",
            }
        }
        assert_eq!(
            arm(TouchSurfacePolicy::for_mode_and_platform(
                Mode::Strict,
                PlatformClass::Desktop,
            )),
            "locked-desktop",
        );
        assert_eq!(
            arm(TouchSurfacePolicy::for_mode_and_platform(
                Mode::Strict,
                PlatformClass::Mobile,
            )),
            "mobile-pass-through",
        );
    }

    #[test]
    fn pathway_dispatch_is_exhaustive_friendly() {
        fn route(p: TouchPathway) -> &'static str {
            match p {
                TouchPathway::NavigatorMaxTouchPoints => "navigator-max-touch-points",
                TouchPathway::WindowOnTouchStart => "window-ontouchstart",
                TouchPathway::ElementOnTouchStart => "element-ontouchstart",
                TouchPathway::PointerMediaQuery => "pointer-media-query",
                TouchPathway::HoverMediaQuery => "hover-media-query",
            }
        }
        for p in TouchPathway::ALL {
            assert!(!route(*p).is_empty());
        }
    }

    #[test]
    fn platform_class_dispatch_is_exhaustive_friendly() {
        fn arm(p: PlatformClass) -> &'static str {
            match p {
                PlatformClass::Desktop => "desktop",
                PlatformClass::Mobile => "mobile",
            }
        }
        assert_eq!(arm(PlatformClass::Desktop), "desktop");
        assert_eq!(arm(PlatformClass::Mobile), "mobile");
    }
}
