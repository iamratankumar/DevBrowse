//! Module 35.10 (part 1) — Display capabilities cohort lock.
//!
//! Closes the per-device display fingerprint signals Module 35.1's
//! letterboxer does not address: `window.devicePixelRatio`,
//! `screen.colorDepth`, `screen.pixelDepth`, `screen.orientation`,
//! and `OrientationChange` events. Module 35.1 locks the
//! letterboxed window dimensions; this module locks the remaining
//! display metadata.
//!
//! ## Mode-applicability (locked v1.23)
//!
//!   * **Strict** — `Locked(&STRICT_DISPLAY_PROFILE)`:
//!     `devicePixelRatio = 1.0`, `colorDepth = 24`,
//!     `pixelDepth = 24`, `orientation.type = "landscape-primary"`,
//!     `orientation.angle = 0`. Locked desktop-class cohort.
//!     Tor parity for `colorDepth` / `orientation`; structurally
//!     ahead by combining all four fields under one Mode-locked
//!     profile.
//!   * **Standard** — `Locked(&STANDARD_DISPLAY_DPR_*)`:
//!     `devicePixelRatio` bucketed to the closest of
//!     `{1.0, 1.5, 2.0, 3.0}` so Retina UX is preserved. Every
//!     Standard DevBrowse user reports one of four cohorts (not
//!     a continuous host-derived value); `colorDepth = 24` and
//!     `pixelDepth = 24` are universal on modern displays and
//!     locked. `orientation` reports `landscape-primary/0°` on
//!     desktop v1 (mobile orientation runtime tracking lands in
//!     Phase 12).
//!
//! ## Architecture references
//!
//!   * **L8** — Gecko WebIDL override; the display accessors are
//!     patched below the JS surface so workers / iframes / service
//!     workers all see the same answer.
//!   * **L9 / §3.2 / §3.3** — per-Mode normalization. Strict locks
//!     the desktop-class cohort; Standard buckets DPR to one of
//!     four values.
//!   * **L41** — Strict non-loosenable on desktop. Module 35.4
//!     settings-lock audit re-asserts.
//!   * **L42 (Module 35.1)** — letterboxer locks
//!     `innerWidth`/`outerWidth`/`screen.width` etc.; this module
//!     adjoins with `devicePixelRatio` so the letterbox quantization
//!     applies after DPR snapping (CSS pixels, not device pixels,
//!     reach the letterbox per §5.5).
//!   * **§5.5** — central fingerprint surface bucketing.
//!   * **threat-model A1** — DPR + colorDepth are classical
//!     passive fingerprint surfaces (CreepJS / amiunique probes);
//!     the cohort lock closes both.
//!
//! ## Edge cases (phase-file lock)
//!
//!   * **DPR bucket coarseness.** A 1.75x host DPR bucketed to
//!     2.0 means UI elements render 14% larger than the host
//!     wants. Below the user-perception threshold for most
//!     content; substantially better UX than Tor's hard 1.0
//!     (which forces 200% non-fractional scaling on Retina).
//!     The 4-bucket choice ({1.0, 1.5, 2.0, 3.0}) covers the
//!     mainstream display population without splitting the
//!     cohort along every fractional DPR.
//!   * **Ties in DPR bucketing** (e.g. 1.75 equidistant from 1.5
//!     and 2.0) round to the LARGER bucket. Convention: a
//!     border-case host with a fractional DPR gets the
//!     better-scaled bucket, matching the Retina UX expectation.
//!   * **colorDepth / pixelDepth = 24 is universal**. Every
//!     mainstream display (24-bit truecolor or higher) reports
//!     24 to JS regardless of underlying panel. Locking to 24
//!     does not break any modern site.
//!   * **`orientation.angle` is 0 (not undefined)**. Some sites
//!     read `screen.orientation.angle` synchronously and crash on
//!     `undefined`. Returning 0 is web-compatible.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire each
//   `DisplayCapabilitiesSurface` pathway. `window.devicePixelRatio`
//   getter, `screen.colorDepth` / `pixelDepth` getters, and
//   `screen.orientation.{type,angle}` getters all consult
//   `DisplayCapabilitiesOverride::policy().profile()` for the
//   renderer's current Mode + host DPR. `OrientationChange` event
//   dispatch is suppressed on desktop (no rotation); Phase 12
//   mobile carve-out re-enables it for actual rotation.
// TODO(Module 35.1 / letterboxer cross-coupling): Module 35.1's
//   `WindowDimensionSurface::ALL` locks the CSS-pixel width/height
//   surface; the letterbox quantization happens AFTER DPR
//   snapping at the libxul bridge. The two modules share the
//   `strict/` directory but no shared types; the coupling is
//   purely sequential at the bridge.
// TODO(Phase 12 mobile carve-out): mobile platforms need actual
//   `screen.orientation` runtime tracking (the user rotates the
//   device). pb-platform Module 4 identifies the platform class
//   at startup; Phase 12 work passes a `PlatformClass::Mobile`
//   into the constructor to swap in a dynamic orientation
//   policy. v1 ignores the platform argument (desktop-only).
// TODO(Phase 10 / Module 71+): adversarial probes assert (a)
//   Strict observes `devicePixelRatio === 1` in every renderer
//   regardless of host display; (b) Standard observes one of
//   `{1.0, 1.5, 2.0, 3.0}` matching the bucketed host DPR;
//   (c) `colorDepth === 24` and `pixelDepth === 24` in both
//   modes; (d) `orientation.type === "landscape-primary"` and
//   `angle === 0` on desktop v1.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Display capabilities profile ─────────────────────────────────────────

/// One cohort snapshot of the W3C display surface. Maps 1:1 to the
/// JS getters under `window.devicePixelRatio`, `screen.colorDepth`,
/// `screen.pixelDepth`, and `screen.orientation`.
///
/// `Copy` is intentional — the libxul bridge reads it on every
/// display-getter invocation.
///
/// `Eq` / `Hash` are dropped because of the `device_pixel_ratio`
/// `f64` field; matches the Module 35.5 / 35.8 convention. The
/// `PartialEq` impl is retained for tests.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DisplayCapabilitiesProfile {
    /// `window.devicePixelRatio` — CSS-pixel to device-pixel ratio.
    /// Strict locks to 1.0; Standard buckets host DPR to one of
    /// `{1.0, 1.5, 2.0, 3.0}`.
    pub device_pixel_ratio: f64,
    /// `screen.colorDepth` — bits per pixel. Locked to 24 in both
    /// modes (universal on modern displays; locking does not break
    /// any mainstream site).
    pub color_depth: u32,
    /// `screen.pixelDepth` — equivalent to `colorDepth` on
    /// modern Gecko / WebKit / Blink. Locked to 24.
    pub pixel_depth: u32,
    /// `screen.orientation.type` — one of `"landscape-primary" |
    /// "landscape-secondary" | "portrait-primary" |
    /// "portrait-secondary"`. Locked to `"landscape-primary"` on
    /// desktop v1; mobile (Phase 12) reports actual orientation.
    pub orientation_type: &'static str,
    /// `screen.orientation.angle` — degrees from primary
    /// orientation. Locked to 0 on desktop v1. `0` (not
    /// undefined) for web-compat: sites that read this
    /// synchronously crash on undefined.
    pub orientation_angle: u32,
}

// ── Locked profiles ──────────────────────────────────────────────────────

/// Strict cohort: locked desktop-class profile. Identical to the
/// 1.0 DPR Standard bucket on every field except by intent —
/// Strict structurally cannot deviate; Standard can move into
/// the 1.5 / 2.0 / 3.0 buckets via host-DPR resolution.
pub static STRICT_DISPLAY_PROFILE: DisplayCapabilitiesProfile = DisplayCapabilitiesProfile {
    device_pixel_ratio: 1.0,
    color_depth: 24,
    pixel_depth: 24,
    orientation_type: "landscape-primary",
    orientation_angle: 0,
};

/// Standard cohort, DPR=1.0 bucket. Used when the host's actual
/// DPR rounds to 1.0 (typical non-Retina display). Identical in
/// value to `STRICT_DISPLAY_PROFILE` but a separate static so the
/// address-identity of "Strict vs Standard" is observable to
/// future audit code.
pub static STANDARD_DISPLAY_DPR_1_0: DisplayCapabilitiesProfile = DisplayCapabilitiesProfile {
    device_pixel_ratio: 1.0,
    color_depth: 24,
    pixel_depth: 24,
    orientation_type: "landscape-primary",
    orientation_angle: 0,
};

/// Standard cohort, DPR=1.5 bucket. Used when the host's actual
/// DPR rounds to 1.5 (some Windows / Linux scaled displays).
pub static STANDARD_DISPLAY_DPR_1_5: DisplayCapabilitiesProfile = DisplayCapabilitiesProfile {
    device_pixel_ratio: 1.5,
    color_depth: 24,
    pixel_depth: 24,
    orientation_type: "landscape-primary",
    orientation_angle: 0,
};

/// Standard cohort, DPR=2.0 bucket. Used when the host's actual
/// DPR rounds to 2.0 (Retina, most macOS, high-DPI Windows).
pub static STANDARD_DISPLAY_DPR_2_0: DisplayCapabilitiesProfile = DisplayCapabilitiesProfile {
    device_pixel_ratio: 2.0,
    color_depth: 24,
    pixel_depth: 24,
    orientation_type: "landscape-primary",
    orientation_angle: 0,
};

/// Standard cohort, DPR=3.0 bucket. Used when the host's actual
/// DPR rounds to 3.0 (premium mobile, some 4K external displays).
pub static STANDARD_DISPLAY_DPR_3_0: DisplayCapabilitiesProfile = DisplayCapabilitiesProfile {
    device_pixel_ratio: 3.0,
    color_depth: 24,
    pixel_depth: 24,
    orientation_type: "landscape-primary",
    orientation_angle: 0,
};

// ── DPR bucketing ────────────────────────────────────────────────────────

/// The 4 DPR buckets Standard mode reports. A host DPR is rounded
/// to the closest bucket; ties round to the larger bucket
/// (better-scaled UX).
pub const STANDARD_DPR_BUCKETS: &[f64] = &[1.0, 1.5, 2.0, 3.0];

/// Typed DPR bucket — the enum form of [`STANDARD_DPR_BUCKETS`].
///
/// Replaces the float-comparison cascade `(bucket - X.X).abs() <
/// f64::EPSILON` in [`standard_profile_for_dpr_bucket`] with
/// exhaustive variant dispatch (P2-6, 2026-05-22). A future fifth
/// bucket forces a compile error at every dispatch site, instead
/// of silently falling through to 1.0.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DprBucket {
    /// 1.0× (non-Retina; the cohort floor).
    One,
    /// 1.5× (Windows / Linux scaled).
    OnePointFive,
    /// 2.0× (Retina, most macOS).
    Two,
    /// 3.0× (premium mobile, 4K external).
    Three,
}

impl DprBucket {
    /// All four buckets, in ascending order.
    pub const ALL: &'static [DprBucket] = &[Self::One, Self::OnePointFive, Self::Two, Self::Three];

    /// The bucket's DPR value as `f64`. Matches the corresponding
    /// entry in [`STANDARD_DPR_BUCKETS`].
    pub const fn as_f64(self) -> f64 {
        match self {
            Self::One => 1.0,
            Self::OnePointFive => 1.5,
            Self::Two => 2.0,
            Self::Three => 3.0,
        }
    }

    /// Resolve the typed bucket for an arbitrary host DPR.
    /// Equivalent to applying [`closest_dpr_bucket`] then matching
    /// on the result; provided as a single helper so call sites
    /// can stay typed.
    pub fn closest(host_dpr: f64) -> Self {
        if !host_dpr.is_finite() || host_dpr <= 0.0 {
            return Self::One;
        }
        let mut best = Self::One;
        let mut best_dist = (host_dpr - Self::One.as_f64()).abs();
        for candidate in [Self::OnePointFive, Self::Two, Self::Three] {
            let d = (host_dpr - candidate.as_f64()).abs();
            if d <= best_dist {
                best = candidate;
                best_dist = d;
            }
        }
        best
    }

    /// Static profile for this bucket. Replaces the float-EPSILON
    /// cascade in [`standard_profile_for_dpr_bucket`] with exact
    /// variant dispatch.
    pub fn profile(self) -> &'static DisplayCapabilitiesProfile {
        match self {
            Self::One => &STANDARD_DISPLAY_DPR_1_0,
            Self::OnePointFive => &STANDARD_DISPLAY_DPR_1_5,
            Self::Two => &STANDARD_DISPLAY_DPR_2_0,
            Self::Three => &STANDARD_DISPLAY_DPR_3_0,
        }
    }
}

/// Returns the closest [`STANDARD_DPR_BUCKETS`] value to
/// `host_dpr`. Round-half-up convention: a host DPR exactly
/// between two buckets resolves to the LARGER bucket so the UI
/// scales toward the higher-fidelity rendering.
///
/// Extreme values clamp: `host_dpr < 1.0` returns 1.0 (the
/// smallest bucket); `host_dpr > 3.0` returns 3.0 (the largest).
///
/// **Hardened inputs (P0-3, 2026-05-22):** non-finite inputs (NaN,
/// `±∞`) and negative inputs return `1.0` (the smallest bucket).
/// Rationale: a NaN comparison (`NaN <= NaN == false`) would
/// previously cause the iteration to retain the first bucket
/// silently — same outcome but undocumented. Explicit handling
/// makes the contract clear, and the smallest bucket is the
/// cohort-safe default (matches Tor's hard 1.0 fallback).
pub fn closest_dpr_bucket(host_dpr: f64) -> f64 {
    // Non-finite (NaN, ±∞) or non-positive inputs collapse to the
    // smallest bucket. Documented contract; matches the Tor RFP
    // posture for unrecognized DPR.
    if !host_dpr.is_finite() || host_dpr <= 0.0 {
        return STANDARD_DPR_BUCKETS[0];
    }
    let mut best = STANDARD_DPR_BUCKETS[0];
    let mut best_dist = (host_dpr - best).abs();
    for &b in &STANDARD_DPR_BUCKETS[1..] {
        let d = (host_dpr - b).abs();
        // `<=` means ties prefer the LATER (larger) bucket since
        // the slice is sorted ascending.
        if d <= best_dist {
            best = b;
            best_dist = d;
        }
    }
    best
}

/// Returns the `STANDARD_DISPLAY_DPR_*` static matching `bucket`.
///
/// **Preferred call path is via `DprBucket::profile()`** (typed
/// dispatch). This `f64`-input variant exists for backward
/// compatibility with call sites that already hold an `f64`
/// bucket from [`closest_dpr_bucket`]; internally it routes
/// through the typed enum so float-comparison drift cannot
/// silently fall back to 1.0.
///
/// Refactored 2026-05-22 (P2-6): now delegates to
/// `DprBucket::closest(bucket).profile()` rather than the
/// `(bucket - X.X).abs() < f64::EPSILON` cascade. For an exact
/// bucket input, the result is identical; for an out-of-grid
/// input, the result is the closest bucket (not silently 1.0).
pub fn standard_profile_for_dpr_bucket(bucket: f64) -> &'static DisplayCapabilitiesProfile {
    DprBucket::closest(bucket).profile()
}

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode policy for display capabilities.
///
/// Single-variant enum (`Locked(&profile)`) — the mode-dispatch
/// happens at construction time via static selection, mirroring
/// Module 35.7 `MediaCapabilitiesPolicy::Locked` + Module 35.9
/// `StorageEstimatePolicy::Locked` shape. The variant is
/// `#[non_exhaustive]` so a Phase-12 mobile dynamic-orientation
/// variant is a second arm, not a mutation of `Locked`.
///
/// `Eq` / `Hash` dropped because the embedded
/// `DisplayCapabilitiesProfile` carries an `f64`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DisplayCapabilitiesPolicy {
    /// Both modes go through the same enum variant; the
    /// referenced profile differs per mode (and per Standard
    /// DPR bucket).
    Locked(&'static DisplayCapabilitiesProfile),
}

impl DisplayCapabilitiesPolicy {
    /// Resolution without a known host DPR. Strict resolves to
    /// `STRICT_DISPLAY_PROFILE`; Standard resolves to the default
    /// 1.0 bucket. Use [`Self::for_mode_with_host_dpr`] when the
    /// host DPR is available (pb-browser orchestrator passes it
    /// in at startup).
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Strict => Self::Locked(&STRICT_DISPLAY_PROFILE),
            Mode::Standard => Self::Locked(&STANDARD_DISPLAY_DPR_1_0),
        }
    }

    /// Resolution with the host's actual DPR. Strict ignores
    /// `host_dpr` (the L41 lock forces 1.0); Standard buckets to
    /// one of `{1.0, 1.5, 2.0, 3.0}` via [`closest_dpr_bucket`].
    pub fn for_mode_with_host_dpr(mode: Mode, host_dpr: f64) -> Self {
        match mode {
            Mode::Strict => Self::Locked(&STRICT_DISPLAY_PROFILE),
            Mode::Standard => {
                let bucket = closest_dpr_bucket(host_dpr);
                Self::Locked(standard_profile_for_dpr_bucket(bucket))
            }
        }
    }

    /// Returns the static profile this policy references.
    pub fn profile(&self) -> &'static DisplayCapabilitiesProfile {
        match self {
            Self::Locked(p) => p,
        }
    }
}

// ── Surface enumeration ──────────────────────────────────────────────────

/// Every JS pathway through which display capabilities surface.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayCapabilitiesSurface {
    /// `window.devicePixelRatio` getter.
    DevicePixelRatio,
    /// `screen.colorDepth` getter.
    ScreenColorDepth,
    /// `screen.pixelDepth` getter.
    ScreenPixelDepth,
    /// `screen.orientation.type` getter.
    ScreenOrientationType,
    /// `screen.orientation.angle` getter.
    ScreenOrientationAngle,
    /// `screen.orientation.onchange` event + `change` event
    /// dispatch. Suppressed in Strict + Standard desktop v1 (no
    /// rotation); Phase 12 mobile carve-out re-enables.
    OrientationChange,
}

impl DisplayCapabilitiesSurface {
    pub const ALL: &'static [DisplayCapabilitiesSurface] = &[
        Self::DevicePixelRatio,
        Self::ScreenColorDepth,
        Self::ScreenPixelDepth,
        Self::ScreenOrientationType,
        Self::ScreenOrientationAngle,
        Self::OrientationChange,
    ];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for
/// `WebIdlSurface::DisplayCapabilities`.
///
/// Construct with `DisplayCapabilitiesOverride::new(mode)` for
/// API symmetry (resolves to the default DPR=1.0 bucket in
/// Standard) or `with_host_dpr(mode, host_dpr)` when the host
/// DPR is known (the pb-browser orchestrator passes it at
/// renderer startup via pb-platform Module 4).
#[derive(Debug, Clone, Copy)]
pub struct DisplayCapabilitiesOverride {
    policy: DisplayCapabilitiesPolicy,
}

impl DisplayCapabilitiesOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: DisplayCapabilitiesPolicy::for_mode(mode),
        }
    }

    pub fn with_host_dpr(mode: Mode, host_dpr: f64) -> Self {
        Self {
            policy: DisplayCapabilitiesPolicy::for_mode_with_host_dpr(mode, host_dpr),
        }
    }

    pub fn policy(&self) -> DisplayCapabilitiesPolicy {
        self.policy
    }
}

impl FingerprintOverride for DisplayCapabilitiesOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::DisplayCapabilities
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. When the libxul FFI lands, the
        // bridge installs per-surface handlers reading from
        // `self.policy.profile()` for every variant of
        // `DisplayCapabilitiesSurface::ALL` × `JsContext::ALL`.
        let _ = (self.policy, JsContext::ALL, DisplayCapabilitiesSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_profile_matches_phase_file_desktop_cohort() {
        // Phase-file Strict cohort: dpr=1.0, colorDepth=24,
        // pixelDepth=24, orientation=landscape-primary, angle=0.
        assert_eq!(STRICT_DISPLAY_PROFILE.device_pixel_ratio, 1.0);
        assert_eq!(STRICT_DISPLAY_PROFILE.color_depth, 24);
        assert_eq!(STRICT_DISPLAY_PROFILE.pixel_depth, 24);
        assert_eq!(STRICT_DISPLAY_PROFILE.orientation_type, "landscape-primary");
        assert_eq!(STRICT_DISPLAY_PROFILE.orientation_angle, 0);
    }

    #[test]
    fn every_standard_bucket_has_correct_dpr_value() {
        assert_eq!(STANDARD_DISPLAY_DPR_1_0.device_pixel_ratio, 1.0);
        assert_eq!(STANDARD_DISPLAY_DPR_1_5.device_pixel_ratio, 1.5);
        assert_eq!(STANDARD_DISPLAY_DPR_2_0.device_pixel_ratio, 2.0);
        assert_eq!(STANDARD_DISPLAY_DPR_3_0.device_pixel_ratio, 3.0);
    }

    #[test]
    fn color_depth_and_pixel_depth_are_24_in_every_profile() {
        // 24-bit truecolor is universal on modern displays;
        // locking to 24 eliminates the colorDepth signal without
        // breaking sites. Asserted across every profile so a
        // future addition doesn't accidentally split the cohort.
        for p in [
            &STRICT_DISPLAY_PROFILE,
            &STANDARD_DISPLAY_DPR_1_0,
            &STANDARD_DISPLAY_DPR_1_5,
            &STANDARD_DISPLAY_DPR_2_0,
            &STANDARD_DISPLAY_DPR_3_0,
        ] {
            assert_eq!(p.color_depth, 24, "{:?} colorDepth must be 24", p);
            assert_eq!(p.pixel_depth, 24, "{:?} pixelDepth must be 24", p);
        }
    }

    #[test]
    fn orientation_locked_to_landscape_primary_in_every_profile() {
        // Desktop v1 cohort: every profile reports
        // landscape-primary/0°. Phase 12 mobile carve-out will
        // introduce dynamic-orientation profiles; for v1 the lock
        // holds across both modes.
        for p in [
            &STRICT_DISPLAY_PROFILE,
            &STANDARD_DISPLAY_DPR_1_0,
            &STANDARD_DISPLAY_DPR_1_5,
            &STANDARD_DISPLAY_DPR_2_0,
            &STANDARD_DISPLAY_DPR_3_0,
        ] {
            assert_eq!(p.orientation_type, "landscape-primary");
            assert_eq!(p.orientation_angle, 0);
        }
    }

    #[test]
    fn standard_dpr_buckets_match_phase_file_set() {
        // Phase-file Standard cohort: {1.0, 1.5, 2.0, 3.0}.
        assert_eq!(STANDARD_DPR_BUCKETS, &[1.0, 1.5, 2.0, 3.0]);
    }

    #[test]
    fn closest_dpr_bucket_exact_match_for_every_bucket() {
        // Exact bucket inputs resolve to themselves.
        for &b in STANDARD_DPR_BUCKETS {
            assert_eq!(closest_dpr_bucket(b), b);
        }
    }

    #[test]
    fn closest_dpr_bucket_handles_typical_fractional_values() {
        // Common Retina / hi-DPI scaling values.
        assert_eq!(closest_dpr_bucket(1.25), 1.5); // borderline; rounds up
        assert_eq!(closest_dpr_bucket(1.49), 1.5);
        assert_eq!(closest_dpr_bucket(1.51), 1.5);
        assert_eq!(closest_dpr_bucket(2.25), 2.0); // closer to 2.0 than 3.0
        assert_eq!(closest_dpr_bucket(2.6), 3.0); // closer to 3.0 than 2.0
    }

    #[test]
    fn closest_dpr_bucket_ties_round_to_larger_bucket() {
        // 1.75 is equidistant from 1.5 and 2.0; convention is
        // round-half-up (prefer larger bucket for better-scaled
        // UX). The implementation uses `<=` against ascending
        // buckets so the LARGER tied bucket wins.
        assert_eq!(closest_dpr_bucket(1.75), 2.0);
        assert_eq!(closest_dpr_bucket(2.5), 3.0);
    }

    #[test]
    fn closest_dpr_bucket_handles_non_finite_and_negative() {
        // Hardened input handling (P0-3, 2026-05-22): NaN, ±∞,
        // negative, and exactly-zero inputs MUST collapse to the
        // smallest bucket (1.0). Prevents silent first-bucket
        // fallback on NaN comparisons + negative arithmetic
        // surprises.
        assert_eq!(closest_dpr_bucket(f64::NAN), 1.0);
        assert_eq!(closest_dpr_bucket(f64::INFINITY), 1.0);
        assert_eq!(closest_dpr_bucket(f64::NEG_INFINITY), 1.0);
        assert_eq!(closest_dpr_bucket(-1.0), 1.0);
        assert_eq!(closest_dpr_bucket(-100.0), 1.0);
        assert_eq!(closest_dpr_bucket(0.0), 1.0);
    }

    #[test]
    fn closest_dpr_bucket_clamps_extreme_values() {
        // Sub-1.0 host DPRs (unusual but possible on some Linux
        // setups) clamp to 1.0; super-3.0 host DPRs (8K @ 200%
        // scaling) clamp to 3.0.
        assert_eq!(closest_dpr_bucket(0.5), 1.0);
        assert_eq!(closest_dpr_bucket(0.75), 1.0);
        assert_eq!(closest_dpr_bucket(4.0), 3.0);
        assert_eq!(closest_dpr_bucket(10.0), 3.0);
    }

    #[test]
    fn standard_profile_for_dpr_bucket_returns_correct_static_by_address() {
        // Address-identity selection: each bucket returns its
        // dedicated static, never a copy.
        assert!(std::ptr::eq(
            standard_profile_for_dpr_bucket(1.0),
            &STANDARD_DISPLAY_DPR_1_0,
        ));
        assert!(std::ptr::eq(
            standard_profile_for_dpr_bucket(1.5),
            &STANDARD_DISPLAY_DPR_1_5,
        ));
        assert!(std::ptr::eq(
            standard_profile_for_dpr_bucket(2.0),
            &STANDARD_DISPLAY_DPR_2_0,
        ));
        assert!(std::ptr::eq(
            standard_profile_for_dpr_bucket(3.0),
            &STANDARD_DISPLAY_DPR_3_0,
        ));
    }

    #[test]
    fn for_mode_strict_resolves_to_strict_static_by_address() {
        let p = DisplayCapabilitiesPolicy::for_mode(Mode::Strict);
        assert!(std::ptr::eq(p.profile(), &STRICT_DISPLAY_PROFILE));
    }

    #[test]
    fn for_mode_standard_default_resolves_to_dpr_1_0() {
        let p = DisplayCapabilitiesPolicy::for_mode(Mode::Standard);
        assert!(std::ptr::eq(p.profile(), &STANDARD_DISPLAY_DPR_1_0));
    }

    #[test]
    fn for_mode_with_host_dpr_strict_ignores_host_dpr() {
        // L41 lock: Strict resolves to STRICT_DISPLAY_PROFILE
        // regardless of any host DPR input.
        for host_dpr in [0.5, 1.0, 1.5, 1.75, 2.0, 3.0, 4.5] {
            let p = DisplayCapabilitiesPolicy::for_mode_with_host_dpr(Mode::Strict, host_dpr);
            assert!(
                std::ptr::eq(p.profile(), &STRICT_DISPLAY_PROFILE),
                "Strict with host_dpr={} must lock to STRICT_DISPLAY_PROFILE",
                host_dpr,
            );
        }
    }

    #[test]
    fn for_mode_with_host_dpr_standard_buckets_correctly() {
        // Spot-check: each input host_dpr resolves to the
        // expected bucket's static.
        let cases = [
            (1.0, &STANDARD_DISPLAY_DPR_1_0),
            (1.5, &STANDARD_DISPLAY_DPR_1_5),
            (1.6, &STANDARD_DISPLAY_DPR_1_5),
            (2.0, &STANDARD_DISPLAY_DPR_2_0),
            (2.25, &STANDARD_DISPLAY_DPR_2_0),
            (3.0, &STANDARD_DISPLAY_DPR_3_0),
            (4.0, &STANDARD_DISPLAY_DPR_3_0),
        ];
        for (host_dpr, expected) in cases {
            let p = DisplayCapabilitiesPolicy::for_mode_with_host_dpr(Mode::Standard, host_dpr);
            assert!(
                std::ptr::eq(p.profile(), expected),
                "host_dpr={} should bucket to dpr={}",
                host_dpr,
                expected.device_pixel_ratio,
            );
        }
    }

    #[test]
    fn strict_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock — no with_user_override constructor exists.
        let a = DisplayCapabilitiesPolicy::for_mode(Mode::Strict);
        let b = DisplayCapabilitiesPolicy::for_mode_with_host_dpr(Mode::Strict, 2.0);
        assert_eq!(a, b);
        assert_eq!(*a.profile(), STRICT_DISPLAY_PROFILE);
    }

    #[test]
    fn standard_resolution_is_idempotent_for_same_host_dpr() {
        // Same host DPR always buckets to the same profile.
        let a = DisplayCapabilitiesPolicy::for_mode_with_host_dpr(Mode::Standard, 1.75);
        let b = DisplayCapabilitiesPolicy::for_mode_with_host_dpr(Mode::Standard, 1.75);
        assert_eq!(a, b);
    }

    #[test]
    fn display_capabilities_surface_all_covers_six_pathways() {
        // 4 sync getters + 1 orientation type getter + 1
        // event-target = 6 pathways. Bumping is a contract change
        // for the libxul bridge.
        assert_eq!(DisplayCapabilitiesSurface::ALL.len(), 6);
        for v in [
            DisplayCapabilitiesSurface::DevicePixelRatio,
            DisplayCapabilitiesSurface::ScreenColorDepth,
            DisplayCapabilitiesSurface::ScreenPixelDepth,
            DisplayCapabilitiesSurface::ScreenOrientationType,
            DisplayCapabilitiesSurface::ScreenOrientationAngle,
            DisplayCapabilitiesSurface::OrientationChange,
        ] {
            assert!(
                DisplayCapabilitiesSurface::ALL.contains(&v),
                "missing surface: {:?}",
                v,
            );
        }
    }

    #[test]
    fn override_reports_display_capabilities_surface_in_both_modes() {
        assert_eq!(
            DisplayCapabilitiesOverride::new(Mode::Standard).surface(),
            WebIdlSurface::DisplayCapabilities,
        );
        assert_eq!(
            DisplayCapabilitiesOverride::new(Mode::Strict).surface(),
            WebIdlSurface::DisplayCapabilities,
        );
    }

    #[test]
    fn override_carries_per_mode_policy() {
        let standard = DisplayCapabilitiesOverride::new(Mode::Standard);
        let strict = DisplayCapabilitiesOverride::new(Mode::Strict);
        // Strict and Standard default-DPR profiles have the
        // SAME field values but live at DIFFERENT addresses
        // (separate statics). Address-identity check ensures the
        // mode-distinction surface is observable.
        assert!(!std::ptr::eq(
            standard.policy().profile(),
            strict.policy().profile(),
        ));
        assert_eq!(*standard.policy().profile(), STANDARD_DISPLAY_DPR_1_0);
        assert_eq!(*strict.policy().profile(), STRICT_DISPLAY_PROFILE);
    }

    #[test]
    fn override_install_is_context_inert() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035101").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = DisplayCapabilitiesOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::DisplayCapabilities);
        }
    }

    #[test]
    fn display_capabilities_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DisplayCapabilitiesOverride>();
        assert_send_sync::<DisplayCapabilitiesPolicy>();
        assert_send_sync::<DisplayCapabilitiesProfile>();
        assert_send_sync::<DisplayCapabilitiesSurface>();
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: DisplayCapabilitiesPolicy) -> &'static str {
            match p {
                DisplayCapabilitiesPolicy::Locked(_) => "locked",
            }
        }
        assert_eq!(
            arm(DisplayCapabilitiesPolicy::for_mode(Mode::Strict)),
            "locked"
        );
        assert_eq!(
            arm(DisplayCapabilitiesPolicy::for_mode(Mode::Standard)),
            "locked",
        );
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: DisplayCapabilitiesSurface) -> &'static str {
            match s {
                DisplayCapabilitiesSurface::DevicePixelRatio => "device-pixel-ratio",
                DisplayCapabilitiesSurface::ScreenColorDepth => "screen-color-depth",
                DisplayCapabilitiesSurface::ScreenPixelDepth => "screen-pixel-depth",
                DisplayCapabilitiesSurface::ScreenOrientationType => "screen-orientation-type",
                DisplayCapabilitiesSurface::ScreenOrientationAngle => "screen-orientation-angle",
                DisplayCapabilitiesSurface::OrientationChange => "orientation-change",
            }
        }
        for s in DisplayCapabilitiesSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }
}
