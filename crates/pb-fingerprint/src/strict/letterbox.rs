//! Module 35.1 — Window dimension letterboxer.
//!
//! Strict tabs return `window.innerWidth` / `innerHeight` /
//! `outerWidth` / `outerHeight` / `screen.width` / `height` /
//! `availWidth` / `availHeight` quantized to a 200 × 100 grid,
//! matching Tor Browser / Mullvad Browser RFP. The OS window may be
//! any size; only the JS-visible dimensions are bucketed.
//!
//! Architecture references:
//!   * **L42** — Window dimension letterboxing (Strict): 200 × 100
//!     grid; multi-monitor layout never reaches content JS. `screen.*`
//!     accessors report the primary monitor's letterboxed dimensions
//!     only, never the union nor a secondary monitor.
//!   * **L41** — Strict-mode settings lock: no user setting can
//!     loosen the Strict letterbox. The API has no
//!     `with_user_override`-style constructor.
//!   * **§5.5** — central fingerprint surface bucketing; letterboxing
//!     runs after DPR snapping, so dimensions reaching the libxul
//!     bridge are already CSS pixels.
//!
//! ## Mode-applicability (locked 2026-05-20, Phase 5.5)
//!
//!   * **Strict** — quantize through `STRICT_LETTERBOX` (200 × 100).
//!     `for_mode(Mode::Strict)` always resolves to `Quantize`; L41 is
//!     structural in the API.
//!   * **Standard** — `Bypass` in v1. Module 35.1 is the Strict-focused
//!     Mullvad-class hardening lock; the Standard §5.5 coarse-bucket
//!     spec lands as a follow-up (see TODO below).
//
// TODO(Standard §5.5 coarse buckets): the §5.5 matrix names a coarse
//   bucketing for Standard mode distinct from Strict; v1 of this
//   module ships Bypass. When the Standard bucket grid is locked,
//   add a `STANDARD_LETTERBOX` static and flip
//   `LetterboxPolicy::for_mode(Mode::Standard)` to
//   `Quantize(&STANDARD_LETTERBOX)`.
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): the bridge consults
//   `LetterboxPolicy::for_mode(ctx.mode())` at each of the
//   eight accessor sites plus `visualViewport.width` / `.height`.
//   Quantization runs AFTER DPR snapping — the dimensions reaching
//   the bridge are CSS pixels, not device pixels (§5.5).
// Module 35.4 (settings-lock audit) has shipped: the L42
//   conformance test in `strict/settings_lock.rs` asserts no
//   settings path loosens `LetterboxPolicy::for_mode(Mode::Strict)`.
//   The current API has no override surface; if a future
//   constructor is added, the audit must extend coverage.
// TODO(Module 35.10 display capabilities): extends 35.1 with DPR
//   bucketing + `screen.colorDepth` / `pixelDepth` /
//   `screen.orientation` / `maxTouchPoints`. Adjacent crate-local
//   surface; no shared types needed today.

use pb_config::Mode;

// ── Locked grid constants ────────────────────────────────────────────────

/// Strict-mode letterbox grid step in CSS pixels (width axis).
/// Matches Tor Browser / Mullvad Browser RFP.
pub const WIDTH_STEP: u32 = 200;

/// Strict-mode letterbox grid step in CSS pixels (height axis).
/// Matches Tor Browser / Mullvad Browser RFP.
pub const HEIGHT_STEP: u32 = 100;

// ── Letterbox grid ───────────────────────────────────────────────────────

/// Letterbox grid: window / screen dimensions are floored to the
/// nearest multiple of (`width_step`, `height_step`). A dimension less
/// than one step reports one step (never zero) so layout-sensitive
/// sites do not crash on `(0, 0)`.
///
/// Floor-rounding is the locked direction: it preserves the property
/// that the reported dimension is never larger than the real OS window
/// (privacy- and layout-safe). Round-nearest leaks the sub-step delta
/// on the boundary; round-up exposes more area than exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Letterbox {
    pub width_step: u32,
    pub height_step: u32,
}

impl Letterbox {
    /// Quantize a `(width, height)` pair in CSS pixels to the grid.
    pub const fn quantize(&self, width: u32, height: u32) -> (u32, u32) {
        let qw = (width / self.width_step) * self.width_step;
        let qh = (height / self.height_step) * self.height_step;
        // Edge case (phase-file Module 35.1): a window smaller than
        // one grid step reports (width_step, height_step) rather than
        // (0, 0); layout-sensitive sites would crash on zero
        // dimensions.
        let qw = if qw == 0 { self.width_step } else { qw };
        let qh = if qh == 0 { self.height_step } else { qh };
        (qw, qh)
    }
}

/// The locked Strict-mode letterbox (200 × 100 grid).
pub const STRICT_LETTERBOX: Letterbox = Letterbox {
    width_step: WIDTH_STEP,
    height_step: HEIGHT_STEP,
};

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode policy for window / screen dimension exposure.
///
/// L41 enforcement is structural: there is no constructor that lets
/// `Mode::Strict` resolve to anything other than
/// `Quantize(&STRICT_LETTERBOX)`. A future `with_user_override` would
/// break the Strict cohort and must be rejected at review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LetterboxPolicy {
    /// Pass real dimensions through unchanged (Standard v1; the
    /// §5.5 coarse-bucket spec for Standard lands as a follow-up).
    Bypass,
    /// Quantize through the supplied grid (Strict).
    Quantize(&'static Letterbox),
}

impl LetterboxPolicy {
    /// Resolve the per-Mode policy. The only Strict resolution is
    /// `Quantize(&STRICT_LETTERBOX)`; no settings path can loosen it.
    pub const fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => LetterboxPolicy::Bypass,
            Mode::Strict => LetterboxPolicy::Quantize(&STRICT_LETTERBOX),
        }
    }
}

// ── WebIDL plumbing-point enumeration ────────────────────────────────────

/// Every WebIDL accessor the libxul bridge routes through the
/// letterbox policy.
///
/// The bridge iterates this list at startup to install the same hook
/// into every dimension-exposing surface. The phase-file goal names
/// eight accessors (`Window*`, `Screen*`); the edge case lifts
/// `visualViewport` to a ninth pathway because the visible-area
/// surface follows the same rule as `innerWidth/Height`.
///
/// Multi-monitor (phase-file edge case): `Screen*` accessors report
/// the **primary** monitor's letterboxed dimensions only; never the
/// union of multi-monitor desktops nor a secondary monitor. The
/// libxul-side primary-monitor selection happens before quantization
/// reaches this enum.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowDimensionSurface {
    /// `window.innerWidth`.
    WindowInnerWidth,
    /// `window.innerHeight`.
    WindowInnerHeight,
    /// `window.outerWidth`.
    WindowOuterWidth,
    /// `window.outerHeight`.
    WindowOuterHeight,
    /// `screen.width` (primary monitor only).
    ScreenWidth,
    /// `screen.height` (primary monitor only).
    ScreenHeight,
    /// `screen.availWidth` (primary monitor only).
    ScreenAvailWidth,
    /// `screen.availHeight` (primary monitor only).
    ScreenAvailHeight,
    /// `visualViewport.width` and `visualViewport.height`. The
    /// libxul bridge routes both properties through the same
    /// `Letterbox::quantize` because the visible-area surface
    /// follows the same letterboxing rule as `innerWidth/Height`.
    VisualViewport,
}

impl WindowDimensionSurface {
    /// Every surface the FFI bridge must wire. Adding a variant to
    /// the enum without adding it here will not break compilation,
    /// so the bridge SHOULD also exhaustively match the enum to
    /// catch the omission at compile time.
    pub const ALL: &'static [WindowDimensionSurface] = &[
        Self::WindowInnerWidth,
        Self::WindowInnerHeight,
        Self::WindowOuterWidth,
        Self::WindowOuterHeight,
        Self::ScreenWidth,
        Self::ScreenHeight,
        Self::ScreenAvailWidth,
        Self::ScreenAvailHeight,
        Self::VisualViewport,
    ];
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_letterbox_uses_locked_200_by_100_grid() {
        // L42 invariant — the grid step IS the cohort definition;
        // changing it is a cohort shift through the Adaptation
        // protocol.
        assert_eq!(STRICT_LETTERBOX.width_step, 200);
        assert_eq!(STRICT_LETTERBOX.height_step, 100);
        assert_eq!(WIDTH_STEP, 200);
        assert_eq!(HEIGHT_STEP, 100);
    }

    #[test]
    fn quantize_floors_to_grid_for_typical_window() {
        // 1920 × 1080: 1920 / 200 = 9.6 -> floor 9 -> 1800.
        //              1080 / 100 = 10.8 -> floor 10 -> 1000.
        let (w, h) = STRICT_LETTERBOX.quantize(1920, 1080);
        assert_eq!((w, h), (1800, 1000));
    }

    #[test]
    fn quantize_at_step_boundary_returns_same_dimensions() {
        // Idempotence on the grid: any input that is already a
        // multiple of (200, 100) is returned unchanged.
        let (w, h) = STRICT_LETTERBOX.quantize(200, 100);
        assert_eq!((w, h), (200, 100));
        let (w, h) = STRICT_LETTERBOX.quantize(400, 200);
        assert_eq!((w, h), (400, 200));
        let (w, h) = STRICT_LETTERBOX.quantize(1800, 1000);
        assert_eq!((w, h), (1800, 1000));
        let (w, h) = STRICT_LETTERBOX.quantize(2400, 1400);
        assert_eq!((w, h), (2400, 1400));
    }

    #[test]
    fn quantize_dimensions_below_one_step_report_one_step_not_zero() {
        // Phase-file edge case: a window resized to less than one
        // grid step reports (width_step, height_step), not (0, 0),
        // so layout-sensitive sites do not crash on zero dimensions.
        assert_eq!(STRICT_LETTERBOX.quantize(0, 0), (200, 100));
        assert_eq!(STRICT_LETTERBOX.quantize(199, 99), (200, 100));
        assert_eq!(STRICT_LETTERBOX.quantize(1, 1), (200, 100));
    }

    #[test]
    fn quantize_clamps_each_axis_independently() {
        // Width at step boundary, height below: only height clamps.
        assert_eq!(STRICT_LETTERBOX.quantize(200, 50), (200, 100));
        // Width below next step (but above one step), height at
        // boundary: width floors to current step; height passes.
        assert_eq!(STRICT_LETTERBOX.quantize(399, 200), (200, 200));
    }

    #[test]
    fn quantize_never_exceeds_real_dimensions() {
        // Floor-rounding invariant: every quantized dimension is
        // <= the real dimension (privacy- and layout-safe direction).
        // Exception (documented): inputs less than one step report
        // one step rather than zero, which is the only direction in
        // which the report exceeds the input.
        for w in [200_u32, 350, 800, 1366, 1920, 2560, 3840] {
            for h in [100_u32, 150, 600, 720, 1080, 1440, 2160] {
                let (qw, qh) = STRICT_LETTERBOX.quantize(w, h);
                assert!(qw <= w, "qw={} > w={}", qw, w);
                assert!(qh <= h, "qh={} > h={}", qh, h);
            }
        }
    }

    #[test]
    fn quantized_dimensions_are_always_multiples_of_grid_step() {
        // Cohort property: every reported dimension is a multiple
        // of the grid step, so every Strict user landing in the
        // same bucket is indistinguishable on this surface.
        for w in 0..=400_u32 {
            for h in 0..=200_u32 {
                let (qw, qh) = STRICT_LETTERBOX.quantize(w, h);
                assert_eq!(qw % 200, 0, "qw={} not multiple of 200 (w={})", qw, w);
                assert_eq!(qh % 100, 0, "qh={} not multiple of 100 (h={})", qh, h);
            }
        }
    }

    #[test]
    fn policy_for_strict_quantizes_through_locked_static() {
        match LetterboxPolicy::for_mode(Mode::Strict) {
            LetterboxPolicy::Quantize(lb) => {
                // Address-identity check: the Strict policy points
                // at the STRICT_LETTERBOX singleton, not a copy.
                // Cohort cohesion depends on this — every Strict
                // renderer resolves to the same physical static.
                assert!(std::ptr::eq(lb, &STRICT_LETTERBOX));
            }
            other => panic!("expected Quantize(STRICT_LETTERBOX), got {:?}", other),
        }
    }

    #[test]
    fn policy_for_standard_bypasses_in_v1() {
        // v1: Standard preserves real dimensions. When the §5.5
        // coarse-bucket spec lands, this test flips to assert the
        // Standard grid.
        assert_eq!(
            LetterboxPolicy::for_mode(Mode::Standard),
            LetterboxPolicy::Bypass
        );
    }

    #[test]
    fn strict_policy_is_idempotent_and_non_loosenable() {
        // L41 lock — the API has no `with_user_override` constructor
        // for letterboxing. Two Strict resolutions are identical and
        // both point at STRICT_LETTERBOX; no path exists to flip
        // Strict to Bypass. If a future constructor lets Strict
        // resolve to Bypass, this test stays green but Module 35.4
        // settings-lock enforcement catches it.
        let a = LetterboxPolicy::for_mode(Mode::Strict);
        let b = LetterboxPolicy::for_mode(Mode::Strict);
        assert_eq!(a, b);
        assert!(matches!(a, LetterboxPolicy::Quantize(_)));
    }

    #[test]
    fn surface_all_covers_eight_accessors_plus_visual_viewport() {
        // Phase-file goal: eight accessors (Window* + Screen*).
        // Phase-file edge case: visualViewport adds a ninth pathway.
        assert_eq!(WindowDimensionSurface::ALL.len(), 9);
        for v in [
            WindowDimensionSurface::WindowInnerWidth,
            WindowDimensionSurface::WindowInnerHeight,
            WindowDimensionSurface::WindowOuterWidth,
            WindowDimensionSurface::WindowOuterHeight,
            WindowDimensionSurface::ScreenWidth,
            WindowDimensionSurface::ScreenHeight,
            WindowDimensionSurface::ScreenAvailWidth,
            WindowDimensionSurface::ScreenAvailHeight,
            WindowDimensionSurface::VisualViewport,
        ] {
            assert!(
                WindowDimensionSurface::ALL.contains(&v),
                "missing surface: {:?}",
                v
            );
        }
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // The libxul bridge matches WindowDimensionSurface to look
        // up the right accessor hook. This test exists so that
        // adding a variant without updating the bridge fails CI
        // here too — the match below is intentionally exhaustive
        // (no `_` arm).
        fn route(s: WindowDimensionSurface) -> &'static str {
            match s {
                WindowDimensionSurface::WindowInnerWidth => "window.innerWidth",
                WindowDimensionSurface::WindowInnerHeight => "window.innerHeight",
                WindowDimensionSurface::WindowOuterWidth => "window.outerWidth",
                WindowDimensionSurface::WindowOuterHeight => "window.outerHeight",
                WindowDimensionSurface::ScreenWidth => "screen.width",
                WindowDimensionSurface::ScreenHeight => "screen.height",
                WindowDimensionSurface::ScreenAvailWidth => "screen.availWidth",
                WindowDimensionSurface::ScreenAvailHeight => "screen.availHeight",
                WindowDimensionSurface::VisualViewport => "visualViewport.{width,height}",
            }
        }
        for s in WindowDimensionSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn letterbox_types_are_send_sync() {
        // The libxul bridge holds policy resolutions in
        // Arc-shared cells across renderer processes within an
        // identity group (§3.2 renderer-sharing). All public
        // letterbox types must be Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Letterbox>();
        assert_send_sync::<LetterboxPolicy>();
        assert_send_sync::<WindowDimensionSurface>();
    }
}
