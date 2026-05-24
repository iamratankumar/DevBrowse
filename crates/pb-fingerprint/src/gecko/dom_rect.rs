//! Module 35.11 — DOMRect / element-bounding-box / TextMetrics
//! cohort lock.
//!
//! Closes the per-font-rendering + per-DPI fingerprint surface
//! exposed by `Element.getClientRects()`, `getBoundingClientRect()`,
//! `Range.getClientRects()`, and `CanvasRenderingContext2D.measureText()`.
//! Sub-pixel positions and text-metrics widths reveal per-host
//! font-rendering differences (font hinting, anti-aliasing, DPI
//! snap) at higher resolution than canvas pixel readbacks — Tor
//! bug 1507879 + CreepJS probes target this surface specifically.
//!
//! **Audit provenance:** P1-4 from the 2026-05-22 comprehensive
//! audit; Best Practices agent identified this as the single
//! biggest Strict-mode gap.
//!
//! ## Mode-applicability
//!
//!   * **Strict** — every DOMRect coordinate is **snapped to
//!     integer pixels** (`x = x.round()`, etc.); every
//!     `TextMetrics.width` (and ascent / descent / bounding
//!     box fields) snaps to integer pixels. No farbling — Strict
//!     locks to a deterministic integer grid (Tor parity for
//!     bug 1507879).
//!   * **Standard** — each coordinate is farbled with a per-
//!     (origin, profile) `±1` integer pixel offset using the
//!     `FarblingSurface::DomRect` / `::TextMetrics` streams.
//!     The farbling is on TOP of integer snapping so the
//!     sub-pixel layout signal does not leak even in Standard;
//!     the per-origin farble adds the same Brave-style cross-
//!     site-tracking defense the canvas / WebGL / audio surfaces
//!     get via Module 35.5.
//!
//! ## Architecture references
//!
//!   * **L8** — Gecko WebIDL override; the DOMRect getter is
//!     patched below the JS surface so workers / iframes / SWs
//!     all see the snapped + farbled values.
//!   * **L41** — Strict integer-snap is non-loosenable.
//!   * **§5.5 + Module 35.5** — farbling streams keyed on
//!     `PartitionKey::farbling_seed`; this module re-uses the
//!     `FarblingSurface::DomRect` and `::TextMetrics` tags so the
//!     per-origin farble is byte-disjoint from canvas / WebGL /
//!     audio (cross-surface correlation defense).
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire each
//   `DomRectSurface` pathway. `Element.getClientRects()` returns
//   a `DOMRectList`; each rect's `x / y / width / height / top /
//   bottom / left / right` getters consult
//   `DomRectOverride::snap(coord, surface_tag, index)`.
//   `CanvasRenderingContext2D.measureText()` returns a
//   `TextMetrics` whose `width / actualBoundingBoxLeft /
//   actualBoundingBoxRight / actualBoundingBoxAscent /
//   actualBoundingBoxDescent / fontBoundingBoxAscent /
//   fontBoundingBoxDescent` similarly route through
//   `snap_text_metric`.
// TODO(Phase 10 / Module 71+): adversarial probes assert (a)
//   Strict observes integer-only DOMRect coords regardless of
//   sub-pixel layout; (b) Standard observes deterministic
//   per-(origin, profile) offsets within ±1 px; (c) different
//   origins under the same profile see DIFFERENT offsets
//   (cross-site-tracking defense).

use crate::farbling::{farble_canvas_byte, FarblingSeed};
use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode DOMRect / TextMetrics policy.
///
/// **Strict** snaps every coordinate to integer pixels (no
/// farbling — the integer grid IS the cohort).
///
/// **Standard** snaps to integers AND adds a per-(origin,
/// profile) `±1` px farble. The `&'static FarblingSeed` is
/// passed in by the libxul bridge (derived from
/// `PartitionKey::farbling_seed`); the override holds only the
/// mode-dispatch state, so the seed lives off the override.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomRectPolicy {
    /// Strict: integer-snap only; no farbling.
    IntegerSnapOnly,
    /// Standard: integer-snap + per-origin farble.
    SnapAndFarble,
}

impl DomRectPolicy {
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Strict => Self::IntegerSnapOnly,
            Mode::Standard => Self::SnapAndFarble,
        }
    }
}

// ── Surface enumeration ──────────────────────────────────────────────────

/// Every JS pathway through which DOMRect / TextMetrics surfaces.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomRectSurface {
    /// `Element.getClientRects()` -> `DOMRectList`.
    ElementGetClientRects,
    /// `Element.getBoundingClientRect()` -> `DOMRect`.
    ElementGetBoundingClientRect,
    /// `Range.getClientRects()` -> `DOMRectList`.
    RangeGetClientRects,
    /// `Range.getBoundingClientRect()` -> `DOMRect`.
    RangeGetBoundingClientRect,
    /// `CanvasRenderingContext2D.measureText()` -> `TextMetrics`.
    CanvasMeasureText,
    /// `SVGGraphicsElement.getBBox()` -> `DOMRect` (SVG-specific
    /// bounding-box getter; same fingerprint surface as the HTML
    /// path).
    SvgGetBBox,
}

impl DomRectSurface {
    pub const ALL: &'static [DomRectSurface] = &[
        Self::ElementGetClientRects,
        Self::ElementGetBoundingClientRect,
        Self::RangeGetClientRects,
        Self::RangeGetBoundingClientRect,
        Self::CanvasMeasureText,
        Self::SvgGetBBox,
    ];
}

// ── Snap helpers ─────────────────────────────────────────────────────────

/// Snap one DOMRect coordinate to an integer pixel and optionally
/// apply a `±1` px farble derived from `(seed, index)`.
///
/// Index discipline (avoids cross-coord collisions on the same
/// rect): the libxul bridge computes
/// `index = rect_id * 8 + field_ordinal` where `field_ordinal`
/// runs 0..=7 across `x, y, width, height, top, bottom, left,
/// right`. Different rects on the same element receive
/// independent offsets.
pub fn snap_dom_rect_coord(
    policy: DomRectPolicy,
    coord: f64,
    seed: &FarblingSeed,
    index: u64,
) -> f64 {
    let snapped = coord.round();
    match policy {
        DomRectPolicy::IntegerSnapOnly => snapped,
        DomRectPolicy::SnapAndFarble => {
            // Reuse the Canvas farble helper with surface tag
            // FarblingSurface::DomRect via the dedicated stream.
            // We borrow the canvas farble shape (`±amplitude`
            // signed offset) but the SHA-256 chain uses the
            // `DomRect` surface tag, keeping streams disjoint.
            // Amplitude = 1 px (matching the Module 35.5 canvas
            // ±1 LSB amplitude).
            let offset = farble_dom_rect_offset(seed, index, 1) as f64;
            snapped + offset
        }
    }
}

/// Snap one `TextMetrics` field (width / ascent / descent / etc.)
/// to integer pixels. Same shape as `snap_dom_rect_coord` but
/// uses the `FarblingSurface::TextMetrics` stream (disjoint from
/// DomRect / Canvas).
pub fn snap_text_metric(
    policy: DomRectPolicy,
    metric: f64,
    seed: &FarblingSeed,
    index: u64,
) -> f64 {
    let snapped = metric.round();
    match policy {
        DomRectPolicy::IntegerSnapOnly => snapped,
        DomRectPolicy::SnapAndFarble => {
            let offset = farble_text_metric_offset(seed, index, 1) as f64;
            snapped + offset
        }
    }
}

/// Per-DOMRect ±amplitude integer offset. Implementation routes
/// through `farble_canvas_byte` (shape parity) but uses the
/// DomRect surface tag via a dedicated wrapper to keep the
/// SHA-256 stream disjoint from canvas.
fn farble_dom_rect_offset(seed: &FarblingSeed, index: u64, amplitude: u8) -> i8 {
    // Use the `FarblingSurface::DomRect` tag by calling the
    // farbling crate's stream helper with the right surface.
    // The public farble_canvas_byte function hardcodes
    // FarblingSurface::Canvas; for DomRect we need a parallel
    // implementation that takes the DomRect tag. We re-use the
    // public canvas helper's algorithm (modulo bias documented
    // there); the surface tag changes via the `FarblingSurface`
    // input to `stream_byte`. Because the public
    // `farble_canvas_byte` does not take a surface parameter,
    // we route through `farble_canvas_byte` with a different
    // index to get a different stream byte — but that breaks
    // the cross-surface independence property.
    //
    // The correct fix is to expose `stream_byte` (or a similar
    // helper) publicly so this module can route through the
    // DomRect tag directly. For now we use a domain-separated
    // SHA-256 chain inline — re-implementing the byte derivation
    // with the DomRect tag in scope. (Acceptable v1 trade-off;
    // a future refactor lifts `stream_byte` to `pub`.)
    if amplitude == 0 {
        return 0;
    }
    let b = dom_rect_stream_byte(seed, index);
    let span = 2u16 * amplitude as u16 + 1;
    let bucket = (b as u16 % span) as i16;
    (bucket - amplitude as i16) as i8
}

/// Per-TextMetric ±amplitude integer offset (disjoint stream
/// from DomRect).
fn farble_text_metric_offset(seed: &FarblingSeed, index: u64, amplitude: u8) -> i8 {
    if amplitude == 0 {
        return 0;
    }
    let b = text_metric_stream_byte(seed, index);
    let span = 2u16 * amplitude as u16 + 1;
    let bucket = (b as u16 % span) as i16;
    (bucket - amplitude as i16) as i8
}

/// DomRect-tagged stream byte derivation (`FarblingSurface::DomRect`
/// = tag 0x04). Mirrors the `farbling::stream_byte` shape but
/// inlined here so this module does not depend on the (private)
/// `stream_byte` symbol.
fn dom_rect_stream_byte(seed: &FarblingSeed, index: u64) -> u8 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"PB-FARBLE-V1");
    h.update(seed);
    h.update([crate::farbling::FarblingSurface::DomRect.tag()]);
    h.update(index.to_le_bytes());
    h.finalize()[0]
}

/// TextMetrics-tagged stream byte derivation
/// (`FarblingSurface::TextMetrics` = tag 0x05).
fn text_metric_stream_byte(seed: &FarblingSeed, index: u64) -> u8 {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"PB-FARBLE-V1");
    h.update(seed);
    h.update([crate::farbling::FarblingSurface::TextMetrics.tag()]);
    h.update(index.to_le_bytes());
    h.finalize()[0]
}

/// Suppress unused-warning on the imported helper. The public
/// `farble_canvas_byte` is the reference algorithm but this
/// module uses surface-specific inlined variants to keep the
/// SHA-256 streams disjoint.
#[allow(dead_code)]
fn _reference_canvas_farble_helper_unused(seed: &FarblingSeed, index: u64, amplitude: u8) -> i8 {
    farble_canvas_byte(seed, index, amplitude)
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct DomRectOverride {
    policy: DomRectPolicy,
}

impl DomRectOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: DomRectPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> DomRectPolicy {
        self.policy
    }

    /// Snap (+ optionally farble) one DOMRect coordinate.
    pub fn snap_coord(&self, coord: f64, seed: &FarblingSeed, index: u64) -> f64 {
        snap_dom_rect_coord(self.policy, coord, seed, index)
    }

    /// Snap (+ optionally farble) one `TextMetrics` field.
    pub fn snap_text_metric(&self, metric: f64, seed: &FarblingSeed, index: u64) -> f64 {
        snap_text_metric(self.policy, metric, seed, index)
    }
}

impl FingerprintOverride for DomRectOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::DomRect
    }

    fn install(&self, _ctx: &OverrideContext) {
        let _ = (self.policy, JsContext::ALL, DomRectSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_a() -> FarblingSeed {
        [0x10; 16]
    }

    #[test]
    fn dom_rect_policy_for_mode_dispatch() {
        assert_eq!(
            DomRectPolicy::for_mode(Mode::Strict),
            DomRectPolicy::IntegerSnapOnly
        );
        assert_eq!(
            DomRectPolicy::for_mode(Mode::Standard),
            DomRectPolicy::SnapAndFarble
        );
    }

    #[test]
    fn strict_snaps_to_integer_no_farble() {
        // Strict snaps `coord.round()` and applies NO farble —
        // the integer grid is the cohort identity.
        let seed = seed_a();
        for (input, expected) in [
            (10.0, 10.0),
            (10.4, 10.0),
            (10.5, 11.0), // round-half-to-even or round-half-up; rust `round()` rounds half away from zero
            (10.6, 11.0),
            (-1.3, -1.0),
            (-1.7, -2.0),
            (0.0, 0.0),
        ] {
            let result = snap_dom_rect_coord(DomRectPolicy::IntegerSnapOnly, input, &seed, 0);
            assert_eq!(
                result, expected,
                "Strict snap of {} should be {}, got {}",
                input, expected, result
            );
        }
    }

    #[test]
    fn standard_snaps_then_adds_farble_in_bound() {
        // Standard: snapped integer + ±1 farble. Result is always
        // integer (snapped + integer offset). Output is within
        // [snapped - 1, snapped + 1].
        let seed = seed_a();
        for input in [0.0_f64, 1.5, 100.7, -5.3] {
            for index in 0..50_u64 {
                let result = snap_dom_rect_coord(DomRectPolicy::SnapAndFarble, input, &seed, index);
                let snapped = input.round();
                let delta = (result - snapped).abs();
                assert!(
                    delta <= 1.0,
                    "Standard snap+farble({}) should be within ±1 of round({})={}; got {}",
                    input,
                    input,
                    snapped,
                    result,
                );
                // Result must be integer (snapped + integer offset).
                assert_eq!(
                    result,
                    result.round(),
                    "result {} should be integer",
                    result
                );
            }
        }
    }

    #[test]
    fn standard_farble_is_deterministic_per_seed_index() {
        // Same seed + same index = same farbled output (cohort
        // contract).
        let seed = seed_a();
        for index in 0..30_u64 {
            let a = snap_dom_rect_coord(DomRectPolicy::SnapAndFarble, 100.0, &seed, index);
            let b = snap_dom_rect_coord(DomRectPolicy::SnapAndFarble, 100.0, &seed, index);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn dom_rect_and_text_metric_streams_are_disjoint() {
        // Cross-surface independence: same seed + same index
        // should produce different offsets on DomRect vs
        // TextMetrics streams (FarblingSurface::DomRect tag 0x04
        // vs FarblingSurface::TextMetrics tag 0x05). Most indices
        // should disagree.
        let seed = seed_a();
        let mut disagree = 0;
        for i in 0..200_u64 {
            let dr = snap_dom_rect_coord(DomRectPolicy::SnapAndFarble, 100.0, &seed, i);
            let tm = snap_text_metric(DomRectPolicy::SnapAndFarble, 100.0, &seed, i);
            if dr != tm {
                disagree += 1;
            }
        }
        // ±1 farble = 3 buckets; matching by chance is ~1/3.
        // Expect at least 80/200 disagreements (40%).
        assert!(
            disagree > 80,
            "DomRect and TextMetrics streams should differ on most indices; saw {}/200 disagreement",
            disagree,
        );
    }

    #[test]
    fn standard_different_seeds_diverge() {
        // Per-(origin, profile) cohort: different seeds (different
        // origins) produce different farbled outputs for the same
        // index. Cross-site tracking defense.
        let seed_x = [0x10; 16];
        let seed_y = [0x20; 16];
        let mut disagree = 0;
        for i in 0..200_u64 {
            let x = snap_dom_rect_coord(DomRectPolicy::SnapAndFarble, 100.0, &seed_x, i);
            let y = snap_dom_rect_coord(DomRectPolicy::SnapAndFarble, 100.0, &seed_y, i);
            if x != y {
                disagree += 1;
            }
        }
        assert!(
            disagree > 80,
            "different seeds should produce different farbled output for most indices; saw {}/200",
            disagree,
        );
    }

    #[test]
    fn dom_rect_surface_all_covers_phase_file_pathways() {
        // 4 DOMRect pathways (Element x 2, Range x 2) + 1
        // TextMetrics + 1 SVG = 6.
        assert_eq!(DomRectSurface::ALL.len(), 6);
        for v in [
            DomRectSurface::ElementGetClientRects,
            DomRectSurface::ElementGetBoundingClientRect,
            DomRectSurface::RangeGetClientRects,
            DomRectSurface::RangeGetBoundingClientRect,
            DomRectSurface::CanvasMeasureText,
            DomRectSurface::SvgGetBBox,
        ] {
            assert!(DomRectSurface::ALL.contains(&v));
        }
    }

    #[test]
    fn override_reports_dom_rect_surface() {
        assert_eq!(
            DomRectOverride::new(Mode::Strict).surface(),
            WebIdlSurface::DomRect
        );
        assert_eq!(
            DomRectOverride::new(Mode::Standard).surface(),
            WebIdlSurface::DomRect
        );
    }

    #[test]
    fn override_install_is_context_inert() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035110").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = DomRectOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
        }
    }

    #[test]
    fn dom_rect_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DomRectOverride>();
        assert_send_sync::<DomRectPolicy>();
        assert_send_sync::<DomRectSurface>();
    }

    #[test]
    fn policy_and_surface_dispatch_is_exhaustive_friendly() {
        fn arm_policy(p: DomRectPolicy) -> &'static str {
            match p {
                DomRectPolicy::IntegerSnapOnly => "snap-only",
                DomRectPolicy::SnapAndFarble => "snap-and-farble",
            }
        }
        fn arm_surface(s: DomRectSurface) -> &'static str {
            match s {
                DomRectSurface::ElementGetClientRects => "element-get-client-rects",
                DomRectSurface::ElementGetBoundingClientRect => "element-get-bounding-client-rect",
                DomRectSurface::RangeGetClientRects => "range-get-client-rects",
                DomRectSurface::RangeGetBoundingClientRect => "range-get-bounding-client-rect",
                DomRectSurface::CanvasMeasureText => "canvas-measure-text",
                DomRectSurface::SvgGetBBox => "svg-get-b-box",
            }
        }
        for s in DomRectSurface::ALL {
            assert!(!arm_surface(*s).is_empty());
        }
        assert_eq!(
            arm_policy(DomRectPolicy::for_mode(Mode::Strict)),
            "snap-only"
        );
        assert_eq!(
            arm_policy(DomRectPolicy::for_mode(Mode::Standard)),
            "snap-and-farble"
        );
    }
}
