//! Module 27 — Canvas readback normalization.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the readback
//!     pathway is intercepted below the JS surface so worker
//!     `OffscreenCanvas` and frame `HTMLCanvasElement` share a
//!     single policy.
//!   * **§3.3 / L9** — "max fingerprint normalization" is a
//!     **Strict-only** feature. Standard preserves the native Gecko
//!     render path (cohort-by-choice: a user picking Standard
//!     accepts a different cohort than Strict; this matches Module
//!     25 WebRTC Disabled-vs-PerSitePermission, Module 30 fonts
//!     Tor-allowlist-vs-bucketed, Module 32 timers 100ms-vs-1ms,
//!     Module 33 timezone UTC-vs-host).
//!   * **§5.5** — central fingerprint bucketing: every Strict-mode
//!     pixel readback routes through one `CanvasRenderProfile`.
//!   * **threat-model A1** — HTML5 canvas font rasterization is the
//!     textbook fingerprint vector (per-GPU / per-driver / per-AA-
//!     mode pixel deltas; the Strict cohort splits without
//!     normalization).
//!
//! ## Locked decision (phase-5 Goal)
//!
//! **Strict pre-rasterization through a normalized font + render
//! path. No per-user noise.** Within the Strict cohort, identical
//! canvas operations produce byte-identical pixel output across
//! every DevBrowse user. Standard does not normalize — its readback
//! flows through the native Gecko rasterizer unmodified.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * The locked rasterizer parameter set (`CanvasRenderProfile`)
//!     that the libxul-side canvas hook consults at readback time
//!     **when the per-renderer policy is `NormalizedRasterizer`
//!     (Strict)**.
//!   * The enumeration of every readback pathway (`CanvasSurface`)
//!     the Gecko bridge must wire — the edge cases section of the
//!     phase file lifted into a typed list so a future libxul-tag
//!     bump cannot silently miss one.
//!   * A `FingerprintOverride` impl for `WebIdlSurface::Canvas` so
//!     the libxul bridge has a single registration point regardless
//!     of mode. `install()` for a Standard-mode override is a
//!     deliberate no-op (the native rasterizer stays in place).
//!
//! It IS NOT:
//!   * The rasterizer itself. The actual Skia/Cairo replacement
//!     lives in libxul; this module pins the parameters the Strict
//!     replacement must honor.
//!   * The bundled-font set. Module 30 owns the font allowlist;
//!     `CanvasRenderProfile::font_set` is a reference label that
//!     Module 30 resolves to the actual font list.
//!   * The WebGL parameter surface. Module 28 covers
//!     `RENDERER` / `VENDOR` / etc.; `CanvasSurface::WebGlReadPixels`
//!     is here only because pixel readback shares the same render
//!     profile regardless of which JS API surfaced it.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): the rasterizer replacement
//   is a Gecko-side change that lands alongside the libxul tag.
//   `CanvasOverride::install`
//   currently has no side effects because the FFI hook is not yet
//   live; once libxul is wired, Strict-mode install() will register
//   a per-renderer callback that returns &LOCKED_CANVAS_PROFILE on
//   demand, and Standard-mode install() will remain a no-op.
// Module 30 has shipped: `CanvasRenderProfile::font_set` is now
//   `&'static BundledFontSet` pointing at `BUNDLED_FONT_SET_V1`.
//   The canvas + fonts Strict cohorts are unified by address identity
//   (see `tests::locked_profile_font_set_unifies_with_module_30`).
// Module 28 (WebGL) has shipped: `LOCKED_CANVAS_PROFILE` is shared
//   into `WebGlReadbackPolicy` so `WebGLRenderingContext.readPixels`
//   uses the same Strict profile and the Strict cohort is unsplit
//   by readback API. Address-identity assertion (`std::ptr::eq`
//   against `&LOCKED_CANVAS_PROFILE`) lives in webgl.rs tests.
// TODO(Phase 6 / pb-gpu): Strict-mode Canvas 2D rasterization MUST
//   stay on CPU (`LOCKED_CANVAS_PROFILE.rasterizer = Rasterizer::Cpu`)
//   even when pb-gpu offers a GPU-accelerated 2D path. Routing
//   Strict Canvas 2D through the GPU pipeline silently splits the
//   cohort along driver-version lines. Phase 6 implementers: do not
//   add an opt-in GPU rasterizer for Canvas 2D without a Mode gate.

use crate::gecko::fonts::{BundledFontSet, BUNDLED_FONT_SET_V1};
use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked rasterizer parameters (Strict cohort) ──────────────────────────

/// Anti-aliasing mode used by the normalized rasterizer.
///
/// `SubpixelRgb` / `SubpixelBgr` are intentionally forbidden in the
/// locked profile because sub-pixel AA depends on monitor
/// RGB / BGR layout, which is per-host and splits the cohort.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AntialiasMode {
    None,
    Grayscale,
    SubpixelRgb,
    SubpixelBgr,
}

/// Font-hinting mode. Hinting introduces hardware-dependent
/// per-glyph deltas; the locked profile uses `None`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HintingMode {
    None,
    Slight,
    Full,
}

/// Whether the rasterizer runs on the GPU or in software. The
/// locked profile pins `Cpu` because GPU rasterizers vary by driver
/// version and split the cohort along driver-version lines.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rasterizer {
    Cpu,
    Gpu,
}

/// Color space. The locked profile pins sRGB because
/// `DisplayP3` / `Linear` outputs reveal the host's color-managed
/// monitor and split the cohort.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColorSpace {
    SRgb,
    DisplayP3,
    Linear,
}

/// Pixel-snapping rule for stroke / fill paths. The locked profile
/// pins `SnapToInteger` because sub-pixel positioning rounding
/// differs between vendors' rasterizers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PixelSnap {
    None,
    SnapToInteger,
}

/// Locked rasterizer parameter bundle for the Strict cohort. The
/// libxul-side canvas hook consults this on every Strict-mode
/// readback so all Strict DevBrowse renderers produce identical
/// pixel output for identical inputs.
///
/// `Copy` is intentional — the profile is a value type read on
/// every readback, never a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanvasRenderProfile {
    /// Cohort-locked bundled font set. References the same
    /// `BUNDLED_FONT_SET_V1` static that Module 30's
    /// `FontsEnumerationPolicy::LockedAllowlist` returns under
    /// Strict, so the canvas-rasterizer cohort and the
    /// font-enumeration cohort cannot drift apart. Assert by
    /// `std::ptr::eq(font_set, &BUNDLED_FONT_SET_V1)`.
    pub font_set: &'static BundledFontSet,
    pub antialias: AntialiasMode,
    pub hinting: HintingMode,
    pub rasterizer: Rasterizer,
    pub color_space: ColorSpace,
    pub pixel_snap: PixelSnap,
}

/// The single cohort-safe profile for Strict mode. Standard does
/// NOT use this — see [`CanvasReadbackPolicy::for_mode`].
///
/// `static` (not `const`): callers compare `&'static` references by
/// address (`std::ptr::eq`) to prove every Strict consumer is
/// reading the same singleton. `const` items can be constant-folded
/// so each `&LOCKED_CANVAS_PROFILE` site receives a fresh address,
/// which silently weakens the Strict-cohort-safety invariant.
pub static LOCKED_CANVAS_PROFILE: CanvasRenderProfile = CanvasRenderProfile {
    font_set: &BUNDLED_FONT_SET_V1,
    antialias: AntialiasMode::Grayscale,
    hinting: HintingMode::None,
    rasterizer: Rasterizer::Cpu,
    color_space: ColorSpace::SRgb,
    pixel_snap: PixelSnap::SnapToInteger,
};

// ── Per-mode readback policy ──────────────────────────────────────────────

/// Per-mode canvas readback policy.
///
/// **v1.23 amiunique-generic refactor (Phase 5.5 Module 35.5):** both
/// modes resolve to the same `Normalized` variant carrying
/// `LOCKED_CANVAS_PROFILE` (cohort identity is unified — every
/// DevBrowse user appears in the same canvas-rasterizer cohort on
/// amiunique). Modes differ only in the `farbling` field:
///   * Strict → `farbling: None` — pure cohort lock; every Strict
///     user sees byte-identical readback (Tor / Mullvad posture).
///   * Standard → `farbling: Some(&STANDARD_FARBLING_PROFILE)` —
///     same cohort base PLUS per-(origin, IdentityProfile) ±1 LSB
///     noise on each readback byte (Brave+-grade cross-site
///     protection while same-site identity stays stable across
///     browser restarts).
///
/// Supersedes the v1.12 `NativePassThrough` / `NormalizedRasterizer`
/// two-variant shape. Standard no longer pass-throughs — it now
/// activates the rasterizer hook with the farbling layer on top.
///
/// `Eq` / `Hash` intentionally NOT derived: `FarblingProfile`
/// carries an `f32` (audio amplitude) that does not satisfy `Eq`
/// (`NaN != NaN` per IEEE 754). The policy is still `PartialEq`
/// so tests can compare values, but it cannot be used as a
/// `HashMap` key. Mirrors the `AudioReadbackPolicy` convention
/// established when `AudioProfile.f32_quantization_step` landed
/// in v1.14.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CanvasReadbackPolicy {
    /// Canvas readback flows through the libxul rasterizer hook
    /// producing deterministic pixels using `profile`. When
    /// `farbling.is_some()`, the per-byte ±LSB noise from
    /// `farbling` is applied on top using a seed derived from the
    /// partition_key (see `pb_storage::PartitionKey::farbling_seed`
    /// and `crate::farbling`).
    Normalized {
        profile: &'static CanvasRenderProfile,
        farbling: Option<&'static crate::farbling::FarblingProfile>,
    },
}

impl CanvasReadbackPolicy {
    /// Locked snapshot for `mode` (v1.23):
    ///   * `Mode::Standard` -> `Normalized { profile: &LOCKED_CANVAS_PROFILE, farbling: Some(&STANDARD_FARBLING_PROFILE) }`
    ///   * `Mode::Strict`   -> `Normalized { profile: &LOCKED_CANVAS_PROFILE, farbling: None }`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Normalized {
                profile: &LOCKED_CANVAS_PROFILE,
                farbling: Some(&crate::farbling::STANDARD_FARBLING_PROFILE),
            },
            Mode::Strict => Self::Normalized {
                profile: &LOCKED_CANVAS_PROFILE,
                farbling: None,
            },
        }
    }

    /// The rasterizer profile this policy uses. Always
    /// `&LOCKED_CANVAS_PROFILE` after the v1.23 refactor — both
    /// modes share the cohort base.
    pub fn profile(&self) -> &'static CanvasRenderProfile {
        match self {
            Self::Normalized { profile, .. } => profile,
        }
    }

    /// The farbling profile this policy carries, if any. `None`
    /// in Strict (pure cohort lock), `Some` in Standard
    /// (per-(origin, profile_id) noise on dynamic readbacks).
    pub fn farbling(&self) -> Option<&'static crate::farbling::FarblingProfile> {
        match self {
            Self::Normalized { farbling, .. } => *farbling,
        }
    }

    /// True iff the libxul rasterizer hook will be activated for
    /// this policy. After the v1.23 refactor this is `true` for
    /// both modes — both share the cohort-base rasterizer.
    pub fn normalizes(&self) -> bool {
        matches!(self, Self::Normalized { .. })
    }
}

// ── Readback-pathway enumeration ──────────────────────────────────────────

/// Every JS API pathway that can read back canvas pixels.
///
/// The libxul bridge MUST register the normalized rasterizer behind
/// every variant **for Strict-mode renderers** — missing one leaves
/// a Strict readback channel that bypasses the cohort-safe profile
/// (a privacy regression). This enum lifts the phase-file edge-case
/// list (worker-context OffscreenCanvas / ImageBitmap pathway /
/// WebGL readPixels) into a typed list so a future libxul-tag bump
/// cannot silently miss a new pathway — see the exhaustive-match
/// contract on `WebIdlSurface` (Module 26 interface.rs).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CanvasSurface {
    /// `CanvasRenderingContext2D.getImageData`.
    GetImageData,
    /// `HTMLCanvasElement.toDataURL`.
    ToDataUrl,
    /// `HTMLCanvasElement.toBlob`.
    ToBlob,
    /// Worker-context `OffscreenCanvasRenderingContext2D.getImageData`.
    /// Worker scope is separately exposed in JS — see Module 26
    /// `JsContext::DedicatedWorker` / `SharedWorker`.
    OffscreenGetImageData,
    /// Worker-context `OffscreenCanvas.convertToBlob`.
    OffscreenConvertToBlob,
    /// `createImageBitmap(canvas)` — the ImageBitmap pathway can
    /// surface raw pixels via subsequent operations, so it routes
    /// through the same profile.
    CreateImageBitmap,
    /// `WebGLRenderingContext.readPixels`. The WebGL parameter
    /// surface is Module 28's; this pathway is here because pixel
    /// readback shares the rasterizer profile.
    WebGlReadPixels,
}

impl CanvasSurface {
    /// Every readback pathway the bridge must wire. Asserted
    /// against the phase-file edge-case list by
    /// `tests::canvas_surface_all_covers_edge_cases`.
    pub const ALL: &'static [CanvasSurface] = &[
        Self::GetImageData,
        Self::ToDataUrl,
        Self::ToBlob,
        Self::OffscreenGetImageData,
        Self::OffscreenConvertToBlob,
        Self::CreateImageBitmap,
        Self::WebGlReadPixels,
    ];
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Canvas`.
///
/// Construct with `CanvasOverride::new(mode)` so the policy is
/// resolved once at construction; the override is then registered
/// by the libxul bridge into every `JsContext` for the renderer.
///
/// Mode-divergent behavior is in the *policy*, not the *trait*:
/// every renderer registers a `CanvasOverride`, but Strict-mode
/// `install` activates the normalized rasterizer and Standard-mode
/// `install` is a no-op. Keeping the registration structurally
/// uniform across modes means the bridge has one code path.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data, so `install(&OverrideContext)` produces
/// observationally identical state regardless of `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct CanvasOverride {
    policy: CanvasReadbackPolicy,
}

impl CanvasOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: CanvasReadbackPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> CanvasReadbackPolicy {
        self.policy
    }

    /// The rasterizer profile this override pins. Always
    /// `&LOCKED_CANVAS_PROFILE` after the v1.23 amiunique-generic
    /// refactor — both modes share the cohort-base rasterizer.
    /// Strict and Standard diverge only on the policy's farbling
    /// slot (`policy().farbling()`).
    pub fn profile(&self) -> &'static CanvasRenderProfile {
        self.policy.profile()
    }
}

impl FingerprintOverride for CanvasOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Canvas
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect on either branch. The libxul rasterizer
        // hook is not yet wired (see crate-level TODO). When the FFI
        // lands:
        //   * NormalizedRasterizer(p) -> register a per-renderer
        //     callback returning `p` on demand.
        //   * NativePassThrough       -> remain a no-op; the native
        //     rasterizer stays in place for Standard.
        let _ = (self.policy, JsContext::ALL);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_profile_matches_strict_cohort_parameters() {
        // The exact locked values are the v1 Strict-cohort definition.
        // Changing any of these is a cohort shift and triggers the
        // Adaptation protocol (README §Adaptation).
        assert_eq!(LOCKED_CANVAS_PROFILE.font_set.label, "devbrowse-bundled-v1");
        assert_eq!(LOCKED_CANVAS_PROFILE.antialias, AntialiasMode::Grayscale);
        assert_eq!(LOCKED_CANVAS_PROFILE.hinting, HintingMode::None);
        assert_eq!(LOCKED_CANVAS_PROFILE.rasterizer, Rasterizer::Cpu);
        assert_eq!(LOCKED_CANVAS_PROFILE.color_space, ColorSpace::SRgb);
        assert_eq!(LOCKED_CANVAS_PROFILE.pixel_snap, PixelSnap::SnapToInteger);
    }

    #[test]
    fn locked_profile_font_set_unifies_with_module_30() {
        // Cross-module cohort-unification invariant: the canvas
        // rasterizer's bundled-font set is the exact same static
        // Module 30's Strict allowlist returns. Address identity
        // is the regression test — equal-by-value would silently
        // pass if a future change cloned the struct.
        assert!(std::ptr::eq(
            LOCKED_CANVAS_PROFILE.font_set,
            &BUNDLED_FONT_SET_V1,
        ));
    }

    #[test]
    fn standard_resolves_to_cohort_base_with_farbling() {
        // v1.23 amiunique-generic refactor: Standard shares the
        // Strict cohort base AND carries STANDARD_FARBLING_PROFILE
        // for per-(origin, profile_id) noise on dynamic readbacks.
        let p = CanvasReadbackPolicy::for_mode(Mode::Standard);
        assert!(matches!(p, CanvasReadbackPolicy::Normalized { .. }));
        assert!(std::ptr::eq(p.profile(), &LOCKED_CANVAS_PROFILE));
        let f = p
            .farbling()
            .expect("Standard MUST carry a farbling profile");
        assert!(std::ptr::eq(f, &crate::farbling::STANDARD_FARBLING_PROFILE));
        assert!(p.normalizes());
    }

    #[test]
    fn strict_resolves_to_cohort_base_without_farbling() {
        // v1.23: Strict shares the same cohort base (address
        // identity vs LOCKED_CANVAS_PROFILE) but carries
        // farbling=None — pure cohort lock, every Strict user
        // sees byte-identical readback (Tor / Mullvad posture).
        let p = CanvasReadbackPolicy::for_mode(Mode::Strict);
        assert!(matches!(p, CanvasReadbackPolicy::Normalized { .. }));
        assert!(std::ptr::eq(p.profile(), &LOCKED_CANVAS_PROFILE));
        assert_eq!(p.farbling(), None);
        assert!(p.normalizes());
    }

    #[test]
    fn standard_and_strict_share_canvas_cohort_base() {
        // v1.23 cohort unification: the rasterizer profile is the
        // exact same static in both modes (address identity).
        let s = CanvasReadbackPolicy::for_mode(Mode::Standard);
        let r = CanvasReadbackPolicy::for_mode(Mode::Strict);
        assert!(std::ptr::eq(s.profile(), r.profile()));
        // Modes diverge ONLY on farbling.
        assert!(s.farbling().is_some());
        assert!(r.farbling().is_none());
    }

    #[test]
    fn canvas_surface_all_covers_edge_cases() {
        // Phase-file edge cases for Module 27:
        //   - worker-context OffscreenCanvas
        //   - ImageBitmap pathway
        //   - WebGLRenderingContext.readPixels
        // Plus the obvious top-frame pathways (GetImageData /
        // ToDataUrl / ToBlob). Adding a new readback API to the
        // platform requires a variant here and breaks this test
        // until the bridge gains the corresponding plumb-in.
        assert_eq!(CanvasSurface::ALL.len(), 7);

        for v in [
            CanvasSurface::GetImageData,
            CanvasSurface::ToDataUrl,
            CanvasSurface::ToBlob,
            CanvasSurface::OffscreenGetImageData,
            CanvasSurface::OffscreenConvertToBlob,
            CanvasSurface::CreateImageBitmap,
            CanvasSurface::WebGlReadPixels,
        ] {
            assert!(CanvasSurface::ALL.contains(&v), "missing pathway: {:?}", v);
        }
    }

    #[test]
    fn canvas_override_reports_canvas_surface_under_both_modes() {
        // The bridge registers under WebIdlSurface::Canvas regardless
        // of mode (uniform registration; mode-divergence is in the
        // policy).
        assert_eq!(
            CanvasOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Canvas
        );
        assert_eq!(
            CanvasOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Canvas
        );
    }

    #[test]
    fn both_overrides_carry_the_locked_profile_v1_23() {
        // v1.23 refactor: both modes share LOCKED_CANVAS_PROFILE.
        // Module 27's prior "Standard has no profile" assertion
        // is superseded — modes now differ only on the farbling
        // layer carried by CanvasReadbackPolicy.
        let standard = CanvasOverride::new(Mode::Standard);
        let strict = CanvasOverride::new(Mode::Strict);
        assert!(std::ptr::eq(standard.profile(), &LOCKED_CANVAS_PROFILE));
        assert!(std::ptr::eq(strict.profile(), &LOCKED_CANVAS_PROFILE));
        // Per-mode divergence is on the farbling slot inside the policy:
        assert!(standard.policy().farbling().is_some());
        assert_eq!(strict.policy().farbling(), None);
    }

    #[test]
    fn canvas_override_install_is_context_inert() {
        // Edge case: override must be inert in iframe / worker /
        // service-worker / dedicated-worker. Drive install across
        // every JsContext for both modes and assert observed state
        // (the policy + surface) does not vary across contexts.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000027").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = CanvasOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Canvas);
        }
    }

    #[test]
    fn canvas_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CanvasOverride>();
        assert_send_sync::<CanvasReadbackPolicy>();
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // Mirror of the Module 26 exhaustive-match contract for
        // CanvasSurface. The bridge MUST match without a `_` arm
        // so a new pathway added to the enum fails compilation
        // until the bridge wires it.
        fn route(s: CanvasSurface) -> &'static str {
            match s {
                CanvasSurface::GetImageData => "get-image-data",
                CanvasSurface::ToDataUrl => "to-data-url",
                CanvasSurface::ToBlob => "to-blob",
                CanvasSurface::OffscreenGetImageData => "offscreen-get-image-data",
                CanvasSurface::OffscreenConvertToBlob => "offscreen-convert-to-blob",
                CanvasSurface::CreateImageBitmap => "create-image-bitmap",
                CanvasSurface::WebGlReadPixels => "webgl-read-pixels",
            }
        }
        for s in CanvasSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // The libxul bridge will match on CanvasReadbackPolicy to
        // decide whether to register the rasterizer hook. Lock in
        // the exhaustive-match contract here so a future variant
        // (e.g. a "RequiresGesture" Strict sub-mode) cannot be
        // silently treated as native pass-through.
        fn arm(p: CanvasReadbackPolicy) -> &'static str {
            match p {
                CanvasReadbackPolicy::Normalized { farbling: None, .. } => "cohort-locked",
                CanvasReadbackPolicy::Normalized {
                    farbling: Some(_), ..
                } => "cohort-locked-farbled",
            }
        }
        assert_eq!(
            arm(CanvasReadbackPolicy::for_mode(Mode::Standard)),
            "cohort-locked-farbled",
        );
        assert_eq!(
            arm(CanvasReadbackPolicy::for_mode(Mode::Strict)),
            "cohort-locked",
        );
    }
}
