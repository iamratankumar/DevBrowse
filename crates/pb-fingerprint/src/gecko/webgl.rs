//! Module 28 — WebGL parameter normalization.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the
//!     `WebGLRenderingContext.getParameter` /
//!     `WebGLRenderingContext.getSupportedExtensions` /
//!     `WebGLRenderingContext.getExtension` / `WebGL2RenderingContext.*`
//!     pathways are intercepted below the JS surface so worker
//!     `OffscreenCanvas` WebGL contexts share a single policy.
//!   * **§3.3 / L9** — "max fingerprint normalization" is a
//!     **Strict-only** feature. Standard preserves the native Gecko
//!     WebGL parameter readout (cohort-by-choice: a user picking
//!     Standard accepts a different cohort than Strict; matches
//!     Modules 25 / 27 / 30 / 32 / 33). Firefox already restricts
//!     `WEBGL_debug_renderer_info` to privileged contexts by default
//!     (`webgl.enable-debug-renderer-info = false`), so "native
//!     Gecko" in Standard inherits that floor without DevBrowse
//!     adding a separate carve-out.
//!   * **§5.5** — central fingerprint bucketing: every Strict-mode
//!     WebGL parameter readout routes through one `WebGlProfile`,
//!     and the Strict `readPixels` pathway reuses
//!     `LOCKED_CANVAS_PROFILE` from Module 27 so the Strict cohort
//!     is not split by readback-API choice.
//!   * **threat-model A1** — `UNMASKED_RENDERER` / `UNMASKED_VENDOR`
//!     leak the exact GPU + driver version (one of the highest-
//!     entropy passive fingerprint surfaces). Timer-query extensions
//!     (`EXT_disjoint_timer_query` / `EXT_disjoint_timer_query_webgl2`)
//!     bypass L43's 100 ms timer floor and provide a high-resolution
//!     GPU clock.
//!
//! ## Locked decision (phase-5 Goal + Mode-applicability)
//!
//! **Strict-only cohort lock.** Within the Strict cohort, every
//! WebGL parameter returns the same `LOCKED_WEBGL_PROFILE` value
//! across every DevBrowse user; the extension list is the curated
//! Strict allowlist; `WEBGL_debug_renderer_info` and the two timer-
//! query extensions are absent from the allowlist; `readPixels` is
//! routed through `LOCKED_CANVAS_PROFILE` (Module 27 dependency).
//! Standard does not normalize — its WebGL parameter readout flows
//! through the native Gecko surface unchanged.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * The locked WebGL parameter bundle (`WebGlProfile`) the
//!     libxul-side WebGL hook consults at readback time **when the
//!     per-renderer policy is `NormalizedProfile` (Strict)**.
//!   * The enumeration of every parameter pathway (`WebGlParameter`)
//!     the Gecko bridge must wire, lifted from the phase-file Goal
//!     into a typed list so a future libxul-tag bump cannot silently
//!     miss one.
//!   * The enumeration of every extension that MUST be absent from
//!     the Strict allowlist (`WebGlBlockedExtension`) — typed so a
//!     regression test catches an allowlist that accidentally
//!     re-includes one.
//!   * A `FingerprintOverride` impl for `WebIdlSurface::WebGl` so
//!     the libxul bridge has a single registration point regardless
//!     of mode. `install()` for a Standard-mode override is a
//!     deliberate no-op (the native parameter readout stays in place).
//!
//! It IS NOT:
//!   * The libxul WebGL hook itself. The actual `getParameter` /
//!     `getSupportedExtensions` / `getExtension` interception lives
//!     in libxul; this module pins the values the Strict hook must
//!     honor.
//!   * The Strict `readPixels` rasterizer. That belongs to Module 27
//!     (`LOCKED_CANVAS_PROFILE`); this module references the
//!     singleton so the Strict cohort stays unified across readback
//!     APIs.
//!   * A full WebGL extension audit. The v1 allowlist is a
//!     conservative minimal set; the full curated list ratifies
//!     against the Phase 10 adversarial fingerprint suite. Bumps to
//!     the allowlist go through the cohort-watch adaptation protocol
//!     (README §Adaptation protocol).

// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): the WebGL hook replacement
//   is a Gecko-side change that lands alongside the libxul tag.
//   `WebGlOverride::install` currently has no side effects because
//   the FFI hook is not yet live; once libxul is wired, Strict-mode
//   install() will register a per-renderer callback that returns
//   &LOCKED_WEBGL_PROFILE on demand for `getParameter` /
//   `getSupportedExtensions`, blocks `getExtension` lookups against
//   WebGlBlockedExtension::ALL, and routes `readPixels` through
//   `LOCKED_CANVAS_PROFILE`. Standard-mode install() will remain a
//   no-op.
// TODO(Phase 10 / adversarial suite): ratify the Strict extension
//   allowlist against CreepJS + FPStandard + Disconnect probes. The
//   v1 list here is the minimal conservative cohort; widening it
//   needs adversarial-suite sign-off so a new extension does not
//   silently leak GPU identity (e.g. `WEBGL_compressed_texture_*`
//   support varies by GPU family).
// TODO(Phase 6 / pb-gpu): Strict-mode WebGL contexts MUST stay on
//   the same cohort-safe backend. Routing Strict WebGL through a
//   pb-gpu-managed GPU adapter without a Mode gate would re-leak
//   the driver identity that `WEBGL_debug_renderer_info` blocks.
//   Phase 6 implementers: any GPU-adapter selection that varies per
//   host hardware is a Strict cohort split.

use crate::gecko::canvas::{CanvasRenderProfile, LOCKED_CANVAS_PROFILE};
use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked WebGL parameter bundle (Strict cohort) ─────────────────────────

/// JS-observable WebGL parameter the libxul bridge must hook.
///
/// Every variant corresponds to a `getParameter` argument or a
/// dedicated method (`getSupportedExtensions` / `getExtension`) the
/// Strict hook must intercept. Adding a new variant is the contract
/// handshake with libxul: a parameter that the bridge does not wire
/// is silently inert and a privacy regression.
///
/// The enum is `#[non_exhaustive]` because Strict-mode coverage
/// expands as new high-entropy WebGL parameters are identified
/// (e.g. WebGL 2 adds `MAX_DRAW_BUFFERS`, `MAX_COLOR_ATTACHMENTS`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebGlParameter {
    /// `WebGLRenderingContext.getParameter(VENDOR)`.
    Vendor,
    /// `WebGLRenderingContext.getParameter(RENDERER)`.
    Renderer,
    /// `WebGLRenderingContext.getParameter(VERSION)`.
    Version,
    /// `WebGLRenderingContext.getParameter(SHADING_LANGUAGE_VERSION)`.
    ShadingLanguageVersion,
    /// `WebGLRenderingContext.getSupportedExtensions()` — the full
    /// extension allowlist, returned as a `Sequence<DOMString>`.
    SupportedExtensions,
    /// `WebGLRenderingContext.getParameter(MAX_TEXTURE_SIZE)`.
    MaxTextureSize,
    /// `WebGLRenderingContext.getParameter(MAX_VIEWPORT_DIMS)`.
    MaxViewportDims,
    /// `WebGLRenderingContext.getParameter(MAX_VERTEX_UNIFORM_VECTORS)`.
    MaxVertexUniformVectors,
    /// `WebGLRenderingContext.getParameter(MAX_FRAGMENT_UNIFORM_VECTORS)`.
    MaxFragmentUniformVectors,
    /// `WebGLRenderingContext.getParameter(MAX_VARYING_VECTORS)`.
    MaxVaryingVectors,
    /// `WebGLRenderingContext.getParameter(MAX_VERTEX_ATTRIBS)`.
    MaxVertexAttribs,
    /// `WebGLRenderingContext.getParameter(MAX_RENDERBUFFER_SIZE)`.
    MaxRenderbufferSize,
    /// `WebGLRenderingContext.getParameter(MAX_COMBINED_TEXTURE_IMAGE_UNITS)`.
    MaxCombinedTextureImageUnits,
    /// `WebGLRenderingContext.readPixels` — the pixel-readback
    /// pathway. The Strict hook routes this through
    /// `LOCKED_CANVAS_PROFILE` (Module 27 dependency) so the Strict
    /// cohort is not split by readback-API choice. This variant is
    /// owned by Module 28 at the WebIDL hook level but consults the
    /// Module 27 profile for actual pixel normalization.
    ReadPixels,
}

impl WebGlParameter {
    /// Every WebGL parameter / pathway the FFI bridge must wire.
    /// Asserted against the phase-file edge-case list by
    /// `tests::webgl_parameter_all_covers_edge_cases`.
    pub const ALL: &'static [WebGlParameter] = &[
        Self::Vendor,
        Self::Renderer,
        Self::Version,
        Self::ShadingLanguageVersion,
        Self::SupportedExtensions,
        Self::MaxTextureSize,
        Self::MaxViewportDims,
        Self::MaxVertexUniformVectors,
        Self::MaxFragmentUniformVectors,
        Self::MaxVaryingVectors,
        Self::MaxVertexAttribs,
        Self::MaxRenderbufferSize,
        Self::MaxCombinedTextureImageUnits,
        Self::ReadPixels,
    ];
}

/// WebGL extension that MUST be absent from the Strict allowlist.
///
/// Each variant is a known fingerprint or timing-side-channel vector.
/// The `WebGlProfile::extensions` allowlist is asserted disjoint from
/// `WebGlBlockedExtension::ALL` by
/// `tests::extensions_allowlist_does_not_include_blocked_extensions`.
/// This is the regression-test surface: a future allowlist widening
/// that re-includes any of these breaks the build.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebGlBlockedExtension {
    /// `WEBGL_debug_renderer_info` — exposes `UNMASKED_VENDOR_WEBGL`
    /// and `UNMASKED_RENDERER_WEBGL`, leaking the exact GPU + driver
    /// string (one of the highest-entropy passive fingerprint
    /// vectors). Firefox restricts this to privileged contexts by
    /// default; Strict keeps the restriction unconditional.
    DebugRendererInfo,
    /// `EXT_disjoint_timer_query` — high-resolution GPU clock that
    /// bypasses L43's 100 ms Strict timer floor and reveals
    /// per-driver timing characteristics.
    DisjointTimerQuery,
    /// `EXT_disjoint_timer_query_webgl2` — WebGL 2 variant of the
    /// same timer-query side channel.
    DisjointTimerQueryWebGl2,
}

impl WebGlBlockedExtension {
    /// Every extension Strict mode MUST refuse to expose.
    pub const ALL: &'static [WebGlBlockedExtension] = &[
        Self::DebugRendererInfo,
        Self::DisjointTimerQuery,
        Self::DisjointTimerQueryWebGl2,
    ];

    /// JS-visible extension name. Equality against this string is
    /// what the libxul `getExtension` interceptor consults to refuse
    /// a lookup. Returned as `&'static str` so the comparison is a
    /// pointer-or-bytes check against the allowlist entries.
    pub fn js_name(&self) -> &'static str {
        match self {
            Self::DebugRendererInfo => "WEBGL_debug_renderer_info",
            Self::DisjointTimerQuery => "EXT_disjoint_timer_query",
            Self::DisjointTimerQueryWebGl2 => "EXT_disjoint_timer_query_webgl2",
        }
    }
}

/// Locked WebGL parameter bundle for the Strict cohort. The
/// libxul-side WebGL hook consults this on every Strict-mode
/// `getParameter` / `getSupportedExtensions` / `getExtension` call
/// so all Strict DevBrowse renderers return identical values.
///
/// `Copy` is intentional — the profile is a value type read on
/// every parameter query, never a handle. The struct holds raw
/// scalars and `&'static` slices so a clone is free.
///
/// `vendor` / `renderer` deliberately match what Firefox returns
/// when `WEBGL_debug_renderer_info` is unavailable (the default
/// privileged-only setting). This maximizes cohort overlap with
/// the wider Firefox / Tor Browser cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebGlProfile {
    /// `getParameter(VENDOR)` return value.
    pub vendor: &'static str,
    /// `getParameter(RENDERER)` return value.
    pub renderer: &'static str,
    /// `getParameter(VERSION)` for `WebGLRenderingContext` (WebGL 1).
    pub version_webgl1: &'static str,
    /// `getParameter(VERSION)` for `WebGL2RenderingContext`.
    pub version_webgl2: &'static str,
    /// `getParameter(SHADING_LANGUAGE_VERSION)` (WebGL 1).
    pub shading_language_version_webgl1: &'static str,
    /// `getParameter(SHADING_LANGUAGE_VERSION)` (WebGL 2).
    pub shading_language_version_webgl2: &'static str,
    /// The curated Strict extension allowlist returned by
    /// `getSupportedExtensions()`. Anything not in this slice — in
    /// particular every `WebGlBlockedExtension::ALL` entry — returns
    /// `null` from `getExtension` and is omitted from
    /// `getSupportedExtensions()`.
    pub extensions: &'static [&'static str],
    /// `getParameter(MAX_TEXTURE_SIZE)`.
    pub max_texture_size: u32,
    /// `getParameter(MAX_VIEWPORT_DIMS)` (length-2 Int32Array).
    pub max_viewport_dims: [u32; 2],
    /// `getParameter(MAX_VERTEX_UNIFORM_VECTORS)`.
    pub max_vertex_uniform_vectors: u32,
    /// `getParameter(MAX_FRAGMENT_UNIFORM_VECTORS)`.
    pub max_fragment_uniform_vectors: u32,
    /// `getParameter(MAX_VARYING_VECTORS)`.
    pub max_varying_vectors: u32,
    /// `getParameter(MAX_VERTEX_ATTRIBS)`.
    pub max_vertex_attribs: u32,
    /// `getParameter(MAX_RENDERBUFFER_SIZE)`.
    pub max_renderbuffer_size: u32,
    /// `getParameter(MAX_COMBINED_TEXTURE_IMAGE_UNITS)`.
    pub max_combined_texture_image_units: u32,
    /// The shared Module 27 rasterizer profile used for
    /// `readPixels`. This is `&'static` (not owned) precisely so
    /// `std::ptr::eq` against `&LOCKED_CANVAS_PROFILE` can verify
    /// the cohort unification with Module 27.
    pub canvas_profile: &'static CanvasRenderProfile,
}

/// The Strict-cohort allowlist. The v1 list is conservative and
/// covers the WebGL 1 extensions that ship in every desktop Gecko
/// build without varying by GPU family (deliberately minimal until
/// the Phase 10 adversarial suite ratifies a wider set).
///
/// `WEBGL_debug_renderer_info`, `EXT_disjoint_timer_query`, and
/// `EXT_disjoint_timer_query_webgl2` are absent. Their absence is
/// enforced by `tests::extensions_allowlist_does_not_include_blocked_extensions`.
const STRICT_EXTENSIONS_ALLOWLIST: &[&str] = &[
    "OES_standard_derivatives",
    "OES_element_index_uint",
    "OES_vertex_array_object",
    "ANGLE_instanced_arrays",
    "WEBGL_lose_context",
];

/// The single cohort-safe profile for Strict mode. Standard does
/// NOT use this — see [`WebGlReadbackPolicy::for_mode`].
///
/// `static` (not `const`): callers compare `&'static` references by
/// address (`std::ptr::eq`) to prove every Strict consumer is
/// reading the same singleton. `const` items can be constant-folded
/// so each `&LOCKED_WEBGL_PROFILE` site receives a fresh address,
/// which silently weakens the Strict-cohort-safety invariant
/// (identical pattern to Module 27 `LOCKED_CANVAS_PROFILE`).
///
/// Numeric values reflect a conservative cohort-safe baseline that
/// is below the limits of every modern desktop GPU, so the locked
/// values never force a Strict site to allocate beyond what the
/// underlying driver supports.
pub static LOCKED_WEBGL_PROFILE: WebGlProfile = WebGlProfile {
    vendor: "Mozilla",
    renderer: "Mozilla",
    version_webgl1: "WebGL 1.0",
    version_webgl2: "WebGL 2.0",
    shading_language_version_webgl1: "WebGL GLSL ES 1.0",
    shading_language_version_webgl2: "WebGL GLSL ES 3.00",
    extensions: STRICT_EXTENSIONS_ALLOWLIST,
    max_texture_size: 16384,
    max_viewport_dims: [16384, 16384],
    max_vertex_uniform_vectors: 1024,
    max_fragment_uniform_vectors: 1024,
    max_varying_vectors: 30,
    max_vertex_attribs: 16,
    max_renderbuffer_size: 16384,
    max_combined_texture_image_units: 32,
    canvas_profile: &LOCKED_CANVAS_PROFILE,
};

// ── Per-mode WebGL readback policy ────────────────────────────────────────

/// Per-mode WebGL readout policy. Strict pins the parameter readout
/// to `LOCKED_WEBGL_PROFILE`; Standard leaves the native Gecko
/// surface in place.
///
/// Per-mode WebGL readback policy.
///
/// **v1.23 amiunique-generic refactor (Phase 5.5 Module 35.5):**
/// both modes resolve to the same `Normalized` variant carrying
/// `LOCKED_WEBGL_PROFILE`. Standard now locks vendor / renderer /
/// extension allowlist to the same cohort base as Strict (was:
/// native pass-through) AND adds per-(origin, IdentityProfile)
/// ±1 noise on numeric `MAX_*` parameters. Strict keeps the pure
/// cohort lock (`farbling: None`).
///
/// Supersedes the v1.13 `NativePassThrough` / `NormalizedProfile`
/// two-variant shape. Standard no longer pass-throughs; the
/// vendor=Mozilla / renderer=Mozilla / 5-extension allowlist now
/// applies to both modes.
///
/// `Eq` / `Hash` intentionally NOT derived for the same reason
/// as `CanvasReadbackPolicy`: the embedded `FarblingProfile`
/// carries an `f32`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WebGlReadbackPolicy {
    /// WebGL parameter readout flows through the libxul hook
    /// returning fields from `profile`. When `farbling.is_some()`,
    /// the per-parameter ±1 noise from `farbling` is applied to
    /// numeric `MAX_*` values (clamped to stay within the
    /// cohort-locked bounds in `profile`).
    Normalized {
        profile: &'static WebGlProfile,
        farbling: Option<&'static crate::farbling::FarblingProfile>,
    },
}

impl WebGlReadbackPolicy {
    /// Locked snapshot for `mode` (v1.23):
    ///   * `Mode::Standard` -> `Normalized { profile: &LOCKED_WEBGL_PROFILE, farbling: Some(&STANDARD_FARBLING_PROFILE) }`
    ///   * `Mode::Strict`   -> `Normalized { profile: &LOCKED_WEBGL_PROFILE, farbling: None }`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Normalized {
                profile: &LOCKED_WEBGL_PROFILE,
                farbling: Some(&crate::farbling::STANDARD_FARBLING_PROFILE),
            },
            Mode::Strict => Self::Normalized {
                profile: &LOCKED_WEBGL_PROFILE,
                farbling: None,
            },
        }
    }

    /// The WebGL profile this policy uses. Always
    /// `&LOCKED_WEBGL_PROFILE` after the v1.23 refactor — both
    /// modes share the cohort base.
    pub fn profile(&self) -> &'static WebGlProfile {
        match self {
            Self::Normalized { profile, .. } => profile,
        }
    }

    /// The farbling profile this policy carries, if any.
    pub fn farbling(&self) -> Option<&'static crate::farbling::FarblingProfile> {
        match self {
            Self::Normalized { farbling, .. } => *farbling,
        }
    }

    /// The shared rasterizer profile the libxul `readPixels`
    /// interceptor routes through. Returns the address-identical
    /// `&LOCKED_CANVAS_PROFILE` (Module 27 cross-coupling).
    pub fn canvas_profile(&self) -> &'static CanvasRenderProfile {
        self.profile().canvas_profile
    }

    /// True iff the libxul WebGL hook will be activated for this
    /// policy. After the v1.23 refactor this is `true` for both
    /// modes.
    pub fn normalizes(&self) -> bool {
        matches!(self, Self::Normalized { .. })
    }
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::WebGl`.
///
/// Construct with `WebGlOverride::new(mode)` so the policy is
/// resolved once at construction; the override is then registered
/// by the libxul bridge into every `JsContext` for the renderer.
///
/// Mode-divergent behavior is in the *policy*, not the *trait*:
/// every renderer registers a `WebGlOverride`, but Strict-mode
/// `install` activates the cohort-locked parameter hook and
/// Standard-mode `install` is a no-op. Keeping the registration
/// structurally uniform across modes means the bridge has one code
/// path.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data, so `install(&OverrideContext)` produces
/// observationally identical state regardless of `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct WebGlOverride {
    policy: WebGlReadbackPolicy,
}

impl WebGlOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: WebGlReadbackPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> WebGlReadbackPolicy {
        self.policy
    }

    /// The WebGL profile this override pins. Always
    /// `&LOCKED_WEBGL_PROFILE` after the v1.23 refactor — both
    /// modes share the cohort base. Strict vs Standard divergence
    /// is on `policy().farbling()`.
    pub fn profile(&self) -> &'static WebGlProfile {
        self.policy.profile()
    }

    /// The shared rasterizer profile the libxul `readPixels`
    /// interceptor routes through (Module 27 cross-coupling).
    pub fn canvas_profile(&self) -> &'static CanvasRenderProfile {
        self.policy.canvas_profile()
    }
}

impl FingerprintOverride for WebGlOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::WebGl
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect on either branch. The libxul WebGL hook
        // is not yet wired (see crate-level TODO). When the FFI
        // lands:
        //   * NormalizedProfile(p) -> register a per-renderer
        //     callback returning fields from `p` on demand, refuse
        //     `getExtension` lookups in WebGlBlockedExtension::ALL,
        //     and route `readPixels` through `p.canvas_profile`.
        //   * NativePassThrough -> remain a no-op; the native
        //     parameter readout stays in place for Standard.
        let _ = (self.policy, JsContext::ALL, WebGlBlockedExtension::ALL);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_profile_matches_strict_cohort_parameters() {
        // The exact locked values are the v1 Strict-cohort
        // definition. Changing any of these is a cohort shift and
        // triggers the Adaptation protocol (README §Adaptation).
        assert_eq!(LOCKED_WEBGL_PROFILE.vendor, "Mozilla");
        assert_eq!(LOCKED_WEBGL_PROFILE.renderer, "Mozilla");
        assert_eq!(LOCKED_WEBGL_PROFILE.version_webgl1, "WebGL 1.0");
        assert_eq!(LOCKED_WEBGL_PROFILE.version_webgl2, "WebGL 2.0");
        assert_eq!(
            LOCKED_WEBGL_PROFILE.shading_language_version_webgl1,
            "WebGL GLSL ES 1.0"
        );
        assert_eq!(
            LOCKED_WEBGL_PROFILE.shading_language_version_webgl2,
            "WebGL GLSL ES 3.00"
        );
        assert_eq!(LOCKED_WEBGL_PROFILE.max_texture_size, 16384);
        assert_eq!(LOCKED_WEBGL_PROFILE.max_viewport_dims, [16384, 16384]);
        assert_eq!(LOCKED_WEBGL_PROFILE.max_vertex_uniform_vectors, 1024);
        assert_eq!(LOCKED_WEBGL_PROFILE.max_fragment_uniform_vectors, 1024);
        assert_eq!(LOCKED_WEBGL_PROFILE.max_varying_vectors, 30);
        assert_eq!(LOCKED_WEBGL_PROFILE.max_vertex_attribs, 16);
        assert_eq!(LOCKED_WEBGL_PROFILE.max_renderbuffer_size, 16384);
        assert_eq!(LOCKED_WEBGL_PROFILE.max_combined_texture_image_units, 32);
    }

    #[test]
    fn locked_profile_canvas_profile_is_module_27_singleton() {
        // Cross-module cohort unification (Module 27 dependency):
        // the Strict WebGL `readPixels` pathway MUST route through
        // the same `&LOCKED_CANVAS_PROFILE` address every Strict
        // canvas readback uses. Address identity, not value equality.
        assert!(std::ptr::eq(
            LOCKED_WEBGL_PROFILE.canvas_profile,
            &LOCKED_CANVAS_PROFILE
        ));
    }

    #[test]
    fn standard_resolves_to_cohort_base_with_farbling() {
        // v1.23 amiunique-generic refactor: Standard now locks
        // vendor / renderer / extension allowlist to the same
        // cohort base as Strict (was: native pass-through),
        // PLUS carries STANDARD_FARBLING_PROFILE for per-(origin,
        // profile_id) ±1 noise on numeric MAX_* parameters.
        let p = WebGlReadbackPolicy::for_mode(Mode::Standard);
        assert!(matches!(p, WebGlReadbackPolicy::Normalized { .. }));
        assert!(std::ptr::eq(p.profile(), &LOCKED_WEBGL_PROFILE));
        assert!(std::ptr::eq(p.canvas_profile(), &LOCKED_CANVAS_PROFILE));
        let f = p
            .farbling()
            .expect("Standard MUST carry a farbling profile");
        assert!(std::ptr::eq(f, &crate::farbling::STANDARD_FARBLING_PROFILE));
        assert!(p.normalizes());
    }

    #[test]
    fn strict_resolves_to_cohort_base_without_farbling() {
        // v1.23: Strict shares the same cohort base (address
        // identity) but carries farbling=None — pure cohort lock.
        let p = WebGlReadbackPolicy::for_mode(Mode::Strict);
        assert!(matches!(p, WebGlReadbackPolicy::Normalized { .. }));
        assert!(std::ptr::eq(p.profile(), &LOCKED_WEBGL_PROFILE));
        assert!(std::ptr::eq(p.canvas_profile(), &LOCKED_CANVAS_PROFILE));
        assert_eq!(p.farbling(), None);
        assert!(p.normalizes());
    }

    #[test]
    fn standard_and_strict_share_webgl_cohort_base() {
        // v1.23 cohort unification: WebGL profile + canvas_profile
        // are address-identical across both modes.
        let s = WebGlReadbackPolicy::for_mode(Mode::Standard);
        let r = WebGlReadbackPolicy::for_mode(Mode::Strict);
        assert!(std::ptr::eq(s.profile(), r.profile()));
        assert!(std::ptr::eq(s.canvas_profile(), r.canvas_profile()));
        // Modes diverge ONLY on farbling.
        assert!(s.farbling().is_some());
        assert!(r.farbling().is_none());
    }

    #[test]
    fn webgl_parameter_all_covers_edge_cases() {
        // Phase-file Goal coverage for Module 28: the Strict hook
        // MUST wire VENDOR / RENDERER / VERSION /
        // SHADING_LANGUAGE_VERSION / extension list / numeric
        // getParameter values, plus the readPixels readback pathway
        // shared with Module 27. Adding a new WebGL parameter that
        // leaks GPU identity needs a variant here.
        assert_eq!(WebGlParameter::ALL.len(), 14);

        for v in [
            WebGlParameter::Vendor,
            WebGlParameter::Renderer,
            WebGlParameter::Version,
            WebGlParameter::ShadingLanguageVersion,
            WebGlParameter::SupportedExtensions,
            WebGlParameter::MaxTextureSize,
            WebGlParameter::MaxViewportDims,
            WebGlParameter::MaxVertexUniformVectors,
            WebGlParameter::MaxFragmentUniformVectors,
            WebGlParameter::MaxVaryingVectors,
            WebGlParameter::MaxVertexAttribs,
            WebGlParameter::MaxRenderbufferSize,
            WebGlParameter::MaxCombinedTextureImageUnits,
            WebGlParameter::ReadPixels,
        ] {
            assert!(
                WebGlParameter::ALL.contains(&v),
                "missing WebGL parameter: {:?}",
                v
            );
        }
    }

    #[test]
    fn blocked_extension_all_covers_edge_cases() {
        // Phase-file edge cases for Module 28: WEBGL_debug_renderer_info
        // (unmasked GPU identity) + timer-query extensions (high-
        // resolution GPU clock bypassing L43). Adding a new
        // detected fingerprint-leaking extension needs a variant
        // here so the allowlist-disjointness test catches a
        // re-inclusion regression.
        assert_eq!(WebGlBlockedExtension::ALL.len(), 3);

        for v in [
            WebGlBlockedExtension::DebugRendererInfo,
            WebGlBlockedExtension::DisjointTimerQuery,
            WebGlBlockedExtension::DisjointTimerQueryWebGl2,
        ] {
            assert!(
                WebGlBlockedExtension::ALL.contains(&v),
                "missing blocked extension: {:?}",
                v
            );
        }

        assert_eq!(
            WebGlBlockedExtension::DebugRendererInfo.js_name(),
            "WEBGL_debug_renderer_info"
        );
        assert_eq!(
            WebGlBlockedExtension::DisjointTimerQuery.js_name(),
            "EXT_disjoint_timer_query"
        );
        assert_eq!(
            WebGlBlockedExtension::DisjointTimerQueryWebGl2.js_name(),
            "EXT_disjoint_timer_query_webgl2"
        );
    }

    #[test]
    fn extensions_allowlist_does_not_include_blocked_extensions() {
        // Privacy invariant: the Strict allowlist MUST be disjoint
        // from WebGlBlockedExtension::ALL. A future allowlist
        // widening that re-includes any blocked extension breaks
        // this test (compilation succeeds, the test fails loudly).
        for blocked in WebGlBlockedExtension::ALL {
            let name = blocked.js_name();
            assert!(
                !LOCKED_WEBGL_PROFILE.extensions.contains(&name),
                "Strict allowlist must not include blocked extension {}",
                name
            );
        }
    }

    #[test]
    fn webgl_override_reports_webgl_surface_under_both_modes() {
        // The bridge registers under WebIdlSurface::WebGl regardless
        // of mode (uniform registration; mode-divergence is in the
        // policy).
        assert_eq!(
            WebGlOverride::new(Mode::Standard).surface(),
            WebIdlSurface::WebGl
        );
        assert_eq!(
            WebGlOverride::new(Mode::Strict).surface(),
            WebIdlSurface::WebGl
        );
    }

    #[test]
    fn both_overrides_carry_the_locked_profile_v1_23() {
        // v1.23 refactor: both modes share LOCKED_WEBGL_PROFILE
        // and LOCKED_CANVAS_PROFILE. Per-mode divergence is on
        // policy().farbling().
        let standard = WebGlOverride::new(Mode::Standard);
        let strict = WebGlOverride::new(Mode::Strict);
        assert!(std::ptr::eq(standard.profile(), &LOCKED_WEBGL_PROFILE));
        assert!(std::ptr::eq(strict.profile(), &LOCKED_WEBGL_PROFILE));
        assert!(std::ptr::eq(
            standard.canvas_profile(),
            &LOCKED_CANVAS_PROFILE
        ));
        assert!(std::ptr::eq(
            strict.canvas_profile(),
            &LOCKED_CANVAS_PROFILE
        ));
        assert!(standard.policy().farbling().is_some());
        assert_eq!(strict.policy().farbling(), None);

        let p = strict.profile();
        assert!(std::ptr::eq(p, &LOCKED_WEBGL_PROFILE));

        let c = strict.canvas_profile();
        assert!(std::ptr::eq(c, &LOCKED_CANVAS_PROFILE));
    }

    #[test]
    fn webgl_override_install_is_context_inert() {
        // Edge case: override must be inert across iframe / worker /
        // service-worker / dedicated-worker. Drive install across
        // every JsContext for both modes and assert observed state
        // (the policy + surface) does not vary across contexts.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000028").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = WebGlOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::WebGl);
        }
    }

    #[test]
    fn webgl_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WebGlOverride>();
        assert_send_sync::<WebGlReadbackPolicy>();
        assert_send_sync::<WebGlProfile>();
        assert_send_sync::<WebGlParameter>();
        assert_send_sync::<WebGlBlockedExtension>();
    }

    #[test]
    fn parameter_dispatch_is_exhaustive_friendly() {
        // The libxul bridge will match on WebGlParameter to look up
        // the right return value. Lock in the exhaustive-match
        // contract here so a future variant cannot be silently
        // dropped to a default arm. Mirror of Module 27
        // `surface_dispatch_is_exhaustive_friendly`.
        fn route(p: WebGlParameter) -> &'static str {
            match p {
                WebGlParameter::Vendor => "vendor",
                WebGlParameter::Renderer => "renderer",
                WebGlParameter::Version => "version",
                WebGlParameter::ShadingLanguageVersion => "shading-language-version",
                WebGlParameter::SupportedExtensions => "supported-extensions",
                WebGlParameter::MaxTextureSize => "max-texture-size",
                WebGlParameter::MaxViewportDims => "max-viewport-dims",
                WebGlParameter::MaxVertexUniformVectors => "max-vertex-uniform-vectors",
                WebGlParameter::MaxFragmentUniformVectors => "max-fragment-uniform-vectors",
                WebGlParameter::MaxVaryingVectors => "max-varying-vectors",
                WebGlParameter::MaxVertexAttribs => "max-vertex-attribs",
                WebGlParameter::MaxRenderbufferSize => "max-renderbuffer-size",
                WebGlParameter::MaxCombinedTextureImageUnits => "max-combined-texture-image-units",
                WebGlParameter::ReadPixels => "read-pixels",
            }
        }
        for p in WebGlParameter::ALL {
            assert!(!route(*p).is_empty());
        }
    }

    #[test]
    fn blocked_extension_dispatch_is_exhaustive_friendly() {
        // The libxul `getExtension` interceptor matches on
        // WebGlBlockedExtension to decide which extension lookup to
        // refuse. Exhaustive match keeps a new blocked extension
        // from being silently dropped.
        fn route(e: WebGlBlockedExtension) -> &'static str {
            match e {
                WebGlBlockedExtension::DebugRendererInfo => "debug-renderer-info",
                WebGlBlockedExtension::DisjointTimerQuery => "disjoint-timer-query",
                WebGlBlockedExtension::DisjointTimerQueryWebGl2 => "disjoint-timer-query-webgl2",
            }
        }
        for e in WebGlBlockedExtension::ALL {
            assert!(!route(*e).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // The libxul bridge will match on WebGlReadbackPolicy to
        // decide whether to register the parameter hook. Lock in
        // the exhaustive-match contract here so a future variant
        // (e.g. a "Strict + cohort-rotated" sub-mode) cannot be
        // silently treated as native pass-through.
        fn arm(p: WebGlReadbackPolicy) -> &'static str {
            match p {
                WebGlReadbackPolicy::Normalized { farbling: None, .. } => "cohort-locked",
                WebGlReadbackPolicy::Normalized {
                    farbling: Some(_), ..
                } => "cohort-locked-farbled",
            }
        }
        assert_eq!(
            arm(WebGlReadbackPolicy::for_mode(Mode::Standard)),
            "cohort-locked-farbled",
        );
        assert_eq!(
            arm(WebGlReadbackPolicy::for_mode(Mode::Strict)),
            "cohort-locked",
        );
    }
}
