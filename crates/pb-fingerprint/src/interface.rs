//! Module 26 — WebIDL fingerprint-override interface.
//!
//! Defines the trait surface every per-surface fingerprint override
//! (Modules 27-35) implements. Surfaces are wired into Gecko via the
//! libxul WebIDL FFI bridge — never via JS prototype patching.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; no JS prototype
//!     patching. Workers and iframes inherit automatically because
//!     the override lives below the JS surface.
//!   * **L9 / §3.1** — `OverrideContext` carries the `Mode` that was
//!     locked at IdentityProfile creation. This surface never mutates
//!     Mode; it only reads it.
//!   * **§3.2 / §3.3** — per-Mode normalization is keyed on
//!     `OverrideContext::mode()`. Strict produces tighter cohorts than
//!     Standard, but both share the same WebIDL plumb-in points.
//!   * **§5.5** — central fingerprint surface: every per-surface module
//!     consults this trait, so the bucketing strategy lives in one
//!     enumerated place (`WebIdlSurface`).
//!   * **L7** — `profile_id` is the UUID v4 minted by Module 6
//!     (`IdentityProfile`). Treat it as opaque; never log it (L27).
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * The abstract trait + context type that every per-surface
//!     override (Modules 27-35) implements. Phase 5.5 layers Strict-
//!     specific overrides (L42 letterboxing, L43 100ms timer quantum,
//!     L44 disabled-by-default APIs) on top of the same trait.
//!   * The plumbing-point list (`WebIdlSurface`) the libxul FFI
//!     bridge iterates at startup to register one override per
//!     (surface, JS context) pair.
//!
//! It IS NOT:
//!   * The FFI bridge itself. The libxul-side WebIDL hook
//!     registration is part of the `pb-browser` orchestrator
//!     binary (Phase 11 / Module 80 startup sequence — pending);
//!     pb-browser iterates `WebIdlSurface::ALL × JsContext::ALL`
//!     at boot and installs each override via `cbindgen` exports
//!     against this trait. The libxul ABI + L40 build config
//!     is verified by Module 69 (Phase 9 — pending) on every
//!     libxul tag bump. The libxul Cargo dep version is workspace-
//!     level build infrastructure; **it is NOT "Module 1"**
//!     (Module 1 ships only the Cargo workspace + toolchain pin).
//!   * The per-surface normalization logic. Each of Modules 27-35
//!     ships its own `FingerprintOverride` impl in `gecko/<surface>.rs`.
//
// Modules 27-35 have shipped: each per-surface module ships a
//   concrete `FingerprintOverride` impl returning the matching
//   `WebIdlSurface` variant from `surface()`. The bridge matches on
//   the variant to find the right plumb-in point. Phase 5.5
//   modules 35.6, 35.7, 35.8 each added one impl + one
//   `WebIdlSurface` variant; 35.9 + 35.10 will add 4 more
//   (target `WebIdlSurface::ALL.len() == 16` at Phase 5.5 exit).
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80; Module 69
//   Phase 9 verifies on each tag bump): the WebIDL hook registration is
//   the FFI handshake. Adding a new `WebIdlSurface` variant without
//   the corresponding plumb-in is silently inert and a privacy
//   regression — the bridge MUST exhaustively match `WebIdlSurface`.
// TODO(post-Phase-5.5 refactor candidate): `OverrideContext::js_context`
//   is informational in v1 because every implementation is required
//   to be context-inert. The original plan parked this against
//   Module 35.2; 35.2 shipped without the refactor (the AsyncEventClass
//   plumbing was the load-bearing 35.2 deliverable). A future
//   refactor may want a `Cow`-style override wrapper that documents
//   context-inert at the type level (compile-time guarantee instead
//   of trait-doc obligation). Owner unclaimed; not blocking any
//   pending module.

use pb_config::Mode;
use uuid::Uuid;

// ── JS execution context ──────────────────────────────────────────────────

/// JavaScript execution context the override is being invoked from.
///
/// Each variant corresponds to a separately-exposed JS scope (each
/// has its own copy of `Date`, `performance`, `navigator`,
/// `OffscreenCanvas`, etc.). Workers and iframes inherit the WebIDL
/// override automatically because the hook lives below the JS layer
/// (L8) — but the FFI bridge MUST still register the override into
/// every context at startup, otherwise a worker scope can call its
/// own un-overridden surface and use the divergence as a
/// fingerprint side-channel.
///
/// `JsContext` is informational metadata for the FFI plumbing list;
/// override implementations MUST be context-inert (see
/// [`FingerprintOverride`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsContext {
    /// Top-level document (the navigated tab itself).
    TopFrame,
    /// Cross- or same-origin `<iframe>` document.
    IFrame,
    /// `new Worker(...)` dedicated worker scope.
    DedicatedWorker,
    /// `new SharedWorker(...)` shared worker scope.
    SharedWorker,
    /// `navigator.serviceWorker.register(...)` service worker scope.
    ServiceWorker,
}

impl JsContext {
    /// Every JS context the FFI bridge must register an override into.
    /// The bridge iterates this slice at startup so a new variant
    /// added here is automatically wired into every plumb-in.
    pub const ALL: &'static [JsContext] = &[
        Self::TopFrame,
        Self::IFrame,
        Self::DedicatedWorker,
        Self::SharedWorker,
        Self::ServiceWorker,
    ];
}

// ── Override context ──────────────────────────────────────────────────────

/// Context passed to every override invocation.
///
/// Carries:
///   * `mode` — the per-Mode normalization key (L9, §3.1). Locked at
///     IdentityProfile creation; this surface never mutates it.
///   * `profile_id` — the UUID v4 minted by Module 6. Opaque to the
///     override; used only for cohort-key derivation (L7).
///   * `js_context` — informational (see [`JsContext`] doc).
///
/// L27: this struct intentionally has no `Display` impl. The
/// `profile_id` is a privacy-sensitive identifier; it must never
/// reach a log line. Use [`IdentityProfile::redacted_label`] for
/// log surfaces.
///
/// `Copy` is intentional: `OverrideContext` is 24 bytes (UUID + Mode
/// byte + JsContext byte + padding) and crosses the WebIDL hook
/// boundary on every override invocation. Cloning would be free;
/// copying gives the same instruction with stricter borrow-check
/// semantics.
///
/// [`IdentityProfile::redacted_label`]: ../../pb_identity/profile/struct.IdentityProfile.html#method.redacted_label
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverrideContext {
    mode: Mode,
    profile_id: Uuid,
    js_context: JsContext,
}

impl OverrideContext {
    /// Construct a context. The FFI bridge calls this once per
    /// (surface, JS context) plumb-in at startup.
    pub fn new(mode: Mode, profile_id: Uuid, js_context: JsContext) -> Self {
        Self {
            mode,
            profile_id,
            js_context,
        }
    }

    /// Mode locked at IdentityProfile creation (§3.1).
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Stable identity key (UUID v4, L7). Opaque to the override.
    pub fn profile_id(&self) -> Uuid {
        self.profile_id
    }

    /// Which JS scope this invocation came from. Override
    /// implementations MUST NOT branch on this — see the
    /// context-inert invariant on [`FingerprintOverride`].
    pub fn js_context(&self) -> JsContext {
        self.js_context
    }
}

// ── WebIDL plumbing-point enumeration ─────────────────────────────────────

/// Every WebIDL surface that Modules 27-35 hook through libxul.
///
/// The Gecko bridge iterates this list at startup and registers an
/// override per (surface, [`JsContext`]) pair, so a worker scope
/// cannot bypass an override that only the top-frame scope had
/// (L8 + the workers-and-iframes-inherit edge case).
///
/// Adding a new variant is the contract handshake with libxul: the
/// FFI bridge MUST gain a corresponding plumb-in or the override is
/// silently inert (a privacy regression). This is why the bridge
/// matches `WebIdlSurface` exhaustively rather than via a default arm.
///
/// Phase 5.5 may add Strict-only variants for L42 (window-dimension
/// letterboxing), L43 (100 ms timer quantum), and L44
/// (disabled-by-default API surface) — each is a separate plumb-in
/// because Strict layers on top of the Standard surface rather than
/// replacing it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebIdlSurface {
    /// Module 27 — `CanvasRenderingContext2D.getImageData` /
    /// `HTMLCanvasElement.toDataURL` / `OffscreenCanvas` /
    /// `WebGLRenderingContext.readPixels`.
    Canvas,
    /// Module 28 — `WebGLRenderingContext.getParameter` /
    /// `WEBGL_debug_renderer_info` / extension list.
    WebGl,
    /// Module 29 — `OfflineAudioContext` rendering /
    /// `AnalyserNode.getByteFrequencyData` / `DynamicsCompressorNode`.
    Audio,
    /// Module 30 — `document.fonts` / CSS font-detection enumeration.
    Fonts,
    /// Module 31 — `navigator.getBattery` (returns "not supported").
    Battery,
    /// Module 32 — `Date.now` / `performance.now` /
    /// `Performance.timeOrigin` / `PerformanceObserver`.
    Timers,
    /// Module 33 — `Intl.DateTimeFormat.resolvedOptions().timeZone` /
    /// `Date.prototype.getTimezoneOffset` / `Intl.Locale` defaults.
    Timezone,
    /// Module 34 — `navigator.userAgent` / `plugins` / `mimeTypes` /
    /// `languages` / `hardwareConcurrency` / `deviceMemory` / etc.
    /// **`navigator.userAgentData` is intentionally NOT exposed** —
    /// Firefox does not implement the Chromium Client Hints API;
    /// DevBrowse blends into the Firefox cohort by matching that
    /// absence rather than spoofing a brand list.
    Navigator,
    /// Module 35.6 — `navigator.gpu.requestAdapter()` /
    /// `GPUAdapter.info` / `GPUAdapter.features` /
    /// `GPUAdapter.limits` / `GPUDevice.lost`. Strict cohort-locks
    /// to `LOCKED_WEBGPU_PROFILE` (vendor = `"Mozilla"`, matching
    /// Module 28 WebGL); Standard buckets the vendor class to one
    /// of {Intel, NVIDIA, AMD, Apple, Other} while locking
    /// architecture / driver / features / limits to the same
    /// cohort base. WebGPU stays USABLE in Strict — Tor / Mullvad
    /// disable WebGPU entirely; DevBrowse goes structurally ahead
    /// of them on this v2025+ surface.
    WebGpu,
    /// Module 35.7 — `speechSynthesis.getVoices()` /
    /// `speechSynthesis.onvoiceschanged`. Strict locks to a
    /// 4-voice cohort (en-US / en-GB / ja-JP / ar-SA covering
    /// Latin / CJK / Arabic script directions) preserving
    /// screen-reader accessibility; Tor returns the empty list
    /// (breaks accessibility) — DevBrowse goes structurally ahead.
    /// Standard locale-buckets the visible voice set.
    SpeechSynthesis,
    /// Module 35.7 — `navigator.mediaCapabilities.decodingInfo()` /
    /// `encodingInfo()`. Mode-invariant lock on the codec
    /// `{supported, smooth, powerEfficient}` answer table —
    /// H.264 baseline / VP9 / AAC / Opus / MP3 supported; HEVC /
    /// AV1 unsupported — regardless of host hardware. Actual
    /// playback uses real codecs (EME / DRM unaffected).
    MediaCapabilities,
    /// Module 35.8 — `navigator.connection` (Network Information
    /// API). Strict removes the API entirely (`navigator.connection`
    /// is `undefined`; L44 pattern matching Module 31 Battery's
    /// mode-invariant removal but Strict-only here). Standard
    /// cohort-locks to broadband values (`effectiveType = "4g"`,
    /// `downlink = 10`, `rtt = 50`, `saveData = false`,
    /// `type = "wifi"`) so connection-class — a strong geographic
    /// correlate, especially on mobile (Phase 12) — does not leak.
    /// Tor returns a stub but still exposes the API surface;
    /// DevBrowse goes structurally ahead by removing the surface in
    /// Strict.
    NetworkInformation,
    /// Module 35.9 — `navigator.permissions.query()`. Strict returns
    /// `"denied"` for every API in Module 35.3's L44 disabled list
    /// (cross-coupling: the L44 enum is the source of truth) and
    /// `"prompt"` for every other API name (polluted-oracle
    /// protection — never reveals that a gate exists). Standard
    /// consults Module 59 (`PermissionStore`) per-API. The override
    /// sees one API name at a time; bulk enumeration is structurally
    /// impossible.
    Permissions,
    /// Module 35.9 — `navigator.storage.estimate()`. Strict returns
    /// `{quota: 0, usage: 0}` (Tor parity); Standard returns
    /// `{quota: 1 GiB, usage: 0}` (locked cohort value; per-origin
    /// actual usage hidden behind the partition-key boundary so
    /// sites can't probe their own quota).
    StorageEstimate,
    /// Module 35.10 — Display capabilities (`window.devicePixelRatio`,
    /// `screen.colorDepth`, `screen.pixelDepth`, `screen.orientation`,
    /// `OrientationChange` events). Strict locks the
    /// desktop-class cohort (`dpr=1.0`, `colorDepth=24`,
    /// `pixelDepth=24`, `orientation=landscape-primary/0°`).
    /// Standard buckets DPR into `{1.0, 1.5, 2.0, 3.0}` so Retina
    /// UX is preserved while every Standard user reports one of
    /// four cohorts (substantially better than Tor's hard 1.0).
    /// Closes the per-device fingerprint signals Module 35.1's
    /// letterboxer does not address.
    DisplayCapabilities,
    /// Module 35.10 — Touch surface (`navigator.maxTouchPoints`,
    /// `ontouchstart`, pointer / hover media queries). Both modes
    /// on desktop share `maxTouchPoints=0` + `pointer=fine` +
    /// `hover=hover` (the v1.23 amiunique-generic cohort lock —
    /// Standard desktop joins the Strict desktop cohort instead of
    /// reporting native). Mobile platforms (Phase 12) carve out
    /// via pb-platform detection and pass-through actual touch
    /// values to preserve mobile-responsive site compatibility.
    /// **Module 34 boundary**: `maxTouchPoints` is NOT in
    /// `NavigatorSurface::ALL`; this surface owns it.
    TouchSurface,
    /// Module 35.11 — DOMRect / element-bounding-box surface
    /// covering `Element.getClientRects()`,
    /// `Element.getBoundingClientRect()`, `Range.getClientRects()`,
    /// `Range.getBoundingClientRect()`, and
    /// `CanvasRenderingContext2D.measureText()`. Sub-pixel
    /// positions and text-metrics widths leak per-font-rendering
    /// and per-host-DPI signals (Tor bug 1507879; CreepJS probes).
    /// Strict snaps every DOMRect coordinate to integers and
    /// every TextMetrics width to integer pixels; Standard
    /// farbles via the per-(origin, profile) seed using the
    /// `FarblingSurface::DomRect` and `::TextMetrics` tags
    /// (added 2026-05-22, P1-4).
    DomRect,
    /// Module 35.12 — `Intl.*` defaults beyond the timezone
    /// surface Module 33 already covers (`Intl.NumberFormat`,
    /// `Intl.Collator`, `Intl.RelativeTimeFormat`,
    /// `Intl.PluralRules`). Each carries per-locale defaults that
    /// reveal the host locale catalog (numbering systems available,
    /// collator strength, etc.). Both modes lock to the `en-US`
    /// cohort defaults matching `LOCKED_LANGUAGE` (Module 34).
    Intl,
    /// Module 35.13 — `navigator.keyboard.getLayoutMap()` (W3C
    /// Keyboard Map API). Returns a `Map<USB-HID-code, key-glyph>`
    /// that reveals the host keyboard layout (QWERTY vs AZERTY vs
    /// Cyrillic etc.) — high-entropy locale signal. Both modes
    /// lock to the US-QWERTY map (matches `LOCKED_LANGUAGE = en-US`).
    KeyboardLayoutMap,
}

impl WebIdlSurface {
    /// Every surface the FFI bridge must wire. Adding a new variant
    /// to the enum without adding it here will not break compilation,
    /// so the bridge SHOULD also exhaustively match the enum to
    /// catch the omission at compile time.
    pub const ALL: &'static [WebIdlSurface] = &[
        Self::Canvas,
        Self::WebGl,
        Self::Audio,
        Self::Fonts,
        Self::Battery,
        Self::Timers,
        Self::Timezone,
        Self::Navigator,
        Self::WebGpu,
        Self::SpeechSynthesis,
        Self::MediaCapabilities,
        Self::NetworkInformation,
        Self::Permissions,
        Self::StorageEstimate,
        Self::DisplayCapabilities,
        Self::TouchSurface,
        Self::DomRect,
        Self::Intl,
        Self::KeyboardLayoutMap,
    ];
}

// ── Trait every per-surface override implements ───────────────────────────

/// Trait every per-surface fingerprint override (Modules 27-35) implements.
///
/// Implementations MUST be `Send + Sync` because the libxul bridge
/// holds them in `Arc<dyn FingerprintOverride>` slots shared across
/// renderer processes within an identity group (§3.2 renderer-sharing).
///
/// **Context-inert invariant.** For a given
/// (`OverrideContext::mode`, `OverrideContext::profile_id`) pair,
/// every observable behavior the override exposes MUST be identical
/// across every [`JsContext`] variant. A worker that observes a
/// different normalized canvas pixel / `Date.now` quantum / UA string
/// from the top frame can use the divergence as a fingerprint
/// side-channel — that is the L8 "workers and iframes inherit
/// automatically" guarantee, lifted to a trait obligation. The
/// `js_context` field exists for the FFI plumbing list, not for
/// per-context branching in implementations.
///
/// L27: implementations MUST NOT echo `profile_id` or any host /
/// origin string into a `Display` impl. Errors flow through
/// `Error::source()` only.
pub trait FingerprintOverride: Send + Sync + std::fmt::Debug {
    /// The WebIDL surface this implementation owns. The FFI bridge
    /// uses this to look up the right implementation for each
    /// plumb-in registration.
    fn surface(&self) -> WebIdlSurface;

    /// Invoked once per (renderer, JS context) at startup so per-Mode
    /// normalized values can be precomputed. MUST be deterministic
    /// given the [`OverrideContext`] — no clock reads, no system
    /// queries, no entropy sampling. Cohort identity depends on
    /// `install` being a pure function of its inputs.
    fn install(&self, ctx: &OverrideContext);
}

/// v1 helper: `install()` is a no-op pending libxul FFI wiring
/// (pb-browser Phase 11 / Module 80; verified by Module 69 in
/// Phase 9). Each per-surface override calls this from its
/// `install` body to centralize the "v1 no-op" rationale and
/// silence the unused-variable lint uniformly across all
/// implementations.
///
/// The `_` underscores intentionally discard the args; the FFI
/// bridge consumes them once the wiring lands.
///
/// Standardizes the `let _ = (self.policy, JsContext::ALL, ...)`
/// pattern that previously appeared inline in every override
/// (P3-5, 2026-05-22).
#[inline(always)]
pub fn noop_install_pending_ffi(_ctx: &OverrideContext) {
    // v1: no side effect. When the libxul FFI lands, per-surface
    // overrides replace this call with their actual wiring.
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn fixed_profile_id() -> Uuid {
        // Stable test UUID; not real CSPRNG output (tests are deterministic).
        Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()
    }

    #[test]
    fn override_context_round_trips_fields() {
        let pid = fixed_profile_id();
        let ctx = OverrideContext::new(Mode::Strict, pid, JsContext::DedicatedWorker);

        assert_eq!(ctx.mode(), Mode::Strict);
        assert_eq!(ctx.profile_id(), pid);
        assert_eq!(ctx.js_context(), JsContext::DedicatedWorker);
    }

    #[test]
    fn override_context_is_copy() {
        let pid = fixed_profile_id();
        let ctx = OverrideContext::new(Mode::Standard, pid, JsContext::TopFrame);
        // Two reads after a "move" — only compiles if Copy.
        let a = ctx;
        let b = ctx;
        assert_eq!(a.mode(), b.mode());
    }

    #[test]
    fn js_context_all_covers_every_variant() {
        // Edge case: override must be wired into iframe / dedicated
        // worker / shared worker / service worker so a worker scope
        // cannot call an un-overridden surface. ALL is the FFI
        // bridge's iteration source — if a variant is missing here,
        // a whole class of JS contexts loses the override.
        assert_eq!(JsContext::ALL.len(), 5);
        for v in [
            JsContext::TopFrame,
            JsContext::IFrame,
            JsContext::DedicatedWorker,
            JsContext::SharedWorker,
            JsContext::ServiceWorker,
        ] {
            assert!(JsContext::ALL.contains(&v), "missing JsContext: {:?}", v);
        }
    }

    #[test]
    fn webidl_surface_all_covers_modules_27_through_35_13() {
        // 8 Phase-5 surfaces (Modules 27-34) + 8 Phase-5.5
        // surfaces (35.6-35.10) + 3 post-Phase-5.5-audit surfaces
        // (35.11 DomRect, 35.12 Intl, 35.13 KeyboardLayoutMap —
        // landed 2026-05-22 from the comprehensive audit). ALL =
        // 19.
        assert_eq!(WebIdlSurface::ALL.len(), 19);
        for v in [
            WebIdlSurface::Canvas,
            WebIdlSurface::WebGl,
            WebIdlSurface::Audio,
            WebIdlSurface::Fonts,
            WebIdlSurface::Battery,
            WebIdlSurface::Timers,
            WebIdlSurface::Timezone,
            WebIdlSurface::Navigator,
            WebIdlSurface::WebGpu,
            WebIdlSurface::SpeechSynthesis,
            WebIdlSurface::MediaCapabilities,
            WebIdlSurface::NetworkInformation,
            WebIdlSurface::Permissions,
            WebIdlSurface::StorageEstimate,
            WebIdlSurface::DisplayCapabilities,
            WebIdlSurface::TouchSurface,
            WebIdlSurface::DomRect,
            WebIdlSurface::Intl,
            WebIdlSurface::KeyboardLayoutMap,
        ] {
            assert!(WebIdlSurface::ALL.contains(&v), "missing surface: {:?}", v);
        }
    }

    /// Mock override that records every (mode, profile_id, js_context)
    /// it was installed under, so the test can assert the
    /// context-inert invariant from outside.
    #[derive(Debug, Default)]
    struct RecordingOverride {
        installs: Mutex<Vec<(Mode, Uuid, JsContext)>>,
    }

    impl FingerprintOverride for RecordingOverride {
        fn surface(&self) -> WebIdlSurface {
            WebIdlSurface::Canvas
        }

        fn install(&self, ctx: &OverrideContext) {
            self.installs
                .lock()
                .unwrap()
                .push((ctx.mode(), ctx.profile_id(), ctx.js_context()));
        }
    }

    #[test]
    fn override_is_invoked_in_every_js_context() {
        // Edge case: simulate the FFI bridge installing the override
        // into every JS context at startup. The override must accept
        // every variant without error — the bridge cannot opt out
        // of any context, otherwise a worker bypass exists.
        let pid = fixed_profile_id();
        let ovr = RecordingOverride::default();

        for jsc in JsContext::ALL {
            let ctx = OverrideContext::new(Mode::Standard, pid, *jsc);
            ovr.install(&ctx);
        }

        let installs = ovr.installs.lock().unwrap();
        assert_eq!(installs.len(), JsContext::ALL.len());

        // Context-inert: every install saw the same (mode, profile_id);
        // only `js_context` varies. If a future override were to
        // branch its behavior on `js_context`, this is the test that
        // would need to grow into a behavioral assertion.
        for (m, p, _jsc) in installs.iter() {
            assert_eq!(*m, Mode::Standard);
            assert_eq!(*p, pid);
        }
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // The bridge matches WebIdlSurface to look up the right
        // implementation. This test exists so that adding a variant
        // without updating the bridge fails CI here too — the match
        // below is intentionally exhaustive (no `_` arm).
        fn route(s: WebIdlSurface) -> &'static str {
            match s {
                WebIdlSurface::Canvas => "canvas",
                WebIdlSurface::WebGl => "webgl",
                WebIdlSurface::Audio => "audio",
                WebIdlSurface::Fonts => "fonts",
                WebIdlSurface::Battery => "battery",
                WebIdlSurface::Timers => "timers",
                WebIdlSurface::Timezone => "timezone",
                WebIdlSurface::Navigator => "navigator",
                WebIdlSurface::WebGpu => "webgpu",
                WebIdlSurface::SpeechSynthesis => "speech-synthesis",
                WebIdlSurface::MediaCapabilities => "media-capabilities",
                WebIdlSurface::NetworkInformation => "network-information",
                WebIdlSurface::Permissions => "permissions",
                WebIdlSurface::StorageEstimate => "storage-estimate",
                WebIdlSurface::DisplayCapabilities => "display-capabilities",
                WebIdlSurface::TouchSurface => "touch-surface",
                WebIdlSurface::DomRect => "dom-rect",
                WebIdlSurface::Intl => "intl",
                WebIdlSurface::KeyboardLayoutMap => "keyboard-layout-map",
            }
        }
        for s in WebIdlSurface::ALL {
            // Every variant routes to a non-empty label; the real
            // bridge routes to an Arc<dyn FingerprintOverride>.
            assert!(!route(*s).is_empty());
        }
    }
}
