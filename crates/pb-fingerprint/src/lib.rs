//! Fingerprint normalization — Phase 5 (Modules 26-35).
//!
//! Architecture invariants enforced at this crate boundary:
//!   * **L8** — Gecko WebIDL override points only; no JS prototype
//!     patching. Workers and iframes inherit automatically because
//!     the override lives below the JS surface.
//!   * **L9 / §3.1** — every override is keyed on the Mode that was
//!     locked at IdentityProfile creation; this crate never mutates Mode.
//!   * **§5.5** — central fingerprint surface bucketing: every per-
//!     surface module routes through the [`interface`] trait so the
//!     plumbing list stays in one place.
//!   * **L7 / L27** — `profile_id` is the UUID v4 from Module 6 and
//!     is opaque to overrides; never log it.
//!
//! Unsafe policy: this crate currently forbids unsafe. When Gecko
//! WebIDL FFI lands (post Module 1 libxul tag), downgrade the lint to
//! `#![deny(unsafe_code)]` and require an explicit
//! `#[allow(unsafe_code)]` annotation on the FFI module so unsafe
//! blocks remain visible in code review.

#![forbid(unsafe_code)]

pub mod gecko;
pub mod interface;
pub mod webkit_stub;

pub use interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};

// Module 27 — Canvas readback normalization (Strict-only normalization;
// Standard preserves the native Gecko rasterizer per §3.3).
pub use gecko::canvas::{
    AntialiasMode, CanvasOverride, CanvasReadbackPolicy, CanvasRenderProfile, CanvasSurface,
    ColorSpace, HintingMode, PixelSnap, Rasterizer, LOCKED_CANVAS_PROFILE,
};

// Module 28 — WebGL parameter normalization (Strict-only cohort lock;
// Standard preserves the native Gecko WebGL surface per §3.3; readPixels
// in Strict reuses LOCKED_CANVAS_PROFILE from Module 27 so the Strict
// cohort is not split by readback-API choice).
pub use gecko::webgl::{
    WebGlBlockedExtension, WebGlOverride, WebGlParameter, WebGlProfile, WebGlReadbackPolicy,
    LOCKED_WEBGL_PROFILE,
};

// Module 29 — Audio context / Web Audio normalization (Strict-only
// cohort lock; Standard preserves the native Gecko audio path per
// §3.3; LOCKED_AUDIO_PROFILE pins the DynamicsCompressorNode
// implementation + DSP path + post-render quantization grid so the
// Strict cohort sees byte-identical OfflineAudioContext output across
// hosts).
pub use gecko::audio::{
    AudioOverride, AudioProfile, AudioReadbackPolicy, AudioSurface, CompressorImpl, DspPath,
    LOCKED_AUDIO_PROFILE,
};

// Module 30 — Fonts enumeration normalization (first Phase-5 module
// where both modes normalize: Strict pins BUNDLED_FONT_SET_V1; Standard
// buckets via STANDARD_BUCKETED_TABLE_V1 with per-site full-access
// opt-in via Module 59 / FontsGrants; CanvasRenderProfile::font_set
// references BUNDLED_FONT_SET_V1 so the canvas + fonts Strict cohorts
// are unified by address identity).
pub use gecko::fonts::{
    BundledFontSet, CapturingFontsGrants, DenyAllFontsGrants, FontBucket, FontsEnumerationPolicy,
    FontsGrants, FontsOverride, FontsSurface, StandardBucketedTable, BUNDLED_FONT_SET_V1,
    STANDARD_BUCKETED_TABLE_V1,
};

// Module 31 — Battery API removal (first Phase-5 module where the
// decision is mode-invariant: both Mode::Standard and Mode::Strict map
// to BatteryApiPolicy::Removed; navigator.getBattery is patched out of
// the WebIDL surface in every JsContext).
pub use gecko::battery::{BatteryApiPolicy, BatteryOverride, BatterySurface};

// Module 32 — Timer quantization (both modes quantize, per-Mode quanta:
// Standard 1 ms, Strict 100 ms per L43 Tor Browser RFP parity; GPU stays
// 2 ms in both modes per L8; floor-rounded to preserve same-microtask
// correlation + monotonic non-decreasing contract).
pub use gecko::timers::{
    TimerOverride, TimerProfile, TimerQuantizationPolicy, TimerSurface, GPU_QUANTUM_NS,
    STANDARD_TIMER_PROFILE, STRICT_TIMER_PROFILE,
};

// Module 33 — Timezone normalization. Strict is locked to UTC and is
// NON-CONFIGURABLE (Tor / Mullvad-style; L41 enforced by
// for_mode_with_user_selection). Standard defaults to host TZ
// (NativePassThrough) and supports user selection from COMMON_TIMEZONES
// (Firefox-style; UserConfigured variant). Per-identity storage of the
// selection lives in pb-identity (Module 6) when that path lands.
pub use gecko::timezone::{
    TimezoneOverride, TimezonePolicy, TimezoneProfile, TimezoneSurface, AMERICA_CHICAGO,
    AMERICA_LOS_ANGELES, AMERICA_NEW_YORK, ASIA_KOLKATA, ASIA_SINGAPORE, ASIA_TOKYO,
    AUSTRALIA_SYDNEY, COMMON_TIMEZONES, EUROPE_BERLIN, EUROPE_LONDON, LOCKED_TIMEZONE_PROFILE,
};

// Module 34 — Navigator / UA normalization. Mostly mode-invariant locking
// with one per-Mode field: hardware_concurrency = 4 for Standard, 2 for
// Strict (Tor / Mullvad / Firefox RFP cohort). Two profile statics
// (STANDARD_NAVIGATOR_PROFILE / STRICT_NAVIGATOR_PROFILE) differ only in
// hardware_concurrency; UA / languages / etc. are byte-identical. The
// locked UA string mirrors pb_network::DEVBROWSE_USER_AGENT exactly
// (paired regression tests on both crate sides catch drift; Phase 10
// live-renderer suite is the third defense).
pub use gecko::navigator::{
    NavigatorOverride, NavigatorPolicy, NavigatorProfile, NavigatorSurface, LOCKED_LANGUAGE,
    LOCKED_LANGUAGES, LOCKED_USER_AGENT, STANDARD_NAVIGATOR_PROFILE, STRICT_NAVIGATOR_PROFILE,
};

// Module 35 — WebKit backend stub. Phase 12 iOS scaffolding (not a Gecko
// WebIDL plumb-in per Module 26). WebKit on iOS does not expose Gecko-style
// WebIDL override points, so Phase-5 normalization is best-effort UA-level
// only. The stub ships the surface today so Phase 12 can implement against
// a stable contract; every Phase-5 surface returns Unsupported in v1.
pub use webkit_stub::{
    WebKitNormalizationCapability, WebKitNormalizationSurface, WebKitStub, WebKitStubProfile,
    WEBKIT_STUB_PROFILE,
};
