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
//! Unsafe policy: this crate currently forbids unsafe. When the
//! Gecko WebIDL FFI lands (wired by pb-browser at Phase 11 /
//! Module 80; verified by Module 69 in Phase 9 — neither tied to
//! the Module 1 workspace-setup module), downgrade the lint to
//! `#![deny(unsafe_code)]` and require an explicit
//! `#[allow(unsafe_code)]` annotation on the FFI module so unsafe
//! blocks remain visible in code review.

#![forbid(unsafe_code)]

pub mod farbling;
pub mod gecko;
pub mod interface;
pub mod strict;
pub mod webkit_stub;

pub use interface::{
    noop_install_pending_ffi, FingerprintOverride, JsContext, OverrideContext, WebIdlSurface,
};

// Module 35.5 — Per-(origin, IdentityProfile) deterministic farbling
// for dynamic readback surfaces. Standard mode shares the Strict cohort
// identity AND adds noise on canvas / WebGL-numeric / audio readbacks
// (v1.23 amiunique-generic refactor). Seed source is
// `pb_storage::PartitionKey::farbling_seed`.
pub use farbling::{
    farble_audio_sample, farble_audio_sample_with_epoch, farble_canvas_byte,
    farble_canvas_byte_with_epoch, farble_webgl_int, farble_webgl_int_with_epoch, FarblingEpoch,
    FarblingProfile, FarblingSeed, FarblingStreamKey, FarblingStreamKeyV2, FarblingSurface,
    FARBLING_SEED_LEN, NO_FARBLING_EPOCH, STANDARD_FARBLING_PROFILE,
};

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
    FontsGrants, FontsOverride, FontsSurface, HostileFontsGrants, StandardBucketedTable,
    BUNDLED_FONT_SET_V1, STANDARD_BUCKETED_TABLE_V1,
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
    is_in_common_timezones, TimezoneOverride, TimezonePolicy, TimezoneProfile, TimezoneSurface,
    AMERICA_CHICAGO, AMERICA_LOS_ANGELES, AMERICA_NEW_YORK, ASIA_KOLKATA, ASIA_SINGAPORE,
    ASIA_TOKYO, AUSTRALIA_SYDNEY, COMMON_TIMEZONES, EUROPE_BERLIN, EUROPE_LONDON,
    LOCKED_TIMEZONE_PROFILE,
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

// Module 35.7 — Speech Synthesis voices (Strict 4-voice cohort preserving
// screen-reader accessibility; Standard locale-bucketed) + Media
// Capabilities (mode-invariant codec baseline: H.264/VP9/AAC/Opus/MP3
// supported; HEVC/AV1 unsupported regardless of host hardware). Two new
// WebIdlSurface variants added; ALL grew 9→11.
pub use gecko::media_capabilities::{
    CodecSupport, MediaCapabilitiesOverride, MediaCapabilitiesPolicy, MediaCapabilitiesSurface,
    LOCKED_MEDIA_CAPABILITIES,
};
pub use gecko::speech_voices::{
    SpeechVoicesOverride, SpeechVoicesPolicy, SpeechVoicesSurface, VoiceProfile, LOCKED_VOICE_SET,
};

// Module 35.6 — WebGPU adapter normalization. Locks
// navigator.gpu.requestAdapter() adapter info under both modes. Strict
// cohort-locks vendor = "Mozilla" matching Module 28 WebGL (cross-module
// anti-contradiction); Standard buckets the host GPU vendor into 5
// classes while sharing the same architecture / driver / features /
// limits cohort base. WebGPU stays USABLE in Strict — Tor / Mullvad
// disable WebGPU entirely; DevBrowse goes structurally ahead.
pub use gecko::webgpu::{
    WebGpuLimits, WebGpuOverride, WebGpuProfile, WebGpuReadbackPolicy, WebGpuSurface, WebGpuVendor,
    LOCKED_WEBGPU_PROFILE,
};

// Module 35.8 — Network Information API. Strict removes
// navigator.connection entirely (property deleted from Navigator
// prototype; mirrors Module 35.3 NavigatorPropertyDeleted family but
// owned per-API here per the no-redundant-state lock — see module
// doc); Standard cohort-locks to broadband baseline (effectiveType =
// "4g", downlink = 10 Mbps, rtt = 50 ms, saveData = false, type =
// "wifi"). DevBrowse goes structurally ahead of Tor which returns a
// "4g" stub but still exposes the API surface. WebIdlSurface::ALL grew
// 11 → 12.
pub use gecko::network_info::{
    NetworkInformationOverride, NetworkInformationPolicy, NetworkInformationProfile,
    NetworkInformationSurface, LOCKED_NETWORK_INFORMATION_PROFILE,
};

// Module 35.9 — Permissions API enumeration + Storage estimate.
// Permissions: Strict denies every recognized W3C permission name
// (L44-mapped and non-L44 alike — the L41 lock forbids Strict grant
// flow); unknown names return Prompt (polluted-oracle protection
// against revealing the gate catalog). Standard delegates to
// PermissionStore (Module 59 in Phase 8; v1 ships DefaultPromptStore).
// Storage estimate: Strict reports {quota: 0, usage: 0} (Tor parity);
// Standard reports {quota: 1 GiB, usage: 0} cohort-locked.
// WebIdlSurface::ALL grew 12 → 14.
pub use gecko::permissions_query::{
    l44_disabled, CapturingPermissionStore, DefaultPromptStore, PermissionName, PermissionState,
    PermissionStore, PermissionsOverride, PermissionsPolicy, PermissionsSurface,
};
pub use gecko::storage_estimate::{
    StorageEstimateOverride, StorageEstimatePolicy, StorageEstimateProfile, StorageEstimateSurface,
    STANDARD_STORAGE_ESTIMATE, STRICT_STORAGE_ESTIMATE,
};

// Module 35.1 — Window dimension letterboxer (Strict-only normalization
// per L42; Standard bypasses in v1 pending §5.5 coarse-bucket spec).
// L41 lock is structural — for_mode(Mode::Strict) always resolves to
// Quantize(&STRICT_LETTERBOX); no user-override constructor exists.
pub use strict::letterbox::{
    Letterbox, LetterboxPolicy, WindowDimensionSurface, HEIGHT_STEP, STRICT_LETTERBOX, WIDTH_STEP,
};

// Module 35.2 — Strict-mode timer quantization (L41 + L43 layer over
// Module 32). Module 32 owns the per-Mode quantum + floor-rounding
// mechanism (single source of truth: TimerProfile::quantize_js_ns /
// quantize_js_ms). Module 35.2 ships the AsyncEventClass plumbing list
// for the six event-fire surfaces the bridge bounds via
// TimerProfile::quantize_js_ms, plus L41 idempotence regression tests
// that re-assert Module 32's structural lock.
pub use strict::timers::AsyncEventClass;

// Module 35.3 — Disabled-by-default API surface (L44 lock). 17 L44 API
// families return "not supported" in Strict without consulting Module 59
// permission center; L41 lock makes the disable non-loosenable. The 17th
// variant (SharedMemoryAndAtomics) closes the Module 35.2 audit
// carry-forward (SAB + Atomics.wait cross-thread clock channel).
pub use strict::disabled_apis::{
    disabled_for_mode, DelegatedSurface, DisableMechanism, DisabledApi,
};

// Module 35.4 — L41 settings-lock audit + conformance. Cross-module
// audit list (LockedInvariant + LockOwner) pointing at each L-invariant's
// owning typed for_mode resolver — no duplication of existing
// per-module enforcement. Generic for_mode<T> helper for FUTURE
// settings-consuming sites without a typed resolver yet (existing
// typed resolvers are not refactored to use it). Conformance tests
// invoke each pb-fingerprint-owned resolver and assert Strict
// idempotence.
pub use strict::settings_lock::{for_mode as settings_for_mode, LockOwner, LockedInvariant};

// Module 35.10 — Display capabilities + Touch surface cohort lock
// (extends Module 35.1 letterboxer). Display: Strict locks DPR=1.0 /
// colorDepth=24 / orientation=landscape-primary/0°; Standard buckets
// DPR into {1.0, 1.5, 2.0, 3.0} (Retina UX preserved). Touch: both
// modes on desktop share the maxTouchPoints=0 + pointer=fine cohort
// (v1.23 amiunique-generic unification); Phase 12 mobile carve-out
// via PlatformClass::Mobile pass-through. Module 34 boundary:
// maxTouchPoints is owned here, NOT in NavigatorSurface. Closes
// Phase 5.5 (10/10 modules done). WebIdlSurface::ALL reached 16
// variants — Phase 5.5 exit target per v1.23 audit.
pub use strict::display::{
    closest_dpr_bucket, standard_profile_for_dpr_bucket, DisplayCapabilitiesOverride,
    DisplayCapabilitiesPolicy, DisplayCapabilitiesProfile, DisplayCapabilitiesSurface, DprBucket,
    STANDARD_DISPLAY_DPR_1_0, STANDARD_DISPLAY_DPR_1_5, STANDARD_DISPLAY_DPR_2_0,
    STANDARD_DISPLAY_DPR_3_0, STANDARD_DPR_BUCKETS, STRICT_DISPLAY_PROFILE,
};
pub use strict::touch::{
    PlatformClass, TouchPathway, TouchSurfaceOverride, TouchSurfacePolicy, TouchSurfaceProfile,
    DESKTOP_TOUCH_PROFILE,
};

// Module 35.11 — DOMRect / element-bounding-box / TextMetrics
// cohort lock (P1-4 from the 2026-05-22 audit). Strict snaps every
// coordinate to integer pixels; Standard snaps + farbles ±1 px via
// the FarblingSurface::DomRect / ::TextMetrics streams.
pub use gecko::dom_rect::{
    snap_dom_rect_coord, snap_text_metric, DomRectOverride, DomRectPolicy, DomRectSurface,
};

// Module 35.12 — Intl.* defaults cohort lock (P2-7a). Both modes
// lock to the en-US cohort defaults beyond what Module 33 already
// covers for DateTimeFormat.
pub use gecko::intl_defaults::{
    IntlDefaultsOverride, IntlDefaultsPolicy, IntlDefaultsProfile, IntlSurface,
    LOCKED_INTL_DEFAULTS,
};

// Module 35.13 — navigator.keyboard.getLayoutMap() cohort lock
// (P2-7b). Mode-invariant US-QWERTY layout (matches LOCKED_LANGUAGE).
pub use gecko::keyboard_layout::{
    KeyboardKeyEntry, KeyboardLayoutOverride, KeyboardLayoutPolicy, KeyboardLayoutSurface,
    US_QWERTY_LAYOUT,
};
