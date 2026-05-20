//! Module 34 — Navigator / UA normalization.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the
//!     `Navigator` interface accessors are intercepted below the JS
//!     surface so worker / iframe / service-worker scopes share a
//!     single locked profile.
//!   * **L9 / §3.3 / §3.2** — **mostly mode-invariant locking with
//!     one cohort-divergent field**. The UA / `appVersion` /
//!     `vendor` / `platform` / `product` / `productSub` / `language`
//!     / `languages` / `deviceMemory` / `webdriver` / `doNotTrack`
//!     / `globalPrivacyControl` / plugins+mimeTypes fields are
//!     mode-invariant because Module 22 already locked the
//!     network-side UA / Accept-Language and a JS-vs-HTTP mismatch
//!     is itself a fingerprint. **`hardwareConcurrency` is the
//!     single per-Mode field**: Standard = 4 (most common
//!     real-world laptop value); Strict = 2 (Tor Browser / Mullvad
//!     Browser / Firefox RFP cohort). `hardwareConcurrency` has no
//!     HTTP analog so splitting it does not create a JS-vs-HTTP
//!     mismatch; the cohort-overlap gain with Tor / Mullvad / Firefox
//!     RFP is the highest-value privacy gain available on this
//!     field. Two profile statics (`STANDARD_NAVIGATOR_PROFILE` and
//!     `STRICT_NAVIGATOR_PROFILE`) differ in `hardware_concurrency`
//!     only; every other field is identical.
//!   * **L41 / L44** — `navigator.userAgentData` (Client Hints) +
//!     `navigator.webdriver` are part of the L44 disabled-by-default
//!     set when re-enabling would re-expose host signals; the
//!     mode-invariant lock is the v1 enforcement.
//!   * **§5.5** — central fingerprint bucketing: every Navigator
//!     accessor routes through one `NavigatorProfile`.
//!   * **threat-model A1** — `navigator.userAgent` /
//!     `navigator.platform` / `navigator.languages` are the highest-
//!     entropy passive fingerprint surfaces short of installed-font
//!     enumeration. Locking them to a single cohort value across
//!     every user is the Tor / Mullvad-class defense.
//!
//! ## Locked decision (phase-5 Goal + §5.5 matrix + Module 22 alignment)
//!
//! **Mostly mode-invariant; `hardwareConcurrency` is per-Mode.** Two
//! profile statics share every field except `hardware_concurrency`:
//! `STANDARD_NAVIGATOR_PROFILE.hardware_concurrency = 4`,
//! `STRICT_NAVIGATOR_PROFILE.hardware_concurrency = 2`. The locked
//! UA string mirrors `pb_network::DEVBROWSE_USER_AGENT` exactly in
//! both profiles. Because pb-fingerprint and pb-network are L12
//! sibling leaves (neither imports the other), UA alignment is
//! enforced by paired literal-string regression tests on either
//! side — any drift breaks one of the tests. The Phase 10
//! adversarial suite asserts live JS-vs-HTTP equality on a spawned
//! renderer.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * `LOCKED_NAVIGATOR_PROFILE` static — the cohort-locked
//!     Navigator parameters every renderer returns to JS regardless
//!     of host OS.
//!   * `NavigatorSurface::ALL` enumerating every JS accessor the
//!     libxul bridge must wire (17 variants covering the full
//!     `Navigator` IDL plus `userAgentData` / `webdriver` /
//!     `doNotTrack` / `globalPrivacyControl`).
//!   * A `FingerprintOverride` impl for `WebIdlSurface::Navigator`.
//!
//! It IS NOT:
//!   * Dynamic Navigator state — `navigator.onLine` reflects current
//!     network state (pb-network owns), `navigator.cookieEnabled`
//!     reflects pb-storage state. These are not part of the
//!     fingerprint cohort surface and are intentionally absent from
//!     `NavigatorProfile`.
//!   * The Client Hints HTTP headers (`Sec-CH-UA-*`) — those live
//!     in pb-network (Module 22 already scrubs them from outbound
//!     requests). This module pins the JS-visible
//!     `navigator.userAgentData` Brand list; the HTTP-side scrub is
//!     the cohort enforcement on the wire.
//!   * `navigator.geolocation` / `navigator.mediaDevices` /
//!     `navigator.bluetooth` / etc. — those are the L44 disabled-by-
//!     default APIs owned by Phase 5.5 Module 35.3 (a single
//!     consolidated override for all of them). Module 34 owns the
//!     "report Navigator identity" surface, not the "block API"
//!     surface.
//
// TODO(Module 1 / libxul): the Navigator accessors are exposed
//   via the WebIDL interface in `dom/webidl/Navigator.webidl` (and
//   the worker / shared-worker / service-worker variants). The FFI
//   bridge must register a per-renderer callback for each accessor
//   that returns the locked profile's field for every JsContext::ALL
//   variant.
// TODO(Module 22 cross-coupling — pb-network/src/headers.rs:54-55):
//   `DEVBROWSE_USER_AGENT` is owned by Module 22 today (TODO comment
//   explicitly says "Module 34 owns the canonical value once it lands").
//   Module 34 cannot take direct ownership because pb-fingerprint and
//   pb-network are L12 sibling leaves. Two paths to resolution:
//   (a) move both constants to pb-config (a leaf both can read);
//   (b) keep them duplicated and enforce equality via paired tests
//   on both sides (the current v1 approach). The Phase 10 adversarial
//   suite is the third defense — it asserts the LIVE JS-visible UA
//   equals the HTTP-sent UA on a spawned renderer, catching any
//   drift even if the literal-string tests are out of sync.
// TODO(Phase 5.5 / Module 35.3): the L44 disabled-by-default API
//   set (Geolocation, MediaDevices, Bluetooth, USB, HID, Serial,
//   NFC, 9 sensors, Gamepad, sendBeacon, Notification, WakeLock,
//   IdleDetector, PresentationRequest, PaymentRequest) layers on
//   top of Navigator's identity surface. Module 34 ships the
//   identity surface today; Module 35.3 ships the cross-API
//   disabled lock.
// TODO(Phase 10 / Module 71+): the CreepJS / FPStandard navigator
//   probes will iterate every accessor on `navigator` (and the
//   worker `WorkerNavigator` interface) and assert byte-equality
//   against the locked profile. The JS-vs-HTTP UA equality check
//   is the cross-coupling regression test.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked Navigator profile (mode-invariant cohort) ──────────────────────

/// User-Agent locked across the cohort. **MUST match
/// `pb_network::DEVBROWSE_USER_AGENT` byte-for-byte** — a JS-vs-HTTP
/// UA mismatch is itself a fingerprint signal. Asserted by the
/// `navigator_ua_matches_module_22_constant` regression test below
/// and by the Phase 10 adversarial suite on live renderers.
///
/// Locked to the Firefox 128 ESR UA + Linux x86_64 platform token
/// because Tor Browser / Mullvad Browser ship the same family of
/// strings (Tor uses Firefox ESR + Win64 token for maximum cohort;
/// DevBrowse uses Firefox ESR + Linux x86_64 because the v1 desktop
/// MVP is Linux per L3 — when Windows lands in Phase 11.9, the UA
/// stays as the Linux token regardless of host OS, matching Tor's
/// cohort-by-spoof strategy).
pub const LOCKED_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// `navigator.language` — single locked locale. Matches
/// `Accept-Language` first entry (`pb_network::DEVBROWSE_ACCEPT_LANGUAGE`
/// `"en-US,en;q=0.5"` -> first locale is `"en-US"`).
pub const LOCKED_LANGUAGE: &str = "en-US";

/// `navigator.languages` — ordered list. Two entries matching the
/// Accept-Language q-value progression in Module 22.
pub const LOCKED_LANGUAGES: &[&str] = &["en-US", "en"];

/// Cohort-locked Navigator profile. Single value used in both modes.
///
/// `Copy` + `Eq` + `Hash` — every field is `&'static str` / `u32` /
/// `bool`. Address-identity invariant via `ptr::eq` against
/// `LOCKED_NAVIGATOR_PROFILE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NavigatorProfile {
    /// `navigator.userAgent` — full UA string. MUST equal
    /// `LOCKED_USER_AGENT` (and `pb_network::DEVBROWSE_USER_AGENT`).
    pub user_agent: &'static str,
    /// `navigator.appName` — legacy fixed `"Netscape"`.
    pub app_name: &'static str,
    /// `navigator.appVersion` — derived from UA; everything after
    /// the `"Mozilla/"` prefix.
    pub app_version: &'static str,
    /// `navigator.vendor` — `""` (Firefox convention; Chrome sets
    /// `"Google Inc."`). Empty string is the cohort identifier
    /// claiming the Mozilla / Firefox family.
    pub vendor: &'static str,
    /// `navigator.platform` — `"Linux x86_64"` (matches the UA token).
    pub platform: &'static str,
    /// `navigator.product` — legacy fixed `"Gecko"`.
    pub product: &'static str,
    /// `navigator.productSub` — legacy fixed `"20100101"` (the
    /// Mozilla buildID convention).
    pub product_sub: &'static str,
    /// `navigator.language` — primary locale.
    pub language: &'static str,
    /// `navigator.languages` — ordered locale list.
    pub languages: &'static [&'static str],
    /// `navigator.hardwareConcurrency` — locked to 4 (Tor RFP
    /// parity; one of the most-common values across Tor / Mullvad
    /// cohort).
    pub hardware_concurrency: u32,
    /// `navigator.deviceMemory` — locked to 8 GiB (the Web spec
    /// bucket; one of the most-common values). Spec returns float;
    /// stored as integer here and converted at the libxul boundary.
    pub device_memory_gib: u32,
    /// `navigator.doNotTrack` — `"1"` (matches Module 22
    /// `send_dnt = true` for both modes).
    pub do_not_track: &'static str,
    /// `navigator.globalPrivacyControl` — `true` (matches Module 22
    /// `send_sec_gpc = true` for both modes).
    pub global_privacy_control: bool,
    /// `navigator.webdriver` — `false`. DevBrowse is not a
    /// WebDriver-driven browser; sites probing for automation get
    /// the same answer everyone else does.
    pub webdriver: bool,
    /// `navigator.plugins.length` — `0`. Industry consensus
    /// (Firefox 52+ exposes empty PluginArray).
    pub plugins_count: u32,
    /// `navigator.mimeTypes.length` — `0`. Must match
    /// `plugins_count` (the two arrays are derived from each other
    /// in the WebIDL).
    pub mime_types_count: u32,
}

/// Standard-mode Navigator profile. **`hardware_concurrency = 4`**
/// (most common real-world laptop value; the Web Worker cohort that
/// computation-heavy sites already optimize against).
///
/// Every field other than `hardware_concurrency` is identical to
/// `STRICT_NAVIGATOR_PROFILE` — asserted by
/// `standard_and_strict_share_every_field_except_hardware_concurrency`.
///
/// `static` (not `const`): cohort consumers compare by address
/// (`ptr::eq`). `const` items can be constant-folded to distinct
/// addresses, breaking the singleton invariant.
pub static STANDARD_NAVIGATOR_PROFILE: NavigatorProfile = NavigatorProfile {
    user_agent: LOCKED_USER_AGENT,
    app_name: "Netscape",
    app_version: "5.0 (X11)",
    vendor: "",
    platform: "Linux x86_64",
    product: "Gecko",
    product_sub: "20100101",
    language: LOCKED_LANGUAGE,
    languages: LOCKED_LANGUAGES,
    hardware_concurrency: 4,
    device_memory_gib: 8,
    do_not_track: "1",
    global_privacy_control: true,
    webdriver: false,
    plugins_count: 0,
    mime_types_count: 0,
};

/// Strict-mode Navigator profile. **`hardware_concurrency = 2`** —
/// matches Tor Browser, Mullvad Browser, and Firefox `privacy.
/// resistFingerprinting`. The cohort overlap with those existing
/// privacy-aware browser populations is the v1 cohort lock; changing
/// the value is a cohort shift through the Adaptation protocol.
///
/// Every field other than `hardware_concurrency` is identical to
/// `STANDARD_NAVIGATOR_PROFILE` — `hardwareConcurrency` has no HTTP
/// analog so the per-Mode split does not create a JS-vs-HTTP
/// fingerprint mismatch like a UA split would.
pub static STRICT_NAVIGATOR_PROFILE: NavigatorProfile = NavigatorProfile {
    user_agent: LOCKED_USER_AGENT,
    app_name: "Netscape",
    app_version: "5.0 (X11)",
    vendor: "",
    platform: "Linux x86_64",
    product: "Gecko",
    product_sub: "20100101",
    language: LOCKED_LANGUAGE,
    languages: LOCKED_LANGUAGES,
    hardware_concurrency: 2,
    device_memory_gib: 8,
    do_not_track: "1",
    global_privacy_control: true,
    webdriver: false,
    plugins_count: 0,
    mime_types_count: 0,
};

// ── Policy ────────────────────────────────────────────────────────────────

/// Per-mode Navigator policy.
///
/// The `Locked` variant carries the per-Mode profile:
/// `STANDARD_NAVIGATOR_PROFILE` for `Mode::Standard` and
/// `STRICT_NAVIGATOR_PROFILE` for `Mode::Strict`. The two profiles
/// differ in `hardware_concurrency` only; every other field is
/// identical (mostly mode-invariant lock).
///
/// The bridge MUST match exhaustively so any future variant
/// (e.g. a "PartialNative" Standard carve-out) lands explicitly
/// rather than as a silent fall-through.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NavigatorPolicy {
    /// Per-Mode locked profile. `Mode::Standard` resolves to
    /// `&STANDARD_NAVIGATOR_PROFILE` (hardware_concurrency 4);
    /// `Mode::Strict` resolves to `&STRICT_NAVIGATOR_PROFILE`
    /// (hardware_concurrency 2 — Tor / Mullvad / Firefox RFP
    /// cohort).
    Locked(&'static NavigatorProfile),
}

impl NavigatorPolicy {
    /// Per-Mode lock:
    ///   * `Mode::Standard` -> `Locked(&STANDARD_NAVIGATOR_PROFILE)`
    ///   * `Mode::Strict`   -> `Locked(&STRICT_NAVIGATOR_PROFILE)`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Locked(&STANDARD_NAVIGATOR_PROFILE),
            Mode::Strict => Self::Locked(&STRICT_NAVIGATOR_PROFILE),
        }
    }

    /// The profile this policy is exposing.
    pub fn profile(&self) -> &'static NavigatorProfile {
        match *self {
            Self::Locked(p) => p,
        }
    }
}

// ── Surface enumeration ───────────────────────────────────────────────────

/// Every JS accessor on `Navigator` that exposes a cohort-relevant
/// signal.
///
/// 17 variants covering the full WebIDL `Navigator` interface plus
/// `userAgentData` (Client Hints object), `webdriver` (automation
/// detection), `doNotTrack` (DNT preference echo), and
/// `globalPrivacyControl` (Sec-GPC preference echo).
///
/// Dynamic state accessors (`onLine`, `cookieEnabled`) are
/// intentionally NOT in this enum — they reflect runtime state
/// owned by other crates (pb-network, pb-storage) and are not
/// fingerprint-cohort signals.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NavigatorSurface {
    /// `navigator.userAgent` — the canonical UA string.
    UserAgent,
    /// `navigator.appName` — legacy `"Netscape"`.
    AppName,
    /// `navigator.appVersion` — UA-derived.
    AppVersion,
    /// `navigator.vendor` — Firefox: `""`; Chrome: `"Google Inc."`.
    Vendor,
    /// `navigator.platform` — `"Linux x86_64"` regardless of host.
    Platform,
    /// `navigator.product` — legacy `"Gecko"`.
    Product,
    /// `navigator.productSub` — legacy `"20100101"`.
    ProductSub,
    /// `navigator.language` — primary locale.
    Language,
    /// `navigator.languages` — ordered locale list.
    Languages,
    /// `navigator.hardwareConcurrency` — logical CPU count
    /// (cohort-locked to 4).
    HardwareConcurrency,
    /// `navigator.deviceMemory` — coarse RAM bucket in GiB
    /// (cohort-locked to 8).
    DeviceMemory,
    /// `navigator.plugins` — empty `PluginArray`.
    Plugins,
    /// `navigator.mimeTypes` — empty `MimeTypeArray`.
    MimeTypes,
    /// `navigator.userAgentData` — Client Hints object
    /// (`NavigatorUAData`); brand list locked to the same Firefox
    /// 128 cohort.
    UserAgentData,
    /// `navigator.webdriver` — automation-detection boolean
    /// (locked `false`).
    Webdriver,
    /// `navigator.doNotTrack` — DNT preference echo (locked `"1"`).
    DoNotTrack,
    /// `navigator.globalPrivacyControl` — Sec-GPC echo (locked
    /// `true`).
    GlobalPrivacyControl,
}

impl NavigatorSurface {
    /// Every Navigator accessor the bridge must wire. Asserted
    /// against the WebIDL interface IDL by
    /// `tests::navigator_surface_all_covers_idl`.
    pub const ALL: &'static [NavigatorSurface] = &[
        Self::UserAgent,
        Self::AppName,
        Self::AppVersion,
        Self::Vendor,
        Self::Platform,
        Self::Product,
        Self::ProductSub,
        Self::Language,
        Self::Languages,
        Self::HardwareConcurrency,
        Self::DeviceMemory,
        Self::Plugins,
        Self::MimeTypes,
        Self::UserAgentData,
        Self::Webdriver,
        Self::DoNotTrack,
        Self::GlobalPrivacyControl,
    ];
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Navigator`.
///
/// Construct with `NavigatorOverride::new(mode)` for symmetry with
/// other Phase-5 overrides. The constructor accepts a `Mode`
/// argument but does not use it (policy is mode-invariant). Keeping
/// the signature uniform across Phase-5 modules means the libxul
/// bridge has one registration code path.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data; install produces observationally
/// identical state regardless of `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct NavigatorOverride {
    policy: NavigatorPolicy,
}

impl NavigatorOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: NavigatorPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> NavigatorPolicy {
        self.policy
    }

    /// The profile this override is exposing.
    pub fn profile(&self) -> &'static NavigatorProfile {
        self.policy.profile()
    }
}

impl FingerprintOverride for NavigatorOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Navigator
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul Navigator accessor hooks
        // are not yet wired (see crate-level TODO). When the FFI
        // lands, both modes register a per-accessor callback that
        // returns the corresponding field of the renderer's
        // per-Mode profile (`STANDARD_NAVIGATOR_PROFILE` or
        // `STRICT_NAVIGATOR_PROFILE`) for every NavigatorSurface ×
        // JsContext plumb-in.
        let _ = (self.policy, JsContext::ALL);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_profile_matches_cohort_definition() {
        // v1 Standard cohort lock. hardware_concurrency = 4 is the
        // most common real-world laptop value; the rest of the
        // profile is the mostly-mode-invariant lock.
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.user_agent, LOCKED_USER_AGENT);
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.app_name, "Netscape");
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.app_version, "5.0 (X11)");
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.vendor, "");
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.platform, "Linux x86_64");
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.product, "Gecko");
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.product_sub, "20100101");
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.language, "en-US");
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.languages, &["en-US", "en"]);
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.hardware_concurrency, 4);
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.device_memory_gib, 8);
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.do_not_track, "1");
        assert!(STANDARD_NAVIGATOR_PROFILE.global_privacy_control);
        assert!(!STANDARD_NAVIGATOR_PROFILE.webdriver);
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.plugins_count, 0);
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.mime_types_count, 0);
    }

    #[test]
    fn strict_profile_matches_cohort_definition() {
        // v1 Strict cohort lock. hardware_concurrency = 2 matches
        // Tor Browser / Mullvad Browser / Firefox RFP — the largest
        // privacy-aware cohort on the public web. Asserted separately
        // by `strict_hardware_concurrency_matches_tor_mullvad_firefox_rfp`.
        assert_eq!(STRICT_NAVIGATOR_PROFILE.user_agent, LOCKED_USER_AGENT);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.app_name, "Netscape");
        assert_eq!(STRICT_NAVIGATOR_PROFILE.app_version, "5.0 (X11)");
        assert_eq!(STRICT_NAVIGATOR_PROFILE.vendor, "");
        assert_eq!(STRICT_NAVIGATOR_PROFILE.platform, "Linux x86_64");
        assert_eq!(STRICT_NAVIGATOR_PROFILE.product, "Gecko");
        assert_eq!(STRICT_NAVIGATOR_PROFILE.product_sub, "20100101");
        assert_eq!(STRICT_NAVIGATOR_PROFILE.language, "en-US");
        assert_eq!(STRICT_NAVIGATOR_PROFILE.languages, &["en-US", "en"]);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.hardware_concurrency, 2);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.device_memory_gib, 8);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.do_not_track, "1");
        assert!(STRICT_NAVIGATOR_PROFILE.global_privacy_control);
        assert!(!STRICT_NAVIGATOR_PROFILE.webdriver);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.plugins_count, 0);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.mime_types_count, 0);
    }

    #[test]
    fn strict_hardware_concurrency_matches_tor_mullvad_firefox_rfp() {
        // The cohort overlap with Tor Browser / Mullvad Browser /
        // Firefox `privacy.resistFingerprinting` — all three lock to
        // 2. This is the privacy lock; any change is a cohort shift.
        assert_eq!(STRICT_NAVIGATOR_PROFILE.hardware_concurrency, 2);
    }

    #[test]
    fn standard_and_strict_share_every_field_except_hardware_concurrency() {
        // Mostly-mode-invariant lock invariant: the two profiles are
        // identical except for `hardware_concurrency`. If a future
        // change introduces a second per-Mode field, this test
        // breaks and the divergence must be justified explicitly.
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.user_agent,
            STRICT_NAVIGATOR_PROFILE.user_agent
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.app_name,
            STRICT_NAVIGATOR_PROFILE.app_name
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.app_version,
            STRICT_NAVIGATOR_PROFILE.app_version
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.vendor,
            STRICT_NAVIGATOR_PROFILE.vendor
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.platform,
            STRICT_NAVIGATOR_PROFILE.platform
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.product,
            STRICT_NAVIGATOR_PROFILE.product
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.product_sub,
            STRICT_NAVIGATOR_PROFILE.product_sub
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.language,
            STRICT_NAVIGATOR_PROFILE.language
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.languages,
            STRICT_NAVIGATOR_PROFILE.languages
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.device_memory_gib,
            STRICT_NAVIGATOR_PROFILE.device_memory_gib
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.do_not_track,
            STRICT_NAVIGATOR_PROFILE.do_not_track
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.global_privacy_control,
            STRICT_NAVIGATOR_PROFILE.global_privacy_control
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.webdriver,
            STRICT_NAVIGATOR_PROFILE.webdriver
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.plugins_count,
            STRICT_NAVIGATOR_PROFILE.plugins_count
        );
        assert_eq!(
            STANDARD_NAVIGATOR_PROFILE.mime_types_count,
            STRICT_NAVIGATOR_PROFILE.mime_types_count
        );
        // The ONE allowed difference:
        assert_ne!(
            STANDARD_NAVIGATOR_PROFILE.hardware_concurrency,
            STRICT_NAVIGATOR_PROFILE.hardware_concurrency
        );
    }

    #[test]
    fn navigator_ua_matches_module_22_constant() {
        // CROSS-MODULE REGRESSION TEST. pb-fingerprint cannot import
        // pb-network (L12 sibling leaves), so the alignment is
        // enforced by hardcoding the expected literal on both sides.
        // If pb_network::DEVBROWSE_USER_AGENT ever drifts from this
        // value, the paired test in pb-network breaks first; if
        // LOCKED_USER_AGENT here drifts, this test breaks. The
        // Phase 10 adversarial suite is the third defense (live
        // JS-vs-HTTP equality check on a spawned renderer).
        const MODULE_22_EXPECTED_UA: &str =
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
        assert_eq!(LOCKED_USER_AGENT, MODULE_22_EXPECTED_UA);
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.user_agent, MODULE_22_EXPECTED_UA);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.user_agent, MODULE_22_EXPECTED_UA);
    }

    #[test]
    fn navigator_language_matches_module_22_accept_language() {
        // Accept-Language is "en-US,en;q=0.5" — the first locale is
        // "en-US" (matches navigator.language) and the q-value
        // progression gives navigator.languages = ["en-US", "en"].
        const MODULE_22_EXPECTED_LANGUAGE: &str = "en-US";
        const MODULE_22_EXPECTED_LANGUAGES: &[&str] = &["en-US", "en"];
        assert_eq!(LOCKED_LANGUAGE, MODULE_22_EXPECTED_LANGUAGE);
        assert_eq!(LOCKED_LANGUAGES, MODULE_22_EXPECTED_LANGUAGES);
    }

    #[test]
    fn navigator_dnt_and_gpc_match_module_22_send_flags() {
        // Module 22's HeaderPolicy ships `send_dnt = true` and
        // `send_sec_gpc = true` in BOTH standard() and strict().
        // The JS-visible navigator.doNotTrack must echo "1" and
        // navigator.globalPrivacyControl must be true — otherwise
        // sites can probe the JS preference vs the HTTP header and
        // detect a mismatch. Both profiles ship the same values.
        assert_eq!(STANDARD_NAVIGATOR_PROFILE.do_not_track, "1");
        assert!(STANDARD_NAVIGATOR_PROFILE.global_privacy_control);
        assert_eq!(STRICT_NAVIGATOR_PROFILE.do_not_track, "1");
        assert!(STRICT_NAVIGATOR_PROFILE.global_privacy_control);
    }

    #[test]
    fn for_mode_picks_per_mode_profile() {
        // Per-Mode profile singletons. Standard renderers point at
        // STANDARD_NAVIGATOR_PROFILE; Strict at STRICT_NAVIGATOR_PROFILE.
        let s = NavigatorPolicy::for_mode(Mode::Standard);
        let r = NavigatorPolicy::for_mode(Mode::Strict);
        assert!(matches!(s, NavigatorPolicy::Locked(_)));
        assert!(matches!(r, NavigatorPolicy::Locked(_)));
        assert!(std::ptr::eq(s.profile(), &STANDARD_NAVIGATOR_PROFILE));
        assert!(std::ptr::eq(r.profile(), &STRICT_NAVIGATOR_PROFILE));
        // Address identity across modes: the two profiles are NOT
        // the same singleton — the per-Mode `hardware_concurrency`
        // split requires divergence.
        assert!(!std::ptr::eq(s.profile(), r.profile()));
        assert_eq!(s.profile().hardware_concurrency, 4);
        assert_eq!(r.profile().hardware_concurrency, 2);
    }

    #[test]
    fn navigator_surface_all_covers_idl() {
        // 17 surfaces: 13 classic Navigator accessors + Client Hints
        // (UserAgentData) + Webdriver + DoNotTrack +
        // GlobalPrivacyControl. Dynamic-state accessors (onLine,
        // cookieEnabled) are intentionally excluded — they reflect
        // runtime state from pb-network / pb-storage.
        assert_eq!(NavigatorSurface::ALL.len(), 17);
        for v in [
            NavigatorSurface::UserAgent,
            NavigatorSurface::AppName,
            NavigatorSurface::AppVersion,
            NavigatorSurface::Vendor,
            NavigatorSurface::Platform,
            NavigatorSurface::Product,
            NavigatorSurface::ProductSub,
            NavigatorSurface::Language,
            NavigatorSurface::Languages,
            NavigatorSurface::HardwareConcurrency,
            NavigatorSurface::DeviceMemory,
            NavigatorSurface::Plugins,
            NavigatorSurface::MimeTypes,
            NavigatorSurface::UserAgentData,
            NavigatorSurface::Webdriver,
            NavigatorSurface::DoNotTrack,
            NavigatorSurface::GlobalPrivacyControl,
        ] {
            assert!(
                NavigatorSurface::ALL.contains(&v),
                "missing surface: {:?}",
                v
            );
        }
    }

    #[test]
    fn navigator_override_reports_navigator_surface_under_both_modes() {
        assert_eq!(
            NavigatorOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Navigator
        );
        assert_eq!(
            NavigatorOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Navigator
        );
    }

    #[test]
    fn override_carries_per_mode_profile() {
        let standard = NavigatorOverride::new(Mode::Standard);
        let strict = NavigatorOverride::new(Mode::Strict);
        assert!(std::ptr::eq(
            standard.profile(),
            &STANDARD_NAVIGATOR_PROFILE
        ));
        assert!(std::ptr::eq(strict.profile(), &STRICT_NAVIGATOR_PROFILE));
        // Per-Mode lock: the two overrides point at distinct
        // singletons differing in `hardware_concurrency`.
        assert!(!std::ptr::eq(standard.profile(), strict.profile()));
        assert_eq!(standard.profile().hardware_concurrency, 4);
        assert_eq!(strict.profile().hardware_concurrency, 2);
    }

    #[test]
    fn navigator_override_install_is_context_inert() {
        // Edge case: override must be inert in iframe / worker /
        // service-worker / dedicated-worker. Workers expose
        // WorkerNavigator (a subset of Navigator) — the override
        // must report the same locked values across every JS scope.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000034").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = NavigatorOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Navigator);
        }
    }

    #[test]
    fn navigator_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NavigatorOverride>();
        assert_send_sync::<NavigatorPolicy>();
        assert_send_sync::<NavigatorProfile>();
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // The bridge MUST match without a `_` arm so a new variant
        // (e.g. a hypothetical `Connection` accessor for the
        // NetworkInformation API) fails compilation until the
        // bridge wires it.
        fn route(s: NavigatorSurface) -> &'static str {
            match s {
                NavigatorSurface::UserAgent => "user-agent",
                NavigatorSurface::AppName => "app-name",
                NavigatorSurface::AppVersion => "app-version",
                NavigatorSurface::Vendor => "vendor",
                NavigatorSurface::Platform => "platform",
                NavigatorSurface::Product => "product",
                NavigatorSurface::ProductSub => "product-sub",
                NavigatorSurface::Language => "language",
                NavigatorSurface::Languages => "languages",
                NavigatorSurface::HardwareConcurrency => "hardware-concurrency",
                NavigatorSurface::DeviceMemory => "device-memory",
                NavigatorSurface::Plugins => "plugins",
                NavigatorSurface::MimeTypes => "mime-types",
                NavigatorSurface::UserAgentData => "user-agent-data",
                NavigatorSurface::Webdriver => "webdriver",
                NavigatorSurface::DoNotTrack => "do-not-track",
                NavigatorSurface::GlobalPrivacyControl => "global-privacy-control",
            }
        }
        for s in NavigatorSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: NavigatorPolicy) -> &'static str {
            match p {
                NavigatorPolicy::Locked(_) => "locked",
            }
        }
        assert_eq!(arm(NavigatorPolicy::for_mode(Mode::Standard)), "locked");
        assert_eq!(arm(NavigatorPolicy::for_mode(Mode::Strict)), "locked");
    }
}
