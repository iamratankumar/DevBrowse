//! Module 35 — WebKit backend stub.
//!
//! ## What this module is
//!
//! When DevBrowse runs on iOS (Phase 12), the underlying engine is
//! **WebKit, forced by Apple App Store policy 2.5.6** — third-party
//! browser engines are not permitted on iOS. WebKit does not expose
//! Gecko-style WebIDL override points (the L8 mechanism used by
//! Modules 27-34), so Phase-5 fingerprint normalization on iOS is
//! **best-effort UA-level compat only**, not the active rasterizer /
//! DSP / Navigator-accessor patching that Gecko ships.
//!
//! Module 35 ships the surface today so Phase 12 can implement
//! against a stable contract. The actual iOS implementation is
//! design-disciplined-not-implemented per the project plan
//! (Phase 12 is mobile and reserved).
//!
//! Sites that treat WebKit as a privileged tier (Apple Pay being the
//! canonical example — sites that probe for `window.ApplePaySession`
//! or sniff `Safari` in the UA) work naturally on the iOS build
//! because the underlying engine IS WebKit. The phase-file edge case
//! "must not falsely advertise WebKit-only API presence" is the
//! desktop-Gecko obligation: DevBrowse on Gecko MUST NOT spoof
//! WebKit-specific APIs (`window.safari`, `WebKitCSSMatrix`,
//! `ApplePaySession`) because the underlying engine cannot actually
//! deliver them.
//!
//! Architecture references:
//!   * **L8** — WebKit on iOS does not expose Gecko WebIDL override
//!     points; the cohort lock surface for iOS users is the natural
//!     Safari identity, not a normalized profile we install.
//!   * **§3.3 / §3.2** — best-effort posture for iOS: every Gecko
//!     normalization (canvas / WebGL / audio / fonts / battery /
//!     timers / timezone / navigator) maps to
//!     `WebKitNormalizationCapability::Unsupported`. The mode
//!     parameter is accepted for API symmetry but does not
//!     influence behavior — both Standard and Strict iOS users
//!     inherit the WebKit-native identity.
//!   * **Cross-platform principle (CLAUDE.md):** every Phase-5
//!     module must keep the public API surface identical across
//!     Linux / macOS / iOS / Android. Module 35 is the iOS-side
//!     surface; the trait shape mirrors the Gecko-side
//!     `FingerprintOverride` contract (Module 26) so cross-platform
//!     callers do not branch by platform.
//!   * **Module 26 / interface.rs comment**: "Module 35 (WebKit
//!     stub) is not a Gecko WebIDL plumb-in" — `WebIdlSurface::ALL`
//!     intentionally does not enumerate a WebKit variant. The iOS
//!     backend lives behind this module instead.
//!
//! ## Mode-applicability
//!
//! **Mode-invariant best-effort pass-through.** Both Standard and
//! Strict iOS users see the WebKit-native identity (`WEBKIT_STUB_PROFILE`).
//! Strict cannot enforce Tor-grade normalization on WebKit because
//! the engine does not expose the hooks; this is documented as a
//! known platform limitation in the v1 UX and surfaced via
//! `WebKitNormalizationCapability::Unsupported`. Users seeking
//! Tor-grade normalization on iOS should be redirected to the
//! desktop builds (where Gecko's WebIDL hooks are available) or to
//! Tor Browser's own iOS variant (which ships its own WebKit
//! mitigations).
//!
//! ## What this is NOT
//!
//! - **Not a Safari-impersonation layer for the desktop Gecko build.**
//!   Module 34 already locks the desktop UA to Firefox; Module 35
//!   does not provide a per-site UA flip to Safari. (If a future
//!   "force Safari UA for Apple Pay sites" feature lands, it would
//!   be a separate module + a Module 59 permission-center hook, not
//!   this stub.)
//! - **Not a WebKit API shim.** DevBrowse on Gecko must not spoof
//!   `window.safari`, `WebKitCSSMatrix`, `ApplePaySession`, etc. —
//!   that would create site-breakage when scripts actually invoke
//!   the spoofed APIs.
//
// TODO(Phase 12 / iOS): the iOS backend implementation lands here
//   when Phase 12 starts. At minimum:
//   - WKWebView configuration that disables third-party storage by
//     default (matches §3.5 partition-key intent on the platform
//     where Gecko-style network-state-partitioning is not available).
//   - UA pinning to the locked iOS Safari UA cohort (so DevBrowse on
//     iOS does not split into per-device cohorts via UA suffix).
//   - WKContentRuleList integration for the Module 21 blocklist.
//   - Best-effort timer quantization via `setTimeout` shimming
//     (sub-ms resolution is harder to reach than Gecko's
//     `performance.now()` patch but a reasonable proxy is possible).
// TODO(Module 69 / wrapper-compatibility): when Phase 12 ships, the
//   wrapper-checker must include iOS WebKit version tracking. WebKit
//   bumps move every iOS user's UA cohort together (no per-user
//   divergence), so this is a low-frequency cohort shift event but
//   must be tracked.

use pb_config::Mode;

// ── WebKit-native identity (cohort-cohort accounting) ─────────────────────

/// Safari-style identity values DevBrowse inherits when running on
/// WebKit / iOS. These are NOT values we install on top of WebKit —
/// they are the natural WebKit identity, documented here so the
/// cross-platform cohort accounting has a known-static reference.
///
/// The iOS Safari UA reported by iOS 17 + Safari 17 + iPhone (the
/// dominant Phase 12 target cohort). Older iOS versions report a
/// slightly different UA token; DevBrowse on iOS will join the
/// cohort of the iOS version it ships against, not pin to a
/// historical UA.
///
/// `Copy` + `Eq` + `Hash` because every field is `&'static str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WebKitStubProfile {
    /// `navigator.userAgent` — natural WebKit/Safari iOS string.
    pub user_agent: &'static str,
    /// `navigator.vendor` — Apple's WebKit convention.
    pub vendor: &'static str,
    /// `navigator.platform` — iOS / iPhone-class identifier.
    pub platform: &'static str,
}

/// The v1 iOS WebKit cohort identity. iOS 17 + Safari 17 + iPhone
/// (the dominant Phase 12 target). When Phase 12 actually ships, the
/// libxul wrapper-compatibility checker tracks WebKit version bumps
/// and updates this constant via the Adaptation protocol.
///
/// `static` (not `const`): cohort consumers compare by address
/// (`ptr::eq`). Same rationale as the Gecko-side `LOCKED_*`
/// statics — `const` items can be constant-folded to distinct
/// addresses and silently break singleton invariants.
pub static WEBKIT_STUB_PROFILE: WebKitStubProfile = WebKitStubProfile {
    user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
         AppleWebKit/605.1.15 (KHTML, like Gecko) \
         Version/17.0 Mobile/15E148 Safari/604.1",
    vendor: "Apple Computer, Inc.",
    platform: "iPhone",
};

// ── Per-surface normalization capability ──────────────────────────────────

/// Whether a given Gecko-side fingerprint normalization is reachable
/// on WebKit / iOS.
///
/// **Almost everything is `Unsupported` on WebKit.** WebKit does not
/// expose the Gecko-style WebIDL hook points that Modules 27-34 use,
/// so the iOS backend cannot install pixel-level / DSP-level /
/// accessor-level overrides. A few areas (timer-quantization via
/// `setTimeout` shimming, blocklist via `WKContentRuleList`) are
/// reachable through different APIs, but the v1 stub reports
/// `Unsupported` across the board; Phase 12 will refine specific
/// rows.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebKitNormalizationCapability {
    /// The surface is not reachable on WebKit; the renderer inherits
    /// the native WebKit behavior. Cohort-accounted as "WebKit
    /// native, no DevBrowse-side normalization."
    Unsupported,
    /// The surface is partially reachable via a non-WebIDL API
    /// (`WKContentRuleList`, `setTimeout` shimming, etc.). Phase 12
    /// will use this variant for the specific rows it actually
    /// implements.
    BestEffort,
}

/// Maps each Gecko-side Phase-5 module to its WebKit reachability.
///
/// `Unsupported` for every Phase-5 surface in v1. Phase 12 may
/// promote specific rows to `BestEffort` as the iOS backend ships.
/// The bridge / UI consults this list to surface the "this
/// normalization is unavailable on iOS" message per-feature, so
/// users moving from desktop to iOS get an explicit "what changes"
/// summary rather than silent degradation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebKitNormalizationSurface {
    /// Module 27 — Canvas readback. Unsupported (no WebIDL hook for
    /// the rasterizer on WebKit).
    Canvas,
    /// Module 28 — WebGL parameters. Unsupported.
    WebGl,
    /// Module 29 — Web Audio. Unsupported.
    Audio,
    /// Module 30 — Fonts enumeration. Partial: iOS already ships a
    /// limited font set, so the natural cohort is already narrow;
    /// reported as `Unsupported` because DevBrowse does not actively
    /// normalize it.
    Fonts,
    /// Module 31 — Battery API. Unsupported on iOS Safari (Safari
    /// already removed the API natively in 2018; the cohort is
    /// already correct, but the v1 stub reports Unsupported because
    /// the absence is WebKit's behavior, not ours).
    Battery,
    /// Module 32 — Timers. `BestEffort` reachable via `setTimeout`
    /// shimming (sub-ms resolution is harder to bound than Gecko's
    /// `performance.now()` patch, but a usable proxy exists). Phase
    /// 12 may upgrade this row.
    Timers,
    /// Module 33 — Timezone. Unsupported (WebKit does not expose a
    /// hook for `Intl.DateTimeFormat`'s timezone resolver).
    Timezone,
    /// Module 34 — Navigator. Unsupported (UA / `languages` /
    /// `hardwareConcurrency` are WebKit-native on iOS).
    Navigator,
}

impl WebKitNormalizationSurface {
    /// Every Gecko-side surface the Phase 12 backend may need to
    /// account for. Mirrors the Phase-5 module list except for
    /// WebKit-not-applicable surfaces (e.g. the Strict-only L42
    /// letterboxing).
    pub const ALL: &'static [WebKitNormalizationSurface] = &[
        Self::Canvas,
        Self::WebGl,
        Self::Audio,
        Self::Fonts,
        Self::Battery,
        Self::Timers,
        Self::Timezone,
        Self::Navigator,
    ];

    /// The v1 reachability map. Every surface returns
    /// `Unsupported` today; Phase 12 may refine specific entries
    /// (likely candidates: `Timers` → `BestEffort` via setTimeout
    /// shimming).
    pub fn capability_v1(self) -> WebKitNormalizationCapability {
        match self {
            Self::Canvas
            | Self::WebGl
            | Self::Audio
            | Self::Fonts
            | Self::Battery
            | Self::Timezone
            | Self::Navigator => WebKitNormalizationCapability::Unsupported,
            // Timers is the most-reachable surface on WebKit via
            // setTimeout / Date.now shimming; v1 still reports
            // Unsupported because Phase 12 has not implemented it,
            // but the row is the most-likely candidate for promotion.
            Self::Timers => WebKitNormalizationCapability::Unsupported,
        }
    }
}

// ── Stub backend ──────────────────────────────────────────────────────────

/// The iOS WebKit backend stub.
///
/// Construct with `WebKitStub::new(mode)`. The mode argument is
/// accepted for API symmetry with the Gecko-side Phase-5 modules
/// but does not influence behavior — both Standard and Strict iOS
/// users inherit the WebKit-native identity. This is documented as
/// a known platform limitation: Strict on iOS cannot reach
/// Tor-grade normalization because WebKit does not expose the
/// hooks.
///
/// `Copy` because the struct contains only the mode tag + an
/// implicit reference to the static `WEBKIT_STUB_PROFILE`.
#[derive(Debug, Clone, Copy)]
pub struct WebKitStub {
    mode: Mode,
}

impl WebKitStub {
    pub fn new(mode: Mode) -> Self {
        Self { mode }
    }

    /// The mode this stub was constructed with. Carried for cohort
    /// accounting; behavior does not vary by mode in v1.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The WebKit-native identity values this stub reports. Address
    /// identity (`ptr::eq` against `WEBKIT_STUB_PROFILE`) for the
    /// cohort-singleton check.
    pub fn profile(&self) -> &'static WebKitStubProfile {
        &WEBKIT_STUB_PROFILE
    }

    /// Whether the given Gecko-side normalization is reachable on
    /// WebKit. Delegates to
    /// `WebKitNormalizationSurface::capability_v1`.
    pub fn capability(&self, surface: WebKitNormalizationSurface) -> WebKitNormalizationCapability {
        surface.capability_v1()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webkit_stub_profile_matches_ios_safari_17() {
        // v1 iOS Safari 17 + iPhone cohort. Phase 12 wrapper-checker
        // tracks WebKit version bumps and updates this through the
        // Adaptation protocol.
        assert_eq!(WEBKIT_STUB_PROFILE.vendor, "Apple Computer, Inc.");
        assert_eq!(WEBKIT_STUB_PROFILE.platform, "iPhone");
        assert!(WEBKIT_STUB_PROFILE.user_agent.contains("iPhone"));
        assert!(WEBKIT_STUB_PROFILE.user_agent.contains("AppleWebKit"));
        assert!(WEBKIT_STUB_PROFILE.user_agent.contains("Safari"));
        assert!(
            WEBKIT_STUB_PROFILE.user_agent.contains("Version/17.0"),
            "v1 stub pinned to Safari 17"
        );
    }

    #[test]
    fn webkit_stub_does_not_advertise_devbrowse_in_ua() {
        // Phase-file edge case: "must not falsely advertise
        // WebKit-only API presence; pure UA-string compat only."
        // The stub UA is plain iOS Safari — no DevBrowse branding,
        // no Firefox / Gecko tokens that would create a confused
        // cohort. Sites probing for "Safari" / "AppleWebKit" pass
        // naturally; sites probing for "Firefox" / "Gecko" / our
        // branding do NOT match.
        let ua = WEBKIT_STUB_PROFILE.user_agent;
        assert!(!ua.contains("DevBrowse"), "DevBrowse branding in UA");
        assert!(!ua.contains("Firefox"), "Firefox token in iOS UA");
        // Note: WebKit UAs DO contain "Gecko" inside "(KHTML, like
        // Gecko)" — that's the historical compatibility token every
        // Safari ships, not a Gecko-engine claim. Don't assert
        // !contains("Gecko") — the parenthetical is required for
        // cohort overlap.
    }

    #[test]
    fn every_phase_5_surface_is_unsupported_in_v1() {
        // The v1 reachability assertion. Phase 12 will refine
        // specific rows; this test will need to be updated when
        // (e.g.) Timers gets promoted to BestEffort. Until then,
        // every surface returns Unsupported and the iOS UX surfaces
        // this as the known platform limitation.
        for surface in WebKitNormalizationSurface::ALL {
            assert_eq!(
                surface.capability_v1(),
                WebKitNormalizationCapability::Unsupported,
                "{:?} reachability changed without an Adaptation-protocol entry",
                surface,
            );
        }
    }

    #[test]
    fn webkit_normalization_surface_all_covers_gecko_phase_5_modules() {
        // The 8 Gecko-side Phase-5 modules that have a WebKit-side
        // accounting row: Canvas (27), WebGl (28), Audio (29),
        // Fonts (30), Battery (31), Timers (32), Timezone (33),
        // Navigator (34). The Strict-only Phase 5.5 surfaces are
        // not enumerated because they are Gecko-WebIDL-specific
        // (letterboxing / 100ms timer quantum / disabled-API set)
        // and the iOS UX path is to direct Strict-on-iOS users to
        // a different product entirely.
        assert_eq!(WebKitNormalizationSurface::ALL.len(), 8);
        for v in [
            WebKitNormalizationSurface::Canvas,
            WebKitNormalizationSurface::WebGl,
            WebKitNormalizationSurface::Audio,
            WebKitNormalizationSurface::Fonts,
            WebKitNormalizationSurface::Battery,
            WebKitNormalizationSurface::Timers,
            WebKitNormalizationSurface::Timezone,
            WebKitNormalizationSurface::Navigator,
        ] {
            assert!(
                WebKitNormalizationSurface::ALL.contains(&v),
                "missing surface: {:?}",
                v
            );
        }
    }

    #[test]
    fn stub_carries_mode_but_behavior_is_mode_invariant() {
        // The Mode parameter is accepted for cross-platform API
        // symmetry but does not influence behavior — both Standard
        // and Strict iOS users inherit the WebKit-native identity.
        let s = WebKitStub::new(Mode::Standard);
        let r = WebKitStub::new(Mode::Strict);

        assert_eq!(s.mode(), Mode::Standard);
        assert_eq!(r.mode(), Mode::Strict);

        // Profile pointer is the same across modes (singleton).
        assert!(std::ptr::eq(s.profile(), &WEBKIT_STUB_PROFILE));
        assert!(std::ptr::eq(r.profile(), &WEBKIT_STUB_PROFILE));
        assert!(std::ptr::eq(s.profile(), r.profile()));

        // Capability map identical for both modes.
        for surface in WebKitNormalizationSurface::ALL {
            assert_eq!(s.capability(*surface), r.capability(*surface));
        }
    }

    #[test]
    fn stub_capability_matches_surface_capability_v1() {
        // The instance method is a thin pass-through to the surface
        // method. Pin the equivalence so a future change that
        // diverges the two (e.g. a per-instance override for testing)
        // forces an explicit update.
        let stub = WebKitStub::new(Mode::Standard);
        for surface in WebKitNormalizationSurface::ALL {
            assert_eq!(stub.capability(*surface), surface.capability_v1());
        }
    }

    #[test]
    fn webkit_stub_types_are_send_sync() {
        // Cross-platform principle: the iOS backend will be held in
        // Arc<...> by the Phase 12 dispatcher; the stub types must
        // be Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WebKitStub>();
        assert_send_sync::<WebKitStubProfile>();
        assert_send_sync::<WebKitNormalizationCapability>();
        assert_send_sync::<WebKitNormalizationSurface>();
    }

    #[test]
    fn capability_dispatch_is_exhaustive_friendly() {
        // Mirror of the Gecko-side exhaustive-match contract. A
        // future surface added to WebKitNormalizationSurface (say,
        // a Phase 5.5 row that does become reachable on WebKit)
        // breaks compilation here until it gets a capability row.
        fn route(c: WebKitNormalizationCapability) -> &'static str {
            match c {
                WebKitNormalizationCapability::Unsupported => "unsupported",
                WebKitNormalizationCapability::BestEffort => "best-effort",
            }
        }
        assert_eq!(
            route(WebKitNormalizationCapability::Unsupported),
            "unsupported"
        );
        assert_eq!(
            route(WebKitNormalizationCapability::BestEffort),
            "best-effort"
        );
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: WebKitNormalizationSurface) -> &'static str {
            match s {
                WebKitNormalizationSurface::Canvas => "canvas",
                WebKitNormalizationSurface::WebGl => "webgl",
                WebKitNormalizationSurface::Audio => "audio",
                WebKitNormalizationSurface::Fonts => "fonts",
                WebKitNormalizationSurface::Battery => "battery",
                WebKitNormalizationSurface::Timers => "timers",
                WebKitNormalizationSurface::Timezone => "timezone",
                WebKitNormalizationSurface::Navigator => "navigator",
            }
        }
        for s in WebKitNormalizationSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }
}
