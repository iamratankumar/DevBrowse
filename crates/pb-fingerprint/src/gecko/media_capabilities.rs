//! Module 35.7 (part 2) — `MediaCapabilities` cohort lock.
//!
//! Locks `navigator.mediaCapabilities.decodingInfo()` /
//! `encodingInfo()` to a mode-invariant codec baseline. Both
//! Standard and Strict report identical
//! `{supported, smooth, powerEfficient}` answers regardless of
//! host hardware. Tor / Mullvad disable HEVC / AV1; DevBrowse
//! goes structurally similar — HEVC and AV1 report unsupported
//! to keep the cohort uniform even though the underlying engine
//! may technically support them on some hosts. Actual playback
//! uses real codecs (EME / DRM unaffected).
//!
//! ## Locked decision (phase-file)
//!
//! `MediaCapabilities` is the **second** Phase-5 / Phase-5.5
//! mode-invariant surface (joining Module 31 Battery).
//! `MediaCapabilitiesPolicy::Locked(...)` is the single variant
//! returned by both `for_mode(Standard)` and `for_mode(Strict)`.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override; the
//!     `MediaCapabilities.decodingInfo` / `encodingInfo` methods
//!     are intercepted below the JS surface so workers share a
//!     single policy.
//!   * **§5.5** — central fingerprint bucketing.
//!   * **threat-model A1** — codec support varies by hardware
//!     (HEVC requires Apple Silicon / NVIDIA NVENC / Intel
//!     Quick Sync; AV1 varies by GPU generation). The mode-
//!     invariant lock collapses this surface to one cohort.
//!
//! Cohort choice rationale:
//!   * **H.264 baseline (`avc1.42E01E`)** — universal across
//!     every modern browser; reporting `supported` is safe.
//!   * **VP9 (`vp09.00.10.08`)** — YouTube baseline; widely
//!     supported.
//!   * **AAC (`mp4a.40.2`)** — universal audio baseline.
//!   * **Opus (`opus`)** — WebRTC audio codec; widely supported.
//!   * **MP3 (`mp4a.40.34` / `audio/mpeg`)** — universal audio.
//!   * **HEVC (`hvc1.1.6.L93.B0`)** — patent-licensed; reporting
//!     `unsupported` matches Tor / Mullvad and avoids the
//!     hardware-tier leak.
//!   * **AV1 (`av01.0.05M.08`)** — royalty-free but hardware
//!     support varies; reporting `unsupported` for cohort
//!     uniformity. Sites that need AV1 fall back to VP9.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire
//   `MediaCapabilities.decodingInfo({contentType: ...})` to
//   match the request's `contentType` against
//   `LOCKED_MEDIA_CAPABILITIES` and return the matching answer.
//   Unknown content types return the safe default
//   `{supported: false, smooth: false, powerEfficient: false}`
//   (avoids leaking codec-support entropy on novel codecs).
//   `encodingInfo` reuses the same answer table.
// Module 35.4 (settings-lock audit) has shipped: the codec list is
//   non-loosenable by user settings (asserted by the L44 conformance
//   tests in `strict/settings_lock.rs`). A future "enable HEVC"
//   toggle would be a cohort split and must go through the
//   Adaptation protocol.
// TODO(Phase 8 / streaming UX): document the HEVC = unsupported
//   tradeoff so users who need 4K HDR HEVC streams know to use
//   the platform-native player.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Codec support entry ──────────────────────────────────────────────────

/// One row in the locked codec answer table. Maps an RFC 6381
/// `contentType` string to the JS-observable
/// `{supported, smooth, powerEfficient}` triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodecSupport {
    /// Canonical `contentType` the libxul bridge matches the
    /// `MediaCapabilities.decodingInfo({contentType: ...})` call
    /// against. Format: `<container>; codecs="<rfc-6381-id>"` or
    /// the bare MIME type for legacy codecs.
    pub content_type: &'static str,
    /// `MediaDecodingInfo.supported` — whether the engine
    /// claims to decode this codec. Cohort-locked regardless of
    /// host hardware.
    pub supported: bool,
    /// `MediaDecodingInfo.smooth` — whether playback is smooth
    /// (typically 24+ fps for video / no dropouts for audio).
    /// Locked to the supported value for cohort uniformity.
    pub smooth: bool,
    /// `MediaDecodingInfo.powerEfficient` — whether playback
    /// uses hardware acceleration. Locked to the supported
    /// value (a hardware-accel claim is the privacy-safe
    /// answer; the actual implementation may be software).
    pub power_efficient: bool,
}

// ── Locked answer table (mode-invariant) ─────────────────────────────────

/// The mode-invariant codec answer table.
///
/// 5 supported codecs (H.264 / VP9 / AAC / Opus / MP3) + 2
/// unsupported (HEVC / AV1). Both Standard and Strict return
/// these values regardless of host hardware. Bumping the table
/// is a cohort shift under the Adaptation protocol.
pub static LOCKED_MEDIA_CAPABILITIES: &[CodecSupport] = &[
    // ── Supported codecs ─────────────────────────────────────────────
    // H.264 baseline profile, level 3.0 — universal baseline.
    CodecSupport {
        content_type: "video/mp4; codecs=\"avc1.42E01E\"",
        supported: true,
        smooth: true,
        power_efficient: true,
    },
    // VP9 profile 0 — YouTube baseline.
    CodecSupport {
        content_type: "video/webm; codecs=\"vp09.00.10.08\"",
        supported: true,
        smooth: true,
        power_efficient: true,
    },
    // AAC-LC — universal audio baseline.
    CodecSupport {
        content_type: "audio/mp4; codecs=\"mp4a.40.2\"",
        supported: true,
        smooth: true,
        power_efficient: true,
    },
    // Opus — WebRTC audio codec.
    CodecSupport {
        content_type: "audio/ogg; codecs=\"opus\"",
        supported: true,
        smooth: true,
        power_efficient: true,
    },
    // MP3 — universal audio.
    CodecSupport {
        content_type: "audio/mpeg",
        supported: true,
        smooth: true,
        power_efficient: true,
    },
    // ── Unsupported codecs ───────────────────────────────────────────
    // HEVC Main profile, level 3.1 — patent-licensed; cohort
    // posture reports unsupported regardless of actual host
    // capability (matches Tor / Mullvad).
    CodecSupport {
        content_type: "video/mp4; codecs=\"hvc1.1.6.L93.B0\"",
        supported: false,
        smooth: false,
        power_efficient: false,
    },
    // AV1 profile 0 — royalty-free but hardware support varies;
    // cohort uniformity wins over enabling-on-some-hosts.
    CodecSupport {
        content_type: "video/mp4; codecs=\"av01.0.05M.08\"",
        supported: false,
        smooth: false,
        power_efficient: false,
    },
];

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode media-capabilities policy. **Mode-invariant** — both
/// modes resolve to the same single-variant value (joining
/// Module 31 Battery as the second Phase-5 mode-invariant
/// surface).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaCapabilitiesPolicy {
    /// Both modes: return answers from the locked codec table.
    Locked(&'static [CodecSupport]),
}

impl MediaCapabilitiesPolicy {
    /// Locked snapshot for `mode`. Mode-invariant: both Standard
    /// and Strict return `Locked(LOCKED_MEDIA_CAPABILITIES)`.
    pub fn for_mode(_mode: Mode) -> Self {
        Self::Locked(LOCKED_MEDIA_CAPABILITIES)
    }

    /// The codec answer table this policy reads from.
    pub fn table(&self) -> &'static [CodecSupport] {
        match self {
            Self::Locked(t) => t,
        }
    }
}

// ── Surface enumeration ──────────────────────────────────────────────────

/// Every JS pathway the libxul media-capabilities bridge must
/// wire.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaCapabilitiesSurface {
    /// `navigator.mediaCapabilities.decodingInfo(config)`.
    DecodingInfo,
    /// `navigator.mediaCapabilities.encodingInfo(config)`.
    EncodingInfo,
}

impl MediaCapabilitiesSurface {
    pub const ALL: &'static [MediaCapabilitiesSurface] = &[Self::DecodingInfo, Self::EncodingInfo];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for
/// `WebIdlSurface::MediaCapabilities`.
#[derive(Debug, Clone, Copy)]
pub struct MediaCapabilitiesOverride {
    policy: MediaCapabilitiesPolicy,
}

impl MediaCapabilitiesOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: MediaCapabilitiesPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> MediaCapabilitiesPolicy {
        self.policy
    }
}

impl FingerprintOverride for MediaCapabilitiesOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::MediaCapabilities
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul media-capabilities
        // bridge is not yet wired.
        let _ = (self.policy, JsContext::ALL, MediaCapabilitiesSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_table_carries_five_supported_and_two_unsupported_codecs() {
        // 5 supported (H.264 / VP9 / AAC / Opus / MP3) + 2
        // unsupported (HEVC / AV1).
        assert_eq!(LOCKED_MEDIA_CAPABILITIES.len(), 7);
        let supported = LOCKED_MEDIA_CAPABILITIES
            .iter()
            .filter(|c| c.supported)
            .count();
        let unsupported = LOCKED_MEDIA_CAPABILITIES
            .iter()
            .filter(|c| !c.supported)
            .count();
        assert_eq!(supported, 5);
        assert_eq!(unsupported, 2);
    }

    #[test]
    fn supported_codecs_cover_h264_vp9_aac_opus_mp3() {
        // Pinned by RFC 6381 codec strings; bumping any of these
        // is a cohort shift through the Adaptation protocol.
        let supported: Vec<&str> = LOCKED_MEDIA_CAPABILITIES
            .iter()
            .filter(|c| c.supported)
            .map(|c| c.content_type)
            .collect();
        assert!(
            supported.iter().any(|s| s.contains("avc1.42E01E")),
            "H.264 baseline missing: {:?}",
            supported,
        );
        assert!(
            supported.iter().any(|s| s.contains("vp09")),
            "VP9 missing: {:?}",
            supported,
        );
        assert!(
            supported.iter().any(|s| s.contains("mp4a.40.2")),
            "AAC missing: {:?}",
            supported,
        );
        assert!(
            supported.iter().any(|s| s.contains("opus")),
            "Opus missing: {:?}",
            supported,
        );
        assert!(
            supported.iter().any(|s| s.contains("audio/mpeg")),
            "MP3 missing: {:?}",
            supported,
        );
    }

    #[test]
    fn unsupported_codecs_cover_hevc_and_av1() {
        let unsupported: Vec<&str> = LOCKED_MEDIA_CAPABILITIES
            .iter()
            .filter(|c| !c.supported)
            .map(|c| c.content_type)
            .collect();
        assert!(
            unsupported.iter().any(|s| s.contains("hvc1")),
            "HEVC missing from unsupported set: {:?}",
            unsupported,
        );
        assert!(
            unsupported.iter().any(|s| s.contains("av01")),
            "AV1 missing from unsupported set: {:?}",
            unsupported,
        );
    }

    #[test]
    fn supported_codecs_claim_smooth_and_power_efficient() {
        // Cohort uniformity: every supported codec reports
        // smooth + power_efficient = true. Varying these
        // per-host would re-leak the hardware tier.
        for c in LOCKED_MEDIA_CAPABILITIES.iter().filter(|c| c.supported) {
            assert!(
                c.smooth,
                "supported codec {:?} is not smooth",
                c.content_type
            );
            assert!(
                c.power_efficient,
                "supported codec {:?} is not power_efficient",
                c.content_type,
            );
        }
    }

    #[test]
    fn unsupported_codecs_are_consistently_unsupported() {
        // unsupported = true implies smooth = false +
        // power_efficient = false (anything else is contradictory
        // per the MediaCapabilities spec).
        for c in LOCKED_MEDIA_CAPABILITIES.iter().filter(|c| !c.supported) {
            assert!(!c.smooth);
            assert!(!c.power_efficient);
        }
    }

    #[test]
    fn content_types_are_non_empty_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in LOCKED_MEDIA_CAPABILITIES {
            assert!(!c.content_type.is_empty(), "empty content_type");
            assert!(
                seen.insert(c.content_type),
                "duplicate content_type: {}",
                c.content_type,
            );
        }
    }

    #[test]
    fn media_capabilities_policy_is_mode_invariant() {
        // Mode-invariant: both modes return the same single
        // variant pointing at the same locked table (joins
        // Module 31 Battery as the second Phase-5 mode-
        // invariant surface).
        let s = MediaCapabilitiesPolicy::for_mode(Mode::Standard);
        let r = MediaCapabilitiesPolicy::for_mode(Mode::Strict);
        assert_eq!(s, r);
        assert_eq!(s.table(), r.table());
    }

    #[test]
    fn media_capabilities_surface_all_covers_decoding_and_encoding() {
        assert_eq!(MediaCapabilitiesSurface::ALL.len(), 2);
        for v in [
            MediaCapabilitiesSurface::DecodingInfo,
            MediaCapabilitiesSurface::EncodingInfo,
        ] {
            assert!(
                MediaCapabilitiesSurface::ALL.contains(&v),
                "missing: {:?}",
                v
            );
        }
    }

    #[test]
    fn override_reports_media_capabilities_surface_in_both_modes() {
        assert_eq!(
            MediaCapabilitiesOverride::new(Mode::Standard).surface(),
            WebIdlSurface::MediaCapabilities,
        );
        assert_eq!(
            MediaCapabilitiesOverride::new(Mode::Strict).surface(),
            WebIdlSurface::MediaCapabilities,
        );
    }

    #[test]
    fn override_install_is_context_inert() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035072").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = MediaCapabilitiesOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::MediaCapabilities);
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: MediaCapabilitiesPolicy) -> &'static str {
            match p {
                MediaCapabilitiesPolicy::Locked(_) => "locked",
            }
        }
        assert_eq!(
            arm(MediaCapabilitiesPolicy::for_mode(Mode::Strict)),
            "locked"
        );
        assert_eq!(
            arm(MediaCapabilitiesPolicy::for_mode(Mode::Standard)),
            "locked",
        );
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: MediaCapabilitiesSurface) -> &'static str {
            match s {
                MediaCapabilitiesSurface::DecodingInfo => "decoding-info",
                MediaCapabilitiesSurface::EncodingInfo => "encoding-info",
            }
        }
        for s in MediaCapabilitiesSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn media_capabilities_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MediaCapabilitiesOverride>();
        assert_send_sync::<MediaCapabilitiesPolicy>();
        assert_send_sync::<CodecSupport>();
        assert_send_sync::<MediaCapabilitiesSurface>();
    }
}
