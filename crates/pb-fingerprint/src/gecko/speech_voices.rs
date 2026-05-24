//! Module 35.7 (part 1) — Speech Synthesis voices cohort lock.
//!
//! Locks `speechSynthesis.getVoices()` to a curated 4-voice
//! cohort in Strict so the per-OS voice list (typically ~50
//! voices, ~10^5 combinations) does not leak host identity.
//! Standard locale-buckets the visible voice set so users
//! still see voices matching their locale without exposing
//! the host's specific installed-voice set.
//!
//! **DevBrowse goes structurally ahead of Tor / Mullvad.** Both
//! Tor and Mullvad return the EMPTY voice list, which breaks
//! screen readers and accessibility tools that depend on
//! [`SpeechSynthesisVoice`] discovery. DevBrowse Strict returns
//! a 4-voice cohort covering the major script directions
//! (Latin via en-US + en-GB, CJK via ja-JP, Arabic via ar-SA)
//! so screen-reader UX is preserved while the cohort still
//! locks at ~1-bit entropy across all Strict users.
//!
//! Real platform voices play behind the scenes; only the
//! `getVoices()` metadata list is locked. `speechSynthesis.speak()`
//! continues to drive the actual platform TTS engine.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override; the
//!     `nsSpeechTask` enumerator is replaced for Strict-mode
//!     renderers and bucketed for Standard.
//!   * **§3.3 / §3.2** — per-Mode normalization. Strict cohort
//!     lock; Standard locale bucket.
//!   * **§5.5** — central fingerprint bucketing.
//!   * **threat-model A1** — installed-voice enumeration is one
//!     of the highest-entropy passive fingerprint surfaces
//!     (Olejnik 2019, FPMon studies); the locked cohort closes it
//!     without breaking accessibility.
//!
//! ## Mode-applicability (locked v1.23)
//!
//!   * **Strict** — `SpeechVoicesPolicy::CohortLocked(&LOCKED_VOICE_SET)`.
//!     Every Strict DevBrowse user sees the same 4 voices in
//!     the same order regardless of host OS.
//!   * **Standard** — `SpeechVoicesPolicy::LocaleBucketed`. The
//!     libxul bridge returns a synthetic voice list keyed on the
//!     user's locale: Spanish-locale users see a Spanish-cohort
//!     entry, etc. The host's specific installed-voice list is
//!     NOT exposed. Per-locale buckets are populated by the
//!     bridge from a curated table; this module only ships the
//!     policy contract — the bucket table itself lands with the
//!     libxul build (wired into Gecko by pb-browser at Phase 11 /
//!     Module 80).
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire
//   `nsSpeechTask::GetVoices` to return `LOCKED_VOICE_SET` under
//   Strict and the per-locale bucket under Standard.
//   `onvoiceschanged` MUST fire once at renderer startup so
//   sites that wait for the event before reading
//   `getVoices()` work; subsequent host voice changes do NOT
//   fire the event (the cohort never changes).
// Module 35.4 (settings-lock audit) has shipped: no user setting
//   can loosen Strict's `CohortLocked` to expose the host voice
//   list (asserted by the L44 conformance tests in
//   `strict/settings_lock.rs`). Structural lock — no
//   `for_mode_with_user_override` constructor exists.
// TODO(Phase 8 / Module 64 first-launch wizard): the wizard
//   wires the user's locale into the Standard bucket selection
//   at session start. The locale is itself a fingerprint
//   surface (Module 33 Timezone / Module 34 Navigator already
//   lock it). Module 35.7's Standard bucket is therefore
//   bounded by the already-locked locale cohort.
// TODO(Phase 10 / Module 71+): adversarial probes assert (a)
//   Strict returns exactly LOCKED_VOICE_SET in every renderer;
//   (b) Standard returns the bucket matching `navigator.language`;
//   (c) `speechSynthesis.speak()` still produces audio output
//   when invoked with one of the cohort voiceURIs.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Voice profile ────────────────────────────────────────────────────────

/// One cohort voice as returned by `getVoices()`. Maps 1:1 to the
/// JS `SpeechSynthesisVoice` IDL.
///
/// `Copy` is intentional — read on every enumeration; never a
/// handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VoiceProfile {
    /// `SpeechSynthesisVoice.voiceURI` — stable identifier the
    /// site uses with `SpeechSynthesisUtterance.voice`. The
    /// libxul bridge maps this back to the actual platform voice
    /// at `speak()` time.
    pub voice_uri: &'static str,
    /// `SpeechSynthesisVoice.name` — human-readable label. Pinned
    /// to a cohort-uniform string per voice; not derived from
    /// the host's actual voice name.
    pub name: &'static str,
    /// `SpeechSynthesisVoice.lang` — BCP 47 language tag.
    pub lang: &'static str,
    /// `SpeechSynthesisVoice.default` — whether the engine treats
    /// this as the default voice when no `voice` is specified.
    /// Exactly one entry in `LOCKED_VOICE_SET` is the default
    /// (asserted by test).
    pub default: bool,
    /// `SpeechSynthesisVoice.localService` — `true` means the
    /// voice runs on-device (no network round-trip). Pinned to
    /// `true` for every cohort voice; an offline-voice claim is
    /// the privacy-safe answer (a `localService = false` voice
    /// would suggest the user has network-tied voices installed,
    /// itself a fingerprint).
    pub local_service: bool,
}

// ── Locked voice set (Strict cohort) ─────────────────────────────────────

/// The 4-voice cohort returned to every Strict-mode renderer.
///
/// Coverage choice (Latin / CJK / Arabic script directions) is
/// the minimum cohort that preserves screen-reader accessibility
/// across the major writing systems without splitting the cohort
/// per-OS. Tor / Mullvad return the empty list — DevBrowse goes
/// structurally ahead.
///
/// Ordering is locked (en-US first; default voice first).
pub static LOCKED_VOICE_SET: &[VoiceProfile] = &[
    VoiceProfile {
        voice_uri: "devbrowse-cohort-en-US-v1",
        name: "DevBrowse Standard Voice (en-US)",
        lang: "en-US",
        default: true,
        local_service: true,
    },
    VoiceProfile {
        voice_uri: "devbrowse-cohort-en-GB-v1",
        name: "DevBrowse Standard Voice (en-GB)",
        lang: "en-GB",
        default: false,
        local_service: true,
    },
    VoiceProfile {
        voice_uri: "devbrowse-cohort-ja-JP-v1",
        name: "DevBrowse Standard Voice (ja-JP)",
        lang: "ja-JP",
        default: false,
        local_service: true,
    },
    VoiceProfile {
        voice_uri: "devbrowse-cohort-ar-SA-v1",
        name: "DevBrowse Standard Voice (ar-SA)",
        lang: "ar-SA",
        default: false,
        local_service: true,
    },
];

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode voice enumeration policy.
///
/// Two variants with semantically distinct libxul-side behavior
/// (not a redundant divergence — `CohortLocked` returns a fixed
/// slice; `LocaleBucketed` triggers a per-renderer locale
/// lookup). Both modes preserve `speak()` functionality.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpeechVoicesPolicy {
    /// Strict: every renderer returns this exact voice slice.
    CohortLocked(&'static [VoiceProfile]),
    /// Standard: libxul bridge returns the locale-bucketed
    /// voice list at request time. The bucket table lives
    /// libxul-side; this variant is the contract.
    LocaleBucketed,
}

impl SpeechVoicesPolicy {
    /// Locked snapshot for `mode`:
    ///   * `Mode::Standard` -> `LocaleBucketed`
    ///   * `Mode::Strict`   -> `CohortLocked(LOCKED_VOICE_SET)`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::LocaleBucketed,
            Mode::Strict => Self::CohortLocked(LOCKED_VOICE_SET),
        }
    }
}

// ── Surface enumeration ──────────────────────────────────────────────────

/// Every JS pathway the libxul speech bridge must wire.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpeechVoicesSurface {
    /// `speechSynthesis.getVoices()` — the voice enumeration entry
    /// point. Returns a `FrozenArray<SpeechSynthesisVoice>`.
    GetVoices,
    /// `speechSynthesis.onvoiceschanged` event handler. The
    /// bridge fires this once at startup so sites that wait for
    /// the event still resolve; subsequent host voice changes
    /// are suppressed (the cohort never mutates after startup).
    OnVoicesChanged,
}

impl SpeechVoicesSurface {
    pub const ALL: &'static [SpeechVoicesSurface] = &[Self::GetVoices, Self::OnVoicesChanged];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::SpeechSynthesis`.
#[derive(Debug, Clone, Copy)]
pub struct SpeechVoicesOverride {
    policy: SpeechVoicesPolicy,
}

impl SpeechVoicesOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: SpeechVoicesPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> SpeechVoicesPolicy {
        self.policy
    }
}

impl FingerprintOverride for SpeechVoicesOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::SpeechSynthesis
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul speech bridge is not
        // yet wired (see crate-level TODO).
        let _ = (self.policy, JsContext::ALL, SpeechVoicesSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_voice_set_covers_four_cohort_languages() {
        // Phase-file Strict cohort: en-US, en-GB, ja-JP, ar-SA.
        // Latin + CJK + Arabic script directions.
        assert_eq!(LOCKED_VOICE_SET.len(), 4);
        let langs: Vec<&str> = LOCKED_VOICE_SET.iter().map(|v| v.lang).collect();
        assert_eq!(langs, vec!["en-US", "en-GB", "ja-JP", "ar-SA"]);
    }

    #[test]
    fn locked_voice_set_has_exactly_one_default() {
        // SpeechSynthesisVoice spec invariant: exactly one voice
        // is `default`. The libxul bridge would otherwise emit
        // ambiguous or empty `voice` resolution for utterances
        // with no explicit voice.
        let defaults: Vec<&VoiceProfile> = LOCKED_VOICE_SET.iter().filter(|v| v.default).collect();
        assert_eq!(defaults.len(), 1, "expected exactly one default voice");
        assert_eq!(defaults[0].lang, "en-US");
    }

    #[test]
    fn every_locked_voice_is_local_service_for_cohort_safety() {
        // local_service = false would suggest the user has
        // network-tied voices installed — itself a fingerprint.
        // Cohort posture is "every voice is on-device".
        for v in LOCKED_VOICE_SET {
            assert!(v.local_service, "{:?} is not local_service", v.lang);
        }
    }

    #[test]
    fn every_locked_voice_has_non_empty_fields() {
        for v in LOCKED_VOICE_SET {
            assert!(!v.voice_uri.is_empty(), "{:?} has empty voice_uri", v.lang);
            assert!(!v.name.is_empty(), "{:?} has empty name", v.lang);
            assert!(!v.lang.is_empty(), "voice has empty lang");
        }
    }

    #[test]
    fn voice_uris_are_unique() {
        // The libxul bridge resolves `voice_uri` back to a
        // platform voice; a duplicate would create an ambiguous
        // mapping.
        let mut seen = std::collections::HashSet::new();
        for v in LOCKED_VOICE_SET {
            assert!(
                seen.insert(v.voice_uri),
                "duplicate voice_uri: {}",
                v.voice_uri
            );
        }
    }

    #[test]
    fn voice_uris_carry_v1_versioning_tag() {
        // Bumping the cohort voice set is a cohort shift under
        // the Adaptation protocol; the v1 tag in the URI string
        // means a v2 set produces disjoint URIs by construction.
        for v in LOCKED_VOICE_SET {
            assert!(
                v.voice_uri.ends_with("-v1"),
                "voice_uri {:?} must end with -v1",
                v.voice_uri,
            );
        }
    }

    #[test]
    fn strict_resolves_to_cohort_locked_voice_set() {
        let p = SpeechVoicesPolicy::for_mode(Mode::Strict);
        match p {
            SpeechVoicesPolicy::CohortLocked(voices) => {
                assert_eq!(voices.len(), 4);
                // Content equality with LOCKED_VOICE_SET (the
                // const slice is inlined per use; address
                // identity does not hold for `static`-vs-`const`
                // pointers across compilation units, but value
                // equality is the load-bearing claim).
                assert_eq!(voices, LOCKED_VOICE_SET);
            }
            other => panic!("expected CohortLocked, got {:?}", other),
        }
    }

    #[test]
    fn standard_resolves_to_locale_bucketed() {
        let p = SpeechVoicesPolicy::for_mode(Mode::Standard);
        assert!(matches!(p, SpeechVoicesPolicy::LocaleBucketed));
    }

    #[test]
    fn strict_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock — no with_user_override constructor.
        let a = SpeechVoicesPolicy::for_mode(Mode::Strict);
        let b = SpeechVoicesPolicy::for_mode(Mode::Strict);
        assert_eq!(a, b);
    }

    #[test]
    fn speech_voices_surface_all_covers_two_pathways() {
        assert_eq!(SpeechVoicesSurface::ALL.len(), 2);
        for v in [
            SpeechVoicesSurface::GetVoices,
            SpeechVoicesSurface::OnVoicesChanged,
        ] {
            assert!(SpeechVoicesSurface::ALL.contains(&v), "missing: {:?}", v);
        }
    }

    #[test]
    fn override_reports_speech_synthesis_surface_in_both_modes() {
        assert_eq!(
            SpeechVoicesOverride::new(Mode::Standard).surface(),
            WebIdlSurface::SpeechSynthesis,
        );
        assert_eq!(
            SpeechVoicesOverride::new(Mode::Strict).surface(),
            WebIdlSurface::SpeechSynthesis,
        );
    }

    #[test]
    fn override_install_is_context_inert() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035071").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = SpeechVoicesOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::SpeechSynthesis);
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: SpeechVoicesPolicy) -> &'static str {
            match p {
                SpeechVoicesPolicy::CohortLocked(_) => "cohort-locked",
                SpeechVoicesPolicy::LocaleBucketed => "locale-bucketed",
            }
        }
        assert_eq!(
            arm(SpeechVoicesPolicy::for_mode(Mode::Strict)),
            "cohort-locked",
        );
        assert_eq!(
            arm(SpeechVoicesPolicy::for_mode(Mode::Standard)),
            "locale-bucketed",
        );
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: SpeechVoicesSurface) -> &'static str {
            match s {
                SpeechVoicesSurface::GetVoices => "get-voices",
                SpeechVoicesSurface::OnVoicesChanged => "on-voices-changed",
            }
        }
        for s in SpeechVoicesSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn speech_voices_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SpeechVoicesOverride>();
        assert_send_sync::<SpeechVoicesPolicy>();
        assert_send_sync::<VoiceProfile>();
        assert_send_sync::<SpeechVoicesSurface>();
    }
}
