//! Module 29 — Audio context / Web Audio normalization.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the audio readback
//!     pathway is intercepted below the JS surface so worker-scope
//!     `OfflineAudioContext` and the top-frame `AudioContext` share a
//!     single policy.
//!   * **§3.3 / L9** — "max fingerprint normalization" is a
//!     **Strict-only** feature. Standard preserves the native Gecko
//!     audio path (cohort-by-choice: a user picking Standard accepts
//!     a different cohort than Strict; same shape as Module 25
//!     WebRTC Disabled-vs-PerSitePermission, Module 27 canvas
//!     Native-vs-LOCKED_CANVAS_PROFILE, Module 28 WebGL
//!     Native-vs-LOCKED_WEBGL_PROFILE, Module 30 fonts
//!     Tor-allowlist-vs-bucketed, Module 32 timers 100ms-vs-1ms,
//!     Module 33 timezone UTC-vs-host).
//!   * **§5.5** — central fingerprint bucketing: every Strict-mode
//!     audio readback routes through one `AudioProfile`.
//!   * **threat-model A1** — `OfflineAudioContext` rendering through a
//!     `DynamicsCompressorNode` is the textbook audio fingerprint
//!     vector (per-CPU SIMD path, per-OS denormal-handling,
//!     per-architecture FP-rounding deltas; the Strict cohort splits
//!     without normalization).
//!
//! ## Locked decision (phase-5 Goal)
//!
//! **Strict pre-quantization through a cohort-locked DSP path. No
//! per-user noise.** Within the Strict cohort, identical Web Audio
//! graphs produce byte-identical post-render `Float32Array` output
//! across every DevBrowse user. Standard does not normalize — its
//! audio flows through the native Gecko DSP path unmodified.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * The locked DSP parameter set (`AudioProfile`) that the
//!     libxul-side audio hook consults at readback time **when the
//!     per-renderer policy is `NormalizedProfile` (Strict)**.
//!   * The enumeration of every readback pathway (`AudioSurface`)
//!     the Gecko bridge must wire — the phase-file edge-case list
//!     (`AnalyserNode.getByteFrequencyData` precision +
//!     `OfflineAudioContext` deterministic rendering) lifted into a
//!     typed list so a future libxul-tag bump cannot silently miss
//!     a pathway.
//!   * A `FingerprintOverride` impl for `WebIdlSurface::Audio` so
//!     the libxul bridge has a single registration point regardless
//!     of mode. `install()` for a Standard-mode override is a
//!     deliberate no-op (the native DSP path stays in place).
//!
//! It IS NOT:
//!   * The DSP path itself. The actual deterministic compressor +
//!     scalar reference renderer lives in libxul; this module pins
//!     the parameters the Strict replacement must honor.
//!   * The `Web Audio API` permission gate. There is no Strict opt-in
//!     for "real audio" — Strict tabs always see the normalized
//!     output (L41 / Phase 5.5 forbids loosening Strict via
//!     settings).
//!
//! ## Why the determinism switches are typed enums, not booleans
//!
//! `CompressorImpl` and `DspPath` are the actual determinism
//! mechanism, not just metadata. A future cohort shift that, for
//! example, wanted to permit a SIMD path on a specific micro-arch
//! would have to add a variant here and trip the exhaustive-match
//! contract in libxul. Booleans would silently absorb the shift.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): the deterministic compressor
//   + scalar-reference DSP path is a Gecko-side change that lands
//   alongside the libxul tag. `AudioOverride::install` currently
//   has no side
//   effects because the FFI hook is not yet live; once libxul is
//   wired, Strict-mode install() will register a per-renderer
//   callback that returns `&LOCKED_AUDIO_PROFILE` on demand, and
//   Standard-mode install() will remain a no-op.
// TODO(Phase 5.5 / Module 35.2): timer-quantization (L43, 100 ms
//   Strict floor) lives in Module 32, not here. The audio surface
//   does NOT re-implement timer quantization. Cross-coupling note:
//   `Performance.now()` reads during audio rendering are quantized
//   by Module 32; this module pins only the audio buffer values.
// TODO(Phase 10 / Module 71+): the AudioContext fingerprint probe
//   (CreepJS audio_fingerprint, FPStandard) must observe identical
//   post-render sums in Strict across hosts. Wire the Phase 10
//   harness to drive an `OfflineAudioContext` graph through
//   `AudioOverride::new(Mode::Strict)` and assert the sum is
//   bit-identical to a recorded cohort-reference value.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked DSP parameters (Strict cohort) ─────────────────────────────────

/// `DynamicsCompressorNode` implementation choice. The W3C-default
/// parameters (`threshold=-24 dB`, `knee=30 dB`, `ratio=12`,
/// `attack=0.003 s`, `release=0.25 s`) are spec-mandated and therefore
/// cohort-uniform; the *implementation's* floating-point path is
/// what fingerprints the cohort. The locked profile pins
/// `CohortLocked` so every Strict renderer evaluates the compressor
/// transfer function through the same deterministic FP reference
/// implementation regardless of host CPU / SIMD-extensions / denormal
/// handling.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressorImpl {
    /// Gecko's native compressor (may dispatch to SIMD; cohort-splits
    /// by micro-arch). Standard mode.
    Native,
    /// Deterministic scalar reference implementation; bit-identical
    /// output across every host. Strict mode.
    CohortLocked,
}

/// Audio DSP code path. SIMD-accelerated paths (SSE / AVX / NEON)
/// produce per-micro-arch floating-point deltas in mixing, convolution,
/// and `AnalyserNode` FFT magnitudes. The locked profile pins
/// `ScalarReference` so Strict cohort renderers share a single FP
/// path.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DspPath {
    /// Native (may use SIMD; cohort-splits). Standard mode.
    Native,
    /// Deterministic scalar code path; no auto-vectorization. Strict
    /// mode.
    ScalarReference,
}

/// Locked Web Audio parameter bundle for the Strict cohort. The
/// libxul-side audio hook consults this on every Strict-mode
/// readback so all Strict DevBrowse renderers produce identical
/// post-render `Float32Array` / `Uint8Array` output for identical
/// inputs.
///
/// `Copy` is intentional — the profile is a value type read on
/// every readback, never a handle.
///
/// Note: `f32` / `f64` preclude `Eq` / `Hash` derives. The profile
/// is `PartialEq` only; cohort identity is asserted by `std::ptr::eq`
/// against `LOCKED_AUDIO_PROFILE` (single-static-singleton invariant)
/// rather than structural equality.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AudioProfile {
    /// Sample rate exposed to JS via `AudioContext.sampleRate` /
    /// `OfflineAudioContext.sampleRate`. Locked at 44.1 kHz for
    /// maximum cohort overlap with Tor Browser / Mullvad Browser.
    pub sample_rate_hz: u32,
    /// Channel count for the destination node. Locked stereo.
    pub channel_count: u32,
    /// `AudioContext.baseLatency` cohort-locked seconds (real-time
    /// only; `OfflineAudioContext` does not expose it).
    pub base_latency_seconds: f64,
    /// `AudioContext.outputLatency` cohort-locked seconds (real-time
    /// only).
    pub output_latency_seconds: f64,
    /// Post-render quantization grid for `Float32Array` readbacks.
    /// Every returned sample is rounded to a multiple of this step
    /// before crossing the JS boundary. 1e-7 matches the Tor
    /// Browser / Brave audio-fingerprint defenses.
    pub f32_quantization_step: f32,
    /// `DynamicsCompressorNode` implementation choice. See
    /// [`CompressorImpl`].
    pub compressor: CompressorImpl,
    /// Audio DSP code path. See [`DspPath`].
    pub dsp_path: DspPath,
}

/// The single cohort-safe profile for Strict mode. Standard does
/// NOT use this — see [`AudioReadbackPolicy::for_mode`].
///
/// `static` (not `const`): callers compare `&'static` references by
/// address (`std::ptr::eq`) to prove every Strict consumer is
/// reading the same singleton. `const` items can be constant-folded
/// so each `&LOCKED_AUDIO_PROFILE` site receives a fresh address,
/// which silently weakens the Strict-cohort-safety invariant.
pub static LOCKED_AUDIO_PROFILE: AudioProfile = AudioProfile {
    sample_rate_hz: 44_100,
    channel_count: 2,
    base_latency_seconds: 0.005,
    output_latency_seconds: 0.020,
    f32_quantization_step: 1.0e-7,
    compressor: CompressorImpl::CohortLocked,
    dsp_path: DspPath::ScalarReference,
};

// ── Per-mode readback policy ──────────────────────────────────────────────

/// Per-mode audio readback policy.
///
/// **v1.23 amiunique-generic refactor (Phase 5.5 Module 35.5):**
/// both modes resolve to the same `Normalized` variant carrying
/// `LOCKED_AUDIO_PROFILE`. Standard now activates the cohort-locked
/// DSP path (`CompressorImpl::CohortLocked` +
/// `DspPath::ScalarReference`) AND adds per-(origin,
/// IdentityProfile) ±1e-5 noise on `Float32Array` sample readback.
/// Strict keeps the pure cohort lock (`farbling: None`).
///
/// Supersedes the v1.14 `NativePassThrough` / `NormalizedProfile`
/// two-variant shape. Standard no longer pass-throughs; the
/// locked compressor + scalar DSP path now applies to both modes.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AudioReadbackPolicy {
    /// Audio readback flows through the libxul hook producing
    /// deterministic post-render buffers using `profile`. When
    /// `farbling.is_some()`, the per-sample ±eps noise from
    /// `farbling` is applied to `Float32Array` readback paths
    /// (the un-farbled samples drive actual audio playback;
    /// only the JS-readback view carries noise).
    Normalized {
        profile: &'static AudioProfile,
        farbling: Option<&'static crate::farbling::FarblingProfile>,
    },
}

impl AudioReadbackPolicy {
    /// Locked snapshot for `mode` (v1.23):
    ///   * `Mode::Standard` -> `Normalized { profile: &LOCKED_AUDIO_PROFILE, farbling: Some(&STANDARD_FARBLING_PROFILE) }`
    ///   * `Mode::Strict`   -> `Normalized { profile: &LOCKED_AUDIO_PROFILE, farbling: None }`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Normalized {
                profile: &LOCKED_AUDIO_PROFILE,
                farbling: Some(&crate::farbling::STANDARD_FARBLING_PROFILE),
            },
            Mode::Strict => Self::Normalized {
                profile: &LOCKED_AUDIO_PROFILE,
                farbling: None,
            },
        }
    }

    /// The audio profile this policy uses. Always
    /// `&LOCKED_AUDIO_PROFILE` after the v1.23 refactor — both
    /// modes share the cohort base.
    pub fn profile(&self) -> &'static AudioProfile {
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

    /// True iff the libxul audio hook will be activated for this
    /// policy. After the v1.23 refactor this is `true` for both
    /// modes.
    pub fn normalizes(&self) -> bool {
        matches!(self, Self::Normalized { .. })
    }
}

// ── Readback-pathway enumeration ──────────────────────────────────────────

/// Every JS API pathway that can read back Web Audio data.
///
/// The libxul bridge MUST register the normalized DSP hook behind
/// every variant **for Strict-mode renderers** — missing one leaves
/// a Strict readback channel that bypasses the cohort-safe profile
/// (a privacy regression). This enum lifts the phase-file edge-case
/// list (`AnalyserNode.getByteFrequencyData` precision +
/// `OfflineAudioContext` deterministic rendering) into a typed list
/// so a future libxul-tag bump cannot silently miss a new pathway —
/// see the exhaustive-match contract on `WebIdlSurface` (Module 26
/// interface.rs).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AudioSurface {
    /// `OfflineAudioContext.startRendering()` returning an
    /// `AudioBuffer`. The canonical audio-fingerprint probe routes
    /// a `DynamicsCompressorNode` through this pathway and sums the
    /// output.
    OfflineRenderBuffer,
    /// `AudioBuffer.getChannelData(channel)` returning a
    /// `Float32Array`. Strict quantizes each sample to
    /// `f32_quantization_step` before the buffer crosses the JS
    /// boundary.
    AudioBufferGetChannelData,
    /// `AnalyserNode.getByteFrequencyData(Uint8Array)`. Phase-file
    /// edge case: byte-precision FFT magnitudes carry per-host FFT
    /// deltas; the locked DSP path eliminates them.
    AnalyserByteFrequencyData,
    /// `AnalyserNode.getFloatFrequencyData(Float32Array)`.
    AnalyserFloatFrequencyData,
    /// `AnalyserNode.getByteTimeDomainData(Uint8Array)`.
    AnalyserByteTimeDomainData,
    /// `AnalyserNode.getFloatTimeDomainData(Float32Array)`.
    AnalyserFloatTimeDomainData,
    /// `AudioContext.baseLatency` (real-time `AudioContext` only).
    AudioContextBaseLatency,
    /// `AudioContext.outputLatency` (real-time `AudioContext` only).
    AudioContextOutputLatency,
    /// `AudioContext.sampleRate` / `OfflineAudioContext.sampleRate`.
    AudioContextSampleRate,
}

impl AudioSurface {
    /// Every readback pathway the bridge must wire. Asserted
    /// against the phase-file edge-case list by
    /// `tests::audio_surface_all_covers_edge_cases`.
    pub const ALL: &'static [AudioSurface] = &[
        Self::OfflineRenderBuffer,
        Self::AudioBufferGetChannelData,
        Self::AnalyserByteFrequencyData,
        Self::AnalyserFloatFrequencyData,
        Self::AnalyserByteTimeDomainData,
        Self::AnalyserFloatTimeDomainData,
        Self::AudioContextBaseLatency,
        Self::AudioContextOutputLatency,
        Self::AudioContextSampleRate,
    ];
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Audio`.
///
/// Construct with `AudioOverride::new(mode)` so the policy is
/// resolved once at construction; the override is then registered
/// by the libxul bridge into every `JsContext` for the renderer.
///
/// Mode-divergent behavior is in the *policy*, not the *trait*:
/// every renderer registers an `AudioOverride`, but Strict-mode
/// `install` activates the normalized DSP path and Standard-mode
/// `install` is a no-op. Keeping the registration structurally
/// uniform across modes means the bridge has one code path.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data, so `install(&OverrideContext)` produces
/// observationally identical state regardless of `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct AudioOverride {
    policy: AudioReadbackPolicy,
}

impl AudioOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: AudioReadbackPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> AudioReadbackPolicy {
        self.policy
    }

    /// The audio profile this override pins. Always
    /// `&LOCKED_AUDIO_PROFILE` after the v1.23 amiunique-generic
    /// refactor — both modes share the cohort-locked DSP path.
    /// Strict and Standard diverge only on `policy().farbling()`.
    pub fn profile(&self) -> &'static AudioProfile {
        self.policy.profile()
    }
}

impl FingerprintOverride for AudioOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Audio
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect on either branch. The libxul DSP hook
        // is not yet wired (see crate-level TODO). When the FFI
        // lands:
        //   * NormalizedProfile(p) -> register a per-renderer
        //     callback returning `p` on demand; libxul swaps in the
        //     deterministic compressor + scalar reference DSP path.
        //   * NativePassThrough    -> remain a no-op; the native
        //     pipeline stays in place for Standard.
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
        assert_eq!(LOCKED_AUDIO_PROFILE.sample_rate_hz, 44_100);
        assert_eq!(LOCKED_AUDIO_PROFILE.channel_count, 2);
        assert_eq!(LOCKED_AUDIO_PROFILE.base_latency_seconds, 0.005);
        assert_eq!(LOCKED_AUDIO_PROFILE.output_latency_seconds, 0.020);
        assert_eq!(LOCKED_AUDIO_PROFILE.f32_quantization_step, 1.0e-7);
        assert_eq!(
            LOCKED_AUDIO_PROFILE.compressor,
            CompressorImpl::CohortLocked
        );
        assert_eq!(LOCKED_AUDIO_PROFILE.dsp_path, DspPath::ScalarReference);
    }

    #[test]
    fn locked_profile_pins_determinism_mechanism() {
        // Phase-file edge case: "OfflineAudioContext rendering
        // deterministic across hardware." The mechanism is the
        // CohortLocked compressor + ScalarReference DSP path; without
        // both, the per-CPU SIMD path splits the cohort along
        // micro-arch lines. Assert the mechanism is locked, not just
        // the parameters.
        assert_eq!(
            LOCKED_AUDIO_PROFILE.compressor,
            CompressorImpl::CohortLocked
        );
        assert_eq!(LOCKED_AUDIO_PROFILE.dsp_path, DspPath::ScalarReference);
        // The quantization grid is the second determinism layer:
        // even if a future SIMD path produces sub-grid deltas, the
        // post-render rounding collapses them.
        assert!(LOCKED_AUDIO_PROFILE.f32_quantization_step > 0.0);
        assert!(LOCKED_AUDIO_PROFILE.f32_quantization_step <= 1.0e-6);
    }

    #[test]
    fn standard_resolves_to_cohort_base_with_farbling() {
        // v1.23 amiunique-generic refactor: Standard now activates
        // the cohort-locked DSP path AND carries
        // STANDARD_FARBLING_PROFILE for per-sample ±1e-5 noise on
        // Float32Array readback.
        let p = AudioReadbackPolicy::for_mode(Mode::Standard);
        assert!(matches!(p, AudioReadbackPolicy::Normalized { .. }));
        assert!(std::ptr::eq(p.profile(), &LOCKED_AUDIO_PROFILE));
        let f = p
            .farbling()
            .expect("Standard MUST carry a farbling profile");
        assert!(std::ptr::eq(f, &crate::farbling::STANDARD_FARBLING_PROFILE));
        assert!(p.normalizes());
    }

    #[test]
    fn strict_resolves_to_cohort_base_without_farbling() {
        // v1.23: Strict shares the same cohort base but carries
        // farbling=None — pure cohort lock.
        let p = AudioReadbackPolicy::for_mode(Mode::Strict);
        assert!(matches!(p, AudioReadbackPolicy::Normalized { .. }));
        assert!(std::ptr::eq(p.profile(), &LOCKED_AUDIO_PROFILE));
        assert_eq!(p.farbling(), None);
        assert!(p.normalizes());
    }

    #[test]
    fn standard_and_strict_share_audio_cohort_base() {
        // v1.23 cohort unification: audio profile is the exact
        // same static in both modes (address identity).
        let s = AudioReadbackPolicy::for_mode(Mode::Standard);
        let r = AudioReadbackPolicy::for_mode(Mode::Strict);
        assert!(std::ptr::eq(s.profile(), r.profile()));
        // Modes diverge ONLY on farbling.
        assert!(s.farbling().is_some());
        assert!(r.farbling().is_none());
    }

    #[test]
    fn audio_surface_all_covers_edge_cases() {
        // Phase-file edge cases for Module 29:
        //   - AnalyserNode.getByteFrequencyData precision
        //   - OfflineAudioContext rendering deterministic
        // Plus the AudioBuffer / AnalyserNode siblings and the
        // AudioContext metadata trio (baseLatency / outputLatency /
        // sampleRate). Adding a new readback API to the platform
        // requires a variant here and breaks this test until the
        // bridge gains the corresponding plumb-in.
        assert_eq!(AudioSurface::ALL.len(), 9);

        for v in [
            AudioSurface::OfflineRenderBuffer,
            AudioSurface::AudioBufferGetChannelData,
            AudioSurface::AnalyserByteFrequencyData,
            AudioSurface::AnalyserFloatFrequencyData,
            AudioSurface::AnalyserByteTimeDomainData,
            AudioSurface::AnalyserFloatTimeDomainData,
            AudioSurface::AudioContextBaseLatency,
            AudioSurface::AudioContextOutputLatency,
            AudioSurface::AudioContextSampleRate,
        ] {
            assert!(AudioSurface::ALL.contains(&v), "missing pathway: {:?}", v);
        }
    }

    #[test]
    fn audio_override_reports_audio_surface_under_both_modes() {
        // The bridge registers under WebIdlSurface::Audio regardless
        // of mode (uniform registration; mode-divergence is in the
        // policy).
        assert_eq!(
            AudioOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Audio
        );
        assert_eq!(
            AudioOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Audio
        );
    }

    #[test]
    fn both_overrides_carry_the_locked_profile_v1_23() {
        // v1.23 refactor: both modes share LOCKED_AUDIO_PROFILE.
        // Per-mode divergence is on policy().farbling().
        let standard = AudioOverride::new(Mode::Standard);
        let strict = AudioOverride::new(Mode::Strict);
        assert!(std::ptr::eq(standard.profile(), &LOCKED_AUDIO_PROFILE));
        assert!(std::ptr::eq(strict.profile(), &LOCKED_AUDIO_PROFILE));
        assert!(standard.policy().farbling().is_some());
        assert_eq!(strict.policy().farbling(), None);
    }

    #[test]
    fn audio_override_install_is_context_inert() {
        // Edge case: override must be inert in iframe / worker /
        // service-worker / dedicated-worker. Drive install across
        // every JsContext for both modes and assert observed state
        // (the policy + surface) does not vary across contexts.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000029").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = AudioOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Audio);
        }
    }

    #[test]
    fn audio_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AudioOverride>();
        assert_send_sync::<AudioReadbackPolicy>();
        assert_send_sync::<AudioProfile>();
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // Mirror of the Module 26 exhaustive-match contract for
        // AudioSurface. The bridge MUST match without a `_` arm
        // so a new pathway added to the enum fails compilation
        // until the bridge wires it.
        fn route(s: AudioSurface) -> &'static str {
            match s {
                AudioSurface::OfflineRenderBuffer => "offline-render-buffer",
                AudioSurface::AudioBufferGetChannelData => "audio-buffer-get-channel-data",
                AudioSurface::AnalyserByteFrequencyData => "analyser-byte-frequency-data",
                AudioSurface::AnalyserFloatFrequencyData => "analyser-float-frequency-data",
                AudioSurface::AnalyserByteTimeDomainData => "analyser-byte-time-domain-data",
                AudioSurface::AnalyserFloatTimeDomainData => "analyser-float-time-domain-data",
                AudioSurface::AudioContextBaseLatency => "audio-context-base-latency",
                AudioSurface::AudioContextOutputLatency => "audio-context-output-latency",
                AudioSurface::AudioContextSampleRate => "audio-context-sample-rate",
            }
        }
        for s in AudioSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // The libxul bridge will match on AudioReadbackPolicy to
        // decide whether to register the DSP hook. Lock in the
        // exhaustive-match contract here so a future variant (e.g.
        // a "QuantizationOnly" Strict sub-mode that keeps the native
        // compressor but rounds the output) cannot be silently
        // treated as native pass-through.
        fn arm(p: AudioReadbackPolicy) -> &'static str {
            match p {
                AudioReadbackPolicy::Normalized { farbling: None, .. } => "cohort-locked",
                AudioReadbackPolicy::Normalized {
                    farbling: Some(_), ..
                } => "cohort-locked-farbled",
            }
        }
        assert_eq!(
            arm(AudioReadbackPolicy::for_mode(Mode::Standard)),
            "cohort-locked-farbled",
        );
        assert_eq!(
            arm(AudioReadbackPolicy::for_mode(Mode::Strict)),
            "cohort-locked",
        );
    }

    #[test]
    fn determinism_switches_dispatch_exhaustively() {
        // CompressorImpl and DspPath are the cohort-determinism
        // mechanism. The bridge MUST match exhaustively so a future
        // variant (e.g. CompressorImpl::Aarch64NeonScalar) cannot
        // silently fall through to the SIMD path.
        fn compressor(c: CompressorImpl) -> &'static str {
            match c {
                CompressorImpl::Native => "native",
                CompressorImpl::CohortLocked => "cohort-locked",
            }
        }
        fn dsp(d: DspPath) -> &'static str {
            match d {
                DspPath::Native => "native",
                DspPath::ScalarReference => "scalar-reference",
            }
        }
        assert_eq!(compressor(CompressorImpl::Native), "native");
        assert_eq!(compressor(CompressorImpl::CohortLocked), "cohort-locked");
        assert_eq!(dsp(DspPath::Native), "native");
        assert_eq!(dsp(DspPath::ScalarReference), "scalar-reference");
    }
}
