//! Module 35.5 — per-(origin, IdentityProfile) deterministic farbling
//! for dynamic readback surfaces.
//!
//! Phase 5.5's amiunique-generic refactor: Standard mode shares the
//! Strict cohort identity (same `LOCKED_CANVAS_PROFILE` /
//! `LOCKED_WEBGL_PROFILE` / `LOCKED_AUDIO_PROFILE` statics) AND adds
//! deterministic noise on dynamic readbacks so cross-site tracking
//! is defeated. Same-site identity stays stable across browser
//! restarts (UX preserved). Strict keeps the pure cohort lock
//! (`farbling: None`) — every Strict user is identical.
//!
//! ## Mode-applicability
//!
//!   * **Standard** — `Some(&STANDARD_FARBLING_PROFILE)`. Canvas
//!     readback bytes, audio `Float32Array` samples, and WebGL
//!     numeric `MAX_*` parameters all carry a small deterministic
//!     offset derived from the partition key's farbling seed.
//!   * **Strict** — `None`. Pure cohort lock; no noise. Two Strict
//!     users with the same locked profiles see byte-identical
//!     readbacks (Tor / Mullvad cohort posture).
//!
//! ## Determinism contract
//!
//! For a given `(seed, surface, index)` tuple, the farble offset
//! is a deterministic SHA-256 sub-derivation. Properties:
//!
//!   1. **Stable per (origin, IdentityProfile, surface, index).**
//!      Same partition key (which keys on (origin, profile_id, ctx)
//!      per pb-storage §3.5) yields the same farbling seed
//!      ([`pb_storage::PartitionKey::farbling_seed`]); same seed +
//!      same surface + same index yields the same offset. A site
//!      reading a canvas pixel twice gets the same farbled value;
//!      same site across browser restarts gets the same value.
//!   2. **Different across origins** under the same profile.
//!      Different partition keys → different seeds → different
//!      farble streams. Cross-site tracking via canvas / audio /
//!      WebGL readback is defeated.
//!   3. **Independent across surfaces.** Canvas / WebGL-numeric /
//!      audio carry disjoint [`FarblingSurface`] tags, so the same
//!      seed produces different streams per surface. A site
//!      cross-correlating canvas-offset[i] vs audio-offset[i]
//!      learns nothing about the profile.
//!   4. **No time / call-count dependence.** Pure function of
//!      inputs; no internal counter, no clock read.
//!
//! ## Architecture references
//!
//!   * **L7** — audited primitives only. The farble derivation
//!     uses `sha2` (already an audited dep; the same primitive
//!     `pb-storage::partition_key` uses).
//!   * **§3.5** — partition_key keys on (origin, profile_id,
//!     ctx); the farbling seed inherits that keying via
//!     [`pb_storage::PartitionKey::farbling_seed`].
//!   * **§5.5** — central fingerprint bucketing; farbling is the
//!     dynamic-readback layer on top of the static cohort lock.
//!   * **v1.23 audit** — supersedes the v1.12 / v1.13 / v1.14
//!     "Standard = NativePassThrough" decisions for Modules 27 /
//!     28 / 29. Standard now cohort-bases AND farbles.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): the libxul-side readback
//   patch calls `farble_canvas_byte` / `farble_audio_sample`
//   / `farble_webgl_int` at the canvas `getImageData` /
//   `AudioBuffer.getChannelData` / WebGL `getParameter(MAX_*)`
//   call sites with `seed = partition_key.farbling_seed()` and
//   per-call `index` (byte offset for canvas, sample index for
//   audio, parameter ordinal for WebGL).
// TODO(pb-testkit Module 0.5 farbling-aware harness extension):
//   `fixture::fingerprint_override` gains farbling drivers so
//   Phase 6+ tests can assert same-(origin, profile_id) →
//   identical farbled output and different-origin → different
//   farbled output without re-deriving the partition_key seed.
// TODO(Phase 10 / Module 71+): adversarial-fingerprint suite
//   asserts (a) two `getImageData` calls in the same renderer
//   same site = identical farbled output; (b) same site across
//   browser restarts = identical (deterministic); (c) different
//   sites in same profile = different farbled output;
//   (d) different identity profiles = different farbled output.

use sha2::{Digest, Sha256};

// ── Locked grid constants ────────────────────────────────────────────────

/// Width of the farbling seed in bytes. Mirrors
/// [`pb_storage::FARBLING_SEED_LEN`]; pinned here as the public
/// type alias the libxul bridge and the gecko::canvas / webgl /
/// audio modules consume so they don't need a pb-storage import.
pub const FARBLING_SEED_LEN: usize = 16;

/// A farbling seed: 16 bytes derived from a `PartitionKey` via
/// [`pb_storage::PartitionKey::farbling_seed`]. Treat as
/// privacy-sensitive (an adversary who learned the seed could
/// predict every farble offset for the corresponding partition);
/// never log, never echo to a `Display` impl.
pub type FarblingSeed = [u8; FARBLING_SEED_LEN];

/// Domain-separation label for the v1 farble derivation (epoch=0
/// path; deterministic across browser restarts). Distinct from
/// pb-storage's `FARBLING_SEED_DOMAIN` so a single SHA-256 chain
/// over (seed, surface, index) yields outputs disjoint from any
/// other pb-storage / pb-fingerprint sub-derivation.
///
/// V1 prioritizes same-site identity stability over WWW'25-class
/// statistical-attack resistance (the UX trade locked in v1.23
/// amiunique-generic posture).
const FARBLE_DERIVATION_DOMAIN: &[u8] = b"PB-FARBLE-V1";

/// Domain-separation label for the v2 farble derivation (epoch>0
/// path; rotates per session). The orchestrator (pb-browser at
/// Phase 11 / Module 80) supplies a `FarblingEpoch` from a CSPRNG
/// at startup; the v2 helpers fold it into the derivation chain
/// so per-(origin, profile) outputs change across browser
/// restarts.
///
/// V2 outputs are byte-disjoint from V1 outputs by construction
/// (different domain prefix). The orchestrator chooses v1 or v2
/// per IdentityProfile setting; the per-mode policy stays
/// unaware. WWW'25-class statistical pixel-recovery attacks
/// against fixed-amplitude noise (published 2025) are defeated
/// by the v2 path because each browser restart presents a new
/// per-pixel offset distribution.
///
/// **Cohort-shift discipline (Adaptation protocol):** moving a
/// surface from v1 to v2 is a cohort shift and must land via an
/// architecture revision-log entry. v2 is **not enabled by
/// default in v1.0**; pb-browser configures per IdentityProfile.
const FARBLE_DERIVATION_DOMAIN_V2: &[u8] = b"PB-FARBLE-V2";

/// A 16-byte epoch the orchestrator generates at startup (CSPRNG)
/// to rotate the v2 farbling derivation across browser restarts.
/// `[0u8; 16]` is the sentinel "no epoch" value (v1 path).
pub type FarblingEpoch = [u8; 16];

/// The sentinel "no epoch" value. `farble_*_with_epoch` helpers
/// with this epoch produce outputs **identical** to the v1
/// helpers — provided as a convenience so the orchestrator can
/// configure all-or-nothing per identity without branching.
pub const NO_FARBLING_EPOCH: FarblingEpoch = [0u8; 16];

// ── Surface tags ─────────────────────────────────────────────────────────

/// Disjoint farbling streams per readback surface. Without this
/// tag, a site cross-correlating `canvas-offset[i]` vs
/// `audio-offset[i]` could learn the offset value for any single
/// surface from a different one. The tag shifts each surface into
/// a separate SHA-256 expansion.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FarblingSurface {
    /// Module 27 — canvas readback (`getImageData`, `toDataURL`,
    /// `OffscreenCanvas`, `WebGLRenderingContext.readPixels`).
    Canvas,
    /// Module 28 — WebGL numeric parameters (`MAX_TEXTURE_SIZE`,
    /// `MAX_VIEWPORT_DIMS`, etc.). Farbling is applied within the
    /// cohort-locked bounds; the libxul bridge clamps after.
    WebGlNumeric,
    /// Module 29 — audio buffer readback
    /// (`AudioBuffer.getChannelData`, `AnalyserNode.getByteFrequencyData`).
    Audio,
    /// Module 35.11 — DOMRect coordinates from
    /// `Element.getClientRects()` / `getBoundingClientRect()` /
    /// `Range.getClientRects()`. Sub-pixel positions leak per-font-
    /// rendering + per-DPI signals.
    DomRect,
    /// Module 35.11 — TextMetrics widths from
    /// `CanvasRenderingContext2D.measureText()`. Sub-pixel widths
    /// leak per-font-rendering signals at a finer resolution than
    /// canvas pixel readbacks.
    TextMetrics,
}

impl FarblingSurface {
    /// Single-byte tag prepended to the SHA-256 chain. Distinct
    /// across variants by construction. Adding a variant requires
    /// allocating a new tag here; the libxul bridge's exhaustive
    /// match catches an oversight.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Canvas => 0x01,
            Self::WebGlNumeric => 0x02,
            Self::Audio => 0x03,
            Self::DomRect => 0x04,
            Self::TextMetrics => 0x05,
        }
    }
}

// ── FarblingProfile ──────────────────────────────────────────────────────

/// Per-Mode farbling parameters.
///
/// Values pinned by the v1.23 amiunique-generic audit; any change
/// is a cohort shift through the Adaptation protocol.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FarblingProfile {
    /// Stable label for the profile version. Bumped via the
    /// Adaptation protocol on any value change.
    pub label: &'static str,
    /// Canvas readback per-byte farble amplitude. Each byte gets
    /// an offset in `[-canvas_lsb_amplitude, +canvas_lsb_amplitude]`.
    /// v1: 1 (i.e. ±1 LSB per byte) — below human visual
    /// perception, above the all-zeros cohort floor that would
    /// trivially collide with Strict.
    pub canvas_lsb_amplitude: u8,
    /// Audio readback per-sample farble amplitude. Each
    /// `Float32Array` sample gets an offset in
    /// `[-audio_quantization_eps, +audio_quantization_eps]`. v1:
    /// 1e-5 — well below the audio perceptual threshold (~1e-3
    /// for typical content; Tor / Brave use the same order of
    /// magnitude).
    pub audio_quantization_eps: f32,
    /// WebGL numeric `MAX_*` farble amplitude. Each parameter
    /// gets an integer offset in `[-webgl_numeric_amplitude,
    /// +webgl_numeric_amplitude]` clamped to stay within the
    /// cohort-locked bounds (Module 28 `LOCKED_WEBGL_PROFILE`).
    /// v1: 1.
    pub webgl_numeric_amplitude: i32,
}

/// The locked Standard-mode farbling profile.
pub static STANDARD_FARBLING_PROFILE: FarblingProfile = FarblingProfile {
    label: "devbrowse-farbling-standard-v1",
    canvas_lsb_amplitude: 1,
    audio_quantization_eps: 1e-5,
    webgl_numeric_amplitude: 1,
};

// ── Internal stream byte derivation ──────────────────────────────────────

/// Derive one uniform byte from a `(seed, surface, index)` tuple.
/// All public `farble_*` helpers project this byte into the
/// per-surface range.
///
/// V1 path: deterministic across restarts.
fn stream_byte(seed: &FarblingSeed, surface: FarblingSurface, index: u64) -> u8 {
    let mut h = Sha256::new();
    h.update(FARBLE_DERIVATION_DOMAIN);
    h.update(seed);
    h.update([surface.tag()]);
    h.update(index.to_le_bytes());
    h.finalize()[0]
}

/// V2 path: derive one uniform byte from a
/// `(epoch, seed, surface, index)` tuple. Used by the
/// `farble_*_with_epoch` helpers. Outputs are disjoint from v1
/// `stream_byte` by construction (different domain prefix).
fn stream_byte_v2(
    epoch: &FarblingEpoch,
    seed: &FarblingSeed,
    surface: FarblingSurface,
    index: u64,
) -> u8 {
    let mut h = Sha256::new();
    h.update(FARBLE_DERIVATION_DOMAIN_V2);
    h.update(epoch);
    h.update(seed);
    h.update([surface.tag()]);
    h.update(index.to_le_bytes());
    h.finalize()[0]
}

// ── Pre-derived stream keys (P1-5, 2026-05-22) ───────────────────────────

/// A pre-derived stream key for one `(seed, surface)` pair. Lets
/// the libxul bridge amortize the SHA-256 init cost across many
/// bytes of a single readback (e.g. one 1024×1024 canvas readback
/// touches ~4M bytes; without this pre-derivation each byte
/// reallocates a fresh `Sha256`).
///
/// **Performance contract (per README §13):** the v1 hot path
/// (`farble_canvas_byte` ×N) reallocates `Sha256` per call. For
/// the eventual libxul-wired FFI, the bridge constructs one
/// `FarblingStreamKey` per `(seed, surface)` per readback and
/// drives `stream_byte_from_key` per index — one
/// `Sha256::new()` per readback rather than per byte.
///
/// V2-aware variant `FarblingStreamKeyV2` carries the epoch.
#[derive(Debug, Clone)]
pub struct FarblingStreamKey {
    /// Captured prefix-hash state: the `Sha256` instance updated
    /// with `(domain, seed, surface_tag)` ready to absorb
    /// `index.to_le_bytes()`.
    prefix: Sha256,
}

impl FarblingStreamKey {
    /// Derive a pre-prepared stream key for the v1 (deterministic)
    /// path. Clones the prefix-hash state on each byte derivation
    /// — `Sha256::clone()` is cheap (~96 bytes copy) vs
    /// `Sha256::new() + update(domain) + update(seed) +
    /// update(surface_tag)` per byte (~4 hash-state updates).
    pub fn new(seed: &FarblingSeed, surface: FarblingSurface) -> Self {
        let mut prefix = Sha256::new();
        prefix.update(FARBLE_DERIVATION_DOMAIN);
        prefix.update(seed);
        prefix.update([surface.tag()]);
        Self { prefix }
    }

    /// Emit one stream byte at `index`. Output is byte-identical
    /// to `stream_byte(seed, surface, index)` for the same
    /// `(seed, surface)`.
    pub fn byte_at(&self, index: u64) -> u8 {
        let mut h = self.prefix.clone();
        h.update(index.to_le_bytes());
        h.finalize()[0]
    }
}

/// V2 (per-session-epoch) pre-derived stream key. Same shape as
/// [`FarblingStreamKey`] but folds the epoch into the prefix.
/// Output of `byte_at(i)` is byte-identical to
/// `stream_byte_v2(epoch, seed, surface, i)`.
#[derive(Debug, Clone)]
pub struct FarblingStreamKeyV2 {
    prefix: Sha256,
}

impl FarblingStreamKeyV2 {
    pub fn new(epoch: &FarblingEpoch, seed: &FarblingSeed, surface: FarblingSurface) -> Self {
        let mut prefix = Sha256::new();
        prefix.update(FARBLE_DERIVATION_DOMAIN_V2);
        prefix.update(epoch);
        prefix.update(seed);
        prefix.update([surface.tag()]);
        Self { prefix }
    }

    pub fn byte_at(&self, index: u64) -> u8 {
        let mut h = self.prefix.clone();
        h.update(index.to_le_bytes());
        h.finalize()[0]
    }
}

// ── Public farble functions ──────────────────────────────────────────────

/// Deterministic signed offset for canvas readback byte at
/// `byte_index`. Result in `[-amplitude, +amplitude]`.
///
/// `amplitude == 0` returns 0 (no farbling).
///
/// **Distribution bias (documented):** the `(b as u16 % span)`
/// reduction has a worst-case bias bound of `1/256` — when `256`
/// is not a multiple of `span = 2A + 1`, the lowest few buckets
/// receive one extra hit from the 256-byte input space. For the
/// shipped `STANDARD_FARBLING_PROFILE.canvas_lsb_amplitude = 1`
/// (`span = 3`), the bias is `256 / 3 = 85` remainder `1`, so
/// the bucket `bucket_index = 0` receives 86 of 256 inputs vs
/// the uniform 85 1/3 — a 0.39% deviation, well below any
/// statistical-attack threshold that fingerprinters publish
/// today. If Phase 10 flags a need for exact uniformity, switch
/// to rejection sampling (re-derive `b` while `b >= (256 - 256 %
/// span)`); the cost is negligible (~2% extra iterations).
pub fn farble_canvas_byte(seed: &FarblingSeed, byte_index: u64, amplitude: u8) -> i8 {
    if amplitude == 0 {
        return 0;
    }
    let b = stream_byte(seed, FarblingSurface::Canvas, byte_index);
    let span = 2u16 * amplitude as u16 + 1; // {-A,..,+A} = 2A+1 values
    let bucket = (b as u16 % span) as i16;
    (bucket - amplitude as i16) as i8
}

/// Deterministic offset for an audio `Float32Array` sample at
/// `sample_index`. Result in `[-eps, +eps]`.
///
/// `eps` is the per-sample farble amplitude (e.g. `1e-5`). Maps a
/// uniform byte to a 256-step floating-point quantization within
/// the range.
///
/// **Hardened inputs (P0-3, 2026-05-22):** non-finite or
/// non-positive `eps` (NaN, ±∞, or `eps < 0.0`) returns `0.0`
/// instead of propagating NaN or producing inverted-sign output.
/// The cohort contract is "noise in `[-eps, +eps]`"; a malformed
/// eps could only loosen the cohort, so the safe behavior is to
/// emit zero (matching the `eps == 0.0` short-circuit).
pub fn farble_audio_sample(seed: &FarblingSeed, sample_index: u64, eps: f32) -> f32 {
    // Reject NaN, ±∞, and any non-positive eps. `is_finite` is
    // false for NaN + ∞; `<= 0.0` catches negative and zero
    // (negative would invert sign; zero short-circuits anyway).
    if !eps.is_finite() || eps <= 0.0 {
        return 0.0;
    }
    let b = stream_byte(seed, FarblingSurface::Audio, sample_index);
    // Map u8 to (-1, +1] in floating point, then scale by eps.
    // (2 * b / 255 - 1) gives [-1, +1]; multiply by eps.
    let unit = (b as f32) * (2.0 / 255.0) - 1.0;
    unit * eps
}

/// Deterministic signed offset for a WebGL numeric parameter at
/// `param_index`. Result in `[-amplitude, +amplitude]`.
///
/// The libxul bridge clamps the (parameter_value + offset) result
/// to the Module 28 `LOCKED_WEBGL_PROFILE` cohort bounds so a
/// negative offset on a cohort-floor parameter does not underflow.
///
/// **Hardened inputs (P0-2, 2026-05-22):** `amplitude <= 0` returns
/// 0 (no farbling — covers the `==0` short-circuit AND defensively
/// rejects negative amplitudes that would invert the range
/// semantics). `amplitude >= i32::MAX / 2` returns 0 as well — the
/// span calculation `2 * amplitude + 1` would overflow `i32`
/// otherwise. The current `STANDARD_FARBLING_PROFILE` ships
/// `webgl_numeric_amplitude = 1` so the guard is defensive against
/// future use; the function is `pub` and callers may pass larger
/// values.
pub fn farble_webgl_int(seed: &FarblingSeed, param_index: u64, amplitude: i32) -> i32 {
    if amplitude <= 0 || amplitude >= i32::MAX / 2 {
        return 0;
    }
    let b = stream_byte(seed, FarblingSurface::WebGlNumeric, param_index);
    // `amplitude < i32::MAX / 2` guarantees `2 * amplitude + 1`
    // fits in `i32` and the `as u32` cast is lossless.
    let span = (2i32 * amplitude + 1) as u32;
    let bucket = (b as u32) % span;
    (bucket as i32) - amplitude
}

// ── V2 (per-session-epoch) public helpers (P2-2, 2026-05-22) ─────────────

/// Per-session-epoch canvas farble (v2). When `epoch ==
/// NO_FARBLING_EPOCH`, the output is **NOT** identical to v1
/// (different derivation domain) — the v2 path is a separate
/// cohort by construction. Use `farble_canvas_byte` (v1) for
/// deterministic-across-restarts behavior; use this v2 helper
/// when the orchestrator has opted into per-session rotation.
pub fn farble_canvas_byte_with_epoch(
    epoch: &FarblingEpoch,
    seed: &FarblingSeed,
    byte_index: u64,
    amplitude: u8,
) -> i8 {
    if amplitude == 0 {
        return 0;
    }
    let b = stream_byte_v2(epoch, seed, FarblingSurface::Canvas, byte_index);
    let span = 2u16 * amplitude as u16 + 1;
    let bucket = (b as u16 % span) as i16;
    (bucket - amplitude as i16) as i8
}

/// Per-session-epoch audio farble (v2). Same hardening as
/// [`farble_audio_sample`] (NaN / ±∞ / negative eps → 0).
pub fn farble_audio_sample_with_epoch(
    epoch: &FarblingEpoch,
    seed: &FarblingSeed,
    sample_index: u64,
    eps: f32,
) -> f32 {
    if !eps.is_finite() || eps <= 0.0 {
        return 0.0;
    }
    let b = stream_byte_v2(epoch, seed, FarblingSurface::Audio, sample_index);
    let unit = (b as f32) * (2.0 / 255.0) - 1.0;
    unit * eps
}

/// Per-session-epoch WebGL numeric farble (v2). Same hardening
/// as [`farble_webgl_int`] (≤0 or ≥i32::MAX/2 → 0).
pub fn farble_webgl_int_with_epoch(
    epoch: &FarblingEpoch,
    seed: &FarblingSeed,
    param_index: u64,
    amplitude: i32,
) -> i32 {
    if amplitude <= 0 || amplitude >= i32::MAX / 2 {
        return 0;
    }
    let b = stream_byte_v2(epoch, seed, FarblingSurface::WebGlNumeric, param_index);
    let span = (2i32 * amplitude + 1) as u32;
    let bucket = (b as u32) % span;
    (bucket as i32) - amplitude
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_a() -> FarblingSeed {
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ]
    }

    fn seed_b() -> FarblingSeed {
        [0xff; 16]
    }

    #[test]
    fn standard_farbling_profile_locks_v1_values() {
        // v1.23 audit pinned these. Any change is a cohort shift.
        assert_eq!(
            STANDARD_FARBLING_PROFILE.label,
            "devbrowse-farbling-standard-v1"
        );
        assert_eq!(STANDARD_FARBLING_PROFILE.canvas_lsb_amplitude, 1);
        assert_eq!(STANDARD_FARBLING_PROFILE.audio_quantization_eps, 1e-5);
        assert_eq!(STANDARD_FARBLING_PROFILE.webgl_numeric_amplitude, 1);
    }

    #[test]
    fn farbling_surface_tags_are_pairwise_distinct() {
        // A duplicate tag would collapse two surfaces into the
        // same farbling stream — the cross-surface independence
        // property would silently break.
        let tags = [
            FarblingSurface::Canvas.tag(),
            FarblingSurface::WebGlNumeric.tag(),
            FarblingSurface::Audio.tag(),
            FarblingSurface::DomRect.tag(),
            FarblingSurface::TextMetrics.tag(),
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "duplicate surface tag");
            }
        }
    }

    // ── farble_canvas_byte ───────────────────────────────────────────

    #[test]
    fn farble_canvas_byte_is_deterministic() {
        let seed = seed_a();
        for i in 0..100 {
            let a = farble_canvas_byte(&seed, i, 1);
            let b = farble_canvas_byte(&seed, i, 1);
            assert_eq!(a, b, "non-deterministic at index {}", i);
        }
    }

    #[test]
    fn farble_canvas_byte_respects_amplitude_bound() {
        let seed = seed_a();
        for amp in [1u8, 2, 5, 8, 32, 127] {
            for i in 0..1000_u64 {
                let v = farble_canvas_byte(&seed, i, amp);
                let amp_i = amp as i8;
                assert!(
                    v >= -amp_i && v <= amp_i,
                    "amp={} i={} v={} out of [-{}, +{}]",
                    amp,
                    i,
                    v,
                    amp,
                    amp,
                );
            }
        }
    }

    #[test]
    fn farble_canvas_byte_amplitude_zero_returns_zero() {
        let seed = seed_a();
        for i in 0..50 {
            assert_eq!(farble_canvas_byte(&seed, i, 0), 0);
        }
    }

    #[test]
    fn farble_canvas_byte_differs_across_seeds() {
        // Cross-origin protection: different seeds yield
        // different farble streams. We sample 200 indices and
        // assert at least 80% disagree (probabilistic; with
        // amplitude=1 there are 3 buckets so random agreement is
        // ~33%, two-seed agreement is much lower).
        let a = seed_a();
        let b = seed_b();
        let mut agree = 0;
        for i in 0..200_u64 {
            if farble_canvas_byte(&a, i, 1) == farble_canvas_byte(&b, i, 1) {
                agree += 1;
            }
        }
        assert!(
            agree < 100,
            "expected most indices to disagree across seeds, got {}/200 agreement",
            agree,
        );
    }

    #[test]
    fn farble_canvas_byte_amplitude_one_uses_three_buckets() {
        // ±1 amplitude = {-1, 0, +1}. Sweep 300 indices and
        // confirm all three values appear (uniform sampling).
        let seed = seed_a();
        let mut seen = [false; 3];
        for i in 0..300_u64 {
            let v = farble_canvas_byte(&seed, i, 1);
            seen[(v + 1) as usize] = true;
        }
        assert!(seen[0] && seen[1] && seen[2], "buckets seen: {:?}", seen);
    }

    // ── farble_audio_sample ──────────────────────────────────────────

    #[test]
    fn farble_audio_sample_is_deterministic() {
        let seed = seed_a();
        for i in 0..100 {
            let a = farble_audio_sample(&seed, i, 1e-5);
            let b = farble_audio_sample(&seed, i, 1e-5);
            assert_eq!(a.to_bits(), b.to_bits());
        }
    }

    #[test]
    fn farble_audio_sample_respects_eps_bound() {
        let seed = seed_a();
        for eps in [1e-7_f32, 1e-5, 1e-3, 1.0] {
            for i in 0..500_u64 {
                let v = farble_audio_sample(&seed, i, eps);
                assert!(
                    v >= -eps && v <= eps,
                    "eps={} i={} v={} out of [-eps, +eps]",
                    eps,
                    i,
                    v,
                );
            }
        }
    }

    #[test]
    fn farble_audio_sample_eps_zero_returns_zero() {
        let seed = seed_a();
        for i in 0..50 {
            assert_eq!(farble_audio_sample(&seed, i, 0.0), 0.0);
        }
    }

    #[test]
    fn farble_audio_sample_handles_non_finite_or_negative_eps() {
        // Hardened input (P0-3, 2026-05-22): NaN, ±∞, or negative
        // eps returns 0.0 instead of propagating NaN / inverting
        // sign. The cohort contract is "[-eps, +eps]"; malformed
        // eps collapses to zero (safe default — no farble).
        let seed = seed_a();
        for i in 0..50 {
            assert_eq!(farble_audio_sample(&seed, i, f32::NAN), 0.0);
            assert_eq!(farble_audio_sample(&seed, i, f32::INFINITY), 0.0);
            assert_eq!(farble_audio_sample(&seed, i, f32::NEG_INFINITY), 0.0);
            assert_eq!(farble_audio_sample(&seed, i, -1e-5), 0.0);
            assert_eq!(farble_audio_sample(&seed, i, -1.0), 0.0);
        }
    }

    // ── farble_webgl_int ─────────────────────────────────────────────

    #[test]
    fn farble_webgl_int_is_deterministic() {
        let seed = seed_a();
        for i in 0..100 {
            let a = farble_webgl_int(&seed, i, 1);
            let b = farble_webgl_int(&seed, i, 1);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn farble_webgl_int_respects_amplitude_bound() {
        let seed = seed_a();
        for amp in [1_i32, 2, 5, 16] {
            for i in 0..500_u64 {
                let v = farble_webgl_int(&seed, i, amp);
                assert!(
                    v >= -amp && v <= amp,
                    "amp={} i={} v={} out of [-{}, +{}]",
                    amp,
                    i,
                    v,
                    amp,
                    amp,
                );
            }
        }
    }

    #[test]
    fn farble_webgl_int_rejects_negative_or_overflow_amplitude() {
        // Hardened input (P0-2, 2026-05-22): amplitude <= 0 returns
        // 0 (no farble); amplitude >= i32::MAX/2 returns 0 to
        // prevent the `2 * amplitude + 1` span calculation from
        // overflowing i32.
        let seed = seed_a();
        for i in 0..50_u64 {
            assert_eq!(farble_webgl_int(&seed, i, 0), 0);
            assert_eq!(farble_webgl_int(&seed, i, -1), 0);
            assert_eq!(farble_webgl_int(&seed, i, -1000), 0);
            assert_eq!(farble_webgl_int(&seed, i, i32::MIN), 0);
            assert_eq!(farble_webgl_int(&seed, i, i32::MAX), 0);
            assert_eq!(farble_webgl_int(&seed, i, i32::MAX / 2), 0);
            // Largest still-safe amplitude is `i32::MAX/2 - 1`;
            // verify it does not panic and returns a bounded value.
            let safe_amp = i32::MAX / 2 - 1;
            let v = farble_webgl_int(&seed, i, safe_amp);
            assert!(v.abs() < i32::MAX / 2);
        }
    }

    // ── Cross-surface independence ───────────────────────────────────

    #[test]
    fn farble_streams_are_independent_across_surfaces() {
        // Same seed + same index + different surface = different
        // stream. If the surface tag were dropped, all three
        // surfaces would produce the same byte for index i — a
        // hostile site could correlate canvas-offset[i] with
        // audio-offset[i] and learn one from the other.
        let seed = seed_a();
        let mut disagree = 0;
        for i in 0..200_u64 {
            let c = stream_byte(&seed, FarblingSurface::Canvas, i);
            let w = stream_byte(&seed, FarblingSurface::WebGlNumeric, i);
            let a = stream_byte(&seed, FarblingSurface::Audio, i);
            if c != w {
                disagree += 1;
            }
            if c != a {
                disagree += 1;
            }
            if w != a {
                disagree += 1;
            }
        }
        // 200 indices * 3 pairwise comparisons = 600 total;
        // expect ~99% disagreement (256-byte alphabet, random
        // collision ~0.4%).
        assert!(
            disagree > 500,
            "expected cross-surface independence, got {}/600 disagreement",
            disagree,
        );
    }

    // ── Known-answer pinning ─────────────────────────────────────────

    #[test]
    fn farble_canvas_byte_known_answer_v1() {
        // Pin the v1 derivation. If this hash chain ever
        // changes, FARBLE_DERIVATION_DOMAIN MUST be bumped to v2.
        let seed = seed_a();
        // Recompute by hand to verify the encoding.
        let mut h = Sha256::new();
        h.update(b"PB-FARBLE-V1");
        h.update(seed);
        h.update([0x01_u8]); // Canvas tag
        h.update(42_u64.to_le_bytes());
        let expected_byte = h.finalize()[0];
        let expected_v = ((expected_byte as u16 % 3) as i16 - 1) as i8;
        assert_eq!(farble_canvas_byte(&seed, 42, 1), expected_v);
    }

    #[test]
    fn farbling_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FarblingProfile>();
        assert_send_sync::<FarblingSurface>();
        assert_send_sync::<FarblingStreamKey>();
        assert_send_sync::<FarblingStreamKeyV2>();
    }

    // ── V2 (per-session-epoch) tests (P2-2, 2026-05-22) ──────────────

    fn epoch_a() -> FarblingEpoch {
        [
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
            0xaf, 0xb0,
        ]
    }

    fn epoch_b() -> FarblingEpoch {
        [
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ]
    }

    #[test]
    fn v2_is_disjoint_from_v1_by_domain_prefix() {
        // V1 and V2 use different SHA-256 domain prefixes, so even
        // with epoch = NO_FARBLING_EPOCH the outputs MUST be
        // different (they are derived from disjoint streams).
        let seed = seed_a();
        let mut equal_count = 0;
        for i in 0..200 {
            let v1 = farble_canvas_byte(&seed, i, 8);
            let v2 = farble_canvas_byte_with_epoch(&NO_FARBLING_EPOCH, &seed, i, 8);
            if v1 == v2 {
                equal_count += 1;
            }
        }
        // Random byte-level agreement should be ~200/17 ≈ 12. A
        // huge number would indicate the domain prefix is not
        // actually separating the streams.
        assert!(
            equal_count < 40,
            "v1 and v2 outputs should be disjoint streams; saw {}/200 agreement",
            equal_count,
        );
    }

    #[test]
    fn v2_rotates_per_epoch() {
        // Different epochs MUST produce different per-byte outputs
        // — that's the WWW'25 attack mitigation. Same seed, same
        // index, different epoch should differ on most indices.
        let seed = seed_a();
        let ea = epoch_a();
        let eb = epoch_b();
        let mut equal_count = 0;
        for i in 0..200 {
            let va = farble_canvas_byte_with_epoch(&ea, &seed, i, 8);
            let vb = farble_canvas_byte_with_epoch(&eb, &seed, i, 8);
            if va == vb {
                equal_count += 1;
            }
        }
        assert!(
            equal_count < 40,
            "v2 epochs should rotate the stream; saw {}/200 agreement",
            equal_count,
        );
    }

    #[test]
    fn v2_is_deterministic_for_fixed_epoch() {
        // Within one session (fixed epoch), v2 outputs are
        // deterministic — same UX guarantee as v1 holds for the
        // session's lifetime.
        let seed = seed_a();
        let epoch = epoch_a();
        for i in 0..100 {
            let a = farble_canvas_byte_with_epoch(&epoch, &seed, i, 4);
            let b = farble_canvas_byte_with_epoch(&epoch, &seed, i, 4);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn v2_audio_handles_non_finite_eps() {
        let seed = seed_a();
        let epoch = epoch_a();
        for i in 0..30 {
            assert_eq!(
                farble_audio_sample_with_epoch(&epoch, &seed, i, f32::NAN),
                0.0
            );
            assert_eq!(farble_audio_sample_with_epoch(&epoch, &seed, i, -1e-5), 0.0);
        }
    }

    #[test]
    fn v2_webgl_rejects_overflow_amplitude() {
        let seed = seed_a();
        let epoch = epoch_a();
        for i in 0..30_u64 {
            assert_eq!(farble_webgl_int_with_epoch(&epoch, &seed, i, 0), 0);
            assert_eq!(farble_webgl_int_with_epoch(&epoch, &seed, i, -1), 0);
            assert_eq!(farble_webgl_int_with_epoch(&epoch, &seed, i, i32::MAX), 0);
        }
    }

    // ── FarblingStreamKey tests (P1-5, 2026-05-22) ───────────────────

    #[test]
    fn stream_key_v1_byte_at_matches_stream_byte() {
        // Pre-derived stream key MUST emit byte-identical output
        // to the per-call `stream_byte` for the same (seed,
        // surface). This is the performance contract: the FFI
        // bridge can switch to the pre-derived key without
        // changing observable behavior.
        let seed = seed_a();
        for surface in [
            FarblingSurface::Canvas,
            FarblingSurface::WebGlNumeric,
            FarblingSurface::Audio,
        ] {
            let key = FarblingStreamKey::new(&seed, surface);
            for i in 0..200_u64 {
                assert_eq!(
                    key.byte_at(i),
                    stream_byte(&seed, surface, i),
                    "surface {:?} index {}",
                    surface,
                    i,
                );
            }
        }
    }

    #[test]
    fn stream_key_v2_byte_at_matches_stream_byte_v2() {
        let seed = seed_a();
        let epoch = epoch_a();
        for surface in [
            FarblingSurface::Canvas,
            FarblingSurface::WebGlNumeric,
            FarblingSurface::Audio,
        ] {
            let key = FarblingStreamKeyV2::new(&epoch, &seed, surface);
            for i in 0..200_u64 {
                assert_eq!(
                    key.byte_at(i),
                    stream_byte_v2(&epoch, &seed, surface, i),
                    "surface {:?} index {}",
                    surface,
                    i,
                );
            }
        }
    }
}
