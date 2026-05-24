//! Module 39 — GPU-side timer quantization (2 ms, mode-invariant).
//!
//! Floors every GPU-observable timestamp to a 2 ms grid. Mirror
//! of Module 32 for the GPU domain: where pb-fingerprint Module
//! 32 owns the JS clock quantum (1 ms Standard / 100 ms Strict),
//! pb-gpu Module 39 owns the GPU clock quantum (2 ms, both
//! modes). The GPU value is mode-invariant per L8 / L43 ("GPU
//! stays 2 ms (L8)"); this module is the authoritative source of
//! truth, and pb-fingerprint mirrors the value at
//! `gecko::timers::GPU_QUANTUM_NS` for documentation + cross-
//! module regression purposes.
//!
//! ## Architecture references
//!
//!   * **L8** — Fingerprint normalization through Gecko WebIDL
//!     override points. The 2 ms GPU quantum is one of the
//!     normalization values L8 enforces.
//!   * **L12** — pb-gpu cannot import pb-fingerprint. The
//!     cross-module alignment with `pb_fingerprint::gecko::timers::GPU_QUANTUM_NS`
//!     is therefore enforced by paired literal-value assertions
//!     on both sides (same pattern as Module 36 ↔ Module 35.6
//!     `COHORT_VENDOR` / `LOCKED_GPU_FEATURES` /
//!     `LOCKED_GPU_LIMITS` pairing, and Module 34 ↔ pb-network
//!     `LOCKED_USER_AGENT` / `DEVBROWSE_USER_AGENT` pairing).
//!   * **L13** — `#![forbid(unsafe_code)]` at crate root.
//!   * **L27** — no error surface here; quantization is total
//!     and infallible. The Display-redaction rule does not
//!     apply.
//!   * **L43 timer quantization** — phase-file inline lock:
//!     "performance.now() / Date.now() / Performance.timeOrigin
//!     quantized to 100 ms in Strict; 1 ms in Standard; GPU
//!     stays 2 ms (L8)". Module 32 owns the JS side
//!     (`STANDARD_TIMER_PROFILE.js_quantum_ns` /
//!     `STRICT_TIMER_PROFILE.js_quantum_ns`); Module 39 owns
//!     the GPU side here. Both are non-loosenable for Strict
//!     per L41.
//!   * **Module 32 — pb-fingerprint timers** — pairs by value
//!     equality (`pb_fingerprint::gecko::timers::GPU_QUANTUM_NS
//!     == GPU_TIMER_QUANTUM_NS`). Module 32 exposes the GPU
//!     quantum on `TimerProfile.gpu_quantum_ns` so the libxul
//!     bridge can read either side and get the same value.
//!   * **Module 28 (WebGL extensions allowlist)** — the WebGL
//!     `EXT_disjoint_timer_query` family is NOT in the
//!     5-extension allowlist, so it is not exposed to renderers.
//!     Module 39's [`GpuTimerSurface::WebGlDisjointTimerQuery`]
//!     variant lists it anyway for defense in depth: if a future
//!     libxul tag bump accidentally re-enables the extension,
//!     the bridge MUST quantize through this module.
//!   * **Module 35.6 (WebGPU)** — Module 36's
//!     `LOCKED_GPU_FEATURES == &[]` means the WebGPU
//!     `timestamp-query` feature is unrequestable. Same defense-
//!     in-depth listing under
//!     [`GpuTimerSurface::WebGpuQuerySetTimestamp`].
//!
//! ## Cross-platform principle
//!
//! No `cfg`-gated public API. Pure arithmetic + a `#[non_exhaustive]`
//! enum. Identical on every platform.
//
// TODO(Phase 11 / Module 80 — libxul GPU FFI bridge): wire
//   [`quantize_gpu_timer_ns`] in behind every libxul callback
//   that delivers a GPU-observable timestamp. The libxul bridge
//   MUST iterate [`GpuTimerSurface::ALL`] and register the
//   quantization hook behind each variant — a missed surface is
//   a sub-quantum side channel.
// TODO(Phase 10 — adversarial fingerprint suite): a live probe
//   asserts every GPU-timer-adjacent JS surface reads quantized
//   to 2 ms. The probe drives pb-gpu indirectly via a renderer;
//   the property here is that the bridge calls
//   `quantize_gpu_timer_ns` before any value crosses into JS.

// ── Quantum constant ──────────────────────────────────────────────────────

/// GPU timer quantum in nanoseconds: 2 ms (`2_000_000` ns).
///
/// Mode-invariant per L8 / L43. **pb-gpu Module 39 is the
/// authoritative source of truth**; pb-fingerprint Module 32
/// mirrors the value at `gecko::timers::GPU_QUANTUM_NS` and at
/// `TimerProfile.gpu_quantum_ns` for both
/// `STANDARD_TIMER_PROFILE` and `STRICT_TIMER_PROFILE`. Drift on
/// either side fails the paired regression test
/// [`tests::gpu_timer_quantum_matches_module_32_documentation_value`]
/// here and `gpu_quantum_is_2ms_in_both_modes` in
/// `crates/pb-fingerprint/src/gecko/timers.rs`.
///
/// Why 2 ms rather than 1 ms (Standard JS) or 100 ms (Strict
/// JS): GPU timing is a separate channel from `performance.now()`.
/// A 2 ms quantum on the GPU side is the cohort-wide L8 value
/// that survives both modes' surfaces — Strict gets 100 ms on
/// the JS side independently, but the GPU's 2 ms is enough to
/// destroy the timing channel against the page event loop
/// (which itself is throttled to 100 ms in Strict).
pub const GPU_TIMER_QUANTUM_NS: u64 = 2_000_000;

// ── Locked profile ────────────────────────────────────────────────────────

/// Locked GPU timer profile.
///
/// Mode-invariant single static (mirrors Module 31's
/// `BatteryApiPolicy::Removed`, Module 35.7's `MediaCapabilitiesPolicy::Locked`,
/// Module 35.10's shared desktop `TouchSurfacePolicy::LockedDesktop`
/// — the v1.23 amiunique-generic cohort unification pattern
/// applied at the GPU domain).
///
/// `static` (not `const`): cohort consumers compare by address
/// (`std::ptr::eq`) to assert the singleton. See
/// `crates/pb-gpu/src/coordinator.rs` for the same pattern on
/// `LOCKED_GPU_LIMITS`.
pub static LOCKED_GPU_TIMER_PROFILE: GpuTimerProfile = GpuTimerProfile {
    label: "devbrowse-gpu-timer-v1",
    quantum_ns: GPU_TIMER_QUANTUM_NS,
};

/// Cohort-locked GPU timer profile shape.
///
/// Mode-invariant in v1. Held as a struct rather than a free
/// constant so a future per-Mode policy hook (unlikely given the
/// L8 lock, but the shape doesn't preclude it) lands without
/// changing the public surface, and so the libxul bridge can
/// pass `&'static GpuTimerProfile` around the way it does with
/// Module 32's `TimerProfile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GpuTimerProfile {
    pub label: &'static str,
    pub quantum_ns: u64,
}

impl GpuTimerProfile {
    /// Floor `raw_ns` to the profile's `quantum_ns`.
    ///
    /// Total + infallible: every `u64` maps to a value `<= raw_ns`
    /// that is divisible by `quantum_ns`. Uses integer division;
    /// no floating-point rounding mode dependency.
    pub const fn quantize_ns(self, raw_ns: u64) -> u64 {
        (raw_ns / self.quantum_ns) * self.quantum_ns
    }
}

// ── Top-level convenience ─────────────────────────────────────────────────

/// Floor `raw_ns` to [`GPU_TIMER_QUANTUM_NS`].
///
/// Equivalent to `LOCKED_GPU_TIMER_PROFILE.quantize_ns(raw_ns)`.
/// Provided as a free function so callsites that already have a
/// raw nanosecond value can quantize without going through a
/// profile handle.
pub const fn quantize_gpu_timer_ns(raw_ns: u64) -> u64 {
    (raw_ns / GPU_TIMER_QUANTUM_NS) * GPU_TIMER_QUANTUM_NS
}

// ── Surface enumeration ───────────────────────────────────────────────────

/// Every GPU pathway that exposes a sub-quantum-resolution
/// timestamp.
///
/// The libxul bridge MUST register [`quantize_gpu_timer_ns`]
/// behind every variant — a missed surface is a sub-quantum side
/// channel even with the rest of the GPU clock locked.
///
/// Most of these variants are *already* gated off at the
/// feature-list / extension-allowlist level by sibling modules
/// (Module 36 `LOCKED_GPU_FEATURES = &[]`, Module 28
/// `LOCKED_WEBGL_PROFILE` 5-extension allowlist). The variants
/// remain here as **defense in depth**: if a future libxul tag
/// bump accidentally re-enables one, Module 39's quantize hook
/// is the last line of defense.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GpuTimerSurface {
    /// WebGPU `GPUQuerySet` of type `'timestamp'` (the
    /// `writeTimestamp` family on the compute / render pass
    /// encoders, then resolved via `queue.resolveQuerySet`).
    /// Locked off by Module 36 (`LOCKED_GPU_FEATURES = &[]`); the
    /// `"timestamp-query"` WebGPU feature is unrequestable.
    WebGpuQuerySetTimestamp,
    /// WebGL `EXT_disjoint_timer_query` / `EXT_disjoint_timer_query_webgl2`
    /// — `getQueryParameter(query, gl.QUERY_RESULT)`. Locked off
    /// by Module 28's 5-extension allowlist.
    WebGlDisjointTimerQuery,
    /// `WebGLSync` `clientWaitSync` returns elapsed wall-clock
    /// time in some implementations (the
    /// `WAIT_FAILED`/`TIMEOUT_EXPIRED`/`CONDITION_SATISFIED`
    /// return path is bounded, but the bridge MUST still
    /// quantize any elapsed-time reading exposed to JS).
    WebGlClientWaitSync,
}

impl GpuTimerSurface {
    /// Exhaustive list. Adding a variant updates `ALL` in the
    /// same edit (per the project's surface-enum convention
    /// shared with Module 26 `WebIdlSurface::ALL`, Module 35.1
    /// `WindowDimensionSurface::ALL`, etc.).
    pub const ALL: &'static [Self] = &[
        Self::WebGpuQuerySetTimestamp,
        Self::WebGlDisjointTimerQuery,
        Self::WebGlClientWaitSync,
    ];
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Quantum value ──────────────────────────────────────────────────

    #[test]
    fn gpu_timer_quantum_is_2_ms() {
        assert_eq!(GPU_TIMER_QUANTUM_NS, 2_000_000);
    }

    #[test]
    fn gpu_timer_quantum_matches_module_32_documentation_value() {
        // CROSS-MODULE REGRESSION (Module 32, pb-fingerprint).
        // pb-gpu Module 39 is the authoritative source of truth
        // for the GPU quantum. pb-fingerprint mirrors the value
        // at `gecko::timers::GPU_QUANTUM_NS` and at
        // `TimerProfile.gpu_quantum_ns` for both
        // STANDARD_TIMER_PROFILE and STRICT_TIMER_PROFILE.
        //
        // L12 forbids pb-gpu from importing pb-fingerprint, so
        // the alignment is enforced by paired literal-value
        // assertions on both sides (mirrors Module 36 ↔ Module
        // 35.6 pattern). Drift in either direction fails CI
        // before merge.
        const MODULE_32_EXPECTED_GPU_QUANTUM_NS: u64 = 2_000_000;
        assert_eq!(GPU_TIMER_QUANTUM_NS, MODULE_32_EXPECTED_GPU_QUANTUM_NS);
    }

    // ── Locked profile ─────────────────────────────────────────────────

    #[test]
    fn locked_profile_carries_the_2ms_quantum() {
        assert_eq!(LOCKED_GPU_TIMER_PROFILE.quantum_ns, GPU_TIMER_QUANTUM_NS);
    }

    #[test]
    fn locked_profile_label_is_versioned() {
        // Cohort consumers may want to detect profile drift via
        // the label. Versioning the label here means a v2
        // profile lands as a new static + a label bump; the
        // amiunique-generic v1.23 cohort base remains stable
        // for v1.
        assert_eq!(LOCKED_GPU_TIMER_PROFILE.label, "devbrowse-gpu-timer-v1");
    }

    #[test]
    fn quantize_through_profile_matches_free_function() {
        // The free function `quantize_gpu_timer_ns` and the
        // profile method `LOCKED_GPU_TIMER_PROFILE.quantize_ns`
        // must return identical values for every input.
        for raw in [0, 1, 999, 1_999_999, 2_000_000, 5_500_500, u64::MAX / 2] {
            assert_eq!(
                quantize_gpu_timer_ns(raw),
                LOCKED_GPU_TIMER_PROFILE.quantize_ns(raw),
                "free fn and profile method must agree for raw={raw}"
            );
        }
    }

    // ── Quantize behavior ──────────────────────────────────────────────

    #[test]
    fn quantize_zero_is_zero() {
        assert_eq!(quantize_gpu_timer_ns(0), 0);
    }

    #[test]
    fn quantize_below_quantum_floors_to_zero() {
        // 1_999_999 ns < 2_000_000 ns ⇒ floors to 0.
        assert_eq!(quantize_gpu_timer_ns(1), 0);
        assert_eq!(quantize_gpu_timer_ns(999_999), 0);
        assert_eq!(quantize_gpu_timer_ns(1_999_999), 0);
    }

    #[test]
    fn quantize_at_exact_boundary_is_boundary() {
        assert_eq!(quantize_gpu_timer_ns(2_000_000), 2_000_000);
        assert_eq!(quantize_gpu_timer_ns(4_000_000), 4_000_000);
        assert_eq!(quantize_gpu_timer_ns(20_000_000), 20_000_000);
    }

    #[test]
    fn quantize_just_below_next_boundary_floors_down() {
        assert_eq!(quantize_gpu_timer_ns(2_000_001), 2_000_000);
        assert_eq!(quantize_gpu_timer_ns(3_999_999), 2_000_000);
        assert_eq!(quantize_gpu_timer_ns(5_999_999), 4_000_000);
    }

    #[test]
    fn quantize_large_values_dont_overflow() {
        // Floor of u64::MAX is the largest multiple of 2_000_000
        // that fits in a u64. The arithmetic must not overflow.
        let large = u64::MAX;
        let q = quantize_gpu_timer_ns(large);
        assert!(q <= large);
        assert_eq!(q % GPU_TIMER_QUANTUM_NS, 0);
    }

    #[test]
    fn quantize_output_is_always_a_multiple_of_the_quantum() {
        for raw in [
            0,
            1,
            999,
            2_000_000,
            2_500_500,
            123_456_789,
            999_999_999_999,
        ] {
            let q = quantize_gpu_timer_ns(raw);
            assert_eq!(q % GPU_TIMER_QUANTUM_NS, 0, "raw={raw} produced q={q}");
            assert!(q <= raw, "raw={raw} produced q={q} > raw");
        }
    }

    // ── Mode invariance ────────────────────────────────────────────────

    #[test]
    fn quantize_is_mode_invariant() {
        // The function signature takes no Mode parameter; that
        // IS the mode invariance. This test pins the contract
        // structurally — adding a Mode parameter to either
        // function or the profile breaks the build.
        let raw = 12_345_678;
        let direct = quantize_gpu_timer_ns(raw);
        let via_profile = LOCKED_GPU_TIMER_PROFILE.quantize_ns(raw);
        assert_eq!(direct, via_profile);
        // The locked profile is a single static — there is no
        // STANDARD_GPU_TIMER_PROFILE or STRICT_GPU_TIMER_PROFILE.
        // (Module 31 Battery and Module 35.7 MediaCapabilities
        // use the same mode-invariant single-static pattern.)
    }

    // ── Surface enumeration ────────────────────────────────────────────

    #[test]
    fn surface_all_lists_every_variant() {
        // Exhaustive count: every variant of GpuTimerSurface
        // is in ALL. If a future variant is added to the enum
        // without also being added to ALL, the libxul bridge
        // misses a quantization hook.
        assert_eq!(GpuTimerSurface::ALL.len(), 3);
        assert!(GpuTimerSurface::ALL.contains(&GpuTimerSurface::WebGpuQuerySetTimestamp));
        assert!(GpuTimerSurface::ALL.contains(&GpuTimerSurface::WebGlDisjointTimerQuery));
        assert!(GpuTimerSurface::ALL.contains(&GpuTimerSurface::WebGlClientWaitSync));
    }

    #[test]
    fn surface_all_has_no_duplicates() {
        use std::collections::HashSet;
        let set: HashSet<_> = GpuTimerSurface::ALL.iter().copied().collect();
        assert_eq!(set.len(), GpuTimerSurface::ALL.len());
    }

    // ── Send + Sync ────────────────────────────────────────────────────

    #[test]
    fn types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GpuTimerProfile>();
        assert_send_sync::<GpuTimerSurface>();
    }
}
