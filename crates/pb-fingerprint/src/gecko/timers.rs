//! Module 32 — Timer quantization.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the high-resolution
//!     clock backing `performance.now()` is intercepted below the JS
//!     surface so worker / iframe / service-worker `performance`
//!     objects share a single quantum. GPU timestamps (`pb-gpu` /
//!     Module 36-39) stay at 2 ms in both modes regardless of the
//!     JS quantum.
//!   * **L9 / §3.3 / §3.2** — *both* modes quantize, with different
//!     quanta (locked v1.11 §5.5 matrix + L43):
//!       * **Standard** — 1 ms (`STANDARD_TIMER_PROFILE`; the §5.5
//!         floor; defeats sub-ms timing channels that are already
//!         off the table for site-perf reasons).
//!       * **Strict** — 100 ms (`STRICT_TIMER_PROFILE`; matches Tor
//!         Browser RFP; Phase 5.5 Module 35.2 enforces non-loosen-
//!         ability via L41).
//!   * **L41 / L43** — the 100 ms Strict quantum is non-loosenable
//!     by user settings; Phase 5.5 Module 35.2 wraps Module 32's
//!     hook with the L41 enforcement layer.
//!   * **§5.5** — central fingerprint bucketing: every JS-observable
//!     clock surface routes through one `TimerProfile`.
//!   * **threat-model A1 / N6 (partial)** — sub-ms clocks are the
//!     foundation of timing-side-channel attacks (Spectre,
//!     cache-occupancy probes) AND a high-entropy passive
//!     fingerprint (CPU clock skew, JIT warm-up cost, micro-arch
//!     hints). Quantization addresses both classes; the 100 ms
//!     floor in Strict is the Tor Browser RFP-grade defense.
//!
//! ## Locked decision (phase-5 Goal + §5.5 matrix v1.11 + L43)
//!
//! **Both modes quantize through the same mechanism, only the value
//! differs.** Unlike Module 30 fonts (where Standard buckets and
//! Strict allowlists are different mechanisms) or Module 27 / 28 /
//! 29 (Strict-only), Module 32 ships a single `Quantized(...)`
//! policy variant whose payload is the per-Mode profile. A future
//! "NativePassThrough" variant (e.g. for a Tor-style "extension
//! relaxed timer" carve-out) would be a second variant; the bridge
//! MUST exhaustively match so a future variant cannot silently
//! fall through to the wrong arm.
//!
//! ## Same-microtask correlation
//!
//! The quantization function floors to the previous multiple of the
//! quantum (`(now_ns / Q) * Q`). This guarantees two `performance.now()`
//! reads in the same microtask, sampled within the same Q-ns
//! window, return the **same** value. Rounding to nearest would
//! leak the sub-quantum delta on the boundary; rounding up would
//! break the monotonic-non-decreasing contract of the spec. Floor
//! preserves both.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * `STANDARD_TIMER_PROFILE` + `STRICT_TIMER_PROFILE` statics
//!     carrying the per-Mode JS quantum + the mode-invariant GPU
//!     quantum (2 ms; the pb-gpu lock the L8 invariant refers to).
//!   * `TimerProfile::quantize_js_ns` + `quantize_gpu_ns` helpers
//!     that the libxul-side clock interceptor uses to round every
//!     `performance.now()` / `Date.now()` / event timestamp / rAF
//!     timestamp / PerformanceObserver entry timestamp to the
//!     applicable quantum.
//!   * `TimerSurface::ALL`: every JS pathway the bridge must wire.
//!   * A `FingerprintOverride` impl for `WebIdlSurface::Timers` so
//!     the libxul bridge has a single registration point under both
//!     modes; the policy carries the per-Mode profile choice.
//!
//! It IS NOT:
//!   * The actual JS-side rounding. Module 1 (libxul tag) patches
//!     `nsRFPService::ReduceTimePrecisionAsMSecs` (or its
//!     equivalent in the current libxul tag) to call into
//!     `TimerProfile::quantize_js_ns`. This module pins the
//!     contract.
//!   * The Phase 5.5 Module 35.2 L41-enforcement layer that asserts
//!     no settings path can loosen the Strict 100 ms quantum
//!     (including a hostile pb-config write or a recovered backup
//!     with a tampered config blob). Module 32 ships the per-Mode
//!     floor; Module 35.2 ships the lock.
//
// TODO(Module 1 / libxul): the clock interceptor lands alongside
//   the libxul tag. Wire `nsRFPService::ReduceTimePrecisionAsMSecs`
//   (and the analogous nanosecond-precision entry points the
//   current libxul tag exposes) to call into
//   `TimerProfile::quantize_js_ns` for the renderer's current Mode.
//   The worker / service-worker / shared-worker performance objects
//   each get their own clock; the FFI registration must reach every
//   JsContext::ALL variant.
// TODO(Module 36-39 / pb-gpu): the 2 ms GPU quantum is pb-gpu's
//   lock per L8; Module 32 carries `gpu_quantum_ns` in the profile
//   as documentation only. pb-gpu MUST NOT consult this struct;
//   instead it reads its own constant and the cross-check happens
//   in a Phase 6 integration test asserting the two values are
//   equal.
// TODO(Phase 5.5 / Module 35.2): the L41-enforcement layer reads
//   `STRICT_TIMER_PROFILE.js_quantum_ns` and asserts that no
//   settings path can produce a smaller quantum for Strict-mode
//   renderers. Module 35.2 also handles `requestAnimationFrame`
//   jitter bounding (the rAF callback timestamp argument is
//   covered by `TimerSurface::RequestAnimationFrameTimestamp`
//   here; Module 35.2 layers the L43-mandated bounded async jitter
//   on top).
// TODO(Module 29 / audio + Module 30 / fonts cross-coupling): the
//   audio.rs / fonts.rs modules reference Module 32's timer
//   quantization for two specific cases: (a) `performance.now()`
//   reads during `OfflineAudioContext` rendering (Module 29 pins
//   only the audio buffer values; the timer reads go through
//   Module 32); (b) `FontFaceSet.ready` callback latency (Module
//   30 flagged this as needing latency quantization; Strict's
//   100 ms floor absorbs sub-100ms enumeration deltas, Standard
//   inherits the 1 ms floor which is below the enumeration-count
//   delta and would require an additional per-callback quantizer
//   from a future module).
// TODO(Phase 10 / Module 71+): the CreepJS / FPStandard timer
//   probes will measure `performance.now()` resolution under both
//   modes and assert (a) Strict reports a quantum >= 100 ms and
//   (b) Standard reports a quantum >= 1 ms. Same-microtask
//   correlation tests will assert two reads in the same
//   microtask return identical quantized values.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked timer profiles (per-Mode cohort) ───────────────────────────────

/// Cohort-locked timer quantization parameters.
///
/// `Copy` + `Eq` + `Hash` because every field is `u64` / `&'static
/// str` and the address-identity invariant is asserted via
/// `std::ptr::eq` against the matching mode's `*_TIMER_PROFILE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerProfile {
    /// Stable label for the per-Mode profile version. Bumped via
    /// the Adaptation protocol on any quantum change.
    pub label: &'static str,
    /// Quantum in nanoseconds applied to every JS-observable clock
    /// read (`Date.now`, `performance.now`, event timestamps, rAF
    /// timestamps, PerformanceObserver entries). Floor-rounded:
    /// `quantize_js_ns(t) == (t / js_quantum_ns) * js_quantum_ns`.
    pub js_quantum_ns: u64,
    /// Quantum in nanoseconds applied to GPU-side timestamps
    /// (pb-gpu's lock per L8). Carried here for documentation only;
    /// pb-gpu reads its own constant and a Phase 6 integration test
    /// asserts equality. **Mode-invariant: 2 ms in both Standard
    /// and Strict.**
    pub gpu_quantum_ns: u64,
}

impl TimerProfile {
    /// Floor-round a nanosecond timestamp to the JS quantum.
    ///
    /// Floor (not nearest, not ceiling) preserves both the
    /// same-microtask correlation invariant (two reads within a
    /// Q-ns window return the same value) AND the
    /// monotonic-non-decreasing contract of `performance.now()`.
    /// Rounding to nearest would leak the sub-quantum delta on
    /// the boundary; rounding up would let two reads in the same
    /// microtask both advance by Q.
    ///
    /// `u64` saturates at the constant 0 floor; the libxul side
    /// MUST pass non-negative monotonic ns since clock origin.
    pub fn quantize_js_ns(&self, now_ns: u64) -> u64 {
        (now_ns / self.js_quantum_ns) * self.js_quantum_ns
    }

    /// Floor-round a nanosecond timestamp to the GPU quantum.
    /// Documentation-only helper; pb-gpu does its own rounding.
    pub fn quantize_gpu_ns(&self, now_ns: u64) -> u64 {
        (now_ns / self.gpu_quantum_ns) * self.gpu_quantum_ns
    }
}

/// Mode-invariant GPU quantum: 2 ms. Pulled out as a `pub const`
/// so the value is visible in a single place and the two profile
/// statics can reference it without diverging.
pub const GPU_QUANTUM_NS: u64 = 2_000_000;

/// Standard-mode profile. 1 ms JS quantum (the §5.5 floor); the
/// §5.5 matrix has carried this value since v1.0.
///
/// `static` (not `const`): cohort consumers (libxul clock
/// interceptor + Phase 5.5 Module 35.2) compare by address
/// (`ptr::eq`). See canvas.rs / fonts.rs for the rationale.
pub static STANDARD_TIMER_PROFILE: TimerProfile = TimerProfile {
    label: "devbrowse-timer-standard-v1",
    js_quantum_ns: 1_000_000,
    gpu_quantum_ns: GPU_QUANTUM_NS,
};

/// Strict-mode profile. 100 ms JS quantum (Tor Browser RFP parity;
/// L43); the matrix has carried this value since v1.11 alongside
/// the L43 invariant.
pub static STRICT_TIMER_PROFILE: TimerProfile = TimerProfile {
    label: "devbrowse-timer-strict-v1",
    js_quantum_ns: 100_000_000,
    gpu_quantum_ns: GPU_QUANTUM_NS,
};

// ── Per-mode quantization policy ──────────────────────────────────────────

/// Per-mode timer quantization policy.
///
/// Both modes quantize through the same mechanism (`Quantized`
/// variant); only the profile payload differs. This shape is
/// intentional: a future "Disabled" or "PerSurfaceCarveOut"
/// posture lands as a new variant and the bridge's exhaustive
/// match traps the addition.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerQuantizationPolicy {
    /// Quantize every JS clock surface to the referenced profile's
    /// `js_quantum_ns`. Both `Mode::Standard` and `Mode::Strict`
    /// map to this variant in v1; the profile differentiates the
    /// cohort.
    Quantized(&'static TimerProfile),
}

impl TimerQuantizationPolicy {
    /// Locked snapshot for `mode`:
    ///   * `Mode::Standard` -> `Quantized(&STANDARD_TIMER_PROFILE)`
    ///   * `Mode::Strict`   -> `Quantized(&STRICT_TIMER_PROFILE)`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::Quantized(&STANDARD_TIMER_PROFILE),
            Mode::Strict => Self::Quantized(&STRICT_TIMER_PROFILE),
        }
    }

    /// The profile this policy is quantizing through.
    pub fn profile(&self) -> &'static TimerProfile {
        match *self {
            Self::Quantized(p) => p,
        }
    }
}

// ── Surface enumeration ───────────────────────────────────────────────────

/// Every JS pathway that exposes a high-resolution timestamp.
///
/// The libxul bridge MUST register the quantization hook behind
/// every variant — a missed surface is a sub-quantum side channel
/// in Strict, even with `performance.now()` itself locked.
/// PerformanceObserver is one variant covering all `PerformanceEntry`
/// subtypes (Resource / Navigation / Paint / Mark / Measure) because
/// the observer dispatch path is one libxul function call site;
/// adding a per-subtype variant would force the bridge to register
/// the same hook six times.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerSurface {
    /// `Date.now()` — wall-clock milliseconds (Unix epoch). Already
    /// nominally ms-precise but Gecko exposes a higher-resolution
    /// internal source in some code paths; the quantizer ensures
    /// the returned value matches the JS quantum exactly.
    DateNow,
    /// `performance.now()` — monotonic high-resolution timer since
    /// `timeOrigin`. The primary timing-side-channel attack target.
    PerformanceNow,
    /// `performance.timeOrigin` — the high-res Unix-epoch anchor
    /// for `performance.now()`. Quantized so the (timeOrigin + now)
    /// composition does not leak sub-quantum entropy.
    PerformanceTimeOrigin,
    /// `performance.timing` — legacy Navigation Timing object with
    /// per-phase `domainLookupStart` / `connectStart` / etc.
    /// timestamps. Deprecated by `PerformanceObserver` but still
    /// exposed; quantized for backward compatibility coverage.
    PerformanceTiming,
    /// `PerformanceObserver` entries (Resource Timing / Navigation
    /// Timing / Paint Timing / User Timing / Long Task / Event
    /// Timing). One variant because the libxul-side observer
    /// dispatch path is one function; the quantizer rounds every
    /// timestamp on every entry before the callback fires.
    PerformanceObserverEntry,
    /// `requestAnimationFrame` callback receives a high-res
    /// `DOMHighResTimeStamp` argument. Quantized so the rAF
    /// cadence does not leak per-host vsync timing. Phase 5.5
    /// Module 35.2 layers async-jitter bounding on top in Strict.
    RequestAnimationFrameTimestamp,
    /// `Event.timeStamp` — every DOM event carries a
    /// `DOMHighResTimeStamp`. Mouse / pointer / wheel / scroll /
    /// touch events are particularly leaky because rapid sequences
    /// expose sub-quantum inter-event deltas.
    EventTimeStamp,
}

impl TimerSurface {
    /// Every surface the bridge must wire. Asserted against the
    /// phase-file edge-case list by
    /// `tests::timer_surface_all_covers_edge_cases`.
    pub const ALL: &'static [TimerSurface] = &[
        Self::DateNow,
        Self::PerformanceNow,
        Self::PerformanceTimeOrigin,
        Self::PerformanceTiming,
        Self::PerformanceObserverEntry,
        Self::RequestAnimationFrameTimestamp,
        Self::EventTimeStamp,
    ];
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Timers`.
///
/// Construct with `TimerOverride::new(mode)` so the policy is
/// resolved once at construction; the override is then registered
/// by the libxul bridge into every `JsContext` for the renderer.
///
/// Both modes carry an active policy (`Quantized(...)`); `install`
/// is still a no-op pending the libxul clock interceptor. Once
/// wired, the interceptor consults `policy().profile()` on every
/// timer read.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data, so `install(&OverrideContext)`
/// produces observationally identical state regardless of
/// `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct TimerOverride {
    policy: TimerQuantizationPolicy,
}

impl TimerOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: TimerQuantizationPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> TimerQuantizationPolicy {
        self.policy
    }

    /// The profile carrying this override's quantum values.
    /// Useful for the libxul interceptor and for cross-module
    /// tests that need to assert the cohort lock.
    pub fn profile(&self) -> &'static TimerProfile {
        self.policy.profile()
    }
}

impl FingerprintOverride for TimerOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Timers
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul clock interceptor is not
        // yet wired (see crate-level TODO). When the FFI lands,
        // both modes register a callback that calls
        // `self.profile().quantize_js_ns(...)` on every timer read
        // for every `TimerSurface::ALL` × `JsContext::ALL` plumb-in.
        let _ = (self.policy, JsContext::ALL);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_profile_locks_1ms_js_quantum() {
        // §5.5 floor (since v1.0). Any change is a cohort shift
        // through the Adaptation protocol.
        assert_eq!(STANDARD_TIMER_PROFILE.label, "devbrowse-timer-standard-v1");
        assert_eq!(STANDARD_TIMER_PROFILE.js_quantum_ns, 1_000_000);
    }

    #[test]
    fn strict_profile_locks_100ms_js_quantum() {
        // L43 Tor Browser RFP parity (since v1.11). Phase 5.5
        // Module 35.2 enforces non-loosenability per L41.
        assert_eq!(STRICT_TIMER_PROFILE.label, "devbrowse-timer-strict-v1");
        assert_eq!(STRICT_TIMER_PROFILE.js_quantum_ns, 100_000_000);
    }

    #[test]
    fn gpu_quantum_is_2ms_in_both_modes() {
        // L8 lock: GPU timestamps stay at 2 ms regardless of Mode.
        // pb-gpu is the authoritative source; this is documentation.
        assert_eq!(GPU_QUANTUM_NS, 2_000_000);
        assert_eq!(STANDARD_TIMER_PROFILE.gpu_quantum_ns, GPU_QUANTUM_NS);
        assert_eq!(STRICT_TIMER_PROFILE.gpu_quantum_ns, GPU_QUANTUM_NS);
    }

    #[test]
    fn for_mode_returns_correct_singleton() {
        let s = TimerQuantizationPolicy::for_mode(Mode::Standard);
        let r = TimerQuantizationPolicy::for_mode(Mode::Strict);
        // Address identity: every renderer of the same Mode reads
        // the same singleton.
        assert!(std::ptr::eq(s.profile(), &STANDARD_TIMER_PROFILE));
        assert!(std::ptr::eq(r.profile(), &STRICT_TIMER_PROFILE));
        // Cross-Mode sanity: profiles differ, so pointer
        // comparisons across modes are NOT equal.
        assert!(!std::ptr::eq(s.profile(), r.profile()));
    }

    #[test]
    fn quantize_js_ns_floors_to_quantum() {
        let s = &STANDARD_TIMER_PROFILE;
        let r = &STRICT_TIMER_PROFILE;
        // Standard 1 ms = 1_000_000 ns
        assert_eq!(s.quantize_js_ns(0), 0);
        assert_eq!(s.quantize_js_ns(999_999), 0);
        assert_eq!(s.quantize_js_ns(1_000_000), 1_000_000);
        assert_eq!(s.quantize_js_ns(1_999_999), 1_000_000);
        assert_eq!(s.quantize_js_ns(2_500_500), 2_000_000);
        // Strict 100 ms = 100_000_000 ns
        assert_eq!(r.quantize_js_ns(0), 0);
        assert_eq!(r.quantize_js_ns(99_999_999), 0);
        assert_eq!(r.quantize_js_ns(100_000_000), 100_000_000);
        assert_eq!(r.quantize_js_ns(199_999_999), 100_000_000);
        assert_eq!(r.quantize_js_ns(550_000_000), 500_000_000);
    }

    #[test]
    fn quantize_preserves_same_microtask_correlation() {
        // Two reads at t and t+δ where δ < quantum MUST return the
        // same value (otherwise the sub-quantum delta is observable
        // as the canonical timing side-channel). Floor rounding is
        // the mechanism.
        let s = &STANDARD_TIMER_PROFILE;
        let r = &STRICT_TIMER_PROFILE;

        let t_standard = 5_000_500_u64; // 5.0005 ms
        assert_eq!(
            s.quantize_js_ns(t_standard),
            s.quantize_js_ns(t_standard + 100), // +100 ns < 1 ms
        );

        let t_strict = 210_000_000_u64; // 210 ms — inside the [200, 300) ms quantum
        assert_eq!(
            r.quantize_js_ns(t_strict),
            r.quantize_js_ns(t_strict + 50_000_000), // 260 ms still inside [200, 300)
        );

        // And conversely: a step across a quantum boundary MUST
        // advance. Without this, `performance.now()` would not be
        // monotonic-strictly-increasing across timer-fire cycles.
        let just_under = 99_999_999_u64;
        let just_over = 100_000_000_u64;
        assert!(r.quantize_js_ns(just_over) > r.quantize_js_ns(just_under));
    }

    #[test]
    fn quantize_gpu_ns_floors_to_gpu_quantum() {
        let s = &STANDARD_TIMER_PROFILE;
        // 2 ms = 2_000_000 ns
        assert_eq!(s.quantize_gpu_ns(0), 0);
        assert_eq!(s.quantize_gpu_ns(1_999_999), 0);
        assert_eq!(s.quantize_gpu_ns(2_000_000), 2_000_000);
        assert_eq!(s.quantize_gpu_ns(3_500_000), 2_000_000);
        assert_eq!(s.quantize_gpu_ns(4_000_000), 4_000_000);
    }

    #[test]
    fn timer_surface_all_covers_edge_cases() {
        // Phase-file edge cases for Module 32:
        //   - worker-context performance object (context-inert
        //     obligation covers this; not a separate variant)
        //   - PerformanceObserver entries (PerformanceObserverEntry)
        //   - Resource Timing API entries (subsumed under
        //     PerformanceObserverEntry; the dispatch path is shared)
        //   - same-microtask correlation (a property of the
        //     quantize function, asserted in its own test)
        // Plus the entry-point timestamps (Date.now /
        // performance.now / timeOrigin / performance.timing) and
        // the event / rAF timestamps that route through the same
        // clock.
        assert_eq!(TimerSurface::ALL.len(), 7);
        for v in [
            TimerSurface::DateNow,
            TimerSurface::PerformanceNow,
            TimerSurface::PerformanceTimeOrigin,
            TimerSurface::PerformanceTiming,
            TimerSurface::PerformanceObserverEntry,
            TimerSurface::RequestAnimationFrameTimestamp,
            TimerSurface::EventTimeStamp,
        ] {
            assert!(TimerSurface::ALL.contains(&v), "missing surface: {:?}", v);
        }
    }

    #[test]
    fn timer_override_reports_timers_surface_under_both_modes() {
        assert_eq!(
            TimerOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Timers
        );
        assert_eq!(
            TimerOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Timers
        );
    }

    #[test]
    fn standard_and_strict_overrides_carry_distinct_profiles() {
        let standard = TimerOverride::new(Mode::Standard);
        let strict = TimerOverride::new(Mode::Strict);
        assert!(std::ptr::eq(standard.profile(), &STANDARD_TIMER_PROFILE));
        assert!(std::ptr::eq(strict.profile(), &STRICT_TIMER_PROFILE));
        // The two profiles are NOT the same singleton — the
        // per-Mode cohort lock requires divergence.
        assert!(!std::ptr::eq(standard.profile(), strict.profile()));
        // And the JS quanta differ by 100x.
        assert_eq!(
            strict.profile().js_quantum_ns,
            standard.profile().js_quantum_ns * 100,
        );
    }

    #[test]
    fn timer_override_install_is_context_inert() {
        // Edge case: override must be inert in iframe / worker /
        // service-worker / dedicated-worker. The worker-context
        // performance object is the phase-file edge case here;
        // the context-inert trait obligation closes it.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000032").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = TimerOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Timers);
        }
    }

    #[test]
    fn timer_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TimerOverride>();
        assert_send_sync::<TimerQuantizationPolicy>();
        assert_send_sync::<TimerProfile>();
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: TimerSurface) -> &'static str {
            match s {
                TimerSurface::DateNow => "date-now",
                TimerSurface::PerformanceNow => "performance-now",
                TimerSurface::PerformanceTimeOrigin => "performance-time-origin",
                TimerSurface::PerformanceTiming => "performance-timing",
                TimerSurface::PerformanceObserverEntry => "performance-observer-entry",
                TimerSurface::RequestAnimationFrameTimestamp => "request-animation-frame-timestamp",
                TimerSurface::EventTimeStamp => "event-time-stamp",
            }
        }
        for s in TimerSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: TimerQuantizationPolicy) -> &'static str {
            match p {
                TimerQuantizationPolicy::Quantized(_) => "quantized",
            }
        }
        assert_eq!(
            arm(TimerQuantizationPolicy::for_mode(Mode::Standard)),
            "quantized"
        );
        assert_eq!(
            arm(TimerQuantizationPolicy::for_mode(Mode::Strict)),
            "quantized"
        );
    }
}
