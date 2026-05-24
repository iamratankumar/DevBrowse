//! Module 35.2 — Strict-mode timer quantization (L41 + L43 layer).
//!
//! Module 32 (`gecko::timers`) is the single source of truth for the
//! per-Mode JS quantum and the floor-rounding mechanism:
//!
//!   * `STANDARD_TIMER_PROFILE.js_quantum_ns = 1_000_000` (1 ms,
//!     §5.5 floor since v1.0).
//!   * `STRICT_TIMER_PROFILE.js_quantum_ns = 100_000_000` (100 ms,
//!     L43 Tor Browser RFP parity since v1.11).
//!   * `TimerProfile::quantize_js_ns(u64) -> u64` floor-rounds clock
//!     reads in nanoseconds.
//!   * `TimerProfile::quantize_js_ms(f64) -> f64` (added by Module
//!     35.2 to Module 32's natural home) floor-rounds clock reads in
//!     `DOMHighResTimeStamp` form; delegates to the ns version so
//!     the two surfaces agree by construction.
//!   * `TimerQuantizationPolicy::for_mode(mode) -> Self` is the
//!     per-Mode locked-singleton resolver. No `with_user_override`
//!     constructor exists.
//!
//! Module 35.2 does NOT ship a parallel `TimerQuantum` enum or a
//! second `quantize_*` function — two sources of truth for the same
//! per-Mode quantum is exactly how cohort drift is introduced.
//! Instead, Module 35.2 ships ONLY the layer over Module 32 that the
//! phase file calls out:
//!
//!   1. **`AsyncEventClass`** — the six async-event SCHEDULING
//!      surfaces (Module 32's `TimerSurface` covers clock READS;
//!      Module 35.2's `AsyncEventClass` covers event FIRE). The
//!      libxul bridge consults this enum at every scheduling site
//!      and floor-rounds the observable arrival time through
//!      `TimerProfile::quantize_js_ms`. By construction the FIRE
//!      pathway equals the READ pathway, so a clock read inside a
//!      fired callback returns the same value as the bounded
//!      arrival — closing the `(arrival, now())` side channel.
//!      Cross-coupling: `RequestIdleCallback` (FIRE) pairs with
//!      Module 32's `TimerSurface::IdleDeadlineTimeRemaining`
//!      (READ); both must be wired in lockstep so the residual-
//!      time argument inside the callback respects the same
//!      quantum as the callback fire.
//!   2. **L41 idempotence assertion** — the structural lock already
//!      lives in Module 32 (`TimerQuantizationPolicy::for_mode` has
//!      no `with_user_override` constructor). This module ships the
//!      regression test that catches a future loosening of that
//!      structural lock alongside any Phase 5.5 work that touches
//!      `gecko::timers`.
//!
//! Architecture references:
//!   * **L41** — Strict-mode settings lock; no user setting can
//!     lower the Strict 100 ms quantum. Structural in Module 32's
//!     API; Module 35.4 ships the broader cross-crate audit.
//!   * **L43** — Timer quantization (Strict 100 ms / Standard 1 ms;
//!     GPU mode-invariant 2 ms via pb-gpu).
//!   * **§5.5** — central fingerprint bucketing.
//!   * **threat-model A1 / N6 (partial)** — sub-quantum clock + event
//!     arrival times are the canonical timing side-channel; the
//!     async-jitter bound closes the second leak even when
//!     `performance.now()` itself is already quantized.
//
// Module 35.4 (settings-lock audit) has shipped: the conformance
//   tests in `strict/settings_lock.rs` walk every settings-
//   consuming site in pb-fingerprint / pb-network / pb-extensions
//   and assert no path can produce a smaller Strict quantum. Module
//   35.2's regression test covers `TimerQuantizationPolicy::for_mode`
//   idempotence; the audit extends coverage to call sites.
// TODO(libxul FFI async-event bridge — pb-browser Phase 11 /
//   Module 80; verified by Module 69 in Phase 9): the FFI hook
//   lands alongside the libxul tag. setTimeout / setInterval
//   scheduling
//   goes through `nsGlobalWindowInner::SetTimeoutOrInterval`; rAF
//   callbacks go through `nsRefreshDriver`; postMessage delivery
//   goes through `PostMessageEvent`; Promise.then microtasks drain
//   through the microtask queue. Each site bounds the observable
//   arrival via `TimerQuantizationPolicy::for_mode(ctx.mode())
//   .profile().quantize_js_ms(scheduled_ms)`. Actual fire is
//   permitted at any time >= the bounded arrival per spec.
// TODO(Phase 10 / Module 71+): live-renderer probes assert
//   setTimeout / rAF / postMessage / microtask / idle-callback /
//   broadcast-channel deltas in Strict land on 100 ms boundaries.
//   `AsyncEventClass::ALL` is the plumbing list the bridge
//   iterates; Phase 10 verifies behavior.
// Module 35.3 (L44 disabled APIs) SAB carry-forward has shipped:
//   SharedArrayBuffer + Atomics.wait is a wholly separate cross-
//   thread timer that bypasses every quantizer in Module 32 +
//   Module 35.2 (the historical Spectre "spreader" attack vector).
//   The lock landed as `DisabledApi::SharedMemoryAndAtomics` in
//   Module 35.3's enum (with the `SpecialCase` mechanism so the
//   `Atomics` namespace itself stays defined while `wait` /
//   `notify` throw as method calls). This is API-disabling rather
//   than quantization; Module 35.2 does not
//   itself defend against this channel — quantization alone is
//   insufficient.

// ── Async-event scheduling surfaces ──────────────────────────────────────

/// Every async-event scheduling pathway whose observable arrival
/// time the libxul bridge MUST bound to a quantum boundary via
/// `TimerProfile::quantize_js_ms`.
///
/// Grouping rule: surfaces that share a single libxul scheduling
/// site are one variant. `setTimeout` and `setInterval` share
/// `nsGlobalWindowInner::SetTimeoutOrInterval`; `Promise.then` and
/// `queueMicrotask` share the microtask queue drain.
///
/// The libxul bridge MUST register the bound-arrival hook behind
/// every variant — a missed surface is a Strict-mode sub-quantum
/// side channel (the adversary correlates inter-event deltas
/// against a real high-resolution clock the bridge forgot to
/// bound, even with `performance.now()` already locked).
///
/// Cross-coupling note: `requestIdleCallback` ships TWO surfaces —
/// the callback FIRE timing here (`RequestIdleCallback`) and the
/// `IdleDeadline.timeRemaining()` READ inside the callback
/// (Module 32 `TimerSurface::IdleDeadlineTimeRemaining`). Both
/// must be wired in lockstep or the residual-time return value
/// becomes the real-clock leak the bound-arrival surface tried to
/// close.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsyncEventClass {
    /// `setTimeout(fn, delay)` and `setInterval(fn, delay)` — same
    /// libxul scheduling site.
    SetTimeoutSetInterval,
    /// `requestAnimationFrame(callback)` — the callback's
    /// `DOMHighResTimeStamp` argument is bounded to the quantum
    /// boundary so per-host vsync timing does not leak.
    RequestAnimationFrameCallback,
    /// `MessageChannel.postMessage` cross-realm delivery and
    /// `Window.postMessage` same-/cross-origin delivery.
    MessageChannelPostMessage,
    /// `Promise.then` continuation and `queueMicrotask` — both
    /// drain through the microtask queue.
    PromiseMicrotask,
    /// `requestIdleCallback(callback)` — fires when the browser is
    /// idle. Two surfaces: this variant covers the FIRE side (the
    /// callback's invocation timing); the READ side
    /// (`IdleDeadline.timeRemaining()`) lives in Module 32's
    /// `TimerSurface::IdleDeadlineTimeRemaining` so the residual-
    /// time argument floors through the same quantum. Both MUST be
    /// wired in lockstep.
    RequestIdleCallback,
    /// `BroadcastChannel.onmessage` arrival timing — distinct from
    /// `MessageChannel` because the cross-document broadcast goes
    /// through a different libxul dispatch site
    /// (`BroadcastChannelService`). Without a separate bound-
    /// arrival hook here, cross-tab broadcasts inside one identity
    /// profile leak inter-tab clock deltas.
    BroadcastChannelOnMessage,
}

impl AsyncEventClass {
    /// Every async-event surface the bridge must wire.
    pub const ALL: &'static [AsyncEventClass] = &[
        Self::SetTimeoutSetInterval,
        Self::RequestAnimationFrameCallback,
        Self::MessageChannelPostMessage,
        Self::PromiseMicrotask,
        Self::RequestIdleCallback,
        Self::BroadcastChannelOnMessage,
    ];
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gecko::timers::{
        TimerQuantizationPolicy, STANDARD_TIMER_PROFILE, STRICT_TIMER_PROFILE,
    };
    use pb_config::Mode;

    #[test]
    fn async_event_class_all_enumerates_every_scheduling_surface() {
        // Phase-file subtask 4 (extended after the v1.23 surface
        // audit): setTimeout, requestAnimationFrame,
        // MessageChannel.postMessage, Promise.then microtask
        // ordering, requestIdleCallback, BroadcastChannel.
        // Grouping rule applied: setTimeout + setInterval share
        // one scheduling site (one variant); Promise.then +
        // queueMicrotask share the microtask queue (one variant).
        // BroadcastChannel kept separate from MessageChannel
        // because the libxul dispatch site is different.
        // requestIdleCallback added because IdleDeadline.timeRemaining
        // is its own clock surface (paired with Module 32's
        // TimerSurface::IdleDeadlineTimeRemaining).
        assert_eq!(AsyncEventClass::ALL.len(), 6);
        for v in [
            AsyncEventClass::SetTimeoutSetInterval,
            AsyncEventClass::RequestAnimationFrameCallback,
            AsyncEventClass::MessageChannelPostMessage,
            AsyncEventClass::PromiseMicrotask,
            AsyncEventClass::RequestIdleCallback,
            AsyncEventClass::BroadcastChannelOnMessage,
        ] {
            assert!(
                AsyncEventClass::ALL.contains(&v),
                "missing async event class: {:?}",
                v,
            );
        }
    }

    #[test]
    fn async_class_dispatch_is_exhaustive_friendly() {
        // The libxul bridge matches AsyncEventClass to look up the
        // right scheduling hook. Exhaustive match (no `_` arm)
        // catches a future variant addition at compile time.
        fn route(c: AsyncEventClass) -> &'static str {
            match c {
                AsyncEventClass::SetTimeoutSetInterval => "settimeout-setinterval",
                AsyncEventClass::RequestAnimationFrameCallback => "raf-callback",
                AsyncEventClass::MessageChannelPostMessage => "messagechannel-postmessage",
                AsyncEventClass::PromiseMicrotask => "promise-microtask",
                AsyncEventClass::RequestIdleCallback => "request-idle-callback",
                AsyncEventClass::BroadcastChannelOnMessage => "broadcastchannel-onmessage",
            }
        }
        for c in AsyncEventClass::ALL {
            assert!(!route(*c).is_empty());
        }
    }

    #[test]
    fn idle_callback_fire_pairs_with_idle_deadline_read_in_module_32() {
        // requestIdleCallback ships two surfaces that MUST agree:
        //   - FIRE side: AsyncEventClass::RequestIdleCallback (here)
        //   - READ side: Module 32 TimerSurface::IdleDeadlineTimeRemaining
        // Both must be in their respective ALL lists so the libxul
        // bridge wires both. A missed pairing leaves the residual-
        // time argument inside the callback as a real-clock leak
        // even with the callback fire bounded.
        use crate::gecko::timers::TimerSurface;
        assert!(AsyncEventClass::ALL.contains(&AsyncEventClass::RequestIdleCallback));
        assert!(TimerSurface::ALL.contains(&TimerSurface::IdleDeadlineTimeRemaining));
    }

    #[test]
    fn async_event_class_is_send_sync() {
        // The libxul bridge holds the plumbing list across renderer
        // processes within an identity group (§3.2 renderer-sharing).
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AsyncEventClass>();
    }

    // ── L41 regression layer over Module 32 ──────────────────────────────
    //
    // Module 32 already ships the structural L41 lock: there is no
    // `TimerQuantizationPolicy::for_mode_with_user_override` and the
    // per-Mode `TimerProfile` statics carry the locked `js_quantum_ns`
    // values. Module 35.2 re-asserts the invariants here so a future
    // change to `gecko::timers` that loosens Strict (intentionally or
    // accidentally) fails the Phase 5.5 layer's tests, not just
    // Module 32's.

    #[test]
    fn strict_quantum_is_structurally_non_loosenable() {
        // for_mode(Strict) MUST be idempotent and resolve to
        // STRICT_TIMER_PROFILE; no path exists to produce a smaller
        // Strict quantum.
        let a = TimerQuantizationPolicy::for_mode(Mode::Strict);
        let b = TimerQuantizationPolicy::for_mode(Mode::Strict);
        assert_eq!(a, b);
        assert!(std::ptr::eq(a.profile(), &STRICT_TIMER_PROFILE));
        // And the quantum is the L43-locked 100 ms.
        assert_eq!(a.profile().js_quantum_ns, 100_000_000);
    }

    #[test]
    fn standard_resolves_to_locked_1ms_profile() {
        let p = TimerQuantizationPolicy::for_mode(Mode::Standard);
        assert!(std::ptr::eq(p.profile(), &STANDARD_TIMER_PROFILE));
        assert_eq!(p.profile().js_quantum_ns, 1_000_000);
    }

    #[test]
    fn async_arrival_bound_via_quantize_js_ms_floors_in_strict() {
        // Phase-file subtask 4 contract: in Strict, async events
        // fire no earlier than the quantum boundary their scheduled
        // time floors to. The bridge calls `profile.quantize_js_ms`
        // at the four AsyncEventClass scheduling sites; this test
        // pins the floor behavior the bridge depends on.
        let profile = TimerQuantizationPolicy::for_mode(Mode::Strict).profile();
        assert_eq!(profile.quantize_js_ms(0.0), 0.0);
        assert_eq!(profile.quantize_js_ms(99.999), 0.0);
        assert_eq!(profile.quantize_js_ms(137.0), 100.0);
        assert_eq!(profile.quantize_js_ms(199.999), 100.0);
        assert_eq!(profile.quantize_js_ms(550.0), 500.0);
    }

    #[test]
    fn async_arrival_bound_via_quantize_js_ms_floors_in_standard() {
        let profile = TimerQuantizationPolicy::for_mode(Mode::Standard).profile();
        assert_eq!(profile.quantize_js_ms(0.7), 0.0);
        assert_eq!(profile.quantize_js_ms(1.5), 1.0);
        assert_eq!(profile.quantize_js_ms(137.42), 137.0);
    }

    #[test]
    fn fire_pathway_equals_read_pathway_by_construction() {
        // Composition lock: a clock read inside a fired callback
        // returns the same quantized value as the bounded arrival.
        // Otherwise the (arrival, now()) pair leaks the actual fire
        // delta. Because Module 32's `quantize_js_ms` is the single
        // source of truth used at BOTH scheduling and read sites,
        // this is true by construction; the test pins the property.
        for mode in [Mode::Standard, Mode::Strict] {
            let profile = TimerQuantizationPolicy::for_mode(mode).profile();
            for &t in &[0.0_f64, 0.5, 1.5, 50.0, 99.999, 137.42, 550.0, 999.999] {
                let arrival = profile.quantize_js_ms(t);
                let read = profile.quantize_js_ms(arrival);
                assert!(
                    (arrival - read).abs() < 1e-9,
                    "arrival {} != subsequent read {} at mode={:?} t={}",
                    arrival,
                    read,
                    mode,
                    t,
                );
            }
        }
    }
}
