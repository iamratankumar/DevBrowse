//! Module 31 — Battery Status API removal.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the
//!     `navigator.getBattery()` accessor is removed below the JS
//!     surface so workers and iframes inherit the removal
//!     automatically.
//!   * **L9 / §3.3 / §3.2** — **mode-invariant removal**. Both modes
//!     return `"not supported"`: Strict by L44 mandate (Battery is in
//!     the disabled-by-default API set); Standard by industry
//!     consensus (Firefox removed `navigator.getBattery` in 52+; the
//!     spec itself acknowledges the API leaks battery-cycle
//!     identification and is no longer recommended for general
//!     browsers).
//!   * **L44** — Battery is one of the explicit Strict-disabled APIs;
//!     L41 makes the L44 list non-loosenable by user settings.
//!   * **§5.5** — central fingerprint bucketing: the Battery API
//!     surface is a single typed enumeration (`BatterySurface::ALL`)
//!     the libxul bridge iterates to remove every accessor.
//!   * **threat-model A1** — battery level + charging state were
//!     used as cross-site identifiers (Olejnik / Englehardt 2016);
//!     even with the Promise-style API the level granularity allows
//!     short-lived re-identification across same-host tabs.
//!
//! ## Locked decision (phase-5 Goal + §5.5 matrix v1.11)
//!
//! **Module 31 is the first Phase-5 module where the per-Mode
//! decision is mode-invariant removal** (Modules 25 / 27 / 28 / 29
//! are Strict-only cohort lock with Standard pass-through; Module 30
//! is both-modes-normalize). Battery is removed for everyone — the
//! API has no legitimate use case that outweighs the cross-site
//! identification surface, and shipping it in Standard would
//! contradict L44's "consent-by-mode-choice" framing (Strict users
//! get the lock; Standard users opt into a permission center for
//! everything else, but the spec's own threat assessment says even
//! permission-gated battery is a poor tradeoff).
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * The single `BatteryApiPolicy::Removed` policy returned by
//!     `for_mode` regardless of input.
//!   * The enumeration of every BatteryManager accessor and event
//!     the libxul bridge must redact (`BatterySurface::ALL`).
//!   * A `FingerprintOverride` impl for `WebIdlSurface::Battery`
//!     that uniformly registers under both modes; `install()` is a
//!     no-op pending the libxul WebIDL accessor removal.
//!
//! It IS NOT:
//!   * The actual WebIDL accessor removal. Module 1 (libxul tag)
//!     compiles libxul with `dom.battery.enabled = false` and patches
//!     `Navigator.webidl` so `getBattery` does not exist on the
//!     prototype. This module pins the contract; libxul honors it.
//!   * A permission-gated re-enable path. There is none. Unlike
//!     Module 30 fonts (per-site `FontsGrants` opt-in for Standard),
//!     Battery has no `BatteryGrants` trait — the API stays removed
//!     regardless of any settings or site grant.
//
// TODO(Module 1 / libxul): the WebIDL accessor removal lands
//   alongside the libxul tag. Configuration knobs:
//   - `dom.battery.enabled = false` in the build-time prefs.
//   - `Navigator.webidl` patched to drop the `getBattery()` operation
//     (so `'getBattery' in navigator === false`, not just
//     `navigator.getBattery() rejects`).
//   - Worker / SharedWorker / ServiceWorker global Navigator surfaces
//     get the same treatment — every JsContext::ALL variant.
// TODO(Module 69 / wrapper-compatibility checker): on every libxul
//   tag bump, assert that `navigator.getBattery` is undefined in a
//   spawned renderer under both Mode::Standard and Mode::Strict.
//   A regression where libxul re-adds the accessor must fail the
//   build.
// TODO(Phase 5.5 / Module 35.3 + 35.4): the L44 disabled-API surface
//   includes Battery; Module 35.3 ships a single typed "L44-disabled
//   API" override that consolidates Battery + Geolocation +
//   MediaDevices + Bluetooth + USB + HID + Serial + NFC + 9 sensors
//   + Gamepad + sendBeacon + Notification + WakeLock + IdleDetector
//   + PresentationRequest + PaymentRequest. Module 31 ships only
//   the per-API hook for Battery; Module 35.3 is the cross-API
//   enforcement layer (and asserts L41: settings cannot re-enable
//   any of these in Strict, and cannot re-enable Battery in either
//   mode regardless of mode).
// TODO(Phase 10 / Module 71+): the CreepJS / FPStandard battery
//   probe checks for `'getBattery' in navigator`; the Strict and
//   Standard adversarial probes must both observe `false`.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Per-mode policy (mode-invariant) ──────────────────────────────────────

/// Battery Status API policy. Single variant for v1 — the API is
/// removed in both modes.
///
/// The enum is `#[non_exhaustive]` and carries a single variant on
/// purpose: future cohort decisions (e.g. a "Removed but reports a
/// flat 100% / not-charging stub for site-compat" carve-out) would
/// be a second variant, not a mutation of the existing one. The
/// libxul bridge MUST match this enum exhaustively so a future
/// variant cannot silently fall through to the wrong behavior.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatteryApiPolicy {
    /// `navigator.getBattery` is not exposed (`'getBattery' in
    /// navigator === false`). Worker / shared-worker /
    /// service-worker Navigator surfaces are equally redacted.
    /// L44 mandates this for Strict; industry consensus mandates
    /// this for Standard.
    Removed,
}

impl BatteryApiPolicy {
    /// Mode-invariant: both `Mode::Standard` and `Mode::Strict` map
    /// to `Removed`. The function takes a `Mode` for symmetry with
    /// the other Phase-5 modules (Modules 27 / 28 / 29 / 30) — the
    /// libxul bridge calls `for_mode` uniformly regardless of the
    /// per-module decision shape.
    pub fn for_mode(_mode: Mode) -> Self {
        Self::Removed
    }

    /// True iff the policy redacts every Battery surface. Today
    /// this is a tautology (the single variant is `Removed`);
    /// offered as a named predicate so call sites read naturally
    /// and so a future variant that does not redact would have a
    /// place to return `false` without breaking call-site shape.
    pub fn is_removed(&self) -> bool {
        matches!(self, Self::Removed)
    }
}

// ── Surface enumeration ───────────────────────────────────────────────────

/// Every JS pathway through which the Battery Status API surfaces.
///
/// The libxul bridge MUST remove every variant — missing one leaves
/// a residual accessor that a fingerprint probe can use even though
/// the obvious entry point (`navigator.getBattery`) is gone. The
/// BatteryManager properties + events are listed even though they
/// are unreachable once `getBattery` itself is removed, because (a)
/// defense-in-depth against a libxul build that re-enables
/// `getBattery` but forgets to patch the manager surface, and (b) a
/// future "stub manager" carve-out would need every property and
/// event redacted at the same time.
///
/// `JsContext::ALL` × this set is the full removal matrix the
/// bridge iterates at renderer startup.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatterySurface {
    /// `navigator.getBattery()` — the entry point. Removal target.
    NavigatorGetBattery,
    /// `BatteryManager.level` — float 0..=1.0.
    BatteryManagerLevel,
    /// `BatteryManager.charging` — boolean.
    BatteryManagerCharging,
    /// `BatteryManager.chargingTime` — seconds until full;
    /// `Infinity` when discharging.
    BatteryManagerChargingTime,
    /// `BatteryManager.dischargingTime` — seconds until empty;
    /// `Infinity` when charging.
    BatteryManagerDischargingTime,
    /// `BatteryManager` event handlers (`onchargingchange`,
    /// `onlevelchange`, `onchargingtimechange`,
    /// `ondischargingtimechange`). Treated as one variant because
    /// the libxul side patches the event-target table for the
    /// whole interface, not per-event.
    BatteryManagerEvents,
}

impl BatterySurface {
    /// Every surface the bridge must redact. Asserted against the
    /// spec's BatteryManager IDL by
    /// `tests::battery_surface_all_covers_spec_idl`.
    pub const ALL: &'static [BatterySurface] = &[
        Self::NavigatorGetBattery,
        Self::BatteryManagerLevel,
        Self::BatteryManagerCharging,
        Self::BatteryManagerChargingTime,
        Self::BatteryManagerDischargingTime,
        Self::BatteryManagerEvents,
    ];
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Battery`.
///
/// Construct with `BatteryOverride::new(mode)` for symmetry with
/// the other Phase-5 overrides; the constructor accepts a `Mode`
/// argument but does not use it (the policy is mode-invariant).
/// Keeping the constructor signature uniform across Phase-5 modules
/// means the libxul bridge has one registration code path.
///
/// Context-inert per Module 26: there is no state to vary across
/// `JsContext` variants; the API is removed in every scope.
#[derive(Debug, Clone, Copy)]
pub struct BatteryOverride {
    policy: BatteryApiPolicy,
}

impl BatteryOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: BatteryApiPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> BatteryApiPolicy {
        self.policy
    }
}

impl FingerprintOverride for BatteryOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Battery
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul WebIDL accessor removal is
        // not yet wired (see crate-level TODO). When the FFI lands,
        // both modes register the same redaction callback that
        // returns `undefined` for every variant of
        // `BatterySurface::ALL` × `JsContext::ALL`.
        let _ = (self.policy, JsContext::ALL);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_mode_invariant_removed() {
        // The lock: both modes resolve to Removed. Any future change
        // here is a breaking cohort decision and must land via the
        // Adaptation protocol + an architecture revision-log entry.
        assert_eq!(
            BatteryApiPolicy::for_mode(Mode::Standard),
            BatteryApiPolicy::Removed
        );
        assert_eq!(
            BatteryApiPolicy::for_mode(Mode::Strict),
            BatteryApiPolicy::Removed
        );
        assert!(BatteryApiPolicy::for_mode(Mode::Standard).is_removed());
        assert!(BatteryApiPolicy::for_mode(Mode::Strict).is_removed());
    }

    #[test]
    fn battery_surface_all_covers_spec_idl() {
        // BatteryManager IDL (W3C Battery Status API, retired but
        // still in Gecko): one entry point + 4 properties + the
        // event-handler table. Six variants total.
        assert_eq!(BatterySurface::ALL.len(), 6);
        for v in [
            BatterySurface::NavigatorGetBattery,
            BatterySurface::BatteryManagerLevel,
            BatterySurface::BatteryManagerCharging,
            BatterySurface::BatteryManagerChargingTime,
            BatterySurface::BatteryManagerDischargingTime,
            BatterySurface::BatteryManagerEvents,
        ] {
            assert!(BatterySurface::ALL.contains(&v), "missing surface: {:?}", v);
        }
    }

    #[test]
    fn battery_override_reports_battery_surface_under_both_modes() {
        // Uniform registration; the policy carries the
        // mode-invariant decision but the trait dispatch is uniform.
        assert_eq!(
            BatteryOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Battery
        );
        assert_eq!(
            BatteryOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Battery
        );
    }

    #[test]
    fn battery_override_carries_removed_policy_in_both_modes() {
        let standard = BatteryOverride::new(Mode::Standard);
        let strict = BatteryOverride::new(Mode::Strict);
        assert_eq!(standard.policy(), BatteryApiPolicy::Removed);
        assert_eq!(strict.policy(), BatteryApiPolicy::Removed);
        // Sanity: the two overrides are observationally
        // indistinguishable. If a future variant landed in
        // BatteryApiPolicy, this is the test that would force the
        // mode-divergence to be explicit.
        assert_eq!(standard.policy(), strict.policy());
    }

    #[test]
    fn battery_override_install_is_context_inert() {
        // Edge case: override must be inert in iframe / worker /
        // service-worker / dedicated-worker. The trait obligation
        // (Module 26 context-inert) is trivially satisfied for a
        // mode-invariant removal — every install sees the same
        // Removed policy regardless of JsContext.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000031").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = BatteryOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Battery);
        }
    }

    #[test]
    fn battery_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BatteryOverride>();
        assert_send_sync::<BatteryApiPolicy>();
        assert_send_sync::<BatterySurface>();
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // The bridge MUST match without a `_` arm so a new variant
        // (e.g. a hypothetical "BatteryManagerOnchargingchange"
        // split-out from BatteryManagerEvents) fails compilation
        // until the bridge wires it.
        fn route(s: BatterySurface) -> &'static str {
            match s {
                BatterySurface::NavigatorGetBattery => "navigator-get-battery",
                BatterySurface::BatteryManagerLevel => "battery-manager-level",
                BatterySurface::BatteryManagerCharging => "battery-manager-charging",
                BatterySurface::BatteryManagerChargingTime => "battery-manager-charging-time",
                BatterySurface::BatteryManagerDischargingTime => "battery-manager-discharging-time",
                BatterySurface::BatteryManagerEvents => "battery-manager-events",
            }
        }
        for s in BatterySurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // The libxul bridge matches BatteryApiPolicy to decide
        // whether to register the redaction callback. Lock in the
        // exhaustive-match contract so a future variant (e.g. a
        // "StubbedManager" carve-out) cannot be silently treated as
        // Removed.
        fn arm(p: BatteryApiPolicy) -> &'static str {
            match p {
                BatteryApiPolicy::Removed => "removed",
            }
        }
        assert_eq!(arm(BatteryApiPolicy::for_mode(Mode::Standard)), "removed");
        assert_eq!(arm(BatteryApiPolicy::for_mode(Mode::Strict)), "removed");
    }
}
