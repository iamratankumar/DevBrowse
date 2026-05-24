//! Module 35.3 — Disabled-by-default API surface (L44 lock).
//!
//! In Strict tabs, the L44 list of JS APIs returns "not supported"
//! (constructor throws, property `undefined`, or the variant-
//! specific special-case behavior) **without consulting Module 59
//! permission center**. The L41 lock makes the disable
//! non-loosenable: no user setting, no per-site permission grant,
//! no extension can re-enable any L44 API in Strict.
//!
//! Architecture references:
//!   * **L41** — Strict-mode settings lock; the disable surface is
//!     structurally Strict-only (`disabled_for_mode(Standard)`
//!     returns the empty slice — Standard's per-API handling lives
//!     in the relevant Phase-5 / Phase-8 module).
//!   * **L44** — Disabled-by-default API surface (Strict). This
//!     module IS the enumeration.
//!   * **§3.3** — Strict mode tradeoff: site compatibility is
//!     downgraded in exchange for the cohort lock.
//!   * **§5.5** — central fingerprint surface bucketing.
//!
//! ## Mode-applicability
//!
//!   * **Strict** — every variant in `DisabledApi::ALL` returns
//!     "not supported" via its variant-specific
//!     [`DisableMechanism`]. The libxul bridge iterates the list
//!     at startup and patches the WebIDL surface accordingly.
//!   * **Standard** — `disabled_for_mode(Standard)` returns the
//!     empty slice. Standard's per-API handling is delegated:
//!     Module 31 covers Battery (mode-invariant removal); Module
//!     59 (Phase 8) covers permission flow for MediaDevices,
//!     Geolocation, Notification, WakeLock, IdleDetector,
//!     PresentationRequest, PaymentRequest; Module 35.8 covers
//!     NetworkInformation; the remaining APIs (Web Bluetooth /
//!     USB / HID / Serial / NFC, sensor APIs, Beacon, Gamepad)
//!     follow Firefox 119+ ETP defaults in Standard until
//!     Module 59 overrides.
//!
//! ## L44 grouping rule
//!
//! Variants correspond to **logical API families**, not individual
//! JS constructors. `SensorApis` is one variant covering all 9
//! sensor constructors because they share a single libxul disable
//! switch (`dom.sensors.enabled = false`); the individual
//! constructor names are returned by [`DisabledApi::js_surfaces`].
//! This mirrors the L44 invariant's phrasing ("all 9 sensor APIs"
//! as one family).
//!
//! ## Edge cases (phase-file lock)
//!
//!   * **`Notification.permission` MUST return `"denied"`, NOT
//!     throw.** The property read is synchronous and many sites
//!     branch on it; returning `"denied"` is web-compatible while
//!     throwing breaks features that gracefully degrade. Encoded
//!     in `DisabledApi::Notification`'s [`DisableMechanism`]
//!     special-case slot.
//!   * **`navigator.getGamepads()` MUST return `[]`, NOT `null`.**
//!     Several mainstream game frameworks crash on `null`.
//!     Encoded in `DisabledApi::Gamepad`'s special-case slot.
//!   * **`navigator`-property deletes MUST remove the property
//!     from the prototype chain, not just set it to `undefined`.**
//!     Code that does `if ("mediaDevices" in navigator)` MUST see
//!     `false`. Encoded as
//!     [`DisableMechanism::NavigatorPropertyDeleted`] — distinct
//!     from a hypothetical "set to undefined" mechanism.
//!
//! ## Decoupling from Module 59
//!
//! This module is **decoupled** from Module 59 (permission center)
//! by design: Strict skips permission flows entirely. A future
//! Module 35.3 vs Module 59 cross-coupling test asserts that
//! `disabled_for_mode(Strict)` does NOT consult Module 59's
//! permission store, even when the store has explicit grants for
//! an L44 API.
//!
//! ## Delegation to existing modules (no redundant state)
//!
//! Some L44 surfaces are already owned by an existing Phase-5
//! module; `DisabledApi::ALL` does NOT re-enumerate them so there
//! is exactly one source of truth per surface:
//!
//!   * **Battery** — owned by Module 31 (`gecko::battery`).
//!     `BatteryApiPolicy::Removed` is **mode-invariant**
//!     (`for_mode(Standard)` AND `for_mode(Strict)` both return
//!     `Removed`); `BatterySurface::ALL` enumerates the 6
//!     individual JS surfaces. Adding `Battery` here would be a
//!     second source of truth and exactly the cohort-drift surface
//!     the Adaptation protocol exists to prevent. The
//!     phase-file Battery bullet — which read "Module 31 handles
//!     Standard" — was based on a stale assumption (Module 31
//!     actually handles BOTH modes mode-invariantly).
//!   * **WebRTC** — owned by Module 25 (`pb_network::webrtc`).
//!     `WebRtcPolicy::Disabled` is locked for Strict per L35.
//!     The `webrtc_is_not_in_this_list` test pins the boundary.
//!   * **NetworkInformation** — owned by Module 35.8
//!     (`gecko::network_info`).
//!     `NetworkInformationPolicy::Removed` is the Strict
//!     decision; `LockedCohort(&LOCKED_NETWORK_INFORMATION_PROFILE)`
//!     is the Standard decision (per-API per-Mode, mirroring the
//!     Module 31 Battery delegation precedent). Adding
//!     `NetworkInformation` here would be a second source of truth
//!     for Strict + a contradiction for Standard (Module 35.3's
//!     Standard resolver returns the empty slice; Module 35.8's
//!     returns `LockedCohort`). The
//!     `network_information_is_delegated_to_module_35_8_not_duplicated_here`
//!     test pins the boundary.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): per-variant disable wiring
//   lands alongside the libxul tag. Mapping (sketch — exact pref
//   names depend on the current libxul tag):
//     - NavigatorPropertyDeleted variants: WebIDL accessor patch
//       removing the property from the navigator prototype.
//     - ConstructorThrows variants: WebIDL [Func="StrictModeDisabled"]
//       extended attribute or equivalent constructor gate.
//     - SpecialCase variants: per-variant patch — Notification's
//       `permission` getter returns `"denied"`; Gamepad's
//       `getGamepads()` returns `[]` and `gamepadconnected` event
//       dispatch is suppressed; SharedArrayBuffer's constructor +
//       `Atomics.wait` / `Atomics.notify` throw.
//   The bridge MUST iterate `DisabledApi::ALL` × `JsContext::ALL`
//   so workers / iframes / SWs cannot bypass.
// Module 35.4 (settings-lock audit) has shipped: the L41/L44
//   audit pass in `strict/settings_lock.rs` re-asserts no settings
//   path can remove a variant from `disabled_for_mode(Mode::Strict)`.
//   The current API has no user-override constructor; the 35.4
//   audit list extends to cross-crate settings (pb-config /
//   pb-extensions writes that could mask the static list).
// TODO(Module 59 permission center, Phase 8): Standard mode's
//   per-API permission flow for the L44 APIs that have legitimate
//   Standard use cases (MediaDevices, Geolocation, Notification,
//   WakeLock, IdleDetector, PresentationRequest, PaymentRequest).
//   Cross-coupling test from this module asserts that even an
//   explicit Module 59 grant cannot re-enable an L44 API in
//   Strict.
// Module 31 (Battery) delegation has shipped: Module 31 owns
//   BatteryApiPolicy::Removed as mode-invariant; Module 35.3 does
//   NOT duplicate the disable here (no DisabledApi::Battery
//   variant). The libxul bridge consults BOTH module's lists at
//   startup and unions the disables. Test `battery_is_delegated_
//   to_module_31_not_duplicated_here` pins the no-duplication
//   contract.
// Module 35.8 (NetworkInformation) delegation has shipped: Module
//   35.8 owns NetworkInformationPolicy::{Removed | LockedCohort}
//   per-API; Module 35.3 does NOT duplicate the disable here (no
//   DisabledApi::NetworkInformation variant). The libxul bridge
//   consults BOTH lists at startup and unions the Strict
//   disables. Test `network_information_is_delegated_to_module_
//   35_8_not_duplicated_here` pins the no-duplication contract,
//   mirroring the Battery delegation precedent.
// Module 25 (WebRTC) boundary has shipped: WebRTC is L35 / Module
//   25 owned by pb-network::webrtc, NOT in this list. The phase-
//   file note "WebRTC stays separate" applies; this module's ALL
//   does NOT include WebRTC. Test `webrtc_is_not_in_this_list`
//   pins the structural ban.
// TODO(Phase 10 / Module 71+): live-renderer probes assert
//   every L44 API surface returns "not supported" in Strict
//   regardless of permission-center state. `DisabledApi::ALL`
//   is the ground-truth list Phase 10 iterates.

use pb_config::Mode;

// ── Disable mechanism ────────────────────────────────────────────────────

/// How the libxul bridge wires a particular L44 disable.
///
/// Distinct from "what's disabled" ([`DisabledApi`]) so the
/// libxul-side patching can dispatch on the mechanism even when
/// the JS surface name differs per platform. Adding a variant is
/// an FFI-bridge handshake — the bridge MUST exhaustively match.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisableMechanism {
    /// The named property is deleted from the `navigator`
    /// prototype so `<prop> in navigator === false` AND
    /// `navigator.<prop> === undefined`. Setting to `undefined`
    /// alone is insufficient — sites use the `in`-reflection
    /// pattern.
    NavigatorPropertyDeleted,
    /// The named constructor throws on invocation
    /// (`new <Class>()` raises a `TypeError`). The constructor
    /// is itself reachable as a global (so `typeof Class !==
    /// "undefined"` to avoid breaking feature-detect branches
    /// that gracefully degrade) but inert.
    ConstructorThrows,
    /// Variant-specific patch — see the [`DisabledApi`] variant
    /// doc for the exact behavior. Used for the three phase-file
    /// edge cases:
    ///   * `Notification`: constructor throws BUT
    ///     `Notification.permission` returns `"denied"`.
    ///   * `Gamepad`: `getGamepads()` returns `[]` (NOT `null`),
    ///     events never fire.
    ///   * `SharedMemoryAndAtomics`: `SharedArrayBuffer`
    ///     constructor throws AND `Atomics.wait` / `Atomics.notify`
    ///     throw when called as methods (a method-throw, not a
    ///     constructor-throw — the `Atomics` namespace itself
    ///     stays defined).
    SpecialCase,
}

// ── Disabled API enumeration ─────────────────────────────────────────────

/// The L44 disabled-by-default API surface (Strict).
///
/// Each variant corresponds to a logical API family; the
/// individual JS surface names (constructors, navigator
/// properties, methods) are returned by
/// [`DisabledApi::js_surfaces`]. The variant ordering matches the
/// L44 invariant's enumeration; `SharedMemoryAndAtomics` is the
/// only variant not in the original L44 list — added by the
/// Module 35.2 audit which identified `SharedArrayBuffer +
/// Atomics.wait` as a cross-thread clock channel that bypasses
/// every Module 32 / 35.2 quantizer.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisabledApi {
    /// `navigator.geolocation` is deleted from the `navigator`
    /// prototype. `Geolocation.getCurrentPosition` /
    /// `watchPosition` are inaccessible through the deleted
    /// property reference.
    Geolocation,
    /// `navigator.mediaDevices` is deleted. `getUserMedia` /
    /// `enumerateDevices` / `getDisplayMedia` are all reached
    /// only through the deleted property, so all three are
    /// inert.
    MediaDevices,
    /// `navigator.bluetooth` is deleted (Web Bluetooth).
    WebBluetooth,
    /// `navigator.usb` is deleted (WebUSB).
    WebUsb,
    /// `navigator.hid` is deleted (WebHID).
    WebHid,
    /// `navigator.serial` is deleted (Web Serial).
    WebSerial,
    /// `NDEFReader` constructor throws (Web NFC).
    WebNfc,
    /// All 9 sensor APIs (`Accelerometer`, `Gyroscope`,
    /// `Magnetometer`, `AmbientLightSensor`,
    /// `LinearAccelerationSensor`, `OrientationSensor`,
    /// `GravitySensor`, `RelativeOrientationSensor`,
    /// `AbsoluteOrientationSensor`) — constructors throw.
    /// Treated as one logical family because they share a
    /// single libxul disable switch (`dom.sensors.enabled =
    /// false`); the 9 individual names are returned by
    /// `js_surfaces()`.
    SensorApis,
    /// `navigator.getGamepads()` returns `[]` (NOT `null`);
    /// `gamepadconnected` / `gamepaddisconnected` events never
    /// fire. Special-case behavior — `[]` is web-compat
    /// (mainstream game frameworks crash on `null`).
    Gamepad,
    /// `navigator.sendBeacon` is deleted.
    Beacon,
    // Battery: NOT a variant here. Module 31
    // (`gecko::battery::BatteryApiPolicy::Removed`) owns the
    // mode-invariant Battery removal. Re-enumerating it would
    // be a second source of truth — see crate-level
    // "Delegation to existing modules" doc.
    /// `Notification` constructor throws BUT
    /// `Notification.permission` returns `"denied"` (NOT throw).
    /// The property read is synchronous and many sites branch
    /// on it; throwing breaks features that gracefully degrade.
    Notification,
    /// `navigator.wakeLock` is deleted.
    WakeLock,
    /// `IdleDetector` constructor throws.
    IdleDetector,
    /// `PresentationRequest` constructor throws.
    PresentationRequest,
    /// `PaymentRequest` constructor throws.
    PaymentRequest,
    /// `SharedArrayBuffer` constructor throws AND `Atomics.wait`
    /// / `Atomics.notify` throw when called as methods. The
    /// `Atomics` namespace itself stays defined (only the
    /// timing-relevant methods throw); other `Atomics.*`
    /// operations (load / store / add / etc.) are unaffected
    /// when used on a regular `TypedArray` (without SAB).
    ///
    /// **Added by the Module 35.2 audit** which identified
    /// `SharedArrayBuffer + Atomics.wait` as a wholly separate
    /// cross-thread timer channel that bypasses every Module 32
    /// / 35.2 quantizer (the historical Spectre "spreader"
    /// attack vector). Disabling at this layer closes the
    /// channel without relying on COOP/COEP isolation alone.
    SharedMemoryAndAtomics,
}

impl DisabledApi {
    /// Every L44 API family this module owns.
    ///
    /// 16 variants: 15 phase-file-listed families (16 - Battery,
    /// delegated to Module 31) + 1 audit addition
    /// (`SharedMemoryAndAtomics` from the Module 35.2 audit).
    /// The libxul bridge unions this with Module 31's
    /// `BatterySurface::ALL` and Module 25's WebRTC disable.
    pub const ALL: &'static [DisabledApi] = &[
        Self::Geolocation,
        Self::MediaDevices,
        Self::WebBluetooth,
        Self::WebUsb,
        Self::WebHid,
        Self::WebSerial,
        Self::WebNfc,
        Self::SensorApis,
        Self::Gamepad,
        Self::Beacon,
        Self::Notification,
        Self::WakeLock,
        Self::IdleDetector,
        Self::PresentationRequest,
        Self::PaymentRequest,
        Self::SharedMemoryAndAtomics,
    ];

    /// The individual JS surfaces this family disables. The
    /// libxul bridge iterates this list per variant to apply
    /// the per-surface patch (e.g. `SensorApis` returns the 9
    /// individual constructor names).
    pub fn js_surfaces(&self) -> &'static [&'static str] {
        match self {
            Self::Geolocation => &["navigator.geolocation"],
            Self::MediaDevices => &["navigator.mediaDevices"],
            Self::WebBluetooth => &["navigator.bluetooth"],
            Self::WebUsb => &["navigator.usb"],
            Self::WebHid => &["navigator.hid"],
            Self::WebSerial => &["navigator.serial"],
            Self::WebNfc => &["NDEFReader"],
            Self::SensorApis => &[
                "Accelerometer",
                "Gyroscope",
                "Magnetometer",
                "AmbientLightSensor",
                "LinearAccelerationSensor",
                "OrientationSensor",
                "GravitySensor",
                "RelativeOrientationSensor",
                "AbsoluteOrientationSensor",
            ],
            Self::Gamepad => &["navigator.getGamepads"],
            Self::Beacon => &["navigator.sendBeacon"],
            Self::Notification => &["Notification"],
            Self::WakeLock => &["navigator.wakeLock"],
            Self::IdleDetector => &["IdleDetector"],
            Self::PresentationRequest => &["PresentationRequest"],
            Self::PaymentRequest => &["PaymentRequest"],
            Self::SharedMemoryAndAtomics => {
                &["SharedArrayBuffer", "Atomics.wait", "Atomics.notify"]
            }
        }
    }

    /// How the libxul bridge wires this family's disable.
    pub fn disable_mechanism(&self) -> DisableMechanism {
        match self {
            // navigator.* property deletion family.
            Self::Geolocation
            | Self::MediaDevices
            | Self::WebBluetooth
            | Self::WebUsb
            | Self::WebHid
            | Self::WebSerial
            | Self::Beacon
            | Self::WakeLock => DisableMechanism::NavigatorPropertyDeleted,
            // Constructor-throws family.
            Self::WebNfc
            | Self::SensorApis
            | Self::IdleDetector
            | Self::PresentationRequest
            | Self::PaymentRequest => DisableMechanism::ConstructorThrows,
            // Special-case families — see per-variant doc.
            Self::Gamepad | Self::Notification | Self::SharedMemoryAndAtomics => {
                DisableMechanism::SpecialCase
            }
        }
    }
}

// ── Typed delegation registry (P2-5, 2026-05-22) ─────────────────────────

/// Surfaces explicitly delegated to **other modules** by the
/// no-redundant-state lock — not owned by `DisabledApi::ALL`.
///
/// Replaces the previous string-search delegation tests
/// (`name.to_lowercase().contains("battery")` etc.) with a typed
/// registry. Adding a new variant here is the contract handshake
/// with the owning module; the corresponding regression test
/// asserts the JS surface name does NOT appear in any
/// `DisabledApi::ALL` variant's `js_surfaces()`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DelegatedSurface {
    /// Battery API — owned by Module 31 (`gecko::battery`).
    /// `BatteryApiPolicy::Removed` is mode-invariant.
    Battery,
    /// Network Information API — owned by Module 35.8
    /// (`gecko::network_info`). `NetworkInformationPolicy::{Removed
    /// | LockedCohort}` is per-Mode.
    NetworkInformation,
    /// WebRTC — owned by Module 25 (`pb_network::webrtc`).
    /// `WebRtcPolicy::Disabled` for Strict per L35.
    WebRtc,
}

impl DelegatedSurface {
    pub const ALL: &'static [DelegatedSurface] =
        &[Self::Battery, Self::NetworkInformation, Self::WebRtc];

    /// JS-side substrings that MUST NOT appear in any
    /// `DisabledApi::ALL` variant's `js_surfaces()`. Used by the
    /// no-redundant-state regression test.
    ///
    /// Substring match is intentional — it catches both the
    /// canonical name and any future variant naming that includes
    /// the delegated surface as a substring.
    pub fn forbidden_substrings(self) -> &'static [&'static str] {
        match self {
            // Match "battery", "Battery", "BatteryManager*"
            Self::Battery => &["battery"],
            // Match "connection", "NetworkInformation",
            // "networkInformation"
            Self::NetworkInformation => &["connection", "networkinformation"],
            // Match "rtc", "RTC", "WebRTC", "RTCPeerConnection"
            Self::WebRtc => &["rtc"],
        }
    }

    /// Owning module identifier (for log / error messages).
    pub fn owner(self) -> &'static str {
        match self {
            Self::Battery => "Module 31 (gecko::battery)",
            Self::NetworkInformation => "Module 35.8 (gecko::network_info)",
            Self::WebRtc => "Module 25 (pb_network::webrtc)",
        }
    }
}

// ── Per-Mode resolver ────────────────────────────────────────────────────

/// The L44 list resolved per Mode.
///
/// Structural L41 lock: `disabled_for_mode(Mode::Strict)` always
/// returns `DisabledApi::ALL`; no settings path can shrink the
/// list. `disabled_for_mode(Mode::Standard)` always returns the
/// empty slice — Standard's per-API handling is delegated (see
/// crate-level Mode-applicability doc).
pub fn disabled_for_mode(mode: Mode) -> &'static [DisabledApi] {
    match mode {
        Mode::Standard => &[],
        Mode::Strict => DisabledApi::ALL,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_enumerates_sixteen_owned_l44_families() {
        // 15 phase-file-listed families owned by this module
        // (16 phase-file bullets minus Battery, which is owned by
        // Module 31) + 1 audit addition (SharedMemoryAndAtomics
        // from the Module 35.2 audit).
        assert_eq!(DisabledApi::ALL.len(), 16);
    }

    #[test]
    fn all_covers_every_owned_phase_file_listed_family() {
        // Phase file's L44 enumeration minus the Battery family
        // (delegated to Module 31). Asserted individually so a
        // future deletion is caught here, not just by ALL.len()
        // drifting.
        for v in [
            DisabledApi::Geolocation,
            DisabledApi::MediaDevices,
            DisabledApi::WebBluetooth,
            DisabledApi::WebUsb,
            DisabledApi::WebHid,
            DisabledApi::WebSerial,
            DisabledApi::WebNfc,
            DisabledApi::SensorApis,
            DisabledApi::Gamepad,
            DisabledApi::Beacon,
            DisabledApi::Notification,
            DisabledApi::WakeLock,
            DisabledApi::IdleDetector,
            DisabledApi::PresentationRequest,
            DisabledApi::PaymentRequest,
        ] {
            assert!(DisabledApi::ALL.contains(&v), "missing L44 family: {:?}", v,);
        }
    }

    #[test]
    fn shared_memory_and_atomics_satisfies_module_35_2_carry_forward() {
        // Module 35.2's audit flagged SharedArrayBuffer + Atomics.wait
        // as a cross-thread clock channel that bypasses every
        // Module 32 / 35.2 quantizer. The TODO in strict/timers.rs
        // pointed at this module; the assertion below pins the
        // closure of that carry-forward.
        assert!(DisabledApi::ALL.contains(&DisabledApi::SharedMemoryAndAtomics));
        let surfaces = DisabledApi::SharedMemoryAndAtomics.js_surfaces();
        assert!(surfaces.contains(&"SharedArrayBuffer"));
        assert!(surfaces.contains(&"Atomics.wait"));
        assert!(surfaces.contains(&"Atomics.notify"));
    }

    #[test]
    fn sensor_apis_variant_covers_all_nine_sensor_constructors() {
        // L44 invariant: "all 9 sensor APIs". The SensorApis
        // variant is one logical family but exposes 9 JS
        // constructor names.
        let surfaces = DisabledApi::SensorApis.js_surfaces();
        assert_eq!(surfaces.len(), 9);
        for s in [
            "Accelerometer",
            "Gyroscope",
            "Magnetometer",
            "AmbientLightSensor",
            "LinearAccelerationSensor",
            "OrientationSensor",
            "GravitySensor",
            "RelativeOrientationSensor",
            "AbsoluteOrientationSensor",
        ] {
            assert!(surfaces.contains(&s), "missing sensor: {}", s);
        }
    }

    #[test]
    fn every_variant_has_non_empty_js_surfaces() {
        for v in DisabledApi::ALL {
            let surfaces = v.js_surfaces();
            assert!(!surfaces.is_empty(), "variant {:?} has no JS surfaces", v,);
            for name in surfaces {
                assert!(!name.is_empty(), "variant {:?} has an empty JS name", v);
            }
        }
    }

    #[test]
    fn navigator_property_families_match_phase_file_edge_case() {
        // Phase-file edge case: navigator.* surfaces MUST be
        // DELETED from the prototype (so `in navigator` returns
        // false), not just set to undefined. This is encoded as
        // NavigatorPropertyDeleted, distinct from a hypothetical
        // "set to undefined" mechanism.
        for v in [
            DisabledApi::Geolocation,
            DisabledApi::MediaDevices,
            DisabledApi::WebBluetooth,
            DisabledApi::WebUsb,
            DisabledApi::WebHid,
            DisabledApi::WebSerial,
            DisabledApi::Beacon,
            DisabledApi::WakeLock,
        ] {
            assert_eq!(
                v.disable_mechanism(),
                DisableMechanism::NavigatorPropertyDeleted,
                "{:?} should be deleted from navigator prototype",
                v,
            );
        }
    }

    #[test]
    fn constructor_throw_families_dispatch_constructor_mechanism() {
        for v in [
            DisabledApi::WebNfc,
            DisabledApi::SensorApis,
            DisabledApi::IdleDetector,
            DisabledApi::PresentationRequest,
            DisabledApi::PaymentRequest,
        ] {
            assert_eq!(
                v.disable_mechanism(),
                DisableMechanism::ConstructorThrows,
                "{:?} should throw on construct",
                v,
            );
        }
    }

    #[test]
    fn special_case_families_carry_special_case_mechanism() {
        // The three special-case behaviors:
        //   - Notification.permission returns "denied" (not throw)
        //   - getGamepads() returns [] (not null)
        //   - SharedArrayBuffer constructor throws + Atomics.wait
        //     throws as a method (not a constructor)
        for v in [
            DisabledApi::Notification,
            DisabledApi::Gamepad,
            DisabledApi::SharedMemoryAndAtomics,
        ] {
            assert_eq!(
                v.disable_mechanism(),
                DisableMechanism::SpecialCase,
                "{:?} should use SpecialCase mechanism",
                v,
            );
        }
    }

    #[test]
    fn disabled_for_mode_strict_returns_full_list() {
        let strict = disabled_for_mode(Mode::Strict);
        assert_eq!(strict.len(), 16);
        // Content equality: every Strict resolution returns the
        // same 17 variants as `DisabledApi::ALL` in the same
        // order. (Address identity does not hold here because
        // `ALL` is a `const` slice — each use site inlines a
        // fresh instance — matching the convention used by
        // every other `*::ALL` in this crate.)
        assert_eq!(strict, DisabledApi::ALL);
    }

    #[test]
    fn disabled_for_mode_standard_returns_empty_slice() {
        // Standard does NOT route through this list (per phase-
        // file subtask 2). Per-API handling lives elsewhere
        // (Module 31 for Battery; Module 59 for permission flow).
        let standard = disabled_for_mode(Mode::Standard);
        assert_eq!(standard.len(), 0);
    }

    #[test]
    fn strict_resolution_is_structurally_non_loosenable() {
        // L41 lock — the API has no `with_user_override`
        // constructor. Two Strict resolutions return identical
        // content; no settings path can shrink the list. Module
        // 35.4 settings-lock audit pins this against call sites.
        let a = disabled_for_mode(Mode::Strict);
        let b = disabled_for_mode(Mode::Strict);
        assert_eq!(a, b);
        assert_eq!(a.len(), DisabledApi::ALL.len());
        assert_eq!(a, DisabledApi::ALL);
    }

    #[test]
    fn webrtc_is_not_in_this_list() {
        // Phase-file note: "WebRTC stays separate — it's L35 /
        // Module 25." This test pins the boundary so a future
        // accidental addition of WebRTC here is caught.
        for v in DisabledApi::ALL {
            for name in v.js_surfaces() {
                assert!(
                    !name.to_lowercase().contains("rtc"),
                    "WebRTC surface {:?} leaked into Module 35.3 (belongs to Module 25)",
                    name,
                );
            }
        }
    }

    #[test]
    fn delegated_surfaces_registry_is_disjoint_from_disabled_api_all() {
        // P2-5 (2026-05-22) — replaces the prior three string-
        // search delegation tests (battery / connection / rtc)
        // with a single typed-registry sweep. Adding a new
        // `DelegatedSurface` variant + its forbidden substrings
        // is the contract handshake with the owning module; this
        // test asserts none of the substrings appear in any
        // `DisabledApi::ALL` variant's `js_surfaces()`.
        for delegated in DelegatedSurface::ALL {
            for needle in delegated.forbidden_substrings() {
                for variant in DisabledApi::ALL {
                    for surface_name in variant.js_surfaces() {
                        let lower = surface_name.to_lowercase();
                        assert!(
                            !lower.contains(needle),
                            "Delegated surface {:?} (owned by {}) substring {:?} leaked \
                             into Module 35.3 via DisabledApi::{:?} -> {:?}",
                            delegated,
                            delegated.owner(),
                            needle,
                            variant,
                            surface_name,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn network_information_is_delegated_to_module_35_8_not_duplicated_here() {
        // Module 35.8 (`gecko::network_info::NetworkInformationPolicy`)
        // owns the per-API per-Mode policy: Strict = Removed,
        // Standard = LockedCohort. Re-enumerating it here would be
        // a second source of truth for Strict AND a contradiction
        // for Standard (this module's Standard resolver returns
        // the empty slice; Module 35.8's returns LockedCohort).
        // The libxul bridge unions both modules' surfaces at
        // startup; NetworkInformation is reachable through Module
        // 35.8's `NetworkInformationSurface::ALL`, not this list.
        //
        // Structural ban: no JS surface name in this module's
        // enumeration may reference connection / network-info.
        for v in DisabledApi::ALL {
            for name in v.js_surfaces() {
                let lower = name.to_lowercase();
                assert!(
                    !lower.contains("connection"),
                    "Network Information surface {:?} leaked into Module 35.3 (owned by Module 35.8)",
                    name,
                );
                assert!(
                    !lower.contains("networkinformation"),
                    "Network Information surface {:?} leaked into Module 35.3 (owned by Module 35.8)",
                    name,
                );
            }
        }
        // Cross-module assertion: Module 35.8's per-Mode policy
        // disagrees with Module 35.3's Standard empty-slice
        // decision (Module 35.8 returns LockedCohort under
        // Standard, not the empty slice). The Strict policies
        // both lock down — but through disjoint per-API surfaces
        // that the bridge unions.
        use crate::gecko::network_info::NetworkInformationPolicy;
        assert_eq!(
            NetworkInformationPolicy::for_mode(pb_config::Mode::Strict),
            NetworkInformationPolicy::Removed,
        );
        assert!(matches!(
            NetworkInformationPolicy::for_mode(pb_config::Mode::Standard),
            NetworkInformationPolicy::LockedCohort(_),
        ));
    }

    #[test]
    fn battery_is_delegated_to_module_31_not_duplicated_here() {
        // Module 31 (`gecko::battery::BatteryApiPolicy::Removed`)
        // owns the mode-invariant Battery removal. Re-enumerating
        // it here would be a second source of truth — exactly the
        // cohort-drift surface the Adaptation protocol exists to
        // prevent. The libxul bridge unions Module 31's surface
        // with Module 35.3's; Battery is reachable through
        // Module 31's `BatterySurface::ALL`, not this list.
        //
        // The assertion below is a structural ban: no JS surface
        // name in this module's enumeration may reference Battery.
        for v in DisabledApi::ALL {
            for name in v.js_surfaces() {
                assert!(
                    !name.to_lowercase().contains("battery"),
                    "Battery surface {:?} leaked into Module 35.3 (owned by Module 31)",
                    name,
                );
            }
        }
        // Cross-module assertion: Module 31's policy is mode-
        // invariant Removed; the Strict cohort lock holds via
        // Module 31's API, not via redundant enumeration here.
        use crate::gecko::battery::BatteryApiPolicy;
        assert_eq!(
            BatteryApiPolicy::for_mode(pb_config::Mode::Strict),
            BatteryApiPolicy::Removed,
        );
        assert_eq!(
            BatteryApiPolicy::for_mode(pb_config::Mode::Standard),
            BatteryApiPolicy::Removed,
        );
    }

    #[test]
    fn dispatch_is_exhaustive_friendly() {
        // The libxul bridge matches DisabledApi to look up the
        // right per-family disable hook. Exhaustive match (no
        // `_` arm) catches a future variant addition at compile
        // time — adding a variant without updating the bridge is
        // a silent privacy regression.
        fn route(v: DisabledApi) -> &'static str {
            match v {
                DisabledApi::Geolocation => "geolocation",
                DisabledApi::MediaDevices => "media-devices",
                DisabledApi::WebBluetooth => "web-bluetooth",
                DisabledApi::WebUsb => "web-usb",
                DisabledApi::WebHid => "web-hid",
                DisabledApi::WebSerial => "web-serial",
                DisabledApi::WebNfc => "web-nfc",
                DisabledApi::SensorApis => "sensor-apis",
                DisabledApi::Gamepad => "gamepad",
                DisabledApi::Beacon => "beacon",
                DisabledApi::Notification => "notification",
                DisabledApi::WakeLock => "wake-lock",
                DisabledApi::IdleDetector => "idle-detector",
                DisabledApi::PresentationRequest => "presentation-request",
                DisabledApi::PaymentRequest => "payment-request",
                DisabledApi::SharedMemoryAndAtomics => "shared-memory-and-atomics",
            }
        }
        for v in DisabledApi::ALL {
            assert!(!route(*v).is_empty());
        }
    }

    #[test]
    fn disable_mechanism_dispatch_is_exhaustive_friendly() {
        fn arm(m: DisableMechanism) -> &'static str {
            match m {
                DisableMechanism::NavigatorPropertyDeleted => "navigator-property-deleted",
                DisableMechanism::ConstructorThrows => "constructor-throws",
                DisableMechanism::SpecialCase => "special-case",
            }
        }
        for v in DisabledApi::ALL {
            assert!(!arm(v.disable_mechanism()).is_empty());
        }
    }

    #[test]
    fn disabled_api_types_are_send_sync() {
        // The libxul bridge holds the list across renderer
        // processes within an identity group (§3.2 renderer-
        // sharing).
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DisabledApi>();
        assert_send_sync::<DisableMechanism>();
    }
}
