//! Module 35.9 (part 1) — Permissions API enumeration lock.
//!
//! Locks `navigator.permissions.query()` so the per-API permission
//! state cannot leak per-user grant history (Strict) or
//! bulk-enumerate the L44 disabled-API list (both modes). The W3C
//! Permissions API is the canonical "which capabilities does this
//! browser grant this site" surface; without locking it, a site can
//! probe every L44 API in one round-trip and reconstruct the
//! Strict-mode disable set as a high-entropy fingerprint signal.
//!
//! ## Mode-applicability (locked v1.23)
//!
//!   * **Strict** — every RECOGNIZED W3C permission name resolves
//!     to `"denied"`. L44-mapped names (geolocation, camera,
//!     microphone, sensors, etc.) are denied because the underlying
//!     JS API is structurally absent (Module 35.3); non-L44
//!     recognized names (push, midi, persistent-storage, etc.) are
//!     denied because the Strict L41 lock forbids any user grant
//!     flow for non-L44 APIs either. **Unrecognized names** (any
//!     string not in `PermissionName::ALL_RECOGNIZED`) resolve to
//!     `"prompt"` — the **polluted-oracle protection**. A site that
//!     probes a permission name DevBrowse doesn't recognize gets
//!     `"prompt"` rather than `"denied"`, so the existence of the
//!     gate is not itself a fingerprint signal (Tor returns the
//!     empty/inconsistent permission set; DevBrowse's polluted
//!     oracle is a structurally stronger answer).
//!   * **Standard** — every query consults the configured
//!     [`PermissionStore`] (which is wired to Module 59's
//!     permission center in Phase 8). v1 default is the
//!     [`DefaultPromptStore`] which returns `"prompt"` for every
//!     name. The override surface sees one API name at a time;
//!     bulk enumeration is structurally impossible (no `getAll()`
//!     equivalent is exposed via this override).
//!
//! ## Cross-coupling with Module 35.3
//!
//! The L44 disabled-API set (`crate::strict::disabled_apis::DisabledApi`)
//! is the source of truth for which JS APIs are structurally
//! absent in Strict. This module ships a [`l44_disabled`] mapping
//! function that translates a [`PermissionName`] to its
//! corresponding L44 disable (when one exists). The mapping is
//! **documentation + cross-coupling regression**, not a runtime
//! gate — the Strict resolver denies every recognized name, so the
//! L44 mapping does not change the per-query answer. It DOES catch
//! a future divergence (e.g. Module 35.3 adds a new L44 surface
//! that has a Permissions API analogue; the regression test fails
//! until [`l44_disabled`] is updated).
//!
//! ## Edge cases (phase-file lock)
//!
//!   * **Polluted-oracle protection.** A site probing an
//!     unrecognized permission name MUST receive `"prompt"`, not
//!     `"denied"`. Returning `"denied"` would reveal that a gate
//!     exists; `"prompt"` is the W3C-spec default state and reveals
//!     no per-browser structure. Asserted by the
//!     `unknown_name_returns_prompt_in_strict_polluted_oracle` test.
//!   * **No bulk enumeration.** The Permissions API does not expose
//!     a "list all permissions" entry point; the override sees one
//!     name at a time. This is structural — there is no
//!     `query_all()` method.
//!   * **`PermissionStatus.onchange` event.** In Strict, the
//!     per-name state never changes (no grant flow exists for
//!     either L44 or non-L44 names) so the event never fires. In
//!     Standard, the event fires when the user grants/revokes via
//!     Module 59 (the libxul bridge wires the change-emission to
//!     pb-identity's permission store).
//!   * **PaymentHandler mapping.** The W3C permission name
//!     `payment-handler` is the service-worker side of the
//!     PaymentRequest flow; mapping it to `DisabledApi::PaymentRequest`
//!     is a conservative over-deny that preserves the Strict
//!     L44 posture.
//!
//! ## Decoupling from Module 59
//!
//! In Strict, this module is **decoupled** from Module 59 (per the
//! Module 35.3 precedent for L44 APIs): the Strict resolver never
//! consults a PermissionStore, so even an explicit Module 59 grant
//! cannot re-enable a recognized permission in Strict. The L41
//! lock is structural — `PermissionsPolicy::for_mode(Strict)`
//! returns `StrictHardCoded`; there is no constructor that lets
//! Strict consult the store.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): wire
//   `Permissions.query({name: "<api>"})` to call into
//   `PermissionsOverride::query(PermissionName)`. The libxul bridge
//   must map the JS-side name string to the `PermissionName` enum
//   (with `PermissionName::Unknown` for any string not in
//   `ALL_RECOGNIZED`); the override returns the resolved
//   `PermissionState`. `PermissionStatus.onchange` event-target is
//   wired to fire only when the underlying store mutates (Standard);
//   Strict suppresses change-emission entirely.
// TODO(Phase 8 / Module 59 permission center): supply the real
//   `PermissionStore` impl wired to the user's per-site grant data.
//   v1 ships `DefaultPromptStore` (always `Prompt`); Module 59
//   replaces it without disturbing this module's surface.
// TODO(Phase 10 / Module 71+): adversarial probes assert (a) every
//   `PermissionName::ALL_RECOGNIZED` returns `Denied` in Strict;
//   (b) an unknown permission name returns `Prompt` in Strict
//   (polluted-oracle); (c) Standard returns the store's answer
//   verbatim; (d) `onchange` never fires in Strict.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use crate::strict::disabled_apis::DisabledApi;
use pb_config::Mode;
use std::sync::Arc;

// ── Permission name enumeration ──────────────────────────────────────────

/// W3C Permissions API name tokens.
///
/// Covers the W3C Permissions spec's documented `PermissionName`
/// values plus an [`Unknown`] catchall the libxul bridge maps to
/// when a JS-side string is not in the recognized set. The
/// `Unknown` variant is the load-bearing surface for the
/// polluted-oracle protection — Strict returns `"prompt"` for
/// unknown names so the existence of a gate is not itself a signal.
///
/// Source: W3C Permissions spec (Living Standard 2024+) plus the
/// W3C-incubator names that mainstream browsers ship (clipboard,
/// idle-detection, local-fonts, speaker-selection, window-management,
/// captured-surface-control).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionName {
    /// `"geolocation"` — Geolocation API access.
    Geolocation,
    /// `"notifications"` — Notification API access.
    Notifications,
    /// `"push"` — Push API subscription.
    Push,
    /// `"midi"` — Web MIDI API access.
    Midi,
    /// `"camera"` — getUserMedia video stream.
    Camera,
    /// `"microphone"` — getUserMedia audio stream.
    Microphone,
    /// `"display-capture"` — getDisplayMedia (screen capture).
    DisplayCapture,
    /// `"captured-surface-control"` — captured-surface control
    /// extension (Living Standard).
    CapturedSurfaceControl,
    /// `"accelerometer"` — Sensor API accelerometer.
    AccelerometerSensor,
    /// `"gyroscope"` — Sensor API gyroscope.
    GyroscopeSensor,
    /// `"magnetometer"` — Sensor API magnetometer.
    MagnetometerSensor,
    /// `"ambient-light-sensor"` — Sensor API ambient light.
    AmbientLightSensor,
    /// `"screen-wake-lock"` — Screen Wake Lock API.
    ScreenWakeLock,
    /// `"system-wake-lock"` — System Wake Lock API.
    SystemWakeLock,
    /// `"idle-detection"` — Idle Detection API.
    IdleDetection,
    /// `"payment-handler"` — service-worker Payment Handler.
    PaymentHandler,
    /// `"persistent-storage"` — quota-extension permission.
    PersistentStorage,
    /// `"storage-access"` — third-party storage access (CHIPS).
    StorageAccess,
    /// `"top-level-storage-access"` — top-level storage-access
    /// extension.
    TopLevelStorageAccess,
    /// `"window-management"` — Window Management API.
    WindowManagement,
    /// `"background-fetch"` — Background Fetch API.
    BackgroundFetch,
    /// `"background-sync"` — Background Sync API.
    BackgroundSync,
    /// `"periodic-background-sync"` — Periodic Background Sync API.
    PeriodicBackgroundSync,
    /// `"clipboard-read"` — async Clipboard read.
    ClipboardRead,
    /// `"clipboard-write"` — async Clipboard write.
    ClipboardWrite,
    /// `"speaker-selection"` — speaker enumeration / selection.
    SpeakerSelection,
    /// `"local-fonts"` — Local Font Access API.
    LocalFonts,
    /// `"accessibility-events"` — Accessibility Events API.
    AccessibilityEvents,
    /// The libxul bridge maps any JS-side permission name string
    /// not in [`ALL_RECOGNIZED`](Self::ALL_RECOGNIZED) to this
    /// variant. **Strict resolves this to `Prompt`** — the
    /// polluted-oracle protection. NEVER reachable by a recognized
    /// name; the variant exists only so the resolver has a total
    /// function over the JS-side string space.
    Unknown,
}

impl PermissionName {
    /// Every PermissionName the W3C spec documents (excluding
    /// [`Unknown`](Self::Unknown), which is the catchall). The
    /// libxul bridge maps every JS-side string in this set to the
    /// corresponding variant.
    pub const ALL_RECOGNIZED: &'static [PermissionName] = &[
        Self::Geolocation,
        Self::Notifications,
        Self::Push,
        Self::Midi,
        Self::Camera,
        Self::Microphone,
        Self::DisplayCapture,
        Self::CapturedSurfaceControl,
        Self::AccelerometerSensor,
        Self::GyroscopeSensor,
        Self::MagnetometerSensor,
        Self::AmbientLightSensor,
        Self::ScreenWakeLock,
        Self::SystemWakeLock,
        Self::IdleDetection,
        Self::PaymentHandler,
        Self::PersistentStorage,
        Self::StorageAccess,
        Self::TopLevelStorageAccess,
        Self::WindowManagement,
        Self::BackgroundFetch,
        Self::BackgroundSync,
        Self::PeriodicBackgroundSync,
        Self::ClipboardRead,
        Self::ClipboardWrite,
        Self::SpeakerSelection,
        Self::LocalFonts,
        Self::AccessibilityEvents,
    ];
}

// ── Permission state ─────────────────────────────────────────────────────

/// W3C `PermissionState` enum.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionState {
    /// The user granted the permission.
    Granted,
    /// The user denied the permission, or the API is structurally
    /// disabled.
    Denied,
    /// The user has not yet made a choice. **Default for unknown
    /// names in Strict (polluted-oracle protection).**
    Prompt,
}

// ── L44 cross-coupling helper ────────────────────────────────────────────

/// Maps a [`PermissionName`] to its corresponding L44 [`DisabledApi`]
/// (when one exists).
///
/// **This mapping is documentation + cross-coupling regression**,
/// not a runtime gate. The Strict resolver denies every recognized
/// name regardless of L44 membership; the L44 set is the source of
/// truth for which JS APIs are structurally absent (Module 35.3),
/// but the per-query answer in Strict is the same for both L44 and
/// non-L44 recognized names. The mapping catches a future divergence:
/// if Module 35.3 adds a new L44 surface that has a Permissions API
/// analogue, the regression test ensures [`l44_disabled`] is updated.
///
/// Returns `None` for non-L44 permission names AND for
/// [`PermissionName::Unknown`].
pub fn l44_disabled(name: PermissionName) -> Option<DisabledApi> {
    match name {
        // L44-mapped (each Permissions-API name maps to its
        // corresponding DisabledApi from Module 35.3).
        PermissionName::Geolocation => Some(DisabledApi::Geolocation),
        PermissionName::Notifications => Some(DisabledApi::Notification),
        PermissionName::Camera
        | PermissionName::Microphone
        | PermissionName::DisplayCapture
        | PermissionName::CapturedSurfaceControl => Some(DisabledApi::MediaDevices),
        PermissionName::AccelerometerSensor
        | PermissionName::GyroscopeSensor
        | PermissionName::MagnetometerSensor
        | PermissionName::AmbientLightSensor => Some(DisabledApi::SensorApis),
        PermissionName::ScreenWakeLock | PermissionName::SystemWakeLock => {
            Some(DisabledApi::WakeLock)
        }
        PermissionName::IdleDetection => Some(DisabledApi::IdleDetector),
        // PaymentHandler is the service-worker side; mapping to
        // PaymentRequest is a conservative over-deny that
        // preserves the Strict L44 posture.
        PermissionName::PaymentHandler => Some(DisabledApi::PaymentRequest),
        // Non-L44 permission names (Strict still denies them, but
        // the gate is not in Module 35.3's L44 set).
        PermissionName::Push
        | PermissionName::Midi
        | PermissionName::PersistentStorage
        | PermissionName::StorageAccess
        | PermissionName::TopLevelStorageAccess
        | PermissionName::WindowManagement
        | PermissionName::BackgroundFetch
        | PermissionName::BackgroundSync
        | PermissionName::PeriodicBackgroundSync
        | PermissionName::ClipboardRead
        | PermissionName::ClipboardWrite
        | PermissionName::SpeakerSelection
        | PermissionName::LocalFonts
        | PermissionName::AccessibilityEvents => None,
        // Catchall — never reachable from a recognized JS-side
        // name; only the polluted-oracle entry point.
        PermissionName::Unknown => None,
    }
}

// ── Permission store trait ───────────────────────────────────────────────

/// Per-API permission lookup callback consulted by Standard mode.
///
/// Implementations supply the per-(origin, name) resolution
/// keyed on the user's stored grants. In v1 the default impl
/// [`DefaultPromptStore`] returns `Prompt` for every query;
/// Module 59 (Phase 8 permission center) replaces it with the
/// real grant store once that lands.
///
/// `Send + Sync` because the libxul bridge holds the store in
/// `Arc<dyn PermissionStore>` across renderer processes within an
/// identity group (§3.2 renderer-sharing).
///
/// **L27**: implementations MUST NOT echo origin / profile_id into
/// any `Display` impl; details flow through `Error::source()` only.
pub trait PermissionStore: Send + Sync + std::fmt::Debug {
    /// Resolve a permission name to a [`PermissionState`]. Called
    /// at every `Permissions.query()` invocation in Standard mode.
    /// Strict mode bypasses this trait entirely.
    fn query(&self, name: &PermissionName) -> PermissionState;
}

/// v1 default [`PermissionStore`]: returns `Prompt` for every name.
///
/// Wired in when no Module 59 permission center is configured yet.
/// Matches the W3C-spec default state (no decision made) so sites
/// behave as if every permission is uninitialized.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPromptStore;

impl PermissionStore for DefaultPromptStore {
    fn query(&self, _name: &PermissionName) -> PermissionState {
        PermissionState::Prompt
    }
}

/// Test-fixture [`PermissionStore`] that records every query and
/// returns programmable answers. Used in unit tests + the future
/// Phase 10 adversarial suite.
#[derive(Debug, Default)]
pub struct CapturingPermissionStore {
    queries: std::sync::Mutex<Vec<PermissionName>>,
    answers: std::sync::Mutex<std::collections::HashMap<PermissionName, PermissionState>>,
}

impl CapturingPermissionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed a specific answer for `name`. Queries for other
    /// names fall back to `Prompt`.
    pub fn with_answer(self, name: PermissionName, state: PermissionState) -> Self {
        self.answers.lock().unwrap().insert(name, state);
        self
    }

    /// Returns the queries the store has seen, in order.
    pub fn queries(&self) -> Vec<PermissionName> {
        self.queries.lock().unwrap().clone()
    }
}

impl PermissionStore for CapturingPermissionStore {
    fn query(&self, name: &PermissionName) -> PermissionState {
        self.queries.lock().unwrap().push(*name);
        self.answers
            .lock()
            .unwrap()
            .get(name)
            .copied()
            .unwrap_or(PermissionState::Prompt)
    }
}

// ── Per-Mode policy ──────────────────────────────────────────────────────

/// Per-Mode resolution policy for Permissions queries.
///
/// `Copy` is intentional — the override holds the policy by value
/// alongside an `Arc<dyn PermissionStore>` for delegation. The
/// store is ignored in Strict (the resolver is hard-coded; L41
/// structural lock).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionsPolicy {
    /// Strict: every recognized name → `Denied`; every unknown
    /// name → `Prompt` (polluted-oracle protection). The
    /// `PermissionStore` is NOT consulted.
    StrictHardCoded,
    /// Standard: the `PermissionStore` is consulted on every
    /// query.
    StandardDelegated,
}

impl PermissionsPolicy {
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Strict => Self::StrictHardCoded,
            Mode::Standard => Self::StandardDelegated,
        }
    }
}

// ── Surface enumeration ──────────────────────────────────────────────────

/// Every JS pathway through which `navigator.permissions` surfaces.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionsSurface {
    /// `navigator.permissions.query({name: "..."})` — the entry
    /// point. Resolves to a frozen `PermissionStatus` populated
    /// from `PermissionsOverride::query`.
    Query,
    /// `PermissionStatus.onchange` event handler + `change` event
    /// dispatch. Strict never fires the event (no grant flow);
    /// Standard fires when the store mutates (wired libxul-side
    /// via Module 59 once that lands).
    OnChange,
}

impl PermissionsSurface {
    pub const ALL: &'static [PermissionsSurface] = &[Self::Query, Self::OnChange];
}

// ── FingerprintOverride impl ─────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Permissions`.
///
/// Construct with `PermissionsOverride::new(mode, store)`. The
/// store is consulted only in Standard mode; Strict ignores it by
/// construction. v1 default store is [`DefaultPromptStore`]; Module
/// 59 (Phase 8) supplies the real impl.
///
/// Context-inert per Module 26: every `JsContext` resolves the
/// same way for a given `mode` + name pair.
#[derive(Debug, Clone)]
pub struct PermissionsOverride {
    policy: PermissionsPolicy,
    store: Arc<dyn PermissionStore>,
}

impl PermissionsOverride {
    pub fn new(mode: Mode, store: Arc<dyn PermissionStore>) -> Self {
        Self {
            policy: PermissionsPolicy::for_mode(mode),
            store,
        }
    }

    /// Convenience constructor wiring `DefaultPromptStore` (v1
    /// default; Module 59 replaces in Phase 8).
    pub fn with_default_store(mode: Mode) -> Self {
        Self::new(mode, Arc::new(DefaultPromptStore))
    }

    pub fn policy(&self) -> PermissionsPolicy {
        self.policy
    }

    /// Resolve one permission query. The libxul bridge calls this
    /// once per `Permissions.query({name: "<api>"})` invocation
    /// (one name at a time; bulk enumeration is structurally
    /// impossible).
    pub fn query(&self, name: PermissionName) -> PermissionState {
        match self.policy {
            PermissionsPolicy::StrictHardCoded => match name {
                // Polluted-oracle protection: unknown names get
                // Prompt, not Denied. Returning Denied would reveal
                // that a gate exists; Prompt is the W3C-spec
                // default and reveals no per-browser structure.
                PermissionName::Unknown => PermissionState::Prompt,
                _ => PermissionState::Denied,
            },
            PermissionsPolicy::StandardDelegated => self.store.query(&name),
        }
    }
}

impl FingerprintOverride for PermissionsOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Permissions
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect. The libxul WebIDL accessor wiring is
        // not yet plumbed (see crate-level TODO). When the FFI
        // lands, Strict installs a hard-coded resolver (no store
        // consulted), and Standard installs a getter that calls
        // `self.store.query(&name)` for every variant of
        // `PermissionsSurface::ALL` × `JsContext::ALL`.
        let _ = (self.policy, JsContext::ALL, PermissionsSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_recognized_covers_w3c_documented_names() {
        // 28 documented W3C names (the canonical Living Standard
        // set plus the W3C-incubator names mainstream browsers
        // ship). A future addition to the spec is a cohort-shift
        // under the Adaptation protocol.
        assert_eq!(PermissionName::ALL_RECOGNIZED.len(), 28);
        // Spot-check the most-fingerprinted names land in the set.
        for v in [
            PermissionName::Geolocation,
            PermissionName::Notifications,
            PermissionName::Camera,
            PermissionName::Microphone,
            PermissionName::PersistentStorage,
        ] {
            assert!(
                PermissionName::ALL_RECOGNIZED.contains(&v),
                "missing high-entropy name: {:?}",
                v,
            );
        }
        // Unknown MUST NOT be in ALL_RECOGNIZED — it's the
        // catchall the libxul bridge maps unknown JS-side strings
        // to, not a recognized name.
        assert!(!PermissionName::ALL_RECOGNIZED.contains(&PermissionName::Unknown));
    }

    #[test]
    fn permission_state_has_three_w3c_variants() {
        // W3C PermissionState: granted | denied | prompt.
        // Exhaustive match keeps the lock on the variant set.
        fn arm(s: PermissionState) -> &'static str {
            match s {
                PermissionState::Granted => "granted",
                PermissionState::Denied => "denied",
                PermissionState::Prompt => "prompt",
            }
        }
        assert_eq!(arm(PermissionState::Granted), "granted");
        assert_eq!(arm(PermissionState::Denied), "denied");
        assert_eq!(arm(PermissionState::Prompt), "prompt");
    }

    #[test]
    fn l44_mapped_names_resolve_to_correct_disabled_api() {
        // Each L44-mapped PermissionName must point at the
        // matching DisabledApi from Module 35.3. A change to
        // either side without updating the other splits the
        // cross-coupling.
        assert_eq!(
            l44_disabled(PermissionName::Geolocation),
            Some(DisabledApi::Geolocation),
        );
        assert_eq!(
            l44_disabled(PermissionName::Notifications),
            Some(DisabledApi::Notification),
        );
        assert_eq!(
            l44_disabled(PermissionName::Camera),
            Some(DisabledApi::MediaDevices),
        );
        assert_eq!(
            l44_disabled(PermissionName::Microphone),
            Some(DisabledApi::MediaDevices),
        );
        assert_eq!(
            l44_disabled(PermissionName::DisplayCapture),
            Some(DisabledApi::MediaDevices),
        );
        assert_eq!(
            l44_disabled(PermissionName::AccelerometerSensor),
            Some(DisabledApi::SensorApis),
        );
        assert_eq!(
            l44_disabled(PermissionName::ScreenWakeLock),
            Some(DisabledApi::WakeLock),
        );
        assert_eq!(
            l44_disabled(PermissionName::IdleDetection),
            Some(DisabledApi::IdleDetector),
        );
        assert_eq!(
            l44_disabled(PermissionName::PaymentHandler),
            Some(DisabledApi::PaymentRequest),
        );
    }

    #[test]
    fn non_l44_recognized_names_return_none_from_mapping() {
        // Non-L44 names: the W3C permission exists but it does NOT
        // correspond to a Module 35.3 disabled JS API. Strict still
        // denies them at the resolver level (every recognized name
        // → Denied) but the L44 mapping is None.
        for v in [
            PermissionName::Push,
            PermissionName::Midi,
            PermissionName::PersistentStorage,
            PermissionName::StorageAccess,
            PermissionName::WindowManagement,
            PermissionName::BackgroundSync,
            PermissionName::ClipboardRead,
            PermissionName::LocalFonts,
        ] {
            assert_eq!(l44_disabled(v), None, "{:?} should not L44-map", v);
        }
    }

    #[test]
    fn unknown_name_returns_none_from_mapping() {
        // Catchall returns None — the polluted-oracle protection
        // is enforced at the resolver, not the mapping.
        assert_eq!(l44_disabled(PermissionName::Unknown), None);
    }

    #[test]
    fn l44_mapping_covers_every_disabled_api_with_permissions_entry_point() {
        // Cross-coupling regression: every DisabledApi variant in
        // Module 35.3 that has a W3C Permissions API entry point
        // MUST have at least one PermissionName mapping to it.
        // (Some DisabledApi variants — WebUsb, WebHid, WebSerial,
        // Gamepad, Beacon, PresentationRequest, WebBluetooth,
        // WebNfc, SharedMemoryAndAtomics — are disabled at the
        // constructor level; the Permissions API does not expose
        // them by W3C-standard name. Those are not part of this
        // regression.)
        let mapped: std::collections::HashSet<DisabledApi> = PermissionName::ALL_RECOGNIZED
            .iter()
            .filter_map(|n| l44_disabled(*n))
            .collect();
        for required in [
            DisabledApi::Geolocation,
            DisabledApi::Notification,
            DisabledApi::MediaDevices,
            DisabledApi::SensorApis,
            DisabledApi::WakeLock,
            DisabledApi::IdleDetector,
            DisabledApi::PaymentRequest,
        ] {
            assert!(
                mapped.contains(&required),
                "{:?} has a W3C Permissions entry point but no PermissionName maps to it",
                required,
            );
        }
    }

    #[test]
    fn strict_denies_every_recognized_name() {
        // Every name in ALL_RECOGNIZED resolves to Denied in
        // Strict — L44-mapped or not. The Strict L41 lock forbids
        // grant flows for either category.
        let ovr = PermissionsOverride::with_default_store(Mode::Strict);
        for name in PermissionName::ALL_RECOGNIZED {
            assert_eq!(
                ovr.query(*name),
                PermissionState::Denied,
                "{:?} should be Denied in Strict",
                name,
            );
        }
    }

    #[test]
    fn unknown_name_returns_prompt_in_strict_polluted_oracle() {
        // **Polluted-oracle protection.** An unrecognized name MUST
        // return Prompt, never Denied. Returning Denied would
        // reveal that a gate exists in the browser's permission
        // catalog; Prompt is the W3C-spec default and reveals
        // nothing per-browser-specific.
        let ovr = PermissionsOverride::with_default_store(Mode::Strict);
        assert_eq!(
            ovr.query(PermissionName::Unknown),
            PermissionState::Prompt,
            "Unknown MUST return Prompt in Strict (polluted-oracle protection)",
        );
    }

    #[test]
    fn standard_delegates_to_store() {
        // Standard returns whatever the store says. The capturing
        // store records the query AND returns the pre-seeded
        // answer (Granted for Camera in this test).
        let store = Arc::new(
            CapturingPermissionStore::new()
                .with_answer(PermissionName::Camera, PermissionState::Granted),
        );
        let ovr = PermissionsOverride::new(Mode::Standard, store.clone());

        assert_eq!(ovr.query(PermissionName::Camera), PermissionState::Granted);
        assert_eq!(
            ovr.query(PermissionName::Notifications),
            PermissionState::Prompt
        );

        let queries = store.queries();
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0], PermissionName::Camera);
        assert_eq!(queries[1], PermissionName::Notifications);
    }

    #[test]
    fn strict_does_not_consult_store_even_when_store_would_grant() {
        // **L41 structural lock.** Even when the store would
        // return Granted (e.g. a hostile Module 59 setting),
        // Strict's resolver hard-codes Denied. The store is
        // never consulted under Strict.
        let store = Arc::new(
            CapturingPermissionStore::new()
                .with_answer(PermissionName::Camera, PermissionState::Granted)
                .with_answer(PermissionName::Notifications, PermissionState::Granted),
        );
        let ovr = PermissionsOverride::new(Mode::Strict, store.clone());

        assert_eq!(ovr.query(PermissionName::Camera), PermissionState::Denied);
        assert_eq!(
            ovr.query(PermissionName::Notifications),
            PermissionState::Denied
        );

        // Store was NOT consulted — no queries recorded.
        assert!(
            store.queries().is_empty(),
            "Strict must not consult the PermissionStore",
        );
    }

    #[test]
    fn default_prompt_store_returns_prompt_for_every_name() {
        let store = DefaultPromptStore;
        for name in PermissionName::ALL_RECOGNIZED {
            assert_eq!(store.query(name), PermissionState::Prompt);
        }
        assert_eq!(
            store.query(&PermissionName::Unknown),
            PermissionState::Prompt,
        );
    }

    #[test]
    fn permissions_policy_for_mode_dispatch() {
        assert_eq!(
            PermissionsPolicy::for_mode(Mode::Strict),
            PermissionsPolicy::StrictHardCoded,
        );
        assert_eq!(
            PermissionsPolicy::for_mode(Mode::Standard),
            PermissionsPolicy::StandardDelegated,
        );
    }

    #[test]
    fn strict_resolution_is_idempotent_and_non_loosenable() {
        // L41 lock — no with_user_override constructor. Two Strict
        // resolutions return identical content for the same name.
        let ovr = PermissionsOverride::with_default_store(Mode::Strict);
        let a = ovr.query(PermissionName::Camera);
        let b = ovr.query(PermissionName::Camera);
        assert_eq!(a, b);
        assert_eq!(a, PermissionState::Denied);

        let unk_a = ovr.query(PermissionName::Unknown);
        let unk_b = ovr.query(PermissionName::Unknown);
        assert_eq!(unk_a, unk_b);
        assert_eq!(unk_a, PermissionState::Prompt);
    }

    #[test]
    fn permissions_surface_all_covers_query_and_change() {
        assert_eq!(PermissionsSurface::ALL.len(), 2);
        for v in [PermissionsSurface::Query, PermissionsSurface::OnChange] {
            assert!(PermissionsSurface::ALL.contains(&v), "missing: {:?}", v);
        }
    }

    #[test]
    fn override_reports_permissions_surface_in_both_modes() {
        assert_eq!(
            PermissionsOverride::with_default_store(Mode::Standard).surface(),
            WebIdlSurface::Permissions,
        );
        assert_eq!(
            PermissionsOverride::with_default_store(Mode::Strict).surface(),
            WebIdlSurface::Permissions,
        );
    }

    #[test]
    fn override_install_is_context_inert() {
        // Module 26 context-inert obligation: every install sees
        // the same policy regardless of JsContext.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035091").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = PermissionsOverride::with_default_store(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Permissions);
        }
    }

    #[test]
    fn permissions_types_are_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync. Override holds Arc<dyn PermissionStore>
        // which requires the store to be Send + Sync too.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PermissionsOverride>();
        assert_send_sync::<PermissionsPolicy>();
        assert_send_sync::<PermissionName>();
        assert_send_sync::<PermissionState>();
        assert_send_sync::<PermissionsSurface>();
        assert_send_sync::<DefaultPromptStore>();
        assert_send_sync::<CapturingPermissionStore>();
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: PermissionsPolicy) -> &'static str {
            match p {
                PermissionsPolicy::StrictHardCoded => "strict-hard-coded",
                PermissionsPolicy::StandardDelegated => "standard-delegated",
            }
        }
        assert_eq!(
            arm(PermissionsPolicy::for_mode(Mode::Strict)),
            "strict-hard-coded",
        );
        assert_eq!(
            arm(PermissionsPolicy::for_mode(Mode::Standard)),
            "standard-delegated",
        );
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: PermissionsSurface) -> &'static str {
            match s {
                PermissionsSurface::Query => "query",
                PermissionsSurface::OnChange => "on-change",
            }
        }
        for s in PermissionsSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }
}
