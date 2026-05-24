//! Module 36 — GPU coordinator.
//!
//! Owns the singleton WebGPU / WebGL adapter handle for the GPU
//! process. Mediates per-identity allocation requests through
//! opaque [`ScopeToken`]s consumed by Module 37 (memory budget),
//! Module 38 (queue isolation), and Module 39 (timing
//! quantization).
//!
//! ## Architecture references
//!
//!   * **L12** — pb-gpu cannot import pb-fingerprint or
//!     pb-identity (only pb-ipc / pb-config / pb-sandbox are
//!     cross-importable). The cohort-locked GPU surface is
//!     therefore owned independently here and pinned to
//!     Module 35.6's JS-facing surface by paired literal-value
//!     assertions (mirrors the pb-network / pb-fingerprint
//!     `DEVBROWSE_USER_AGENT` pattern at
//!     crates/pb-network/src/headers.rs:365-379).
//!   * **L13** — `#![forbid(unsafe_code)]` at the crate root.
//!     Real `wgpu::Adapter` / libxul GPU bridge wiring is Phase 11
//!     (Module 80); when it lands it goes in a separate FFI
//!     submodule with `#[allow(unsafe_code)]` (per crate-root
//!     doc in `lib.rs`).
//!   * **Module 35.6 (pb-fingerprint, WebGPU)** — the
//!     JS-observable `GPUAdapter.features` / `.limits` / `.info`
//!     surface is pinned to `LOCKED_WEBGPU_PROFILE`. pb-gpu owns
//!     the production allocation envelope and MUST agree with
//!     that surface byte-for-byte (otherwise a renderer probing
//!     via JS would see a different `max_buffer_size` than the
//!     value the kernel-side allocator enforces, splitting the
//!     cohort along host hardware lines). Cross-coupling pinned
//!     by `locked_limits_match_module_35_6_webgpu_spec_minima`
//!     + `cohort_vendor_matches_module_35_6` below.
//!   * **Module 28 (pb-fingerprint, WebGL)** — cohort vendor
//!     string is `"Mozilla"` for both WebGL and WebGPU surfaces;
//!     pb-gpu's [`COHORT_VENDOR`] matches.
//!   * **Phase 6 edge case** — adapter loss recovery (driver
//!     crash) MUST NOT leak partial state across identities.
//!     Enforced by the coordinator's monotonic epoch counter:
//!     [`GpuCoordinator::recover_after_loss`] bumps the epoch,
//!     and every previously-issued [`ScopeToken`] (across all
//!     identities) becomes stale and is rejected by
//!     [`GpuCoordinator::validate`].
//!
//! ## Cross-platform principle
//!
//! Public API is identical on Linux / macOS (and Windows once
//! Phase 11.9 ships; iOS / Android in Phase 12). The stub
//! adapter-discovery path returns [`AdapterDescriptor::COHORT_LOCKED`]
//! on every platform; the real per-platform adapter probe lives
//! behind the future libxul bridge.
//
// TODO(Phase 11 / Module 80 — libxul GPU FFI bridge): replace the
//   stub adapter-discovery path with a real `wgpu::Instance` /
//   libxul-bridge probe. The probe MUST still funnel through
//   `AdapterDescriptor::COHORT_LOCKED` for the JS-observable
//   fields; only the kernel-side allocator gets the raw host
//   handle. The handle is held entirely inside pb-gpu and never
//   crosses the IPC boundary into a renderer.
// TODO(Module 37 — memory budget): consumes `ScopeToken` to key
//   per-identity allocation counters. Adapter-loss epoch bump
//   here is what forces Module 37 to drop every per-identity
//   bucket atomically.
// TODO(Module 38 — queue isolation): consumes `ScopeToken` to key
//   per-identity command queues. Adapter-loss epoch bump
//   invalidates queued command buffers.
// TODO(Module 39 — timing quantization): does NOT consume
//   `ScopeToken` directly; instead consults the coordinator for
//   the cohort-locked 2 ms timer-query resolution (mirrors
//   Module 32 for the GPU domain). Cross-coupling regression
//   will live in Module 39's own file.
// TODO(Phase 10 — adversarial fingerprint suite): a live probe
//   asserts `GPUAdapter.requestDevice({ requiredFeatures: [...]
//   })` rejects every feature NOT in `LOCKED_GPU_FEATURES`. The
//   probe drives pb-gpu indirectly via a spawned renderer; the
//   property here is that pb-gpu's enforced allowlist agrees
//   with Module 35.6's advertised allowlist.

use pb_config::Mode;
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

// ── Cohort-locked GPU surface ────────────────────────────────────────────

/// Cohort vendor string for the GPU adapter.
///
/// Byte-equals `pb_fingerprint::gecko::webgpu::LOCKED_WEBGPU_PROFILE.vendor.as_str()`
/// and `pb_fingerprint::gecko::webgl::LOCKED_WEBGL_PROFILE.vendor`.
/// A renderer seeing a different vendor here vs the JS surface
/// would split the cohort. Pinned by the paired regression test
/// `cohort_vendor_matches_module_35_6` below.
pub const COHORT_VENDOR: &str = "Mozilla";

/// Cohort-fixed adapter feature list.
///
/// Empty in v1 — every optional WebGPU feature would split the
/// cohort along hardware lines (e.g. `"timestamp-query"` is only
/// available on discrete GPUs of certain vintages). Byte-equals
/// `pb_fingerprint::gecko::webgpu::LOCKED_WEBGPU_PROFILE.features`.
pub const LOCKED_GPU_FEATURES: &[&str] = &[];

/// Cohort-locked WebGPU spec-minimum adapter limits.
///
/// Mirrors `pb_fingerprint::gecko::webgpu::LOCKED_WEBGPU_PROFILE.limits`
/// field-by-field and value-by-value. Pinned to the WebGPU spec
/// minima (https://www.w3.org/TR/webgpu/#limits) so the cohort is
/// indistinguishable from a minimal-spec conformant adapter.
///
/// `static` (not `const`): [`AdapterDescriptor::COHORT_LOCKED`]
/// references this by `&'static GpuLimits`; address identity is
/// asserted by `adapter_descriptor_references_locked_limits_by_address`.
pub static LOCKED_GPU_LIMITS: GpuLimits = GpuLimits {
    max_texture_dimension_1d: 8192,
    max_texture_dimension_2d: 8192,
    max_texture_dimension_3d: 2048,
    max_texture_array_layers: 256,
    max_bind_groups: 4,
    max_buffer_size: 268_435_456, // 256 MiB
    max_compute_workgroup_size_x: 256,
    max_compute_workgroup_size_y: 256,
    max_compute_workgroup_size_z: 64,
    max_compute_invocations_per_workgroup: 256,
};

/// Cohort-locked GPU adapter limits.
///
/// Field-for-field mirror of
/// `pb_fingerprint::gecko::webgpu::WebGpuLimits`. Both crates
/// own their own definition because L12 forbids cross-imports
/// between sibling leaves; the paired regression tests in this
/// file and in `crates/pb-fingerprint/src/gecko/webgpu.rs` are
/// what keeps them aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GpuLimits {
    pub max_texture_dimension_1d: u32,
    pub max_texture_dimension_2d: u32,
    pub max_texture_dimension_3d: u32,
    pub max_texture_array_layers: u32,
    pub max_bind_groups: u32,
    pub max_buffer_size: u64,
    pub max_compute_workgroup_size_x: u32,
    pub max_compute_workgroup_size_y: u32,
    pub max_compute_workgroup_size_z: u32,
    pub max_compute_invocations_per_workgroup: u32,
}

/// Cohort-locked adapter descriptor returned by
/// [`GpuCoordinator::adapter`].
///
/// All renderers, regardless of host GPU vendor / driver /
/// architecture, see the same descriptor. The real adapter
/// handle never crosses the IPC boundary into a renderer; only
/// this descriptor does. Mirrors Module 35.6's
/// `WebGpuReadbackPolicy::profile()` cohort base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AdapterDescriptor {
    /// Cohort vendor string. Always [`COHORT_VENDOR`] (`"Mozilla"`).
    pub vendor: &'static str,
    /// Cohort-fixed feature allowlist. Always [`LOCKED_GPU_FEATURES`].
    pub features: &'static [&'static str],
    /// Cohort-fixed adapter limits. Address-identical to
    /// [`LOCKED_GPU_LIMITS`] across every call (regression pinned
    /// by `adapter_descriptor_references_locked_limits_by_address`).
    pub limits: &'static GpuLimits,
}

impl AdapterDescriptor {
    /// The single cohort-locked descriptor pb-gpu hands out.
    /// Mode-invariant in v1; if Standard ever needs a richer
    /// descriptor (extra optional features, etc.) it MUST still
    /// go through the cohort-shift Adaptation protocol (README
    /// §"Adaptation protocol") not a per-host probe.
    pub const COHORT_LOCKED: AdapterDescriptor = AdapterDescriptor {
        vendor: COHORT_VENDOR,
        features: LOCKED_GPU_FEATURES,
        limits: &LOCKED_GPU_LIMITS,
    };
}

// ── Scope token ──────────────────────────────────────────────────────────

/// Opaque per-identity GPU scope token.
///
/// Issued by [`GpuCoordinator::issue_scope_token`]. Consumed by
/// Modules 37 / 38 (and future GPU sub-modules) to key
/// per-identity allocation buckets, command queues, and budget
/// counters. The token's interior fields are accessor-only; a
/// consumer cannot mint a token without going through the
/// coordinator.
///
/// ### Validity
///
///   * Carries the coordinator's epoch at issuance time. Adapter
///     loss + recovery bumps the epoch ([`GpuCoordinator::recover_after_loss`])
///     and every previously-issued token (across ALL identities)
///     becomes stale.
///   * Stale tokens are rejected by [`GpuCoordinator::validate`]
///     with [`CoordinatorError::StaleToken`]. This is the
///     load-bearing mechanism that prevents partial GPU state
///     from one identity from being observed by another after a
///     driver crash (phase-file Edge cases for Module 36).
///
/// ### Copy semantics
///
/// `Copy` so tokens can be passed across IPC and module
/// boundaries cheaply. The validity check is performed at the
/// boundary with the coordinator, not by passing references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeToken {
    profile_id: Uuid,
    mode: Mode,
    epoch: u64,
}

impl ScopeToken {
    /// The identity profile this token scopes allocations to.
    pub fn profile_id(self) -> Uuid {
        self.profile_id
    }

    /// The identity's mode at issuance time. Modules 37 / 38 may
    /// apply mode-specific policy (e.g. Strict gets a smaller
    /// memory budget) without re-querying the orchestrator.
    pub fn mode(self) -> Mode {
        self.mode
    }

    /// The coordinator epoch this token was issued under. Stale
    /// if it does not match `GpuCoordinator::epoch()`.
    pub fn epoch(self) -> u64 {
        self.epoch
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

/// GPU coordinator errors.
///
/// `Display` impls are opaque per L27 (forensic redaction); the
/// caller should NOT log the rendered string with identifying
/// context. Detail is intentionally absent — there is no `source`
/// for these because the cases are structural, not wrapped.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoordinatorError {
    /// The token's epoch is older than the coordinator's current
    /// epoch. Adapter has been lost and recovered since issuance;
    /// re-issue.
    #[error("gpu scope token is stale")]
    StaleToken,
    /// Adapter is not currently available (driver crash before
    /// recovery). Issuance refuses until
    /// [`GpuCoordinator::recover_after_loss`] runs.
    #[error("gpu adapter unavailable")]
    AdapterUnavailable,
}

// ── Coordinator ──────────────────────────────────────────────────────────

/// Internal coordinator state held under a single mutex. Bundling
/// `epoch` + `available` under one lock keeps the
/// "is-available-and-current-epoch" check atomic: a concurrent
/// `recover_after_loss` cannot squeeze in between an availability
/// check and an epoch read.
struct State {
    epoch: u64,
    available: bool,
}

/// Process-wide GPU coordinator.
///
/// Single instance per GPU process. Shared across all renderers
/// of every identity. Thread-safe — `Send + Sync`. Holds the
/// (stubbed for now) adapter handle and the epoch / availability
/// state machine.
pub struct GpuCoordinator {
    state: Mutex<State>,
}

impl GpuCoordinator {
    /// New coordinator. `epoch == 1`, adapter available.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                epoch: 1,
                available: true,
            }),
        }
    }

    /// The cohort-locked adapter descriptor. Always
    /// [`AdapterDescriptor::COHORT_LOCKED`]. Mode-invariant —
    /// every renderer in every identity sees the same value.
    pub fn adapter(&self) -> AdapterDescriptor {
        AdapterDescriptor::COHORT_LOCKED
    }

    /// Current epoch. Tokens whose `epoch()` does not match this
    /// value are stale.
    pub fn epoch(&self) -> u64 {
        self.state
            .lock()
            .expect("gpu coordinator lock poisoned")
            .epoch
    }

    /// Is the adapter currently available?
    pub fn is_available(&self) -> bool {
        self.state
            .lock()
            .expect("gpu coordinator lock poisoned")
            .available
    }

    /// Issue a new scope token for `profile_id` under `mode`.
    ///
    /// Fails with [`CoordinatorError::AdapterUnavailable`] if the
    /// adapter is not currently available (between a loss and a
    /// recovery).
    pub fn issue_scope_token(
        &self,
        profile_id: Uuid,
        mode: Mode,
    ) -> Result<ScopeToken, CoordinatorError> {
        let s = self.state.lock().expect("gpu coordinator lock poisoned");
        if !s.available {
            return Err(CoordinatorError::AdapterUnavailable);
        }
        Ok(ScopeToken {
            profile_id,
            mode,
            epoch: s.epoch,
        })
    }

    /// Validate a scope token. `Ok(())` iff the token's epoch
    /// matches the current epoch.
    ///
    /// Returns [`CoordinatorError::StaleToken`] for any token
    /// issued before the most recent
    /// [`Self::recover_after_loss`]. Does NOT check availability:
    /// a valid (current-epoch) token remains valid even if the
    /// adapter is currently unavailable, because availability is
    /// transient and the caller may simply retry.
    pub fn validate(&self, token: ScopeToken) -> Result<(), CoordinatorError> {
        let cur = self
            .state
            .lock()
            .expect("gpu coordinator lock poisoned")
            .epoch;
        if token.epoch == cur {
            Ok(())
        } else {
            Err(CoordinatorError::StaleToken)
        }
    }

    /// Driver crash / adapter loss event.
    ///
    /// Marks the adapter unavailable. Does NOT yet bump the
    /// epoch — outstanding tokens remain valid during the loss
    /// window so callers can detect their in-flight work was
    /// interrupted. The epoch bump (and consequent token
    /// invalidation) happens on [`Self::recover_after_loss`].
    pub fn on_adapter_loss(&self) {
        let mut s = self.state.lock().expect("gpu coordinator lock poisoned");
        s.available = false;
    }

    /// Recovery after a driver crash.
    ///
    /// Bumps the epoch (invalidating every previously-issued
    /// token across every identity — this is the load-bearing
    /// "no partial state leak across identities" property from
    /// the phase-file Edge cases) and marks the adapter available
    /// again.
    ///
    /// Idempotent in the sense that consecutive calls each bump
    /// the epoch by one and leave availability `true`; callers
    /// SHOULD pair `on_adapter_loss` and `recover_after_loss`
    /// 1:1 but a spurious extra recovery is not a security
    /// regression (it only invalidates additional tokens).
    pub fn recover_after_loss(&self) {
        let mut s = self.state.lock().expect("gpu coordinator lock poisoned");
        s.epoch = s.epoch.wrapping_add(1);
        s.available = true;
    }
}

impl Default for GpuCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Profile-id helpers — opaque UUIDs, deliberately not parsed
    // from a meaningful pattern. Two distinct values so cross-
    // identity tests can prove independence.
    fn pid_a() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000036001").unwrap()
    }
    fn pid_b() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000036002").unwrap()
    }

    // ── Cohort-locked surface ──────────────────────────────────────────

    #[test]
    fn cohort_vendor_is_mozilla() {
        // Cohort base shared with Module 28 (WebGL) + Module 35.6
        // (WebGPU). Drift is a cohort shift through the Adaptation
        // protocol.
        assert_eq!(COHORT_VENDOR, "Mozilla");
    }

    #[test]
    fn cohort_vendor_matches_module_35_6() {
        // CROSS-MODULE REGRESSION (Module 35.6). pb-gpu and
        // pb-fingerprint are L12 sibling leaves (neither imports
        // the other), so the cohort vendor alignment is enforced
        // by paired literal-string assertions. Mirror on the
        // pb-fingerprint side: `locked_profile_pins_mozilla_vendor`
        // in crates/pb-fingerprint/src/gecko/webgpu.rs.
        const MODULE_35_6_EXPECTED_VENDOR: &str = "Mozilla";
        assert_eq!(COHORT_VENDOR, MODULE_35_6_EXPECTED_VENDOR);
    }

    #[test]
    fn locked_gpu_features_is_empty() {
        // Empty in v1; any addition is a cohort shift through the
        // Adaptation protocol.
        assert_eq!(LOCKED_GPU_FEATURES.len(), 0);
    }

    #[test]
    fn locked_gpu_features_matches_module_35_6() {
        // CROSS-MODULE REGRESSION (Module 35.6). Paired with
        // `locked_profile_pins_mozilla_vendor` (which also asserts
        // `LOCKED_WEBGPU_PROFILE.features.len() == 0`).
        const MODULE_35_6_EXPECTED_FEATURES_LEN: usize = 0;
        assert_eq!(LOCKED_GPU_FEATURES.len(), MODULE_35_6_EXPECTED_FEATURES_LEN);
    }

    #[test]
    fn locked_limits_match_module_35_6_webgpu_spec_minima() {
        // CROSS-MODULE REGRESSION (Module 35.6). Paired with
        // `locked_limits_match_webgpu_spec_minima` in
        // crates/pb-fingerprint/src/gecko/webgpu.rs. If any field
        // drifts on either side, the test on the other side
        // breaks. Values pinned to the WebGPU spec minima
        // (https://www.w3.org/TR/webgpu/#limits).
        let l = &LOCKED_GPU_LIMITS;
        assert_eq!(l.max_texture_dimension_1d, 8192);
        assert_eq!(l.max_texture_dimension_2d, 8192);
        assert_eq!(l.max_texture_dimension_3d, 2048);
        assert_eq!(l.max_texture_array_layers, 256);
        assert_eq!(l.max_bind_groups, 4);
        assert_eq!(l.max_buffer_size, 268_435_456);
        assert_eq!(l.max_compute_workgroup_size_x, 256);
        assert_eq!(l.max_compute_workgroup_size_y, 256);
        assert_eq!(l.max_compute_workgroup_size_z, 64);
        assert_eq!(l.max_compute_invocations_per_workgroup, 256);
    }

    #[test]
    fn adapter_descriptor_references_locked_limits_by_address() {
        // Address identity: every call to `AdapterDescriptor::COHORT_LOCKED`
        // (and every coordinator's `adapter()`) returns a struct
        // whose `limits` points at the SAME static. Proves the
        // cohort base is a singleton, not a re-created struct.
        let d = AdapterDescriptor::COHORT_LOCKED;
        assert!(std::ptr::eq(d.limits, &LOCKED_GPU_LIMITS));
    }

    #[test]
    fn adapter_descriptor_references_locked_features_by_address() {
        // Same singleton requirement for the features slice.
        let d = AdapterDescriptor::COHORT_LOCKED;
        assert!(std::ptr::eq(d.features, LOCKED_GPU_FEATURES));
    }

    #[test]
    fn adapter_descriptor_carries_cohort_vendor() {
        let d = AdapterDescriptor::COHORT_LOCKED;
        assert_eq!(d.vendor, "Mozilla");
        assert_eq!(d.vendor, COHORT_VENDOR);
    }

    // ── Coordinator: construction + read-only state ────────────────────

    #[test]
    fn new_coordinator_starts_at_epoch_one_and_available() {
        let c = GpuCoordinator::new();
        assert_eq!(c.epoch(), 1);
        assert!(c.is_available());
    }

    #[test]
    fn default_coordinator_matches_new() {
        let c = GpuCoordinator::default();
        assert_eq!(c.epoch(), 1);
        assert!(c.is_available());
    }

    #[test]
    fn adapter_is_cohort_locked_under_both_modes() {
        // Phase-file Edge cases for capability normalization:
        // mode-invariant. A Standard coordinator and a Strict
        // coordinator (not that we construct distinct ones — the
        // coordinator is process-wide) hand out the same descriptor.
        let c = GpuCoordinator::new();
        let d = c.adapter();
        assert_eq!(d, AdapterDescriptor::COHORT_LOCKED);
        // Address identity on the limits pointer survives one
        // round-trip through the coordinator.
        assert!(std::ptr::eq(d.limits, &LOCKED_GPU_LIMITS));
    }

    // ── Scope token issuance ───────────────────────────────────────────

    #[test]
    fn issue_returns_token_with_current_epoch_and_inputs() {
        let c = GpuCoordinator::new();
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(t.profile_id(), pid_a());
        assert_eq!(t.mode(), Mode::Standard);
        assert_eq!(t.epoch(), c.epoch());
        assert_eq!(t.epoch(), 1);
    }

    #[test]
    fn issue_preserves_mode_per_identity() {
        let c = GpuCoordinator::new();
        let a = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let b = c.issue_scope_token(pid_b(), Mode::Strict).unwrap();
        assert_eq!(a.mode(), Mode::Standard);
        assert_eq!(b.mode(), Mode::Strict);
        assert_ne!(a.profile_id(), b.profile_id());
    }

    #[test]
    fn issue_returns_same_epoch_for_back_to_back_tokens() {
        let c = GpuCoordinator::new();
        let a = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let b = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(a.epoch(), b.epoch());
    }

    #[test]
    fn validate_accepts_fresh_token() {
        let c = GpuCoordinator::new();
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(c.validate(t), Ok(()));
    }

    // ── Adapter loss / recovery ────────────────────────────────────────

    #[test]
    fn on_adapter_loss_marks_unavailable() {
        let c = GpuCoordinator::new();
        c.on_adapter_loss();
        assert!(!c.is_available());
    }

    #[test]
    fn on_adapter_loss_does_not_bump_epoch() {
        // Outstanding tokens remain valid during the loss window
        // so consumers can detect their in-flight work was
        // interrupted. Invalidation happens on recovery.
        let c = GpuCoordinator::new();
        let e_before = c.epoch();
        c.on_adapter_loss();
        assert_eq!(c.epoch(), e_before);
    }

    #[test]
    fn issue_during_loss_window_fails() {
        let c = GpuCoordinator::new();
        c.on_adapter_loss();
        let r = c.issue_scope_token(pid_a(), Mode::Standard);
        assert_eq!(r, Err(CoordinatorError::AdapterUnavailable));
    }

    #[test]
    fn token_issued_before_loss_stays_valid_until_recovery() {
        // Loss alone doesn't invalidate. Validation passes between
        // loss and recovery (the consumer is the one detecting
        // availability separately).
        let c = GpuCoordinator::new();
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        c.on_adapter_loss();
        assert_eq!(c.validate(t), Ok(()));
    }

    #[test]
    fn recover_after_loss_bumps_epoch_and_restores_availability() {
        let c = GpuCoordinator::new();
        let e_before = c.epoch();
        c.on_adapter_loss();
        c.recover_after_loss();
        assert_eq!(c.epoch(), e_before + 1);
        assert!(c.is_available());
    }

    #[test]
    fn recovery_invalidates_pre_loss_tokens() {
        let c = GpuCoordinator::new();
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        c.on_adapter_loss();
        c.recover_after_loss();
        assert_eq!(c.validate(t), Err(CoordinatorError::StaleToken));
    }

    #[test]
    fn recovery_invalidates_pre_loss_tokens_across_all_identities() {
        // PHASE-FILE EDGE CASE (load-bearing): adapter loss
        // recovery (driver crash) does not leak partial state
        // across identities. The mechanism is epoch invalidation
        // applied uniformly to every identity's outstanding
        // tokens — a Module 37/38 implementation can therefore
        // safely drop every per-identity bucket without checking
        // which identity owned which token.
        let c = GpuCoordinator::new();
        let t_a = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let t_b = c.issue_scope_token(pid_b(), Mode::Strict).unwrap();
        c.on_adapter_loss();
        c.recover_after_loss();
        assert_eq!(c.validate(t_a), Err(CoordinatorError::StaleToken));
        assert_eq!(c.validate(t_b), Err(CoordinatorError::StaleToken));
    }

    #[test]
    fn post_recovery_tokens_are_valid_under_new_epoch() {
        let c = GpuCoordinator::new();
        c.on_adapter_loss();
        c.recover_after_loss();
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(t.epoch(), c.epoch());
        assert_eq!(c.validate(t), Ok(()));
    }

    #[test]
    fn validate_does_not_consult_availability() {
        // A valid (current-epoch) token stays valid even if the
        // adapter is currently unavailable. Availability is
        // transient; staleness is permanent (until reissue).
        let c = GpuCoordinator::new();
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        c.on_adapter_loss();
        assert!(!c.is_available());
        assert_eq!(c.validate(t), Ok(()));
    }

    #[test]
    fn repeated_loss_recovery_cycles_bump_epoch_monotonically() {
        let c = GpuCoordinator::new();
        let e0 = c.epoch();
        for _ in 0..5 {
            c.on_adapter_loss();
            c.recover_after_loss();
        }
        assert_eq!(c.epoch(), e0 + 5);
    }

    #[test]
    fn token_equality_distinguishes_epoch() {
        // Two tokens for the same identity and mode but different
        // epochs are NOT equal. A stale token must not compare
        // equal to a fresh one — otherwise a consumer caching
        // (token -> bucket) state by equality could route fresh
        // work into a stale bucket.
        let c = GpuCoordinator::new();
        let t1 = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        c.on_adapter_loss();
        c.recover_after_loss();
        let t2 = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(t1.profile_id(), t2.profile_id());
        assert_eq!(t1.mode(), t2.mode());
        assert_ne!(t1.epoch(), t2.epoch());
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_equality_distinguishes_profile_id() {
        let c = GpuCoordinator::new();
        let a = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let b = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn token_equality_distinguishes_mode() {
        let c = GpuCoordinator::new();
        let a = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let b = c.issue_scope_token(pid_a(), Mode::Strict).unwrap();
        assert_ne!(a, b);
    }

    // ── Concurrency / Send + Sync ──────────────────────────────────────

    #[test]
    fn types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GpuCoordinator>();
        assert_send_sync::<ScopeToken>();
        assert_send_sync::<AdapterDescriptor>();
        assert_send_sync::<GpuLimits>();
        assert_send_sync::<CoordinatorError>();
    }

    #[test]
    fn coordinator_is_shareable_across_threads() {
        // Smoke test: an Arc<GpuCoordinator> can issue tokens
        // concurrently. We don't try to prove linearizability
        // here — just that the public API is callable from
        // multiple threads without compile- or runtime panics.
        use std::sync::Arc;
        use std::thread;

        let c = Arc::new(GpuCoordinator::new());
        let mut handles = Vec::new();
        for i in 0..4u8 {
            let c2 = Arc::clone(&c);
            handles.push(thread::spawn(move || {
                let pid = Uuid::from_u128(u128::from(i) + 1);
                let mode = if i % 2 == 0 {
                    Mode::Standard
                } else {
                    Mode::Strict
                };
                let t = c2.issue_scope_token(pid, mode).unwrap();
                assert_eq!(c2.validate(t), Ok(()));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // No adapter loss happened → epoch unchanged.
        assert_eq!(c.epoch(), 1);
    }

    // ── Error display (L27 redaction) ──────────────────────────────────

    #[test]
    fn error_display_is_opaque() {
        // L27: error Display ships an opaque string without
        // identifying context (no profile_id, no epoch). Detail
        // would flow through `Error::source()` if needed; here
        // the cases are structural and have no source.
        let stale = format!("{}", CoordinatorError::StaleToken);
        let unavail = format!("{}", CoordinatorError::AdapterUnavailable);
        assert!(!stale.contains('-')); // no UUID hyphens
        assert!(!unavail.contains('-'));
        assert!(!stale.is_empty());
        assert!(!unavail.is_empty());
    }
}
