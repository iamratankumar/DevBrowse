//! Module 37 — Per-identity GPU memory budget.
//!
//! Enforces a per-identity GPU allocation cap (sourced from
//! `pb-config`) on top of Module 36's [`ScopeToken`]. Refuses
//! allocations beyond the cap; evicts LRU *within* the same
//! identity, NEVER across identities. The "never across" property
//! is what makes cross-identity texture sharing impossible — see
//! [`MemoryBudget::try_allocate`] and the
//! `cross_identity_*` regressions below.
//!
//! ## Architecture references
//!
//!   * **L12** — pb-gpu may import pb-config (allowed leaf
//!     dependency) and uses [`crate::coordinator::ScopeToken`] from
//!     the sibling Module 36. It does NOT import pb-fingerprint or
//!     pb-identity. The L12 dependency rule keeps the kernel-side
//!     allocator decoupled from the JS-observable surface.
//!   * **L13** — `#![forbid(unsafe_code)]` at the crate root.
//!   * **L27** — [`BudgetError`] `Display` impls ship opaque
//!     strings; identifying detail (profile_id, allocation id,
//!     byte counts) never appears in the rendered string. Detail
//!     would flow through `Error::source()` if needed — these
//!     cases are structural and have no source.
//!   * **Module 36 — coordinator** — supplies [`ScopeToken`]
//!     ({profile_id, mode, epoch}). The coordinator's monotonic
//!     epoch is paired with the budget's own internal `epoch` via
//!     [`MemoryBudget::on_recovery`]: an adapter loss + recovery
//!     in the coordinator MUST be followed by a matching
//!     `on_recovery(coordinator.epoch())` here. The pair is what
//!     drops every per-identity bucket atomically (phase-file Edge
//!     case for Module 36, consumed by Module 37). Tokens whose
//!     epoch does not match the budget's current epoch are
//!     rejected with [`BudgetError::StaleToken`].
//!   * **Phase-file Edge case (Module 37)** — cross-identity
//!     texture sharing must be impossible even via WebGPU
//!     `GPUExternalTexture`. Mechanism: every operation here
//!     looks up the per-identity bucket by `token.profile_id()`
//!     and only ever touches that bucket. An [`AllocationId`]
//!     minted under identity A is opaque to identity B — B's
//!     bucket does not contain A's id, so
//!     [`MemoryBudget::touch`] / [`MemoryBudget::release`] under
//!     B's token return [`BudgetError::UnknownAllocation`]
//!     regardless of whether B somehow learned the integer value
//!     of A's id. LRU eviction iterates only B's `lru` deque, so
//!     A's allocations cannot be evicted by B's pressure.
//!
//! ## Cross-platform principle
//!
//! Public API is identical on Linux / macOS (and Windows once
//! Phase 11.9 ships; iOS / Android in Phase 12). No `cfg`-gated
//! public functions; the in-memory bookkeeping has no platform
//! dependencies.
//
// TODO(Phase 11 / Module 80 — libxul GPU FFI bridge): plug the
//   real allocation backend in behind [`MemoryBudget::try_allocate`].
//   v1 here is pure bookkeeping — the kernel-side allocator that
//   actually reserves device memory is Phase 11 territory. The
//   budget surface remains the same; only the body of
//   `try_allocate` / `release` grows to call the FFI.
// TODO(Phase 10 — adversarial fingerprint suite): a live probe
//   exhausts identity A's budget and asserts identity B's budget
//   is unaffected (no eviction, used_bytes unchanged, allocations
//   still resident). Property: per-identity isolation under
//   adversarial memory pressure.

use pb_config::{GpuConfig, Mode};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

use crate::coordinator::{GpuCoordinator, ScopeToken};

// ── Budget profile ────────────────────────────────────────────────────────

/// Per-identity GPU memory budget profile.
///
/// Derived from [`pb_config::GpuConfig`] via [`BudgetProfile::from_config`].
/// Mode parameter is passed through for forward compatibility; in v1
/// Standard and Strict share the same cap (the cohort is uniform across
/// modes, mirroring Module 36's `AdapterDescriptor::COHORT_LOCKED`). A
/// future per-mode policy hook (e.g. tighter Strict cap to reduce
/// observable memory pressure timing) lands here without changing the
/// public surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetProfile {
    pub cap_bytes: u64,
}

impl BudgetProfile {
    /// Defense-in-depth lower bound (MiB). pb-config's loader
    /// already rejects values below 64 MiB; this clamp catches the
    /// case where a future caller constructs a `GpuConfig` outside
    /// the loader and forgets to validate.
    pub const MIN_CAP_MIB: u32 = 64;
    /// Defense-in-depth upper bound (MiB). Mirrors loader.rs.
    pub const MAX_CAP_MIB: u32 = 4096;

    /// Build a profile from a validated [`GpuConfig`] and the
    /// identity's mode. Clamps to `[MIN_CAP_MIB, MAX_CAP_MIB]`.
    pub fn from_config(cfg: &GpuConfig, mode: Mode) -> Self {
        // Mode kept in the signature for a future per-mode policy
        // hook; v1 uses the same cap for both modes.
        let _ = mode;
        let cap_mib = cfg
            .memory_cap_mib
            .clamp(Self::MIN_CAP_MIB, Self::MAX_CAP_MIB);
        Self {
            cap_bytes: u64::from(cap_mib) * 1024 * 1024,
        }
    }
}

// ── Allocation handle ─────────────────────────────────────────────────────

/// Opaque per-allocation handle.
///
/// Issued by [`MemoryBudget::try_allocate`]. Consumers pass it back to
/// [`MemoryBudget::touch`] (mark as MRU) and [`MemoryBudget::release`]
/// (free bytes). The integer value carries no semantic meaning beyond
/// uniqueness within a single [`MemoryBudget`] instance.
///
/// ### Cross-identity isolation
///
/// An `AllocationId` minted under identity A is meaningless to identity
/// B's [`ScopeToken`]: every budget operation looks up the per-identity
/// bucket via `token.profile_id()` and the id must live in *that*
/// bucket's sizes map. B's bucket does not contain A's id, so any
/// B-token operation on A's id returns
/// [`BudgetError::UnknownAllocation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationId(u64);

impl AllocationId {
    /// Raw integer value. Exposed for diagnostics / tests; consumers
    /// should treat the value as opaque.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Memory-budget errors.
///
/// `Display` is opaque per L27. Detail (identity id, allocation id,
/// byte counts) is intentionally absent from the rendered string;
/// callers that need diagnostics can match the variant directly.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum BudgetError {
    /// Token's epoch is older than the budget's current epoch. The
    /// caller must obtain a fresh token from the coordinator
    /// (issuance pairs with [`MemoryBudget::on_recovery`]).
    #[error("gpu scope token is stale")]
    StaleToken,
    /// Allocation request had zero bytes — meaningless and rejected.
    #[error("gpu allocation size is zero")]
    ZeroSize,
    /// Requested size is larger than the per-identity cap itself;
    /// even full eviction within the identity could not free enough.
    #[error("gpu allocation exceeds cap")]
    OverCap,
    /// LRU eviction emptied the identity's bucket but still could
    /// not satisfy the request (defensive — should be unreachable if
    /// the `OverCap` early-return is observed; reported instead of
    /// looping forever).
    #[error("gpu memory budget exhausted")]
    Exhausted,
    /// The supplied [`AllocationId`] is not present in this
    /// identity's bucket — either it never existed, was already
    /// released, was evicted, or belongs to a different identity
    /// (the cross-identity-isolation path).
    #[error("gpu allocation id unknown")]
    UnknownAllocation,
}

// ── Internal state ────────────────────────────────────────────────────────

#[derive(Debug)]
struct IdentityBucket {
    used_bytes: u64,
    /// Front = least-recently-used, back = most-recently-used.
    lru: VecDeque<AllocationId>,
    sizes: HashMap<AllocationId, u64>,
}

impl IdentityBucket {
    fn new() -> Self {
        Self {
            used_bytes: 0,
            lru: VecDeque::new(),
            sizes: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct State {
    /// Current budget epoch. Tokens whose `epoch()` does not match
    /// this value are rejected. Paired with the coordinator's epoch
    /// by the orchestrator via [`MemoryBudget::on_recovery`].
    epoch: u64,
    next_id: u64,
    /// Per-identity buckets keyed by `profile_id`. The "never across
    /// identities" eviction rule is structural: every code path
    /// reaches at most one bucket, looked up via `token.profile_id()`.
    buckets: HashMap<Uuid, IdentityBucket>,
}

// ── Memory budget ─────────────────────────────────────────────────────────

/// Per-identity GPU memory budget.
///
/// Single instance per GPU coordinator. The orchestrator constructs one
/// alongside the coordinator and pairs the two on adapter loss / recovery:
///
/// ```ignore
/// // Driver crash:
/// coord.on_adapter_loss();
/// // ...recovery handshake...
/// coord.recover_after_loss();
/// budget.on_recovery(coord.epoch());
/// ```
///
/// Thread-safe (`Send + Sync`). All mutation is single-mutex serialized;
/// the budget is not a hot path in v1 (allocation sizes are MiB-scale,
/// not per-frame).
pub struct MemoryBudget {
    profile: BudgetProfile,
    state: Mutex<State>,
}

impl MemoryBudget {
    /// Construct a fresh budget at `initial_epoch`.
    ///
    /// For most callers, prefer [`MemoryBudget::from_coordinator`]
    /// which reads the epoch from the coordinator directly.
    pub fn new(profile: BudgetProfile, initial_epoch: u64) -> Self {
        Self {
            profile,
            state: Mutex::new(State {
                epoch: initial_epoch,
                next_id: 1,
                buckets: HashMap::new(),
            }),
        }
    }

    /// Construct a budget paired with `coordinator`'s current epoch.
    pub fn from_coordinator(profile: BudgetProfile, coordinator: &GpuCoordinator) -> Self {
        Self::new(profile, coordinator.epoch())
    }

    /// Per-identity cap in bytes. Same value for every identity.
    pub fn cap_bytes(&self) -> u64 {
        self.profile.cap_bytes
    }

    /// Current budget epoch. Tokens whose `epoch()` does not match
    /// this value are stale.
    pub fn epoch(&self) -> u64 {
        self.state.lock().expect("budget lock poisoned").epoch
    }

    /// Currently-used bytes for the identity carried by `token`.
    ///
    /// Returns `0` for stale tokens or identities that have never
    /// allocated. Read-only; does not surface a `StaleToken` error
    /// because the caller's natural reaction would be the same as
    /// "no allocations".
    pub fn used_bytes(&self, token: ScopeToken) -> u64 {
        let s = self.state.lock().expect("budget lock poisoned");
        if token.epoch() != s.epoch {
            return 0;
        }
        s.buckets
            .get(&token.profile_id())
            .map(|b| b.used_bytes)
            .unwrap_or(0)
    }

    /// Attempt to allocate `size_bytes` against `token`'s identity.
    ///
    /// On success returns an [`AllocationId`] addressing the new
    /// allocation in the identity's bucket. On failure returns
    /// one of [`BudgetError::ZeroSize`] / [`BudgetError::OverCap`] /
    /// [`BudgetError::StaleToken`] / [`BudgetError::Exhausted`].
    ///
    /// If admitting the allocation would push the identity above the
    /// cap, the budget evicts LRU entries *within the same identity*
    /// until the new allocation fits. No other identity's bucket is
    /// consulted or modified — this is the load-bearing
    /// cross-identity-isolation property (phase-file Edge case).
    pub fn try_allocate(
        &self,
        token: ScopeToken,
        size_bytes: u64,
    ) -> Result<AllocationId, BudgetError> {
        if size_bytes == 0 {
            return Err(BudgetError::ZeroSize);
        }
        if size_bytes > self.profile.cap_bytes {
            return Err(BudgetError::OverCap);
        }
        let mut s = self.state.lock().expect("budget lock poisoned");
        if token.epoch() != s.epoch {
            return Err(BudgetError::StaleToken);
        }
        let bucket = s
            .buckets
            .entry(token.profile_id())
            .or_insert_with(IdentityBucket::new);
        // LRU eviction strictly within this identity's bucket.
        while bucket.used_bytes.saturating_add(size_bytes) > self.profile.cap_bytes {
            let Some(evict_id) = bucket.lru.pop_front() else {
                return Err(BudgetError::Exhausted);
            };
            let evicted = bucket.sizes.remove(&evict_id).unwrap_or(0);
            bucket.used_bytes = bucket.used_bytes.saturating_sub(evicted);
        }
        let id = AllocationId(s.next_id);
        s.next_id = s.next_id.wrapping_add(1);
        // Re-borrow bucket (lifetime broke at `s.next_id` mutation).
        let bucket = s
            .buckets
            .get_mut(&token.profile_id())
            .expect("bucket present after entry() insertion");
        bucket.used_bytes = bucket.used_bytes.saturating_add(size_bytes);
        bucket.lru.push_back(id);
        bucket.sizes.insert(id, size_bytes);
        Ok(id)
    }

    /// Mark `id` as most-recently-used so a subsequent allocation
    /// pressure does not evict it first.
    ///
    /// Returns [`BudgetError::UnknownAllocation`] if `id` is not in
    /// this identity's bucket. This includes the cross-identity
    /// case: B's token on A's id returns `UnknownAllocation`
    /// (A's id lives in A's bucket, never B's).
    pub fn touch(&self, token: ScopeToken, id: AllocationId) -> Result<(), BudgetError> {
        let mut s = self.state.lock().expect("budget lock poisoned");
        if token.epoch() != s.epoch {
            return Err(BudgetError::StaleToken);
        }
        let Some(bucket) = s.buckets.get_mut(&token.profile_id()) else {
            return Err(BudgetError::UnknownAllocation);
        };
        if !bucket.sizes.contains_key(&id) {
            return Err(BudgetError::UnknownAllocation);
        }
        if let Some(pos) = bucket.lru.iter().position(|x| *x == id) {
            bucket.lru.remove(pos);
        }
        bucket.lru.push_back(id);
        Ok(())
    }

    /// Free the bytes associated with `id` from this identity's
    /// bucket.
    ///
    /// Cross-identity safety mirrors [`Self::touch`]: B's token on
    /// A's id returns [`BudgetError::UnknownAllocation`].
    pub fn release(&self, token: ScopeToken, id: AllocationId) -> Result<(), BudgetError> {
        let mut s = self.state.lock().expect("budget lock poisoned");
        if token.epoch() != s.epoch {
            return Err(BudgetError::StaleToken);
        }
        let Some(bucket) = s.buckets.get_mut(&token.profile_id()) else {
            return Err(BudgetError::UnknownAllocation);
        };
        let Some(size) = bucket.sizes.remove(&id) else {
            return Err(BudgetError::UnknownAllocation);
        };
        bucket.used_bytes = bucket.used_bytes.saturating_sub(size);
        if let Some(pos) = bucket.lru.iter().position(|x| *x == id) {
            bucket.lru.remove(pos);
        }
        Ok(())
    }

    /// Pair with the coordinator's `recover_after_loss`: clear every
    /// per-identity bucket and adopt `new_epoch` as the budget's
    /// current epoch.
    ///
    /// After this call, every previously-issued [`AllocationId`]
    /// becomes unrecognized (bucket cleared) and every
    /// previously-issued [`ScopeToken`] becomes stale (epoch
    /// mismatch). This is the load-bearing "no partial GPU state
    /// leak across identities after a driver crash" property
    /// (phase-file Module 36 Edge case, consumed by Module 37).
    pub fn on_recovery(&self, new_epoch: u64) {
        let mut s = self.state.lock().expect("budget lock poisoned");
        s.epoch = new_epoch;
        s.buckets.clear();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::CoordinatorError;

    fn pid_a() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000037001").unwrap()
    }
    fn pid_b() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000037002").unwrap()
    }

    fn small_profile() -> BudgetProfile {
        // 64 MiB → 67_108_864 bytes; smallest legal cap.
        BudgetProfile::from_config(&GpuConfig { memory_cap_mib: 64 }, Mode::Standard)
    }

    // ── BudgetProfile ──────────────────────────────────────────────────

    #[test]
    fn budget_profile_default_is_512_mib() {
        let p = BudgetProfile::from_config(&GpuConfig::default(), Mode::Standard);
        assert_eq!(p.cap_bytes, 512 * 1024 * 1024);
    }

    #[test]
    fn budget_profile_clamps_below_min() {
        // Defense in depth — pb-config's loader rejects below 64,
        // but a caller bypassing the loader still gets a sane value.
        let p = BudgetProfile::from_config(&GpuConfig { memory_cap_mib: 16 }, Mode::Standard);
        assert_eq!(p.cap_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn budget_profile_clamps_above_max() {
        let p = BudgetProfile::from_config(
            &GpuConfig {
                memory_cap_mib: 16_384,
            },
            Mode::Standard,
        );
        assert_eq!(p.cap_bytes, 4096 * 1024 * 1024);
    }

    #[test]
    fn budget_profile_mode_passes_through_in_v1() {
        // v1: Standard and Strict share the same cap (cohort uniform).
        // The mode parameter is kept in the signature for a future
        // per-mode policy hook (e.g. tighter Strict cap).
        let cfg = GpuConfig {
            memory_cap_mib: 256,
        };
        let s = BudgetProfile::from_config(&cfg, Mode::Standard);
        let t = BudgetProfile::from_config(&cfg, Mode::Strict);
        assert_eq!(s, t);
    }

    // ── Construction + read-only state ─────────────────────────────────

    #[test]
    fn new_budget_starts_with_given_epoch_and_empty_state() {
        let b = MemoryBudget::new(small_profile(), 7);
        assert_eq!(b.epoch(), 7);
        assert_eq!(b.cap_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn from_coordinator_syncs_initial_epoch() {
        let c = GpuCoordinator::new();
        // Bump the coordinator a few epochs first.
        c.on_adapter_loss();
        c.recover_after_loss();
        c.on_adapter_loss();
        c.recover_after_loss();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        assert_eq!(b.epoch(), c.epoch());
        assert_eq!(b.epoch(), 3);
    }

    #[test]
    fn used_bytes_is_zero_for_unknown_identity() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(b.used_bytes(t), 0);
    }

    // ── try_allocate happy path ────────────────────────────────────────

    #[test]
    fn allocate_within_cap_succeeds_and_updates_used_bytes() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        b.try_allocate(t, 1024).unwrap();
        assert_eq!(b.used_bytes(t), 1024);
    }

    #[test]
    fn allocate_at_exact_cap_boundary_succeeds() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let cap = b.cap_bytes();
        b.try_allocate(t, cap).unwrap();
        assert_eq!(b.used_bytes(t), cap);
    }

    #[test]
    fn allocate_assigns_distinct_ids() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let id1 = b.try_allocate(t, 16).unwrap();
        let id2 = b.try_allocate(t, 16).unwrap();
        assert_ne!(id1, id2);
    }

    // ── try_allocate error paths ───────────────────────────────────────

    #[test]
    fn allocate_zero_size_returns_zerosize() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(b.try_allocate(t, 0), Err(BudgetError::ZeroSize));
    }

    #[test]
    fn allocate_over_cap_returns_overcap() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let oversize = b.cap_bytes() + 1;
        assert_eq!(b.try_allocate(t, oversize), Err(BudgetError::OverCap));
    }

    #[test]
    fn allocate_with_stale_token_returns_staletoken() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        // Bump only the budget's epoch (simulate orchestrator paired
        // with a recovery the token does not know about).
        b.on_recovery(b.epoch() + 1);
        assert_eq!(b.try_allocate(t, 1024), Err(BudgetError::StaleToken));
    }

    // ── LRU eviction within identity ───────────────────────────────────

    #[test]
    fn allocate_evicts_oldest_within_identity_to_fit() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let cap = b.cap_bytes();
        let half = cap / 2;
        let id_old = b.try_allocate(t, half).unwrap();
        let id_mid = b.try_allocate(t, half).unwrap();
        // Bucket is full. Next allocation evicts the oldest (id_old).
        let _id_new = b.try_allocate(t, half).unwrap();
        // id_old is gone — release returns UnknownAllocation.
        assert_eq!(
            b.release(t, id_old),
            Err(BudgetError::UnknownAllocation),
            "evicted id must be unrecognized"
        );
        // id_mid is still resident.
        b.release(t, id_mid).expect("non-evicted id is still valid");
    }

    #[test]
    fn touch_moves_to_mru_so_evictor_picks_someone_else() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let cap = b.cap_bytes();
        let half = cap / 2;
        let id_old = b.try_allocate(t, half).unwrap();
        let id_mid = b.try_allocate(t, half).unwrap();
        // Touch id_old so the next eviction picks id_mid instead.
        b.touch(t, id_old).unwrap();
        let _ = b.try_allocate(t, half).unwrap();
        // id_old survived (was MRU after touch); id_mid was evicted.
        b.release(t, id_old)
            .expect("touched id must survive eviction");
        assert_eq!(b.release(t, id_mid), Err(BudgetError::UnknownAllocation));
    }

    #[test]
    fn touch_unknown_id_returns_unknown_allocation() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        // No allocations exist.
        assert_eq!(
            b.touch(t, AllocationId(99)),
            Err(BudgetError::UnknownAllocation)
        );
    }

    #[test]
    fn touch_with_stale_token_returns_staletoken() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let id = b.try_allocate(t, 1024).unwrap();
        b.on_recovery(b.epoch() + 1);
        assert_eq!(b.touch(t, id), Err(BudgetError::StaleToken));
    }

    #[test]
    fn release_frees_bytes_and_removes_id() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let id = b.try_allocate(t, 2048).unwrap();
        assert_eq!(b.used_bytes(t), 2048);
        b.release(t, id).unwrap();
        assert_eq!(b.used_bytes(t), 0);
        // Second release errors — id is gone.
        assert_eq!(b.release(t, id), Err(BudgetError::UnknownAllocation));
    }

    #[test]
    fn release_unknown_id_returns_unknown_allocation() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(
            b.release(t, AllocationId(99)),
            Err(BudgetError::UnknownAllocation)
        );
    }

    // ── Cross-identity isolation (phase-file Edge case) ────────────────

    #[test]
    fn allocations_are_separate_per_identity() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        b.try_allocate(ta, 1024).unwrap();
        assert_eq!(b.used_bytes(ta), 1024);
        assert_eq!(
            b.used_bytes(tb),
            0,
            "identity B sees no allocation made by identity A"
        );
    }

    #[test]
    fn cross_identity_touch_with_other_identitys_id_returns_unknown() {
        // PHASE-FILE EDGE CASE (load-bearing). Cross-identity texture
        // sharing must be impossible even via WebGPU
        // `GPUExternalTexture`. A renderer for identity B that
        // somehow learns the numeric value of identity A's
        // AllocationId still cannot operate on it: every operation
        // looks up the bucket by token.profile_id() and the id is
        // not in B's bucket.
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        let id_a = b.try_allocate(ta, 1024).unwrap();
        assert_eq!(b.touch(tb, id_a), Err(BudgetError::UnknownAllocation));
    }

    #[test]
    fn cross_identity_release_with_other_identitys_id_returns_unknown() {
        // PHASE-FILE EDGE CASE (load-bearing).
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        let id_a = b.try_allocate(ta, 1024).unwrap();
        assert_eq!(b.release(tb, id_a), Err(BudgetError::UnknownAllocation));
        // A's allocation is still resident under A's identity.
        assert_eq!(b.used_bytes(ta), 1024);
    }

    #[test]
    fn lru_eviction_never_touches_other_identity_buckets() {
        // PHASE-FILE EDGE CASE (load-bearing). Allocation pressure
        // on identity A must NOT evict identity B's allocations.
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        // Fill B's bucket near the cap.
        let cap = b.cap_bytes();
        let id_b = b.try_allocate(tb, cap - 1024).unwrap();
        // A pressures its own bucket with multiple allocations that
        // exceed its share by repeated eviction.
        let third = cap / 3;
        let _ = b.try_allocate(ta, third).unwrap();
        let _ = b.try_allocate(ta, third).unwrap();
        let _ = b.try_allocate(ta, third).unwrap();
        let _ = b.try_allocate(ta, third).unwrap();
        // B's allocation must still be resident.
        b.release(tb, id_b)
            .expect("B's allocation must survive A's eviction storm");
    }

    // ── Recovery semantics ─────────────────────────────────────────────

    #[test]
    fn on_recovery_clears_buckets_and_updates_epoch() {
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let _ = b.try_allocate(ta, 4096).unwrap();
        assert_eq!(b.used_bytes(ta), 4096);
        b.on_recovery(b.epoch() + 1);
        // Old token sees zero — both because the bucket is cleared
        // AND because the epoch no longer matches.
        assert_eq!(b.used_bytes(ta), 0);
        assert_eq!(b.epoch(), 1 + 1);
    }

    #[test]
    fn post_recovery_old_tokens_rejected_across_all_identities() {
        // PHASE-FILE EDGE CASE (load-bearing): epoch invalidation
        // uniformly across identities. Old tokens for A and B both
        // become stale after a single recovery.
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Strict).unwrap();
        b.on_recovery(b.epoch() + 1);
        assert_eq!(b.try_allocate(ta, 1024), Err(BudgetError::StaleToken));
        assert_eq!(b.try_allocate(tb, 1024), Err(BudgetError::StaleToken));
    }

    #[test]
    fn coordinator_recovery_paired_with_budget_recovery_isolates_state() {
        // CROSS-MODULE CONTRACT (Module 36 ↔ Module 37). Orchestrator
        // pairs `coordinator.recover_after_loss()` with
        // `budget.on_recovery(coordinator.epoch())`. After the pair:
        //   1. Every previously-issued ScopeToken is stale (per
        //      coordinator.validate AND per budget.try_allocate).
        //   2. Every per-identity bucket is empty.
        //   3. Fresh tokens issued under the new epoch work
        //      normally and do not see any residual bytes.
        let c = GpuCoordinator::new();
        let b = MemoryBudget::from_coordinator(small_profile(), &c);
        let ta_old = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb_old = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        let _ = b.try_allocate(ta_old, 4096).unwrap();
        let _ = b.try_allocate(tb_old, 4096).unwrap();

        c.on_adapter_loss();
        c.recover_after_loss();
        b.on_recovery(c.epoch());

        // (1) Old tokens stale on both sides.
        assert_eq!(c.validate(ta_old), Err(CoordinatorError::StaleToken));
        assert_eq!(b.try_allocate(ta_old, 1024), Err(BudgetError::StaleToken));
        assert_eq!(c.validate(tb_old), Err(CoordinatorError::StaleToken));
        assert_eq!(b.try_allocate(tb_old, 1024), Err(BudgetError::StaleToken));

        // (2) Fresh token sees an empty bucket.
        let ta_new = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(b.used_bytes(ta_new), 0);

        // (3) Fresh allocation works.
        b.try_allocate(ta_new, 1024).unwrap();
        assert_eq!(b.used_bytes(ta_new), 1024);
    }

    // ── Concurrency ────────────────────────────────────────────────────

    #[test]
    fn types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MemoryBudget>();
        assert_send_sync::<BudgetProfile>();
        assert_send_sync::<AllocationId>();
        assert_send_sync::<BudgetError>();
    }

    #[test]
    fn budget_is_shareable_across_threads() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(GpuCoordinator::new());
        let b = Arc::new(MemoryBudget::from_coordinator(small_profile(), &c));
        let mut handles = Vec::new();
        for i in 0..4u8 {
            let c2 = Arc::clone(&c);
            let b2 = Arc::clone(&b);
            handles.push(thread::spawn(move || {
                let pid = Uuid::from_u128(u128::from(i) + 100);
                let t = c2.issue_scope_token(pid, Mode::Standard).unwrap();
                b2.try_allocate(t, 1024).unwrap();
                assert_eq!(b2.used_bytes(t), 1024);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    // ── L27 Display redaction ──────────────────────────────────────────

    #[test]
    fn error_display_is_opaque() {
        // L27: Display ships an opaque string without identifying
        // detail (profile_id, allocation id, byte count). Detail
        // would flow through `Error::source()` if needed — these
        // cases are structural and have no source.
        for e in [
            BudgetError::StaleToken,
            BudgetError::ZeroSize,
            BudgetError::OverCap,
            BudgetError::Exhausted,
            BudgetError::UnknownAllocation,
        ] {
            let s = format!("{e}");
            assert!(!s.is_empty());
            assert!(!s.contains('-'), "UUID hyphens leak identifying detail");
            assert!(
                !s.chars().any(|c| c.is_ascii_digit()),
                "byte counts leak detail: {s}"
            );
        }
    }
}
