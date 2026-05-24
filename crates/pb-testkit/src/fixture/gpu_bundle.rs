//! Phase 6 cross-phase fixture — `gpu_bundle()`.
//!
//! Wraps the GPU process triple (`GpuCoordinator` + `MemoryBudget` +
//! `QueueScheduler`) as a single shareable bundle so Phase 7+ tests
//! can assert cross-identity GPU isolation without re-deriving the
//! orchestrator wiring. The bundle mirrors what the Phase 11
//! orchestrator (Module 80, pending) will construct at startup:
//! one coordinator, one budget paired to its epoch, one scheduler
//! paired to its epoch.
//!
//! ## Why a fixture rather than per-test setup
//!
//! Every consumer of pb-gpu in the workspace will use these three
//! types together — the budget and scheduler are useless without
//! the coordinator's `ScopeToken`, and an `on_recovery` pair that
//! forgets one of them leaks state. Centralizing the wiring here
//! means a future Phase 7+ test gets a known-correct triple from
//! one call.
//!
//! ## Cross-phase contract (CLAUDE.md §"Cross-phase test contract")
//!
//! Phase 6 ships this fixture into pb-testkit so Phase 7+ tests
//! can exercise the per-identity GPU surface against any
//! IdentityProfile produced by [`crate::fixture::profile`] without
//! caring about the coordinator + budget + scheduler wiring. The
//! contract test at the bottom of this file pins the cross-identity
//! isolation invariants at the fixture level so a regression here
//! caught by any Phase 7+ test that uses the fixture, not just by
//! the in-crate pb-gpu tests.

#![cfg(any(test, feature = "testkit"))]

use std::sync::Arc;

use pb_config::{GpuConfig, Mode};
use pb_gpu::coordinator::{GpuCoordinator, ScopeToken};
use pb_gpu::memory_budget::{BudgetProfile, MemoryBudget};
use pb_gpu::queue::QueueScheduler;
use uuid::Uuid;

/// Default per-identity GPU memory cap for the fixture, in MiB.
///
/// Matches `pb_config::GpuConfig` default. Smaller-than-production
/// caps are available via [`gpu_bundle_with_cap`] for eviction
/// stress tests.
const DEFAULT_CAP_MIB: u32 = 512;

/// Shareable Phase-6 GPU bundle.
///
/// Holds `Arc`-wrapped instances of the three Phase 6 types so
/// callers can clone the bundle freely across threads. The
/// `on_recovery_pair` method enforces the orchestrator-pairing
/// contract documented on
/// [`pb_gpu::memory_budget::MemoryBudget::on_recovery`] and
/// [`pb_gpu::queue::QueueScheduler::on_recovery`] in one call so
/// downstream tests cannot accidentally pair only one side.
#[derive(Clone)]
pub struct GpuBundle {
    pub coordinator: Arc<GpuCoordinator>,
    pub budget: Arc<MemoryBudget>,
    pub scheduler: Arc<QueueScheduler>,
}

impl GpuBundle {
    /// Issue a fresh `ScopeToken` for `profile_id` under `mode`,
    /// going through the bundled coordinator. Tests that want to
    /// drive submission/allocation against multiple identities
    /// call this once per identity.
    pub fn issue_token(&self, profile_id: Uuid, mode: Mode) -> ScopeToken {
        self.coordinator
            .issue_scope_token(profile_id, mode)
            .expect("fixture coordinator never refuses issuance during a test")
    }

    /// Drive a coordinator recovery and pair both sibling
    /// resources to the new epoch in one call (enforces the
    /// "MUST pair both" invariant called out in the Module 37 /
    /// Module 38 docs).
    pub fn on_recovery_pair(&self) {
        self.coordinator.on_adapter_loss();
        self.coordinator.recover_after_loss();
        let new_epoch = self.coordinator.epoch();
        self.budget.on_recovery(new_epoch);
        self.scheduler.on_recovery(new_epoch);
    }
}

/// Construct a Phase-6 GPU bundle with default cap (512 MiB).
pub fn gpu_bundle() -> GpuBundle {
    gpu_bundle_with_cap(DEFAULT_CAP_MIB)
}

/// Construct a Phase-6 GPU bundle with a specific per-identity
/// memory cap (in MiB).
///
/// The value is clamped by `BudgetProfile::from_config` to
/// `[64, 4096]` MiB. Useful for eviction stress tests that need
/// a tight cap to provoke LRU behavior without allocating
/// production-sized buffers.
pub fn gpu_bundle_with_cap(cap_mib: u32) -> GpuBundle {
    let cfg = GpuConfig {
        memory_cap_mib: cap_mib,
    };
    let coordinator = Arc::new(GpuCoordinator::new());
    let profile = BudgetProfile::from_config(&cfg, Mode::Standard);
    let budget = Arc::new(MemoryBudget::from_coordinator(profile, &coordinator));
    let scheduler = Arc::new(QueueScheduler::from_coordinator(&coordinator));
    GpuBundle {
        coordinator,
        budget,
        scheduler,
    }
}

// ── Tests (cross-phase contract) ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pb_gpu::memory_budget::BudgetError;
    use pb_gpu::queue::QueueError;

    fn pid_a() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000060001").unwrap()
    }
    fn pid_b() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000060002").unwrap()
    }

    #[test]
    fn bundle_starts_with_coordinator_at_epoch_one_and_resources_synced() {
        let b = gpu_bundle();
        assert_eq!(b.coordinator.epoch(), 1);
        assert_eq!(b.budget.epoch(), b.coordinator.epoch());
        assert_eq!(b.scheduler.epoch(), b.coordinator.epoch());
    }

    #[test]
    fn bundle_default_cap_is_512_mib() {
        let b = gpu_bundle();
        assert_eq!(b.budget.cap_bytes(), 512 * 1024 * 1024);
    }

    #[test]
    fn bundle_with_custom_cap_round_trips() {
        let b = gpu_bundle_with_cap(128);
        assert_eq!(b.budget.cap_bytes(), 128 * 1024 * 1024);
    }

    #[test]
    fn bundle_cap_clamps_below_minimum() {
        // BudgetProfile clamps to MIN_CAP_MIB = 64.
        let b = gpu_bundle_with_cap(16);
        assert_eq!(b.budget.cap_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn cross_phase_contract_cross_identity_isolation_through_fixture() {
        // PHASE 6 CROSS-PHASE CONTRACT (load-bearing). Future
        // Phase 7+ tests that drive the bundle MUST inherit
        // these isolation invariants — if a downstream module
        // accidentally breaks one, the regression here fires.
        let b = gpu_bundle_with_cap(64);
        let ta = b.issue_token(pid_a(), Mode::Standard);
        let tb = b.issue_token(pid_b(), Mode::Strict);

        // Memory budget: B can't release A's allocation.
        let id_a = b.budget.try_allocate(ta, 1024).unwrap();
        assert_eq!(
            b.budget.release(tb, id_a),
            Err(BudgetError::UnknownAllocation),
            "fixture must preserve cross-identity memory isolation"
        );
        assert_eq!(b.budget.used_bytes(ta), 1024);
        assert_eq!(b.budget.used_bytes(tb), 0);

        // Queue: A's submission does not change B's pending.
        b.scheduler.submit(ta).unwrap();
        b.scheduler.submit(ta).unwrap();
        assert_eq!(b.scheduler.pending_for(ta), 2);
        assert_eq!(b.scheduler.pending_for(tb), 0);
    }

    #[test]
    fn cross_phase_contract_on_recovery_pair_invalidates_both_resources() {
        // PHASE 6 CROSS-PHASE CONTRACT (load-bearing). The bundle's
        // `on_recovery_pair` is the orchestrator-equivalent
        // sequence. Tests that drive recovery through the fixture
        // MUST see stale-token rejection from BOTH resources
        // (Module 37 + Module 38) after one call.
        let b = gpu_bundle();
        let ta = b.issue_token(pid_a(), Mode::Standard);
        b.budget.try_allocate(ta, 4096).unwrap();
        b.scheduler.submit(ta).unwrap();

        b.on_recovery_pair();

        assert_eq!(
            b.budget.try_allocate(ta, 1024),
            Err(BudgetError::StaleToken)
        );
        assert_eq!(b.scheduler.submit(ta), Err(QueueError::StaleToken));
        // Fresh token at the new epoch works on both resources.
        let ta_new = b.issue_token(pid_a(), Mode::Standard);
        b.budget.try_allocate(ta_new, 1024).unwrap();
        b.scheduler.submit(ta_new).unwrap();
    }

    #[test]
    fn bundle_can_be_shared_across_threads_via_arc_clone() {
        use std::thread;
        let b = gpu_bundle();
        let handles: Vec<_> = (0..4u8)
            .map(|i| {
                let b2 = b.clone();
                thread::spawn(move || {
                    let pid = Uuid::from_u128(u128::from(i) + 300);
                    let t = b2.issue_token(pid, Mode::Standard);
                    b2.budget.try_allocate(t, 1024).unwrap();
                    b2.scheduler.submit(t).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
