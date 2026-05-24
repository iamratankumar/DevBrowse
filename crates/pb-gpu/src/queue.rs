//! Module 38 — Per-identity GPU command queue isolation.
//!
//! Each identity has its own command-buffer queue; no buffer
//! crosses identities. Round-robin scheduling across identities
//! ensures a single hostile workload cannot starve other
//! identities of GPU time (phase-file Edge case for Module 38).
//!
//! v1 here is pure bookkeeping + scheduling fairness. The real
//! GPU command-buffer execution lands in Phase 11 / Module 80
//! (libxul GPU FFI bridge); this module owns the isolation +
//! fairness contract that the bridge code consumes.
//!
//! ## Architecture references
//!
//!   * **L12** — pb-gpu imports pb-config (allowed leaf) and
//!     uses sibling-module [`crate::coordinator::ScopeToken`].
//!     Does NOT import pb-fingerprint or pb-identity.
//!   * **L13** — `#![forbid(unsafe_code)]` at crate root.
//!   * **L27** — [`QueueError`] `Display` impls ship opaque
//!     strings; no profile_id / buffer_id / queue depth in the
//!     rendered string.
//!   * **Module 36 — coordinator** — supplies [`ScopeToken`].
//!     The coordinator's epoch is paired with the scheduler's
//!     internal epoch via [`QueueScheduler::on_recovery`]: an
//!     adapter loss + recovery in the coordinator MUST be
//!     followed by a matching `on_recovery(coordinator.epoch())`
//!     here. The pair drops every per-identity queue atomically
//!     so an in-flight command buffer from before the crash
//!     cannot be executed afterwards under any identity (same
//!     mechanism Module 37 uses for memory buckets).
//!   * **Module 37 — memory budget** — sibling consumer of
//!     `ScopeToken`. Submission here and allocation there are
//!     independent (a renderer may queue a command buffer
//!     without having allocated memory and vice-versa); the
//!     orchestrator pairs both with `on_recovery` after a
//!     coordinator recovery.
//!   * **Phase-file Edge case (Module 38)** — queue starvation
//!     under hostile workloads must be prevented. Mechanism:
//!     round-robin dequeue. Each call to
//!     [`QueueScheduler::dequeue`] services the next identity
//!     in rotation; an identity with 1000 pending buffers and
//!     an identity with 1 pending buffer alternate, so the
//!     low-volume identity is serviced within a bounded number
//!     of dequeue cycles regardless of the high-volume
//!     identity's pressure.
//!
//! ## Cross-platform principle
//!
//! No `cfg`-gated public API; the scheduling state machine is
//! plain Rust stdlib (`HashMap`, `VecDeque`, `Mutex`). Identical
//! on Linux / macOS (and Windows once Phase 11.9 ships).
//
// TODO(Phase 11 / Module 80 — libxul GPU FFI bridge): plug the
//   real `wgpu::Queue::submit` (or libxul equivalent) in behind
//   [`QueueScheduler::dequeue`]. v1 returns a [`DequeuedCommand`]
//   carrying identity metadata; Phase 11 maps it to a real GPU
//   queue handle for the actual command-buffer playback.
// TODO(Phase 10 — adversarial fingerprint suite): a live probe
//   submits 1000 buffers as identity A and 1 buffer as identity
//   B, then measures wall-clock latency until B's buffer is
//   serviced. Property: B's latency is bounded by O(1) RR cycles,
//   independent of A's queue depth.

use pb_config::Mode;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

use crate::coordinator::{GpuCoordinator, ScopeToken};

// ── Command buffer handle ─────────────────────────────────────────────────

/// Opaque per-command-buffer handle.
///
/// Issued by [`QueueScheduler::submit`]. v1 carries no payload —
/// it identifies a single submission within a single
/// [`QueueScheduler`] instance. The Phase 11 libxul bridge will
/// pair this handle with the real GPU command buffer via a
/// side-table that lives in the bridge code, not here.
///
/// ### Cross-identity isolation
///
/// A `CommandBufferId` minted under identity A lives only in A's
/// queue; identity B has no operation that takes a
/// `CommandBufferId` as input (the scheduler dequeues internally
/// by rotation), so there is no API path for B to act on A's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandBufferId(u64);

impl CommandBufferId {
    /// Raw integer value. Diagnostics / tests only; consumers
    /// should treat the value as opaque.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

// ── Dequeue output ────────────────────────────────────────────────────────

/// A command buffer pulled from the scheduler, ready for GPU
/// execution.
///
/// Carries the identity metadata so the Phase 11 GPU executor
/// can route the buffer to the right per-identity context
/// without re-consulting the scheduler. The metadata mirrors
/// [`ScopeToken`]'s fields by value (not by reference) so the
/// executor does not need a token in hand to act on the dequeued
/// command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DequeuedCommand {
    pub profile_id: Uuid,
    pub mode: Mode,
    pub epoch: u64,
    pub buffer_id: CommandBufferId,
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Queue scheduler errors.
///
/// `Display` is opaque per L27. Identifying detail (profile_id,
/// buffer_id, queue depth) never appears in the rendered string.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueError {
    /// Token's epoch is older than the scheduler's current
    /// epoch. The caller must obtain a fresh token (issuance
    /// pairs with [`QueueScheduler::on_recovery`]).
    #[error("gpu scope token is stale")]
    StaleToken,
}

// ── Internal state ────────────────────────────────────────────────────────

#[derive(Debug)]
struct IdentityQueue {
    mode: Mode,
    pending: VecDeque<CommandBufferId>,
}

impl IdentityQueue {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            pending: VecDeque::new(),
        }
    }
}

#[derive(Debug)]
struct State {
    /// Current scheduler epoch. Paired with the coordinator via
    /// [`QueueScheduler::on_recovery`].
    epoch: u64,
    next_id: u64,
    /// Per-identity queues. The "no buffer crosses identities"
    /// rule is structural: every submission goes into the
    /// queue keyed by `token.profile_id()` and never leaves
    /// that queue (dequeue moves it OUT to the executor, but
    /// never sideways to another identity's queue).
    queues: HashMap<Uuid, IdentityQueue>,
    /// Round-robin rotation order. The front identity is
    /// serviced next; after a non-empty dequeue it rotates to
    /// the back so the next call services a different identity.
    /// Identities with empty queues are removed from rotation
    /// and re-added on the next `submit`.
    schedule_order: VecDeque<Uuid>,
}

// ── Scheduler ─────────────────────────────────────────────────────────────

/// Per-identity GPU command queue scheduler.
///
/// Single instance per GPU coordinator. Thread-safe
/// (`Send + Sync`). All operations are single-mutex serialized;
/// the scheduler is not a per-frame hot path in v1 (real GPU
/// command submission is Phase 11).
pub struct QueueScheduler {
    state: Mutex<State>,
}

impl QueueScheduler {
    /// Construct a fresh scheduler at `initial_epoch`.
    pub fn new(initial_epoch: u64) -> Self {
        Self {
            state: Mutex::new(State {
                epoch: initial_epoch,
                next_id: 1,
                queues: HashMap::new(),
                schedule_order: VecDeque::new(),
            }),
        }
    }

    /// Construct a scheduler paired with `coordinator`'s current
    /// epoch.
    pub fn from_coordinator(coordinator: &GpuCoordinator) -> Self {
        Self::new(coordinator.epoch())
    }

    /// Current scheduler epoch.
    pub fn epoch(&self) -> u64 {
        self.state.lock().expect("queue lock poisoned").epoch
    }

    /// Number of pending command buffers for `token`'s identity.
    /// Returns `0` for stale tokens or identities that have
    /// never submitted.
    pub fn pending_for(&self, token: ScopeToken) -> usize {
        let s = self.state.lock().expect("queue lock poisoned");
        if token.epoch() != s.epoch {
            return 0;
        }
        s.queues
            .get(&token.profile_id())
            .map(|q| q.pending.len())
            .unwrap_or(0)
    }

    /// Submit a new command buffer under `token`'s identity.
    ///
    /// The buffer enters the identity's FIFO queue. Cross-
    /// identity isolation is structural: the queue is keyed by
    /// `token.profile_id()` and the dequeue path only ever
    /// removes from the queue it was submitted into.
    pub fn submit(&self, token: ScopeToken) -> Result<CommandBufferId, QueueError> {
        let mut s = self.state.lock().expect("queue lock poisoned");
        if token.epoch() != s.epoch {
            return Err(QueueError::StaleToken);
        }
        let id = CommandBufferId(s.next_id);
        s.next_id = s.next_id.wrapping_add(1);
        let pid = token.profile_id();
        let queue = s
            .queues
            .entry(pid)
            .or_insert_with(|| IdentityQueue::new(token.mode()));
        let was_empty = queue.pending.is_empty();
        queue.pending.push_back(id);
        if was_empty {
            // Identity is re-entering rotation. Append at the
            // back so it is serviced AFTER every identity ahead
            // of it has had its turn (fairness on entry).
            s.schedule_order.push_back(pid);
        }
        Ok(id)
    }

    /// Pop the next command buffer to execute according to the
    /// round-robin schedule.
    ///
    /// Returns `None` when every queue is empty.
    ///
    /// ### Round-robin fairness
    ///
    /// The scheduler maintains a `VecDeque<Uuid>` of identities
    /// with pending work. Each dequeue pops the front identity,
    /// services one of its pending buffers, and (if the
    /// identity still has more work) rotates the identity to
    /// the back. An identity with 1000 pending buffers and an
    /// identity with 1 pending buffer alternate cleanly: A, B,
    /// A, A, A, ... (B drops out of rotation after its single
    /// buffer; A then runs alone). The low-volume identity is
    /// serviced within `N` dequeue cycles where `N` is the
    /// number of active identities.
    pub fn dequeue(&self) -> Option<DequeuedCommand> {
        let mut s = self.state.lock().expect("queue lock poisoned");
        let epoch = s.epoch;
        // Skip empty identities defensively (should not happen
        // under normal operation; submit() removes empty queues
        // from rotation only via on_recovery, but the
        // schedule_order may contain an identity whose queue
        // happens to be empty due to defensive paths).
        while let Some(pid) = s.schedule_order.pop_front() {
            let Some(queue) = s.queues.get_mut(&pid) else {
                continue;
            };
            let Some(buffer_id) = queue.pending.pop_front() else {
                continue;
            };
            let mode = queue.mode;
            if !queue.pending.is_empty() {
                s.schedule_order.push_back(pid);
            }
            return Some(DequeuedCommand {
                profile_id: pid,
                mode,
                epoch,
                buffer_id,
            });
        }
        None
    }

    /// Pair with the coordinator's `recover_after_loss`: clear
    /// every per-identity queue and adopt `new_epoch` as the
    /// scheduler's current epoch.
    ///
    /// After this call, every in-flight command buffer is
    /// dropped (the queues are emptied) and every previously-
    /// issued [`ScopeToken`] becomes stale (epoch mismatch).
    /// This is the load-bearing "no in-flight command buffer
    /// from before the crash survives across the recovery"
    /// property (phase-file Module 36 Edge case, consumed by
    /// Module 38).
    pub fn on_recovery(&self, new_epoch: u64) {
        let mut s = self.state.lock().expect("queue lock poisoned");
        s.epoch = new_epoch;
        s.queues.clear();
        s.schedule_order.clear();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::CoordinatorError;
    use std::collections::HashSet;

    fn pid_a() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000038001").unwrap()
    }
    fn pid_b() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000038002").unwrap()
    }
    fn pid_c() -> Uuid {
        Uuid::parse_str("00000000-0000-4000-8000-000000038003").unwrap()
    }

    // ── Construction + read-only state ─────────────────────────────────

    #[test]
    fn new_scheduler_starts_with_given_epoch_and_empty_state() {
        let q = QueueScheduler::new(7);
        assert_eq!(q.epoch(), 7);
    }

    #[test]
    fn from_coordinator_syncs_initial_epoch() {
        let c = GpuCoordinator::new();
        c.on_adapter_loss();
        c.recover_after_loss();
        c.on_adapter_loss();
        c.recover_after_loss();
        let q = QueueScheduler::from_coordinator(&c);
        assert_eq!(q.epoch(), c.epoch());
        assert_eq!(q.epoch(), 3);
    }

    #[test]
    fn pending_for_unknown_identity_is_zero() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(q.pending_for(t), 0);
    }

    // ── Submit happy path ──────────────────────────────────────────────

    #[test]
    fn submit_returns_unique_ids() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let id1 = q.submit(t).unwrap();
        let id2 = q.submit(t).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn submit_increments_pending_count() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        q.submit(t).unwrap();
        q.submit(t).unwrap();
        q.submit(t).unwrap();
        assert_eq!(q.pending_for(t), 3);
    }

    #[test]
    fn submit_with_stale_token_returns_staletoken() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        q.on_recovery(q.epoch() + 1);
        assert_eq!(q.submit(t), Err(QueueError::StaleToken));
    }

    // ── Dequeue happy path ─────────────────────────────────────────────

    #[test]
    fn dequeue_empty_returns_none() {
        let q = QueueScheduler::new(1);
        assert_eq!(q.dequeue(), None);
    }

    #[test]
    fn dequeue_returns_submitted_buffer() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let id = q.submit(t).unwrap();
        let d = q.dequeue().expect("submitted buffer must be dequeueable");
        assert_eq!(d.buffer_id, id);
        assert_eq!(d.profile_id, pid_a());
        assert_eq!(d.mode, Mode::Standard);
        assert_eq!(d.epoch, q.epoch());
    }

    #[test]
    fn dequeued_command_carries_token_mode_and_epoch() {
        // The Phase 11 executor routes work to the per-identity
        // GPU context based on the dequeued metadata; mode and
        // epoch must round-trip identically.
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Strict).unwrap();
        q.submit(ta).unwrap();
        q.submit(tb).unwrap();
        let d1 = q.dequeue().unwrap();
        let d2 = q.dequeue().unwrap();
        // Both modes preserved across the dequeue boundary.
        let modes_by_pid: HashMap<Uuid, Mode> =
            [(d1.profile_id, d1.mode), (d2.profile_id, d2.mode)]
                .into_iter()
                .collect();
        assert_eq!(modes_by_pid[&pid_a()], Mode::Standard);
        assert_eq!(modes_by_pid[&pid_b()], Mode::Strict);
        // Epoch on both equals the scheduler's current epoch.
        assert_eq!(d1.epoch, q.epoch());
        assert_eq!(d2.epoch, q.epoch());
    }

    #[test]
    fn dequeue_within_identity_is_fifo() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let id1 = q.submit(t).unwrap();
        let id2 = q.submit(t).unwrap();
        let id3 = q.submit(t).unwrap();
        assert_eq!(q.dequeue().unwrap().buffer_id, id1);
        assert_eq!(q.dequeue().unwrap().buffer_id, id2);
        assert_eq!(q.dequeue().unwrap().buffer_id, id3);
        assert_eq!(q.dequeue(), None);
    }

    #[test]
    fn dequeue_decrements_pending_count() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        q.submit(t).unwrap();
        q.submit(t).unwrap();
        assert_eq!(q.pending_for(t), 2);
        q.dequeue().unwrap();
        assert_eq!(q.pending_for(t), 1);
        q.dequeue().unwrap();
        assert_eq!(q.pending_for(t), 0);
    }

    // ── Round-robin starvation prevention (phase-file Edge case) ───────

    #[test]
    fn dequeue_round_robin_alternates_across_identities() {
        // Submit A, B, A, B, A, B and expect dequeue to alternate
        // A, B, A, B, A, B in the order identities were first
        // seen.
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        q.submit(ta).unwrap();
        q.submit(tb).unwrap();
        q.submit(ta).unwrap();
        q.submit(tb).unwrap();
        q.submit(ta).unwrap();
        q.submit(tb).unwrap();
        let observed: Vec<Uuid> = (0..6)
            .map(|_| q.dequeue().expect("expected non-empty").profile_id)
            .collect();
        assert_eq!(
            observed,
            vec![pid_a(), pid_b(), pid_a(), pid_b(), pid_a(), pid_b()],
            "round-robin must strictly alternate between two active identities"
        );
    }

    #[test]
    fn one_identity_with_many_does_not_starve_other() {
        // PHASE-FILE EDGE CASE (load-bearing). Identity A
        // submits 1000 buffers (hostile workload). Identity B
        // submits 1 buffer. B's buffer must be serviced within
        // bounded RR cycles, NOT after A's queue drains.
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        for _ in 0..1000 {
            q.submit(ta).unwrap();
        }
        q.submit(tb).unwrap();
        // With two active identities, B's single buffer must
        // appear within the first 2 dequeues (RR cycle length
        // == active identity count).
        let mut serviced: HashSet<Uuid> = HashSet::new();
        for _ in 0..2 {
            serviced.insert(q.dequeue().unwrap().profile_id);
        }
        assert!(
            serviced.contains(&pid_b()),
            "low-volume identity B must be serviced within 2 RR cycles even though A submitted 1000 buffers"
        );
    }

    #[test]
    fn rr_continues_with_remaining_identity_after_one_drains() {
        // After B's single buffer drains, RR should continue
        // servicing A alone (no spurious None, no double-skip
        // penalty).
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        q.submit(ta).unwrap(); // A1
        q.submit(tb).unwrap(); // B1
        q.submit(ta).unwrap(); // A2
        q.submit(ta).unwrap(); // A3
        // First three dequeues: A1, B1, A2 (RR).
        assert_eq!(q.dequeue().unwrap().profile_id, pid_a());
        assert_eq!(q.dequeue().unwrap().profile_id, pid_b());
        assert_eq!(q.dequeue().unwrap().profile_id, pid_a());
        // B is now empty; next dequeue must be A3 (NOT None and
        // NOT a B-shaped slot lingering).
        assert_eq!(q.dequeue().unwrap().profile_id, pid_a());
        assert_eq!(q.dequeue(), None);
    }

    #[test]
    fn rr_handles_three_identities_fairly() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        let tc = c.issue_scope_token(pid_c(), Mode::Strict).unwrap();
        q.submit(ta).unwrap();
        q.submit(tb).unwrap();
        q.submit(tc).unwrap();
        let observed: Vec<Uuid> = (0..3).map(|_| q.dequeue().unwrap().profile_id).collect();
        // Each identity serviced exactly once in three dequeues.
        let unique: HashSet<Uuid> = observed.iter().copied().collect();
        assert_eq!(unique.len(), 3);
        assert!(unique.contains(&pid_a()));
        assert!(unique.contains(&pid_b()));
        assert!(unique.contains(&pid_c()));
    }

    // ── Cross-identity isolation ───────────────────────────────────────

    #[test]
    fn submit_under_one_identity_does_not_change_others_pending() {
        // Submission under A increments A's pending count, NOT
        // B's. The "no buffer crosses identities" property is
        // structurally enforced by the per-profile_id HashMap
        // key.
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        q.submit(ta).unwrap();
        q.submit(ta).unwrap();
        assert_eq!(q.pending_for(ta), 2);
        assert_eq!(q.pending_for(tb), 0);
    }

    #[test]
    fn dequeued_buffer_always_carries_its_submitting_identity() {
        // PHASE-FILE EDGE CASE (load-bearing): "no command buffer
        // crosses identities". Whatever order dequeue picks,
        // every dequeued buffer's profile_id must match the
        // identity that submitted it. We submit a known
        // sequence and verify the (id -> identity) mapping
        // round-trips.
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Strict).unwrap();
        let mut origin: HashMap<CommandBufferId, Uuid> = HashMap::new();
        for _ in 0..5 {
            origin.insert(q.submit(ta).unwrap(), pid_a());
        }
        for _ in 0..5 {
            origin.insert(q.submit(tb).unwrap(), pid_b());
        }
        while let Some(d) = q.dequeue() {
            let expected = origin
                .remove(&d.buffer_id)
                .expect("dequeued id must come from a known submission");
            assert_eq!(
                d.profile_id, expected,
                "dequeued buffer must carry the profile_id that submitted it"
            );
        }
        assert!(
            origin.is_empty(),
            "every submitted buffer must be dequeued under its own identity"
        );
    }

    // ── Recovery semantics ─────────────────────────────────────────────

    #[test]
    fn on_recovery_clears_queues_and_updates_epoch() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let t = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        q.submit(t).unwrap();
        q.submit(t).unwrap();
        assert_eq!(q.pending_for(t), 2);
        q.on_recovery(q.epoch() + 1);
        assert_eq!(q.epoch(), 2);
        // pending_for sees zero — both because the queue is
        // cleared AND because the token's epoch no longer
        // matches the scheduler's.
        assert_eq!(q.pending_for(t), 0);
        assert_eq!(q.dequeue(), None);
    }

    #[test]
    fn post_recovery_old_tokens_rejected_across_all_identities() {
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb = c.issue_scope_token(pid_b(), Mode::Strict).unwrap();
        q.on_recovery(q.epoch() + 1);
        assert_eq!(q.submit(ta), Err(QueueError::StaleToken));
        assert_eq!(q.submit(tb), Err(QueueError::StaleToken));
    }

    #[test]
    fn coordinator_recovery_paired_with_queue_recovery_isolates_state() {
        // CROSS-MODULE CONTRACT (Module 36 ↔ Module 38). Mirror
        // of the Module 37 ↔ 36 contract: orchestrator pairs
        // `coordinator.recover_after_loss()` with
        // `scheduler.on_recovery(coordinator.epoch())`. After
        // the pair:
        //   1. Every previously-issued ScopeToken is stale (per
        //      coordinator.validate AND per scheduler.submit).
        //   2. Every per-identity queue is empty (no in-flight
        //      command buffer from before the crash survives).
        //   3. Fresh tokens under the new epoch work normally.
        let c = GpuCoordinator::new();
        let q = QueueScheduler::from_coordinator(&c);
        let ta_old = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        let tb_old = c.issue_scope_token(pid_b(), Mode::Standard).unwrap();
        q.submit(ta_old).unwrap();
        q.submit(tb_old).unwrap();
        q.submit(ta_old).unwrap();

        c.on_adapter_loss();
        c.recover_after_loss();
        q.on_recovery(c.epoch());

        // (1) Old tokens stale on both sides.
        assert_eq!(c.validate(ta_old), Err(CoordinatorError::StaleToken));
        assert_eq!(q.submit(ta_old), Err(QueueError::StaleToken));
        assert_eq!(c.validate(tb_old), Err(CoordinatorError::StaleToken));
        assert_eq!(q.submit(tb_old), Err(QueueError::StaleToken));

        // (2) No in-flight command buffer survives.
        assert_eq!(q.dequeue(), None);

        // (3) Fresh token works normally; queues start empty.
        let ta_new = c.issue_scope_token(pid_a(), Mode::Standard).unwrap();
        assert_eq!(q.pending_for(ta_new), 0);
        let id_new = q.submit(ta_new).unwrap();
        let d = q.dequeue().unwrap();
        assert_eq!(d.buffer_id, id_new);
        assert_eq!(d.profile_id, pid_a());
        assert_eq!(d.epoch, c.epoch());
    }

    // ── Concurrency ────────────────────────────────────────────────────

    #[test]
    fn types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<QueueScheduler>();
        assert_send_sync::<CommandBufferId>();
        assert_send_sync::<DequeuedCommand>();
        assert_send_sync::<QueueError>();
    }

    #[test]
    fn scheduler_is_shareable_across_threads() {
        use std::sync::Arc;
        use std::thread;
        let c = Arc::new(GpuCoordinator::new());
        let q = Arc::new(QueueScheduler::from_coordinator(&c));
        let mut handles = Vec::new();
        for i in 0..4u8 {
            let c2 = Arc::clone(&c);
            let q2 = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                let pid = Uuid::from_u128(u128::from(i) + 200);
                let t = c2.issue_scope_token(pid, Mode::Standard).unwrap();
                q2.submit(t).unwrap();
                assert_eq!(q2.pending_for(t), 1);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    // ── L27 Display redaction ──────────────────────────────────────────

    #[test]
    fn error_display_is_opaque() {
        // L27: Display ships an opaque string without
        // identifying detail.
        let s = format!("{}", QueueError::StaleToken);
        assert!(!s.is_empty());
        assert!(!s.contains('-'), "UUID hyphens leak identifying detail");
        assert!(
            !s.chars().any(|c| c.is_ascii_digit()),
            "buffer ids leak detail: {s}"
        );
    }
}
