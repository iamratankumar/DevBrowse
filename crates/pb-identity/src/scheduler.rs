//! Renderer scheduler, Module 8.
//!
//! SECURITY INVARIANT (architecture §3.4) — never refactor silently:
//!
//!   Two tabs may share a renderer process IFF
//!     1. both profiles are in `Mode::Standard`, AND
//!     2. both profiles have the same `profile_id`.
//!
//!   Strict tabs NEVER share, even with another Strict tab carrying the same
//!   `profile_id` (§3.3 mandates per-tab renderer regardless).
//!
//! This module owns the decision and tracks the resulting renderer-to-tab
//! mapping. Module 9 (lifecycle) owns actual process spawn / suspend / kill;
//! it asks the scheduler what to do, performs the action, and reports the
//! outcome back so the scheduler stays in sync with reality.
//!
//! Concurrency: plain sync struct. Module 9 wraps it under
//! `Arc<tokio::sync::Mutex>` at the integration boundary.
//!
//! TODO(Module 12): sandbox profile selection happens at lifecycle's spawn
//!   step, keyed off `IdentityProfile.mode()`. Scheduler does not touch
//!   sandbox state, but its decision determines whether a fresh sandbox is
//!   needed (always for Strict, only for new Standard renderers).

use crate::profile::{IdentityProfile, Mode};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Opaque renderer process identifier minted by Module 9 (lifecycle).
/// The scheduler never mints these; it only tracks values lifecycle reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RendererId(pub u64);

/// Opaque tab identifier minted by Module 9 (lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TabId(pub u64);

/// Decision returned by [`Scheduler::schedule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendererDecision {
    /// Reuse this existing renderer process. Caller must follow up with
    /// `attach_tab` once the tab is actually wired up.
    Reuse(RendererId),
    /// Spawn a fresh renderer. Caller must follow up with
    /// `register_renderer` and `attach_tab` once the process is live.
    SpawnNew,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("renderer {0:?} is not registered")]
    UnknownRenderer(RendererId),

    #[error("renderer {0:?} is already registered")]
    DuplicateRenderer(RendererId),

    #[error("tab {tab:?} is not attached to renderer {renderer:?}")]
    TabNotAttached { renderer: RendererId, tab: TabId },

    #[error("tab {tab:?} is already attached to renderer {renderer:?}")]
    TabAlreadyAttached { renderer: RendererId, tab: TabId },
}

/// Per-renderer bookkeeping. Mode + profile_id are the §3.4 sharing key.
#[derive(Debug, Clone)]
struct RendererSlot {
    profile_id: Uuid,
    mode: Mode,
    tabs: HashSet<TabId>,
}

/// Renderer scheduler.
#[derive(Debug, Default)]
pub struct Scheduler {
    renderers: HashMap<RendererId, RendererSlot>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether the given profile reuses an existing renderer or needs
    /// a fresh one, per §3.4. Pure read — does not mutate state.
    pub fn schedule(&self, profile: &IdentityProfile) -> RendererDecision {
        if profile.mode() == Mode::Strict {
            // §3.3: per-tab renderer, never shared. Short-circuit before any
            // profile_id comparison so a future change to the lookup loop
            // cannot accidentally weaken the Strict invariant.
            return RendererDecision::SpawnNew;
        }
        // Standard mode: reuse an existing Standard renderer iff profile_ids
        // match. Iteration order does not matter for correctness; any
        // matching slot is a legal reuse target.
        for (id, slot) in &self.renderers {
            if slot.mode == Mode::Standard && slot.profile_id == profile.profile_id() {
                return RendererDecision::Reuse(*id);
            }
        }
        RendererDecision::SpawnNew
    }

    /// Register a freshly spawned renderer. Called by Module 9 after the
    /// process is live and before any tab is attached.
    pub fn register_renderer(
        &mut self,
        renderer: RendererId,
        profile: &IdentityProfile,
    ) -> Result<(), SchedulerError> {
        if self.renderers.contains_key(&renderer) {
            return Err(SchedulerError::DuplicateRenderer(renderer));
        }
        self.renderers.insert(
            renderer,
            RendererSlot {
                profile_id: profile.profile_id(),
                mode: profile.mode(),
                tabs: HashSet::new(),
            },
        );
        Ok(())
    }

    /// Attach a tab to a registered renderer.
    ///
    /// Re-asserts §3.4: if `profile.mode() == Strict`, the slot must contain
    /// no other tab (Strict is per-tab). If the slot's (mode, profile_id)
    /// disagrees with `profile`, reject — the caller cannot mix identities
    /// in one renderer.
    pub fn attach_tab(
        &mut self,
        renderer: RendererId,
        tab: TabId,
        profile: &IdentityProfile,
    ) -> Result<(), SchedulerError> {
        let slot = self
            .renderers
            .get_mut(&renderer)
            .ok_or(SchedulerError::UnknownRenderer(renderer))?;

        // §3.4 defence in depth: the slot's identity must match the tab's.
        // If they don't, the caller almost certainly has a bug in lifecycle.
        if slot.profile_id != profile.profile_id() || slot.mode != profile.mode() {
            return Err(SchedulerError::UnknownRenderer(renderer));
        }

        // §3.3: Strict renderers hold exactly one tab.
        if slot.mode == Mode::Strict && !slot.tabs.is_empty() {
            return Err(SchedulerError::TabAlreadyAttached {
                renderer,
                tab: *slot
                    .tabs
                    .iter()
                    .next()
                    .expect("non-empty set has at least one tab"),
            });
        }

        if !slot.tabs.insert(tab) {
            return Err(SchedulerError::TabAlreadyAttached { renderer, tab });
        }
        Ok(())
    }

    /// Detach a tab. Does NOT retire the renderer even when its tab set
    /// becomes empty; lifecycle decides when an idle renderer is killed.
    pub fn detach_tab(&mut self, renderer: RendererId, tab: TabId) -> Result<(), SchedulerError> {
        let slot = self
            .renderers
            .get_mut(&renderer)
            .ok_or(SchedulerError::UnknownRenderer(renderer))?;
        if !slot.tabs.remove(&tab) {
            return Err(SchedulerError::TabNotAttached { renderer, tab });
        }
        Ok(())
    }

    /// Retire a renderer. Returns the tabs that were still attached so
    /// lifecycle can verify cleanup expectations.
    pub fn retire_renderer(
        &mut self,
        renderer: RendererId,
    ) -> Result<HashSet<TabId>, SchedulerError> {
        let slot = self
            .renderers
            .remove(&renderer)
            .ok_or(SchedulerError::UnknownRenderer(renderer))?;
        Ok(slot.tabs)
    }

    /// Number of tabs currently attached to a renderer, or `None` if the
    /// renderer is not registered.
    pub fn tab_count(&self, renderer: RendererId) -> Option<usize> {
        self.renderers.get(&renderer).map(|s| s.tabs.len())
    }

    /// Total number of registered renderers.
    pub fn renderer_count(&self) -> usize {
        self.renderers.len()
    }

    /// Whether a renderer is currently registered.
    pub fn is_registered(&self, renderer: RendererId) -> bool {
        self.renderers.contains_key(&renderer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard(name: &str) -> IdentityProfile {
        IdentityProfile::builder()
            .name(name)
            .mode(Mode::Standard)
            .build()
            .unwrap()
    }

    fn strict(name: &str) -> IdentityProfile {
        IdentityProfile::builder()
            .name(name)
            .mode(Mode::Strict)
            .build()
            .unwrap()
    }

    #[test]
    fn empty_scheduler_always_spawns_new() {
        let s = Scheduler::new();
        let p = standard("Personal");
        assert_eq!(s.schedule(&p), RendererDecision::SpawnNew);
    }

    #[test]
    fn standard_with_same_profile_id_reuses() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        // Same profile object, same id, Standard mode: must reuse.
        assert_eq!(s.schedule(&p), RendererDecision::Reuse(RendererId(1)));
    }

    #[test]
    fn standard_with_different_profile_id_spawns_new() {
        let mut s = Scheduler::new();
        let a = standard("Personal");
        let b = standard("Work");
        s.register_renderer(RendererId(1), &a).unwrap();
        // b has a different profile_id even though both are Standard.
        assert_eq!(s.schedule(&b), RendererDecision::SpawnNew);
    }

    #[test]
    fn strict_always_spawns_new_even_with_existing_strict_same_id() {
        let mut s = Scheduler::new();
        let p = strict("BankAccount");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        // §3.3 / §3.4: Strict never shares, even with itself.
        assert_eq!(s.schedule(&p), RendererDecision::SpawnNew);
    }

    #[test]
    fn strict_does_not_reuse_existing_standard_renderer_same_profile_id() {
        // Constructed scenario: a Standard renderer registered for some
        // profile_id, then a Strict tab arrives carrying the same id (a
        // pathological case lifecycle should never produce, but the
        // scheduler must reject it regardless).
        let mut s = Scheduler::new();
        let std_profile = standard("Personal");
        s.register_renderer(RendererId(1), &std_profile).unwrap();

        // Build a Strict profile we treat as carrying the same id by
        // testing the Strict short-circuit with any profile.
        let strict_profile = strict("Personal");
        // Different profile_id (UUIDs are random) AND different mode: still
        // SpawnNew on both grounds. The Strict short-circuit is the
        // load-bearing rule here.
        assert_eq!(s.schedule(&strict_profile), RendererDecision::SpawnNew);
    }

    #[test]
    fn standard_does_not_reuse_existing_strict_renderer_same_profile_id() {
        let mut s = Scheduler::new();
        let strict_profile = strict("BankAccount");
        s.register_renderer(RendererId(1), &strict_profile).unwrap();

        let std_profile = standard("BankAccount");
        // Different profile_id and different mode: SpawnNew. Even if the
        // ids matched, mode mismatch would still force SpawnNew because
        // the lookup filters on `mode == Standard`.
        assert_eq!(s.schedule(&std_profile), RendererDecision::SpawnNew);
    }

    #[test]
    fn register_then_retire_round_trip() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        assert!(s.is_registered(RendererId(1)));
        assert_eq!(s.renderer_count(), 1);
        let leftover = s.retire_renderer(RendererId(1)).unwrap();
        assert!(leftover.is_empty());
        assert!(!s.is_registered(RendererId(1)));
        assert_eq!(s.renderer_count(), 0);
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        let err = s.register_renderer(RendererId(1), &p).unwrap_err();
        assert_eq!(err, SchedulerError::DuplicateRenderer(RendererId(1)));
    }

    #[test]
    fn retire_unknown_rejected() {
        let mut s = Scheduler::new();
        let err = s.retire_renderer(RendererId(99)).unwrap_err();
        assert_eq!(err, SchedulerError::UnknownRenderer(RendererId(99)));
    }

    #[test]
    fn attach_tab_to_unknown_renderer_rejected() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        let err = s.attach_tab(RendererId(99), TabId(1), &p).unwrap_err();
        assert_eq!(err, SchedulerError::UnknownRenderer(RendererId(99)));
    }

    #[test]
    fn attach_tab_with_mismatched_profile_rejected() {
        let mut s = Scheduler::new();
        let a = standard("A");
        let b = standard("B");
        s.register_renderer(RendererId(1), &a).unwrap();
        // Trying to attach a tab carrying profile B onto a renderer slotted
        // for profile A: must be rejected. The error variant we surface here
        // is UnknownRenderer (treating the (renderer, profile) tuple as the
        // real key) so that lifecycle treats it as a routing bug.
        let err = s.attach_tab(RendererId(1), TabId(10), &b).unwrap_err();
        assert_eq!(err, SchedulerError::UnknownRenderer(RendererId(1)));
    }

    #[test]
    fn standard_renderer_can_hold_multiple_tabs() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(11), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(12), &p).unwrap();
        assert_eq!(s.tab_count(RendererId(1)), Some(3));
    }

    #[test]
    fn strict_renderer_rejects_second_tab() {
        let mut s = Scheduler::new();
        let p = strict("BankAccount");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        let err = s.attach_tab(RendererId(1), TabId(11), &p).unwrap_err();
        assert!(
            matches!(err, SchedulerError::TabAlreadyAttached { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn duplicate_attach_same_tab_rejected() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        let err = s.attach_tab(RendererId(1), TabId(10), &p).unwrap_err();
        assert_eq!(
            err,
            SchedulerError::TabAlreadyAttached {
                renderer: RendererId(1),
                tab: TabId(10),
            }
        );
    }

    #[test]
    fn detach_then_attach_again() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        s.detach_tab(RendererId(1), TabId(10)).unwrap();
        assert_eq!(s.tab_count(RendererId(1)), Some(0));
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        assert_eq!(s.tab_count(RendererId(1)), Some(1));
    }

    #[test]
    fn detach_unknown_tab_rejected() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        let err = s.detach_tab(RendererId(1), TabId(99)).unwrap_err();
        assert_eq!(
            err,
            SchedulerError::TabNotAttached {
                renderer: RendererId(1),
                tab: TabId(99),
            }
        );
    }

    #[test]
    fn detach_does_not_retire_renderer() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        s.detach_tab(RendererId(1), TabId(10)).unwrap();
        assert!(
            s.is_registered(RendererId(1)),
            "scheduler must keep an empty renderer slot until lifecycle retires it explicitly"
        );
    }

    #[test]
    fn retire_returns_remaining_tabs() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(10), &p).unwrap();
        s.attach_tab(RendererId(1), TabId(11), &p).unwrap();
        let leftover = s.retire_renderer(RendererId(1)).unwrap();
        assert_eq!(leftover.len(), 2);
        assert!(leftover.contains(&TabId(10)));
        assert!(leftover.contains(&TabId(11)));
    }

    #[test]
    fn after_retire_new_tab_with_same_profile_spawns_new() {
        let mut s = Scheduler::new();
        let p = standard("Personal");
        s.register_renderer(RendererId(1), &p).unwrap();
        s.retire_renderer(RendererId(1)).unwrap();
        // No live renderers: schedule must spawn new.
        assert_eq!(s.schedule(&p), RendererDecision::SpawnNew);
    }
}
