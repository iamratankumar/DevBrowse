//! Tab lifecycle manager, Module 9.
//!
//! Owns the tab/renderer state machine and integrates the registry
//! (Module 7) with the scheduler (Module 8). This module does NOT spawn
//! OS processes; it returns [`ProcessAction`] values describing what the
//! orchestrator (Module 80) must do, and tracks resulting state.
//!
//! SECURITY INVARIANTS:
//!   * §3.1: a tab's binding to its `IdentityProfile` is immutable. There
//!     is no public API to retarget a tab. To "switch" identity, close the
//!     tab and spawn a new one.
//!   * §3.4: enforced via `Scheduler` for renderer reuse; `LifecycleManager`
//!     never bypasses the scheduler decision.
//!   * §3.3: Strict tabs always get a fresh renderer (Scheduler short-circuits).
//!
//! Concurrency: plain sync state machine. The orchestrator wraps a
//! `LifecycleManager` in `Arc<tokio::sync::Mutex>` for async dispatch.
//!
//! Spawn protocol (optimistic):
//!   1. Caller invokes `spawn_tab(profile_id)`. Lifecycle mutates state
//!      (records the tab, registers the renderer with the scheduler if new,
//!      attaches the tab to it) and returns a `ProcessAction` describing
//!      what the orchestrator must do at the OS level.
//!   2. Orchestrator performs the action.
//!   3. If the OS spawn fails, the orchestrator calls `abort_spawn(tab)` to
//!      roll back lifecycle state to pre-spawn.
//!
//! Suspend semantics (Module 10) layers on top of this state machine; this
//! module only owns the Active <-> Suspended state transition.
//!
//! TODO(Module 10): freeze JS execution, network, timers when state
//!   transitions to Suspended. Resume reverses.
//! TODO(Module 12, `pb-sandbox`): orchestrator picks a `SandboxProfile`
//!   keyed on `mode` from the SpawnRenderer action. Lifecycle does not own
//!   sandbox state; it only signals when a fresh renderer is needed.
//! TODO(Module 80): orchestrator wires tokio Mutex + IPC dispatch around
//!   this manager. ProcessAction values map onto pb-ipc messages
//!   (SpawnTab, DestroyTab) defined in Module 5.

use crate::profile::Mode;
use crate::registry::ProfileRegistry;
use crate::scheduler::{RendererDecision, RendererId, Scheduler, SchedulerError, TabId};
use crate::suspension::{ResumeAction, SuspendAction, SuspendReason};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("unknown profile_id {0}")]
    UnknownProfile(Uuid),

    #[error("unknown tab {0:?}")]
    UnknownTab(TabId),

    #[error("tab {0:?} is already in the requested state")]
    NoStateChange(TabId),

    #[error("scheduler error: {0}")]
    Scheduler(#[from] SchedulerError),
}

/// Tab runtime state. Suspended tabs keep their renderer slot but the
/// renderer is expected to freeze execution per Module 10 semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabState {
    Active,
    Suspended,
}

/// What the orchestrator must do at the OS / IPC layer to realize a spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessAction {
    /// Reuse an existing renderer process. Orchestrator sends an
    /// "attach tab" IPC to that renderer; no new OS process is created.
    AttachToExisting {
        renderer: RendererId,
        tab: TabId,
        profile_id: Uuid,
    },
    /// Spawn a fresh renderer process under the given mode's sandbox profile,
    /// then attach the tab.
    SpawnRenderer {
        renderer: RendererId,
        tab: TabId,
        profile_id: Uuid,
        mode: Mode,
    },
}

/// What the orchestrator must do at the OS / IPC layer to realize a close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAction {
    /// Tab detached; renderer still has live tabs.
    DetachOnly { renderer: RendererId, tab: TabId },
    /// Tab detached and renderer is now empty: kill the OS process.
    DetachAndKillRenderer { renderer: RendererId, tab: TabId },
}

#[derive(Debug, Clone)]
struct TabRecord {
    profile_id: Uuid,
    renderer: RendererId,
    state: TabState,
    suspend_reason: Option<SuspendReason>,
}

/// Central lifecycle manager.
///
/// Owns the [`ProfileRegistry`] and an internal [`Scheduler`]. Mints
/// monotonic `TabId` and `RendererId` values starting at 1.
#[derive(Debug)]
pub struct LifecycleManager {
    registry: ProfileRegistry,
    scheduler: Scheduler,
    tabs: HashMap<TabId, TabRecord>,
    next_tab_id: u64,
    next_renderer_id: u64,
}

impl LifecycleManager {
    pub fn new(registry: ProfileRegistry) -> Self {
        Self {
            registry,
            scheduler: Scheduler::new(),
            tabs: HashMap::new(),
            next_tab_id: 1,
            next_renderer_id: 1,
        }
    }

    pub fn registry(&self) -> &ProfileRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut ProfileRegistry {
        &mut self.registry
    }

    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    pub fn tab_state(&self, tab: TabId) -> Option<TabState> {
        self.tabs.get(&tab).map(|r| r.state)
    }

    pub fn tab_renderer(&self, tab: TabId) -> Option<RendererId> {
        self.tabs.get(&tab).map(|r| r.renderer)
    }

    pub fn tab_profile_id(&self, tab: TabId) -> Option<Uuid> {
        self.tabs.get(&tab).map(|r| r.profile_id)
    }

    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    fn mint_tab(&mut self) -> TabId {
        let id = TabId(self.next_tab_id);
        self.next_tab_id += 1;
        id
    }

    fn mint_renderer(&mut self) -> RendererId {
        let id = RendererId(self.next_renderer_id);
        self.next_renderer_id += 1;
        id
    }

    /// Spawn a new tab bound to the given profile.
    ///
    /// On success, lifecycle state has been mutated: a `TabRecord` exists in
    /// `Active` state, the scheduler has a registered renderer for it, and
    /// the tab is attached to that renderer. The returned [`ProcessAction`]
    /// tells the orchestrator what to do at the OS layer.
    ///
    /// If the orchestrator's OS-level spawn subsequently fails, call
    /// [`LifecycleManager::abort_spawn`] to roll back.
    pub fn spawn_tab(&mut self, profile_id: Uuid) -> Result<ProcessAction, LifecycleError> {
        let profile = self
            .registry
            .get(&profile_id)
            .ok_or(LifecycleError::UnknownProfile(profile_id))?
            .clone();

        let tab = self.mint_tab();
        match self.scheduler.schedule(&profile) {
            RendererDecision::Reuse(renderer) => {
                self.scheduler.attach_tab(renderer, tab, &profile)?;
                self.tabs.insert(
                    tab,
                    TabRecord {
                        profile_id,
                        renderer,
                        state: TabState::Active,
                        suspend_reason: None,
                    },
                );
                Ok(ProcessAction::AttachToExisting {
                    renderer,
                    tab,
                    profile_id,
                })
            }
            RendererDecision::SpawnNew => {
                let renderer = self.mint_renderer();
                self.scheduler.register_renderer(renderer, &profile)?;
                self.scheduler.attach_tab(renderer, tab, &profile)?;
                self.tabs.insert(
                    tab,
                    TabRecord {
                        profile_id,
                        renderer,
                        state: TabState::Active,
                        suspend_reason: None,
                    },
                );
                Ok(ProcessAction::SpawnRenderer {
                    renderer,
                    tab,
                    profile_id,
                    mode: profile.mode(),
                })
            }
        }
    }

    /// Roll back a `spawn_tab` whose OS-level realization failed.
    ///
    /// Detaches the tab from the scheduler, retires the renderer if it now
    /// has no tabs, and removes the tab record. After abort, the tab id
    /// is gone; the orchestrator should not retry with the same id.
    pub fn abort_spawn(&mut self, tab: TabId) -> Result<CloseAction, LifecycleError> {
        // close_tab already implements the detach + maybe-retire dance.
        self.close_tab(tab)
    }

    /// Close a tab.
    ///
    /// Detaches the tab from its renderer; if the renderer has no remaining
    /// tabs, retires it and returns [`CloseAction::DetachAndKillRenderer`].
    /// Otherwise returns [`CloseAction::DetachOnly`].
    pub fn close_tab(&mut self, tab: TabId) -> Result<CloseAction, LifecycleError> {
        let record = self
            .tabs
            .remove(&tab)
            .ok_or(LifecycleError::UnknownTab(tab))?;
        let renderer = record.renderer;
        self.scheduler.detach_tab(renderer, tab)?;
        let remaining = self
            .scheduler
            .tab_count(renderer)
            .expect("scheduler must still know the renderer we just detached from");
        if remaining == 0 {
            // No tabs left — retire the slot and signal kill to orchestrator.
            self.scheduler.retire_renderer(renderer)?;
            Ok(CloseAction::DetachAndKillRenderer { renderer, tab })
        } else {
            Ok(CloseAction::DetachOnly { renderer, tab })
        }
    }

    /// Suspend a tab. Returns a [`SuspendAction`] for the orchestrator to
    /// realize via IPC; Module 10's [`crate::suspension::SuspensionPolicy`]
    /// describes what the renderer should do while Suspended.
    pub fn suspend_tab(
        &mut self,
        tab: TabId,
        reason: SuspendReason,
    ) -> Result<SuspendAction, LifecycleError> {
        let record = self
            .tabs
            .get_mut(&tab)
            .ok_or(LifecycleError::UnknownTab(tab))?;
        if record.state == TabState::Suspended {
            return Err(LifecycleError::NoStateChange(tab));
        }
        record.state = TabState::Suspended;
        record.suspend_reason = Some(reason);
        Ok(SuspendAction {
            tab,
            renderer: record.renderer,
            reason,
        })
    }

    /// Resume a suspended tab. Returns a [`ResumeAction`] for the orchestrator
    /// to undo whatever the suspension policy applied.
    pub fn resume_tab(&mut self, tab: TabId) -> Result<ResumeAction, LifecycleError> {
        let record = self
            .tabs
            .get_mut(&tab)
            .ok_or(LifecycleError::UnknownTab(tab))?;
        if record.state == TabState::Active {
            return Err(LifecycleError::NoStateChange(tab));
        }
        record.state = TabState::Active;
        record.suspend_reason = None;
        Ok(ResumeAction {
            tab,
            renderer: record.renderer,
        })
    }

    /// Why the tab is suspended. `None` if the tab is Active or unknown.
    pub fn tab_suspend_reason(&self, tab: TabId) -> Option<SuspendReason> {
        self.tabs.get(&tab).and_then(|r| r.suspend_reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{IdentityProfile, Mode};

    fn make_registry() -> (ProfileRegistry, Uuid, Uuid, Uuid) {
        let mut r = ProfileRegistry::new_in_memory();
        let p_std_a = IdentityProfile::builder()
            .name("Personal")
            .mode(Mode::Standard)
            .build()
            .unwrap();
        let p_std_b = IdentityProfile::builder()
            .name("Work")
            .mode(Mode::Standard)
            .build()
            .unwrap();
        let p_strict = IdentityProfile::builder()
            .name("BankAccount")
            .mode(Mode::Strict)
            .build()
            .unwrap();
        let id_a = p_std_a.profile_id();
        let id_b = p_std_b.profile_id();
        let id_strict = p_strict.profile_id();
        r.insert(p_std_a).unwrap();
        r.insert(p_std_b).unwrap();
        r.insert(p_strict).unwrap();
        (r, id_a, id_b, id_strict)
    }

    #[test]
    fn spawn_first_standard_tab_spawns_renderer() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let action = lm.spawn_tab(id_a).unwrap();
        assert!(matches!(
            action,
            ProcessAction::SpawnRenderer {
                mode: Mode::Standard,
                ..
            }
        ));
        assert_eq!(lm.tab_count(), 1);
    }

    #[test]
    fn second_standard_tab_same_profile_attaches_to_existing() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let first = lm.spawn_tab(id_a).unwrap();
        let first_renderer = match first {
            ProcessAction::SpawnRenderer { renderer, .. } => renderer,
            _ => panic!("expected SpawnRenderer for first tab"),
        };
        let second = lm.spawn_tab(id_a).unwrap();
        match second {
            ProcessAction::AttachToExisting { renderer, .. } => {
                assert_eq!(renderer, first_renderer);
            }
            _ => panic!("expected AttachToExisting for second tab same profile"),
        }
        assert_eq!(lm.tab_count(), 2);
    }

    #[test]
    fn second_standard_tab_different_profile_spawns_new() {
        let (reg, id_a, id_b, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        lm.spawn_tab(id_a).unwrap();
        let action = lm.spawn_tab(id_b).unwrap();
        assert!(matches!(action, ProcessAction::SpawnRenderer { .. }));
    }

    #[test]
    fn strict_tab_always_spawns_new_even_with_existing_strict() {
        let (reg, _, _, id_strict) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let first = lm.spawn_tab(id_strict).unwrap();
        let second = lm.spawn_tab(id_strict).unwrap();
        assert!(matches!(first, ProcessAction::SpawnRenderer { .. }));
        assert!(matches!(second, ProcessAction::SpawnRenderer { .. }));
    }

    #[test]
    fn unknown_profile_rejected() {
        let reg = ProfileRegistry::new_in_memory();
        let mut lm = LifecycleManager::new(reg);
        let bogus = Uuid::new_v4();
        let err = lm.spawn_tab(bogus).unwrap_err();
        assert_eq!(err, LifecycleError::UnknownProfile(bogus));
    }

    #[test]
    fn close_only_tab_kills_renderer() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let action = lm.spawn_tab(id_a).unwrap();
        let tab = match action {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        let close = lm.close_tab(tab).unwrap();
        assert!(matches!(close, CloseAction::DetachAndKillRenderer { .. }));
        assert_eq!(lm.tab_count(), 0);
    }

    #[test]
    fn close_one_of_many_tabs_keeps_renderer() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let a1 = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        let _a2 = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::AttachToExisting { tab, .. } => tab,
            other => panic!("expected AttachToExisting, got {other:?}"),
        };
        let close = lm.close_tab(a1).unwrap();
        assert!(matches!(close, CloseAction::DetachOnly { .. }));
        assert_eq!(lm.tab_count(), 1);
    }

    #[test]
    fn close_unknown_tab_rejected() {
        let reg = ProfileRegistry::new_in_memory();
        let mut lm = LifecycleManager::new(reg);
        let err = lm.close_tab(TabId(999)).unwrap_err();
        assert_eq!(err, LifecycleError::UnknownTab(TabId(999)));
    }

    #[test]
    fn suspend_then_resume_round_trip() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let tab = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        assert_eq!(lm.tab_state(tab), Some(TabState::Active));
        let suspend = lm.suspend_tab(tab, SuspendReason::UserRequested).unwrap();
        assert_eq!(suspend.tab, tab);
        assert_eq!(suspend.reason, SuspendReason::UserRequested);
        assert_eq!(lm.tab_state(tab), Some(TabState::Suspended));
        assert_eq!(
            lm.tab_suspend_reason(tab),
            Some(SuspendReason::UserRequested)
        );
        let resume = lm.resume_tab(tab).unwrap();
        assert_eq!(resume.tab, tab);
        assert_eq!(lm.tab_state(tab), Some(TabState::Active));
        assert_eq!(lm.tab_suspend_reason(tab), None);
    }

    #[test]
    fn suspend_already_suspended_rejected() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let tab = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        lm.suspend_tab(tab, SuspendReason::UserRequested).unwrap();
        let err = lm
            .suspend_tab(tab, SuspendReason::UserRequested)
            .unwrap_err();
        assert_eq!(err, LifecycleError::NoStateChange(tab));
    }

    #[test]
    fn resume_active_tab_rejected() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let tab = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        let err = lm.resume_tab(tab).unwrap_err();
        assert_eq!(err, LifecycleError::NoStateChange(tab));
    }

    #[test]
    fn suspend_unknown_tab_rejected() {
        let reg = ProfileRegistry::new_in_memory();
        let mut lm = LifecycleManager::new(reg);
        let err = lm
            .suspend_tab(TabId(42), SuspendReason::UserRequested)
            .unwrap_err();
        assert_eq!(err, LifecycleError::UnknownTab(TabId(42)));
    }

    #[test]
    fn abort_spawn_rolls_back_state() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let action = lm.spawn_tab(id_a).unwrap();
        let tab = match action {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        let close = lm.abort_spawn(tab).unwrap();
        assert!(matches!(close, CloseAction::DetachAndKillRenderer { .. }));
        assert_eq!(lm.tab_count(), 0);
    }

    #[test]
    fn tab_profile_id_immutable_for_lifetime() {
        // §3.1: there is no public API to retarget a tab's profile_id.
        // This test pins the read-only accessor and the absence of a setter.
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let tab = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        assert_eq!(lm.tab_profile_id(tab), Some(id_a));
        // After suspend + resume, the binding is unchanged.
        lm.suspend_tab(tab, SuspendReason::UserRequested).unwrap();
        lm.resume_tab(tab).unwrap();
        assert_eq!(lm.tab_profile_id(tab), Some(id_a));
    }

    #[test]
    fn renderer_isolation_across_profiles() {
        // Two Standard tabs on different profiles must end up on different
        // renderers; verify via tab_renderer accessor.
        let (reg, id_a, id_b, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let tab_a = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        let tab_b = match lm.spawn_tab(id_b).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        let r_a = lm.tab_renderer(tab_a).unwrap();
        let r_b = lm.tab_renderer(tab_b).unwrap();
        assert_ne!(r_a, r_b);
    }

    #[test]
    fn tab_ids_are_monotonic_starting_at_one() {
        let (reg, id_a, _, _) = make_registry();
        let mut lm = LifecycleManager::new(reg);
        let t1 = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::SpawnRenderer { tab, .. } => tab,
            _ => unreachable!(),
        };
        let t2 = match lm.spawn_tab(id_a).unwrap() {
            ProcessAction::AttachToExisting { tab, .. } => tab,
            _ => unreachable!(),
        };
        assert_eq!(t1, TabId(1));
        assert_eq!(t2, TabId(2));
    }
}
