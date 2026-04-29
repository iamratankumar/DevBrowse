//! Suspension semantics, Module 10.
//!
//! Module 9 owns the Active <-> Suspended state transition. Module 10 adds
//! the *meaning* of "suspended": the reason a tab was suspended, the policy
//! a renderer should apply while suspended, and the action values the
//! orchestrator dispatches over IPC.
//!
//! This module defines TYPES ONLY. It does not freeze JS, pause network,
//! or release GPU memory; those are renderer-side responsibilities driven
//! by IPC commands derived from a [`SuspendAction`] + [`SuspensionPolicy`].
//!
//! Why split the policy from the action: a [`SuspendAction`] is "this tab
//! has just transitioned to Suspended"; a [`SuspensionPolicy`] is "here is
//! how a Suspended tab should behave". The orchestrator combines them
//! (often per-mode: Strict tabs may use a stricter policy than Standard)
//! before issuing IPC. Lifecycle does not embed policy because policy is
//! a global / per-mode concern, not a per-tab one.
//!
//! TODO(Module 80, orchestrator): map [`SuspendAction`] + [`SuspensionPolicy`]
//!   onto pb-ipc `SuspendTab` / `ResumeTab` messages (added v1.6). Conversion
//!   adapters between [`SuspendReason`] and the proto `SuspendReason` enum
//!   live in this crate (pb-identity may import pb-ipc).
//! TODO(per-mode policy): in Phase 2 the architecture leaves Strict-vs-
//!   Standard suspension policy choice to the orchestrator. Document the
//!   chosen split in §3 when it lands.
//! TODO(idle suspension): `SuspendReason::BackgroundIdle` and
//!   `SuspendReason::MemoryPressure` are reserved variants. Auto-suspension
//!   triggers are deferred (architecture §7: "Tab discard under memory
//!   pressure | Deferred").

use crate::scheduler::{RendererId, TabId};
use serde::{Deserialize, Serialize};

/// Why a tab was suspended.
///
/// `UserRequested` is the only variant wired in v1. The other variants are
/// reserved so call sites that branch on reason are exhaustive today and
/// stay correct when auto-suspension lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspendReason {
    /// User toggled suspend explicitly (UI, hotkey, settings).
    UserRequested,
    /// Background tab inactive past a policy threshold. (Reserved; not
    /// produced by any code path in v1.)
    BackgroundIdle,
    /// OS / process-host signaled memory pressure. (Reserved; deferred
    /// per architecture §7.)
    MemoryPressure,
}

/// Behavior a renderer should apply while a tab is suspended.
///
/// Defaults pause everything that costs CPU / network / battery while
/// keeping the DOM in memory so resume is instant. Override per-mode or
/// per-tab in the orchestrator when policy diverges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspensionPolicy {
    /// Pause JavaScript execution (event loop, microtasks, async tasks).
    pub pause_js: bool,
    /// Pause `setTimeout`, `setInterval`, `requestAnimationFrame`, and
    /// `requestIdleCallback`.
    pub pause_timers: bool,
    /// Block new network requests; in-flight requests run to completion.
    pub pause_network: bool,
    /// Pause `<video>` / `<audio>` / WebAudio playback.
    pub pause_media: bool,
    /// Keep the parsed DOM in memory. Setting `false` enables full discard
    /// (re-parse on resume); deferred per §7 and not implemented in v1.
    pub preserve_dom: bool,
    /// Auto-kill the renderer after this many seconds suspended. `None`
    /// means never auto-kill (default in v1).
    pub max_suspended_seconds: Option<u64>,
}

impl Default for SuspensionPolicy {
    fn default() -> Self {
        Self {
            pause_js: true,
            pause_timers: true,
            pause_network: true,
            pause_media: true,
            preserve_dom: true,
            max_suspended_seconds: None,
        }
    }
}

/// Emitted by [`crate::lifecycle::LifecycleManager::suspend_tab`] when a
/// tab transitions Active -> Suspended. The orchestrator translates this
/// into a renderer-side IPC command using [`SuspensionPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuspendAction {
    pub tab: TabId,
    pub renderer: RendererId,
    pub reason: SuspendReason,
}

/// Emitted by [`crate::lifecycle::LifecycleManager::resume_tab`] when a tab
/// transitions Suspended -> Active. The orchestrator instructs the renderer
/// to undo whatever [`SuspensionPolicy`] applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeAction {
    pub tab: TabId,
    pub renderer: RendererId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_pauses_everything_and_preserves_dom() {
        let p = SuspensionPolicy::default();
        assert!(p.pause_js);
        assert!(p.pause_timers);
        assert!(p.pause_network);
        assert!(p.pause_media);
        assert!(p.preserve_dom);
        assert_eq!(
            p.max_suspended_seconds, None,
            "v1: never auto-kill (architecture §7 deferred)"
        );
    }

    #[test]
    fn suspend_reason_serializes_snake_case() {
        // toml round-trip via wrapper (toml requires a top-level table):
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            r: SuspendReason,
        }
        let w = W {
            r: SuspendReason::BackgroundIdle,
        };
        let s = toml::to_string(&w).unwrap();
        assert!(
            s.contains("r = \"background_idle\""),
            "expected snake_case serialization, got:\n{s}"
        );
        let w2: W = toml::from_str(&s).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn policy_round_trips_via_toml() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W {
            p: SuspensionPolicy,
        }
        let w = W {
            p: SuspensionPolicy {
                pause_js: true,
                pause_timers: false,
                pause_network: true,
                pause_media: true,
                preserve_dom: true,
                max_suspended_seconds: Some(300),
            },
        };
        let s = toml::to_string(&w).unwrap();
        let w2: W = toml::from_str(&s).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn suspend_and_resume_actions_carry_ids() {
        let s = SuspendAction {
            tab: TabId(7),
            renderer: RendererId(3),
            reason: SuspendReason::UserRequested,
        };
        assert_eq!(s.tab, TabId(7));
        assert_eq!(s.renderer, RendererId(3));
        assert_eq!(s.reason, SuspendReason::UserRequested);

        let r = ResumeAction {
            tab: TabId(7),
            renderer: RendererId(3),
        };
        assert_eq!(r.tab, TabId(7));
        assert_eq!(r.renderer, RendererId(3));
    }
}
