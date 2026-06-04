//! UI regression scenarios — developer QA suite.
//!
//! This entire file is gated behind `#[cfg(test)]` and is never compiled into
//! production builds. Zero runtime cost, zero binary size impact.
//!
//! See `docs/ui-testing.md` for the full guide on running, reading, and
//! extending these scenarios.
//!
//! Quick reference
//! ---------------
//! Run all regressions:   cargo test -p pb-ui regression
//! Run all UI tests:      cargo test -p pb-ui
//! Run one scenario:      cargo test -p pb-ui regression_sidebar_tooltip

#![cfg(test)]

use crate::{
    design,
    shell::{ready_state_for_test, update, view, AppPhase, Message, Mode},
    sidebar::SidebarMsg,
    tab_bar::TabBarMsg,
};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Send one message and discard the returned Task.
/// Async side-effects (timers, IPC) do not run in unit tests — only the
/// synchronous state mutations matter for regression assertions.
fn step(state: &mut crate::shell::AppState, msg: Message) {
    let _ = update(state, msg);
}

/// Build the widget tree for `state` and immediately drop it.
/// This verifies view() does not panic (bad index, failed unwrap, etc.)
/// for the current state. It does NOT check visual layout or pixel values.
fn assert_view_stable(state: &crate::shell::AppState) {
    let _el = view(state);
}

// ---------------------------------------------------------------------------
// Group 1: View stability
//
// Purpose: view() must never panic regardless of state. These scenarios
// exercise edge cases (0 tabs, extreme window sizes, fullscreen) that could
// cause index-out-of-bounds or failed unwraps in layout code.
// ---------------------------------------------------------------------------

/// view() must never panic for the default Ready state.
#[test]
fn regression_view_stable_on_ready_state() {
    let state = ready_state_for_test();
    assert_view_stable(&state);
}

/// view() must stay stable when there are zero open tabs.
#[test]
fn regression_view_stable_with_zero_tabs() {
    let mut state = ready_state_for_test();
    let ids: Vec<usize> = state.tab_bar.tabs.iter().map(|t| t.id).collect();
    for id in ids {
        step(
            &mut state,
            Message::TabBar(TabBarMsg::TabCloseRequested(id)),
        );
    }
    assert_view_stable(&state);
}

/// view() must stay stable at common and extreme window sizes.
#[test]
fn regression_view_stable_across_window_sizes() {
    let mut state = ready_state_for_test();
    for (w, h) in [(800.0_f32, 600.0_f32), (1920.0, 1080.0), (375.0, 812.0)] {
        step(
            &mut state,
            Message::WindowResized(iced::window::Id::unique(), iced::Size::new(w, h)),
        );
        assert_view_stable(&state);
    }
}

/// view() must stay stable in Strict mode (terracotta wallpaper + border overlay).
#[test]
fn regression_view_stable_in_strict_mode() {
    let mut state = ready_state_for_test();
    state.mode = Mode::Strict;
    state.phase = AppPhase::Ready;
    assert_view_stable(&state);
}

/// view() must stay stable after a drag-reorder operation completes.
#[test]
fn regression_view_stable_after_drag() {
    let mut state = ready_state_for_test();
    let from_id = state.tab_bar.tabs[0].id;
    let to_id = state.tab_bar.tabs[1].id;
    step(
        &mut state,
        Message::Sidebar(SidebarMsg::PillPressed(from_id)),
    );
    step(&mut state, Message::Sidebar(SidebarMsg::SidebarMoved));
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(to_id)));
    step(&mut state, Message::Sidebar(SidebarMsg::SidebarReleased));
    assert_view_stable(&state);
}

// ---------------------------------------------------------------------------
// Group 2: Tab lifecycle
//
// Purpose: opening, activating, and closing tabs must update state correctly.
// These catch regressions in TabBar logic, sidebar sync, and active-tab tracking.
// ---------------------------------------------------------------------------

/// Opening a new tab increases the tab count by exactly one.
#[test]
fn regression_new_tab_increases_count() {
    let mut state = ready_state_for_test();
    let before = state.tab_bar.tabs.len();
    step(&mut state, Message::TabBar(TabBarMsg::NewTabPressed));
    assert_eq!(state.tab_bar.tabs.len(), before + 1);
}

/// Closing a standard tab removes it immediately with no modal.
#[test]
fn regression_close_standard_tab_removes_it() {
    let mut state = ready_state_for_test();
    let id = state
        .tab_bar
        .tabs
        .iter()
        .find(|t| t.mode == Mode::Standard)
        .unwrap()
        .id;
    let before = state.tab_bar.tabs.len();
    step(
        &mut state,
        Message::TabBar(TabBarMsg::TabCloseRequested(id)),
    );
    assert_eq!(state.tab_bar.tabs.len(), before - 1);
    assert!(!state.tab_bar.tabs.iter().any(|t| t.id == id));
}

/// Closing a tab via the sidebar tooltip X button removes it.
#[test]
fn regression_tooltip_x_closes_standard_tab() {
    let mut state = ready_state_for_test();
    let id = state
        .tab_bar
        .tabs
        .iter()
        .find(|t| t.mode == Mode::Standard)
        .unwrap()
        .id;
    let before = state.tab_bar.tabs.len();
    step(
        &mut state,
        Message::Sidebar(SidebarMsg::PillClosePressed(id)),
    );
    assert_eq!(state.tab_bar.tabs.len(), before - 1);
}

/// Tapping a sidebar pill (press + release, no move) activates that tab.
#[test]
fn regression_sidebar_pill_tap_activates_tab() {
    let mut state = ready_state_for_test();
    let target_id = state
        .tab_bar
        .tabs
        .iter()
        .find(|t| t.id != state.tab_bar.active_id)
        .unwrap()
        .id;
    step(
        &mut state,
        Message::Sidebar(SidebarMsg::PillPressed(target_id)),
    );
    step(
        &mut state,
        Message::Sidebar(SidebarMsg::PillReleased(target_id)),
    );
    assert_eq!(state.tab_bar.active_id, target_id);
}

// ---------------------------------------------------------------------------
// Group 3: Sidebar tooltip lifecycle
//
// Purpose: the pill hover-card has a custom state machine (enter → grace →
// commit). These scenarios lock down every transition so refactors to the
// tooltip timer or the shell overlay don't silently break it.
// ---------------------------------------------------------------------------

/// Hovering a pill sets tooltip_pill_id and clears any pending hide.
#[test]
fn regression_pill_hover_shows_tooltip() {
    let mut state = ready_state_for_test();
    let id = state.tab_bar.tabs[0].id;
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(id)));
    assert_eq!(state.sidebar.tooltip_pill_id, Some(id));
    assert!(!state.sidebar.tooltip_hide_pending);
}

/// Leaving a pill starts the grace period but keeps the card visible.
#[test]
fn regression_pill_leave_starts_grace_period() {
    let mut state = ready_state_for_test();
    let id = state.tab_bar.tabs[0].id;
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(id)));
    step(&mut state, Message::Sidebar(SidebarMsg::PillLeft(id)));
    assert!(state.sidebar.tooltip_hide_pending);
    assert_eq!(state.sidebar.tooltip_pill_id, Some(id)); // still visible
}

/// Re-entering the pill during the grace period cancels the hide.
#[test]
fn regression_reenter_during_grace_cancels_hide() {
    let mut state = ready_state_for_test();
    let id = state.tab_bar.tabs[0].id;
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(id)));
    step(&mut state, Message::Sidebar(SidebarMsg::PillLeft(id)));
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(id)));
    assert!(!state.sidebar.tooltip_hide_pending);
    assert_eq!(state.sidebar.tooltip_pill_id, Some(id));
}

/// When the grace-period timer fires, the tooltip is hidden.
#[test]
fn regression_grace_period_commit_hides_tooltip() {
    let mut state = ready_state_for_test();
    let id = state.tab_bar.tabs[0].id;
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(id)));
    step(&mut state, Message::Sidebar(SidebarMsg::PillLeft(id)));
    step(&mut state, Message::HideTooltip); // simulates the 200ms timer firing
    assert_eq!(state.sidebar.tooltip_pill_id, None);
    assert!(!state.sidebar.tooltip_hide_pending);
}

/// A stale HideTooltip (timer that fired after re-entry) must be a no-op.
#[test]
fn regression_late_hide_tooltip_noop_after_reentry() {
    let mut state = ready_state_for_test();
    let id = state.tab_bar.tabs[0].id;
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(id)));
    step(&mut state, Message::Sidebar(SidebarMsg::PillLeft(id)));
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(id))); // re-entered
    step(&mut state, Message::HideTooltip); // stale timer
    assert_eq!(state.sidebar.tooltip_pill_id, Some(id)); // still visible
}

// ---------------------------------------------------------------------------
// Group 4: Sidebar drag-to-reorder
//
// Purpose: dragging a pill over another must swap their positions in the tab
// list without corrupting the drag_id tracking (the yo-yo bug fix in Module
// 44.3 must not regress).
// ---------------------------------------------------------------------------

/// Dragging pill A over pill B swaps their positions.
#[test]
fn regression_sidebar_drag_reorders_tabs() {
    let mut state = ready_state_for_test();
    let from_id = state.tab_bar.tabs[0].id;
    let to_id = state.tab_bar.tabs[1].id;
    step(
        &mut state,
        Message::Sidebar(SidebarMsg::PillPressed(from_id)),
    );
    step(&mut state, Message::Sidebar(SidebarMsg::SidebarMoved));
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(to_id)));
    assert_eq!(state.tab_bar.tabs[0].id, to_id);
    assert_eq!(state.tab_bar.tabs[1].id, from_id);
}

/// A tap (press+release without SidebarMoved) must NOT trigger a reorder.
#[test]
fn regression_tap_does_not_reorder() {
    let mut state = ready_state_for_test();
    let id0 = state.tab_bar.tabs[0].id;
    let id1 = state.tab_bar.tabs[1].id;
    step(&mut state, Message::Sidebar(SidebarMsg::PillPressed(id0)));
    // No SidebarMoved — this is a tap, not a drag.
    step(&mut state, Message::Sidebar(SidebarMsg::PillReleased(id0)));
    // Order must be unchanged.
    assert_eq!(state.tab_bar.tabs[0].id, id0);
    assert_eq!(state.tab_bar.tabs[1].id, id1);
}

// ---------------------------------------------------------------------------
// Group 5: L41 — Strict mode invariants
//
// Purpose: Standard→Strict is one-way (§3.6). The morph must complete
// correctly and the reverse must be blocked unconditionally.
// ---------------------------------------------------------------------------

/// After morph completes, mode is Strict and phase is Ready.
#[test]
fn regression_strict_mode_locks_after_morph() {
    let mut state = ready_state_for_test();
    step(&mut state, Message::ConvertToStrict);
    step(
        &mut state,
        Message::MorphTick(design::motion::MODE_CONVERT_MS),
    );
    assert_eq!(state.mode, Mode::Strict);
    assert_eq!(state.phase, AppPhase::Ready);
}

/// ConvertToStrict from Strict mode is a no-op (§3.6 one-way lock).
#[test]
fn regression_strict_to_standard_is_blocked() {
    let mut state = ready_state_for_test();
    state.mode = Mode::Strict;
    state.phase = AppPhase::Ready;
    step(&mut state, Message::ConvertToStrict);
    assert_eq!(state.mode, Mode::Strict);
}

// ---------------------------------------------------------------------------
// Group 6: Window resize
//
// Purpose: dimensions and tab-bar width must stay in sync. view() must remain
// stable at any size so layout arithmetic never divides by zero or overflows.
// ---------------------------------------------------------------------------

/// window_width and window_height update on WindowResized.
#[test]
fn regression_window_resize_syncs_dimensions() {
    let mut state = ready_state_for_test();
    step(
        &mut state,
        Message::WindowResized(iced::window::Id::unique(), iced::Size::new(2560.0, 1440.0)),
    );
    assert_eq!(state.window_width, 2560.0);
    assert_eq!(state.window_height, 1440.0);
    assert_view_stable(&state);
}

/// is_fullscreen can be toggled without breaking view().
#[test]
fn regression_fullscreen_toggle_view_stable() {
    let mut state = ready_state_for_test();
    state.is_fullscreen = true;
    assert_view_stable(&state);
    state.is_fullscreen = false;
    assert_view_stable(&state);
}

// ---------------------------------------------------------------------------
// Group: Module 47 — Find in page
// ---------------------------------------------------------------------------

/// view() must not panic with find bar open.
#[test]
fn regression_find_bar_view_stable_open() {
    let mut state = ready_state_for_test();
    step(
        &mut state,
        Message::Find(crate::find_in_page::FindMsg::Opened),
    );
    assert!(state.find.open);
    assert_view_stable(&state);
}

/// view() must not panic with find bar closed (default state).
#[test]
fn regression_find_bar_view_stable_closed() {
    let state = ready_state_for_test();
    assert!(!state.find.open);
    assert_view_stable(&state);
}

/// Cmd+F equivalent opens the find bar.
#[test]
fn regression_find_bar_opens_via_message() {
    let mut state = ready_state_for_test();
    step(
        &mut state,
        Message::Find(crate::find_in_page::FindMsg::Opened),
    );
    assert!(state.find.open);
}

/// FindEscape closes the find bar when open.
#[test]
fn regression_find_bar_escape_closes_when_open() {
    let mut state = ready_state_for_test();
    step(
        &mut state,
        Message::Find(crate::find_in_page::FindMsg::Opened),
    );
    step(&mut state, Message::FindEscape);
    assert!(!state.find.open);
}

/// FindEscape with find bar already closed: no panic.
#[test]
fn regression_find_escape_noop_when_closed() {
    let mut state = ready_state_for_test();
    step(&mut state, Message::FindEscape);
    assert!(!state.find.open);
    assert_view_stable(&state);
}

/// Query change is reflected in state.
#[test]
fn regression_find_bar_query_round_trips() {
    let mut state = ready_state_for_test();
    step(
        &mut state,
        Message::Find(crate::find_in_page::FindMsg::Opened),
    );
    step(
        &mut state,
        Message::Find(crate::find_in_page::FindMsg::QueryChanged(
            "privacy".to_string(),
        )),
    );
    assert_eq!(state.find.query, "privacy");
    assert_view_stable(&state);
}

/// find bar open in Strict mode must not panic.
#[test]
fn regression_find_bar_stable_in_strict_mode() {
    let mut state = ready_state_for_test();
    state.mode = Mode::Strict;
    step(
        &mut state,
        Message::Find(crate::find_in_page::FindMsg::Opened),
    );
    assert_view_stable(&state);
}
