//! pb-ui::tab_bar — Module 44.
//!
//! Sticky horizontal tab bar, identity capsule, and tabs-pill counter.
//! Spec: docs/superpowers/specs/2026-05-28-module-44-tab-bar-design.md
//! Patterns: mode-indicator.md, strict-tab-close.md
//! Mock: mock/devbrowse-v7-locked.html (Scene 1 bottom, Scene 2 top)
//! Invariants: L27, L41, §3.6
//!
//! Sub-modules (view layer):
//!   strip      — view_strip() + chip() rendering
//!   top_chrome — view_top_chrome() (identity capsule + tabs-pill)
//!   modal      — view_strict_close_modal()
//!
//! TODO Module 44 wiring: TabClosed(id) -> pb-network::TabBroker (Phase 11, Module 80)
//! TODO Module 44 wiring: NewTabRequested -> pb-network::TabBroker (Phase 11, Module 80)
//! TODO Module 44 wiring: has_unsaved_input <- ChromeCommand::UnsavedInputChanged (Phase 11)
//! TODO Module 44 wiring: TabBarPosition <- pb-storage::Settings::tab_bar_position (Module 64)
//! TODO Module 44 wiring: Cmd+W shortcut <- keyboard::on_key_press subscription (Module 44.1)

mod modal;
mod strip;
mod top_chrome;

use crate::design;
use crate::shell::Mode;

// ---------------------------------------------------------------------------
// Position
// ---------------------------------------------------------------------------

/// Where the tab bar is anchored in the window.
/// Set at construction; changed only by the settings module (Module 64).
/// Change `TabBarPosition::Bottom` to `TabBarPosition::Top` in shell.rs to preview the top variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TabBarPosition {
    #[default]
    Bottom,
    Top,
}

// ---------------------------------------------------------------------------
// Tab entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TabEntry {
    pub id: usize,
    /// Page title shown in the chip when space allows.
    pub title: String,
    /// 1-2 char favicon stand-in (no network fetch in Phase 8).
    pub favicon_label: String,
    pub mode: Mode,
    pub is_pinned: bool,
    pub is_muted: bool,
    /// True when the renderer reports at least one dirty input element.
    /// Drives the Strict-tab-close modal (strict-tab-close.md).
    pub has_unsaved_input: bool,
    /// Dominant colour sampled from the site's favicon [r, g, b, a] 0-1.
    /// None until the favicon loads. Used to tint the inactive sidebar pill.
    pub accent_color: Option<[f32; 4]>,
    /// Display URL shown on card view cards. Phase 11 replaces with live URL.
    pub url: String,
}

// ---------------------------------------------------------------------------
// Strict-close modal state
// ---------------------------------------------------------------------------

/// State machine for the strict-tab-close warning modal (strict-tab-close.md).
/// `Confirming(id)` is only reachable from a Strict tab (§3.6 structural lock).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum StrictCloseModal {
    #[default]
    Hidden,
    Confirming(usize),
}

// ---------------------------------------------------------------------------
// Messages and events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum TabBarMsg {
    // Strip-level events (emitted by the single strip mouse_area).
    StripMoved(f32),
    StripPressed,
    StripReleased,
    StripExited,

    // Modal events.
    StrictCloseConfirmed,
    StrictCloseCancelled,

    // Plus button.
    NewTabPressed,
    // Counter pill hover target — no action.
    Noop,

    /// Stabilization timer expired. The u32 is the generation it was scheduled
    /// for; if it doesn't match the current generation it is a stale timer from
    /// a previous close and is silently discarded.
    StabilizeExpired(u32),

    /// Tabs-pill grid button clicked — shell opens the Tab Screen.
    TabsGridPressed,

    // Kept for tests — not emitted by the view.
    TabActivated(usize),
    TabCloseRequested(usize),
    TabHovered(Option<usize>),
}

/// Events that cross the module boundary to the shell.
#[derive(Debug, Clone)]
pub enum TabBarEvent {
    TabClosed(usize),
    NewTabRequested,
    /// User clicked empty strip space — shell should call window::drag().
    WindowDragRequested,
    /// Strip X-button close fired; shell must schedule a 400 ms StabilizeExpired
    /// carrying this generation number.
    StabilizeRequested(u32),
    /// Tabs-pill grid button clicked — shell opens the Tab Screen (Module 44.6).
    TabScreenRequested,
}

// ---------------------------------------------------------------------------
// TabBar
// ---------------------------------------------------------------------------

pub struct TabBar {
    pub position: TabBarPosition,
    pub tabs: Vec<TabEntry>,
    pub active_id: usize,
    pub hovered_tab_id: Option<usize>,
    pub modal: StrictCloseModal,
    pub mode: Mode,
    /// Never logged (L27). Displayed in identity capsule only.
    pub profile_name: String,
    /// Synced from AppState::window_width on every WindowResized.
    pub(crate) window_width: f32,
    /// Cursor x within the strip's local coordinate space (0 = strip left edge).
    pub(crate) cursor_strip_x: f32,
    /// Tab being dragged for reorder, if any.
    pub(crate) drag_id: Option<usize>,
    /// X where the drag press started.
    pub(crate) drag_start_x: f32,
    /// True once the cursor has moved enough to commit to a drag (not a click).
    pub(crate) drag_active: bool,
    /// X at which the last swap happened; prevents immediate oscillation back.
    pub(crate) drag_last_swap_x: f32,
    /// Tab close stabilization: holds (active_px, other_px) at their pre-close
    /// values for 400 ms after each strip X-button close, so X buttons stay
    /// under the cursor and the user can keep clicking without chasing them.
    /// Cleared immediately when the cursor leaves the strip or the timer fires.
    pub(crate) frozen_chip_px: Option<(f32, f32)>,
    /// Monotonically increasing counter — incremented on every strip close.
    /// StabilizeExpired carries the generation it was scheduled for; if it
    /// doesn't match the current value the timer is stale and discarded.
    /// This makes the 400 ms window always measure from the *last* close.
    pub(crate) stabilize_generation: u32,
}

impl std::fmt::Debug for TabBar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TabBar")
            .field("position", &self.position)
            .field("tab_count", &self.tabs.len())
            .field("active_id", &self.active_id)
            .field("modal", &self.modal)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Construction and sync
// ---------------------------------------------------------------------------

impl TabBar {
    pub fn new(position: TabBarPosition) -> Self {
        Self {
            position,
            tabs: Self::stub_tabs(),
            active_id: 2,
            hovered_tab_id: None,
            modal: StrictCloseModal::Hidden,
            mode: Mode::Standard,
            profile_name: String::new(),
            window_width: 1280.0,
            cursor_strip_x: 0.0,
            drag_id: None,
            drag_start_x: 0.0,
            drag_active: false,
            drag_last_swap_x: 0.0,
            frozen_chip_px: None,
            stabilize_generation: 0,
        }
    }

    /// Called by shell on ProfileLoaded and ModeChanged.
    /// `profile_name` is never logged (L27).
    /// Also updates the active tab's mode so its chip reflects the conversion (§3.6).
    pub fn sync_mode(&mut self, mode: Mode, profile_name: &str) {
        self.mode = mode;
        self.profile_name = profile_name.to_string();
        // The active tab converts in-place (§3.1 / §3.6 — no Strict→Standard return).
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == self.active_id) {
            tab.mode = mode;
        }
    }

    /// Called by shell on every WindowResized so position math stays accurate.
    pub fn sync_window(&mut self, window_width: f32) {
        self.window_width = window_width;
    }

    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    pub fn has_active_modal(&self) -> bool {
        self.modal != StrictCloseModal::Hidden
    }

    fn stub_tabs() -> Vec<TabEntry> {
        vec![
            TabEntry {
                id: 0,
                title: "github.com".into(),
                favicon_label: "G".into(),
                mode: Mode::Standard,
                is_pinned: false,
                is_muted: false,
                has_unsaved_input: false,
                accent_color: Some([0.133, 0.133, 0.133, 1.0]),
                url: "https://github.com".into(),
            },
            TabEntry {
                id: 1,
                title: "figma.com".into(),
                favicon_label: "F".into(),
                mode: Mode::Standard,
                is_pinned: false,
                is_muted: false,
                has_unsaved_input: false,
                accent_color: Some([0.627, 0.322, 1.0, 1.0]),
                url: "https://figma.com".into(),
            },
            TabEntry {
                id: 2,
                title: "github / devbrowse".into(),
                favicon_label: "G".into(),
                mode: Mode::Standard,
                is_pinned: false,
                is_muted: false,
                has_unsaved_input: false,
                accent_color: Some([0.133, 0.133, 0.133, 1.0]),
                url: "https://github.com/devbrowse".into(),
            },
            TabEntry {
                id: 3,
                title: "NYT \u{00b7} Opinion".into(),
                favicon_label: "N".into(),
                mode: Mode::Standard,
                is_pinned: false,
                is_muted: true,
                has_unsaved_input: false,
                accent_color: Some([0.847, 0.067, 0.102, 1.0]),
                url: "https://nytimes.com/opinion".into(),
            },
            TabEntry {
                id: 4,
                title: "strict \u{00b7} banking".into(),
                favicon_label: "B".into(),
                mode: Mode::Strict,
                is_pinned: false,
                is_muted: false,
                has_unsaved_input: true,
                accent_color: None,
                url: "https://bank.example".into(),
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// Position math — pub(crate) so strip.rs can call self.tab_positions()
// ---------------------------------------------------------------------------

impl TabBar {
    /// Per-tab pixel widths. Active tab gets preferred space; others share equally.
    /// Returns (active_px, other_px).
    /// When `frozen_chip_px` is set (stabilization active), inactive chips use
    /// the frozen width so X buttons don't drift while the user keeps clicking.
    fn chip_widths(&self) -> (f32, f32) {
        // Stabilization freeze: return the exact pre-close widths so neither
        // active nor inactive chips change size while the user is clicking X.
        if let Some((frozen_active, frozen_other)) = self.frozen_chip_px {
            if self.tabs.is_empty() {
                return (0.0, 0.0);
            }
            return (frozen_active, frozen_other);
        }
        let n = self.tabs.len();
        if n == 0 {
            return (0.0, 0.0);
        }
        const SPACING: f32 = 1.0;
        // Active tab always shows title + X, so it needs at least 80 px.
        const ACTIVE_MIN_PX: f32 = 80.0;
        let row_pad = design::space::S4 * 2.0;
        let total_spacing = SPACING * (n as f32 - 1.0);
        let available =
            (self.window_width - design::layout::SIDEBAR_COLLAPSED_PX - row_pad - total_spacing)
                .max(0.0);
        let equal_px = available / n as f32;

        if n == 1 {
            return (available.max(ACTIVE_MIN_PX), available.max(ACTIVE_MIN_PX));
        }

        if equal_px >= 80.0 {
            // Ample: active gets a 1.3× width advantage over peers.
            let active_px = (equal_px * 1.30).min(available - (n as f32 - 1.0) * 80.0);
            let other_px = ((available - active_px) / (n as f32 - 1.0)).max(80.0);
            return (active_px, other_px);
        }

        // Dense / crowded: active always gets ACTIVE_MIN_PX (80 px) so title + X
        // are always visible regardless of tab count.  Inactive chips share the
        // remainder without a floor — they go icon-only as space shrinks.
        let active_px = ACTIVE_MIN_PX.min(available);
        let other_px = if available > active_px {
            (available - active_px) / (n as f32 - 1.0)
        } else {
            0.0
        };
        (active_px, other_px)
    }

    /// Exact (tab_id, x_start, width) for each tab in render order.
    /// pub(crate) so strip.rs can call self.tab_positions().
    pub(crate) fn tab_positions(&self) -> Vec<(usize, f32, f32)> {
        let (active_px, other_px) = self.chip_widths();
        let mut x = design::space::S4;
        let mut out = Vec::with_capacity(self.tabs.len());
        for tab in &self.tabs {
            let w = if tab.id == self.active_id {
                active_px
            } else {
                other_px
            };
            out.push((tab.id, x, w));
            x += w + 1.0;
        }
        out
    }

    fn tab_id_at_x(&self, x: f32) -> Option<usize> {
        for (id, x_start, w) in self.tab_positions() {
            if x >= x_start && x < x_start + w {
                return Some(id);
            }
        }
        None
    }

    /// Returns the array index (not tab id) for the tab slot the cursor is in.
    /// Used for drag-reorder swapping.
    fn tab_idx_at_x(&self, x: f32) -> Option<usize> {
        let positions = self.tab_positions();
        for (i, (_, x_start, w)) in positions.iter().enumerate() {
            if x >= *x_start && x < x_start + w {
                return Some(i);
            }
        }
        // Clamp to edges when dragging fast past the strip boundaries.
        if let Some((_, x_start, _)) = positions.first() {
            if x < *x_start {
                return Some(0);
            }
        }
        if let Some((_, x_start, w)) = positions.last() {
            if x >= x_start + w {
                return Some(positions.len().saturating_sub(1));
            }
        }
        None
    }

    fn cursor_in_close_zone(&self) -> bool {
        let Some(id) = self.hovered_tab_id else {
            return false;
        };
        if self
            .tabs
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.is_pinned)
            .unwrap_or(true)
        {
            return false;
        }
        for (tab_id, x_start, w) in self.tab_positions() {
            if tab_id == id {
                // Active chip is always ≥ 80 px (shows title + X).
                // Inactive icon-only chips (< 80 px) have no close button.
                if w < 80.0 {
                    return false;
                }
                return self.cursor_strip_x > x_start + w - 26.0;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

impl TabBar {
    pub fn update(&mut self, msg: TabBarMsg) -> Option<TabBarEvent> {
        match msg {
            TabBarMsg::StripMoved(x) => {
                self.cursor_strip_x = x;
                let new_hover = self.tab_id_at_x(x);
                if self.hovered_tab_id != new_hover {
                    self.hovered_tab_id = new_hover;
                }
                if let Some(drag_id) = self.drag_id {
                    if !self.drag_active && (x - self.drag_start_x).abs() > 8.0 {
                        self.drag_active = true;
                    }
                    if self.drag_active {
                        // Guard against immediate oscillation: only allow a swap
                        // once the cursor has moved at least half a chip width
                        // away from where the previous swap happened. Without
                        // this, tab_positions() shifts after each swap and the
                        // cursor satisfies the condition again in reverse.
                        let moved_since_swap = (x - self.drag_last_swap_x).abs();
                        if moved_since_swap > 30.0 {
                            let drag_i = self.tabs.iter().position(|t| t.id == drag_id);
                            let target_i = self.tab_idx_at_x(x);
                            if let (Some(di), Some(ti)) = (drag_i, target_i) {
                                if di != ti {
                                    self.tabs.swap(di, ti);
                                    self.drag_last_swap_x = x;
                                }
                            }
                        }
                    }
                }
                None
            }
            TabBarMsg::StripPressed => {
                let Some(id) = self.hovered_tab_id else {
                    return Some(TabBarEvent::WindowDragRequested);
                };
                if self.cursor_in_close_zone() {
                    self.drag_id = None;
                    // from_strip=true: freeze chips and request the 200 ms timer.
                    return self.close_tab(id, true);
                }
                self.active_id = id;
                self.drag_id = Some(id);
                self.drag_start_x = self.cursor_strip_x;
                self.drag_last_swap_x = self.cursor_strip_x;
                self.drag_active = false;
                if let Some(tab) = self.tabs.iter().find(|t| t.id == id) {
                    self.mode = tab.mode;
                }
                None
            }
            TabBarMsg::StripReleased => {
                self.drag_id = None;
                self.drag_active = false;
                None
            }
            TabBarMsg::StripExited => {
                self.hovered_tab_id = None;
                // Cursor left the strip — snap to final widths immediately.
                self.frozen_chip_px = None;
                // During an active drag the shell's global-capture mouse_area tracks
                // cursor position and calls StripReleased on mouse-up no matter where
                // the cursor is. Do NOT clear drag state here or the tab snaps to its
                // last swapped position the moment the cursor leaves the strip.
                if !self.drag_active {
                    self.cursor_strip_x = 0.0;
                    self.drag_id = None;
                }
                None
            }
            TabBarMsg::TabActivated(id) => {
                self.active_id = id;
                None
            }
            TabBarMsg::TabHovered(id) => {
                self.hovered_tab_id = id;
                None
            }
            TabBarMsg::TabCloseRequested(id) => {
                if let Some(tab) = self.tabs.iter().find(|t| t.id == id) {
                    if tab.mode == Mode::Strict && tab.has_unsaved_input {
                        self.modal = StrictCloseModal::Confirming(id);
                        return None;
                    }
                }
                // from_strip=false: keyboard/programmatic close, no stabilization.
                self.close_tab(id, false)
            }
            TabBarMsg::StrictCloseConfirmed => {
                if let StrictCloseModal::Confirming(id) = self.modal {
                    self.modal = StrictCloseModal::Hidden;
                    return self.close_tab(id, false);
                }
                None
            }
            TabBarMsg::StrictCloseCancelled => {
                self.modal = StrictCloseModal::Hidden;
                None
            }
            TabBarMsg::NewTabPressed => {
                let new_id = self
                    .tabs
                    .iter()
                    .map(|t| t.id)
                    .max()
                    .map(|m| m + 1)
                    .unwrap_or(0);
                self.tabs.push(TabEntry {
                    id: new_id,
                    title: format!("New Tab {}", new_id + 1),
                    favicon_label: "N".into(),
                    mode: Mode::Standard,
                    is_pinned: false,
                    is_muted: false,
                    has_unsaved_input: false,
                    accent_color: None,
                    url: String::new(),
                });
                self.active_id = new_id;
                self.mode = Mode::Standard;
                self.hovered_tab_id = None;
                Some(TabBarEvent::NewTabRequested)
            }
            TabBarMsg::Noop => None,
            TabBarMsg::TabsGridPressed => Some(TabBarEvent::TabScreenRequested),
            TabBarMsg::StabilizeExpired(gen) => {
                // Discard if a newer close has already superseded this timer.
                if gen == self.stabilize_generation {
                    self.frozen_chip_px = None;
                }
                None
            }
        }
    }

    fn close_tab(&mut self, id: usize, from_strip: bool) -> Option<TabBarEvent> {
        // Determine successor before removal: prefer right neighbour, fall back
        // to left (when closing the last tab), fall back to 0 (no tabs left).
        let successor = if self.active_id == id {
            let idx = self.tabs.iter().position(|t| t.id == id).unwrap_or(0);
            self.tabs
                .get(idx + 1)
                .or_else(|| self.tabs.get(idx.saturating_sub(1)))
                .map(|t| t.id)
        } else {
            None
        };

        if from_strip {
            // Freeze BOTH widths at their pre-close values so no chip changes
            // size while the user is clicking. Bump the generation so any
            // in-flight timer from a previous close is discarded when it fires.
            let (active_px, other_px) = self.chip_widths();
            self.frozen_chip_px = Some((active_px, other_px));
            self.stabilize_generation = self.stabilize_generation.wrapping_add(1);
        }

        self.tabs.retain(|t| t.id != id);
        if self.active_id == id {
            self.active_id =
                successor.unwrap_or_else(|| self.tabs.first().map(|t| t.id).unwrap_or(0));
        }
        // Re-evaluate hover so the chip now under the cursor shows its X button.
        self.hovered_tab_id = self.tab_id_at_x(self.cursor_strip_x);

        if from_strip {
            Some(TabBarEvent::StabilizeRequested(self.stabilize_generation))
        } else {
            Some(TabBarEvent::TabClosed(id))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_bar_defaults_to_bottom_position() {
        let tb = TabBar::new(TabBarPosition::Bottom);
        assert_eq!(tb.position, TabBarPosition::Bottom);
    }

    #[test]
    fn stub_tabs_count_is_five() {
        let tb = TabBar::new(TabBarPosition::Bottom);
        assert_eq!(tb.tab_count(), 5);
    }

    #[test]
    fn stub_has_no_pinned_tabs() {
        let tb = TabBar::new(TabBarPosition::Bottom);
        assert!(!tb.tabs.iter().any(|t| t.is_pinned));
    }

    #[test]
    fn stub_has_one_strict_tab_with_unsaved_input() {
        let tb = TabBar::new(TabBarPosition::Bottom);
        let n = tb
            .tabs
            .iter()
            .filter(|t| t.mode == Mode::Strict && t.has_unsaved_input)
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn close_standard_tab_emits_event_immediately() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        let event = tb.update(TabBarMsg::TabCloseRequested(2));
        assert!(matches!(event, Some(TabBarEvent::TabClosed(2))));
        assert_eq!(tb.tab_count(), 4);
    }

    #[test]
    fn close_strict_tab_no_unsaved_emits_immediately() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.tabs
            .iter_mut()
            .find(|t| t.id == 4)
            .unwrap()
            .has_unsaved_input = false;
        let event = tb.update(TabBarMsg::TabCloseRequested(4));
        assert!(matches!(event, Some(TabBarEvent::TabClosed(4))));
    }

    #[test]
    fn close_strict_tab_with_unsaved_opens_modal() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        let event = tb.update(TabBarMsg::TabCloseRequested(4));
        assert!(event.is_none());
        assert_eq!(tb.modal, StrictCloseModal::Confirming(4));
    }

    #[test]
    fn strict_close_confirmed_emits_tab_closed() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.update(TabBarMsg::TabCloseRequested(4));
        let event = tb.update(TabBarMsg::StrictCloseConfirmed);
        assert!(matches!(event, Some(TabBarEvent::TabClosed(4))));
        assert_eq!(tb.modal, StrictCloseModal::Hidden);
    }

    #[test]
    fn strict_close_cancelled_leaves_tab_open() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.update(TabBarMsg::TabCloseRequested(4));
        let event = tb.update(TabBarMsg::StrictCloseCancelled);
        assert!(event.is_none());
        assert_eq!(tb.modal, StrictCloseModal::Hidden);
        assert_eq!(tb.tab_count(), 5);
    }

    #[test]
    fn close_active_tab_activates_right_neighbour() {
        // Stub tabs: ids 0,1,2,3,4. Active = 2 (index 2). Right neighbour = id 3.
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.active_id = 2;
        tb.update(TabBarMsg::TabCloseRequested(2));
        assert_eq!(tb.active_id, 3, "should land on right neighbour (id 3)");
    }

    #[test]
    fn close_last_tab_activates_left_neighbour() {
        // Active = 3 (last Standard tab, index 3). No right → fall to left (id 2).
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        // Remove strict tab so id 3 is the last.
        tb.tabs.retain(|t| t.id != 4);
        tb.active_id = 3;
        tb.update(TabBarMsg::TabCloseRequested(3));
        assert_eq!(tb.active_id, 2, "should fall back to left neighbour (id 2)");
    }

    #[test]
    fn close_non_active_tab_leaves_active_unchanged() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.active_id = 2;
        tb.update(TabBarMsg::TabCloseRequested(3));
        assert_eq!(tb.active_id, 2, "active tab should not change");
    }

    #[test]
    fn modal_only_reachable_from_strict_tab() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.update(TabBarMsg::TabCloseRequested(2));
        assert_eq!(tb.modal, StrictCloseModal::Hidden);
    }

    #[test]
    fn drag_reorder_does_not_change_mode() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.tabs.swap(2, 4);
        assert_eq!(
            tb.tabs.iter().find(|t| t.id == 4).unwrap().mode,
            Mode::Strict
        );
        assert_eq!(
            tb.tabs.iter().find(|t| t.id == 2).unwrap().mode,
            Mode::Standard
        );
    }

    #[test]
    fn identity_capsule_label_is_strict_in_strict_mode() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.sync_mode(Mode::Strict, "work");
        assert_eq!(tb.mode, Mode::Strict);
        assert_eq!(tb.profile_name, "work");
    }

    #[test]
    fn show_title_true_at_80px_per_tab() {
        // + button removed; overhead = sidebar(52) + row_pad(16) + spacing(4) = 72.
        // Need 5 × 80 = 400 chip px → window = 472.
        let window_width = 472.0_f32;
        let row_pad = design::space::S4 * 2.0;
        let spacing = 4.0; // 1px × (5-1) dividers
        let available = window_width - design::layout::SIDEBAR_COLLAPSED_PX - row_pad - spacing;
        let per_tab = available / 5.0;
        assert!(per_tab >= 80.0, "got per_tab={per_tab}");
    }

    #[test]
    fn show_title_false_below_80px_per_tab() {
        let window_width = 450.0_f32;
        let row_pad = design::space::S4 * 2.0;
        let spacing = 4.0;
        let available = window_width - design::layout::SIDEBAR_COLLAPSED_PX - row_pad - spacing;
        let per_tab = available / 5.0;
        assert!(per_tab < 80.0, "got per_tab={per_tab}");
    }

    #[test]
    fn pinned_tab_suppresses_close_on_hover() {
        let tb = TabBar::new(TabBarPosition::Bottom);
        assert!(!tb.tabs.iter().any(|t| t.is_pinned));
    }

    #[test]
    fn strip_hidden_with_one_tab() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        let ids: Vec<usize> = tb.tabs.iter().skip(1).map(|t| t.id).collect();
        for id in ids {
            tb.tabs.retain(|t| t.id != id);
        }
        assert_eq!(tb.tab_count(), 1);
    }

    #[test]
    fn all_tabs_get_equal_fill_width() {
        let tb = TabBar::new(TabBarPosition::Bottom);
        let row_pad = design::space::S4 * 2.0;
        let spacing = tb.tab_count() as f32 - 1.0;
        let available = 1280.0_f32 - design::layout::SIDEBAR_COLLAPSED_PX - row_pad - spacing;
        let per_tab = available / tb.tab_count() as f32;
        assert!(per_tab > 80.0, "got {per_tab}");
    }

    #[test]
    fn crowded_tabs_never_exceed_available_width() {
        // 40 tabs on a 1280 px window — far more than fit at MIN_PX.
        // active_px + (n-1)*other_px + spacing must not exceed the row's chip area.
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        tb.window_width = 1280.0;
        for i in 5..40 {
            tb.tabs.push(crate::tab_bar::TabEntry {
                id: i,
                title: format!("Tab {i}"),
                favicon_label: "T".into(),
                mode: crate::shell::Mode::Standard,
                is_pinned: false,
                is_muted: false,
                has_unsaved_input: false,
                accent_color: None,
                url: String::new(),
            });
        }
        let (active_px, other_px) = tb.chip_widths();
        let n = tb.tabs.len() as f32;
        let spacing = n - 1.0;
        let total_chips = active_px + other_px * (n - 1.0) + spacing;
        let row_pad = design::space::S4 * 2.0;
        let max_chip_area = tb.window_width - design::layout::SIDEBAR_COLLAPSED_PX - row_pad;
        assert!(
            total_chips <= max_chip_area + 0.5,
            "chips {total_chips:.1} exceed available {max_chip_area:.1}"
        );
    }

    #[test]
    fn tabs_grid_pressed_emits_tab_screen_requested() {
        let mut tb = TabBar::new(TabBarPosition::Bottom);
        let event = tb.update(TabBarMsg::TabsGridPressed);
        assert!(matches!(event, Some(TabBarEvent::TabScreenRequested)));
    }
}
