//! Tab Screen — Module 44.6 (state machine + stub view).
//!
//! Shell-level full-screen tab manager triggered by the tabs-pill grid button.
//! Owns its own state, messages, and events; wired into AppState in shell.rs.
//!
//! View (`view()`) is a stub returning None — implemented in Module 44.6.
//! See the TODO block below for the full design.
//!
//! ── Design intent (Module 44.6) ──────────────────────────────────────────────
//!
//! Full-screen tab manager replacing the content area on tabs-pill click.
//!
//! Layout:
//!   ┌──────────────────────────────────────────────────────────┐
//!   │  [🔍 Search tabs...]        [All] [Social] [News] [...]  │
//!   ├──────────────────────────────────────────────────────────┤
//!   │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
//!   │  │ favicon  │  │ favicon  │  │ favicon  │              │
//!   │  │ title    │  │ title    │  │ title    │              │
//!   │  │ [preview]│  │ [preview]│  │ [preview]│              │
//!   │  │      [x] │  │      [x] │  │      [x] │              │
//!   │  └──────────┘  └──────────┘  └──────────┘              │
//!   │  ... scrollable, pinch/ctrl+scroll to zoom grid ...     │
//!   └──────────────────────────────────────────────────────────┘
//!
//! Cards: favicon circle, title (truncated), page screenshot preview, close (×).
//! Active tab gets blue border highlight.
//!
//! Screenshot previews:
//!   Phase 8  — colored gradient placeholder from TabEntry::accent_color.
//!   Phase 11 — Gecko rasterizes a 440×280 px thumbnail on page load/update.
//!              Wire via: TabEntry::screenshot: Option<iced::widget::image::Handle>
//!
//! Grid zoom:
//!   Ctrl+scroll or two-finger pinch scales cards (zoom_level range 0.4–1.6).
//!   Base card size 220×160 px scaled by zoom_level.
//!
//! Tab search:
//!   Text input at top filtering by title + URL substring (case-insensitive).
//!   Clears on close; does not persist between openings.
//!
//! Category chips — generated dynamically from tabs present (only show chip
//! if ≥1 tab belongs to that category). Ordered: All, then categories A-Z.
//!
//!   Phase 8  — domain keyword heuristics only:
//!              "bank"/"finance" in domain → Finance, "shop" → Shopping, etc.
//!
//!   Phase 11 — content-based classifier:
//!              Read og:description, JSON-LD @type, URL path segments.
//!              Multilingual keyword sets covering top-20 languages.
//!              CJK: character n-gram tokenization (no word spaces).
//!              No external calls — all local, privacy-safe.
//!              Expected accuracy ~85-90% on mainstream sites; "Other" fallback.
//!              Full categorization design is a future dedicated phase.
//!
//! TODO Module 44.6: implement view() replacing the None stub below.

use iced::Element;

use crate::tab_bar::TabEntry;

// ---------------------------------------------------------------------------
// Chip + nav enums
// ---------------------------------------------------------------------------

/// Which grouping chip is active in the tab screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CardViewChip {
    #[default]
    All,
    ByMode,
}

/// Arrow-key / Enter / Delete navigation for the card grid.
#[derive(Debug, Clone, Copy)]
pub enum CardNavKey {
    Left,
    Right,
    Up,
    Down,
    Enter,
    Close,
}

// ---------------------------------------------------------------------------
// Messages and events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum CardViewMsg {
    Close,
    ChipSelected(CardViewChip),
    CardActivated(usize),
    CardClosePressed(usize),
    KeyNav(CardNavKey),
}

/// Events that cross the module boundary to the shell.
#[derive(Debug, Clone)]
pub enum CardViewEvent {
    /// User activated a tab from the card grid — shell activates it in TabBar.
    TabActivated(usize),
    /// User pressed close on a card — shell routes to TabBar for modal logic.
    TabCloseRequested(usize),
}

// ---------------------------------------------------------------------------
// CardView
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CardView {
    /// True while the full-screen tab manager is visible.
    pub open: bool,
    /// Active category chip.
    pub chip: CardViewChip,
    /// Keyboard-focused card index into ordered_ids().
    pub(crate) focused_idx: Option<usize>,
    /// Zoom level for the card grid (0.4–1.6, default 1.0).
    pub zoom_level: f32,
}

impl Default for CardView {
    fn default() -> Self {
        Self {
            open: false,
            chip: CardViewChip::All,
            focused_idx: None,
            zoom_level: 1.0,
        }
    }
}

impl CardView {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the tab screen and focus the first card.
    pub fn open(&mut self, tab_count: usize) {
        self.open = true;
        self.focused_idx = if tab_count == 0 { None } else { Some(0) };
    }

    /// Close the tab screen and clear transient state.
    pub fn close(&mut self) {
        self.open = false;
        self.focused_idx = None;
    }

    /// Returns ordered tab ids for the active chip.
    pub fn ordered_ids(&self, tabs: &[TabEntry]) -> Vec<usize> {
        use crate::shell::Mode;
        match self.chip {
            CardViewChip::All => tabs.iter().map(|t| t.id).collect(),
            CardViewChip::ByMode => {
                let mut ids: Vec<usize> = tabs
                    .iter()
                    .filter(|t| t.mode == Mode::Standard)
                    .map(|t| t.id)
                    .collect();
                ids.extend(tabs.iter().filter(|t| t.mode == Mode::Strict).map(|t| t.id));
                ids
            }
        }
    }

    pub fn update(&mut self, msg: CardViewMsg, tabs: &[TabEntry]) -> Option<CardViewEvent> {
        match msg {
            CardViewMsg::Close => {
                self.close();
                None
            }
            CardViewMsg::ChipSelected(chip) => {
                self.chip = chip;
                self.focused_idx = if tabs.is_empty() { None } else { Some(0) };
                None
            }
            CardViewMsg::CardActivated(id) => {
                self.close();
                Some(CardViewEvent::TabActivated(id))
            }
            CardViewMsg::CardClosePressed(id) => {
                // Shell routes this to TabBar which handles Strict modal (EC3).
                // Tab screen stays open during confirmation.
                Some(CardViewEvent::TabCloseRequested(id))
            }
            CardViewMsg::KeyNav(key) => {
                let ids = self.ordered_ids(tabs);
                let n = ids.len();
                if n == 0 {
                    return None;
                }
                const COLS: usize = 3;
                match key {
                    CardNavKey::Left => {
                        let idx = self.focused_idx.unwrap_or(0);
                        self.focused_idx = Some(idx.saturating_sub(1));
                    }
                    CardNavKey::Right => {
                        let idx = self.focused_idx.unwrap_or(0);
                        self.focused_idx = Some((idx + 1).min(n - 1));
                    }
                    CardNavKey::Up => {
                        let idx = self.focused_idx.unwrap_or(0);
                        self.focused_idx = Some(idx.saturating_sub(COLS));
                    }
                    CardNavKey::Down => {
                        let idx = self.focused_idx.unwrap_or(0);
                        self.focused_idx = Some((idx + COLS).min(n - 1));
                    }
                    CardNavKey::Enter => {
                        if let Some(idx) = self.focused_idx {
                            if let Some(&id) = ids.get(idx) {
                                return self.update(CardViewMsg::CardActivated(id), tabs);
                            }
                        }
                    }
                    CardNavKey::Close => {
                        if let Some(idx) = self.focused_idx {
                            if let Some(&id) = ids.get(idx) {
                                return self.update(CardViewMsg::CardClosePressed(id), tabs);
                            }
                        }
                    }
                }
                None
            }
        }
    }

    /// Full-screen tab manager view.
    /// Returns None until Module 44.6 is implemented.
    pub fn view(
        &self,
        _tabs: &[TabEntry],
        _palette: &'static crate::design::Palette,
    ) -> Option<Element<'_, CardViewMsg>> {
        // TODO Module 44.6: implement full Tab Screen described in the module doc above.
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::Mode;
    use crate::tab_bar::TabEntry;

    fn make_tabs() -> Vec<TabEntry> {
        vec![
            TabEntry {
                id: 0,
                title: "github.com".into(),
                favicon_label: "G".into(),
                mode: Mode::Standard,
                is_pinned: false,
                is_muted: false,
                has_unsaved_input: false,
                accent_color: None,
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
                accent_color: None,
                url: "https://figma.com".into(),
            },
            TabEntry {
                id: 2,
                title: "strict · banking".into(),
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

    #[test]
    fn open_sets_flag_and_focuses_first() {
        let mut ts = CardView::new();
        ts.open(3);
        assert!(ts.open);
        assert_eq!(ts.focused_idx, Some(0));
    }

    #[test]
    fn open_empty_tabs_sets_no_focus() {
        let mut ts = CardView::new();
        ts.open(0);
        assert!(ts.open);
        assert_eq!(ts.focused_idx, None);
    }

    #[test]
    fn close_msg_closes_screen() {
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.open(tabs.len());
        ts.update(CardViewMsg::Close, &tabs);
        assert!(!ts.open);
    }

    #[test]
    fn card_activated_closes_screen_and_emits_event() {
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.open(tabs.len());
        let event = ts.update(CardViewMsg::CardActivated(1), &tabs);
        assert!(!ts.open);
        assert!(matches!(event, Some(CardViewEvent::TabActivated(1))));
    }

    #[test]
    fn card_close_pressed_emits_event_and_keeps_screen_open() {
        // EC3: screen stays open while Strict modal confirmation is pending.
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.open(tabs.len());
        let event = ts.update(CardViewMsg::CardClosePressed(2), &tabs);
        assert!(ts.open, "screen must stay open during close request");
        assert!(matches!(event, Some(CardViewEvent::TabCloseRequested(2))));
    }

    #[test]
    fn chip_by_mode_orders_standard_before_strict() {
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.chip = CardViewChip::ByMode;
        let ids = ts.ordered_ids(&tabs);
        let strict_pos = ids.iter().position(|&id| {
            tabs.iter()
                .find(|t| t.id == id)
                .map(|t| t.mode == Mode::Strict)
                .unwrap_or(false)
        });
        let last_std_pos = ids.iter().rposition(|&id| {
            tabs.iter()
                .find(|t| t.id == id)
                .map(|t| t.mode == Mode::Standard)
                .unwrap_or(false)
        });
        if let (Some(sp), Some(ls)) = (strict_pos, last_std_pos) {
            assert!(sp > ls, "strict must come after all standard tabs");
        }
    }

    #[test]
    fn ec1_all_standard_by_mode_no_strict_ids() {
        let tabs: Vec<TabEntry> = make_tabs()
            .into_iter()
            .map(|mut t| {
                t.mode = Mode::Standard;
                t
            })
            .collect();
        let mut ts = CardView::new();
        ts.chip = CardViewChip::ByMode;
        let ids = ts.ordered_ids(&tabs);
        assert!(ids.iter().all(|&id| tabs
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.mode == Mode::Standard)
            .unwrap_or(false)));
    }

    #[test]
    fn ec2_all_strict_by_mode_no_standard_ids() {
        let tabs: Vec<TabEntry> = make_tabs()
            .into_iter()
            .map(|mut t| {
                t.mode = Mode::Strict;
                t
            })
            .collect();
        let mut ts = CardView::new();
        ts.chip = CardViewChip::ByMode;
        let ids = ts.ordered_ids(&tabs);
        assert!(ids.iter().all(|&id| tabs
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.mode == Mode::Strict)
            .unwrap_or(false)));
    }

    #[test]
    fn keyboard_nav_right_advances_focus() {
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.open(tabs.len());
        ts.update(CardViewMsg::KeyNav(CardNavKey::Right), &tabs);
        assert_eq!(ts.focused_idx, Some(1));
    }

    #[test]
    fn keyboard_nav_left_clamps_at_zero() {
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.open(tabs.len());
        ts.update(CardViewMsg::KeyNav(CardNavKey::Left), &tabs);
        assert_eq!(ts.focused_idx, Some(0));
    }

    #[test]
    fn keyboard_nav_enter_activates_and_closes() {
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.open(tabs.len());
        ts.update(CardViewMsg::KeyNav(CardNavKey::Right), &tabs);
        let event = ts.update(CardViewMsg::KeyNav(CardNavKey::Enter), &tabs);
        assert!(!ts.open);
        assert!(matches!(event, Some(CardViewEvent::TabActivated(1))));
    }

    #[test]
    fn chip_switch_resets_focus_to_zero() {
        let tabs = make_tabs();
        let mut ts = CardView::new();
        ts.open(tabs.len());
        ts.update(CardViewMsg::KeyNav(CardNavKey::Right), &tabs);
        ts.update(CardViewMsg::ChipSelected(CardViewChip::ByMode), &tabs);
        assert_eq!(ts.focused_idx, Some(0));
    }
}
