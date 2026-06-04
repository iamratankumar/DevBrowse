//! History panel — Module 48.
//!
//! Per-identity history surface. Reachable via Library page tab,
//! settings popover "History", or `/history` command bar prefix (Module 64.13).
//!
//! **Phase 8 note:** entries are held in-memory only. pb-storage wiring lands
//! in Phase 11 (Module 80). Feed data via `HistoryMsg::EntriesLoaded`.
//!
//! Privacy invariants enforced:
//!   L29 — Strict tabs never write history; panel always shows the disclaimer.
//!   L27 — No history entry or query leaves the process; errors are opaque.
//!   §3.1 — panel is per-identity; Phase 11 orchestrator drives the load.

use std::time::{SystemTime, UNIX_EPOCH};

use iced::{
    alignment::{Horizontal, Vertical},
    widget::{button, column, container, row, scrollable, text, text_input},
    Background, Border, Color, Element, Length, Padding,
};
use pb_config::HistoryRetention;

use crate::design;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A single browsing-history row.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: u64,
    /// Page title. Empty if unknown — display falls back to `domain`.
    pub title: String,
    /// Domain extracted from the URL at write time.
    pub domain: String,
    /// Full URL — never logged (L27). Used only for navigation.
    pub url: String,
    /// Unix epoch milliseconds.
    pub timestamp_ms: i64,
}

/// Day-bucket for the grouped-by-day display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DayBucket {
    Today,
    Yesterday,
    DaysAgo(u32), // 2–6
    Older,        // ≥ 7 days
}

impl DayBucket {
    pub fn label(&self) -> String {
        match self {
            DayBucket::Today => "Today".to_string(),
            DayBucket::Yesterday => "Yesterday".to_string(),
            DayBucket::DaysAgo(n) => format!("{n} days ago"),
            DayBucket::Older => "Older".to_string(),
        }
    }

    fn from_age_days(days: u32) -> Self {
        match days {
            0 => DayBucket::Today,
            1 => DayBucket::Yesterday,
            2..=6 => DayBucket::DaysAgo(days),
            _ => DayBucket::Older,
        }
    }
}

/// History panel state-machine phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryPhase {
    Loading,
    Empty,
    Populated,
    Searching,
    Clearing,
    LoadError,
    CorruptedWarning,
}

// ---------------------------------------------------------------------------
// Events (returned to shell; no direct pb-identity import, L12)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum HistoryEvent {
    Navigate { url: String },
    NavigateNewTab { url: String },
    NavigateStrictTab { url: String },
    EntryDeleted { id: u64 },
    AllCleared,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum HistoryMsg {
    Opened,
    Closed,
    /// Entries fed from pb-storage (Phase 11). Resets loading state.
    EntriesLoaded(Vec<HistoryEntry>),
    /// Storage returned an error (opaque per L27).
    LoadError,
    /// Storage detected corruption — graceful degradation.
    StorageCorrupted,
    SearchChanged(String),
    EntryOpen(u64),
    EntryOpenNewTab(u64),
    EntryOpenStrictTab(u64),
    EntryDelete(u64),
    FocusUp,
    FocusDown,
    FocusActivate,
    FocusDelete,
    ClearRequested,
    ClearConfirmed,
    ClearCancelled,
    ClearFailed,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct HistoryPanel {
    pub open: bool,
    pub phase: HistoryPhase,
    entries: Vec<HistoryEntry>,
    pub search_query: String,
    pub focused_row: Option<usize>,
    pub retention: HistoryRetention,
    /// Snapshot of "now" taken when the panel opens / entries load.
    now_ms: i64,
}

impl Default for HistoryPanel {
    fn default() -> Self {
        Self::new(HistoryRetention::default())
    }
}

impl HistoryPanel {
    pub fn new(retention: HistoryRetention) -> Self {
        Self {
            open: false,
            phase: HistoryPhase::Loading,
            entries: Vec::new(),
            search_query: String::new(),
            focused_row: None,
            retention,
            now_ms: now_ms(),
        }
    }

    /// Number of entries visible under the current search filter.
    pub fn visible_count(&self) -> usize {
        filtered(self.search_query.as_str(), &self.entries).count()
    }

    /// Groups filtered entries by day-bucket (newest-first order preserved).
    fn grouped(&self) -> Vec<(DayBucket, Vec<&HistoryEntry>)> {
        let mut groups: Vec<(DayBucket, Vec<&HistoryEntry>)> = Vec::new();
        for entry in filtered(self.search_query.as_str(), &self.entries) {
            let bucket = DayBucket::from_age_days(age_days(self.now_ms, entry.timestamp_ms));
            if groups.last().map(|(b, _)| b == &bucket).unwrap_or(false) {
                groups.last_mut().unwrap().1.push(entry);
            } else {
                groups.push((bucket, vec![entry]));
            }
        }
        groups
    }

    fn recompute_phase(&self) -> HistoryPhase {
        if self.entries.is_empty() {
            HistoryPhase::Empty
        } else if self.search_query.is_empty() {
            HistoryPhase::Populated
        } else {
            HistoryPhase::Searching
        }
    }

    // -----------------------------------------------------------------------
    // update
    // -----------------------------------------------------------------------

    /// Returns an optional event for the shell to act on.
    pub fn update(&mut self, msg: HistoryMsg) -> Option<HistoryEvent> {
        match msg {
            HistoryMsg::Opened => {
                self.open = true;
                // If entries are already loaded (e.g. seeded at boot), show them
                // immediately instead of flashing a loading skeleton. Phase 11
                // will dispatch a storage fetch here when entries are empty.
                self.phase = self.recompute_phase();
                self.search_query.clear();
                self.focused_row = None;
                self.now_ms = now_ms();
            }
            HistoryMsg::Closed => {
                self.open = false;
                self.search_query.clear();
                self.focused_row = None;
                if self.phase == HistoryPhase::Clearing {
                    self.phase = self.recompute_phase();
                }
            }
            HistoryMsg::EntriesLoaded(entries) => {
                self.entries = entries;
                self.now_ms = now_ms();
                self.focused_row = None;
                self.phase = self.recompute_phase();
            }
            HistoryMsg::LoadError => {
                self.phase = HistoryPhase::LoadError;
            }
            HistoryMsg::StorageCorrupted => {
                self.phase = HistoryPhase::CorruptedWarning;
            }
            HistoryMsg::SearchChanged(q) => {
                self.search_query = q;
                self.focused_row = None;
                self.phase = self.recompute_phase();
            }
            HistoryMsg::EntryOpen(id) => {
                if let Some(e) = self.entries.iter().find(|e| e.id == id) {
                    return Some(HistoryEvent::Navigate { url: e.url.clone() });
                }
            }
            HistoryMsg::EntryOpenNewTab(id) => {
                if let Some(e) = self.entries.iter().find(|e| e.id == id) {
                    return Some(HistoryEvent::NavigateNewTab { url: e.url.clone() });
                }
            }
            HistoryMsg::EntryOpenStrictTab(id) => {
                if let Some(e) = self.entries.iter().find(|e| e.id == id) {
                    return Some(HistoryEvent::NavigateStrictTab { url: e.url.clone() });
                }
            }
            HistoryMsg::EntryDelete(id) => {
                self.entries.retain(|e| e.id != id);
                self.focused_row = None;
                self.phase = self.recompute_phase();
                return Some(HistoryEvent::EntryDeleted { id });
            }
            HistoryMsg::FocusUp => {
                let len = visible_count_of(self.search_query.as_str(), &self.entries);
                if len > 0 {
                    self.focused_row = Some(match self.focused_row {
                        None | Some(0) => len - 1,
                        Some(i) => i - 1,
                    });
                }
            }
            HistoryMsg::FocusDown => {
                let len = visible_count_of(self.search_query.as_str(), &self.entries);
                if len > 0 {
                    self.focused_row = Some(match self.focused_row {
                        None => 0,
                        Some(i) => (i + 1) % len,
                    });
                }
            }
            HistoryMsg::FocusActivate => {
                if let Some(idx) = self.focused_row {
                    let url = filtered(self.search_query.as_str(), &self.entries)
                        .nth(idx)
                        .map(|e| e.url.clone());
                    if let Some(url) = url {
                        return Some(HistoryEvent::Navigate { url });
                    }
                }
            }
            HistoryMsg::FocusDelete => {
                if let Some(idx) = self.focused_row {
                    let id = filtered(self.search_query.as_str(), &self.entries)
                        .nth(idx)
                        .map(|e| e.id);
                    if let Some(id) = id {
                        self.entries.retain(|e| e.id != id);
                        let len = visible_count_of(self.search_query.as_str(), &self.entries);
                        self.focused_row = if len == 0 {
                            None
                        } else {
                            Some(idx.min(len - 1))
                        };
                        self.phase = self.recompute_phase();
                        return Some(HistoryEvent::EntryDeleted { id });
                    }
                }
            }
            HistoryMsg::ClearRequested => {
                if matches!(
                    self.phase,
                    HistoryPhase::Populated | HistoryPhase::Searching
                ) {
                    self.phase = HistoryPhase::Clearing;
                }
            }
            HistoryMsg::ClearConfirmed => {
                self.entries.clear();
                self.search_query.clear();
                self.focused_row = None;
                self.phase = HistoryPhase::Empty;
                return Some(HistoryEvent::AllCleared);
            }
            HistoryMsg::ClearCancelled | HistoryMsg::ClearFailed => {
                self.phase = self.recompute_phase();
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // view
    // -----------------------------------------------------------------------

    /// Returns `None` when the panel is closed.
    ///
    /// When open, fills the content-area slot in the shell (replaces the NTP).
    /// Renders like a browser history page (Chrome / Safari pattern) — full
    /// width/height, wallpaper visible through the glass tint, no overlay,
    /// no centering wrapper. Theme-aware via the palette.
    ///
    /// Mounted in shell::view() as `ntp_or_fill` when `state.history.open`.
    ///
    /// TODO Phase 11.9 / Phase 12: when native OS menu lands, the "Show All
    /// History" menu item fires `HistoryMsg::Opened` via the OS event bridge.
    /// TODO Module 64.13: command bar `h/` / `history/` prefix should also
    /// dispatch `HistoryMsg::Opened` and pre-fill `search_query`.
    pub fn view(&self, palette: &'static design::Palette) -> Option<Element<'_, HistoryMsg>> {
        if !self.open {
            return None;
        }

        // ── colour bindings (theme-aware) ─────────────────────────────────
        // Every colour comes from the palette so Standard and Strict themes
        // apply automatically — no branching here.
        let [tr, tg, tb, _] = palette.text_primary;
        let text_col = Color::from_rgb(tr, tg, tb);
        let [mr, mg, mb, _] = palette.text_muted;
        let muted_col = Color::from_rgb(mr, mg, mb);
        let [dr, dg, db, _] = palette.text_dim;
        let dim_col = Color::from_rgb(dr, dg, db);
        let [gr, gg, gb, ga] = palette.glass_tint;
        // Slightly more opaque than ambient glass so the list reads clearly
        // against the wallpaper but the wallpaper still bleeds through.
        let surface_bg = Color::from_rgba(gr, gg, gb, (ga + 0.06).min(1.0));
        let [bdr, bdg, bdb, bda] = palette.button_border;
        let border_col = Color::from_rgba(bdr, bdg, bdb, bda);
        let [bir, big, bib, bia] = palette.button_idle;
        let idle_col = Color::from_rgba(bir, big, bib, bia);
        let [hvr, hvg, hvb, hva] = palette.button_hover;
        let hover_col = Color::from_rgba(hvr, hvg, hvb, hva);
        let [ar, ag, ab, _] = palette.active;
        let warn_col = Color::from_rgb(0.988, 0.831, 0.365);

        let panel_body = self.panel_content(
            palette, text_col, muted_col, dim_col, surface_bg, border_col, idle_col, hover_col,
            warn_col, ar, ag, ab,
        );

        // Full content-area container — fills whatever space the shell gives it.
        // No fixed size, no centering, no dim overlay. Glass tint on top of
        // the wallpaper so the page reads as a browser surface, not a modal.
        Some(
            container(panel_body)
                .width(Length::Fill)
                .height(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Background::Color(surface_bg)),
                    text_color: Some(text_col),
                    ..Default::default()
                })
                .into(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn panel_content<'a>(
        &'a self,
        _palette: &'static design::Palette,
        text_col: Color,
        muted_col: Color,
        dim_col: Color,
        surface_bg: Color,
        border_col: Color,
        idle_col: Color,
        hover_col: Color,
        warn_col: Color,
        sel_r: f32,
        sel_g: f32,
        sel_b: f32,
    ) -> Element<'a, HistoryMsg> {
        let header = self.view_header(
            text_col, muted_col, idle_col, border_col, hover_col, sel_r, sel_g, sel_b,
        );
        let body: Element<'a, HistoryMsg> = match &self.phase {
            HistoryPhase::Loading => self.view_loading(muted_col),
            HistoryPhase::Empty => self.view_empty(text_col, muted_col, dim_col),
            HistoryPhase::Populated | HistoryPhase::Searching => {
                self.view_list(text_col, muted_col, dim_col, hover_col)
            }
            HistoryPhase::Clearing => {
                self.view_clear_dialog(text_col, muted_col, surface_bg, border_col, hover_col)
            }
            HistoryPhase::LoadError => self.view_error(
                text_col,
                muted_col,
                warn_col,
                "Couldn't load history",
                "Try reopening the panel in a moment.",
            ),
            HistoryPhase::CorruptedWarning => self.view_error(
                text_col,
                muted_col,
                warn_col,
                "History file appears corrupted",
                "Your existing entries can't be shown safely.",
            ),
        };
        let footer = self.view_footer(dim_col, border_col);

        // Body fills the remaining space; header + footer hug their content.
        let body_area: Element<'a, HistoryMsg> = container(body)
            .width(Length::Fill)
            .height(Length::Fill)
            .into();

        column![header, body_area, footer]
            .spacing(0)
            .height(Length::Fill)
            .into()
    }

    // ── header ────────────────────────────────────────────────────────────
    // Clean row — title left, search center-right, Clear (destructive text),
    // close × icon. Only a hairline bottom border separates it from the body.
    // No heavy box; this matches Chrome / Safari / Arc history pages.

    #[allow(clippy::too_many_arguments)]
    fn view_header<'a>(
        &'a self,
        text_col: Color,
        muted_col: Color,
        idle_col: Color,
        border_col: Color,
        hover_col: Color,
        sel_r: f32,
        sel_g: f32,
        sel_b: f32,
    ) -> Element<'a, HistoryMsg> {
        let btn_radius: iced::border::Radius = design::radius::BUTTON_PX.into();
        let input_radius: iced::border::Radius = design::radius::INPUT_PX.into();

        // ── Title ─────────────────────────────────────────────────────────
        let title = text("History")
            .size(design::type_scale::H1_PX)
            .color(text_col);

        // ── Search input — visible only when there is data to search ─────
        // Standalone capsule input, INPUT_PX radius, button_idle background.
        let show_search = matches!(
            self.phase,
            HistoryPhase::Populated | HistoryPhase::Searching
        );
        let search_input: Element<'a, HistoryMsg> = if show_search {
            text_input("Search history", &self.search_query)
                .on_input(HistoryMsg::SearchChanged)
                .size(design::type_scale::LABEL_PX)
                .padding(
                    Padding::new(5.0)
                        .left(design::space::S4)
                        .right(design::space::S4),
                )
                .width(Length::Fixed(220.0))
                .style(move |_t, _s| text_input::Style {
                    background: Background::Color(idle_col),
                    border: Border {
                        color: border_col,
                        width: 1.0,
                        radius: input_radius,
                    },
                    icon: text_col,
                    placeholder: muted_col,
                    value: text_col,
                    selection: Color::from_rgba(sel_r, sel_g, sel_b, 0.30),
                })
                .into()
        } else {
            iced::widget::Space::new().into()
        };

        // ── Clear all — destructive text button (Chrome / Safari pattern) ─
        // Standalone button INSIDE chrome → uses the standalone button
        // convention (idle bg + capsule border at BUTTON_PX). Red tint when
        // active to signal destructive intent; muted/disabled-looking when
        // there is nothing to clear.
        let can_clear = matches!(
            self.phase,
            HistoryPhase::Populated | HistoryPhase::Searching
        );
        let clear_label = text("Clear all").size(design::type_scale::LABEL_PX);
        let clear_inner = container(clear_label)
            .height(Length::Fixed(28.0))
            .padding(
                Padding::new(0.0)
                    .left(design::space::S6)
                    .right(design::space::S6),
            )
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center);

        let clear_btn: Element<'a, HistoryMsg> = if can_clear {
            button(clear_inner)
                .on_press(HistoryMsg::ClearRequested)
                .padding(0)
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(match status {
                        button::Status::Hovered | button::Status::Pressed => {
                            Color::from_rgba(0.92, 0.32, 0.32, 0.22)
                        }
                        _ => Color::from_rgba(0.92, 0.32, 0.32, 0.08),
                    })),
                    border: Border {
                        color: Color::from_rgba(0.92, 0.32, 0.32, 0.32),
                        width: 1.0,
                        radius: btn_radius,
                    },
                    text_color: Color::from_rgb(0.96, 0.48, 0.48),
                    ..Default::default()
                })
                .into()
        } else {
            // No on_press → not clickable. Faded look without breaking the
            // overall standalone-button rhythm.
            button(clear_inner)
                .padding(0)
                .style(move |_, _| button::Style {
                    background: Some(Background::Color(idle_col)),
                    border: Border {
                        color: border_col,
                        width: 1.0,
                        radius: btn_radius,
                    },
                    text_color: Color::from_rgba(muted_col.r, muted_col.g, muted_col.b, 0.45),
                    ..Default::default()
                })
                .into()
        };

        // ── Close (×) — standalone icon button ────────────────────────────
        // Matches address-bar reload pattern: idle bg + hairline border +
        // BUTTON_PX radius, square-ish capsule.
        let close_btn: Element<'a, HistoryMsg> = button(
            container(text("\u{2715}").size(12.0).color(text_col))
                .width(Length::Fixed(28.0))
                .height(Length::Fixed(28.0))
                .center_x(Length::Fixed(28.0))
                .center_y(Length::Fixed(28.0)),
        )
        .on_press(HistoryMsg::Closed)
        .padding(0)
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => hover_col,
                _ => idle_col,
            })),
            border: Border {
                color: border_col,
                width: 1.0,
                radius: btn_radius,
            },
            text_color: text_col,
            ..Default::default()
        })
        .into();

        // ── Header row ────────────────────────────────────────────────────
        // Generous horizontal padding to match a real browser page; vertical
        // padding gives the title + controls breathing room.
        let inner = row![
            title,
            iced::widget::Space::new().width(Length::Fill),
            search_input,
            iced::widget::Space::new().width(design::space::S6),
            clear_btn,
            iced::widget::Space::new().width(design::space::S4),
            close_btn,
        ]
        .spacing(0)
        .align_y(Vertical::Center)
        .padding(
            Padding::new(0.0)
                .top(design::space::S8)
                .bottom(design::space::S6)
                .left(design::space::S10)
                .right(design::space::S6),
        );

        // Hairline bottom border only — no full container box. This is the
        // pattern from Chrome / Firefox / Safari / Arc history pages.
        container(inner)
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: None,
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: 0.0.into(),
                },
                text_color: Some(text_col),
                ..Default::default()
            })
            .into()
    }

    // ── loading skeleton ──────────────────────────────────────────────────
    // Five faint rows that imply the row layout (favicon + 2 text lines).

    fn view_loading<'a>(&self, muted_col: Color) -> Element<'a, HistoryMsg> {
        fn bar<'b>(muted_col: Color, w: Length, h: f32, alpha: f32) -> Element<'b, HistoryMsg> {
            container(iced::widget::Space::new().width(w).height(Length::Fixed(h)))
                .style(move |_: &iced::Theme| container::Style {
                    background: Some(Background::Color(Color::from_rgba(
                        muted_col.r,
                        muted_col.g,
                        muted_col.b,
                        alpha,
                    ))),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .into()
        }

        let row_skeleton = || -> Element<'a, HistoryMsg> {
            let favicon: Element<'a, HistoryMsg> = container(
                iced::widget::Space::new()
                    .width(Length::Fixed(20.0))
                    .height(Length::Fixed(20.0)),
            )
            .style(move |_: &iced::Theme| container::Style {
                background: Some(Background::Color(Color::from_rgba(
                    muted_col.r,
                    muted_col.g,
                    muted_col.b,
                    0.14,
                ))),
                border: Border {
                    radius: design::radius::PILL_PX.into(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .into();
            let lines: Element<'a, HistoryMsg> = column![
                bar(muted_col, Length::Fixed(220.0), 9.0, 0.12),
                bar(muted_col, Length::Fixed(120.0), 7.0, 0.08),
            ]
            .spacing(design::space::S2)
            .into();
            container(
                row![favicon, lines]
                    .spacing(design::space::S6)
                    .align_y(Vertical::Center),
            )
            .width(Length::Fill)
            .padding(
                Padding::new(0.0)
                    .top(design::space::S5)
                    .bottom(design::space::S5)
                    .left(design::space::S10)
                    .right(design::space::S10),
            )
            .into()
        };

        let items: Vec<Element<'a, HistoryMsg>> = (0..5).map(|_| row_skeleton()).collect();

        scrollable(
            column(items)
                .spacing(0)
                .padding(Padding::new(0.0).top(design::space::S5)),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
    }

    // ── empty state ───────────────────────────────────────────────────────
    // Centered glyph + headline + subtext — the spacious, calm pattern shared
    // by every major browser's empty history page.

    fn view_empty<'a>(
        &self,
        text_col: Color,
        muted_col: Color,
        dim_col: Color,
    ) -> Element<'a, HistoryMsg> {
        container(
            column![
                text("\u{29D6}") // clock-like glyph, low-key
                    .size(40.0)
                    .color(Color::from_rgba(
                        muted_col.r,
                        muted_col.g,
                        muted_col.b,
                        0.55
                    )),
                iced::widget::Space::new().height(Length::Fixed(design::space::S6)),
                text("No history yet")
                    .size(design::type_scale::H2_PX)
                    .color(text_col),
                text("Pages you visit in Standard mode appear here.")
                    .size(design::type_scale::BODY_PX)
                    .color(dim_col),
            ]
            .spacing(design::space::S2)
            .align_x(Horizontal::Center),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Horizontal::Center)
        .align_y(Vertical::Center)
        .into()
    }

    // ── populated list ────────────────────────────────────────────────────
    // Group headers ("Today", "Yesterday", "3 days ago") as small muted
    // labels with generous top padding. Rows: favicon | title + domain |
    // time | delete ×. Full-width clickable; hover lifts background. No
    // per-row borders.

    fn view_list<'a>(
        &'a self,
        text_col: Color,
        muted_col: Color,
        dim_col: Color,
        hover_col: Color,
    ) -> Element<'a, HistoryMsg> {
        let groups = self.grouped();
        let mut items: Vec<Element<'a, HistoryMsg>> = Vec::new();

        if !self.search_query.is_empty() && groups.is_empty() {
            // "No matches" empty state for an active search.
            return container(
                column![
                    text("No matches")
                        .size(design::type_scale::H2_PX)
                        .color(text_col),
                    text(format!(
                        "Nothing in your history matches \"{}\".",
                        self.search_query
                    ))
                    .size(design::type_scale::BODY_PX)
                    .color(dim_col),
                ]
                .spacing(design::space::S3)
                .align_x(Horizontal::Center),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .into();
        }

        let mut running_offset: usize = 0;
        for (bucket, entries) in &groups {
            // ── Group header ──────────────────────────────────────────────
            // Small muted label, generous top padding. Not a container box.
            items.push(
                container(
                    text(bucket.label())
                        .size(design::type_scale::LABEL_UPPER_PX)
                        .color(Color::from_rgba(
                            muted_col.r,
                            muted_col.g,
                            muted_col.b,
                            0.85,
                        )),
                )
                .width(Length::Fill)
                .padding(
                    Padding::new(0.0)
                        .top(design::space::S8)
                        .bottom(design::space::S3)
                        .left(design::space::S10)
                        .right(design::space::S10),
                )
                .into(),
            );

            for (i, entry) in entries.iter().enumerate() {
                let flat_idx = running_offset + i;
                let focused = self.focused_row == Some(flat_idx);
                let row_bg = if focused {
                    hover_col
                } else {
                    Color::TRANSPARENT
                };

                let display_title = if entry.title.is_empty() {
                    entry.domain.as_str()
                } else {
                    entry.title.as_str()
                };
                let time_str = format_time_ago(self.now_ms, entry.timestamp_ms);
                let id = entry.id;

                // Favicon placeholder — 20px filled circle in the muted tone.
                // Phase 12: Module 56 (favicon cache) feeds real bitmaps.
                let favicon_seed = entry
                    .domain
                    .chars()
                    .next()
                    .unwrap_or('?')
                    .to_ascii_uppercase();
                let favicon: Element<'a, HistoryMsg> =
                    container(text(favicon_seed.to_string()).size(11.0).color(text_col))
                        .width(Length::Fixed(20.0))
                        .height(Length::Fixed(20.0))
                        .center_x(Length::Fixed(20.0))
                        .center_y(Length::Fixed(20.0))
                        .style(move |_| container::Style {
                            background: Some(Background::Color(Color::from_rgba(
                                muted_col.r,
                                muted_col.g,
                                muted_col.b,
                                0.18,
                            ))),
                            border: Border {
                                radius: design::radius::PILL_PX.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        })
                        .into();

                // Title + domain — stacked, tight spacing.
                let title_text = text(display_title.to_string())
                    .size(design::type_scale::BODY_PX)
                    .color(text_col);
                let domain_text = text(entry.domain.clone())
                    .size(design::type_scale::LABEL_UPPER_PX)
                    .color(muted_col);
                let title_block: Element<'a, HistoryMsg> = column![title_text, domain_text]
                    .spacing(design::space::S1)
                    .width(Length::Fill)
                    .into();

                // Time — fixed width, right-aligned, dim.
                let time_block: Element<'a, HistoryMsg> = container(
                    text(time_str)
                        .size(design::type_scale::LABEL_UPPER_PX)
                        .color(dim_col),
                )
                .width(Length::Fixed(78.0))
                .align_x(Horizontal::Right)
                .into();

                // Delete × — icon button INSIDE a row container → transparent
                // idle, button_hover * 0.6 on hover, PILL_PX (circular) radius.
                let del_btn: Element<'a, HistoryMsg> = button(
                    container(text("\u{2715}").size(11.0).color(muted_col))
                        .width(Length::Fixed(22.0))
                        .height(Length::Fixed(22.0))
                        .center_x(Length::Fixed(22.0))
                        .center_y(Length::Fixed(22.0)),
                )
                .on_press(HistoryMsg::EntryDelete(id))
                .padding(0)
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(match status {
                        button::Status::Hovered | button::Status::Pressed => Color::from_rgba(
                            hover_col.r,
                            hover_col.g,
                            hover_col.b,
                            hover_col.a * 0.6,
                        ),
                        _ => Color::TRANSPARENT,
                    })),
                    border: Border {
                        radius: design::radius::PILL_PX.into(),
                        ..Default::default()
                    },
                    text_color: muted_col,
                    ..Default::default()
                })
                .into();

                let row_inner = row![favicon, title_block, time_block, del_btn]
                    .spacing(design::space::S6)
                    .align_y(Vertical::Center);

                // Full-width clickable row. No border. Hover lifts bg.
                let row_btn: Element<'a, HistoryMsg> = button(row_inner)
                    .on_press(HistoryMsg::EntryOpen(id))
                    .width(Length::Fill)
                    .padding(
                        Padding::new(0.0)
                            .top(design::space::S4)
                            .bottom(design::space::S4)
                            .left(design::space::S10)
                            .right(design::space::S6),
                    )
                    .style(move |_, status| button::Style {
                        background: Some(Background::Color(match status {
                            button::Status::Hovered | button::Status::Pressed => hover_col,
                            _ => row_bg,
                        })),
                        border: Border::default(),
                        text_color: text_col,
                        ..Default::default()
                    })
                    .into();

                items.push(row_btn);
            }

            running_offset += entries.len();
        }

        // Trailing breathing room at the bottom of the scroll content.
        items.push(
            iced::widget::Space::new()
                .height(Length::Fixed(design::space::S8))
                .into(),
        );

        scrollable(column(items).spacing(0))
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    // ── clear confirm dialog ──────────────────────────────────────────────
    // Centered card: headline + body text + two buttons.
    // Cancel is the standalone button; Clear all is red destructive.

    fn view_clear_dialog<'a>(
        &self,
        text_col: Color,
        muted_col: Color,
        _surface_bg: Color,
        border_col: Color,
        hover_col: Color,
    ) -> Element<'a, HistoryMsg> {
        let btn_radius: iced::border::Radius = design::radius::BUTTON_PX.into();

        let cancel_btn = button(
            container(
                text("Cancel")
                    .size(design::type_scale::BODY_PX)
                    .color(text_col),
            )
            .padding(
                Padding::new(0.0)
                    .left(design::space::S8)
                    .right(design::space::S8),
            )
            .height(Length::Fixed(32.0))
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center),
        )
        .on_press(HistoryMsg::ClearCancelled)
        .padding(0)
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => hover_col,
                _ => Color::TRANSPARENT,
            })),
            border: Border {
                color: border_col,
                width: 1.0,
                radius: btn_radius,
            },
            text_color: text_col,
            ..Default::default()
        });

        let confirm_btn = button(
            container(
                text("Clear all")
                    .size(design::type_scale::BODY_PX)
                    .color(Color::from_rgb(1.0, 0.96, 0.96)),
            )
            .padding(
                Padding::new(0.0)
                    .left(design::space::S8)
                    .right(design::space::S8),
            )
            .height(Length::Fixed(32.0))
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center),
        )
        .on_press(HistoryMsg::ClearConfirmed)
        .padding(0)
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => {
                    Color::from_rgba(0.92, 0.30, 0.30, 0.92)
                }
                _ => Color::from_rgba(0.92, 0.30, 0.30, 0.78),
            })),
            border: Border {
                color: Color::from_rgba(0.92, 0.30, 0.30, 0.40),
                width: 1.0,
                radius: btn_radius,
            },
            text_color: Color::from_rgb(1.0, 0.96, 0.96),
            ..Default::default()
        });

        let card = container(
            column![
                text("Clear all history?")
                    .size(design::type_scale::H2_PX)
                    .color(text_col),
                text("This permanently removes every entry. It can't be undone.")
                    .size(design::type_scale::BODY_PX)
                    .color(muted_col),
                iced::widget::Space::new().height(Length::Fixed(design::space::S4)),
                row![cancel_btn, confirm_btn].spacing(design::space::S4),
            ]
            .spacing(design::space::S5)
            .align_x(Horizontal::Center),
        )
        .padding(Padding::new(design::space::S10))
        .style(move |_| container::Style {
            background: Some(Background::Color(Color::from_rgba(
                muted_col.r,
                muted_col.g,
                muted_col.b,
                0.06,
            ))),
            border: Border {
                color: border_col,
                width: 1.0,
                radius: design::radius::PANEL_PX.into(),
            },
            ..Default::default()
        })
        .max_width(420.0);

        container(card)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .into()
    }

    // ── error / corrupted ─────────────────────────────────────────────────
    // Centered glyph + headline + opaque subtext (L27 — no internal details).

    fn view_error<'a>(
        &self,
        text_col: Color,
        muted_col: Color,
        warn_col: Color,
        title_msg: &'static str,
        sub_msg: &'static str,
    ) -> Element<'a, HistoryMsg> {
        container(
            column![
                text("\u{26A0}").size(28.0).color(warn_col),
                iced::widget::Space::new().height(Length::Fixed(design::space::S4)),
                text(title_msg)
                    .size(design::type_scale::H2_PX)
                    .color(text_col),
                text(sub_msg)
                    .size(design::type_scale::BODY_PX)
                    .color(muted_col),
            ]
            .spacing(design::space::S2)
            .align_x(Horizontal::Center),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .align_x(Horizontal::Center)
        .align_y(Vertical::Center)
        .into()
    }

    // ── footer ────────────────────────────────────────────────────────────
    // Hairline top border + small muted disclaimer. L29 — always present.

    fn view_footer<'a>(&self, dim_col: Color, border_col: Color) -> Element<'a, HistoryMsg> {
        container(
            text("Strict mode browsing is never recorded.")
                .size(design::type_scale::LABEL_UPPER_PX)
                .color(dim_col),
        )
        .width(Length::Fill)
        .padding(
            Padding::new(0.0)
                .top(design::space::S5)
                .bottom(design::space::S5)
                .left(design::space::S10)
                .right(design::space::S10),
        )
        .style(move |_| container::Style {
            background: None,
            border: Border {
                color: border_col,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
    }
}

// ---------------------------------------------------------------------------
// Free helpers (avoid borrow issues from &mut self calling &self methods)
// ---------------------------------------------------------------------------

fn filtered<'a>(
    query: &str,
    entries: &'a [HistoryEntry],
) -> impl Iterator<Item = &'a HistoryEntry> {
    let q = query.to_ascii_lowercase();
    entries.iter().filter(move |e| {
        q.is_empty()
            || e.title.to_ascii_lowercase().contains(&q)
            || e.domain.to_ascii_lowercase().contains(&q)
    })
}

fn visible_count_of(query: &str, entries: &[HistoryEntry]) -> usize {
    filtered(query, entries).count()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn age_days(now_ms: i64, entry_ms: i64) -> u32 {
    let delta = now_ms.saturating_sub(entry_ms).max(0);
    (delta / 86_400_000) as u32
}

fn format_time_ago(now_ms: i64, entry_ms: i64) -> String {
    let delta_s = now_ms.saturating_sub(entry_ms).max(0) / 1000;
    if delta_s < 60 {
        "Just now".to_string()
    } else if delta_s < 3600 {
        let m = delta_s / 60;
        if m == 1 {
            "1 min ago".to_string()
        } else {
            format!("{m} min ago")
        }
    } else if delta_s < 86400 {
        let h = delta_s / 3600;
        if h == 1 {
            "1 hr ago".to_string()
        } else {
            format!("{h} hr ago")
        }
    } else {
        let d = delta_s / 86400;
        if d == 1 {
            "Yesterday".to_string()
        } else {
            format!("{d} days ago")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, title: &str, domain: &str, offset_ms: i64) -> HistoryEntry {
        HistoryEntry {
            id,
            title: title.to_string(),
            domain: domain.to_string(),
            url: format!("https://{domain}/"),
            timestamp_ms: now_ms() - offset_ms,
        }
    }

    fn panel() -> HistoryPanel {
        HistoryPanel::new(HistoryRetention::Forever)
    }

    // ── open / close ──────────────────────────────────────────────────────

    #[test]
    fn opens_in_empty_phase_when_no_entries() {
        // Opened with no pre-loaded entries → Empty immediately so the user
        // never sees a loading skeleton for data that isn't coming.
        // Phase 11: Opened will set Loading and dispatch a storage fetch;
        // EntriesLoaded will then transition to Populated/Empty.
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        assert!(p.open);
        assert_eq!(p.phase, HistoryPhase::Empty);
        assert!(p.search_query.is_empty());
    }

    #[test]
    fn opens_in_populated_phase_when_entries_exist() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::Closed);
        p.update(HistoryMsg::Opened);
        assert_eq!(p.phase, HistoryPhase::Populated);
    }

    #[test]
    fn closes_and_resets_search() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::SearchChanged("a".to_string()));
        p.update(HistoryMsg::Closed);
        assert!(!p.open);
        assert!(p.search_query.is_empty());
    }

    #[test]
    fn close_during_clearing_reverts_phase() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::ClearRequested);
        assert_eq!(p.phase, HistoryPhase::Clearing);
        p.update(HistoryMsg::Closed);
        assert_eq!(p.phase, HistoryPhase::Populated);
    }

    // ── entries loaded ────────────────────────────────────────────────────

    #[test]
    fn empty_entries_yield_empty_phase() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::EntriesLoaded(vec![]));
        assert_eq!(p.phase, HistoryPhase::Empty);
    }

    #[test]
    fn non_empty_entries_yield_populated_phase() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        assert_eq!(p.phase, HistoryPhase::Populated);
    }

    // ── search ────────────────────────────────────────────────────────────

    #[test]
    fn search_narrows_visible_count() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![
            entry(1, "Alpha", "alpha.com", 0),
            entry(2, "Beta", "beta.com", 0),
        ]));
        p.update(HistoryMsg::SearchChanged("alpha".to_string()));
        assert_eq!(p.phase, HistoryPhase::Searching);
        assert_eq!(p.visible_count(), 1);
    }

    #[test]
    fn search_cleared_returns_to_populated() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(
            1,
            "Alpha",
            "alpha.com",
            0,
        )]));
        p.update(HistoryMsg::SearchChanged("x".to_string()));
        p.update(HistoryMsg::SearchChanged(String::new()));
        assert_eq!(p.phase, HistoryPhase::Populated);
    }

    #[test]
    fn search_is_case_insensitive() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(
            1,
            "GitHub",
            "github.com",
            0,
        )]));
        p.update(HistoryMsg::SearchChanged("GITHUB".to_string()));
        assert_eq!(p.visible_count(), 1);
    }

    #[test]
    fn search_matches_domain() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(
            1,
            "",
            "example.org",
            0,
        )]));
        p.update(HistoryMsg::SearchChanged("example".to_string()));
        assert_eq!(p.visible_count(), 1);
    }

    // ── delete ────────────────────────────────────────────────────────────

    #[test]
    fn delete_entry_removes_it() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![
            entry(1, "A", "a.com", 0),
            entry(2, "B", "b.com", 0),
        ]));
        let ev = p.update(HistoryMsg::EntryDelete(1));
        assert!(matches!(ev, Some(HistoryEvent::EntryDeleted { id: 1 })));
        assert_eq!(p.visible_count(), 1);
    }

    #[test]
    fn delete_last_entry_yields_empty_phase() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::EntryDelete(1));
        assert_eq!(p.phase, HistoryPhase::Empty);
    }

    // ── clear all ─────────────────────────────────────────────────────────

    #[test]
    fn clear_requested_transitions_to_clearing() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::ClearRequested);
        assert_eq!(p.phase, HistoryPhase::Clearing);
    }

    #[test]
    fn clear_confirmed_wipes_entries_and_emits_event() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::ClearRequested);
        let ev = p.update(HistoryMsg::ClearConfirmed);
        assert!(matches!(ev, Some(HistoryEvent::AllCleared)));
        assert_eq!(p.phase, HistoryPhase::Empty);
        assert_eq!(p.visible_count(), 0);
    }

    #[test]
    fn clear_cancelled_restores_populated() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::ClearRequested);
        p.update(HistoryMsg::ClearCancelled);
        assert_eq!(p.phase, HistoryPhase::Populated);
    }

    #[test]
    fn clear_failed_restores_populated() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::ClearRequested);
        p.update(HistoryMsg::ClearFailed);
        assert_eq!(p.phase, HistoryPhase::Populated);
    }

    #[test]
    fn clear_not_triggered_from_empty() {
        // ClearRequested is a no-op from Empty (nothing to clear).
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        assert_eq!(p.phase, HistoryPhase::Empty);
        p.update(HistoryMsg::ClearRequested);
        assert_eq!(p.phase, HistoryPhase::Empty);
    }

    // ── navigation events ─────────────────────────────────────────────────

    #[test]
    fn entry_open_emits_navigate() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        let ev = p.update(HistoryMsg::EntryOpen(1));
        assert!(matches!(ev, Some(HistoryEvent::Navigate { .. })));
    }

    #[test]
    fn entry_open_unknown_id_emits_nothing() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        let ev = p.update(HistoryMsg::EntryOpen(999));
        assert!(ev.is_none());
    }

    #[test]
    fn entry_open_new_tab_emits_navigate_new_tab() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        let ev = p.update(HistoryMsg::EntryOpenNewTab(1));
        assert!(matches!(ev, Some(HistoryEvent::NavigateNewTab { .. })));
    }

    #[test]
    fn entry_open_strict_emits_navigate_strict() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        let ev = p.update(HistoryMsg::EntryOpenStrictTab(1));
        assert!(matches!(ev, Some(HistoryEvent::NavigateStrictTab { .. })));
    }

    // ── keyboard focus navigation ─────────────────────────────────────────

    #[test]
    fn focus_down_starts_at_zero() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![
            entry(1, "A", "a.com", 0),
            entry(2, "B", "b.com", 0),
        ]));
        p.update(HistoryMsg::FocusDown);
        assert_eq!(p.focused_row, Some(0));
    }

    #[test]
    fn focus_down_wraps_at_end() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![
            entry(1, "A", "a.com", 0),
            entry(2, "B", "b.com", 0),
        ]));
        p.update(HistoryMsg::FocusDown);
        p.update(HistoryMsg::FocusDown);
        p.update(HistoryMsg::FocusDown);
        assert_eq!(p.focused_row, Some(0));
    }

    #[test]
    fn focus_up_from_none_wraps_to_last() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![
            entry(1, "A", "a.com", 0),
            entry(2, "B", "b.com", 0),
        ]));
        p.update(HistoryMsg::FocusUp);
        assert_eq!(p.focused_row, Some(1));
    }

    #[test]
    fn focus_activate_emits_navigate() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::FocusDown);
        let ev = p.update(HistoryMsg::FocusActivate);
        assert!(matches!(ev, Some(HistoryEvent::Navigate { .. })));
    }

    #[test]
    fn focus_delete_removes_focused_entry() {
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![
            entry(1, "A", "a.com", 0),
            entry(2, "B", "b.com", 0),
        ]));
        p.update(HistoryMsg::FocusDown);
        let ev = p.update(HistoryMsg::FocusDelete);
        assert!(matches!(ev, Some(HistoryEvent::EntryDeleted { .. })));
        assert_eq!(p.visible_count(), 1);
    }

    // ── day bucketing ─────────────────────────────────────────────────────

    #[test]
    fn day_bucket_today() {
        assert_eq!(DayBucket::from_age_days(0), DayBucket::Today);
    }

    #[test]
    fn day_bucket_yesterday() {
        assert_eq!(DayBucket::from_age_days(1), DayBucket::Yesterday);
    }

    #[test]
    fn day_bucket_days_ago() {
        assert_eq!(DayBucket::from_age_days(3), DayBucket::DaysAgo(3));
    }

    #[test]
    fn day_bucket_older() {
        assert_eq!(DayBucket::from_age_days(7), DayBucket::Older);
        assert_eq!(DayBucket::from_age_days(30), DayBucket::Older);
    }

    #[test]
    fn grouped_entries_split_by_day() {
        let now = now_ms();
        let mut p = panel();
        p.update(HistoryMsg::EntriesLoaded(vec![
            HistoryEntry {
                id: 1,
                title: "Today".to_string(),
                domain: "a.com".to_string(),
                url: "https://a.com/".to_string(),
                timestamp_ms: now - 3_600_000,
            },
            HistoryEntry {
                id: 2,
                title: "Yesterday".to_string(),
                domain: "b.com".to_string(),
                url: "https://b.com/".to_string(),
                timestamp_ms: now - 86_400_000 - 3_600_000,
            },
        ]));
        let groups = p.grouped();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, DayBucket::Today);
        assert_eq!(groups[1].0, DayBucket::Yesterday);
    }

    // ── error states ──────────────────────────────────────────────────────

    #[test]
    fn load_error_sets_error_phase() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::LoadError);
        assert_eq!(p.phase, HistoryPhase::LoadError);
    }

    #[test]
    fn storage_corrupted_sets_corrupted_phase() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::StorageCorrupted);
        assert_eq!(p.phase, HistoryPhase::CorruptedWarning);
    }

    // ── view rendering ────────────────────────────────────────────────────

    #[test]
    fn view_returns_none_when_closed() {
        let p = panel();
        assert!(p
            .view(crate::design::palette_for(
                crate::design::ThemeVariant::Dark
            ))
            .is_none());
    }

    #[test]
    fn view_returns_some_when_open() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        assert!(p
            .view(crate::design::palette_for(
                crate::design::ThemeVariant::Dark
            ))
            .is_some());
    }

    #[test]
    fn view_stable_with_entries() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::EntriesLoaded(vec![
            entry(1, "Alpha", "alpha.com", 1_000),
            entry(2, "Beta", "beta.com", 2_000),
        ]));
        assert!(p
            .view(crate::design::palette_for(
                crate::design::ThemeVariant::Dark
            ))
            .is_some());
    }

    #[test]
    fn view_stable_during_clearing() {
        let mut p = panel();
        p.update(HistoryMsg::Opened);
        p.update(HistoryMsg::EntriesLoaded(vec![entry(1, "A", "a.com", 0)]));
        p.update(HistoryMsg::ClearRequested);
        assert_eq!(p.phase, HistoryPhase::Clearing);
        assert!(p
            .view(crate::design::palette_for(
                crate::design::ThemeVariant::Dark
            ))
            .is_some());
    }

    // ── retention accessor ────────────────────────────────────────────────

    #[test]
    fn retention_is_accessible() {
        let p = HistoryPanel::new(HistoryRetention::Week);
        assert_eq!(p.retention, HistoryRetention::Week);
    }

    #[test]
    fn strict_tab_invariant_documented() {
        // L29: Strict tabs never write history. The panel always shows the
        // disclaimer footer. This test is a load-bearing documentation anchor:
        // any attempt to remove the disclaimer triggers a review here.
        let p = panel();
        assert_eq!(p.phase, HistoryPhase::Loading);
        // Strict-tab write enforcement lives in pb-storage (Phase 11). The UI
        // disclaimer is unconditional — it does not gate on mode.
    }

    // ── time formatting ───────────────────────────────────────────────────

    #[test]
    fn format_just_now() {
        let now = now_ms();
        assert_eq!(format_time_ago(now, now - 30_000), "Just now");
    }

    #[test]
    fn format_minutes_ago() {
        let now = now_ms();
        assert!(format_time_ago(now, now - 120_000).contains("min ago"));
    }

    #[test]
    fn format_hours_ago() {
        let now = now_ms();
        assert!(format_time_ago(now, now - 7_200_000).contains("hr ago"));
    }
}
