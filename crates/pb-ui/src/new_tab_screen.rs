//! pb-ui::new_tab_screen — Module 46.
//!
//! Intent-first new tab page (NTP). Per-identity; never leaks across identities (§3.1).
//!
//! Layout (vertically centred, ~80 % window width):
//!   1. Greeting (chrome-side clock — anti-fingerprint; see safety note below)
//!   2. Primary bar: command bar placeholder (Module 64.13) or plain search bar
//!      when command bar is disabled in UiConfig.
//!   3. 8 compact icon-only favourite tiles (label on hover tooltip)
//!   4. Privacy micro-stats strip (local only — never transmitted)
//!   5. Session-resume card (Standard only, L29)
//!
//! UX spec: docs/design/modules/46.md
//! Invariants: §3.1, §3.6, L18, L29, L40.
//!
//! ## Anti-fingerprint safety — local time
//!
//! `chrono::Local::now().hour()` is called ONLY inside `view()`, which runs
//! exclusively in the Iced chrome process (never inside a renderer document).
//! The hour value is used only to choose a greeting string; it is:
//!   - never passed to a renderer via IPC,
//!   - never serialised into any HTTP header or URL,
//!   - never reachable by content JS through any public API,
//!   - never stored in pb-storage or included in sync payloads.
//!
//! Timezone identity does NOT reach content; L33 (partition keys), L43 (timer
//! quantum), and A1 (tracking adversary) are all unaffected.
//! If this call is ever moved closer to renderer code, re-audit before shipping.
//!
//! TODO Module 64 (wizard):  collect user's preferred display name; write to
//!                           pb-config::IdentityProfile (new `display_name` field).
//! TODO Module 52 (settings): surface "Edit profile name" in Settings > Profile.
//! TODO Module 64.13: wire command bar into `PrimaryBar::CommandBar` slot.
//! TODO Module 80:    wire favorites + session-resume from pb-storage.
//! TODO Module 43:    wire BlockedCount / FingerprintCount increments via ChromeCommand.

use chrono::Timelike as _;
use pb_config::SearchEngine;

use crate::shell::Mode;

/// Rotating placeholder names shown when no profile name is set.
/// Chosen at `NewTabPage::new()` time so it changes per-tab and per-restart.
const PLACEHOLDER_NAMES: &[&str] = &[
    "Wanderer",
    "Explorer",
    "Stargazer",
    "Pioneer",
    "Voyager",
    "Dreamer",
    "Nomad",
    "Cipher",
    "Phantom",
    "Horizon",
    "Traveler",
    "Navigator",
    "Seeker",
    "Drifter",
    "Pathfinder",
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single entry in the favourites grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FavEntry {
    pub name: String,
    pub url: String,
}

/// Local-only per-session privacy counters (never transmitted, L40).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NtpStats {
    pub trackers_blocked: u32,
    pub fingerprint_stops: u32,
}

/// Stub for "what were you working on?" — inferred from last session (Standard only).
/// Full inference deferred to Phase 11 orchestrator wiring (Module 80).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResume {
    pub tab_count: usize,
    /// First-pass: domain of most-visited tab in the last session.
    pub topic: String,
}

/// NTP loading phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NtpPhase {
    #[default]
    Loading,
    /// No favourites stored for this identity.
    Empty,
    /// Favourites loaded; full layout shown.
    Populated,
}

/// Which primary bar to render below the greeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryBar {
    /// Module 64.13 placeholder. Rendered as an inert capsule until 64.13 lands.
    CommandBar,
    /// Plain search bar — used when command bar is disabled in UiConfig.
    SearchBar,
}

/// Messages handled by `NewTabPage::update`.
#[derive(Debug, Clone)]
pub enum NewTabMsg {
    /// pb-storage returned the favourite list (may be empty).
    FavoritesLoaded(Vec<FavEntry>),
    /// pb-storage fetch failed.
    FavoritesLoadFailed,
    /// Session resume data resolved (None if no prior session).
    SessionResumeLoaded(Option<SessionResume>),
    /// User pressed a favourite tile at grid position `n` (0-indexed).
    FavoritePressed(usize),
    /// User pressed Cmd+Enter on a favourite — open in new Strict tab.
    FavoriteOpenStrict(usize),
    /// User pressed the resume-session button.
    ResumeSessionPressed,
    /// Blocked-tracker count incremented by the network layer.
    IncrementBlockedCount,
    /// Fingerprint-attempt count incremented by the fingerprint layer.
    IncrementFingerprintCount,
    /// Hint label fade-out timer fired.
    HintFadeOut,
}

/// Events emitted upward to the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewTabEvent {
    OpenUrl(String),
    OpenUrlStrict(String),
    ResumeSession(SessionResume),
}

/// The full NTP state.
#[derive(Debug)]
pub struct NewTabPage {
    pub phase: NtpPhase,
    /// Whether to show the command-bar placeholder or plain search bar.
    pub primary_bar: PrimaryBar,
    /// Default search engine label for the search-bar placeholder (L18).
    pub search_engine: SearchEngine,
    pub stats: NtpStats,
    /// None in Strict mode (L29) or before pb-storage resolves.
    pub session_resume: Option<SessionResume>,
    pub favorites: Vec<FavEntry>,
    /// True while the "press / anytime" hint is visible (command bar only).
    pub hint_visible: bool,
    mode: Mode,
    /// True when pb-storage returned an error (shows retry link).
    load_failed: bool,
    /// Fallback display name used when the profile name is unset/default.
    /// Chosen once at construction — changes per-tab and per-restart.
    pub placeholder_name: &'static str,
    /// Illustration for the doodle zone. Matches the session label.
    pub doodle: crate::doodles::Doodle,
}

impl NewTabPage {
    pub fn new(mode: Mode, command_bar_enabled: bool, search_engine: SearchEngine) -> Self {
        let idx = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0)
            % PLACEHOLDER_NAMES.len();
        Self {
            phase: NtpPhase::Loading,
            primary_bar: if command_bar_enabled {
                PrimaryBar::CommandBar
            } else {
                PrimaryBar::SearchBar
            },
            search_engine,
            stats: NtpStats::default(),
            session_resume: None,
            favorites: Vec::new(),
            hint_visible: command_bar_enabled,
            mode,
            load_failed: false,
            placeholder_name: PLACEHOLDER_NAMES[idx],
            doodle: crate::doodles::Doodle::Unimplemented,
        }
    }

    /// Pick and store a random doodle for this session.
    pub fn init_doodle(&mut self) {
        self.doodle = crate::doodles::Doodle::random();
    }

    /// Invalidate the doodle cache on theme change.
    pub fn clear_doodle_cache(&mut self) {
        self.doodle.clear_cache();
    }

    /// Called by the shell when the tab's mode changes (Standard→Strict only, §3.6).
    pub fn sync_mode(&mut self, mode: Mode) {
        if self.mode != mode {
            self.mode = mode;
            // Doodle draws differently per mode — invalidate so it redraws.
            self.doodle.clear_cache();
        }
        if mode == Mode::Strict {
            // L29: Strict never writes history; session resume is meaningless.
            self.session_resume = None;
        }
    }

    /// Returns true when the session-resume card should be rendered.
    pub fn show_resume_card(&self) -> bool {
        self.mode == Mode::Standard && self.session_resume.is_some()
    }

    pub fn update(&mut self, msg: NewTabMsg) -> Option<NewTabEvent> {
        match msg {
            NewTabMsg::FavoritesLoaded(favs) => {
                self.favorites = favs;
                self.phase = if self.favorites.is_empty() {
                    NtpPhase::Empty
                } else {
                    NtpPhase::Populated
                };
                self.load_failed = false;
                None
            }
            NewTabMsg::FavoritesLoadFailed => {
                self.phase = NtpPhase::Empty;
                self.load_failed = true;
                None
            }
            NewTabMsg::SessionResumeLoaded(resume) => {
                // Strict mode never stores history — ignore any late-arriving data.
                if self.mode == Mode::Standard {
                    self.session_resume = resume;
                }
                None
            }
            NewTabMsg::FavoritePressed(idx) => {
                self.favorites.get(idx).map(|f| NewTabEvent::OpenUrl(f.url.clone()))
            }
            NewTabMsg::FavoriteOpenStrict(idx) => {
                self.favorites.get(idx).map(|f| NewTabEvent::OpenUrlStrict(f.url.clone()))
            }
            NewTabMsg::ResumeSessionPressed => {
                self.session_resume.clone().map(NewTabEvent::ResumeSession)
            }
            NewTabMsg::IncrementBlockedCount => {
                self.stats.trackers_blocked = self.stats.trackers_blocked.saturating_add(1);
                None
            }
            NewTabMsg::IncrementFingerprintCount => {
                self.stats.fingerprint_stops = self.stats.fingerprint_stops.saturating_add(1);
                None
            }
            NewTabMsg::HintFadeOut => {
                self.hint_visible = false;
                None
            }
        }
    }

    /// Returns the NTP element, or `None` while in `Loading` phase (wallpaper shows through).
    /// `profile_name`: raw value from AppState — "default" or empty treated as unset.
    pub(crate) fn view(
        &self,
        window_width: f32,
        profile_name: &str,
        palette: &'static crate::design::Palette,
    ) -> Option<iced::Element<'_, NewTabMsg>> {
        use iced::widget::{column, container, row, text};
        use iced::{Alignment, Element, Length};

        if self.phase == NtpPhase::Loading {
            return None;
        }

        let content_width = (window_width * 0.8).min(720.0);

        let [tp_r, tp_g, tp_b, _] = palette.text_primary;
        let [tm_r, tm_g, tm_b, _] = palette.text_muted;
        let [td_r, td_g, td_b, _] = palette.text_dim;
        let [bi_r, bi_g, bi_b, bi_a] = palette.button_idle;
        let [bb_r, bb_g, bb_b, bb_a] = palette.button_border;
        let [ac_r, ac_g, ac_b, _] = palette.active;

        let text_primary = iced::Color::from_rgb(tp_r, tp_g, tp_b);
        let text_muted = iced::Color::from_rgb(tm_r, tm_g, tm_b);
        let text_dim = iced::Color::from_rgb(td_r, td_g, td_b);
        let ctrl_bg = iced::Color::from_rgba(bi_r, bi_g, bi_b, bi_a);
        let ctrl_border = iced::Color::from_rgba(bb_r, bb_g, bb_b, bb_a);
        let accent = iced::Color::from_rgb(ac_r, ac_g, ac_b);

        // ── doodle illustration zone ──────────────────────────────────────────
        let doodle_el = self.doodle.view(palette, self.mode);

        // ── session label — doodle name, dim, above greeting ─────────────────
        let label_el = text(self.doodle.name())
            .size(11)
            .color(text_dim);

        // ── greeting (chrome-side clock — anti-fingerprint) ───────────────────
        let display_name = if profile_name.is_empty() || profile_name == "default" {
            self.placeholder_name
        } else {
            profile_name
        };
        let hour = chrono::Local::now().hour();
        let time_of_day = match hour {
            5..=11 => "Good morning",
            12..=16 => "Good afternoon",
            17..=20 => "Good evening",
            _ => "Good night",
        };
        let greeting = text(format!("{time_of_day}, {display_name}."))
            .size(20)
            .color(text_primary);

        // ── primary bar ───────────────────────────────────────────────────────
        // TODO Module 64.13: replace CommandBar arm with real command bar widget.
        let bar_label: Element<NewTabMsg> = match self.primary_bar {
            PrimaryBar::CommandBar => text("/ Search, open a tab, run a command…")
                .size(13)
                .color(text_dim)
                .into(),
            PrimaryBar::SearchBar => {
                let label = search_engine_label(&self.search_engine);
                text(format!("Search {label}…"))
                    .size(13)
                    .color(text_dim)
                    .into()
            }
        };
        let primary_bar: Element<NewTabMsg> = container(bar_label)
            .width(Length::Fill)
            .padding([0, 16])
            .align_y(iced::alignment::Vertical::Center)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(ctrl_bg)),
                border: iced::Border {
                    color: ctrl_border,
                    width: 1.0,
                    radius: 18.0.into(),
                },
                ..Default::default()
            })
            .height(36)
            .into();

        // ── favourites grid ───────────────────────────────────────────────────
        let fav_row: Element<NewTabMsg> = if self.load_failed {
            text("Couldn't load favorites — retry")
                .size(11)
                .color(text_muted)
                .into()
        } else if self.phase == NtpPhase::Empty {
            text("No favorites yet. Visit a site to add it.")
                .size(11)
                .color(text_muted)
                .into()
        } else {
            let tiles: Vec<Element<NewTabMsg>> = self
                .favorites
                .iter()
                .take(8)
                .enumerate()
                .map(|(i, fav)| {
                    let initial = fav
                        .name
                        .chars()
                        .next()
                        .unwrap_or('?')
                        .to_uppercase()
                        .next()
                        .unwrap_or('?')
                        .to_string();
                    iced::widget::button(
                        container(text(initial).size(14).color(text_primary))
                            .width(42)
                            .height(42)
                            .align_x(iced::alignment::Horizontal::Center)
                            .align_y(iced::alignment::Vertical::Center),
                    )
                    .on_press(NewTabMsg::FavoritePressed(i))
                    .style(move |_theme, status| {
                        use iced::widget::button::Status;
                        let hover_a = match status {
                            Status::Hovered | Status::Pressed => bi_a + 0.08,
                            _ => bi_a,
                        };
                        iced::widget::button::Style {
                            background: Some(iced::Background::Color(
                                iced::Color::from_rgba(bi_r, bi_g, bi_b, hover_a),
                            )),
                            border: iced::Border {
                                color: iced::Color::from_rgba(bb_r, bb_g, bb_b, bb_a),
                                width: 1.0,
                                radius: 8.0.into(),
                            },
                            ..Default::default()
                        }
                    })
                    .into()
                })
                .collect();
            row(tiles).spacing(6).into()
        };

        // ── privacy micro-stats ───────────────────────────────────────────────
        // "0 NTP requests" is architecturally always true (L40) — fixed label.
        let stats_row: Element<NewTabMsg> = row![
            text(format!("{} blocked", self.stats.trackers_blocked))
                .size(10)
                .color(text_dim),
            text("·").size(10).color(text_dim),
            text("0 NTP requests").size(10).color(text_dim),
            text("·").size(10).color(text_dim),
            text(format!("{} fingerprint stops", self.stats.fingerprint_stops))
                .size(10)
                .color(text_dim),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .into();

        // ── session resume card (Standard only, L29) ──────────────────────────
        let resume_el: Option<Element<NewTabMsg>> = if self.show_resume_card() {
            self.session_resume.as_ref().map(|sr| {
                container(
                    row![
                        column![
                            text(format!("Yesterday · {} tabs", sr.tab_count))
                                .size(10)
                                .color(text_muted),
                            text(sr.topic.clone()).size(12).color(text_primary),
                        ]
                        .spacing(2),
                        iced::widget::Space::new().width(Length::Fill),
                        iced::widget::button(
                            text("Resume session").size(11).color(accent),
                        )
                        .on_press(NewTabMsg::ResumeSessionPressed)
                        .style(move |_theme, _status| iced::widget::button::Style {
                            background: Some(iced::Background::Color(
                                iced::Color::from_rgba(ac_r, ac_g, ac_b, 0.18),
                            )),
                            border: iced::Border {
                                color: iced::Color::from_rgba(ac_r, ac_g, ac_b, 0.3),
                                width: 1.0,
                                radius: 6.0.into(),
                            },
                            ..Default::default()
                        })
                        .padding([4, 10]),
                    ]
                    .align_y(Alignment::Center),
                )
                .padding([8, 12])
                .style(move |_| container::Style {
                    background: Some(iced::Background::Color(ctrl_bg)),
                    border: iced::Border {
                        color: ctrl_border,
                        width: 1.0,
                        radius: 10.0.into(),
                    },
                    ..Default::default()
                })
                .width(Length::Fill)
                .into()
            })
        } else {
            None
        };

        // ── assemble ──────────────────────────────────────────────────────────
        let mut col = column![doodle_el, label_el, greeting, primary_bar, fav_row, stats_row].spacing(12);
        if let Some(resume) = resume_el {
            col = col.push(resume);
        }

        // FillPortion 1:4 → top spacer takes 20 % of available height.
        Some(
            iced::widget::column![
                iced::widget::Space::new().width(Length::Fill).height(Length::FillPortion(1)),
                container(col.width(content_width))
                    .width(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Center),
                iced::widget::Space::new().width(Length::Fill).height(Length::FillPortion(2)),
            ]
            .width(Length::Fill)
            .height(Length::Fill)
            .into(),
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn search_engine_label(engine: &SearchEngine) -> &'static str {
    match engine {
        SearchEngine::DuckDuckGo => "DuckDuckGo",
        SearchEngine::Startpage => "Startpage",
        SearchEngine::BraveSearch => "Brave Search",
        SearchEngine::Mojeek => "Mojeek",
        SearchEngine::Custom { .. } => "the web",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pb_config::SearchEngine;

    fn std_ntp() -> NewTabPage {
        NewTabPage::new(Mode::Standard, true, SearchEngine::DuckDuckGo)
    }

    fn strict_ntp() -> NewTabPage {
        NewTabPage::new(Mode::Strict, true, SearchEngine::DuckDuckGo)
    }

    fn favs() -> Vec<FavEntry> {
        vec![
            FavEntry { name: "DDG".into(), url: "https://duckduckgo.com".into() },
            FavEntry { name: "GitHub".into(), url: "https://github.com".into() },
        ]
    }

    // ── phase transitions ─────────────────────────────────────────────────────

    #[test]
    fn new_ntp_starts_in_loading_phase() {
        assert_eq!(std_ntp().phase, NtpPhase::Loading);
    }

    #[test]
    fn favorites_loaded_non_empty_transitions_to_populated() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::FavoritesLoaded(favs()));
        assert_eq!(ntp.phase, NtpPhase::Populated);
    }

    #[test]
    fn favorites_loaded_empty_transitions_to_empty() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::FavoritesLoaded(vec![]));
        assert_eq!(ntp.phase, NtpPhase::Empty);
    }

    #[test]
    fn favorites_load_failed_transitions_to_empty_with_error_flag() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::FavoritesLoadFailed);
        assert_eq!(ntp.phase, NtpPhase::Empty);
        assert!(ntp.load_failed);
    }

    // ── favourite press events ────────────────────────────────────────────────

    #[test]
    fn favorite_pressed_emits_open_url() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::FavoritesLoaded(favs()));
        let ev = ntp.update(NewTabMsg::FavoritePressed(0));
        assert_eq!(ev, Some(NewTabEvent::OpenUrl("https://duckduckgo.com".into())));
    }

    #[test]
    fn favorite_pressed_out_of_bounds_emits_nothing() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::FavoritesLoaded(favs()));
        assert_eq!(ntp.update(NewTabMsg::FavoritePressed(99)), None);
    }

    #[test]
    fn favorite_open_strict_emits_open_url_strict() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::FavoritesLoaded(favs()));
        let ev = ntp.update(NewTabMsg::FavoriteOpenStrict(1));
        assert_eq!(ev, Some(NewTabEvent::OpenUrlStrict("https://github.com".into())));
    }

    // ── session resume ────────────────────────────────────────────────────────

    #[test]
    fn session_resume_loaded_stored_in_standard_mode() {
        let mut ntp = std_ntp();
        let resume = SessionResume { tab_count: 5, topic: "Rust / Iced".into() };
        ntp.update(NewTabMsg::SessionResumeLoaded(Some(resume.clone())));
        assert_eq!(ntp.session_resume, Some(resume));
    }

    #[test]
    fn session_resume_ignored_in_strict_mode() {
        let mut ntp = strict_ntp();
        let resume = SessionResume { tab_count: 3, topic: "Research".into() };
        ntp.update(NewTabMsg::SessionResumeLoaded(Some(resume)));
        assert_eq!(ntp.session_resume, None);
    }

    #[test]
    fn show_resume_card_false_in_strict_mode() {
        let mut ntp = strict_ntp();
        ntp.update(NewTabMsg::SessionResumeLoaded(Some(SessionResume {
            tab_count: 2,
            topic: "Research".into(),
        })));
        assert!(!ntp.show_resume_card());
    }

    #[test]
    fn show_resume_card_true_in_standard_with_data() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::SessionResumeLoaded(Some(SessionResume {
            tab_count: 4,
            topic: "DevBrowse".into(),
        })));
        assert!(ntp.show_resume_card());
    }

    #[test]
    fn resume_session_pressed_emits_event() {
        let mut ntp = std_ntp();
        let resume = SessionResume { tab_count: 4, topic: "DevBrowse".into() };
        ntp.update(NewTabMsg::SessionResumeLoaded(Some(resume.clone())));
        let ev = ntp.update(NewTabMsg::ResumeSessionPressed);
        assert_eq!(ev, Some(NewTabEvent::ResumeSession(resume)));
    }

    #[test]
    fn resume_session_pressed_without_data_emits_nothing() {
        let mut ntp = std_ntp();
        assert_eq!(ntp.update(NewTabMsg::ResumeSessionPressed), None);
    }

    // ── mode sync ─────────────────────────────────────────────────────────────

    #[test]
    fn sync_mode_to_strict_clears_session_resume() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::SessionResumeLoaded(Some(SessionResume {
            tab_count: 2,
            topic: "work".into(),
        })));
        ntp.sync_mode(Mode::Strict);
        assert_eq!(ntp.session_resume, None);
    }

    // ── privacy stats ─────────────────────────────────────────────────────────

    #[test]
    fn increment_blocked_count_increments() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::IncrementBlockedCount);
        ntp.update(NewTabMsg::IncrementBlockedCount);
        assert_eq!(ntp.stats.trackers_blocked, 2);
    }

    #[test]
    fn increment_fingerprint_count_increments() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::IncrementFingerprintCount);
        assert_eq!(ntp.stats.fingerprint_stops, 1);
    }

    #[test]
    fn blocked_count_saturates_at_max() {
        let mut ntp = std_ntp();
        ntp.stats.trackers_blocked = u32::MAX;
        ntp.update(NewTabMsg::IncrementBlockedCount);
        assert_eq!(ntp.stats.trackers_blocked, u32::MAX);
    }

    // ── primary bar ───────────────────────────────────────────────────────────

    #[test]
    fn command_bar_enabled_sets_command_bar_primary() {
        let ntp = NewTabPage::new(Mode::Standard, true, SearchEngine::DuckDuckGo);
        assert_eq!(ntp.primary_bar, PrimaryBar::CommandBar);
        assert!(ntp.hint_visible);
    }

    #[test]
    fn command_bar_disabled_sets_search_bar_primary() {
        let ntp = NewTabPage::new(Mode::Standard, false, SearchEngine::DuckDuckGo);
        assert_eq!(ntp.primary_bar, PrimaryBar::SearchBar);
        assert!(!ntp.hint_visible);
    }

    #[test]
    fn hint_fade_out_clears_hint() {
        let mut ntp = std_ntp();
        ntp.update(NewTabMsg::HintFadeOut);
        assert!(!ntp.hint_visible);
    }

    // ── session resume ignored after Standard→Strict sync ────────────────────
    #[test]
    fn session_resume_loaded_after_strict_sync_is_ignored() {
        let mut ntp = std_ntp();
        ntp.sync_mode(Mode::Strict);
        ntp.update(NewTabMsg::SessionResumeLoaded(Some(SessionResume {
            tab_count: 1,
            topic: "late data".into(),
        })));
        assert_eq!(ntp.session_resume, None);
    }
}
