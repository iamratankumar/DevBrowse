//! Find in page — Module 47.
//!
//! Compact floating bar anchored bottom-right. Cmd+F / Ctrl+F opens it;
//! Escape closes it; Enter = next match; Shift+Enter = previous.
//!
//! **Phase 8 search note:** find-in-page searches rendered web-page DOM.
//! The start page (NTP) is Iced widgets — there is no DOM to search.
//! `match_count` is always 0 until the renderer broker is wired in Phase 11.
//! The bar is fully functional as a UI component; results will light up once
//! a renderer is attached.
//!
//! Privacy: query string is never written to disk or sent over the network.

use iced::{
    alignment::Vertical,
    widget::{button, column, container, row, text, text_input},
    Background, Border, Color, Element, Length, Padding, Shadow, Vector,
};

use crate::design;

// ---------------------------------------------------------------------------
// Search mode
// ---------------------------------------------------------------------------

/// How the query is matched against page text.
/// Phase 11 passes this to the renderer broker so it can apply the correct
/// text-search algorithm on the Gecko side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    Contains,
    StartsWith,
    EndsWith,
}

impl SearchMode {
    /// Short symbol shown inside the mode button.
    fn symbol(self) -> &'static str {
        match self {
            SearchMode::Contains => ".*",
            SearchMode::StartsWith => "^",
            SearchMode::EndsWith => "$",
        }
    }

    /// Full label shown in the dropdown list.
    fn label(self) -> &'static str {
        match self {
            SearchMode::Contains => "Contains",
            SearchMode::StartsWith => "Starts with",
            SearchMode::EndsWith => "Ends with",
        }
    }
}

// ---------------------------------------------------------------------------
// State + messages
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct FindBar {
    pub open: bool,
    pub query: String,
    /// Hit count fed back by the renderer (Phase 11). Always 0 in Phase 8.
    pub match_count: usize,
    pub current_match: usize,
    pub mode: SearchMode,
    pub mode_dropdown_open: bool,
}

#[derive(Debug, Clone)]
pub enum FindMsg {
    Opened,
    Closed,
    QueryChanged(String),
    NextMatch,
    PrevMatch,
    ModeDropdownToggled,
    ModeSelected(SearchMode),
}

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------

impl Default for FindBar {
    fn default() -> Self {
        Self::new()
    }
}

impl FindBar {
    pub fn new() -> Self {
        Self {
            open: false,
            query: String::new(),
            match_count: 0,
            current_match: 0,
            mode: SearchMode::Contains,
            mode_dropdown_open: false,
        }
    }

    pub fn update(&mut self, msg: FindMsg) -> iced::Task<FindMsg> {
        match msg {
            FindMsg::Opened => {
                self.open = true;
                self.query.clear();
                self.match_count = 0;
                self.current_match = 0;
                self.mode_dropdown_open = false;
            }
            FindMsg::Closed => {
                self.open = false;
                self.query.clear();
                self.match_count = 0;
                self.current_match = 0;
                self.mode_dropdown_open = false;
            }
            FindMsg::QueryChanged(q) => {
                self.query = q;
                self.mode_dropdown_open = false;
                // Phase 11: forward query + mode to renderer broker here.
                self.match_count = 0;
                self.current_match = 0;
            }
            FindMsg::NextMatch => {
                if self.match_count > 0 {
                    self.current_match = (self.current_match + 1) % self.match_count;
                }
            }
            FindMsg::PrevMatch => {
                if self.match_count > 0 {
                    self.current_match =
                        (self.current_match + self.match_count - 1) % self.match_count;
                }
            }
            FindMsg::ModeDropdownToggled => {
                self.mode_dropdown_open = !self.mode_dropdown_open;
            }
            FindMsg::ModeSelected(m) => {
                self.mode = m;
                self.mode_dropdown_open = false;
                self.match_count = 0;
                self.current_match = 0;
            }
        }
        iced::Task::none()
    }

    /// Returns `None` when closed.
    ///
    /// The returned element is a `Column`: optional mode-dropdown above,
    /// search bar below. Mount it right-aligned + bottom-aligned in the shell
    /// Stack so both pieces stay together.
    pub fn view(&self, palette: &'static design::Palette) -> Option<Element<'_, FindMsg>> {
        if !self.open {
            return None;
        }

        // ── colour bindings ───────────────────────────────────────────────
        let [tr, tg, tb, _] = palette.text_primary;
        let text_color = Color::from_rgb(tr, tg, tb);
        let [mr, mg, mb, _] = palette.text_muted;
        let muted_color = Color::from_rgb(mr, mg, mb);
        let [gr, gg, gb, ga] = palette.glass_tint;
        // Slightly more opaque than ambient glass so the bar reads as its own
        // surface rather than blending into the content area.
        let glass_bg = Color::from_rgba(gr, gg, gb, (ga + 0.18).min(1.0));
        let [br2, bg2, bb2, ba2] = palette.button_border;
        let border_color = Color::from_rgba(br2, bg2, bb2, ba2);
        let [hvr, hvg, hvb, hva] = palette.button_hover;
        let btn_hover = Color::from_rgba(hvr, hvg, hvb, hva);
        let [ar, ag, ab, _] = palette.active;
        let active_color = Color::from_rgb(ar, ag, ab);

        // ── mode dropdown (Column child above the bar) ────────────────────
        let dropdown: Option<Element<'_, FindMsg>> = if self.mode_dropdown_open {
            let items: Vec<Element<'_, FindMsg>> = [
                SearchMode::Contains,
                SearchMode::StartsWith,
                SearchMode::EndsWith,
            ]
            .into_iter()
            .map(|m| {
                let selected = m == self.mode;
                let row_bg = if selected {
                    Color::from_rgba(ar, ag, ab, 0.20)
                } else {
                    Color::TRANSPARENT
                };
                let row_hover = Color::from_rgba(ar, ag, ab, 0.10);
                let sym_color = if selected { active_color } else { text_color };

                button(
                    row![
                        // symbol — fixed 28 px wide so all three labels line up
                        text(m.symbol())
                            .size(12.0)
                            .color(sym_color)
                            .width(28.0),
                        text(m.label())
                            .size(12.0)
                            .color(text_color),
                    ]
                    .spacing(4)
                    .align_y(Vertical::Center),
                )
                // Fill within the Fixed(155) container gives each row the same
                // width without expanding beyond the container boundary.
                .width(Length::Fill)
                .padding(Padding::new(5.0).left(8.0).right(12.0))
                .on_press(FindMsg::ModeSelected(m))
                .style(move |_, status| button::Style {
                    background: Some(Background::Color(match status {
                        button::Status::Hovered | button::Status::Pressed => row_hover,
                        _ => row_bg,
                    })),
                    border: Border {
                        radius: 5.0.into(),
                        ..Default::default()
                    },
                    text_color,
                    ..Default::default()
                })
                .into()
            })
            .collect();

            Some(
                // Fixed width prevents the dropdown from filling the window.
                container(column(items).spacing(1))
                    .width(Length::Fixed(155.0))
                    .padding(Padding::new(5.0))
                    .style(move |_| container::Style {
                        background: Some(Background::Color(glass_bg)),
                        border: Border {
                            color: border_color,
                            width: 1.0,
                            radius: 8.0.into(),
                        },
                        text_color: Some(text_color),
                        shadow: Shadow {
                            color: Color::from_rgba(0.0, 0.0, 0.0, 0.28),
                            offset: Vector::new(0.0, -2.0),
                            blur_radius: 10.0,
                        },
                        snap: false,
                    })
                    .into(),
            )
        } else {
            None
        };

        // ── mode button (left of bar) ─────────────────────────────────────
        let sym = self.mode.symbol();
        let dd_open = self.mode_dropdown_open;
        let mode_btn = button(
            container(
                row![
                    text(sym).size(12.0).color(text_color),
                    text(if dd_open { " ▴" } else { " ▾" })
                        .size(10.0)
                        .color(muted_color),
                ]
                .align_y(Vertical::Center),
            )
            .width(Length::Shrink)
            .height(Length::Fill)
            .align_y(Vertical::Center),
        )
        .height(26.0)
        .padding(Padding::new(0.0).left(8.0).right(6.0))
        .on_press(FindMsg::ModeDropdownToggled)
        .style(move |_, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered | button::Status::Pressed => btn_hover,
                _ => Color::from_rgba(0.0, 0.0, 0.0, 0.0),
            })),
            border: Border {
                color: border_color,
                width: 1.0,
                radius: 5.0.into(),
            },
            text_color,
            ..Default::default()
        });

        // ── text input ────────────────────────────────────────────────────
        // Placeholder explains Phase 8 limitation: find works on web pages,
        // not on the NTP (which is Iced widgets with no DOM).
        let input = text_input("Find in web pages (Phase 11 live)", &self.query)
            .on_input(FindMsg::QueryChanged)
            .on_submit(FindMsg::NextMatch)
            .size(12.0)
            .width(Length::Fixed(210.0))
            .style(move |_t, _s| text_input::Style {
                background: Background::Color(Color::TRANSPARENT),
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 0.0,
                    radius: 0.0.into(),
                },
                icon: text_color,
                placeholder: muted_color,
                value: text_color,
                selection: Color::from_rgba(ar, ag, ab, 0.30),
            });

        // ── match count ───────────────────────────────────────────────────
        let count_str = if self.query.is_empty() {
            String::new()
        } else if self.match_count == 0 {
            "0/0".to_string()
        } else {
            format!("{}/{}", self.current_match + 1, self.match_count)
        };
        let count_label = text(count_str).size(11.0).color(muted_color).width(30.0);

        // ── icon buttons ──────────────────────────────────────────────────
        // `enabled` controls whether the button accepts press events. When
        // disabled (no on_press), Iced delivers Status::Disabled to the style
        // closure so we can dim the icon automatically.
        let mk_btn = move |label: &'static str, msg: FindMsg, enabled: bool| {
            let b = button(
                container(text(label).size(11.0))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Center)
                    .align_y(iced::alignment::Vertical::Center),
            )
            .width(22.0)
            .height(22.0)
            .padding(Padding::new(0.0))
            .style(move |_, status| button::Style {
                background: Some(Background::Color(match status {
                    button::Status::Hovered | button::Status::Pressed => btn_hover,
                    _ => Color::TRANSPARENT,
                })),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                text_color: match status {
                    button::Status::Disabled => muted_color,
                    _ => text_color,
                },
                ..Default::default()
            });
            if enabled {
                b.on_press(msg)
            } else {
                b
            }
        };

        let has_matches = self.match_count > 0;

        // ── bar row ───────────────────────────────────────────────────────
        let bar_row = row![
            mode_btn,
            input,
            count_label,
            mk_btn("▲", FindMsg::PrevMatch, has_matches),
            mk_btn("▼", FindMsg::NextMatch, has_matches),
            mk_btn("✕", FindMsg::Closed, true),
        ]
        .spacing(4)
        .align_y(Vertical::Center);

        let bar = container(bar_row)
            .padding(Padding::new(5.0).left(8.0).right(6.0))
            .style(move |_| container::Style {
                background: Some(Background::Color(glass_bg)),
                border: Border {
                    color: border_color,
                    width: 1.0,
                    radius: 9.0.into(),
                },
                text_color: Some(text_color),
                shadow: Shadow {
                    color: Color::from_rgba(0.0, 0.0, 0.0, 0.20),
                    offset: Vector::new(0.0, 3.0),
                    blur_radius: 10.0,
                },
                snap: false,
            });

        // ── assemble: dropdown above bar ──────────────────────────────────
        let mut col = column![].spacing(4);
        if let Some(dd) = dropdown {
            col = col.push(dd);
        }
        col = col.push(bar);

        Some(col.into())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bar() -> FindBar {
        FindBar::new()
    }

    #[test]
    fn opens_with_empty_query_and_contains_mode() {
        let mut b = bar();
        let _ = b.update(FindMsg::Opened);
        assert!(b.open);
        assert!(b.query.is_empty());
        assert_eq!(b.mode, SearchMode::Contains);
        assert!(!b.mode_dropdown_open);
    }

    #[test]
    fn opened_twice_resets_query_and_closes_dropdown() {
        let mut b = bar();
        let _ = b.update(FindMsg::Opened);
        let _ = b.update(FindMsg::QueryChanged("hello".to_string()));
        let _ = b.update(FindMsg::ModeDropdownToggled);
        let _ = b.update(FindMsg::Opened);
        assert!(b.query.is_empty());
        assert!(!b.mode_dropdown_open);
    }

    #[test]
    fn closes_and_clears_state() {
        let mut b = bar();
        let _ = b.update(FindMsg::Opened);
        let _ = b.update(FindMsg::QueryChanged("foo".to_string()));
        let _ = b.update(FindMsg::ModeDropdownToggled);
        let _ = b.update(FindMsg::Closed);
        assert!(!b.open);
        assert!(b.query.is_empty());
        assert!(!b.mode_dropdown_open);
    }

    #[test]
    fn query_changed_updates_field_and_closes_dropdown() {
        let mut b = bar();
        let _ = b.update(FindMsg::Opened);
        let _ = b.update(FindMsg::ModeDropdownToggled);
        assert!(b.mode_dropdown_open);
        let _ = b.update(FindMsg::QueryChanged("rust".to_string()));
        assert_eq!(b.query, "rust");
        assert!(!b.mode_dropdown_open);
    }

    #[test]
    fn next_match_wraps_around() {
        let mut b = bar();
        b.open = true;
        b.match_count = 3;
        b.current_match = 2;
        let _ = b.update(FindMsg::NextMatch);
        assert_eq!(b.current_match, 0);
    }

    #[test]
    fn prev_match_wraps_around() {
        let mut b = bar();
        b.open = true;
        b.match_count = 3;
        b.current_match = 0;
        let _ = b.update(FindMsg::PrevMatch);
        assert_eq!(b.current_match, 2);
    }

    #[test]
    fn next_noop_when_no_matches() {
        let mut b = bar();
        b.open = true;
        b.match_count = 0;
        let _ = b.update(FindMsg::NextMatch);
        assert_eq!(b.current_match, 0);
    }

    #[test]
    fn prev_noop_when_no_matches() {
        let mut b = bar();
        b.open = true;
        b.match_count = 0;
        let _ = b.update(FindMsg::PrevMatch);
        assert_eq!(b.current_match, 0);
    }

    #[test]
    fn mode_dropdown_toggle() {
        let mut b = bar();
        let _ = b.update(FindMsg::ModeDropdownToggled);
        assert!(b.mode_dropdown_open);
        let _ = b.update(FindMsg::ModeDropdownToggled);
        assert!(!b.mode_dropdown_open);
    }

    #[test]
    fn mode_selected_updates_mode_and_closes_dropdown() {
        let mut b = bar();
        let _ = b.update(FindMsg::ModeDropdownToggled);
        let _ = b.update(FindMsg::ModeSelected(SearchMode::StartsWith));
        assert_eq!(b.mode, SearchMode::StartsWith);
        assert!(!b.mode_dropdown_open);
    }

    #[test]
    fn view_returns_none_when_closed() {
        let b = bar();
        assert!(b
            .view(crate::design::palette_for(
                crate::design::ThemeVariant::Dark
            ))
            .is_none());
    }

    #[test]
    fn view_returns_some_when_open() {
        let mut b = bar();
        let _ = b.update(FindMsg::Opened);
        assert!(b
            .view(crate::design::palette_for(
                crate::design::ThemeVariant::Dark
            ))
            .is_some());
    }

    #[test]
    fn view_stable_with_dropdown_open() {
        let mut b = bar();
        let _ = b.update(FindMsg::Opened);
        let _ = b.update(FindMsg::ModeDropdownToggled);
        assert!(b
            .view(crate::design::palette_for(
                crate::design::ThemeVariant::Dark
            ))
            .is_some());
    }

    #[test]
    fn search_mode_symbols_are_distinct() {
        assert_ne!(
            SearchMode::Contains.symbol(),
            SearchMode::StartsWith.symbol()
        );
        assert_ne!(
            SearchMode::StartsWith.symbol(),
            SearchMode::EndsWith.symbol()
        );
    }

    #[test]
    fn count_zero_when_query_non_empty_and_no_renderer() {
        let mut b = bar();
        let _ = b.update(FindMsg::Opened);
        let _ = b.update(FindMsg::QueryChanged("hello".to_string()));
        // match_count stays 0 in Phase 8 — renderer not attached.
        assert_eq!(b.match_count, 0);
    }

    #[test]
    fn nav_buttons_disabled_when_no_matches() {
        // When match_count == 0, next/prev are no-ops (no state change).
        let mut b = bar();
        b.open = true;
        b.match_count = 0;
        b.current_match = 0;
        let _ = b.update(FindMsg::NextMatch);
        assert_eq!(b.current_match, 0);
        let _ = b.update(FindMsg::PrevMatch);
        assert_eq!(b.current_match, 0);
    }

    #[test]
    fn next_wraps_from_last_to_first() {
        let mut b = bar();
        b.open = true;
        b.match_count = 3;
        b.current_match = 2; // last
        let _ = b.update(FindMsg::NextMatch);
        assert_eq!(b.current_match, 0); // wraps to first
    }

    #[test]
    fn prev_wraps_from_first_to_last() {
        let mut b = bar();
        b.open = true;
        b.match_count = 3;
        b.current_match = 0; // first
        let _ = b.update(FindMsg::PrevMatch);
        assert_eq!(b.current_match, 2); // wraps to last
    }
}
