//! Tab strip view — view_strip() and chip() rendering.
//! Owns: the horizontal chip row, pipe dividers, plus button, single mouse_area.

use iced::widget::{container, mouse_area, row, text, Space};
use iced::{Element, Length};

use crate::design;
use crate::shell::Mode;
use super::{TabBar, TabBarMsg, TabEntry};

// ── Tab strip tunables ────────────────────────────────────────────────────────
const BORDER_STANDARD: iced::Color = iced::Color { r: 0.1516, g: 0.1898, b: 0.235, a: 1.0 };
const BORDER_STRICT_ALPHA: f32 = 0.70;
const STRIP_RADIUS: f32   =  0.0;   // corner radius of the strip bar itself
const CHIP_RADIUS: f32    = 20.0;   // corner radius of individual tab chips
const STRIP_H_MARGIN: f32 =  0.0;  // horizontal gap between strip and window edge
// ─────────────────────────────────────────────────────────────────────────────

impl TabBar {
    /// Sticky horizontal chip row. Hidden when ≤ 1 tab open.
    pub fn view_strip(&self, _window_width: f32) -> Element<'_, TabBarMsg> {
        if self.tabs.len() <= 1 {
            return Space::new().into();
        }

        let positions = self.tab_positions();

        // True when a tab suppresses adjacent dividers (hovered, active, or any Strict tab with tint bg).
        let prominent = |id: usize| {
            self.hovered_tab_id == Some(id)
                || self.active_id == id
                || self.tabs.iter().find(|t| t.id == id).map(|t| t.mode == Mode::Strict).unwrap_or(false)
        };

        // 1px pipe: visible when show=true, invisible 1px spacer when false.
        // Always 1px wide so tab_positions() math is never affected.
        let pipe = |show: bool| -> Element<'_, TabBarMsg> {
            container(Space::new())
                .width(1.0)
                .height(Length::Fixed(20.0))
                .style(move |_| container::Style {
                    background: if show {
                        Some(iced::Background::Color(iced::Color::from_rgba(
                            1.0, 0.98, 0.94, 0.12,
                        )))
                    } else {
                        None
                    },
                    ..Default::default()
                })
                .into()
        };

        let mut chip_elements: Vec<Element<'_, TabBarMsg>> = Vec::new();
        for (i, (tab, &(_, _, w))) in self.tabs.iter().zip(positions.iter()).enumerate() {
            if i > 0 {
                let prev_id = self.tabs[i - 1].id;
                chip_elements.push(pipe(!prominent(prev_id) && !prominent(tab.id)));
            }
            let is_dragged = self.drag_id == Some(tab.id) && self.drag_active;
            chip_elements.push(self.chip(tab, w, is_dragged));
        }

        // New-tab action lives in the sidebar + button; no redundant + in the strip.

        let chip_row = row(chip_elements)
            .width(Length::Fill)
            .align_y(iced::alignment::Vertical::Center)
            .spacing(0.0)
            .padding([0.0, design::space::S4]);

        let strip = container(chip_row)
            .width(Length::Fill)
            .height(Length::Fixed(design::layout::TAB_BAR_HEIGHT_PX))
            .center_y(Length::Fixed(design::layout::TAB_BAR_HEIGHT_PX))
            .style(|_| container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    0.055, 0.071, 0.118, 0.85,
                ))),
                border: iced::Border {
                    color: iced::Color::from_rgba(1.0, 0.98, 0.94, 0.05),
                    width: 1.0,
                    radius: STRIP_RADIUS.into(),
                },
                ..Default::default()
            });

        let strip_with_margin = container(mouse_area(strip)
            .on_move(|pos| TabBarMsg::StripMoved(pos.x))
            .on_press(TabBarMsg::StripPressed)
            .on_release(TabBarMsg::StripReleased)
            .on_exit(TabBarMsg::StripExited)
            .interaction(if self.drag_active {
                iced::mouse::Interaction::Grab
            } else {
                iced::mouse::Interaction::Pointer
            }))
            .width(Length::Fill)
            .padding(iced::Padding { top: 0.0, bottom: 0.0, left: STRIP_H_MARGIN, right: STRIP_H_MARGIN });

        strip_with_margin.into()
    }

    /// Renders a single tab chip. Width is the explicit pixel width from tab_positions().
    /// `is_dragged` is true while this chip is being repositioned by drag.
    pub(crate) fn chip<'a>(&'a self, tab: &'a TabEntry, chip_width: f32, is_dragged: bool) -> Element<'a, TabBarMsg> {
        let is_hovered = self.hovered_tab_id == Some(tab.id);
        let is_active  = self.active_id == tab.id;
        // Active tab always shows title + X regardless of width.
        let show_title = is_active || chip_width >= 80.0;
        let is_strict  = tab.mode == Mode::Strict;

        let text_color = if is_strict {
            iced::Color::from_rgba(0.847, 0.722, 0.627, 1.0)
        } else if is_active {
            iced::Color::from_rgba(0.941, 0.933, 0.894, 1.0)
        } else {
            iced::Color::from_rgba(0.720, 0.730, 0.760, 1.0)
        };

        let fav: Element<'_, TabBarMsg> = container(
            text(&tab.favicon_label).size(10.0).color(iced::Color::WHITE),
        )
        .width(16.0)
        .height(16.0)
        .align_x(iced::alignment::Horizontal::Center)
        .align_y(iced::alignment::Vertical::Center)
        .style(|_| container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(
                0.1, 0.11, 0.14, 1.0,
            ))),
            border: iced::Border {
                radius: design::radius::FAV_PX.into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .into();

        let inner: Element<'_, TabBarMsg> = if show_title {
            let mute_dot: Element<'_, TabBarMsg> = if tab.is_muted {
                container(Space::new())
                    .width(5.0)
                    .height(5.0)
                    .style(|_| container::Style {
                        background: Some(iced::Background::Color(iced::Color::from_rgba(
                            design::palette::ACCENT[0],
                            design::palette::ACCENT[1],
                            design::palette::ACCENT[2],
                            1.0,
                        ))),
                        border: iced::Border { radius: 2.5.into(), ..Default::default() },
                        ..Default::default()
                    })
                    .into()
            } else {
                Space::new().into()
            };

            let close_slot: Element<'_, TabBarMsg> = if is_hovered && !tab.is_pinned {
                container(
                    text("\u{00d7}").size(13.0).color(iced::Color::from_rgba(0.75, 0.75, 0.75, 1.0)),
                )
                .width(18.0)
                .height(18.0)
                .align_x(iced::alignment::Horizontal::Center)
                .align_y(iced::alignment::Vertical::Center)
                .style(|_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        1.0, 1.0, 1.0, 0.10,
                    ))),
                    border: iced::Border { radius: 4.0.into(), ..Default::default() },
                    ..Default::default()
                })
                .into()
            } else {
                container(Space::new()).width(18.0).height(18.0).into()
            };

            let title_clipped: Element<'_, TabBarMsg> = container(
                text(&tab.title)
                    .size(13.0)
                    .color(text_color)
                    .wrapping(iced::widget::text::Wrapping::None),
            )
            .width(Length::Fill)
            .clip(true)
            .into();

            row![
                Space::new().width(design::space::S5),
                fav,
                Space::new().width(design::space::S4),
                title_clipped,
                mute_dot,
                Space::new().width(design::space::S3),
                close_slot,
                Space::new().width(design::space::S4),
            ]
            .align_y(iced::alignment::Vertical::Center)
            .into()
        } else {
            // Icon-only: inactive tab with no room for title. Favicon centered.
            row![
                Space::new().width(Length::Fill),
                fav,
                Space::new().width(Length::Fill),
            ]
            .align_y(iced::alignment::Vertical::Center)
            .into()
        };

        let [sr, sg, sb, _] = design::palette::STRICT;

        let bg = if is_dragged {
            // Lifted "ghost" appearance: stronger fill signals the chip is moving.
            if is_strict { iced::Color::from_rgba(sr, sg, sb, 0.50) }
            else         { iced::Color::from_rgba(0.357, 0.553, 0.937, 0.40) }
        } else if is_active {
            if is_strict { iced::Color::from_rgba(sr, sg, sb, 0.22) }
            else         { iced::Color::from_rgba(0.357, 0.553, 0.937, 0.18) }
        } else if is_hovered {
            if is_strict { iced::Color::from_rgba(sr, sg, sb, 0.14) }
            else         { iced::Color::from_rgba(1.0, 0.98, 0.94, 0.08) }
        } else if is_strict {
            iced::Color::from_rgba(sr, sg, sb, 0.07)
        } else {
            iced::Color::from_rgba(0.0, 0.0, 0.0, 0.0)
        };

        let strict_border = iced::Color::from_rgba(sr, sg, sb, BORDER_STRICT_ALPHA);
        let (border_color, border_width) = if is_dragged {
            // Bright border marks the chip being repositioned.
            if is_strict { (strict_border, 1.5_f32) }
            else         { (iced::Color::from_rgba(0.357, 0.553, 0.937, 1.0), 1.5_f32) }
        } else if is_active || is_hovered {
            if is_strict { (strict_border, 1.0_f32) }
            else         { (BORDER_STANDARD, 1.0_f32) }
        } else {
            (iced::Color::from_rgba(0.0, 0.0, 0.0, 0.0), 0.0_f32)
        };

        container(inner)
            .width(Length::Fixed(chip_width))
            .height(Length::Fixed(design::layout::TAB_BAR_HEIGHT_PX - 12.0))
            .align_y(iced::alignment::Vertical::Center)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(bg)),
                border: iced::Border {
                    color: border_color,
                    width: border_width,
                    radius: CHIP_RADIUS.into(),
                },
                ..Default::default()
            })
            .into()
    }
}
