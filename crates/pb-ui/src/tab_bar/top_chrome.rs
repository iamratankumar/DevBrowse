//! Top-bar chrome view — identity capsule and tabs-button.
//! Both are floating glass pills right-aligned in the top bar area.
//!
//! The tabs-button is a self-contained canvas widget (no Subscription, no
//! per-frame Message). All hover state lives in `canvas::Program::State`
//! and the canvas requests exactly one repaint per enter/exit transition.

use iced::mouse;
use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke};
use iced::widget::{button, container, row, text, tooltip, Space};
use iced::{alignment, Color, Element, Length, Pixels, Point, Rectangle, Renderer, Theme};

use super::{TabBar, TabBarMsg};
use crate::design;
use crate::shell::Mode;

// ── Canvas tabs-button ────────────────────────────────────────────────────────

struct TabsCanvas {
    count: u32,
    palette: &'static crate::design::Palette,
}

#[derive(Default)]
struct HoverState {
    hovered: bool,
    pressed: bool,
}

impl canvas::Program<TabBarMsg> for TabsCanvas {
    type State = HoverState;

    fn update(
        &self,
        state: &mut Self::State,
        event: &iced::Event,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Option<canvas::Action<TabBarMsg>> {
        let hovered = cursor.is_over(bounds);
        let hover_changed = hovered != state.hovered;
        if hover_changed {
            state.hovered = hovered;
            if !hovered {
                state.pressed = false;
            }
        }

        let mut needs_redraw = hover_changed;
        let mut message: Option<TabBarMsg> = None;

        match event {
            iced::Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left))
                if hovered =>
            {
                state.pressed = true;
                needs_redraw = true;
            }
            iced::Event::Mouse(iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left))
                if state.pressed =>
            {
                state.pressed = false;
                message = Some(TabBarMsg::TabsGridPressed);
            }
            _ => {}
        }

        if let Some(msg) = message {
            // publish() always triggers a redraw internally.
            Some(canvas::Action::publish(msg))
        } else if needs_redraw {
            Some(canvas::Action::request_redraw())
        } else {
            None
        }
    }

    fn draw(
        &self,
        state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry<Renderer>> {
        let mut frame = Frame::new(renderer, bounds.size());
        let w = bounds.width;
        let h = bounds.height;
        let g = w.min(h);

        let [ik_r, ik_g, ik_b, _] = self.palette.icon_primary;
        let ink = Color::from_rgba(ik_r, ik_g, ik_b, 1.0);

        // Grid layout constants — shared between rest and hover scenes.
        let pad = g * 0.18;
        let gap = g * 0.10;
        let cell = (g - 2.0 * pad - gap) / 2.0;
        let cell_r = cell * 0.28;

        let center = Point::new(w / 2.0, h / 2.0);

        if state.hovered || state.pressed {
            // Hover / press: circular fill matching the + button, then the count
            // inside a single card shaped like one of the grid cells.
            let circle_r = (g - 1.0) / 2.0;
            let circle_path = Path::new(|b| {
                rounded_rect(b, 0.5, 0.5, w - 1.0, h - 1.0, circle_r);
            });
            let bg_alpha: f32 = if state.pressed { 0.20 } else { 0.12 };
            let [bh_r, bh_g, bh_b, _] = self.palette.button_hover;
            frame.fill(&circle_path, Color::from_rgba(bh_r, bh_g, bh_b, bg_alpha));

            // Card: inner area minus the same pad used by grid cells, so it
            // looks like "one cell expanded to fill the space".
            let card_path = Path::new(|b| {
                rounded_rect(b, pad, pad, g - 2.0 * pad, g - 2.0 * pad, cell_r * 1.8);
            });
            frame.fill(&card_path, Color::from_rgba(0.357, 0.553, 0.937, 0.22));
            frame.stroke(
                &card_path,
                Stroke::default().with_width(1.5).with_color(ink),
            );

            if self.count > 0 {
                frame.fill_text(canvas::Text {
                    content: self.count.to_string(),
                    position: center,
                    color: ink,
                    size: Pixels((g - 2.0 * pad) * 0.52),
                    align_x: iced::widget::text::Alignment::Center,
                    align_y: alignment::Vertical::Center,
                    ..Default::default()
                });
            }
        } else {
            // Rest: 2×2 grid, no outer border on the widget itself.
            let stroke = Stroke::default().with_width(1.5).with_color(ink);
            let cells = [
                (pad, pad),
                (pad + cell + gap, pad),
                (pad, pad + cell + gap),
                (pad + cell + gap, pad + cell + gap),
            ];
            for (i, (x, y)) in cells.into_iter().enumerate() {
                let path = Path::new(|b| rounded_rect(b, x, y, cell, cell, cell_r));
                if i == 0 {
                    // Top-left = active-tab hint.
                    frame.fill(&path, Color::from_rgba(0.357, 0.553, 0.937, 0.30));
                }
                frame.stroke(&path, stroke);
            }
        }

        vec![frame.into_geometry()]
    }

    fn mouse_interaction(
        &self,
        _state: &Self::State,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> mouse::Interaction {
        if cursor.is_over(bounds) {
            mouse::Interaction::Pointer
        } else {
            mouse::Interaction::default()
        }
    }
}

/// Rounded rectangle via primitive path ops — avoids version-specific helpers.
fn rounded_rect(b: &mut canvas::path::Builder, x: f32, y: f32, w: f32, h: f32, r: f32) {
    let r = r.min(w / 2.0).min(h / 2.0).max(0.0);
    b.move_to(Point::new(x + r, y));
    b.line_to(Point::new(x + w - r, y));
    b.quadratic_curve_to(Point::new(x + w, y), Point::new(x + w, y + r));
    b.line_to(Point::new(x + w, y + h - r));
    b.quadratic_curve_to(Point::new(x + w, y + h), Point::new(x + w - r, y + h));
    b.line_to(Point::new(x + r, y + h));
    b.quadratic_curve_to(Point::new(x, y + h), Point::new(x, y + h - r));
    b.line_to(Point::new(x, y + r));
    b.quadratic_curve_to(Point::new(x, y), Point::new(x + r, y));
    b.close();
}

// ── View ──────────────────────────────────────────────────────────────────────

impl TabBar {
    /// Tabs-button and identity capsule for the top-bar overlay.
    /// Shell places this in a Stack above the address bar (right-aligned).
    pub fn view_top_chrome(
        &self,
        palette: &'static crate::design::Palette,
    ) -> Element<'_, TabBarMsg> {
        let count = self.tabs.len();
        let [ar, ag, ab, _] = design::palette::ACCENT;
        let [sr, sg, sb, _] = design::palette::STRICT;

        let glass_tint = Color::from_rgba(
            palette.glass_tint[0],
            palette.glass_tint[1],
            palette.glass_tint[2],
            palette.glass_tint[3],
        );
        let [gbr, gbg, gbb, gba] = palette.button_border;
        let glass_border = Color::from_rgba(gbr, gbg, gbb, gba);

        // Must fit within TOP_BAR_HEIGHT_PX (36 px) — 28 px leaves 4 px margin each side.
        const PILL_BTN_SIZE: f32 = 28.0;

        let [bhr, bhg, bhb, bha] = palette.button_hover;
        let [tr, tg, tb, _] = palette.icon_primary;
        let pill_btn_style = move |_: &iced::Theme, status: button::Status| button::Style {
            background: match status {
                button::Status::Hovered => Some(iced::Background::Color(Color::from_rgba(
                    bhr, bhg, bhb, bha,
                ))),
                button::Status::Pressed => Some(iced::Background::Color(Color::from_rgba(
                    bhr,
                    bhg,
                    bhb,
                    bha * 1.5,
                ))),
                _ => None,
            },
            border: iced::Border {
                radius: 14.0.into(),
                color: Color::TRANSPARENT,
                width: 0.0,
            },
            text_color: Color::from_rgba(tr, tg, tb, 1.0),
            shadow: iced::Shadow::default(),
            snap: false,
        };

        let plus_btn: Element<'_, TabBarMsg> = chrome_tip(
            "New tab",
            button(
                container(
                    text("+")
                        .size(18.0)
                        .color(Color::from_rgba(tr, tg, tb, 1.0)),
                )
                .width(PILL_BTN_SIZE)
                .height(PILL_BTN_SIZE)
                .align_x(iced::alignment::Horizontal::Center)
                .align_y(iced::alignment::Vertical::Center),
            )
            .on_press(TabBarMsg::NewTabPressed)
            .width(PILL_BTN_SIZE)
            .height(PILL_BTN_SIZE)
            .padding(0)
            .style(pill_btn_style)
            .into(),
            palette,
        );

        // Canvas tabs-button: 2 redraws per hover cycle, zero subscriptions.
        let tabs_btn: Element<'_, TabBarMsg> = chrome_tip(
            "Tab card view",
            iced::widget::canvas(TabsCanvas {
                count: count as u32,
                palette,
            })
            .width(Length::Fixed(PILL_BTN_SIZE))
            .height(Length::Fixed(PILL_BTN_SIZE))
            .into(),
            palette,
        );

        let tabs_pill = container(
            row![plus_btn, tabs_btn]
                .align_y(iced::alignment::Vertical::Center)
                .spacing(design::space::S3), // 6 px gap between the two buttons
        )
        .height(Length::Fixed(design::layout::TOP_BAR_HEIGHT_PX))
        .align_y(iced::alignment::Vertical::Center)
        .padding(iced::Padding {
            top: 0.0,
            bottom: 0.0,
            left: design::space::S5,  // 10 px — left margin before + button
            right: design::space::S5, // 10 px — right margin after grid button
        })
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(glass_tint)),
            border: iced::Border {
                color: glass_border,
                width: 1.0,
                radius: design::radius::PILL_PX.into(),
            },
            ..Default::default()
        });

        // L41: capsule label is "strict" in Strict mode, never the profile name.
        let capsule_label = if self.mode == Mode::Strict {
            "strict".to_string()
        } else {
            self.profile_name.clone()
        };

        let dot_color = if self.mode == Mode::Strict {
            Color::from_rgba(sr, sg, sb, 1.0)
        } else {
            Color::from_rgba(ar, ag, ab, 1.0)
        };

        let dot: Element<'_, TabBarMsg> = container(Space::new())
            .width(7.0)
            .height(7.0)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(dot_color)),
                border: iced::Border {
                    radius: 3.5.into(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .into();

        let identity_capsule = container(
            row![
                dot,
                text(capsule_label)
                    .size(design::type_scale::BODY_SM_PX)
                    .color(Color::from_rgba(tr, tg, tb, 1.0)),
                text("\u{25be}")
                    .size(9.0)
                    .color(Color::from_rgba(tr, tg, tb, 0.6)),
            ]
            .align_y(iced::alignment::Vertical::Center)
            .spacing(design::space::S3),
        )
        .height(Length::Fixed(design::layout::TOP_BAR_HEIGHT_PX))
        .align_y(iced::alignment::Vertical::Center)
        .padding([0.0, design::space::S7])
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(glass_tint)),
            border: iced::Border {
                color: glass_border,
                width: 1.0,
                radius: design::radius::PILL_PX.into(),
            },
            ..Default::default()
        });

        row![
            Space::new().width(Length::Fill),
            tabs_pill,
            Space::new().width(design::space::S4),
            chrome_tip("Tab mode", identity_capsule.into(), palette),
            Space::new().width(design::space::S8),
        ]
        .align_y(iced::alignment::Vertical::Center)
        .height(Length::Fixed(design::layout::TOP_BAR_HEIGHT_PX))
        .into()
    }
}

fn chrome_tip<'a>(
    label: &'static str,
    el: Element<'a, TabBarMsg>,
    palette: &'static crate::design::Palette,
) -> Element<'a, TabBarMsg> {
    use iced::widget::{container, text};
    use iced::{Background, Border, Color, Gradient, Shadow, Vector};
    let [r, g, b, _] = palette.glass_tint;
    let [tr, tg, tb, _] = palette.text_primary;
    let bg = iced::gradient::Linear::new(iced::Radians(std::f32::consts::PI))
        .add_stop(0.0, Color::from_rgba(r, g, b, 0.86))
        .add_stop(1.0, Color::from_rgba(r, g, b, 0.82));
    let card = container(text(label).size(12.0).color(Color {
        r: tr,
        g: tg,
        b: tb,
        a: 1.0,
    }))
    .padding(iced::Padding {
        top: 5.0,
        right: 8.0,
        bottom: 5.0,
        left: 8.0,
    })
    .style(move |_| iced::widget::container::Style {
        background: Some(Background::Gradient(Gradient::Linear(bg))),
        border: Border {
            color: Color::from_rgba(1.0, 0.98, 0.94, 0.10),
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.45),
            offset: Vector::new(0.0, 6.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    });
    tooltip(el, card, tooltip::Position::Bottom)
        .gap(4.0)
        .delay(std::time::Duration::from_secs(1))
        .style(|_| iced::widget::container::Style::default())
        .into()
}
