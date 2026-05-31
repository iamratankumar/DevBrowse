//! Top-bar chrome view — identity capsule and tabs-button.
//! Both are floating glass pills right-aligned in the top bar area.
//!
//! The tabs-button is a self-contained canvas widget (no Subscription, no
//! per-frame Message). All hover state lives in `canvas::Program::State`
//! and the canvas requests exactly one repaint per enter/exit transition.

use iced::mouse;
use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke};
use iced::widget::{button, container, row, text, Space};
use iced::{alignment, Color, Element, Length, Pixels, Point, Rectangle, Renderer, Theme};

use super::{TabBar, TabBarMsg};
use crate::design;
use crate::shell::Mode;

// ── Canvas tabs-button ────────────────────────────────────────────────────────

struct TabsCanvas {
    count: u32,
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

        let press_changed = match event {
            iced::Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left))
                if hovered =>
            {
                state.pressed = true;
                true
            }
            iced::Event::Mouse(iced::mouse::Event::ButtonReleased(iced::mouse::Button::Left))
                if state.pressed =>
            {
                state.pressed = false;
                true
            }
            _ => false,
        };

        if hover_changed || press_changed {
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

        let ink = Color::from_rgba(0.690, 0.706, 0.745, 1.0); // matches + button icon color

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
            frame.fill(&circle_path, Color::from_rgba(1.0, 0.98, 0.94, bg_alpha));

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
    pub fn view_top_chrome(&self) -> Element<'_, TabBarMsg> {
        let count = self.tabs.len();
        let [ar, ag, ab, _] = design::palette::ACCENT;
        let [sr, sg, sb, _] = design::palette::STRICT;

        let glass_tint = Color::from_rgba(
            design::palette::GLASS_TINT_DARK[0],
            design::palette::GLASS_TINT_DARK[1],
            design::palette::GLASS_TINT_DARK[2],
            design::palette::GLASS_TINT_DARK[3],
        );
        let glass_border = Color::from_rgba(1.0, 0.98, 0.94, 0.08);

        // Must fit within TOP_BAR_HEIGHT_PX (36 px) — 28 px leaves 4 px margin each side.
        const PILL_BTN_SIZE: f32 = 28.0;

        fn pill_btn_style(_: &iced::Theme, status: button::Status) -> button::Style {
            button::Style {
                background: match status {
                    button::Status::Hovered => Some(iced::Background::Color(Color::from_rgba(
                        1.0, 0.98, 0.94, 0.12,
                    ))),
                    button::Status::Pressed => Some(iced::Background::Color(Color::from_rgba(
                        1.0, 0.98, 0.94, 0.20,
                    ))),
                    _ => None,
                },
                border: iced::Border {
                    radius: 14.0.into(),
                    color: Color::TRANSPARENT,
                    width: 0.0,
                },
                text_color: Color::from_rgba(0.690, 0.706, 0.745, 1.0),
                shadow: iced::Shadow::default(),
                snap: false,
            }
        }

        let plus_btn: Element<'_, TabBarMsg> = button(
            container(
                text("+")
                    .size(18.0)
                    .color(Color::from_rgba(0.690, 0.706, 0.745, 1.0)),
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
        .into();

        // Canvas tabs-button: 2 redraws per hover cycle, zero subscriptions.
        let tabs_btn: Element<'_, TabBarMsg> = iced::widget::canvas(TabsCanvas {
            count: count as u32,
        })
        .width(Length::Fixed(PILL_BTN_SIZE))
        .height(Length::Fixed(PILL_BTN_SIZE))
        .into();

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
                    .color(Color::from_rgba(0.925, 0.929, 0.941, 1.0)),
                text("\u{25be}")
                    .size(9.0)
                    .color(Color::from_rgba(0.416, 0.424, 0.478, 1.0)),
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
            identity_capsule,
            Space::new().width(design::space::S8),
        ]
        .align_y(iced::alignment::Vertical::Center)
        .height(Length::Fixed(design::layout::TOP_BAR_HEIGHT_PX))
        .into()
    }
}
