//! Strict-tab-close warning modal view.
//! Rendered by the shell as a full-window Stack overlay when modal = Confirming(_).

use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Length};

use super::{StrictCloseModal, TabBar, TabBarMsg};
use crate::design;

impl TabBar {
    /// Returns the modal element when active, None when Hidden.
    /// Shell centers this in the main Stack over the full window.
    pub fn view_strict_close_modal(&self) -> Option<Element<'_, TabBarMsg>> {
        if self.modal == StrictCloseModal::Hidden {
            return None;
        }

        let [sr, sg, sb, _] = design::palette::STRICT;
        let terracotta = iced::Color::from_rgba(sr, sg, sb, 1.0);
        let text_primary = iced::Color::from_rgba(0.925, 0.929, 0.941, 1.0);
        let text_secondary = iced::Color::from_rgba(0.847, 0.851, 0.878, 1.0);

        let header = row![
            container(text("!").size(18.0).color(terracotta))
                .width(28.0)
                .height(28.0)
                .align_x(iced::alignment::Horizontal::Center)
                .align_y(iced::alignment::Vertical::Center)
                .style(move |_| container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        sr, sg, sb, 0.18,
                    ))),
                    border: iced::Border {
                        radius: design::radius::BUTTON_PX.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            text("Close this Strict session?")
                .size(design::type_scale::H2_PX)
                .color(text_primary),
        ]
        .align_y(iced::alignment::Vertical::Center)
        .spacing(design::space::S6);

        // L41: modal text is locked — Settings cannot soften this wording.
        let body1 = text(
            "This tab has unsaved input. Closing it will permanently discard everything you typed.",
        )
        .size(design::type_scale::BODY_PX)
        .color(text_secondary);

        let body2 = text(
            "Strict mode has no recovery. There is no \u{2018}reopen closed tab\u{2019} for \
             Strict sessions. If you need this data, copy it out first.",
        )
        .size(design::type_scale::BODY_PX)
        .color(text_secondary);

        let cancel_btn = button(
            text("Cancel")
                .size(design::type_scale::BODY_PX)
                .color(text_primary),
        )
        .on_press(TabBarMsg::StrictCloseCancelled)
        .padding([design::space::S3, design::space::S6])
        .style(move |_, _| button::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(
                1.0, 0.98, 0.94, 0.08,
            ))),
            border: iced::Border {
                color: iced::Color::from_rgba(1.0, 0.98, 0.94, 0.12),
                width: 1.0,
                radius: design::radius::BUTTON_PX.into(),
            },
            text_color: text_primary,
            shadow: iced::Shadow::default(),
            snap: false,
        });

        let confirm_btn = button(
            text("Close and discard")
                .size(design::type_scale::BODY_PX)
                .color(text_primary),
        )
        .on_press(TabBarMsg::StrictCloseConfirmed)
        .padding([design::space::S3, design::space::S6])
        .style(move |_, _| button::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(
                sr, sg, sb, 1.0,
            ))),
            border: iced::Border {
                radius: design::radius::BUTTON_PX.into(),
                ..Default::default()
            },
            text_color: text_primary,
            shadow: iced::Shadow::default(),
            snap: false,
        });

        let btn_row = row![
            Space::new().width(Length::Fill),
            cancel_btn,
            Space::new().width(design::space::S4),
            confirm_btn,
        ]
        .align_y(iced::alignment::Vertical::Center);

        let content = column![header, body1, body2, btn_row]
            .spacing(design::space::S6)
            .padding(design::space::S8);

        let modal = container(content)
            .width(460.0)
            .style(move |_| container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    design::palette::GLASS_TINT_DARK[0],
                    design::palette::GLASS_TINT_DARK[1],
                    design::palette::GLASS_TINT_DARK[2],
                    0.96,
                ))),
                border: iced::Border {
                    color: terracotta,
                    width: design::layout::STRICT_BORDER_PX,
                    radius: design::radius::PANEL_PX.into(),
                },
                ..Default::default()
            });

        Some(modal.into())
    }
}
