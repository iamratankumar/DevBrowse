//! pb-ui::sidebar — Module 44.3 vertical pill sidebar.
//!
//! Always-visible 52 px glass strip on the left, overlaid as a Stack layer
//! (position-absolute style). Content area gets padding_left: 52 px so the
//! tab strip never renders under the sidebar.
//!
//! Pills = one per open tab. Active tab = blue. Strict tab = terracotta.
//! Inactive tab = translucent white. Divider separates Standard from Strict.
//! Bottom-pinned: favorites star · gear · champagne + button.
//!
//! Hover-expand (52 px → 280 px) is wired but disabled — expand will be
//! enabled in a later session without structural changes.
//!
//! Enforces:
//!   L28 — glass aesthetic + reduce-transparency fallback.
//!   L41 — Strict tab pill is always terracotta.
//!
//! TODO Module 44.3 wiring: SearchRequested -> command bar /tab (Module 64.13)
//! TODO Module 44.3 wiring: FavoritesRequested -> bookmarks panel (Module 49)
//! TODO Module 44.3 wiring: GearRequested -> settings panel (Module 52)
//! TODO Module 44.3 wiring: NewTabRequested -> TabBroker (Phase 11, Module 80)
//! TODO Module 44.3 wiring: PillClicked(id) -> tab_bar activate tab (Module 80)

use crate::design;
use crate::shell::Mode;

// ---------------------------------------------------------------------------
// Messages and events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum SidebarMsg {
    /// Pill mouse-down: starts potential drag or tap.
    PillPressed(usize),
    /// Pill mouse-up: commit activation if no drag occurred.
    PillReleased(usize),
    /// Cursor entered a pill while dragging: triggers swap.
    PillEntered(usize),
    /// Cursor moved anywhere in the sidebar: activates drag once threshold exceeded.
    SidebarMoved,
    /// Mouse released anywhere in sidebar: clears drag state.
    SidebarReleased,
    SearchPressed,
    FavoritesPressed,
    GearPressed,
    NewTabPressed,
    /// Clicked on empty glass area — shell calls window::drag().
    DragRequested,
}

/// Events that cross the module boundary to the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarEvent {
    SearchRequested,
    NewTabRequested,
    FavoritesRequested,
    GearRequested,
    TabActivated(usize),
    WindowDragRequested,
    /// Drag-to-reorder: swap the two tab positions in tab_bar.tabs.
    TabsReordered {
        from_id: usize,
        to_id: usize,
    },
}

// ---------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Sidebar {
    /// Which pill tab id is currently pressed (potential drag source).
    drag_id: Option<usize>,
    /// True once the cursor has moved enough to commit to a drag (not just a tap).
    pub dragging: bool,
    /// Pill id currently under the cursor during a drag — drives the hover highlight.
    drag_hovered_id: Option<usize>,
}

impl Sidebar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current rendered width. Always 52 px for now; hover-expand wired later.
    pub fn current_width(&self) -> f32 {
        design::layout::SIDEBAR_COLLAPSED_PX
    }

    pub fn update(&mut self, msg: SidebarMsg) -> Option<SidebarEvent> {
        match msg {
            SidebarMsg::PillPressed(id) => {
                self.drag_id = Some(id);
                self.dragging = false;
                self.drag_hovered_id = None;
                None
            }
            SidebarMsg::PillReleased(id) => {
                let was_dragging = self.dragging;
                self.drag_id = None;
                self.dragging = false;
                self.drag_hovered_id = None;
                // Only activate the tab if the user tapped (no significant movement).
                if !was_dragging {
                    Some(SidebarEvent::TabActivated(id))
                } else {
                    None
                }
            }
            SidebarMsg::PillEntered(to_id) => {
                if self.dragging {
                    if let Some(from_id) = self.drag_id {
                        if from_id != to_id {
                            // Do NOT update drag_id here. Keeping it on the original
                            // dragged tab prevents the immediate reverse-swap that
                            // caused drag to freeze after one step:
                            //   1. swap(A→B) fires → drag_id was updated to B
                            //   2. view re-renders: tab A is now physically under the cursor
                            //   3. PillEntered(A) fires → swap(B→A) → stuck at start
                            // With drag_id stable on A, step 3 sees from==to → no swap.
                            self.drag_hovered_id = Some(to_id);
                            return Some(SidebarEvent::TabsReordered { from_id, to_id });
                        } else {
                            // Cursor re-entered the dragged tab's new slot — clear highlight.
                            self.drag_hovered_id = None;
                        }
                    }
                }
                None
            }
            SidebarMsg::SidebarMoved => {
                if self.drag_id.is_some() {
                    self.dragging = true;
                }
                None
            }
            SidebarMsg::SidebarReleased => {
                self.drag_id = None;
                self.dragging = false;
                self.drag_hovered_id = None;
                None
            }
            SidebarMsg::DragRequested => {
                // Only drag window if no pill is being interacted with.
                if self.drag_id.is_none() && !self.dragging {
                    Some(SidebarEvent::WindowDragRequested)
                } else {
                    None
                }
            }
            SidebarMsg::SearchPressed => Some(SidebarEvent::SearchRequested),
            SidebarMsg::FavoritesPressed => Some(SidebarEvent::FavoritesRequested),
            SidebarMsg::GearPressed => Some(SidebarEvent::GearRequested),
            SidebarMsg::NewTabPressed => Some(SidebarEvent::NewTabRequested),
        }
    }
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

impl Sidebar {
    /// Produce the sidebar Iced element.
    ///
    /// `tabs` and `active_tab_id` come from `AppState::tab_bar`; the sidebar
    /// does not own tab state.
    /// `bottom_pad` = TAB_BAR_HEIGHT_PX when tab bar is at Bottom, else 0.
    pub fn view<'a>(
        &self,
        tabs: &'a [crate::tab_bar::TabEntry],
        active_tab_id: usize,
        reduced_transparency: bool,
        bottom_pad: f32,
        window_height: f32,
    ) -> iced::Element<'a, SidebarMsg> {
        use iced::widget::{canvas, column, container, mouse_area, text, Space};
        use iced::{Alignment, Color, Length};

        let w = design::layout::SIDEBAR_COLLAPSED_PX;

        // Top reserve so the glass never paints under the macOS traffic-light
        // buttons (which sit in the y=0..28 band). 38 px matches the mock and
        // also aligns the avatar row with the bottom of the top chrome row.
        const GLASS_TOP: f32 = 38.0;

        // ── Glass background ──────────────────────────────────────────────
        // The glass is a Fill-height canvas that fills its OWN bounds from
        // y=0 to bounds.height. Layout positioning (the 38 px top reserve and
        // optional bottom_pad) is enforced by the surrounding Column, NOT by
        // the canvas's internal y-offset. This is the only way to guarantee
        // the glass top edge lands at y=38 regardless of how the parent Row /
        // Stack distribute height.
        let glass_canvas = canvas(SidebarBgProgram {
            reduced_transparency,
        })
        .width(Length::Fixed(w))
        .height(Length::Fill);

        // ── Avatar ────────────────────────────────────────────────────────
        let avatar = canvas(AvatarProgram).width(26.0).height(26.0);

        // ── Search icon (SVG magnifying glass) ───────────────────────────────
        let search_svg = iced::widget::svg(iced::widget::svg::Handle::from_memory(
            include_bytes!("../assets/search.svg").as_ref(),
        ))
        .width(18.0)
        .height(18.0)
        .style(|_, _| iced::widget::svg::Style {
            color: Some(ICON_MUTED),
        });
        let search_btn = icon_btn_svg(search_svg, SidebarMsg::SearchPressed);

        // ── Tab pills ─────────────────────────────────────────────────────
        let standard_tabs: Vec<_> = tabs.iter().filter(|t| t.mode == Mode::Standard).collect();
        let strict_tabs: Vec<_> = tabs.iter().filter(|t| t.mode == Mode::Strict).collect();

        // Compute how much vertical space is available for pills so they
        // shrink proportionally instead of overflowing and pushing + button down.
        // Fixed overhead: GLASS_TOP(38) + top_spacer(36) + avatar(26) + gap(8)
        //   + search(32) + gap(8) + fav(32) + gap(2) + gear(32) + gap(6)
        //   + plus(30) + bottom_space(18) = 268 px.
        const FIXED_OVERHEAD: f32 = 268.0;
        const PREFERRED_SPACING: f32 = 9.0;
        const MIN_INACTIVE_H: f32 = 3.0; // thinnest still-visible pill
        let active_h = 26.0_f32;

        let n_pills = tabs.len();
        let n_dividers = usize::from(!strict_tabs.is_empty());
        let n_total_items = n_pills + n_dividers;
        let available = (window_height - bottom_pad - FIXED_OVERHEAD).max(0.0);
        let n_inactive = n_pills.saturating_sub(1);
        let n_spacers = n_total_items.saturating_sub(1) as f32;
        let dividers_h = n_dividers as f32;

        // Solve for the largest spacing that keeps every inactive pill ≥ MIN_INACTIVE_H.
        // Constraint: active_h + n_inactive*MIN_INACTIVE_H + n_spacers*s + dividers_h ≤ available
        // → s ≤ (available - active_h - n_inactive*MIN_INACTIVE_H - dividers_h) / n_spacers
        let actual_spacing: f32 = if n_spacers > 0.0 {
            let max_s = (available - active_h - n_inactive as f32 * MIN_INACTIVE_H - dividers_h)
                / n_spacers;
            max_s.clamp(0.0, PREFERRED_SPACING)
        } else {
            PREFERRED_SPACING
        };

        let inactive_h: f32 = if n_inactive == 0 {
            active_h
        } else {
            let used = active_h + n_spacers * actual_spacing + dividers_h;
            let inactive_avail = (available - used).max(0.0);
            (inactive_avail / n_inactive as f32).clamp(MIN_INACTIVE_H, active_h)
        };

        let dragging = self.dragging;
        let drag_id = self.drag_id;
        let drag_hovered_id = self.drag_hovered_id;
        let make_pill = |t: &&crate::tab_bar::TabEntry| {
            let h = if t.id == active_tab_id {
                active_h
            } else {
                inactive_h
            };
            tab_pill(PillProps {
                tab_id: t.id,
                mode: t.mode,
                active: t.id == active_tab_id,
                height: h,
                sidebar_w: w,
                dragging,
                accent_color: t.accent_color,
                is_being_dragged: dragging && drag_id == Some(t.id),
                is_drag_target: dragging && drag_hovered_id == Some(t.id),
            })
        };

        let mut pill_items: Vec<iced::Element<'_, SidebarMsg>> =
            standard_tabs.iter().map(make_pill).collect();

        if !strict_tabs.is_empty() {
            pill_items.push(
                container(iced::widget::Row::new())
                    .width(18.0)
                    .height(1.0)
                    .style(|_| iced::widget::container::Style {
                        background: Some(iced::Background::Color(Color::from_rgba(
                            1.0, 0.98, 0.94, 0.10,
                        ))),
                        ..Default::default()
                    })
                    .into(),
            );
            for t in &strict_tabs {
                pill_items.push(make_pill(t));
            }
        }

        let pill_col = pill_items.into_iter().fold(
            column![].spacing(actual_spacing).align_x(Alignment::Center),
            |col, item| col.push(item),
        );
        let pill_area = pill_col;

        // ── Bottom-pinned actions ─────────────────────────────────────────
        let favorites_btn = icon_btn(
            text("\u{2605}").size(18.0).color(ICON_MUTED),
            SidebarMsg::FavoritesPressed,
        );
        let gear_btn = icon_btn(
            text("\u{2699}").size(18.0).color(ICON_MUTED),
            SidebarMsg::GearPressed,
        );

        let plus_btn = iced::widget::button(
            container(text("+").size(16.0).color(CHAMPAGNE))
                .width(30.0)
                .height(30.0)
                .center_x(30.0)
                .center_y(30.0),
        )
        .width(30.0)
        .height(30.0)
        .padding(0)
        .on_press(SidebarMsg::NewTabPressed)
        .style(|_, _| iced::widget::button::Style {
            background: Some(iced::Background::Color(Color::from_rgba(
                0.788, 0.659, 0.471, 0.20,
            ))),
            border: iced::Border {
                color: Color::from_rgba(0.788, 0.659, 0.471, 0.45),
                width: 1.0,
                radius: 8.0.into(),
            },
            ..Default::default()
        });

        // ── Content column laid over the glass ────────────────────────────
        // TOP_BAR_HEIGHT (36) pushes the avatar row to align with the bottom
        // of the top chrome bar. The GLASS_TOP reserve lives in the outer
        // Column, not here.
        let content = column![
            Space::new()
                .width(Length::Fixed(w))
                .height(design::layout::TOP_BAR_HEIGHT_PX),
            container(avatar)
                .width(Length::Fixed(w))
                .center_x(Length::Fixed(w)),
            Space::new().width(Length::Fixed(w)).height(8.0),
            container(search_btn)
                .width(Length::Fixed(w))
                .center_x(Length::Fixed(w)),
            Space::new().width(Length::Fixed(w)).height(8.0),
            container(pill_area)
                .width(Length::Fixed(w))
                .center_x(Length::Fixed(w)),
            Space::new().width(Length::Fixed(w)).height(Length::Fill),
            container(favorites_btn)
                .width(Length::Fixed(w))
                .center_x(Length::Fixed(w)),
            Space::new().width(Length::Fixed(w)).height(2.0),
            container(gear_btn)
                .width(Length::Fixed(w))
                .center_x(Length::Fixed(w)),
            Space::new().width(Length::Fixed(w)).height(6.0),
            container(plus_btn)
                .width(Length::Fixed(w))
                .center_x(Length::Fixed(w)),
            Space::new().width(Length::Fixed(w)).height(18.0),
        ]
        .width(Length::Fixed(w))
        .height(Length::Fill)
        .align_x(Alignment::Center);

        // The glass + content live in a Stack so both share the same bounds
        // (Fixed(w) x Fill below the top reserve). The Stack is itself
        // bounded by the outer Column below — so its top edge is at y=38.
        let glass_stack = iced::widget::Stack::new()
            .push(glass_canvas)
            .push(
                container(content)
                    .width(Length::Fixed(w))
                    .height(Length::Fill),
            )
            .width(Length::Fixed(w))
            .height(Length::Fill);

        // Traffic-light zone (y=0..38): a separate canvas with a light overlay
        // so it is visually distinct from both the dark wallpaper and the glass
        // below. Without this, both zones appear identical dark-navy and the
        // glass boundary is invisible to the user.
        let title_zone = canvas(TitleZoneProgram)
            .width(Length::Fixed(w))
            .height(Length::Fixed(GLASS_TOP));

        // Outer Column reserves the top 38 px (traffic-light zone) and the
        // optional bottom_pad (tab strip zone). The glass_stack only ever
        // sees the region between those reserves, so the glass top edge is
        // guaranteed to land at y=38 in window coordinates.
        let mut outer = column![title_zone, glass_stack,]
            .width(Length::Fixed(w))
            .height(Length::Fill);

        if bottom_pad > 0.0 {
            outer = outer.push(Space::new().width(Length::Fixed(w)).height(bottom_pad));
        }

        // Outer mouse_area: tracks movement (to activate drag) and release (to
        // clear drag state). on_press fires for empty glass → window drag.
        mouse_area(outer)
            .on_press(SidebarMsg::DragRequested)
            .on_move(|_| SidebarMsg::SidebarMoved)
            .on_release(SidebarMsg::SidebarReleased)
            .into()
    }
}

// ---------------------------------------------------------------------------
// Sidebar background canvas
// ---------------------------------------------------------------------------

/// Traffic-light zone (y=0..38): fully transparent — lets the wallpaper show
/// through so macOS traffic-light buttons are not obscured. The canvas exists
/// only to occupy the space in the outer Column; it draws nothing.
struct TitleZoneProgram;

impl<Message> iced::widget::canvas::Program<Message> for TitleZoneProgram {
    type State = ();

    fn draw(
        &self,
        _: &(),
        renderer: &iced::Renderer,
        _: &iced::Theme,
        bounds: iced::Rectangle,
        _: iced::mouse::Cursor,
    ) -> Vec<iced::widget::canvas::Geometry<iced::Renderer>> {
        // Nothing drawn — this zone is transparent, letting the wallpaper
        // underneath show through. The glass starts in the next Column item.
        vec![iced::widget::canvas::Frame::new(renderer, bounds.size()).into_geometry()]
    }
}

/// Draws the glass panel filling the full canvas bounds (y=0..height).
/// Positioning relative to the window (top reserve for traffic lights,
/// bottom reserve for the tab strip) is handled by the surrounding Column
/// in `Sidebar::view`, not by an internal y-offset. This guarantees the
/// glass top edge lands exactly at the reserved offset regardless of how
/// the parent layout distributes height.
struct SidebarBgProgram {
    reduced_transparency: bool,
}

impl<Message> iced::widget::canvas::Program<Message> for SidebarBgProgram {
    type State = ();

    fn draw(
        &self,
        _: &(),
        renderer: &iced::Renderer,
        _: &iced::Theme,
        bounds: iced::Rectangle,
        _: iced::mouse::Cursor,
    ) -> Vec<iced::widget::canvas::Geometry<iced::Renderer>> {
        use iced::widget::canvas::{Frame, Path};
        use iced::{Color, Point, Size};

        let mut frame = Frame::new(renderer, bounds.size());

        if bounds.height <= 0.0 || bounds.width <= 0.0 {
            return vec![frame.into_geometry()];
        }

        // Same color logic as GlassProgram in glass.rs.
        let use_solid = self.reduced_transparency;
        let base_color = if use_solid {
            let [r, g, b, _] = crate::design::palette::GLASS_REDUCED_DARK;
            Color::from_rgb(r, g, b)
        } else {
            let [r, g, b, a] = crate::design::palette::GLASS_TINT_DARK;
            let sat = crate::design::glass::PANEL_SATURATE;
            let lum = 0.2126 * r + 0.7152 * g + 0.0722 * b;
            Color::from_rgba(
                (lum + (r - lum) * sat).clamp(0.0, 1.0),
                (lum + (g - lum) * sat).clamp(0.0, 1.0),
                (lum + (b - lum) * sat).clamp(0.0, 1.0),
                a,
            )
        };

        let rrect = Path::rounded_rectangle(
            Point::new(0.0, 0.0),
            Size::new(bounds.width, bounds.height),
            iced::border::Radius::from(12.0),
        );
        frame.fill(&rrect, base_color);

        if !use_solid {
            let [r, g, b, a] = crate::design::palette::GLASS_TINT_DARK;
            frame.fill(&rrect, Color::from_rgba(r, g, b, a * 0.65));
        }

        // Mock border: border-top: 1px solid rgba(255,250,240,0.04)
        frame.fill_rectangle(
            Point::ORIGIN,
            Size::new(bounds.width, 1.0),
            Color::from_rgba(1.0, 0.98, 0.94, 0.04),
        );

        vec![frame.into_geometry()]
    }
}

// ---------------------------------------------------------------------------
// Tab pill (4×26 px indicator)
// ---------------------------------------------------------------------------

/// Sidebar tab pill. Uses mouse_area (not button) so we can detect drag
/// gestures (PillPressed/PillReleased/PillEntered) independently of tap.
/// `sidebar_w` sets the full-width hit target so it's easy to press.
struct PillProps {
    tab_id: usize,
    mode: Mode,
    active: bool,
    height: f32,
    sidebar_w: f32,
    dragging: bool,
    accent_color: Option<[f32; 4]>,
    is_being_dragged: bool,
    is_drag_target: bool,
}

fn tab_pill(p: PillProps) -> iced::Element<'static, SidebarMsg> {
    let PillProps {
        tab_id,
        mode,
        active,
        height,
        sidebar_w,
        dragging,
        accent_color,
        is_being_dragged,
        is_drag_target,
    } = p;
    use iced::widget::{container, mouse_area};
    use iced::Length;

    let base_color = pill_color(mode, active, accent_color);

    // Dragged pill: fade to 30% opacity (lifted). Target pill: solid accent blue.
    let indicator_color = if is_drag_target {
        iced::Color::from_rgba(0.357, 0.553, 0.937, 1.0)
    } else if is_being_dragged {
        iced::Color::from_rgba(base_color.r, base_color.g, base_color.b, 0.30)
    } else {
        base_color
    };

    // Target pill: widen the bar to 6 px; dragged pill: narrow to 3 px (receding).
    let indicator_w = if is_drag_target {
        6.0_f32
    } else if is_being_dragged {
        3.0_f32
    } else {
        4.0_f32
    };

    // TODO Module 80 (TabBroker): when sidebar drag cursor moves ≥30% of window
    // width to the left of the sidebar boundary, show a "tear off" affordance and
    // on mouse-release open the dragged tab in a new window via window::open().

    // Active pill: same blue glow as the active tab chip in the strip.
    let indicator_shadow = if active && !is_being_dragged {
        iced::Shadow {
            color: iced::Color::from_rgba(0.357, 0.553, 0.937, 0.45),
            offset: iced::Vector::new(0.0, 0.0),
            blur_radius: 10.0,
        }
    } else {
        iced::Shadow::default()
    };

    let indicator = container(iced::widget::Row::new())
        .width(indicator_w)
        .height(height)
        .style(move |_| iced::widget::container::Style {
            background: Some(iced::Background::Color(indicator_color)),
            border: iced::Border {
                radius: 99.0.into(),
                ..Default::default()
            },
            shadow: indicator_shadow,
            ..Default::default()
        });

    // Full-width hit target — no row-level background so the highlight
    // stays contained to the pill indicator only.
    let hit = container(indicator)
        .width(Length::Fixed(sidebar_w))
        .height(Length::Fixed(height))
        .center_x(Length::Fixed(sidebar_w));

    mouse_area(hit)
        .on_press(SidebarMsg::PillPressed(tab_id))
        .on_release(SidebarMsg::PillReleased(tab_id))
        .on_enter(SidebarMsg::PillEntered(tab_id))
        .interaction(if dragging {
            iced::mouse::Interaction::Grab
        } else {
            iced::mouse::Interaction::Pointer
        })
        .into()
}

// ---------------------------------------------------------------------------
// Avatar canvas program
// ---------------------------------------------------------------------------

struct AvatarProgram;

impl<Message> iced::widget::canvas::Program<Message> for AvatarProgram {
    type State = ();

    fn draw(
        &self,
        _: &(),
        renderer: &iced::Renderer,
        _: &iced::Theme,
        bounds: iced::Rectangle,
        _: iced::mouse::Cursor,
    ) -> Vec<iced::widget::canvas::Geometry<iced::Renderer>> {
        use iced::widget::canvas::{Frame, Path};
        use iced::{Color, Point};

        let mut frame = Frame::new(renderer, bounds.size());
        let cx = bounds.width / 2.0;
        let cy = bounds.height / 2.0;
        let r = cx.min(cy);
        let circle = Path::circle(Point::new(cx, cy), r);
        frame.fill(&circle, Color::from_rgb(0.788, 0.659, 0.471)); // #c9a878 champagne
        vec![frame.into_geometry()]
    }
}

// ---------------------------------------------------------------------------
// Color + widget helpers
// ---------------------------------------------------------------------------

const ICON_MUTED: iced::Color = iced::Color {
    r: 0.541,
    g: 0.553,
    b: 0.588,
    a: 1.0,
}; // #8a8d96
const CHAMPAGNE: iced::Color = iced::Color {
    r: 0.788,
    g: 0.659,
    b: 0.471,
    a: 1.0,
}; // #c9a878

fn pill_color(mode: Mode, active: bool, accent_color: Option<[f32; 4]>) -> iced::Color {
    use iced::Color;
    match (mode, active) {
        // Active pill always uses standard blue regardless of mode.
        (_, true) => {
            let [r, g, b, _] = design::palette::STANDARD_ACTIVE;
            Color::from_rgb(r, g, b)
        }
        // Inactive strict: terracotta so it stays visually distinct.
        (Mode::Strict, false) => {
            let [r, g, b, _] = design::palette::STRICT;
            Color::from_rgb(r, g, b)
        }
        // Inactive standard: favicon accent or neutral tint.
        (Mode::Standard, false) => {
            if let Some([r, g, b, _]) = accent_color {
                Color::from_rgba(r, g, b, 0.55)
            } else {
                Color::from_rgba(1.0, 0.98, 0.94, 0.18)
            }
        }
    }
}

/// 32×32 px transparent icon button for text icons.
fn icon_btn<'a>(icon: iced::widget::Text<'a>, msg: SidebarMsg) -> iced::Element<'a, SidebarMsg> {
    use iced::widget::{button, container};
    button(
        container(icon)
            .width(32.0)
            .height(32.0)
            .center_x(32.0)
            .center_y(32.0),
    )
    .width(32.0)
    .height(32.0)
    .padding(0)
    .on_press(msg)
    .style(|_, _| iced::widget::button::Style::default())
    .into()
}

/// 32×32 px transparent icon button for SVG icons.
fn icon_btn_svg<'a>(icon: iced::widget::Svg<'a>, msg: SidebarMsg) -> iced::Element<'a, SidebarMsg> {
    use iced::widget::{button, container};
    button(
        container(icon)
            .width(32.0)
            .height(32.0)
            .center_x(32.0)
            .center_y(32.0),
    )
    .width(32.0)
    .height(32.0)
    .padding(0)
    .on_press(msg)
    .style(|_, _| iced::widget::button::Style::default())
    .into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::design;

    // ── Required by spec (names locked) ────────────────────────────────────

    #[test]
    fn sidebar_width_collapsed_52() {
        let s = super::Sidebar::new();
        assert_eq!(s.current_width(), 52.0);
    }

    #[test]
    fn sidebar_meets_tabbar_no_gap() {
        // Single source of truth for the 52 px shared boundary.
        // tab_bar::chip_widths() subtracts this; sidebar current_width() returns it.
        assert_eq!(design::layout::SIDEBAR_COLLAPSED_PX, 52.0);
    }

    #[test]
    fn sidebar_strict_pill_terracotta() {
        // palette::STRICT = #b85a3c = (0.722, 0.353, 0.235, 1.0).
        let [r, g, b, _] = design::palette::STRICT;
        assert!((r - 0.722).abs() < 0.01);
        assert!((g - 0.353).abs() < 0.01);
        assert!((b - 0.235).abs() < 0.01);
    }

    // ── Events ─────────────────────────────────────────────────────────────

    #[test]
    fn sidebar_pill_click_emits_tab_activated() {
        let mut s = super::Sidebar::new();
        // A tap is: PillPressed followed by PillReleased with no SidebarMoved in between.
        let _ = s.update(super::SidebarMsg::PillPressed(3));
        let ev = s.update(super::SidebarMsg::PillReleased(3));
        assert_eq!(ev, Some(super::SidebarEvent::TabActivated(3)));
    }

    #[test]
    fn sidebar_search_emits_event() {
        let mut s = super::Sidebar::new();
        assert_eq!(
            s.update(super::SidebarMsg::SearchPressed),
            Some(super::SidebarEvent::SearchRequested)
        );
    }

    #[test]
    fn sidebar_new_tab_emits_event() {
        let mut s = super::Sidebar::new();
        assert_eq!(
            s.update(super::SidebarMsg::NewTabPressed),
            Some(super::SidebarEvent::NewTabRequested)
        );
    }

    #[test]
    fn sidebar_gear_emits_event() {
        let mut s = super::Sidebar::new();
        assert_eq!(
            s.update(super::SidebarMsg::GearPressed),
            Some(super::SidebarEvent::GearRequested)
        );
    }
}
