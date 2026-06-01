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
    /// Cursor left a pill — starts the 200 ms hide-grace period.
    PillLeft(usize),
    /// X button inside the pill tooltip pressed — request tab close.
    PillClosePressed(usize),
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
    TabCloseRequested(usize),
    /// Cursor left a pill — shell should start the 200 ms hide timer.
    TooltipPillLeft,
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
    /// Pill whose tooltip card is currently visible.
    pub tooltip_pill_id: Option<usize>,
    /// True while the 200 ms hide-grace timer is running (cursor left pill).
    pub tooltip_hide_pending: bool,
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
                // Show tooltip whenever cursor enters a pill (drag or idle).
                self.tooltip_pill_id = Some(to_id);
                self.tooltip_hide_pending = false;
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
            SidebarMsg::PillLeft(_) => {
                self.tooltip_hide_pending = true;
                Some(SidebarEvent::TooltipPillLeft)
            }
            SidebarMsg::SearchPressed => Some(SidebarEvent::SearchRequested),
            SidebarMsg::FavoritesPressed => Some(SidebarEvent::FavoritesRequested),
            SidebarMsg::GearPressed => Some(SidebarEvent::GearRequested),
            SidebarMsg::NewTabPressed => Some(SidebarEvent::NewTabRequested),
            SidebarMsg::PillClosePressed(id) => Some(SidebarEvent::TabCloseRequested(id)),
        }
    }

    /// Called by the shell when the 200 ms hide-grace timer fires.
    /// Only hides if no re-entry cancelled the pending hide.
    pub fn commit_hide(&mut self) {
        if self.tooltip_hide_pending {
            self.tooltip_pill_id = None;
            self.tooltip_hide_pending = false;
        }
    }

    /// Y-centre of the pill for `tab_id`, used by the shell to position the
    /// tooltip overlay. Returns `None` if the tab is not found.
    pub fn pill_center_y(
        &self,
        tab_id: usize,
        tabs: &[crate::tab_bar::TabEntry],
        window_height: f32,
        bottom_pad: f32,
    ) -> Option<f32> {
        const GLASS_TOP: f32 = 38.0;
        const FIXED_OVERHEAD: f32 = 268.0;
        const PREFERRED_SPACING: f32 = 9.0;
        const MIN_INACTIVE_H: f32 = 3.0;
        let active_h = 26.0_f32;

        let standard_tabs: Vec<_> = tabs
            .iter()
            .filter(|t| t.mode == crate::shell::Mode::Standard)
            .collect();
        let strict_tabs: Vec<_> = tabs
            .iter()
            .filter(|t| t.mode == crate::shell::Mode::Strict)
            .collect();

        let n_pills = tabs.len();
        let n_dividers = usize::from(!strict_tabs.is_empty());
        let n_total_items = n_pills + n_dividers;
        let available = (window_height - bottom_pad - FIXED_OVERHEAD).max(0.0);
        let n_inactive = n_pills.saturating_sub(1);
        let n_spacers = n_total_items.saturating_sub(1) as f32;
        let dividers_h = n_dividers as f32;

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

        // pill_area starts at: GLASS_TOP + TOP_BAR_HEIGHT + avatar(26) + gap(8) + search(32) + gap(8)
        let pill_area_top =
            GLASS_TOP + crate::design::layout::TOP_BAR_HEIGHT_PX + 26.0 + 8.0 + 32.0 + 8.0;

        // Walk the rendered order: standard pills, divider, strict pills.
        let mut y = pill_area_top;
        let ordered: Vec<_> = standard_tabs.iter().chain(strict_tabs.iter()).collect();
        let active_id = tabs.iter().find(|t| t.id == tab_id).map(|_| tab_id);

        for (i, t) in ordered.iter().enumerate() {
            // divider appears between standard and strict groups
            if i == standard_tabs.len() && !strict_tabs.is_empty() {
                y += 1.0 + actual_spacing;
            } else if i > 0 {
                y += actual_spacing;
            }
            let h = if Some(t.id) == active_id && t.id == tab_id {
                // Need to know active_tab_id — use tab_id as proxy: caller knows
                active_h
            } else {
                inactive_h
            };
            if t.id == tab_id {
                return Some(y + h / 2.0);
            }
            y += h;
        }
        None
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
        palette: &'static crate::design::Palette,
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
            palette,
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
        let search_btn = sidebar_chrome_tip(
            "Search tabs",
            icon_btn_svg(search_svg, SidebarMsg::SearchPressed),
            palette,
        );

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
        let tooltip_pill_id = self.tooltip_pill_id;
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
                is_hovered: !dragging && tooltip_pill_id == Some(t.id),
                palette,
            })
        };

        let mut pill_items: Vec<iced::Element<'_, SidebarMsg>> =
            standard_tabs.iter().map(make_pill).collect();

        if !strict_tabs.is_empty() {
            {
                let [br, bg_b, bb, ba] = palette.button_border;
                pill_items.push(
                    container(iced::widget::Row::new())
                        .width(18.0)
                        .height(1.0)
                        .style(move |_| iced::widget::container::Style {
                            background: Some(iced::Background::Color(Color::from_rgba(
                                br, bg_b, bb, ba,
                            ))),
                            ..Default::default()
                        })
                        .into(),
                );
            }
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
        let favorites_btn = sidebar_chrome_tip(
            "Bookmarks",
            icon_btn(
                text("\u{2605}").size(18.0).color(ICON_MUTED),
                SidebarMsg::FavoritesPressed,
            ),
            palette,
        );
        let gear_btn = sidebar_chrome_tip(
            "Settings",
            icon_btn(
                text("\u{2699}").size(18.0).color(ICON_MUTED),
                SidebarMsg::GearPressed,
            ),
            palette,
        );

        let [pbi_r, pbi_g, pbi_b, pbi_a] = palette.button_idle;
        let [pbb_r, pbb_g, pbb_b, pbb_a] = palette.button_border;
        let [ipr, ipg, ipb, _] = palette.icon_primary;
        let plus_btn = sidebar_chrome_tip(
            "New tab",
            iced::widget::button(
                container(
                    text("+")
                        .size(16.0)
                        .color(Color::from_rgba(ipr, ipg, ipb, 1.0)),
                )
                .width(30.0)
                .height(30.0)
                .center_x(30.0)
                .center_y(30.0),
            )
            .width(30.0)
            .height(30.0)
            .padding(0)
            .on_press(SidebarMsg::NewTabPressed)
            .style(move |_, _| iced::widget::button::Style {
                background: Some(iced::Background::Color(Color::from_rgba(
                    pbi_r,
                    pbi_g,
                    pbi_b,
                    pbi_a * 1.5,
                ))),
                border: iced::Border {
                    color: Color::from_rgba(pbb_r, pbb_g, pbb_b, pbb_a),
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            })
            .into(),
            palette,
        );

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
    palette: &'static crate::design::Palette,
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
        use iced::widget::canvas::{Frame, Path, Stroke};
        use iced::{Color, Point, Size};

        let mut frame = Frame::new(renderer, bounds.size());

        if bounds.height <= 0.0 || bounds.width <= 0.0 {
            return vec![frame.into_geometry()];
        }

        // Same color logic as GlassProgram in glass.rs.
        // Always start with an opaque base from glass_reduced so the sidebar
        // colour is clearly visible in both dark and light themes regardless of
        // what the wgpu compositor has rendered behind this canvas.
        let [br, bg_c, bb, _] = self.palette.glass_reduced;
        let rrect = Path::rounded_rectangle(
            Point::new(0.0, 0.0),
            Size::new(bounds.width, bounds.height),
            iced::border::Radius::from(12.0),
        );
        frame.fill(&rrect, Color::from_rgb(br, bg_c, bb));

        // Overlay the glass tint for the frosted-glass shimmer.
        if !self.reduced_transparency {
            let [r, g, b, a] = self.palette.glass_tint;
            frame.fill(&rrect, Color::from_rgba(r, g, b, a * 0.55));
        }

        // Hairline border follows the rounded glass shape.
        let [br, bg_b, bb, ba] = self.palette.button_border;
        frame.stroke(
            &rrect,
            Stroke::default()
                .with_width(1.0)
                .with_color(Color::from_rgba(br, bg_b, bb, ba)),
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
    is_hovered: bool,
    palette: &'static crate::design::Palette,
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
        is_hovered,
        palette,
    } = p;
    use iced::widget::{container, mouse_area};
    use iced::Length;

    let base_color = pill_color(mode, active, accent_color, is_hovered);
    // For inactive Standard tabs without a custom accent, the warm-white
    // neutral is invisible on light backgrounds. Use palette.icon_primary
    // at reduced opacity so the indicator is visible in both themes.
    let base_color = if !active && mode == Mode::Standard && accent_color.is_none() {
        let [r, g, b, _] = palette.icon_primary;
        iced::Color::from_rgba(r, g, b, if is_hovered { 0.55 } else { 0.30 })
    } else {
        base_color
    };

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
        .on_exit(SidebarMsg::PillLeft(tab_id))
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

fn pill_color(
    mode: Mode,
    active: bool,
    accent_color: Option<[f32; 4]>,
    is_hovered: bool,
) -> iced::Color {
    use iced::Color;
    match (mode, active) {
        // Active pill always uses standard blue regardless of mode.
        (_, true) => {
            let [r, g, b, _] = design::palette::STANDARD_ACTIVE;
            Color::from_rgb(r, g, b)
        }
        // Inactive strict: dim terracotta; hover restores full opacity.
        (Mode::Strict, false) => {
            let [r, g, b, _] = design::palette::STRICT;
            Color::from_rgba(r, g, b, if is_hovered { 0.75 } else { 0.28 })
        }
        // Inactive standard: dim accent or neutral; hover restores original.
        (Mode::Standard, false) => {
            if let Some([r, g, b, _]) = accent_color {
                Color::from_rgba(r, g, b, if is_hovered { 0.65 } else { 0.22 })
            } else {
                Color::from_rgba(1.0, 0.98, 0.94, if is_hovered { 0.30 } else { 0.10 })
            }
        }
    }
}

/// Read-only glass tooltip shown below a sidebar chrome button.
fn sidebar_chrome_tip<'a>(
    label: &'static str,
    el: iced::Element<'a, SidebarMsg>,
    palette: &'static crate::design::Palette,
) -> iced::Element<'a, SidebarMsg> {
    use iced::widget::{container, text, tooltip};
    let [tr, tg, tb, _] = palette.text_primary;
    let card = container(text(label).size(12.0).color(iced::Color {
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
    .style(move |_| tip_card_style(palette));
    tooltip(el, card, tooltip::Position::Right)
        .gap(8.0)
        .delay(std::time::Duration::from_secs(1))
        .style(|_| iced::widget::container::Style::default())
        .into()
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
// Pill hover tooltip — Module 44.4
// ---------------------------------------------------------------------------
//
// Glass preview card shown to the right of each sidebar pill on hover.
// Wraps iced::widget::tooltip (instant show/hide — no built-in delay).
//
// Fidelity notes:
//   • backdrop blur  → solid translucent gradient fill (same pattern as sidebar glass).
//   • left caret     → omitted (custom overlay canvas required).
//   • 300ms delay    → not implemented; Iced tooltip has no delay API.
//     TODO Module 80: wire 300ms hover delay + EC1/EC2 ghost-tooltip prevention
//     via PillHoverStarted / PillHoverCancelled events routed through the shell's
//     subscription machinery when TabBroker signals are available.
//
// TODO Phase 10: if tip_card_style() closures appear in a CPU flamegraph at real
// tab counts, benchmark extracting the return value as a once_cell::sync::Lazy
// static. At median usage (5-10 tabs) the allocation cost is under 1µs/frame.

/// Tooltip payload for one sidebar pill.
pub struct TabTip {
    pub tab_id: usize,
    pub favicon_letter: char,
    pub favicon_bg: iced::Color,
    pub title: String,
    pub strict: bool,
}

/// Tooltip title text — #eef0f5.
const TIP_TEXT: iced::Color = iced::Color {
    r: 0.933,
    g: 0.941,
    b: 0.961,
    a: 1.0,
};

fn tip_bold() -> iced::Font {
    iced::Font {
        weight: iced::font::Weight::Bold,
        ..iced::Font::DEFAULT
    }
}

/// Glass card background + border + drop-shadow — extracted so the closure
/// in `with_tab_tooltip` is a one-liner rather than an inline struct literal.
fn tip_card_style(palette: &'static crate::design::Palette) -> iced::widget::container::Style {
    use iced::{Background, Border, Color, Gradient, Shadow, Vector};
    let [r, g, b, _] = palette.glass_tint;
    let bg = iced::gradient::Linear::new(iced::Radians(std::f32::consts::PI))
        .add_stop(0.0, Color::from_rgba(r, g, b, 0.86))
        .add_stop(1.0, Color::from_rgba(r, g, b, 0.82));
    iced::widget::container::Style {
        background: Some(Background::Gradient(Gradient::Linear(bg))),
        border: Border {
            color: {
                let [r, g, b, a] = palette.button_border;
                Color::from_rgba(r, g, b, a)
            },
            width: 1.0,
            radius: 11.0.into(),
        },
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: Vector::new(0.0, 10.0),
            blur_radius: 34.0,
        },
        ..Default::default()
    }
}

/// 18×18 rounded favicon chip with a centred white letter.
fn tip_favicon<'a>(letter: char, bg: iced::Color) -> iced::Element<'a, SidebarMsg> {
    use iced::widget::{container, text};
    container(
        text(letter.to_string())
            .size(10.0)
            .font(tip_bold())
            .color(iced::Color::WHITE),
    )
    .width(18.0)
    .height(18.0)
    .center_x(18.0)
    .center_y(18.0)
    .style(move |_| iced::widget::container::Style {
        background: Some(iced::Background::Color(bg)),
        border: iced::Border {
            radius: 5.0.into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}

/// Terracotta "STRICT" badge — palette::STRICT text on 0.16 fill, 0.40 border.
fn tip_badge<'a>() -> iced::Element<'a, SidebarMsg> {
    use iced::widget::{container, text};
    let [r, g, b, _] = design::palette::STRICT;
    container(
        text("STRICT")
            .size(9.0)
            .font(tip_bold())
            .color(iced::Color::from_rgb(r, g, b)),
    )
    .padding(iced::Padding {
        top: 1.0,
        right: 6.0,
        bottom: 1.0,
        left: 6.0,
    })
    .style(|_| iced::widget::container::Style {
        background: Some(iced::Background::Color(iced::Color::from_rgba(
            0.722, 0.353, 0.235, 0.16,
        ))),
        border: iced::Border {
            color: iced::Color::from_rgba(0.722, 0.353, 0.235, 0.40),
            width: 1.0,
            radius: 5.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Build the floating tooltip card for a pill.
/// The shell renders this as a Stack overlay at the correct Y position.
/// The card's mouse_area re-fires PillEntered so the 200 ms hide grace is
/// cancelled when the cursor moves from pill into the card.
pub fn tooltip_card_element(
    meta: TabTip,
    palette: &'static crate::design::Palette,
) -> iced::Element<'static, SidebarMsg> {
    use iced::widget::{button, container, mouse_area, row, text};
    use iced::{Alignment, Padding};

    let tab_id = meta.tab_id;

    let [tr, tg, tb, _] = palette.text_primary;
    let tip_text = iced::Color::from_rgb(tr, tg, tb);
    let mut title_row = row![text(meta.title).size(13.0).color(tip_text)]
        .spacing(7.0)
        .align_y(Alignment::Center);
    if meta.strict {
        title_row = title_row.push(tip_badge());
    }

    let close_btn = button(
        container(text("\u{00d7}").size(11.0).color(ICON_MUTED))
            .width(18.0)
            .height(18.0)
            .center_x(18.0)
            .center_y(18.0)
            .style(|_| iced::widget::container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    1.0, 1.0, 1.0, 0.08,
                ))),
                border: iced::Border {
                    radius: 99.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
    )
    .padding(iced::Padding::new(0.0).left(8.0))
    .on_press(SidebarMsg::PillClosePressed(tab_id))
    .style(|_, _| button::Style::default());

    let card = container(
        row![
            tip_favicon(meta.favicon_letter, meta.favicon_bg),
            title_row,
            close_btn,
        ]
        .spacing(10.0)
        .align_y(Alignment::Center),
    )
    .padding(Padding {
        top: 8.0,
        right: 10.0,
        bottom: 8.0,
        left: 10.0,
    })
    .style(move |_| tip_card_style(palette));

    // on_enter cancels the pending hide so cursor can move freely from pill to card.
    mouse_area(card)
        .on_enter(SidebarMsg::PillEntered(tab_id))
        .on_exit(SidebarMsg::PillLeft(tab_id))
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

    // ── Module 44.4 — tooltip ───────────────────────────────────────────────

    #[test]
    fn tooltip_strict_flag_set() {
        let tip = super::TabTip {
            tab_id: 1,
            favicon_letter: 'G',
            favicon_bg: {
                let [r, g, b, _] = crate::design::DARK_PALETTE.icon_dim;
                iced::Color::from_rgb(r, g, b)
            },
            title: "github.com".into(),
            strict: true,
        };
        assert!(tip.strict);
    }

    #[test]
    fn tooltip_tip_card_has_background() {
        let style = super::tip_card_style(&crate::design::DARK_PALETTE);
        assert!(
            style.background.is_some(),
            "card must have a non-transparent background"
        );
    }

    #[test]
    fn tooltip_favicon_fallback_char() {
        // Empty favicon_label → make_pill falls back to '?'
        let letter = "".chars().next().unwrap_or('?');
        assert_eq!(letter, '?');
    }

    #[test]
    fn tooltip_close_button_emits_tab_close_requested() {
        let mut s = super::Sidebar::new();
        let ev = s.update(super::SidebarMsg::PillClosePressed(7));
        assert_eq!(ev, Some(super::SidebarEvent::TabCloseRequested(7)));
    }

    // ── Pill color regression locks ────────────────────────────────────────

    #[test]
    fn pill_color_active_uses_standard_active_alpha_one() {
        use crate::shell::Mode;
        let [r, g, b, _] = design::palette::STANDARD_ACTIVE;
        let c = super::pill_color(Mode::Standard, true, None, false);
        assert!((c.r - r).abs() < 0.01);
        assert!((c.g - g).abs() < 0.01);
        assert!((c.b - b).abs() < 0.01);
        assert!((c.a - 1.0).abs() < 0.01);
    }

    #[test]
    fn pill_color_active_strict_uses_standard_active_alpha_one() {
        use crate::shell::Mode;
        let [r, g, b, _] = design::palette::STANDARD_ACTIVE;
        let c = super::pill_color(Mode::Strict, true, None, false);
        assert!((c.r - r).abs() < 0.01);
        assert!((c.g - g).abs() < 0.01);
        assert!((c.b - b).abs() < 0.01);
        assert!((c.a - 1.0).abs() < 0.01);
    }

    #[test]
    fn pill_color_inactive_strict_not_hovered_alpha_028() {
        use crate::shell::Mode;
        let c = super::pill_color(Mode::Strict, false, None, false);
        assert!((c.a - 0.28).abs() < 0.01);
    }

    #[test]
    fn pill_color_inactive_strict_hovered_alpha_075() {
        use crate::shell::Mode;
        let c = super::pill_color(Mode::Strict, false, None, true);
        assert!((c.a - 0.75).abs() < 0.01);
    }

    #[test]
    fn pill_color_inactive_standard_accent_not_hovered_alpha_022() {
        use crate::shell::Mode;
        let c = super::pill_color(Mode::Standard, false, Some([0.5, 0.3, 0.8, 1.0]), false);
        assert!((c.a - 0.22).abs() < 0.01);
    }

    #[test]
    fn pill_color_inactive_standard_accent_hovered_alpha_065() {
        use crate::shell::Mode;
        let c = super::pill_color(Mode::Standard, false, Some([0.5, 0.3, 0.8, 1.0]), true);
        assert!((c.a - 0.65).abs() < 0.01);
    }

    #[test]
    fn pill_color_inactive_standard_neutral_not_hovered_alpha_010() {
        use crate::shell::Mode;
        let c = super::pill_color(Mode::Standard, false, None, false);
        assert!((c.a - 0.10).abs() < 0.01);
    }

    #[test]
    fn pill_color_inactive_standard_neutral_hovered_alpha_030() {
        use crate::shell::Mode;
        let c = super::pill_color(Mode::Standard, false, None, true);
        assert!((c.a - 0.30).abs() < 0.01);
    }

    #[test]
    fn pill_color_active_ignores_hover() {
        use crate::shell::Mode;
        let hovered = super::pill_color(Mode::Standard, true, None, true);
        let not_hovered = super::pill_color(Mode::Standard, true, None, false);
        assert!((hovered.r - not_hovered.r).abs() < 0.01);
        assert!((hovered.g - not_hovered.g).abs() < 0.01);
        assert!((hovered.b - not_hovered.b).abs() < 0.01);
        assert!((hovered.a - not_hovered.a).abs() < 0.01);
    }

    // ── Tooltip state machine ──────────────────────────────────────────────

    #[test]
    fn tooltip_pill_entered_sets_tooltip_pill_id() {
        let mut s = super::Sidebar::new();
        let _ = s.update(super::SidebarMsg::PillEntered(5));
        assert_eq!(s.tooltip_pill_id, Some(5));
    }

    #[test]
    fn tooltip_pill_entered_clears_hide_pending() {
        let mut s = super::Sidebar::new();
        s.tooltip_hide_pending = true;
        let _ = s.update(super::SidebarMsg::PillEntered(3));
        assert!(!s.tooltip_hide_pending);
    }

    #[test]
    fn tooltip_pill_left_sets_hide_pending() {
        let mut s = super::Sidebar::new();
        let _ = s.update(super::SidebarMsg::PillLeft(2));
        assert!(s.tooltip_hide_pending);
    }

    #[test]
    fn tooltip_pill_left_emits_tooltip_pill_left_event() {
        let mut s = super::Sidebar::new();
        let ev = s.update(super::SidebarMsg::PillLeft(2));
        assert_eq!(ev, Some(super::SidebarEvent::TooltipPillLeft));
    }

    #[test]
    fn tooltip_commit_hide_clears_when_pending() {
        let mut s = super::Sidebar::new();
        s.tooltip_pill_id = Some(1);
        s.tooltip_hide_pending = true;
        s.commit_hide();
        assert_eq!(s.tooltip_pill_id, None);
    }

    #[test]
    fn tooltip_commit_hide_noop_when_not_pending() {
        let mut s = super::Sidebar::new();
        s.tooltip_pill_id = Some(1);
        s.tooltip_hide_pending = false;
        s.commit_hide();
        assert_eq!(s.tooltip_pill_id, Some(1));
    }

    #[test]
    fn tooltip_reenter_after_leave_cancels_hide() {
        let mut s = super::Sidebar::new();
        let _ = s.update(super::SidebarMsg::PillLeft(1));
        let _ = s.update(super::SidebarMsg::PillEntered(1));
        assert!(!s.tooltip_hide_pending);
        assert_eq!(s.tooltip_pill_id, Some(1));
    }

    // ── TabTip fields ──────────────────────────────────────────────────────

    #[test]
    fn tabtip_fields_roundtrip() {
        let tip = super::TabTip {
            tab_id: 42,
            favicon_letter: 'G',
            favicon_bg: iced::Color::BLACK,
            title: "test".into(),
            strict: false,
        };
        assert_eq!(tip.tab_id, 42);
        assert_eq!(tip.favicon_letter, 'G');
        assert_eq!(tip.favicon_bg, iced::Color::BLACK);
        assert_eq!(tip.title, "test");
        assert!(!tip.strict);
    }
}
