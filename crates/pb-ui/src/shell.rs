//! pb-ui::shell — Module 42 Iced application root.
//!
//! Owns the top-level Iced application: window setup, opaque wallpaper
//! painter, traffic-light spacer, mode visual identity (Standard navy vs
//! Strict terracotta — see `mode-indicator.md`), theme manager, command bus,
//! and mount points for Modules 43-64.
//!
//! UX contract: `docs/design/modules/42.md`.
//! Pattern: `docs/design/patterns/mode-indicator.md`.
//!
//! Enforces:
//!   L3  — Iced wgpu desktop.
//!   L27 — opaque error display (`Display` never exposes paths or libxul errors).
//!   L28 — glass aesthetic + accessibility + reduce-transparency fallback.
//!   L41 — Strict identity non-customizable.
//!   L42 — Strict letterbox: warm-dark borders when window ≠ 200×100 grid.
//!   §3.1 — Standard→Strict conversion is in-place (same tab); product decision
//!           overrides the original "mode locked at creation" note. Strict→Standard
//!           remains forbidden (§3.6).
//!   §3.6 — no Strict-to-Standard transition.
//!
//! TODO Module 42 impl: wire tokio mpsc `CommandBus` through to Modules 43-64
//! mount points once those modules land. Subscribe to `window::close_events`
//! for Strict tear-down. Add `keyboard::on_key_press` subscription for
//! Cmd+Q / Cmd+N / Cmd+W etc. (Module 42 keyboard map in modules/42.md).

use std::sync::Arc;

use iced::widget::canvas::gradient as canvas_gradient;
use iced::{
    mouse,
    widget::{canvas, container, text, Canvas, Column},
    window, Color, Element, Length, Rectangle, Renderer, Size, Task, Theme,
};
use tokio::sync::mpsc;

use crate::design;
// VibrancyAdapter imported here for future wiring; shell queries it to decide
// whether to skip the in-app blur pass (Module 42 TODO item).
#[allow(unused_imports)]
use crate::vibrancy::VibrancyAdapter;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Browser operation mode. Locked at tab/window creation; never settable
/// after construction (§3.1). No Strict → Standard transition (§3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Standard privacy posture (Brave+/Firefox-ETP-115+ parity).
    Standard,
    /// Strict privacy posture (Tor/Mullvad+ parity). Terracotta visual identity.
    Strict,
}

/// Internal application lifecycle phase (docs/design/modules/42.md §State machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppPhase {
    /// Full wallpaper, no chrome yet. Transitions to `Ready` on profile load.
    Starting,
    /// Full chrome rendered.
    Ready,
    /// 600 ms Standard→Strict morph in progress (§3.6). No reverse transition.
    TransitioningMode,
    /// Window closing — saving Standard tab state, Strict state is discarded.
    Closing,
}

/// The full application state. All public fields are read-only to other
/// modules; mutations go through `Message` + `update()`.
#[derive(Debug)]
pub struct AppState {
    /// Current browsing mode for the active window.
    pub mode: Mode,
    /// Application lifecycle phase.
    pub phase: AppPhase,
    /// Active profile name — never logged (L27 opaque).
    profile_name: String,
    /// Open-tab count for the tabs-pill counter.
    pub tab_count: usize,
    /// Window width in logical pixels (updated on every resize event).
    pub window_width: f32,
    /// Window height in logical pixels (updated on every resize event).
    pub window_height: f32,
    /// Main window ID captured from the first resize event.
    pub window_id: Option<window::Id>,
    /// True when the window is in OS-level fullscreen.
    pub is_fullscreen: bool,
    /// OS `prefers-reduced-transparency` flag forwarded from the window event.
    /// When true, all `GlassPanel` surfaces use the solid fallback (§3.4).
    pub reduced_transparency: bool,
    /// OS `prefers-reduced-motion` flag. When true, mode morph duration = 0.
    pub reduced_motion: bool,
    /// Elapsed ms since a mode-convert morph started.
    morph_elapsed_ms: u32,
    /// Sends application-level commands to chrome module subscribers (Modules 43-64).
    pub command_tx: Arc<mpsc::Sender<ChromeCommand>>,
    /// Module 43 — address bar.
    pub address_bar: crate::address_bar::AddressBar,
    /// Module 44 — tab bar, identity capsule, tabs-pill.
    pub tab_bar: crate::tab_bar::TabBar,
    /// Module 44.3 — vertical pill sidebar.
    pub sidebar: crate::sidebar::Sidebar,
}

impl AppState {
    fn new(profile_name: String, command_tx: Arc<mpsc::Sender<ChromeCommand>>) -> Self {
        Self {
            mode: Mode::Standard,
            phase: AppPhase::Starting,
            profile_name,
            tab_count: 0,
            window_width: 1280.0,
            window_height: 800.0,
            window_id: None,
            is_fullscreen: false,
            reduced_transparency: false,
            reduced_motion: false,
            morph_elapsed_ms: 0,
            command_tx,
            address_bar: crate::address_bar::AddressBar::new_stub(Mode::Standard),
            tab_bar: {
                let mut tb = crate::tab_bar::TabBar::new(crate::tab_bar::TabBarPosition::Top);
                tb.sync_window(1280.0);
                tb
            },
            sidebar: crate::sidebar::Sidebar::new(),
        }
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Redacted profile label for screen-reader narration. Never exposes the
    /// raw profile path or id (L27).
    pub fn narration_label(&self) -> String {
        format!(
            "DevBrowse {} mode. Profile {}.",
            match self.mode {
                Mode::Standard => "Standard",
                Mode::Strict => "Strict",
            },
            self.profile_name,
        )
    }
}

/// Commands dispatched over the command bus to chrome modules (43-64).
#[derive(Debug, Clone)]
pub enum ChromeCommand {
    /// Notify all chrome modules that the mode has changed.
    ModeChanged(Mode),
    /// Notify that the active tab changed.
    ActiveTabChanged { tab_count: usize },
    /// Profile load complete — transition from `Starting` to `Ready`.
    ProfileLoaded,
    /// Profile load failed — fall back to wizard (Module 64).
    ProfileLoadFailed,
}

// ---------------------------------------------------------------------------
// Iced Message
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Message {
    /// Profile finished loading.
    ProfileLoaded(String),
    /// Profile load failed (opaque — error details stay out of Display, L27).
    ProfileLoadFailed,
    /// User initiated Standard→Strict conversion (§3.6 one-way).
    ConvertToStrict,
    /// Mode-morph animation tick (ms elapsed).
    MorphTick(u32),
    /// OS accessibility preference changed.
    ReducedTransparencyChanged(bool),
    ReducedMotionChanged(bool),
    /// Window is being closed.
    WindowCloseRequested,
    /// Window resized — captures the window ID on first fire.
    WindowResized(window::Id, Size),
    /// Custom traffic-light buttons (cross-platform, decorations: false).
    CloseWindow,
    MinimizeWindow,
    MaximizeWindow,
    /// Drag the frameless window by the title-bar strip.
    DragWindow,
    /// Address bar internal message (Module 43).
    AddressBar(crate::address_bar::AddressBarMsg),
    /// Tab bar internal message (Module 44).
    TabBar(crate::tab_bar::TabBarMsg),
    /// Sidebar internal message (Module 44.3).
    Sidebar(crate::sidebar::SidebarMsg),
    /// Global cursor position during a tab/sidebar drag (from the full-window
    /// capture layer). Allows dragging outside the widget's own mouse_area.
    GlobalDragMove(iced::Point),
    /// Mouse released anywhere in the window — ends any active drag.
    GlobalDragEnd,
    /// Fullscreen animation settled — apply corner_radius change.
    /// 200 ms grace period expired — hide tooltip if cursor didn't re-enter.
    HideTooltip,
    /// No-op used as a placeholder for mount points not yet connected.
    None,
}

// ---------------------------------------------------------------------------
// Boot / Update / View
// ---------------------------------------------------------------------------

fn boot() -> (AppState, Task<Message>) {
    let (tx, _rx) = mpsc::channel::<ChromeCommand>(64);
    let state = AppState::new("default".to_string(), Arc::new(tx));
    // Immediately emit a simulated profile-loaded message so the shell
    // transitions to Ready without blocking the event loop.
    // In Phase 11 the orchestrator (Module 80) drives this via IPC.
    let task = Task::done(Message::ProfileLoaded("default".to_string()));
    (state, task)
}

/// Sync `state.mode` (and address bar / tab bar display) to the currently
/// active tab's mode. Called whenever the active tab changes so the Strict
/// border, wallpaper, and badge always reflect the tab you're looking at.
fn sync_active_tab_mode(state: &mut AppState) {
    if let Some(tab) = state
        .tab_bar
        .tabs
        .iter()
        .find(|t| t.id == state.tab_bar.active_id)
    {
        let new_mode = tab.mode;
        if state.mode != new_mode {
            state.mode = new_mode;
            state.address_bar.sync_mode(new_mode);
            let pname = state.profile_name().to_string();
            state.tab_bar.sync_mode(new_mode, &pname);
        }
    }
}

/// Test helper: boot the app, transition to Ready, set a known 1440×900 window.
/// Only compiled under `#[cfg(test)]` — zero cost in production.
#[cfg(test)]
pub(crate) fn ready_state_for_test() -> AppState {
    let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
    let mut state = AppState::new("regression-user".to_string(), Arc::new(tx));
    let _ = update(&mut state, Message::ProfileLoaded("regression-user".to_string()));
    let _ = update(
        &mut state,
        Message::WindowResized(
            iced::window::Id::unique(),
            iced::Size::new(1440.0, 900.0),
        ),
    );
    state
}

pub(crate) fn update(state: &mut AppState, message: Message) -> Task<Message> {
    match message {
        Message::ProfileLoaded(name) => {
            state.profile_name = name;
            state.phase = AppPhase::Ready;
            let pname = state.profile_name().to_string();
            state.tab_bar.sync_mode(state.mode, &pname);
            let _ = state.command_tx.try_send(ChromeCommand::ProfileLoaded);
        }
        Message::ProfileLoadFailed => {
            // Fall back to Module 64 wizard. For now keep the Starting phase
            // so the wallpaper stays visible; Module 64 will overlay the wizard.
            let _ = state.command_tx.try_send(ChromeCommand::ProfileLoadFailed);
        }
        Message::ConvertToStrict => {
            if state.mode == Mode::Standard && state.phase == AppPhase::Ready {
                state.phase = AppPhase::TransitioningMode;
                state.morph_elapsed_ms = 0;
            }
            // No Strict→Standard branch. §3.6 forbids it.
        }
        Message::MorphTick(elapsed_ms) => {
            let target_ms = if state.reduced_motion {
                0
            } else {
                design::motion::MODE_CONVERT_MS
            };
            if state.phase == AppPhase::TransitioningMode {
                state.morph_elapsed_ms = elapsed_ms.min(target_ms);
                if state.morph_elapsed_ms >= target_ms {
                    state.mode = Mode::Strict;
                    state.phase = AppPhase::Ready;
                    state.address_bar.sync_mode(Mode::Strict);
                    let pname = state.profile_name().to_string();
                    state.tab_bar.sync_mode(Mode::Strict, &pname);
                    let _ = state
                        .command_tx
                        .try_send(ChromeCommand::ModeChanged(Mode::Strict));
                }
            }
        }
        Message::ReducedTransparencyChanged(v) => {
            state.reduced_transparency = v;
        }
        Message::ReducedMotionChanged(v) => {
            state.reduced_motion = v;
            state.address_bar.reduced_motion = v;
        }
        Message::WindowResized(id, size) => {
            state.window_id = Some(id);
            state.window_width = size.width;
            state.window_height = size.height;
            state.tab_bar.sync_window(size.width);
        }
        Message::CloseWindow => return iced::exit(),
        Message::MinimizeWindow => {
            if let Some(id) = state.window_id {
                return window::minimize(id, true);
            }
        }
        Message::MaximizeWindow => {
            if let Some(id) = state.window_id {
                state.is_fullscreen = !state.is_fullscreen;
                let mode = if state.is_fullscreen {
                    window::Mode::Fullscreen
                } else {
                    window::Mode::Windowed
                };
                return window::set_mode(id, mode);
            }
        }
        Message::DragWindow => {
            if let Some(id) = state.window_id {
                return window::drag(id);
            }
        }
        Message::WindowCloseRequested => {
            state.phase = AppPhase::Closing;
        }
        Message::AddressBar(ab_msg) => {
            let (event, task) = state.address_bar.update(ab_msg);
            if let Some(ev) = event {
                match ev {
                    crate::address_bar::AddressBarEvent::ConvertToStrictClicked => {
                        // In-place conversion: same tab becomes Strict immediately.
                        // §3.6: no reverse. MorphTick animation wired when timer
                        // subscription lands (post Phase 8).
                        if state.mode == Mode::Standard && state.phase == AppPhase::Ready {
                            state.mode = Mode::Strict;
                            state.address_bar.sync_mode(Mode::Strict);
                            let pname = state.profile_name().to_string();
                            state.tab_bar.sync_mode(Mode::Strict, &pname);
                            let _ = state
                                .command_tx
                                .try_send(ChromeCommand::ModeChanged(Mode::Strict));
                        }
                    }
                    crate::address_bar::AddressBarEvent::NavigationCommitted { .. } => {
                        // TODO Module 43 wiring: forward to pb-network NavigationBroker (Phase 11)
                    }
                    crate::address_bar::AddressBarEvent::NetworkViewerRequested => {
                        // TODO Module 43 wiring: ChromeCommand::OpenNetworkViewer (Module 60)
                    }
                }
            }
            return task.map(Message::AddressBar);
        }
        Message::TabBar(tb_msg) => {
            if let Some(event) = state.tab_bar.update(tb_msg) {
                match event {
                    crate::tab_bar::TabBarEvent::TabClosed(_id) => {
                        sync_active_tab_mode(state);
                        // TODO Module 44 wiring: notify pb-network::TabBroker (Phase 11, Module 80)
                    }
                    crate::tab_bar::TabBarEvent::NewTabRequested => {
                        // TODO Module 44 wiring: create new tab (Phase 11, Module 80)
                    }
                    crate::tab_bar::TabBarEvent::WindowDragRequested => {
                        if let Some(id) = state.window_id {
                            return window::drag(id);
                        }
                    }
                    crate::tab_bar::TabBarEvent::StabilizeRequested(gen) => {
                        // 400 ms from the *last* close. Each close stamps a new
                        // generation; stale timers from earlier closes are
                        // discarded when they fire with an outdated generation.
                        return iced::Task::perform(
                            async move {
                                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                                gen
                            },
                            |g| Message::TabBar(crate::tab_bar::TabBarMsg::StabilizeExpired(g)),
                        );
                    }
                }
            }
            // StripPressed activates a tab without emitting a TabBarEvent.
            // Sync unconditionally so switching tabs always updates the mode.
            sync_active_tab_mode(state);
        }
        Message::Sidebar(sb_msg) => {
            if let Some(ev) = state.sidebar.update(sb_msg) {
                match ev {
                    crate::sidebar::SidebarEvent::TabActivated(id) => {
                        let _ = state
                            .tab_bar
                            .update(crate::tab_bar::TabBarMsg::TabActivated(id));
                        sync_active_tab_mode(state);
                    }
                    crate::sidebar::SidebarEvent::NewTabRequested => {
                        let _ = state
                            .tab_bar
                            .update(crate::tab_bar::TabBarMsg::NewTabPressed);
                    }
                    crate::sidebar::SidebarEvent::SearchRequested => {
                        // TODO Module 44.3 wiring: command bar pre-filled /tab (Module 64.13)
                    }
                    crate::sidebar::SidebarEvent::FavoritesRequested => {
                        // TODO Module 44.3 wiring: bookmarks panel (Module 49)
                    }
                    crate::sidebar::SidebarEvent::GearRequested => {
                        // TODO Module 44.3 wiring: settings panel (Module 52)
                    }
                    crate::sidebar::SidebarEvent::WindowDragRequested => {
                        if let Some(id) = state.window_id {
                            return window::drag(id);
                        }
                    }
                    crate::sidebar::SidebarEvent::TabsReordered { from_id, to_id } => {
                        let fi = state.tab_bar.tabs.iter().position(|t| t.id == from_id);
                        let ti = state.tab_bar.tabs.iter().position(|t| t.id == to_id);
                        if let (Some(f), Some(t)) = (fi, ti) {
                            state.tab_bar.tabs.swap(f, t);
                        }
                    }
                    crate::sidebar::SidebarEvent::TabCloseRequested(id) => {
                        // TODO Module 80: route through TabBroker for Strict-close modal
                        // and renderer teardown. For now, remove the tab directly.
                        let _ = state
                            .tab_bar
                            .update(crate::tab_bar::TabBarMsg::TabCloseRequested(id));
                    }
                    crate::sidebar::SidebarEvent::TooltipPillLeft => {
                        return Task::perform(
                            async {
                                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            },
                            |_| Message::HideTooltip,
                        );
                    }
                }
            }
        }
        Message::HideTooltip => {
            state.sidebar.commit_hide();
        }
        Message::GlobalDragMove(pos) => {
            // Feed strip-local x into tab-bar drag while cursor is outside the strip.
            if state.tab_bar.drag_active {
                let local_x = (pos.x - design::layout::SIDEBAR_COLLAPSED_PX).max(0.0);
                let _ = state
                    .tab_bar
                    .update(crate::tab_bar::TabBarMsg::StripMoved(local_x));
            }
            // Sidebar: drag position tracked via PillEntered — no y update needed.
        }
        Message::GlobalDragEnd => {
            if state.tab_bar.drag_id.is_some() || state.tab_bar.drag_active {
                let _ = state
                    .tab_bar
                    .update(crate::tab_bar::TabBarMsg::StripReleased);
            }
        }
        Message::None => {}
    }
    Task::none()
}

pub(crate) fn view(state: &AppState) -> Element<'_, Message> {
    let corner_radius = if state.is_fullscreen { 0.0 } else { 12.0 };
    let wallpaper = wallpaper_canvas(state.mode, state.reduced_transparency, corner_radius)
        .width(Length::Fill)
        .height(Length::Fill);

    let strip = state
        .tab_bar
        .view_strip(state.window_width)
        .map(Message::TabBar);

    let sidebar_w = design::layout::SIDEBAR_COLLAPSED_PX;
    // Sidebar always extends to the window bottom regardless of tab bar position.
    // The strip only renders in the content column (x ≥ 52 px) so there is no
    // overlap with the sidebar column (x = 0–52 px).
    let sidebar_bottom_pad = 0.0_f32;

    // Sidebar: fixed 52 px column. The sidebar widget owns the 38 px top gap
    // (Space before the glass) so the glass never covers traffic-light buttons.
    // Row layout gives the Column a well-defined height = full window height,
    // making the Space + Fill distribution reliable.
    let sidebar = state
        .sidebar
        .view(
            &state.tab_bar.tabs,
            state.tab_bar.active_id,
            state.reduced_transparency,
            sidebar_bottom_pad,
            state.window_height,
        )
        .map(Message::Sidebar);

    // Content column: naturally starts at x=52 because of the Row sibling.
    let content_column = match state.tab_bar.position {
        crate::tab_bar::TabBarPosition::Bottom => Column::new()
            .width(Length::Fill)
            .height(Length::Fill)
            .push(traffic_light_spacer())
            .push(chrome_placeholder(state))
            .push(iced::widget::Space::new().height(Length::Fill))
            .push(strip),
        crate::tab_bar::TabBarPosition::Top => Column::new()
            .width(Length::Fill)
            .height(Length::Fill)
            .push(traffic_light_spacer())
            .push(chrome_placeholder(state)),
    };

    // Row: [sidebar 52px] | [content fills rest]
    // wallpaper sits in the Stack behind the Row so both sidebar glass and
    // content area are transparent over it. Explicit Fill width/height on the
    // Row is required: Iced's Row defaults to Length::Shrink for both axes,
    // and in a Stack the children inherit the Shrink-resolved limits unless
    // the Row asks for Fill itself. Without this, the sidebar's glass canvas
    // receives an undersized `bounds.height` and the glass appears clipped /
    // mis-positioned relative to the window.
    let main_row = iced::widget::Row::new()
        .push(
            container(sidebar)
                .width(Length::Fixed(sidebar_w))
                .height(Length::Fill),
        )
        .push(content_column)
        .width(Length::Fill)
        .height(Length::Fill);

    // Stack::new() defaults to Length::Shrink. The wallpaper Canvas has
    // Length::Fill x Length::Fill, but we set Stack dimensions explicitly to
    // make layout deterministic across Iced versions.
    let mut main_stack = iced::widget::Stack::new()
        .push(wallpaper)
        .push(main_row)
        .width(Length::Fill)
        .height(Length::Fill);

    if let Some(modal) = state.tab_bar.view_strict_close_modal() {
        main_stack = main_stack.push(
            container(modal.map(Message::TabBar))
                .width(Length::Fill)
                .height(Length::Fill)
                .align_x(iced::alignment::Horizontal::Center)
                .align_y(iced::alignment::Vertical::Center),
        );
    }

    // Strict border overlay — rendered ABOVE main_row so the 2 px terracotta
    // ring appears on top of the sidebar, not hidden beneath it. (L42)
    if state.mode == Mode::Strict {
        let [br, bg, bb, _] = design::palette::STRICT;
        let strict_color = Color::from_rgb(br, bg, bb);
        let corner = if state.is_fullscreen {
            0.0_f32
        } else {
            12.0_f32
        };
        main_stack = main_stack.push(
            container(
                iced::widget::Space::new()
                    .width(Length::Fill)
                    .height(Length::Fill),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_| iced::widget::container::Style {
                background: None,
                border: iced::Border {
                    color: strict_color,
                    width: design::layout::STRICT_BORDER_PX,
                    radius: corner.into(),
                },
                text_color: None,
                shadow: iced::Shadow::default(),
                snap: false,
            }),
        );
    }

    // Floating address-bar overlays — absolutely positioned so they never
    // affect layout of the tab bar or anything below (CSS position:absolute).
    let bar_width = state.window_width * 0.40;
    // top = traffic_light_spacer (38) + address bar (36) + gap (S2=4) = 78 px
    let popup_top = 38.0 + design::layout::TOP_BAR_HEIGHT_PX + design::space::S2;

    let badge_popup_visible =
        state.address_bar.badge.popover_open && !state.address_bar.badge.rows.is_empty();

    // Global drag capture: when a tab-bar or sidebar drag is active, push a
    // full-window mouse_area that tracks cursor movement and mouse-up
    // regardless of which widget is under the cursor. Without this, StripExited
    // or leaving the sidebar boundary ends the drag prematurely.
    // Only tab-bar drag needs global capture. Sidebar drag uses PillEntered
    // for swapping — the global capture's on_move would intercept those events
    // and break pill hover detection.
    let any_drag_active = state.tab_bar.drag_active;
    if any_drag_active {
        main_stack = main_stack.push(
            iced::widget::mouse_area(
                container(
                    iced::widget::Space::new()
                        .width(Length::Fill)
                        .height(Length::Fill),
                )
                .width(Length::Fill)
                .height(Length::Fill),
            )
            .on_move(Message::GlobalDragMove)
            .on_release(Message::GlobalDragEnd)
            .interaction(iced::mouse::Interaction::Grab),
        );
    }

    // Event blocker: when any floating popup is open, push a full-screen
    // mouse_area BELOW the popup but ABOVE the tab strip. This captures
    // cursor-moved events so the strip cannot update its hover/drag state
    // while the popup is visible. Clicking outside the popup closes it.
    // Blocker only for badge popup — clicking outside closes it.
    // Strict popup does NOT need a blocker: its chip button must remain
    // clickable through the Stack, and the popup has its own action button.
    if badge_popup_visible {
        let close_badge_msg: Message = if badge_popup_visible {
            Message::AddressBar(crate::address_bar::AddressBarMsg::Badge(
                crate::address_bar::BadgeEvent::PopoverClosed,
            ))
        } else {
            Message::None
        };
        main_stack = main_stack.push(
            iced::widget::mouse_area(
                container(
                    iced::widget::Space::new()
                        .width(Length::Fill)
                        .height(Length::Fill),
                )
                .width(Length::Fill)
                .height(Length::Fill),
            )
            .on_move(|_| Message::None)
            .on_press(close_badge_msg),
        );
    }

    // Pill hover tooltip overlay — positioned to the right of the 52 px sidebar.
    if let Some(tip_id) = state.sidebar.tooltip_pill_id {
        if let Some(tab) = state.tab_bar.tabs.iter().find(|t| t.id == tip_id) {
            let center_y = state.sidebar.pill_center_y(
                tip_id,
                &state.tab_bar.tabs,
                state.window_height,
                sidebar_bottom_pad,
            );
            if let Some(cy) = center_y {
                let favicon_bg = tab
                    .accent_color
                    .map(|[r, g, b, _]| iced::Color::from_rgb(r, g, b))
                    .unwrap_or(iced::Color::from_rgba(0.357, 0.384, 0.471, 0.8));
                let meta = crate::sidebar::TabTip {
                    tab_id: tip_id,
                    favicon_letter: tab.favicon_label.chars().next().unwrap_or('?'),
                    favicon_bg,
                    title: tab.title.clone(),
                    strict: tab.mode == Mode::Strict,
                };
                let card = crate::sidebar::tooltip_card_element(meta).map(Message::Sidebar);
                // card_height estimate: 34px (8+8 padding + 18 content).
                let card_h_half = 17.0_f32;
                let top = (cy - card_h_half).max(0.0);
                main_stack = main_stack.push(
                    container(card)
                        .padding(iced::Padding::new(0.0).top(top).left(sidebar_w + 12.0))
                        .width(Length::Fill)
                        .height(Length::Fill),
                );
            }
        }
    }

    if let Some(popup) = state.address_bar.view_strict_popup(bar_width) {
        main_stack = main_stack.push(
            container(popup.map(Message::AddressBar))
                .padding(iced::Padding::new(0.0).top(popup_top).left(sidebar_w))
                .width(Length::Fill)
                .center_x(Length::Fill)
                .height(Length::Shrink),
        );
    }

    if let Some(popup) = state.address_bar.view_badge_popover(bar_width) {
        main_stack = main_stack.push(
            container(popup.map(Message::AddressBar))
                .padding(iced::Padding::new(0.0).top(popup_top).left(sidebar_w))
                .width(Length::Fill)
                .center_x(Length::Fill)
                .height(Length::Shrink),
        );
    }

    main_stack = main_stack.push(title_drag_zone());
    main_stack = main_stack.push(traffic_lights_overlay());

    container(main_stack)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Invisible drag strip across the top of the frameless window.
/// Clicking and dragging here moves the window via window::drag().
fn title_drag_zone<'a>() -> Element<'a, Message> {
    use iced::widget::mouse_area;
    // Height matches traffic_light_spacer (38 px). Stops exactly at the address
    // bar top so the drag overlay does not intercept address-bar mouse events.
    const DRAG_H: f32 = 38.0;
    mouse_area(
        container(
            iced::widget::Space::new()
                .width(Length::Fill)
                .height(DRAG_H),
        )
        .width(Length::Fill),
    )
    .on_press(Message::DragWindow)
    .into()
}

/// Three colored circles matching the macOS traffic-light style.
/// Rendered identically on every OS (decorations: false).
fn traffic_lights_overlay<'a>() -> Element<'a, Message> {
    use iced::widget::container;
    use iced::{Color, Padding};

    let close = traffic_circle(Color::from_rgb(1.0, 0.373, 0.341), Message::CloseWindow);
    let min = traffic_circle(
        Color::from_rgb(0.996, 0.737, 0.180),
        Message::MinimizeWindow,
    );
    let max = traffic_circle(
        Color::from_rgb(0.157, 0.784, 0.251),
        Message::MaximizeWindow,
    );

    let row = iced::widget::Row::new()
        .push(close)
        .push(iced::widget::Space::new().width(8.0))
        .push(min)
        .push(iced::widget::Space::new().width(8.0))
        .push(max)
        .align_y(iced::alignment::Vertical::Center);

    container(row)
        .padding(Padding::new(0.0).top(14.0).left(14.0))
        .width(Length::Fill)
        .height(Length::Fill)
        .align_y(iced::alignment::Vertical::Top)
        .align_x(iced::alignment::Horizontal::Left)
        .into()
}

/// One 12×12 px circular button.
fn traffic_circle<'a>(color: iced::Color, msg: Message) -> Element<'a, Message> {
    use iced::widget::{button, container};
    button(container(iced::widget::Row::new()).width(12.0).height(12.0))
        .width(12.0)
        .height(12.0)
        .padding(0)
        .on_press(msg)
        .style(move |_, _| iced::widget::button::Style {
            background: Some(iced::Background::Color(color)),
            border: iced::Border {
                radius: 99.0.into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
}

fn title(state: &AppState) -> String {
    let mode_label = match state.mode {
        Mode::Standard => "Standard",
        Mode::Strict => "Strict",
    };
    format!("DevBrowse — {mode_label}")
}

fn theme(_state: &AppState) -> Theme {
    Theme::Dark
}

// ---------------------------------------------------------------------------
// Wallpaper canvas
// ---------------------------------------------------------------------------

/// Returns a `Canvas` widget that paints the mode-appropriate wallpaper
/// gradient. This is the lowest visual layer; glass chrome surfaces are
/// painted above it.
///
/// Standard: radial gradient centred slightly left of mid-window, deep navy.
/// Strict:   warmer terracotta-tinted gradient + 2 px terracotta border.
fn wallpaper_canvas(
    mode: Mode,
    reduced: bool,
    corner_radius: f32,
) -> Canvas<WallpaperProgram, Message> {
    Canvas::new(WallpaperProgram {
        mode,
        reduced_transparency: reduced,
        corner_radius,
    })
}

struct WallpaperProgram {
    mode: Mode,
    reduced_transparency: bool,
    /// 12 px when windowed (transparent corners produce rounded window),
    /// 0 in fullscreen (fills the display edge-to-edge).
    corner_radius: f32,
}

impl canvas::Program<Message> for WallpaperProgram {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry<Renderer>> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());

        // Rounded rectangle — 12 px in windowed mode, 0 px in fullscreen.
        // With transparent: true, pixels outside this path are transparent,
        // which lets the desktop show through the window corners.
        let radius = iced::border::Radius::from(self.corner_radius);
        let bg_path = canvas::Path::rounded_rectangle(iced::Point::ORIGIN, bounds.size(), radius);

        match self.mode {
            Mode::Standard => {
                if self.reduced_transparency {
                    // §3.4 solid fallback for Standard.
                    let [r, g, b, _] = design::palette::STANDARD_WALLPAPER_SOLID;
                    frame.fill(&bg_path, Color::from_rgba(r, g, b, 1.0));
                } else {
                    // Deep navy linear gradient top-left → bottom-right.
                    let [sr, sg, sb, _] = design::palette::BG_DEEP_DARK_START;
                    let [er, eg, eb, _] = design::palette::BG_DEEP_DARK_END;
                    let grad = canvas_gradient::Linear::new(
                        iced::Point::ORIGIN,
                        iced::Point::new(bounds.width, bounds.height),
                    )
                    .add_stop(0.0, Color::from_rgb(sr, sg, sb))
                    .add_stop(1.0, Color::from_rgb(er, eg, eb));
                    frame.fill(&bg_path, grad);
                }
            }
            Mode::Strict => {
                // The 2 px terracotta border is drawn as a container overlay
                // in view() (above main_row) so it appears on top of the
                // sidebar. Only the gradient wallpaper is drawn here.
                if self.reduced_transparency {
                    let [r, g, b, _] = design::palette::STRICT_WALLPAPER_START;
                    frame.fill(&bg_path, Color::from_rgba(r, g, b, 1.0));
                } else {
                    let [sr, sg, sb, _] = design::palette::STRICT_WALLPAPER_START;
                    let [er, eg, eb, _] = design::palette::BG_DEEP_DARK_END;
                    let grad = canvas_gradient::Linear::new(
                        iced::Point::ORIGIN,
                        iced::Point::new(bounds.width, bounds.height),
                    )
                    .add_stop(0.0, Color::from_rgb(sr, sg, sb))
                    .add_stop(1.0, Color::from_rgb(er, eg, eb));
                    frame.fill(&bg_path, grad);
                }
            }
        }

        vec![frame.into_geometry()]
    }
}

// ---------------------------------------------------------------------------
// Chrome placeholder (mount points for Modules 43-64)
// ---------------------------------------------------------------------------

fn traffic_light_spacer<'a>() -> Element<'a, Message> {
    // Reserve 38 px for macOS traffic-light buttons in frameless window mode.
    // Matches mock sidebar top:38px — sidebar content and chrome align at the same row.
    container(text("")).height(Length::Fixed(38.0)).into()
}

/// Top-bar chrome + optional tab strip (Top position only).
/// Mount points filled module-by-module as Phase 8 lands.
fn chrome_placeholder(state: &AppState) -> Element<'_, Message> {
    // Module 43: address bar — centered horizontally.
    // height(Shrink): lets the address bar column expand downward when the
    // strict-popup or suggestion dropdown is visible, instead of compressing
    // the capsule because of column spacing inside a Fixed(36px) container.
    let address_bar = container(
        state
            .address_bar
            .view(state.window_width * 0.40)
            .map(Message::AddressBar),
    )
    .width(Length::Fill)
    .center_x(Length::Fill)
    .height(Length::Shrink);

    // Module 44: identity capsule + tabs-pill — right-aligned overlay.
    let top_chrome = container(state.tab_bar.view_top_chrome().map(Message::TabBar))
        .width(Length::Fill)
        .height(Length::Fixed(design::layout::TOP_BAR_HEIGHT_PX));

    // Stack overlays top chrome on top of the address bar so the address bar
    // stays truly centered regardless of right-side pill widths.
    let top_bar = iced::widget::Stack::new()
        .push(address_bar)
        .push(top_chrome);

    // TODO Module 46 mount point: new tab page
    // TODO Module 53 mount point: mode-switch popup
    // TODO Module 64 mount point: first-launch wizard overlay

    let mut col = Column::new().width(Length::Fill).push(top_bar);

    if state.tab_bar.position == crate::tab_bar::TabBarPosition::Top {
        let top_strip = state
            .tab_bar
            .view_strip(state.window_width)
            .map(Message::TabBar);
        col = col
            .push(iced::widget::Space::new().height(design::space::S4))
            .push(top_strip);
    }

    col.into()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Launch the DevBrowse Iced application.
///
/// Called from `pb-browser` main (Module 80 orchestrator wires this in
/// Phase 11). Phase 8 can call this directly for UI development.
pub fn run() -> iced::Result {
    iced::application(boot, update, view)
        .title(title)
        .theme(theme)
        .style(app_style)
        .centered()
        .subscription(subscription)
        .window(window_settings())
        .run()
}

/// Application style. Forces a fully transparent root background so the
/// wallpaper canvas (Stack base layer) is the only thing painting behind the
/// chrome. Without this, Iced fills the root with the theme's default
/// background color, which on macOS appears as a gray strip under the
/// translucent titlebar in fullscreen.
fn app_style(_state: &AppState, _theme: &Theme) -> iced::theme::Style {
    iced::theme::Style {
        background_color: Color::TRANSPARENT,
        text_color: Color::WHITE,
    }
}
fn subscription(_state: &AppState) -> iced::Subscription<Message> {
    window::resize_events().map(|(id, size)| Message::WindowResized(id, size))
}

fn window_settings() -> window::Settings {
    // Cross-platform frameless window. We draw our own traffic-light circles
    // so the look is identical on macOS, Linux, and Windows.
    // window::drag(id) handles window movement on all platforms via winit.
    window::Settings {
        size: Size::new(1280.0, 800.0),
        min_size: Some(Size::new(800.0, 600.0)),
        resizable: true,
        decorations: false,
        // transparent: true removes the system-drawn border/shadow that appears
        // around frameless windows on macOS and some Linux compositors.
        transparent: true,
        ..window::Settings::default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_state_starts_as_standard_starting() {
        let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
        let state = AppState::new("test".to_string(), Arc::new(tx));
        assert_eq!(state.mode, Mode::Standard);
        assert_eq!(state.phase, AppPhase::Starting);
    }

    #[test]
    fn profile_loaded_transitions_to_ready() {
        let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
        let mut state = AppState::new("test".to_string(), Arc::new(tx));
        let _ = update(&mut state, Message::ProfileLoaded("alice".to_string()));
        assert_eq!(state.phase, AppPhase::Ready);
        assert_eq!(state.profile_name, "alice");
    }

    #[test]
    fn convert_to_strict_only_from_ready_standard() {
        let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
        let mut state = AppState::new("test".to_string(), Arc::new(tx));
        // While in Starting phase, convert is a no-op.
        let _ = update(&mut state, Message::ConvertToStrict);
        assert_eq!(state.mode, Mode::Standard);
        assert_eq!(state.phase, AppPhase::Starting);

        // Transition to Ready first.
        let _ = update(&mut state, Message::ProfileLoaded("alice".to_string()));
        let _ = update(&mut state, Message::ConvertToStrict);
        assert_eq!(state.phase, AppPhase::TransitioningMode);
    }

    #[test]
    fn no_strict_to_standard_transition() {
        // §3.6: once Strict, ConvertToStrict is the only mode message; there
        // is no reverse. Sending ConvertToStrict in Strict stays Strict.
        let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
        let mut state = AppState::new("test".to_string(), Arc::new(tx));
        state.mode = Mode::Strict;
        state.phase = AppPhase::Ready;
        let _ = update(&mut state, Message::ConvertToStrict);
        // ConvertToStrict from Strict+Ready: mode == Standard check fails, no-op.
        assert_eq!(state.mode, Mode::Strict);
    }

    #[test]
    fn morph_tick_completes_at_token_duration() {
        let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
        let mut state = AppState::new("test".to_string(), Arc::new(tx));
        state.phase = AppPhase::TransitioningMode;
        state.mode = Mode::Standard;
        // One tick at the full duration.
        let target = design::motion::MODE_CONVERT_MS;
        let _ = update(&mut state, Message::MorphTick(target));
        assert_eq!(state.mode, Mode::Strict);
        assert_eq!(state.phase, AppPhase::Ready);
    }

    #[test]
    fn reduced_motion_makes_morph_instant() {
        let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
        let mut state = AppState::new("test".to_string(), Arc::new(tx));
        state.reduced_motion = true;
        state.phase = AppPhase::TransitioningMode;
        state.mode = Mode::Standard;
        // Even 0 ms tick completes the morph when reduced_motion = true.
        let _ = update(&mut state, Message::MorphTick(0));
        assert_eq!(state.mode, Mode::Strict);
    }

    #[test]
    fn narration_label_does_not_expose_internals() {
        let (tx, _rx) = mpsc::channel::<ChromeCommand>(8);
        let state = AppState::new("alice".to_string(), Arc::new(tx));
        let label = state.narration_label();
        // Label must contain mode and profile name but not any file path.
        assert!(label.contains("Standard"));
        assert!(label.contains("alice"));
        assert!(!label.contains('/'));
    }

    #[test]
    fn strict_border_constant_matches_token() {
        // L42: 2 px terracotta border in Strict.
        assert_eq!(design::layout::STRICT_BORDER_PX, 2.0);
    }
}

