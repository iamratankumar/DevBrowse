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
//!   §3.1 — mode locked at tab/window creation.
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
    window, Color, Element, Length, Pixels, Rectangle, Renderer, Size, Task, Theme,
};
use tokio::sync::mpsc;

use crate::tokens;
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
    /// OS `prefers-reduced-transparency` flag forwarded from the window event.
    /// When true, all `GlassPanel` surfaces use the solid fallback (§3.4).
    pub reduced_transparency: bool,
    /// OS `prefers-reduced-motion` flag. When true, mode morph duration = 0.
    pub reduced_motion: bool,
    /// Elapsed ms since a mode-convert morph started.
    morph_elapsed_ms: u32,
    /// Sends application-level commands to chrome module subscribers (Modules 43-64).
    pub command_tx: Arc<mpsc::Sender<ChromeCommand>>,
}

impl AppState {
    fn new(profile_name: String, command_tx: Arc<mpsc::Sender<ChromeCommand>>) -> Self {
        Self {
            mode: Mode::Standard,
            phase: AppPhase::Starting,
            profile_name,
            tab_count: 0,
            reduced_transparency: false,
            reduced_motion: false,
            morph_elapsed_ms: 0,
            command_tx,
        }
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

fn update(state: &mut AppState, message: Message) -> Task<Message> {
    match message {
        Message::ProfileLoaded(name) => {
            state.profile_name = name;
            state.phase = AppPhase::Ready;
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
                tokens::motion::MODE_CONVERT_MS
            };
            if state.phase == AppPhase::TransitioningMode {
                state.morph_elapsed_ms = elapsed_ms.min(target_ms);
                if state.morph_elapsed_ms >= target_ms {
                    state.mode = Mode::Strict;
                    state.phase = AppPhase::Ready;
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
        }
        Message::WindowCloseRequested => {
            state.phase = AppPhase::Closing;
        }
        Message::None => {}
    }
    Task::none()
}

fn view(state: &AppState) -> Element<'_, Message> {
    // Wallpaper layer — full-window gradient. Paints behind all chrome.
    let wallpaper = wallpaper_canvas(state.mode, state.reduced_transparency)
        .width(Length::Fill)
        .height(Length::Fill);

    // Traffic-light spacer: 14 px from left + top edges (layout::TRAFFIC_LIGHT_INSET).
    // The actual traffic-light controls are provided by the OS window decoration;
    // we reserve space so chrome elements don't overlap them on macOS.
    let chrome = Column::new()
        .push(traffic_light_spacer())
        .push(chrome_placeholder(state));

    // Stack: wallpaper behind, chrome on top.
    // TODO Module 42 impl: replace `container` stack with `iced::widget::stack`
    // once other modules provide real elements. For now chrome overlays the wallpaper.
    container(iced::widget::Stack::new().push(wallpaper).push(chrome))
        .width(Length::Fill)
        .height(Length::Fill)
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
fn wallpaper_canvas(mode: Mode, reduced: bool) -> Canvas<WallpaperProgram, Message> {
    Canvas::new(WallpaperProgram {
        mode,
        reduced_transparency: reduced,
    })
}

struct WallpaperProgram {
    mode: Mode,
    reduced_transparency: bool,
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

        match self.mode {
            Mode::Standard => {
                if self.reduced_transparency {
                    // §3.4 solid fallback for Standard.
                    let [r, g, b, _] = tokens::palette::STANDARD_WALLPAPER_SOLID;
                    frame.fill_rectangle(
                        iced::Point::ORIGIN,
                        bounds.size(),
                        Color::from_rgba(r, g, b, 1.0),
                    );
                } else {
                    // Deep navy linear gradient top-left → bottom-right
                    // (tokens: bg_deep_dark_start → bg_deep_dark_end).
                    let [sr, sg, sb, _] = tokens::palette::BG_DEEP_DARK_START;
                    let [er, eg, eb, _] = tokens::palette::BG_DEEP_DARK_END;
                    let grad = canvas_gradient::Linear::new(
                        iced::Point::ORIGIN,
                        iced::Point::new(bounds.width, bounds.height),
                    )
                    .add_stop(0.0, Color::from_rgb(sr, sg, sb))
                    .add_stop(1.0, Color::from_rgb(er, eg, eb));
                    frame.fill_rectangle(iced::Point::ORIGIN, bounds.size(), grad);
                }
            }
            Mode::Strict => {
                if self.reduced_transparency {
                    // §3.4 solid fallback for Strict.
                    let [r, g, b, _] = tokens::palette::STRICT_WALLPAPER_START;
                    frame.fill_rectangle(
                        iced::Point::ORIGIN,
                        bounds.size(),
                        Color::from_rgba(r, g, b, 1.0),
                    );
                } else {
                    // Warmer terracotta-tinted gradient for Strict wallpaper.
                    let [sr, sg, sb, _] = tokens::palette::STRICT_WALLPAPER_START;
                    let [er, eg, eb, _] = tokens::palette::BG_DEEP_DARK_END;
                    let grad = canvas_gradient::Linear::new(
                        iced::Point::ORIGIN,
                        iced::Point::new(bounds.width, bounds.height),
                    )
                    .add_stop(0.0, Color::from_rgb(sr, sg, sb))
                    .add_stop(1.0, Color::from_rgb(er, eg, eb));
                    frame.fill_rectangle(iced::Point::ORIGIN, bounds.size(), grad);
                }

                // Strict border: 2 px terracotta border + inset glow (L42, mode-indicator.md).
                let [br, bg, bb, _] = tokens::palette::STRICT;
                let border_color = Color::from_rgb(br, bg, bb);
                let border_px = tokens::layout::STRICT_BORDER_PX;

                // Top edge
                frame.fill_rectangle(
                    iced::Point::ORIGIN,
                    Size::new(bounds.width, border_px),
                    border_color,
                );
                // Bottom edge
                frame.fill_rectangle(
                    iced::Point::new(0.0, bounds.height - border_px),
                    Size::new(bounds.width, border_px),
                    border_color,
                );
                // Left edge
                frame.fill_rectangle(
                    iced::Point::ORIGIN,
                    Size::new(border_px, bounds.height),
                    border_color,
                );
                // Right edge
                frame.fill_rectangle(
                    iced::Point::new(bounds.width - border_px, 0.0),
                    Size::new(border_px, bounds.height),
                    border_color,
                );
            }
        }

        vec![frame.into_geometry()]
    }
}

// ---------------------------------------------------------------------------
// Chrome placeholder (mount points for Modules 43-64)
// ---------------------------------------------------------------------------

fn traffic_light_spacer<'a>() -> Element<'a, Message> {
    // Reserve 14 px top padding so chrome doesn't overlap macOS traffic-lights.
    container(text(""))
        .height(Length::Fixed(tokens::layout::TRAFFIC_LIGHT_INSET_PX))
        .into()
}

/// Top-bar chrome placeholder. Replaced module-by-module as Phase 8 lands.
/// Each line is a mount point comment tracking which module fills the slot.
fn chrome_placeholder(state: &AppState) -> Element<'_, Message> {
    let mode_label = match state.mode {
        Mode::Standard => "Standard",
        Mode::Strict => "Strict · close tab to exit",
    };

    let status = match state.phase {
        AppPhase::Starting => "Loading…",
        AppPhase::Ready => mode_label,
        AppPhase::TransitioningMode => "Converting to Strict…",
        AppPhase::Closing => "Closing…",
    };

    // TODO Module 43 mount point: address bar
    // TODO Module 44 mount point: tab bar / identity capsule
    // TODO Module 46 mount point: new tab page
    // TODO Module 53 mount point: mode-switch popup
    // TODO Module 64 mount point: first-launch wizard overlay
    container(
        text(status)
            .size(Pixels(tokens::type_scale::BODY_PX))
            .color(Color::from([
                tokens::palette::TEXT_PRIMARY_DARK[0],
                tokens::palette::TEXT_PRIMARY_DARK[1],
                tokens::palette::TEXT_PRIMARY_DARK[2],
            ])),
    )
    .padding(tokens::space::S8)
    .into()
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
        .centered()
        .window(window_settings())
        .run()
}

fn window_settings() -> window::Settings {
    window::Settings {
        size: Size::new(1280.0, 800.0),
        min_size: Some(Size::new(800.0, 600.0)),
        resizable: true,
        decorations: true,
        transparent: false,
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
        let target = tokens::motion::MODE_CONVERT_MS;
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
        assert_eq!(tokens::layout::STRICT_BORDER_PX, 2.0);
    }
}
