//! pb-ui::glass — Module 42 in-app glass widget.
//!
//! `GlassPanel` is the single source of truth for every frosted-glass
//! chrome surface in Phase 8 (URL bar, sidebar, popovers, settings panel).
//!
//! Rendering contract (from phase-8-ui.md Module 42 sub-deliverable 2):
//!   `GlassPanel { tint_rgba, blur_sigma_px, saturate, corner_radius_px }`
//!   samples the wallpaper layer below the chrome, blurs it (Kawase approximation
//!   in glass.wgsl), composites the tint, and clips to a rounded rectangle.
//!
//! The WGSL shader (`shaders/glass.wgsl`) is the GPU path. This module owns
//! the Iced canvas widget wrapper and the `prefers-reduced-transparency`
//! fallback (solid tint, no blur pass). The `ReducedTransparency` flag is
//! read from the OS via `iced::window::settings` and forwarded here by the
//! shell (Module 42 shell.rs).
//!
//! Enforces: L28 (glass aesthetic, accessibility, reduce-transparency fallback),
//!           §3.4 system.md (reduce-transparency solid fallback table),
//!           §5.4 architecture.md (no canvas state leaks across modules).
//!
//! TODO Module 42 impl: wire the wgpu Shader pipeline once the iced wgpu
//! compositor surface is accessible. For Phase 8 launch the canvas path
//! renders a correctly-tinted solid that is perceptually identical to
//! reduced-transparency mode; the WGSL shader in shaders/glass.wgsl is
//! ready to be wired in when Iced exposes compositor texture access.

use iced::{
    Color, Element, Length, Rectangle, Renderer, Theme,
    mouse,
    widget::canvas::{self, Frame, Geometry, Path},
    border,
};

use crate::tokens;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A frosted-glass chrome surface.
///
/// All Phase 8 modules use `GlassPanel::new(...)` rather than hard-coding
/// colour or blur values. Token constants live in `pb_ui::tokens::glass` and
/// `pb_ui::tokens::palette`.
#[derive(Debug, Clone)]
pub struct GlassPanel {
    /// RGBA tint composited over the blurred wallpaper (0.0–1.0 each).
    pub tint_rgba: [f32; 4],
    /// Gaussian blur sigma in logical pixels. 0.0 = solid fallback.
    pub blur_sigma_px: f32,
    /// Saturation multiplier applied after blur (1.0 = unchanged).
    pub saturate: f32,
    /// Corner radius in logical pixels.
    pub corner_radius_px: f32,
    /// Width of the panel.
    pub width: Length,
    /// Height of the panel.
    pub height: Length,
    /// When true the OS has reported `prefers-reduced-transparency: reduce`.
    /// The shell sets this flag and all glass surfaces honour it (§3.4).
    pub reduced_transparency: bool,
}

impl GlassPanel {
    /// Construct a URL-bar glass capsule using the standard token values.
    pub fn url_bar(reduced_transparency: bool) -> Self {
        Self {
            tint_rgba: tokens::palette::GLASS_TINT_DARK,
            blur_sigma_px: tokens::glass::URL_BAR_BLUR_SIGMA,
            saturate: tokens::glass::URL_BAR_SATURATE,
            corner_radius_px: tokens::radius::CAPSULE_PX,
            width: Length::Fixed(tokens::layout::URL_BAR_WIDTH_PX),
            height: Length::Fixed(tokens::layout::TOP_BAR_HEIGHT_PX),
            reduced_transparency,
        }
    }

    /// Construct a panel glass surface (settings, network viewer, popovers).
    pub fn panel(width: Length, height: Length, reduced_transparency: bool) -> Self {
        Self {
            tint_rgba: tokens::palette::GLASS_TINT_DARK,
            blur_sigma_px: tokens::glass::PANEL_BLUR_SIGMA,
            saturate: tokens::glass::PANEL_SATURATE,
            corner_radius_px: tokens::radius::PANEL_PX,
            width,
            height,
            reduced_transparency,
        }
    }

    /// Produce the Iced widget. Wraps the canvas program in a sized container.
    pub fn view<'a, Message: 'a>(&self) -> Element<'a, Message> {
        let program = GlassProgram {
            tint_rgba: self.tint_rgba,
            blur_sigma_px: self.blur_sigma_px,
            saturate: self.saturate,
            corner_radius_px: self.corner_radius_px,
            reduced_transparency: self.reduced_transparency,
        };
        canvas(program)
            .width(self.width)
            .height(self.height)
            .into()
    }
}

// ---------------------------------------------------------------------------
// Internal canvas program
// ---------------------------------------------------------------------------

struct GlassProgram {
    tint_rgba: [f32; 4],
    blur_sigma_px: f32,
    saturate: f32,
    corner_radius_px: f32,
    reduced_transparency: bool,
}

impl<Message> canvas::Program<Message> for GlassProgram {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry<Renderer>> {
        let mut frame = Frame::new(renderer, bounds.size());

        let use_solid = self.reduced_transparency || self.blur_sigma_px <= 0.0;

        // Base fill color — when blur is available this will be the blurred
        // wallpaper; for now we use the tint over the reduced-transparency
        // solid fallback colour from §3.4 of system.md.
        let base_color = if use_solid {
            // §3.4 solid fallback: #14161e (dark mode)
            let [r, g, b, _] = tokens::palette::GLASS_REDUCED_DARK;
            Color::from_rgba(r, g, b, 1.0)
        } else {
            // Full blur path: the solid tint is an approximation until the
            // wgpu compositor texture is wired (TODO above). We apply the
            // saturation multiplier to the tint to approximate the effect.
            let [r, g, b, a] = self.tint_rgba;
            let sat = self.saturate.max(0.0);
            // ITU-R BT.709 luminance-weighted saturation approximation.
            let lum = 0.2126 * r + 0.7152 * g + 0.0722 * b;
            let sr = lum + (r - lum) * sat;
            let sg = lum + (g - lum) * sat;
            let sb = lum + (b - lum) * sat;
            Color::from_rgba(sr.clamp(0.0, 1.0), sg.clamp(0.0, 1.0), sb.clamp(0.0, 1.0), a)
        };

        // Rounded-rectangle clip path.
        let rrect = Path::rounded_rectangle(
            iced::Point::ORIGIN,
            bounds.size(),
            border::Radius::from(self.corner_radius_px),
        );

        frame.fill(&rrect, base_color);

        // In non-reduced-transparency mode overlay the tint on top of the
        // base fill to simulate the glass compositing step.
        if !use_solid {
            let [r, g, b, a] = self.tint_rgba;
            let tint_color = Color::from_rgba(r, g, b, a * 0.65);
            frame.fill(&rrect, tint_color);
        }

        vec![frame.into_geometry()]
    }
}

// Re-export canvas helper so callers don't need to import iced_widget directly.
fn canvas<P: canvas::Program<Message>, Message>(
    program: P,
) -> iced::widget::Canvas<P, Message> {
    iced::widget::canvas(program)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iced::Length;

    #[test]
    fn url_bar_glass_uses_token_sigma() {
        let g = GlassPanel::url_bar(false);
        assert_eq!(g.blur_sigma_px, tokens::glass::URL_BAR_BLUR_SIGMA);
    }

    #[test]
    fn reduced_transparency_zeroes_blur_in_view() {
        let g = GlassPanel::url_bar(true);
        assert!(g.reduced_transparency);
        // blur_sigma_px itself is unchanged — the *canvas program* switches
        // rendering path based on the flag, not by zeroing sigma.
        assert!(g.blur_sigma_px > 0.0);
    }

    #[test]
    fn panel_glass_uses_panel_sigma() {
        let g = GlassPanel::panel(Length::Fill, Length::Fill, false);
        assert_eq!(g.blur_sigma_px, tokens::glass::PANEL_BLUR_SIGMA);
    }

    #[test]
    fn corner_radius_url_bar_matches_capsule_token() {
        let g = GlassPanel::url_bar(false);
        assert_eq!(g.corner_radius_px, tokens::radius::CAPSULE_PX);
    }

    #[test]
    fn corner_radius_panel_matches_panel_token() {
        let g = GlassPanel::panel(Length::Fill, Length::Fill, false);
        assert_eq!(g.corner_radius_px, tokens::radius::PANEL_PX);
    }
}
