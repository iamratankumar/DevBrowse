//! Waypoint doodle — teardrop map pin, dashed trail, compass rose.
//!
//! Accent colours: pink #f472b6 (accent1) + violet #a78bfa (accent2).
//! Static: cache cleared only on palette swap.

use iced::widget::canvas::{self, path::Arc, Cache, Frame, Path, Stroke, Text};
use iced::{mouse, Color, Font, Point, Radians, Rectangle, Size, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.957,
    g: 0.447,
    b: 0.714,
    a: 1.0,
}; // #f472b6
const A2: Color = Color {
    r: 0.655,
    g: 0.545,
    b: 0.980,
    a: 1.0,
}; // #a78bfa

pub struct WaypointCache {
    pub cache: Cache,
}

impl WaypointCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for WaypointCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for WaypointCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WaypointCache")
    }
}

pub struct WaypointProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
    /// Cursor position in NTP-view coordinates, updated on every mouse move.
    pub cursor_pos: Point,
}

impl<'a> canvas::Program<NewTabMsg> for WaypointProgram<'a> {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &iced::Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        let size = bounds.size();

        // Rose center in canvas-local coordinates.
        let rx = size.width / 2.0 + 28.0 + 108.0;
        let ry = 108.0_f32;

        // Cursor is in NTP-view coordinates. The canvas is horizontally centered
        // inside the content column (width ≈ canvas width), so X maps closely.
        // Y includes the top-spacer offset; the angle is approximate but tracks
        // cursor direction well enough for a decorative needle.
        let angle =
            (self.cursor_pos.y - ry).atan2(self.cursor_pos.x - rx) + std::f32::consts::FRAC_PI_2;

        // Layer 1 — cached static geometry (pin, trail, rose ring + cross).
        let static_geo = self.cache.draw(renderer, size, |frame| {
            if self.mode == Mode::Strict {
                draw_strict(frame, size, self.palette);
            } else {
                draw(frame, size, self.palette);
            }
        });

        // Layer 2 — uncached rose needle at the current cursor angle.
        let mut needle_frame = Frame::new(renderer, size);
        if self.mode == Mode::Strict {
            draw_rose_needle_strict(&mut needle_frame, rx, ry, angle, self.palette);
        } else {
            draw_rose_needle(&mut needle_frame, rx, ry, angle, self.palette);
        }

        vec![static_geo, needle_frame.into_geometry()]
    }
}

// ── Standard ─────────────────────────────────────────────────────────────────
fn draw(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0 + 28.0;

    let (scale, py) = (1.3_f32, 74.0_f32);
    frame.translate(Vector::new(cx, py));
    frame.scale(scale);
    frame.translate(Vector::new(-cx, -py));

    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.5_f32 } else { 1.0_f32 };
    let stroke_alpha = if is_dark { 0.55_f32 } else { 0.45_f32 };
    let [sr, sg, sb, _] = palette.text_primary;
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * stroke_alpha / 0.55);
    let a1 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A1
    };
    let a2 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A2
    };
    let solid = |col: Color, w: f32| {
        Stroke::default()
            .with_color(Color {
                a: col.a * dim,
                ..col
            })
            .with_width(w)
    };

    // ── Map pin (teardrop) ────────────────────────────────────────────────────
    let pin_cy = 52.0_f32;
    let pin_r = 28.0_f32;
    let tip_y = pin_cy + pin_r + 36.0; // pointed tip

    // Teardrop outline fill
    let teardrop = Path::new(|b| {
        b.move_to(Point::new(cx, pin_cy - pin_r));
        b.quadratic_curve_to(
            Point::new(cx + pin_r + 10.0, pin_cy - pin_r),
            Point::new(cx + pin_r, pin_cy),
        );
        b.quadratic_curve_to(
            Point::new(cx + pin_r, pin_cy + pin_r),
            Point::new(cx, tip_y),
        );
        b.quadratic_curve_to(
            Point::new(cx - pin_r, pin_cy + pin_r),
            Point::new(cx - pin_r, pin_cy),
        );
        b.quadratic_curve_to(
            Point::new(cx - pin_r - 10.0, pin_cy - pin_r),
            Point::new(cx, pin_cy - pin_r),
        );
        b.close();
    });
    frame.fill(&teardrop, a1(0.14));
    frame.stroke(&teardrop, solid(A1, 2.2));

    // Head circle (emphasis ring)
    let head = Path::circle(Point::new(cx, pin_cy), pin_r);
    frame.fill(&head, a1(0.10));
    frame.stroke(&head, solid(A1, 1.8));

    // Inner ring
    let inner = Path::circle(Point::new(cx, pin_cy), 11.0);
    frame.fill(&inner, a1(0.85));

    // Inner dot contrast
    let dot = Path::circle(Point::new(cx, pin_cy), 4.5);
    frame.fill(&dot, sc(0.35));

    // Ground shadow ellipse
    let shadow = Path::new(|b| {
        b.move_to(Point::new(cx - 10.0, tip_y));
        b.arc(Arc {
            center: Point::new(cx, tip_y),
            radius: 10.0,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.close();
    });
    frame.fill(&shadow, sc(0.15));

    // ── Dashed trail from lower-left to pin ───────────────────────────────────
    let trail_start = Point::new(cx - 145.0, 126.0);
    let trail = Path::new(|b| {
        b.move_to(trail_start);
        b.quadratic_curve_to(Point::new(cx - 90.0, 103.0), Point::new(cx - 55.0, 113.0));
        b.quadratic_curve_to(Point::new(cx - 25.0, 120.0), Point::new(cx - 20.0, 96.0));
        b.quadratic_curve_to(Point::new(cx - 15.0, 88.0), Point::new(cx, tip_y + 4.0));
    });
    frame.stroke(
        &trail,
        Stroke::default().with_color(sc(0.45)).with_width(1.5),
    );

    // Trail start dot + outer ring
    let start_dot = Path::circle(trail_start, 5.5);
    frame.fill(&start_dot, a2(0.8 * dim));
    let start_ring = Path::circle(trail_start, 10.0);
    frame.stroke(&start_ring, solid(A2, 1.0));

    // ── Compass rose (lower-right) ────────────────────────────────────────────
    let rx = cx + 108.0;
    let ry = 108.0_f32;
    let rr = 18.0_f32;

    let rose_outer = Path::circle(Point::new(rx, ry), rr);
    frame.fill(&rose_outer, sc(0.06));
    frame.stroke(&rose_outer, solid(sc(0.35), 1.0));

    // Cross lines
    for (x1, y1, x2, y2) in [(rx, ry - rr, rx, ry + rr), (rx - rr, ry, rx + rr, ry)] {
        let line = Path::new(|b| {
            b.move_to(Point::new(x1, y1));
            b.line_to(Point::new(x2, y2));
        });
        frame.stroke(&line, solid(sc(0.3), 0.7));
    }

    // Center jewel
    let jewel = Path::circle(Point::new(rx, ry), 2.5);
    frame.fill(&jewel, sc(0.55));

    // N label
    let n_label = Text {
        content: "N".to_string(),
        position: Point::new(rx, ry - rr - 7.0),
        color: a1(0.8 * dim),
        size: iced::Pixels(8.0),
        font: Font::DEFAULT,
        align_x: iced::alignment::Horizontal::Center.into(),
        align_y: iced::alignment::Vertical::Center,
        line_height: iced::widget::text::LineHeight::default(),
        shaping: iced::widget::text::Shaping::Basic,
        max_width: f32::INFINITY,
    };
    frame.fill_text(n_label);

    // Accent star dot upper-left
    let star = Path::circle(Point::new(cx - 130.0, 22.0), 2.0);
    frame.fill(&star, a2(0.6 * dim));
    let star2 = Path::circle(Point::new(cx - 105.0, 42.0), 1.5);
    frame.fill(&star2, a1(0.5 * dim));
}

// ── Strict — secured location: terracotta, lock inside pin, solid route ───────
fn draw_strict(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0 + 28.0;

    let (scale, py) = (1.3_f32, 74.0_f32);
    frame.translate(Vector::new(cx, py));
    frame.scale(scale);
    frame.translate(Vector::new(-cx, -py));

    let stroke_alpha = if palette.is_dark() {
        0.45_f32
    } else {
        0.38_f32
    };
    let [sr, sg, sb, _] = palette.text_primary;
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * stroke_alpha / 0.45);

    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    let pin_cy = 52.0_f32;
    let pin_r = 28.0_f32;
    let tip_y = pin_cy + pin_r + 36.0;

    // Teardrop
    let teardrop = Path::new(|b| {
        b.move_to(Point::new(cx, pin_cy - pin_r));
        b.quadratic_curve_to(
            Point::new(cx + pin_r + 10.0, pin_cy - pin_r),
            Point::new(cx + pin_r, pin_cy),
        );
        b.quadratic_curve_to(
            Point::new(cx + pin_r, pin_cy + pin_r),
            Point::new(cx, tip_y),
        );
        b.quadratic_curve_to(
            Point::new(cx - pin_r, pin_cy + pin_r),
            Point::new(cx - pin_r, pin_cy),
        );
        b.quadratic_curve_to(
            Point::new(cx - pin_r - 10.0, pin_cy - pin_r),
            Point::new(cx, pin_cy - pin_r),
        );
        b.close();
    });
    frame.fill(&teardrop, t(0.12));
    frame.stroke(&teardrop, solid(tc, 2.2));

    let head = Path::circle(Point::new(cx, pin_cy), pin_r);
    frame.fill(&head, t(0.08));
    frame.stroke(&head, solid(tc, 1.8));

    // Lock icon inside the pin head (replaces inner dot)
    draw_mini_lock(frame, Point::new(cx, pin_cy), &solid, &t);

    // Ground shadow
    let shadow = Path::new(|b| {
        b.move_to(Point::new(cx - 10.0, tip_y));
        b.arc(Arc {
            center: Point::new(cx, tip_y),
            radius: 10.0,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.close();
    });
    frame.fill(&shadow, sc(0.12));

    // Solid secured route (not dashed)
    let trail_start = Point::new(cx - 145.0, 126.0);
    let trail = Path::new(|b| {
        b.move_to(trail_start);
        b.quadratic_curve_to(Point::new(cx - 90.0, 103.0), Point::new(cx - 55.0, 113.0));
        b.quadratic_curve_to(Point::new(cx - 25.0, 120.0), Point::new(cx - 20.0, 96.0));
        b.quadratic_curve_to(Point::new(cx - 15.0, 88.0), Point::new(cx, tip_y + 4.0));
    });
    frame.stroke(&trail, solid(t(0.5), 1.8));

    // Shield at trail origin (instead of plain dot)
    let sx = trail_start.x;
    let sy = trail_start.y;
    let shield = Path::new(|b| {
        b.move_to(Point::new(sx - 9.0, sy - 9.0));
        b.line_to(Point::new(sx + 9.0, sy - 9.0));
        b.line_to(Point::new(sx + 9.0, sy + 1.0));
        b.quadratic_curve_to(Point::new(sx + 9.0, sy + 10.0), Point::new(sx, sy + 14.0));
        b.quadratic_curve_to(
            Point::new(sx - 9.0, sy + 10.0),
            Point::new(sx - 9.0, sy + 1.0),
        );
        b.close();
    });
    frame.fill(&shield, t(0.2));
    frame.stroke(&shield, solid(tc, 1.5));

    // Compass rose lower-right (same structure, terracotta)
    let rx = cx + 108.0;
    let ry = 108.0_f32;
    let rr = 18.0_f32;

    let rose_outer = Path::circle(Point::new(rx, ry), rr);
    frame.stroke(&rose_outer, solid(t(0.4), 1.0));

    for (x1, y1, x2, y2) in [(rx, ry - rr, rx, ry + rr), (rx - rr, ry, rx + rr, ry)] {
        let line = Path::new(|b| {
            b.move_to(Point::new(x1, y1));
            b.line_to(Point::new(x2, y2));
        });
        frame.stroke(&line, solid(sc(0.25), 0.7));
    }

    let jewel = Path::circle(Point::new(rx, ry), 2.5);
    frame.fill(&jewel, sc(0.5));

    let n_label = Text {
        content: "N".to_string(),
        position: Point::new(rx, ry - rr - 7.0),
        color: t(0.75),
        size: iced::Pixels(8.0),
        font: Font::DEFAULT,
        align_x: iced::alignment::Horizontal::Center.into(),
        align_y: iced::alignment::Vertical::Center,
        line_height: iced::widget::text::LineHeight::default(),
        shaping: iced::widget::text::Shaping::Basic,
        max_width: f32::INFINITY,
    };
    frame.fill_text(n_label);
}

// ── Cursor-driven rose needle layers ─────────────────────────────────────────

/// Standard: accent1-filled N + hollow S needle for the compass rose, rotated toward cursor.
fn draw_rose_needle(frame: &mut Frame, rx: f32, ry: f32, angle: f32, palette: &'static Palette) {
    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.5_f32 } else { 1.0_f32 };
    let stroke_alpha = if is_dark { 0.55_f32 } else { 0.45_f32 };
    let [sr, sg, sb, _] = palette.text_primary;
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * stroke_alpha / 0.55);
    let a1 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A1
    };
    let solid = |col: Color, w: f32| {
        Stroke::default()
            .with_color(Color {
                a: col.a * dim,
                ..col
            })
            .with_width(w)
    };
    let rr = 18.0_f32;

    frame.with_save(|f| {
        f.translate(Vector::new(rx, ry));
        f.rotate(Radians(angle));

        let n = Path::new(|b| {
            b.move_to(Point::new(0.0, -(rr - 2.0)));
            b.line_to(Point::new(3.5, -5.0));
            b.line_to(Point::new(-3.5, -5.0));
            b.close();
        });
        f.fill(&n, a1(0.9));

        let s = Path::new(|b| {
            b.move_to(Point::new(0.0, rr - 2.0));
            b.line_to(Point::new(-3.5, 5.0));
            b.line_to(Point::new(3.5, 5.0));
            b.close();
        });
        f.stroke(&s, solid(sc(0.45), 1.0));
    });
}

/// Strict: terracotta N needle for the compass rose, rotated toward cursor.
fn draw_rose_needle_strict(
    frame: &mut Frame,
    rx: f32,
    ry: f32,
    angle: f32,
    _palette: &'static Palette,
) {
    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let rr = 18.0_f32;

    frame.with_save(|f| {
        f.translate(Vector::new(rx, ry));
        f.rotate(Radians(angle));

        let n = Path::new(|b| {
            b.move_to(Point::new(0.0, -(rr - 2.0)));
            b.line_to(Point::new(3.5, -5.0));
            b.line_to(Point::new(-3.5, -5.0));
            b.close();
        });
        f.fill(&n, t(0.9));
    });
}

/// Tiny padlock centered at `pos` — fits inside the pin head (r≈11).
fn draw_mini_lock(
    frame: &mut Frame,
    pos: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    let x = pos.x;
    let y = pos.y;

    // Shackle
    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 4.0, y - 2.0));
        b.line_to(Point::new(x - 4.0, y - 6.0));
        b.arc(Arc {
            center: Point::new(x, y - 6.0),
            radius: 4.0,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 4.0, y - 2.0));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.5));

    // Body
    let body = Path::new(|b| {
        b.move_to(Point::new(x - 6.0, y - 2.0));
        b.line_to(Point::new(x + 6.0, y - 2.0));
        b.line_to(Point::new(x + 6.0, y + 6.0));
        b.line_to(Point::new(x - 6.0, y + 6.0));
        b.close();
    });
    frame.fill(&body, t(0.2));
    frame.stroke(&body, solid(t(0.85), 1.4));

    // Keyhole
    let khole = Path::circle(Point::new(x, y + 1.5), 1.8);
    frame.fill(&khole, t(0.8));
}
