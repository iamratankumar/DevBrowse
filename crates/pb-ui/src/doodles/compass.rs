//! Compass doodle — large rose with spinning needle assembly.
//!
//! Accent colours: fuchsia #e879f9 (accent1) + amber #fbbf24 (accent2).
//! Static: cache cleared only on palette swap.

use iced::widget::canvas::{self, Cache, Frame, Path, Stroke, Text};
use iced::{mouse, Color, Font, Point, Radians, Rectangle, Size, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

// ── accent constants ─────────────────────────────────────────────────────────
const A1: Color = Color {
    r: 0.910,
    g: 0.475,
    b: 0.976,
    a: 1.0,
}; // #e879f9
const A2: Color = Color {
    r: 0.984,
    g: 0.750,
    b: 0.141,
    a: 1.0,
}; // #fbbf24

fn a1(a: f32) -> Color {
    Color { a, ..A1 }
}
fn a2(a: f32) -> Color {
    Color { a, ..A2 }
}

// ── public cache handle ───────────────────────────────────────────────────────
pub struct CompassCache {
    pub cache: Cache,
}

impl CompassCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for CompassCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CompassCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompassCache")
    }
}

// ── canvas program ────────────────────────────────────────────────────────────
pub struct CompassProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
}

impl<'a> canvas::Program<NewTabMsg> for CompassProgram<'a> {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &iced::Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        let geo = self.cache.draw(renderer, bounds.size(), |frame| {
            if self.mode == Mode::Strict {
                draw_strict(frame, bounds.size(), self.palette);
            } else {
                draw(frame, bounds.size(), self.palette);
            }
        });
        vec![geo]
    }
}

// ── drawing ───────────────────────────────────────────────────────────────────
fn draw(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0 + 28.0;
    let cy = 74.0;

    let is_dark = palette.is_dark();
    // In dark mode dim everything — fills and strokes — so the illustration
    // sits quietly behind the content without competing with the wallpaper.
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
    // Dim strokes too — multiply incoming color alpha.
    let solid = |col: Color, w: f32| {
        Stroke::default()
            .with_color(Color {
                a: col.a * dim,
                ..col
            })
            .with_width(w)
    };

    // Outer ring — accent1 fill + stroke
    let outer = Path::circle(Point::new(cx, cy), 55.0);
    frame.fill(&outer, a1(0.06));
    frame.stroke(&outer, solid(A1, 2.2));

    // Mid ring
    let mid = Path::circle(Point::new(cx, cy), 46.0);
    frame.stroke(&mid, solid(sc(0.4), 1.0));

    // Inner ring (dashed approximated as thin solid)
    let inner = Path::circle(Point::new(cx, cy), 38.0);
    frame.stroke(&inner, solid(sc(0.28), 0.8));

    // ── Needle polygons ───────────────────────────────────────────────────────
    // N needle — accent1 filled, points up
    let n_needle = Path::new(|b| {
        b.move_to(Point::new(cx, cy - 50.0));
        b.line_to(Point::new(cx + 7.0, cy - 16.0));
        b.line_to(Point::new(cx - 7.0, cy - 16.0));
        b.close();
    });
    frame.fill(&n_needle, a1(0.95));
    frame.stroke(&n_needle, solid(A1, 1.2));

    // S needle — hollow stroke only
    let s_needle = Path::new(|b| {
        b.move_to(Point::new(cx, cy + 50.0));
        b.line_to(Point::new(cx - 7.0, cy + 16.0));
        b.line_to(Point::new(cx + 7.0, cy + 16.0));
        b.close();
    });
    frame.stroke(&s_needle, solid(sc(0.55), 1.5));

    // W needle — hollow stroke only
    let w_needle = Path::new(|b| {
        b.move_to(Point::new(cx - 50.0, cy));
        b.line_to(Point::new(cx - 16.0, cy - 7.0));
        b.line_to(Point::new(cx - 16.0, cy + 7.0));
        b.close();
    });
    frame.stroke(&w_needle, solid(sc(0.55), 1.3));

    // E needle — accent2 filled
    let e_needle = Path::new(|b| {
        b.move_to(Point::new(cx + 50.0, cy));
        b.line_to(Point::new(cx + 16.0, cy + 7.0));
        b.line_to(Point::new(cx + 16.0, cy - 7.0));
        b.close();
    });
    frame.fill(&e_needle, a2(0.95));
    frame.stroke(&e_needle, solid(A2, 1.2));

    // Axis dividers (thin, behind center jewel)
    let v_line = Path::new(|b| {
        b.move_to(Point::new(cx, cy - 16.0));
        b.line_to(Point::new(cx, cy + 16.0));
    });
    frame.stroke(&v_line, solid(sc(0.28), 0.6));

    let h_line = Path::new(|b| {
        b.move_to(Point::new(cx - 16.0, cy));
        b.line_to(Point::new(cx + 16.0, cy));
    });
    frame.stroke(&h_line, solid(sc(0.28), 0.6));

    // Center jewel
    let jewel_outer = Path::circle(Point::new(cx, cy), 9.0);
    frame.fill(&jewel_outer, a1(0.25));
    frame.stroke(&jewel_outer, solid(A1, 1.8));

    let jewel_core = Path::circle(Point::new(cx, cy), 3.5);
    frame.fill(&jewel_core, A2);

    // ── Intercardinal ticks ───────────────────────────────────────────────────
    let ticks: [(f32, f32, f32, f32); 4] = [
        (cx - 37.0, cy - 37.0, cx - 31.0, cy - 31.0), // NW
        (cx + 37.0, cy - 37.0, cx + 31.0, cy - 31.0), // NE
        (cx - 37.0, cy + 37.0, cx - 31.0, cy + 31.0), // SW
        (cx + 37.0, cy + 37.0, cx + 31.0, cy + 31.0), // SE
    ];
    for (x1, y1, x2, y2) in ticks {
        let t = Path::new(|b| {
            b.move_to(Point::new(x1, y1));
            b.line_to(Point::new(x2, y2));
        });
        frame.stroke(&t, solid(sc(0.38), 1.2));
    }

    // Outer cardinal ticks (N/S/E/W extensions)
    let outer_ticks: [(f32, f32, f32, f32); 4] = [
        (cx, cy - 55.0, cx, cy - 60.0),
        (cx, cy + 55.0, cx, cy + 60.0),
        (cx - 55.0, cy, cx - 60.0, cy),
        (cx + 55.0, cy, cx + 60.0, cy),
    ];
    for (x1, y1, x2, y2) in outer_ticks {
        let t = Path::new(|b| {
            b.move_to(Point::new(x1, y1));
            b.line_to(Point::new(x2, y2));
        });
        frame.stroke(&t, solid(sc(0.45), 1.4));
    }

    // ── Cardinal letters ──────────────────────────────────────────────────────
    let font_size = 13.0_f32;
    let letter = |content: &str, x: f32, y: f32, color: Color| Text {
        content: content.to_string(),
        position: Point::new(x, y),
        color,
        size: iced::Pixels(font_size),
        font: Font::DEFAULT,
        align_x: iced::alignment::Horizontal::Center.into(),
        align_y: iced::alignment::Vertical::Center,
        line_height: iced::widget::text::LineHeight::default(),
        shaping: iced::widget::text::Shaping::Basic,
        max_width: f32::INFINITY,
    };

    frame.fill_text(letter("N", cx, cy - 67.0, a1(0.85)));
    frame.fill_text(letter("S", cx, cy + 69.0, sc(0.5)));
    frame.fill_text(letter("W", cx - 69.0, cy + 1.0, sc(0.5)));
    frame.fill_text(letter("E", cx + 69.0, cy + 1.0, a2(0.85)));

    // ── Sun at East (shining toward the E needle) ─────────────────────────────
    draw_sun(frame, Point::new(cx + 118.0, cy - 12.0), &solid);

    // ── Floating astronauts ───────────────────────────────────────────────────
    // upper-left, gently tilted
    draw_astronaut(frame, Point::new(cx - 138.0, 22.0), 0.18, &solid, &sc);
    // lower-left, tumbling
    draw_astronaut(frame, Point::new(cx - 118.0, 118.0), -0.30, &solid, &sc);
    // lower-right, drifting away
    draw_astronaut(frame, Point::new(cx + 125.0, 112.0), 0.22, &solid, &sc);
}

/// Gradient vignette that fades canvas edges to the wallpaper colour.
/// Amber sun with layered glow and 8 rays — placed at `pos` in canvas space.
fn draw_sun(frame: &mut Frame, pos: Point, solid: &impl Fn(Color, f32) -> Stroke<'static>) {
    // Outer glow halos
    let halo1 = Path::circle(pos, 22.0);
    frame.fill(
        &halo1,
        Color {
            r: A2.r,
            g: A2.g,
            b: A2.b,
            a: 0.07,
        },
    );
    let halo2 = Path::circle(pos, 16.0);
    frame.fill(
        &halo2,
        Color {
            r: A2.r,
            g: A2.g,
            b: A2.b,
            a: 0.13,
        },
    );

    // 8 rays: pairs at 0°, 45°, 90°, 135° + their opposites
    let ray_angles: [f32; 8] = [0.0, 45.0, 90.0, 135.0, 180.0, 225.0, 270.0, 315.0];
    for deg in ray_angles {
        let rad = deg.to_radians();
        let (s, c) = rad.sin_cos();
        let inner = 13.0_f32;
        let outer = if deg % 90.0 == 0.0 { 22.0 } else { 18.0 }; // cardinal rays longer
        let p1 = Point::new(pos.x + c * inner, pos.y + s * inner);
        let p2 = Point::new(pos.x + c * outer, pos.y + s * outer);
        let ray = Path::new(|b| {
            b.move_to(p1);
            b.line_to(p2);
        });
        frame.stroke(
            &ray,
            solid(a2(0.75), if deg % 90.0 == 0.0 { 1.8 } else { 1.2 }),
        );
    }

    // Sun body
    let body = Path::circle(pos, 9.0);
    frame.fill(&body, a2(0.55));
    frame.stroke(&body, solid(A2, 1.8));

    // Bright core
    let core = Path::circle(pos, 5.0);
    frame.fill(&core, a2(0.85));
}

/// Tiny spacesuited astronaut centered at `pos`, rotated by `angle` radians.
fn draw_astronaut(
    frame: &mut Frame,
    pos: Point,
    angle: f32,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    sc: &impl Fn(f32) -> Color,
) {
    frame.with_save(|f| {
        f.translate(Vector::new(pos.x, pos.y));
        f.rotate(Radians(angle));

        // Helmet
        let helmet = Path::circle(Point::new(0.0, -11.0), 7.0);
        f.fill(
            &helmet,
            Color {
                r: sc(0.18).r,
                g: sc(0.18).g,
                b: sc(0.18).b,
                a: 0.18,
            },
        );
        f.stroke(&helmet, solid(sc(0.7), 1.5));

        // Gold visor
        let visor = Path::circle(Point::new(0.5, -11.5), 4.0);
        f.fill(&visor, a2(0.35));
        f.stroke(&visor, solid(A2, 0.9));

        // Torso
        let torso = Path::new(|b| {
            b.move_to(Point::new(-5.0, -4.0));
            b.line_to(Point::new(5.0, -4.0));
            b.line_to(Point::new(5.0, 8.0));
            b.line_to(Point::new(-5.0, 8.0));
            b.close();
        });
        f.fill(
            &torso,
            Color {
                r: sc(0.15).r,
                g: sc(0.15).g,
                b: sc(0.15).b,
                a: 0.15,
            },
        );
        f.stroke(&torso, solid(sc(0.65), 1.4));

        // Chest panel dot
        let dot = Path::circle(Point::new(0.0, 1.5), 1.5);
        f.fill(&dot, a1(0.7));

        // Left arm
        let la = Path::new(|b| {
            b.move_to(Point::new(-5.0, -1.0));
            b.line_to(Point::new(-11.0, 4.0));
        });
        f.stroke(&la, solid(sc(0.65), 2.2));

        // Right arm
        let ra = Path::new(|b| {
            b.move_to(Point::new(5.0, -1.0));
            b.line_to(Point::new(11.0, 4.0));
        });
        f.stroke(&ra, solid(sc(0.65), 2.2));

        // Left leg
        let ll = Path::new(|b| {
            b.move_to(Point::new(-3.0, 8.0));
            b.line_to(Point::new(-4.0, 18.0));
        });
        f.stroke(&ll, solid(sc(0.65), 2.5));

        // Right leg
        let rl = Path::new(|b| {
            b.move_to(Point::new(3.0, 8.0));
            b.line_to(Point::new(4.0, 18.0));
        });
        f.stroke(&rl, solid(sc(0.65), 2.5));

        // Boots
        let lboot = Path::circle(Point::new(-4.0, 19.0), 3.0);
        f.fill(
            &lboot,
            Color {
                r: sc(0.22).r,
                g: sc(0.22).g,
                b: sc(0.22).b,
                a: 0.22,
            },
        );
        f.stroke(&lboot, solid(sc(0.5), 1.0));
        let rboot = Path::circle(Point::new(4.0, 19.0), 3.0);
        f.fill(
            &rboot,
            Color {
                r: sc(0.22).r,
                g: sc(0.22).g,
                b: sc(0.22).b,
                a: 0.22,
            },
        );
        f.stroke(&rboot, solid(sc(0.5), 1.0));
    });
}

// ── Strict mode — doodle-specific security vibe ───────────────────────────────
// Visual language: terracotta accent, desaturated chrome, scan-line grid,
// padlock at center (compass needle → lock), shield in place of sun.
// Each doodle interprets its own theme through a security lens — not generic.
fn draw_strict(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0 + 28.0;
    let cy = 74.0;

    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let stroke_alpha = if is_dark { 0.45_f32 } else { 0.38_f32 };

    // Terracotta strict color (#b85a3c)
    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };

    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * stroke_alpha / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // ── Compass rings — muted, terracotta tint ────────────────────────────────
    let outer = Path::circle(Point::new(cx, cy), 55.0);
    frame.fill(&outer, t(0.05));
    frame.stroke(&outer, solid(t(0.7), 2.0));

    let mid = Path::circle(Point::new(cx, cy), 46.0);
    frame.stroke(&mid, solid(sc(0.3), 0.9));

    let inner = Path::circle(Point::new(cx, cy), 38.0);
    frame.stroke(&inner, solid(sc(0.2), 0.7));

    // ── All four needles — terracotta, N is solid, others hollow ─────────────
    let n_needle = Path::new(|b| {
        b.move_to(Point::new(cx, cy - 50.0));
        b.line_to(Point::new(cx + 7.0, cy - 16.0));
        b.line_to(Point::new(cx - 7.0, cy - 16.0));
        b.close();
    });
    frame.fill(&n_needle, t(0.9));
    frame.stroke(&n_needle, solid(tc, 1.2));

    for (x1, y1, x2, y2, x3, y3) in [
        (cx, cy + 50.0, cx - 7.0, cy + 16.0, cx + 7.0, cy + 16.0), // S
        (cx - 50.0, cy, cx - 16.0, cy - 7.0, cx - 16.0, cy + 7.0), // W
        (cx + 50.0, cy, cx + 16.0, cy + 7.0, cx + 16.0, cy - 7.0), // E
    ] {
        let needle = Path::new(|b| {
            b.move_to(Point::new(x1, y1));
            b.line_to(Point::new(x2, y2));
            b.line_to(Point::new(x3, y3));
            b.close();
        });
        frame.stroke(&needle, solid(t(0.55), 1.3));
    }

    // Intercardinal ticks
    for (x1, y1, x2, y2) in [
        (cx - 37.0, cy - 37.0, cx - 31.0, cy - 31.0),
        (cx + 37.0, cy - 37.0, cx + 31.0, cy - 31.0),
        (cx - 37.0, cy + 37.0, cx - 31.0, cy + 31.0),
        (cx + 37.0, cy + 37.0, cx + 31.0, cy + 31.0),
    ] {
        let t_path = Path::new(|b| {
            b.move_to(Point::new(x1, y1));
            b.line_to(Point::new(x2, y2));
        });
        frame.stroke(&t_path, solid(sc(0.3), 1.0));
    }

    // Cardinal letters
    let font_size = 13.0_f32;
    let letter = |content: &str, x: f32, y: f32, color: Color| Text {
        content: content.to_string(),
        position: Point::new(x, y),
        color,
        size: iced::Pixels(font_size),
        font: Font::DEFAULT,
        align_x: iced::alignment::Horizontal::Center.into(),
        align_y: iced::alignment::Vertical::Center,
        line_height: iced::widget::text::LineHeight::default(),
        shaping: iced::widget::text::Shaping::Basic,
        max_width: f32::INFINITY,
    };
    frame.fill_text(letter("N", cx, cy - 67.0, t(0.85)));
    frame.fill_text(letter("S", cx, cy + 69.0, sc(0.45)));
    frame.fill_text(letter("W", cx - 69.0, cy + 1.0, sc(0.45)));
    frame.fill_text(letter("E", cx + 69.0, cy + 1.0, sc(0.45)));

    // ── Padlock at center (replaces jewel) ────────────────────────────────────
    draw_padlock(frame, Point::new(cx, cy), &solid, &t, &sc);

    // ── Shield in upper-right (replaces sun) ──────────────────────────────────
    draw_shield(frame, Point::new(cx + 118.0, cy - 12.0), &solid, &t, &sc);
}

/// Padlock drawn at `pos`. Shackle up, body below, keyhole inside.
fn draw_padlock(
    frame: &mut Frame,
    pos: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
    sc: &impl Fn(f32) -> Color,
) {
    let x = pos.x;
    let y = pos.y;

    // Shackle (U-shape above body)
    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 5.5, y - 4.0));
        b.line_to(Point::new(x - 5.5, y - 10.0));
        b.arc(canvas::path::Arc {
            center: Point::new(x, y - 10.0),
            radius: 5.5,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 5.5, y - 4.0));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.8));

    // Lock body
    let body = Path::new(|b| {
        b.move_to(Point::new(x - 8.0, y - 4.0));
        b.line_to(Point::new(x + 8.0, y - 4.0));
        b.line_to(Point::new(x + 8.0, y + 8.0));
        b.line_to(Point::new(x - 8.0, y + 8.0));
        b.close();
    });
    frame.fill(&body, t(0.18));
    frame.stroke(&body, solid(t(0.85), 1.6));

    // Keyhole: circle + teardrop
    let keyhole_circle = Path::circle(Point::new(x, y + 1.0), 2.5);
    frame.fill(&keyhole_circle, t(0.7));
    let keyhole_slot = Path::new(|b| {
        b.move_to(Point::new(x - 1.5, y + 3.0));
        b.line_to(Point::new(x + 1.5, y + 3.0));
        b.line_to(Point::new(x + 1.0, y + 7.0));
        b.line_to(Point::new(x - 1.0, y + 7.0));
        b.close();
    });
    frame.fill(&keyhole_slot, t(0.7));

    // Small "STRICT" dot below lock
    let dot = Path::circle(Point::new(x, y + 16.0), 2.0);
    frame.fill(&dot, sc(0.3));
}

/// Shield shape at `pos` — represents security/privacy guard.
fn draw_shield(
    frame: &mut Frame,
    pos: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
    sc: &impl Fn(f32) -> Color,
) {
    let x = pos.x;
    let y = pos.y;
    let _ = sc; // reserved for future use

    // Shield outline: flat top, pointed bottom
    let shield = Path::new(|b| {
        b.move_to(Point::new(x - 16.0, y - 16.0));
        b.line_to(Point::new(x + 16.0, y - 16.0));
        b.line_to(Point::new(x + 16.0, y));
        b.quadratic_curve_to(Point::new(x + 16.0, y + 12.0), Point::new(x, y + 20.0));
        b.quadratic_curve_to(Point::new(x - 16.0, y + 12.0), Point::new(x - 16.0, y));
        b.close();
    });
    frame.fill(&shield, t(0.12));
    frame.stroke(&shield, solid(t(0.8), 2.0));

    // Inner shield line (decorative inset)
    let inner_shield = Path::new(|b| {
        b.move_to(Point::new(x - 10.0, y - 10.0));
        b.line_to(Point::new(x + 10.0, y - 10.0));
        b.line_to(Point::new(x + 10.0, y + 1.0));
        b.quadratic_curve_to(Point::new(x + 10.0, y + 9.0), Point::new(x, y + 15.0));
        b.quadratic_curve_to(Point::new(x - 10.0, y + 9.0), Point::new(x - 10.0, y + 1.0));
        b.close();
    });
    frame.stroke(&inner_shield, solid(t(0.35), 0.8));

    // Checkmark inside shield
    let check = Path::new(|b| {
        b.move_to(Point::new(x - 5.0, y - 1.0));
        b.line_to(Point::new(x - 1.0, y + 4.0));
        b.line_to(Point::new(x + 7.0, y - 6.0));
    });
    frame.stroke(&check, solid(t(0.9), 2.0));
}
