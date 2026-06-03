//! Sanctuary doodle — horseshoe arch, lantern + rays, flanking foliage.
//!
//! Accent colours: green #86efac (accent1) + amber #fcd34d (accent2).
//! Static: cache cleared only on palette swap.

use iced::widget::canvas::{self, path::Arc, Cache, Frame, Path, Stroke};
use iced::{mouse, Color, Point, Radians, Rectangle, Size, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.984,
    g: 0.443,
    b: 0.522,
    a: 1.0,
}; // #fb7185
const A2: Color = Color {
    r: 0.988,
    g: 0.827,
    b: 0.302,
    a: 1.0,
}; // #fcd34d

pub struct SanctuaryCache {
    pub cache: Cache,
}

impl SanctuaryCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for SanctuaryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SanctuaryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SanctuaryCache")
    }
}

pub struct SanctuaryProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
}

impl<'a> canvas::Program<NewTabMsg> for SanctuaryProgram<'a> {
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

// ── Standard ─────────────────────────────────────────────────────────────────
fn draw(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0 + 16.0;

    // Scale 1.3× around the arch centre so the art fills the larger zone.
    let (scale, py) = (1.3_f32, 88.0_f32);
    frame.translate(Vector::new(cx, py));
    frame.scale(scale);
    frame.translate(Vector::new(-cx, -py));

    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.55_f32 } else { 1.0_f32 };
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

    // ── Horseshoe arch ────────────────────────────────────────────────────────
    let arch_outer = Path::new(|b| {
        b.move_to(Point::new(cx - 45.0, 148.0));
        b.line_to(Point::new(cx - 45.0, 64.0));
        b.quadratic_curve_to(Point::new(cx - 45.0, 28.0), Point::new(cx, 28.0));
        b.quadratic_curve_to(Point::new(cx + 45.0, 28.0), Point::new(cx + 45.0, 64.0));
        b.line_to(Point::new(cx + 45.0, 148.0));
        b.line_to(Point::new(cx + 35.0, 148.0));
        b.line_to(Point::new(cx + 35.0, 64.0));
        b.quadratic_curve_to(Point::new(cx + 35.0, 38.0), Point::new(cx, 38.0));
        b.quadratic_curve_to(Point::new(cx - 35.0, 38.0), Point::new(cx - 35.0, 64.0));
        b.line_to(Point::new(cx - 35.0, 148.0));
        b.close();
    });
    frame.fill(&arch_outer, a1(0.18));

    // Crown curve
    let crown = Path::new(|b| {
        b.move_to(Point::new(cx - 35.0, 38.0));
        b.quadratic_curve_to(Point::new(cx, 18.0), Point::new(cx + 35.0, 38.0));
    });
    frame.stroke(&crown, solid(a1(0.4), 0.8));

    // ── Lantern rect at crown ─────────────────────────────────────────────────
    let lantern = Path::new(|b| {
        b.move_to(Point::new(cx - 5.0, 24.0));
        b.line_to(Point::new(cx + 5.0, 24.0));
        b.line_to(Point::new(cx + 5.0, 32.0));
        b.line_to(Point::new(cx - 5.0, 32.0));
        b.close();
    });
    frame.fill(&lantern, a2(0.7));

    // ── Light rays from lantern ───────────────────────────────────────────────
    let ray_origin = Point::new(cx, 32.0);
    for (ex, ey, w, a) in [
        (cx, 4.0, 1.8_f32, 0.7_f32),
        (cx - 27.0, 10.0, 1.3, 0.55),
        (cx + 27.0, 10.0, 1.3, 0.55),
        (cx - 45.0, 20.0, 1.0, 0.4),
        (cx + 45.0, 20.0, 1.0, 0.4),
    ] {
        let ray = Path::new(|b| {
            b.move_to(ray_origin);
            b.line_to(Point::new(ex, ey));
        });
        frame.stroke(&ray, solid(a2(a), w));
    }

    // ── Inner glow — candle at arch centre ────────────────────────────────────
    let gx = cx;
    let gy = 84.0_f32;
    let halo = Path::circle(Point::new(gx, gy), 14.0);
    frame.fill(&halo, Color { a: 0.2 * dim, ..A2 });
    let mid = Path::circle(Point::new(gx, gy), 8.0);
    frame.fill(&mid, a2(0.4));
    let core = Path::circle(Point::new(gx, gy), 4.0);
    frame.fill(&core, a2(1.0));

    // ── Foliage left ──────────────────────────────────────────────────────────
    // Top leaf
    let lf1 = Path::new(|b| {
        b.move_to(Point::new(cx - 90.0, 101.0));
        b.quadratic_curve_to(Point::new(cx - 85.0, 84.0), Point::new(cx - 67.0, 88.0));
        b.quadratic_curve_to(Point::new(cx - 57.0, 92.0), Point::new(cx - 57.0, 101.0));
        b.quadratic_curve_to(Point::new(cx - 67.0, 106.0), Point::new(cx - 77.0, 104.0));
        b.quadratic_curve_to(Point::new(cx - 87.0, 104.0), Point::new(cx - 90.0, 101.0));
        b.close();
    });
    frame.fill(&lf1, a1(0.4));

    // Mid leaf
    let lf2 = Path::new(|b| {
        b.move_to(Point::new(cx - 95.0, 121.0));
        b.quadratic_curve_to(Point::new(cx - 90.0, 104.0), Point::new(cx - 70.0, 108.0));
        b.quadratic_curve_to(Point::new(cx - 57.0, 113.0), Point::new(cx - 57.0, 122.0));
        b.quadratic_curve_to(Point::new(cx - 71.0, 128.0), Point::new(cx - 85.0, 126.0));
        b.quadratic_curve_to(Point::new(cx - 93.0, 126.0), Point::new(cx - 95.0, 121.0));
        b.close();
    });
    frame.fill(&lf2, a1(0.3));

    // Bottom leaf
    let lf3 = Path::new(|b| {
        b.move_to(Point::new(cx - 77.0, 136.0));
        b.quadratic_curve_to(Point::new(cx - 77.0, 120.0), Point::new(cx - 61.0, 120.0));
        b.quadratic_curve_to(Point::new(cx - 49.0, 120.0), Point::new(cx - 49.0, 134.0));
        b.quadratic_curve_to(Point::new(cx - 59.0, 140.0), Point::new(cx - 70.0, 138.0));
        b.quadratic_curve_to(Point::new(cx - 77.0, 140.0), Point::new(cx - 77.0, 136.0));
        b.close();
    });
    frame.fill(&lf3, a1(0.25));

    // ── Foliage right (mirrored) ───────────────────────────────────────────────
    let rf1 = Path::new(|b| {
        b.move_to(Point::new(cx + 90.0, 101.0));
        b.quadratic_curve_to(Point::new(cx + 85.0, 84.0), Point::new(cx + 67.0, 88.0));
        b.quadratic_curve_to(Point::new(cx + 57.0, 92.0), Point::new(cx + 57.0, 101.0));
        b.quadratic_curve_to(Point::new(cx + 67.0, 106.0), Point::new(cx + 77.0, 104.0));
        b.quadratic_curve_to(Point::new(cx + 87.0, 104.0), Point::new(cx + 90.0, 101.0));
        b.close();
    });
    frame.fill(&rf1, a1(0.4));

    let rf2 = Path::new(|b| {
        b.move_to(Point::new(cx + 95.0, 121.0));
        b.quadratic_curve_to(Point::new(cx + 90.0, 104.0), Point::new(cx + 70.0, 108.0));
        b.quadratic_curve_to(Point::new(cx + 57.0, 113.0), Point::new(cx + 57.0, 122.0));
        b.quadratic_curve_to(Point::new(cx + 71.0, 128.0), Point::new(cx + 85.0, 126.0));
        b.quadratic_curve_to(Point::new(cx + 93.0, 126.0), Point::new(cx + 95.0, 121.0));
        b.close();
    });
    frame.fill(&rf2, a1(0.3));

    let rf3 = Path::new(|b| {
        b.move_to(Point::new(cx + 77.0, 136.0));
        b.quadratic_curve_to(Point::new(cx + 77.0, 120.0), Point::new(cx + 61.0, 120.0));
        b.quadratic_curve_to(Point::new(cx + 49.0, 120.0), Point::new(cx + 49.0, 134.0));
        b.quadratic_curve_to(Point::new(cx + 59.0, 140.0), Point::new(cx + 70.0, 138.0));
        b.quadratic_curve_to(Point::new(cx + 77.0, 140.0), Point::new(cx + 77.0, 136.0));
        b.close();
    });
    frame.fill(&rf3, a1(0.25));

    // Horizontal vein on top leaves
    let vl = Path::new(|b| {
        b.move_to(Point::new(cx - 87.0, 102.0));
        b.line_to(Point::new(cx - 62.0, 102.0));
    });
    frame.stroke(&vl, solid(a1(0.5), 0.6));
    let vr = Path::new(|b| {
        b.move_to(Point::new(cx + 87.0, 102.0));
        b.line_to(Point::new(cx + 62.0, 102.0));
    });
    frame.stroke(&vr, solid(a1(0.5), 0.6));

    // ── Accent sparkle dots ───────────────────────────────────────────────────
    let d1 = Path::circle(Point::new(cx - 27.0, 58.0), 2.0);
    frame.fill(&d1, a2(0.5));
    let d2 = Path::circle(Point::new(cx + 25.0, 54.0), 1.8);
    frame.fill(&d2, a2(0.5));

    // Suppress unused
    let _ = sc;
}

// ── Strict — sealed sanctuary: terracotta, portcullis gate, padlock + shield ──
fn draw_strict(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0 + 16.0;

    let (scale, py) = (1.3_f32, 88.0_f32);
    frame.translate(Vector::new(cx, py));
    frame.scale(scale);
    frame.translate(Vector::new(-cx, -py));

    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let stroke_alpha = if is_dark { 0.45_f32 } else { 0.38_f32 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * stroke_alpha / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Arch — terracotta
    let arch = Path::new(|b| {
        b.move_to(Point::new(cx - 45.0, 148.0));
        b.line_to(Point::new(cx - 45.0, 64.0));
        b.quadratic_curve_to(Point::new(cx - 45.0, 28.0), Point::new(cx, 28.0));
        b.quadratic_curve_to(Point::new(cx + 45.0, 28.0), Point::new(cx + 45.0, 64.0));
        b.line_to(Point::new(cx + 45.0, 148.0));
        b.line_to(Point::new(cx + 35.0, 148.0));
        b.line_to(Point::new(cx + 35.0, 64.0));
        b.quadratic_curve_to(Point::new(cx + 35.0, 38.0), Point::new(cx, 38.0));
        b.quadratic_curve_to(Point::new(cx - 35.0, 38.0), Point::new(cx - 35.0, 64.0));
        b.line_to(Point::new(cx - 35.0, 148.0));
        b.close();
    });
    frame.fill(&arch, t(0.12));
    frame.stroke(&arch, solid(tc, 2.2));

    // Stone-block courses on each pillar
    for y in [80.0_f32, 100.0, 120.0, 140.0] {
        for (x1, x2) in [(cx - 45.0, cx - 35.0), (cx + 35.0, cx + 45.0)] {
            let line = Path::new(|b| {
                b.move_to(Point::new(x1, y));
                b.line_to(Point::new(x2, y));
            });
            frame.stroke(&line, solid(sc(0.25), 0.8));
        }
    }

    // Portcullis gate — vertical bars + two horizontal rails
    for x in [cx - 20.0, cx - 8.0, cx + 4.0, cx + 16.0] {
        let bar = Path::new(|b| {
            b.move_to(Point::new(x, 100.0));
            b.line_to(Point::new(x, 148.0));
        });
        frame.stroke(&bar, solid(t(0.55), 1.4));
    }
    for y in [112.0_f32, 132.0] {
        let rail = Path::new(|b| {
            b.move_to(Point::new(cx - 25.0, y));
            b.line_to(Point::new(cx + 22.0, y));
        });
        frame.stroke(&rail, solid(t(0.45), 1.0));
    }

    // Padlock at arch centre
    draw_padlock(frame, Point::new(cx, 72.0), &solid, &t, &sc);

    // Shield at crown
    draw_shield(frame, Point::new(cx, 36.0), &solid, &t);
}

fn draw_padlock(
    frame: &mut Frame,
    pos: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
    _sc: &impl Fn(f32) -> Color,
) {
    let x = pos.x;
    let y = pos.y;

    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 5.5, y - 2.0));
        b.line_to(Point::new(x - 5.5, y - 7.0));
        b.arc(Arc {
            center: Point::new(x, y - 7.0),
            radius: 5.5,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 5.5, y - 2.0));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.8));

    let body = Path::new(|b| {
        b.move_to(Point::new(x - 8.0, y - 2.0));
        b.line_to(Point::new(x + 8.0, y - 2.0));
        b.line_to(Point::new(x + 8.0, y + 8.0));
        b.line_to(Point::new(x - 8.0, y + 8.0));
        b.close();
    });
    frame.fill(&body, t(0.18));
    frame.stroke(&body, solid(t(0.85), 1.6));

    let khole = Path::circle(Point::new(x, y + 2.0), 2.5);
    frame.fill(&khole, t(0.7));
    let kslot = Path::new(|b| {
        b.move_to(Point::new(x - 1.5, y + 4.0));
        b.line_to(Point::new(x + 1.5, y + 4.0));
        b.line_to(Point::new(x + 1.0, y + 7.5));
        b.line_to(Point::new(x - 1.0, y + 7.5));
        b.close();
    });
    frame.fill(&kslot, t(0.7));
}

fn draw_shield(
    frame: &mut Frame,
    pos: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    let x = pos.x;
    let y = pos.y;

    let shield = Path::new(|b| {
        b.move_to(Point::new(x - 10.0, y - 8.0));
        b.line_to(Point::new(x + 10.0, y - 8.0));
        b.line_to(Point::new(x + 10.0, y + 2.0));
        b.quadratic_curve_to(Point::new(x + 10.0, y + 10.0), Point::new(x, y + 14.0));
        b.quadratic_curve_to(
            Point::new(x - 10.0, y + 10.0),
            Point::new(x - 10.0, y + 2.0),
        );
        b.close();
    });
    frame.fill(&shield, t(0.15));
    frame.stroke(&shield, solid(t(0.85), 1.8));

    let check = Path::new(|b| {
        b.move_to(Point::new(x - 4.0, y + 2.0));
        b.line_to(Point::new(x - 1.0, y + 6.0));
        b.line_to(Point::new(x + 5.0, y - 2.0));
    });
    frame.stroke(&check, solid(t(0.9), 1.8));
}
