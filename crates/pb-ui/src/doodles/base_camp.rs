//! Base Camp doodle — mountain range, A-frame tent, interactive sun + compass.
//!
//! Accent colours: green #86efac (A1) + amber #fbbf24 (A2).
//! No 1.3× scale — designed natively for the 190 px DOODLE_H zone.
//! Cursor-driven: sun follows cursor over the canvas; compass needle tracks it.
//! Static cache holds mountains + tent + compass rose ring.
//! Dynamic (uncached) layer: sun disc + rays + compass needle.
//! Strict: terracotta mountains; concrete bunker; surveillance eye; frozen needle.

use std::f32::consts::TAU;

use iced::widget::canvas::{self, Cache, Frame, Path, Stroke};
use iced::{mouse, Color, Point, Radians, Rectangle, Size, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.525,
    g: 0.937,
    b: 0.675,
    a: 1.0,
}; // #86efac green
const A2: Color = Color {
    r: 0.984,
    g: 0.749,
    b: 0.141,
    a: 1.0,
}; // #fbbf24 amber

// Native 190 px layout constants (no scale).
const GROUND_Y: f32 = 162.0;
const PEAK_Y: f32 = 18.0; // mountain peak — 18 px top margin
const COMPASS_R: f32 = 17.0;
const COMPASS_DX: f32 = 100.0; // offset from cx
const COMPASS_Y: f32 = 138.0;

// Default sun position when cursor is not over the canvas.
const SUN_DEFAULT_DX: f32 = 70.0;
const SUN_DEFAULT_Y: f32 = 52.0;

// Sun cursor clamp keeps disc (r=13) and rays (r=20) within the canvas top.
const SUN_MIN_Y: f32 = 22.0;
const SUN_MAX_Y: f32 = 105.0;

pub struct BaseCampCache {
    pub cache: Cache,
}

impl BaseCampCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for BaseCampCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BaseCampCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BaseCampCache")
    }
}

pub struct BaseCampProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
    // cursor_pos kept for compatibility with mod.rs dispatch; actual tracking
    // uses the canvas-local cursor parameter from Program::draw.
    pub cursor_pos: Point,
}

impl canvas::Program<NewTabMsg> for BaseCampProgram<'_> {
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

        let static_geo = self.cache.draw(renderer, size, |frame| {
            if self.mode == Mode::Strict {
                draw_strict_static(frame, size, self.palette);
            } else {
                draw_static(frame, size, self.palette);
            }
        });

        vec![static_geo]
    }
}

// ── Standard static layer (no scale) ─────────────────────────────────────────

fn draw_static(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0;

    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.65_f32 } else { 1.0 };
    let sa = if is_dark { 0.50_f32 } else { 0.45 };
    let [sr, sg, sb, _] = palette.text_primary;
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.50);
    let a1 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A1
    };
    let a2 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A2
    };
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Back mountain (muted silhouette, right of centre)
    let back_mt = Path::new(|b| {
        b.move_to(Point::new(cx + 30.0, GROUND_Y));
        b.line_to(Point::new(cx + 90.0, 90.0));
        b.line_to(Point::new(cx + 155.0, GROUND_Y));
        b.close();
    });
    frame.fill(&back_mt, sc(0.10));

    // Main hero mountain
    let main_mt = Path::new(|b| {
        b.move_to(Point::new(cx - 120.0, GROUND_Y));
        b.line_to(Point::new(cx, PEAK_Y));
        b.line_to(Point::new(cx + 120.0, GROUND_Y));
        b.close();
    });
    frame.fill(&main_mt, a1(0.12));
    frame.stroke(&main_mt, solid(a1(1.0), 2.2));

    // Snow / glacier — zigzag from slopes down from peak
    let snow = Path::new(|b| {
        b.move_to(Point::new(cx - 44.0, 82.0));
        b.line_to(Point::new(cx, PEAK_Y));
        b.line_to(Point::new(cx + 44.0, 82.0));
        b.line_to(Point::new(cx + 24.0, 72.0));
        b.line_to(Point::new(cx + 10.0, 86.0));
        b.line_to(Point::new(cx - 5.0, 68.0));
        b.line_to(Point::new(cx - 24.0, 86.0));
        b.line_to(Point::new(cx - 36.0, 76.0));
        b.line_to(Point::new(cx - 44.0, 82.0));
    });
    frame.fill(&snow, a2(0.28));
    frame.stroke(&snow, solid(a2(1.0), 1.5));

    // Snow cap polygon at very peak
    let cap = Path::new(|b| {
        b.move_to(Point::new(cx, PEAK_Y));
        b.line_to(Point::new(cx + 14.0, PEAK_Y + 24.0));
        b.line_to(Point::new(cx - 14.0, PEAK_Y + 24.0));
        b.close();
    });
    frame.fill(&cap, sc(0.22));

    // Ground line
    let gnd = Path::new(|b| {
        b.move_to(Point::new(cx - 120.0, GROUND_Y));
        b.line_to(Point::new(cx + 155.0, GROUND_Y));
    });
    frame.stroke(&gnd, solid(sc(0.35), 1.0));

    // A-frame tent
    let tx = cx - 80.0;
    let t_peak_y = 112.0_f32;
    let tent = Path::new(|b| {
        b.move_to(Point::new(tx - 22.0, GROUND_Y));
        b.line_to(Point::new(tx, t_peak_y));
        b.line_to(Point::new(tx + 22.0, GROUND_Y));
        b.close();
    });
    frame.fill(&tent, a1(0.22));
    frame.stroke(&tent, solid(a1(1.0), 1.8));
    // Ridge pole
    let ridge = Path::new(|b| {
        b.move_to(Point::new(tx, t_peak_y));
        b.line_to(Point::new(tx, GROUND_Y));
    });
    frame.stroke(&ridge, solid(a1(0.55), 1.2));
    // Door
    let door = Path::new(|b| {
        b.move_to(Point::new(tx - 7.0, GROUND_Y));
        b.line_to(Point::new(tx - 7.0, GROUND_Y - 10.0));
        b.line_to(Point::new(tx + 7.0, GROUND_Y - 10.0));
        b.line_to(Point::new(tx + 7.0, GROUND_Y));
    });
    frame.stroke(&door, solid(a1(0.70), 1.2));

    // Sky sparkle dots
    frame.fill(&Path::circle(Point::new(cx - 90.0, 60.0), 2.5), a2(0.45));
    frame.fill(&Path::circle(Point::new(cx + 38.0, 22.0), 2.0), sc(0.38));

    // Static sun at default position
    let sun = Point::new(cx + SUN_DEFAULT_DX, SUN_DEFAULT_Y);
    frame.fill(&Path::circle(sun, 15.0), a2(0.15));
    frame.fill(&Path::circle(sun, 9.0), a2(0.40));
    for i in 0..8_usize {
        let angle = i as f32 * TAU / 8.0;
        let (sv, cv) = (angle.sin(), angle.cos());
        let (r0, r1) = if i % 2 == 0 {
            (17.0_f32, 24.0)
        } else {
            (16.0, 21.0)
        };
        let ray = Path::new(|b| {
            b.move_to(Point::new(sun.x + sv * r0, sun.y - cv * r0));
            b.line_to(Point::new(sun.x + sv * r1, sun.y - cv * r1));
        });
        frame.stroke(&ray, solid(a2(0.80), 1.8));
    }

    // Compass rose ring + static needle pointing toward sun
    let cc = compass_center(cx);
    frame.fill(&Path::circle(cc, COMPASS_R), sc(0.08));
    frame.stroke(&Path::circle(cc, COMPASS_R), solid(sc(1.0), 1.4));
    for (dx, dy) in [(0.0_f32, -1.0_f32), (0.0, 1.0), (-1.0, 0.0), (1.0, 0.0)] {
        let cl = Path::new(|b| {
            b.move_to(Point::new(cc.x + dx * COMPASS_R, cc.y + dy * COMPASS_R));
            b.line_to(Point::new(cc.x - dx * COMPASS_R, cc.y - dy * COMPASS_R));
        });
        frame.stroke(&cl, solid(sc(0.28), 0.8));
    }
    // North tick
    let n_tick = Path::new(|b| {
        b.move_to(Point::new(cc.x, cc.y - COMPASS_R - 1.0));
        b.line_to(Point::new(cc.x, cc.y - COMPASS_R - 6.0));
    });
    frame.stroke(&n_tick, solid(a1(0.70), 1.3));

    // Static compass needle pointing toward the sun
    let dx = sun.x - cc.x;
    let dy = sun.y - cc.y;
    let needle_angle = dx.atan2(-dy);
    frame.with_save(|f| {
        f.translate(Vector::new(cc.x, cc.y));
        f.rotate(Radians(needle_angle));
        let north = Path::new(|b| {
            b.move_to(Point::new(0.0, -14.0));
            b.line_to(Point::new(4.5, -4.5));
            b.line_to(Point::new(-4.5, -4.5));
            b.close();
        });
        f.fill(&north, a1(0.90));
        let south = Path::new(|b| {
            b.move_to(Point::new(0.0, 14.0));
            b.line_to(Point::new(4.5, 4.5));
            b.line_to(Point::new(-4.5, 4.5));
            b.close();
        });
        f.fill(&south, sc(0.40));
    });
    frame.fill(&Path::circle(cc, 3.0), sc(0.65));

    let _ = size;
}

// ── Strict static layer (no scale) ───────────────────────────────────────────

fn draw_strict_static(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0;

    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let sa = if is_dark { 0.45_f32 } else { 0.38 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Scan lines
    let mut sy = 0.0_f32;
    while sy < size.height {
        let sl = Path::new(|b| {
            b.move_to(Point::new(0.0, sy));
            b.line_to(Point::new(size.width, sy));
        });
        frame.stroke(&sl, solid(t(0.06), 0.5));
        sy += 6.0;
    }

    // Back mountain (terracotta)
    let back_mt = Path::new(|b| {
        b.move_to(Point::new(cx + 30.0, GROUND_Y));
        b.line_to(Point::new(cx + 90.0, 90.0));
        b.line_to(Point::new(cx + 155.0, GROUND_Y));
        b.close();
    });
    frame.fill(&back_mt, t(0.06));
    frame.stroke(&back_mt, solid(t(0.35), 1.4));

    // Main mountain
    let main_mt = Path::new(|b| {
        b.move_to(Point::new(cx - 120.0, GROUND_Y));
        b.line_to(Point::new(cx, PEAK_Y));
        b.line_to(Point::new(cx + 120.0, GROUND_Y));
        b.close();
    });
    frame.fill(&main_mt, t(0.09));
    frame.stroke(&main_mt, solid(tc, 2.2));

    // Snow cap (grayscale)
    let snow = Path::new(|b| {
        b.move_to(Point::new(cx - 44.0, 82.0));
        b.line_to(Point::new(cx, PEAK_Y));
        b.line_to(Point::new(cx + 44.0, 82.0));
        b.line_to(Point::new(cx + 24.0, 72.0));
        b.line_to(Point::new(cx + 10.0, 86.0));
        b.line_to(Point::new(cx - 5.0, 68.0));
        b.line_to(Point::new(cx - 24.0, 86.0));
        b.line_to(Point::new(cx - 36.0, 76.0));
        b.line_to(Point::new(cx - 44.0, 82.0));
    });
    frame.fill(&snow, sc(0.15));
    frame.stroke(&snow, solid(sc(0.48), 1.2));

    // Ground
    let gnd = Path::new(|b| {
        b.move_to(Point::new(cx - 120.0, GROUND_Y));
        b.line_to(Point::new(cx + 155.0, GROUND_Y));
    });
    frame.stroke(&gnd, solid(sc(0.30), 1.0));

    // Concrete bunker (replaces tent)
    let tx = cx - 80.0;
    let bunk_top = 136.0_f32;
    let bunker = Path::new(|b| {
        b.move_to(Point::new(tx - 28.0, GROUND_Y));
        b.line_to(Point::new(tx - 28.0, bunk_top));
        b.line_to(Point::new(tx + 28.0, bunk_top));
        b.line_to(Point::new(tx + 28.0, GROUND_Y));
        b.close();
    });
    frame.fill(&bunker, t(0.10));
    frame.stroke(&bunker, solid(tc, 2.0));
    // Gun slits
    for y in [bunk_top + 8.0, bunk_top + 16.0] {
        let slit = Path::new(|b| {
            b.move_to(Point::new(tx - 20.0, y));
            b.line_to(Point::new(tx + 20.0, y));
        });
        frame.stroke(&slit, solid(sc(0.22), 2.8));
    }
    // Reinforcement X
    let b1 = Path::new(|b| {
        b.move_to(Point::new(tx - 28.0, bunk_top));
        b.line_to(Point::new(tx + 28.0, GROUND_Y));
    });
    let b2 = Path::new(|b| {
        b.move_to(Point::new(tx + 28.0, bunk_top));
        b.line_to(Point::new(tx - 28.0, GROUND_Y));
    });
    frame.stroke(&b1, solid(t(0.20), 0.8));
    frame.stroke(&b2, solid(t(0.20), 0.8));

    // Surveillance eye at fixed position (replaces cursor-tracked sun)
    let eye_x = cx + SUN_DEFAULT_DX;
    let eye_y = SUN_DEFAULT_Y;
    frame.stroke(
        &Path::circle(Point::new(eye_x, eye_y), 17.0),
        solid(t(0.25), 0.8),
    );
    let eye = Path::new(|b| {
        b.move_to(Point::new(eye_x - 14.0, eye_y));
        b.quadratic_curve_to(
            Point::new(eye_x, eye_y - 10.0),
            Point::new(eye_x + 14.0, eye_y),
        );
        b.quadratic_curve_to(
            Point::new(eye_x, eye_y + 10.0),
            Point::new(eye_x - 14.0, eye_y),
        );
        b.close();
    });
    frame.fill(&eye, t(0.08));
    frame.stroke(&eye, solid(tc, 1.8));
    frame.stroke(
        &Path::circle(Point::new(eye_x, eye_y), 6.0),
        solid(t(0.65), 1.2),
    );
    frame.fill(&Path::circle(Point::new(eye_x, eye_y), 3.0), t(1.0));
    let scan = Path::new(|b| {
        b.move_to(Point::new(eye_x - 13.0, eye_y));
        b.line_to(Point::new(eye_x + 13.0, eye_y));
    });
    frame.stroke(&scan, solid(t(0.45), 0.9));

    // Compass rose — frozen
    let cc = compass_center(cx);
    frame.fill(&Path::circle(cc, COMPASS_R), t(0.06));
    frame.stroke(&Path::circle(cc, COMPASS_R), solid(t(0.55), 1.4));
    for (dx, dy) in [(0.0_f32, -1.0_f32), (0.0, 1.0), (-1.0, 0.0), (1.0, 0.0)] {
        let cl = Path::new(|b| {
            b.move_to(Point::new(cc.x + dx * COMPASS_R, cc.y + dy * COMPASS_R));
            b.line_to(Point::new(cc.x - dx * COMPASS_R, cc.y - dy * COMPASS_R));
        });
        frame.stroke(&cl, solid(sc(0.22), 0.8));
    }
    // Frozen needle (north, immobile)
    let fn_north = Path::new(|b| {
        b.move_to(Point::new(cc.x, cc.y - 14.0));
        b.line_to(Point::new(cc.x + 4.5, cc.y - 4.5));
        b.line_to(Point::new(cc.x - 4.5, cc.y - 4.5));
        b.close();
    });
    frame.fill(&fn_north, t(0.50));
    let fn_south = Path::new(|b| {
        b.move_to(Point::new(cc.x, cc.y + 14.0));
        b.line_to(Point::new(cc.x + 4.5, cc.y + 4.5));
        b.line_to(Point::new(cc.x - 4.5, cc.y + 4.5));
        b.close();
    });
    frame.fill(&fn_south, sc(0.30));
    draw_compass_lock(frame, cc, &solid, &t);

    let _ = sc;
}

fn compass_center(cx: f32) -> Point {
    Point::new(cx + COMPASS_DX, COMPASS_Y)
}

fn draw_compass_lock(
    frame: &mut Frame,
    center: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    use iced::widget::canvas::path::Arc;
    use std::f32::consts::PI;
    let x = center.x;
    let y = center.y;
    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 3.0, y - 0.5));
        b.line_to(Point::new(x - 3.0, y - 4.0));
        b.arc(Arc {
            center: Point::new(x, y - 4.0),
            radius: 3.0,
            start_angle: Radians(PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 3.0, y - 0.5));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.1));
    let body = Path::new(|b| {
        b.move_to(Point::new(x - 4.0, y - 0.5));
        b.line_to(Point::new(x + 4.0, y - 0.5));
        b.line_to(Point::new(x + 4.0, y + 4.5));
        b.line_to(Point::new(x - 4.0, y + 4.5));
        b.close();
    });
    frame.fill(&body, t(0.15));
    frame.stroke(&body, solid(t(0.85), 1.1));
}
