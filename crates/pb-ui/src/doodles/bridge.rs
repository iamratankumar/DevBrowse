//! The Bridge doodle — ship's porthole, planet view, helm wheel, console row.
//!
//! Accent colours: sky blue #7dd3fc (A1) + fuchsia #e879f9 (A2).
//! No 1.3× scale — designed natively for the 190 px DOODLE_H zone.
//! Cursor-driven (Standard): planet + ring drift inside the porthole as the
//!   cursor moves; clamped so the planet never exits the porthole rim.
//! Strict: vault door seals the porthole; helm locked; console blocked.

use std::f32::consts::TAU;

use iced::widget::canvas::{self, path::arc::Elliptical, path::Arc, Cache, Frame, Path, Stroke};
use iced::{mouse, Color, Point, Radians, Rectangle, Size, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.490,
    g: 0.827,
    b: 0.988,
    a: 1.0,
}; // #7dd3fc sky blue
const A2: Color = Color {
    r: 0.910,
    g: 0.475,
    b: 0.976,
    a: 1.0,
}; // #e879f9 fuchsia

// Native 190 px layout (no scale).
const PH_DX: f32 = -25.0; // porthole x offset from cx
const PH_Y: f32 = 74.0; // porthole centre y — top edge at y≈20, 20 px margin
const PH_R: f32 = 54.0; // porthole radius
const CN_T: f32 = 136.0; // console top y
const CN_B: f32 = 168.0; // console bottom y
const HW_DX: f32 = 85.0; // helm wheel x offset from cx
const HW_Y: f32 = 151.0; // helm wheel centre y
const HW_R: f32 = 22.0; // helm wheel radius

const PLANET_R: f32 = 16.0;
const PLANET_MAX_R: f32 = PH_R - PLANET_R - 6.0; // clamp planet centre inside porthole

// Default planet offset from porthole centre (used when cursor is off-canvas).
const PLANET_DEFAULT_DX: f32 = 16.0;
const PLANET_DEFAULT_DY: f32 = -9.0;

pub struct BridgeCache {
    pub cache: Cache,
}

impl BridgeCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for BridgeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BridgeCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeCache")
    }
}

pub struct BridgeProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
    pub cursor_pos: Point,
}

impl canvas::Program<NewTabMsg> for BridgeProgram<'_> {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &iced::Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        let size = bounds.size();
        let cx = size.width / 2.0;
        let ph = Point::new(cx + PH_DX, PH_Y);

        let static_geo = self.cache.draw(renderer, size, |frame| {
            if self.mode == Mode::Strict {
                draw_strict(frame, size, self.palette);
            } else {
                draw_static(frame, size, self.palette);
            }
        });

        if self.mode == Mode::Strict {
            return vec![static_geo];
        }

        // Planet position: full canvas maps to porthole interior so the planet
        // can reach every point inside the circle, not just the rim.
        let planet_c = planet_from_cursor(cursor, ph, size);

        let mut dyn_frame = Frame::new(renderer, size);
        draw_planet(&mut dyn_frame, self.palette, planet_c);

        vec![static_geo, dyn_frame.into_geometry()]
    }
}

/// Map the full canvas to the porthole interior so the planet reaches every
/// point inside the circle.
///
/// Cursor at canvas centre → planet at porthole centre.
/// Cursor at any canvas edge → planet at porthole rim (direction preserved).
/// This way the planet explores the full interior, not just the rim.
fn planet_from_cursor(cursor: mouse::Cursor, ph: Point, size: Size) -> Point {
    let raw = match cursor.position() {
        Some(p) => p,
        None => return Point::new(ph.x + PLANET_DEFAULT_DX, ph.y + PLANET_DEFAULT_DY),
    };
    // Normalise cursor: [-1, 1] across the full canvas.
    let nx = (raw.x / size.width.max(1.0)) * 2.0 - 1.0;
    let ny = (raw.y / size.height.max(1.0)) * 2.0 - 1.0;
    let dx = nx * PLANET_MAX_R;
    let dy = ny * PLANET_MAX_R;
    // Clamp to circle so diagonals don't exceed the rim.
    let dist = (dx * dx + dy * dy).sqrt();
    let (fdx, fdy) = if dist <= PLANET_MAX_R {
        (dx, dy)
    } else {
        let s = PLANET_MAX_R / dist;
        (dx * s, dy * s)
    };
    Point::new(ph.x + fdx, ph.y + fdy)
}

// ── Standard static layer ─────────────────────────────────────────────────────

fn draw_static(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0;
    let ph = Point::new(cx + PH_DX, PH_Y);

    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.65_f32 } else { 1.0 };
    let sa = if is_dark { 0.55_f32 } else { 0.50 };
    let [sr, sg, sb, _] = palette.text_primary;
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.55);
    let a1 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A1
    };
    let a2 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A2
    };
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Porthole fill + rings
    frame.fill(&Path::circle(ph, PH_R), a1(0.08));
    frame.stroke(&Path::circle(ph, PH_R), solid(a1(1.0), 2.5));
    frame.stroke(&Path::circle(ph, PH_R - 4.0), solid(a1(0.65), 1.5));

    // Cardinal ticks on porthole rim
    for (dx, dy) in [(0.0_f32, -1.0_f32), (0.0, 1.0), (-1.0, 0.0), (1.0, 0.0)] {
        let tick = Path::new(|b| {
            b.move_to(Point::new(
                ph.x + dx * (PH_R + 1.0),
                ph.y + dy * (PH_R + 1.0),
            ));
            b.line_to(Point::new(
                ph.x + dx * (PH_R + 9.0),
                ph.y + dy * (PH_R + 9.0),
            ));
        });
        frame.stroke(&tick, solid(a1(0.60), 1.5));
    }

    // Static star dots inside the porthole (planet drawn in dynamic layer)
    for (dx, dy, r, a) in [
        (-34.0_f32, -22.0, 2.2_f32, 0.80_f32),
        (8.0, 22.0, 1.8, 0.65),
        (-12.0, 26.0, 1.4, 0.55),
        (6.0, -32.0, 1.2, 0.50),
    ] {
        frame.fill(&Path::circle(Point::new(ph.x + dx, ph.y + dy), r), a2(a));
    }

    // Console strip
    let console = Path::new(|b| {
        b.move_to(Point::new(cx - 95.0, CN_T));
        b.line_to(Point::new(cx + 97.0, CN_T));
        b.line_to(Point::new(cx + 97.0, CN_B));
        b.line_to(Point::new(cx - 95.0, CN_B));
        b.close();
    });
    frame.fill(&console, sc(0.18));
    frame.stroke(&console, solid(sc(1.0), 1.5));

    let dial_y = (CN_T + CN_B) / 2.0;

    // Dial 1 — filled glow
    let d1 = Point::new(cx - 65.0, dial_y);
    frame.fill(&Path::circle(d1, 8.0), a1(0.28));
    frame.stroke(&Path::circle(d1, 8.0), solid(a1(0.9), 1.3));
    frame.fill(&Path::circle(d1, 3.0), a1(0.9));

    // Dial 2 — needle readout
    let d2 = Point::new(cx - 44.0, dial_y);
    frame.stroke(&Path::circle(d2, 8.0), solid(a2(0.8), 1.3));
    let needle = Path::new(|b| {
        b.move_to(d2);
        b.line_to(Point::new(d2.x + 5.0, d2.y - 6.5));
    });
    frame.stroke(&needle, solid(a2(1.0), 1.5));

    // Dial 3 — secondary gauge
    let d3 = Point::new(cx - 23.0, dial_y);
    frame.fill(&Path::circle(d3, 8.0), a1(0.20));
    frame.stroke(&Path::circle(d3, 8.0), solid(a1(0.7), 1.3));
    frame.fill(&Path::circle(d3, 3.5), a1(0.7));

    // Data display screen
    let scr = Path::new(|b| {
        b.move_to(Point::new(cx - 5.0, CN_T + 4.0));
        b.line_to(Point::new(cx + 24.0, CN_T + 4.0));
        b.line_to(Point::new(cx + 24.0, CN_T + 28.0));
        b.line_to(Point::new(cx - 5.0, CN_T + 28.0));
        b.close();
    });
    frame.fill(&scr, a2(0.06));
    frame.stroke(&scr, solid(a2(0.5), 1.0));
    for dy in [6.0_f32, 12.0, 18.0, 24.0] {
        let dl = Path::new(|b| {
            b.move_to(Point::new(cx - 2.0, CN_T + dy));
            b.line_to(Point::new(cx + 21.0, CN_T + dy));
        });
        frame.stroke(&dl, solid(a2(if dy < 14.0 { 0.55 } else { 0.30 }), 0.8));
    }

    // Helm wheel
    let hw = Point::new(cx + HW_DX, HW_Y);
    frame.fill(&Path::circle(hw, HW_R), a2(0.12));
    frame.stroke(&Path::circle(hw, HW_R), solid(a2(1.0), 2.0));
    for i in 0..8_usize {
        let angle = i as f32 * TAU / 8.0;
        let (sv, cv) = (angle.sin(), angle.cos());
        let spoke = Path::new(|b| {
            b.move_to(Point::new(hw.x + sv * 4.5, hw.y - cv * 4.5));
            b.line_to(Point::new(hw.x + sv * HW_R, hw.y - cv * HW_R));
        });
        frame.stroke(&spoke, solid(a2(0.55), 1.1));
        let peg = Path::new(|b| {
            b.move_to(Point::new(hw.x + sv * HW_R, hw.y - cv * HW_R));
            b.line_to(Point::new(
                hw.x + sv * (HW_R + 7.0),
                hw.y - cv * (HW_R + 7.0),
            ));
        });
        frame.stroke(&peg, solid(a2(0.9), 1.8));
    }
    frame.fill(&Path::circle(hw, 4.5), a2(0.7));

    let _ = size;
}

// ── Cursor-driven planet layer (Standard only) ────────────────────────────────

fn draw_planet(frame: &mut Frame, palette: &'static Palette, planet_c: Point) {
    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.65_f32 } else { 1.0 };
    let a2 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A2
    };
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    frame.fill(&Path::circle(planet_c, PLANET_R), a2(0.18));
    frame.stroke(&Path::circle(planet_c, PLANET_R), solid(a2(1.0), 1.5));

    // Orbital ring: slight tilt, rotated with the planet position offset so it
    // appears to wrap around the planet regardless of where it drifts.
    let ring = Path::new(|b| {
        b.ellipse(Elliptical {
            center: planet_c,
            radii: Vector::new(26.0, 7.0),
            rotation: Radians(0.18),
            start_angle: Radians(0.0),
            end_angle: Radians(TAU),
        })
    });
    frame.stroke(&ring, solid(a2(0.50), 1.2));
}

// ── Strict — sealed bridge ────────────────────────────────────────────────────

fn draw_strict(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0;
    let ph = Point::new(cx + PH_DX, PH_Y);

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

    // Vault door
    frame.fill(&Path::circle(ph, PH_R), t(0.08));
    frame.stroke(&Path::circle(ph, PH_R), solid(tc, 2.8));
    frame.stroke(&Path::circle(ph, PH_R - 7.0), solid(t(0.45), 1.2));

    // 8 locking bolts
    for i in 0..8_usize {
        let angle = i as f32 * TAU / 8.0;
        let (sv, cv) = (angle.sin(), angle.cos());
        let bc = Point::new(ph.x + sv * (PH_R - 11.0), ph.y - cv * (PH_R - 11.0));
        let bolt = Path::new(|b| {
            b.move_to(Point::new(bc.x - cv * 5.0, bc.y - sv * 5.0));
            b.line_to(Point::new(bc.x + cv * 5.0, bc.y + sv * 5.0));
        });
        frame.stroke(&bolt, solid(t(0.75), 2.8));
    }

    // Crosshatch inside sealed porthole
    for dy in [-30.0_f32, -18.0, -6.0, 6.0, 18.0, 30.0] {
        let y = ph.y + dy;
        let dx = (PH_R * PH_R - dy * dy).max(0.0).sqrt() - 5.0;
        if dx > 0.0 {
            let hatch = Path::new(|b| {
                b.move_to(Point::new(ph.x - dx, y));
                b.line_to(Point::new(ph.x + dx, y));
            });
            frame.stroke(&hatch, solid(sc(0.18), 0.7));
        }
    }

    draw_keyhole(frame, ph, &solid, &t);

    // Console
    let console = Path::new(|b| {
        b.move_to(Point::new(cx - 95.0, CN_T));
        b.line_to(Point::new(cx + 97.0, CN_T));
        b.line_to(Point::new(cx + 97.0, CN_B));
        b.line_to(Point::new(cx - 95.0, CN_B));
        b.close();
    });
    frame.fill(&console, sc(0.10));
    frame.stroke(&console, solid(t(0.55), 1.5));

    let dial_y = (CN_T + CN_B) / 2.0;
    for dx_off in [cx - 65.0, cx - 44.0, cx - 23.0] {
        let dc = Point::new(dx_off, dial_y);
        frame.stroke(&Path::circle(dc, 8.0), solid(t(0.5), 1.3));
        let x1 = Path::new(|b| {
            b.move_to(Point::new(dc.x - 5.5, dc.y - 5.5));
            b.line_to(Point::new(dc.x + 5.5, dc.y + 5.5));
        });
        let x2 = Path::new(|b| {
            b.move_to(Point::new(dc.x + 5.5, dc.y - 5.5));
            b.line_to(Point::new(dc.x - 5.5, dc.y + 5.5));
        });
        frame.stroke(&x1, solid(t(0.7), 1.2));
        frame.stroke(&x2, solid(t(0.7), 1.2));
    }

    let scr = Path::new(|b| {
        b.move_to(Point::new(cx - 5.0, CN_T + 4.0));
        b.line_to(Point::new(cx + 24.0, CN_T + 4.0));
        b.line_to(Point::new(cx + 24.0, CN_T + 28.0));
        b.line_to(Point::new(cx - 5.0, CN_T + 28.0));
        b.close();
    });
    frame.fill(&scr, t(0.07));
    frame.stroke(&scr, solid(t(0.5), 1.0));
    for dy in [8.0_f32, 16.0, 24.0] {
        let bl = Path::new(|b| {
            b.move_to(Point::new(cx - 2.0, CN_T + dy));
            b.line_to(Point::new(cx + 21.0, CN_T + dy));
        });
        frame.stroke(&bl, solid(t(0.55), 2.0));
    }

    let hw = Point::new(cx + HW_DX, HW_Y);
    frame.fill(&Path::circle(hw, HW_R), t(0.08));
    frame.stroke(&Path::circle(hw, HW_R), solid(tc, 2.0));
    let cp1 = Path::new(|b| {
        b.move_to(Point::new(hw.x - HW_R * 0.65, hw.y - HW_R * 0.65));
        b.line_to(Point::new(hw.x + HW_R * 0.65, hw.y + HW_R * 0.65));
    });
    let cp2 = Path::new(|b| {
        b.move_to(Point::new(hw.x + HW_R * 0.65, hw.y - HW_R * 0.65));
        b.line_to(Point::new(hw.x - HW_R * 0.65, hw.y + HW_R * 0.65));
    });
    frame.stroke(&cp1, solid(t(0.65), 2.0));
    frame.stroke(&cp2, solid(t(0.65), 2.0));
    draw_padlock_mini(frame, Point::new(hw.x, hw.y - 6.0), &solid, &t);

    let _ = sc;
}

fn draw_keyhole(
    frame: &mut Frame,
    center: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    let x = center.x;
    let y = center.y;
    frame.fill(&Path::circle(Point::new(x, y - 2.0), 9.0), t(0.18));
    frame.stroke(
        &Path::circle(Point::new(x, y - 2.0), 9.0),
        solid(t(0.8), 1.8),
    );
    let slot = Path::new(|b| {
        b.move_to(Point::new(x - 6.0, y - 2.0));
        b.line_to(Point::new(x + 6.0, y - 2.0));
        b.line_to(Point::new(x + 3.0, y + 10.0));
        b.line_to(Point::new(x - 3.0, y + 10.0));
        b.close();
    });
    frame.fill(&slot, t(0.75));
}

fn draw_padlock_mini(
    frame: &mut Frame,
    pos: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    let x = pos.x;
    let y = pos.y;
    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 4.5, y));
        b.line_to(Point::new(x - 4.5, y - 5.0));
        b.arc(Arc {
            center: Point::new(x, y - 5.0),
            radius: 4.5,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 4.5, y));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.4));
    let body = Path::new(|b| {
        b.move_to(Point::new(x - 6.5, y));
        b.line_to(Point::new(x + 6.5, y));
        b.line_to(Point::new(x + 6.5, y + 7.0));
        b.line_to(Point::new(x - 6.5, y + 7.0));
        b.close();
    });
    frame.fill(&body, t(0.15));
    frame.stroke(&body, solid(t(0.85), 1.4));
    frame.fill(&Path::circle(Point::new(x, y + 3.0), 2.0), t(0.7));
}
