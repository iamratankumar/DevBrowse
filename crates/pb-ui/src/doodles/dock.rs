//! The Dock doodle — sailboat, mast + sail, water waves, dock posts, anchor.
//!
//! Accent colours: steel blue #5babd0 (accent1) + sage lime #8cbf52 (accent2).
//! Cursor-driven: boat rocks left/right; pennant points toward cursor.
//! Static cache holds waves + dock + anchor; boat body is uncached.

use iced::widget::canvas::{self, Cache, Frame, Path, Stroke};
use iced::{mouse, Color, Point, Radians, Rectangle, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.357,
    g: 0.671,
    b: 0.816,
    a: 1.0,
}; // #5babd0 steel blue
const A2: Color = Color {
    r: 0.549,
    g: 0.745,
    b: 0.322,
    a: 1.0,
}; // #8cbf52 sage lime

// Waterline Y — boat rocks around this pivot.
const PIVOT_Y: f32 = 120.0;

pub struct DockCache {
    pub cache: Cache,
}

impl DockCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}
impl Default for DockCache {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Debug for DockCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DockCache")
    }
}

pub struct DockProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
    pub cursor_pos: Point,
}

impl<'a> canvas::Program<NewTabMsg> for DockProgram<'a> {
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
        let cx = size.width / 2.0 + 16.0;

        // Rocking tilt: cursor X drives a gentle lean in Standard only.
        let tilt = if self.mode == Mode::Standard {
            ((self.cursor_pos.x - cx) * 0.0006_f32).clamp(-0.10, 0.10)
        } else {
            0.0
        };

        // Layer 1 — cached static geometry: waves + dock + anchor.
        let static_geo = self.cache.draw(renderer, size, |frame| {
            apply_scale(frame, cx);
            if self.mode == Mode::Strict {
                draw_static_strict(frame, cx, self.palette);
            } else {
                draw_static(frame, cx, self.palette);
            }
        });

        // Layer 2 — uncached boat body (hull + mast + sail + pennant), rocking together.
        let mut boat_frame = Frame::new(renderer, size);
        apply_scale(&mut boat_frame, cx);
        boat_frame.with_save(|f| {
            f.translate(Vector::new(cx, PIVOT_Y));
            f.rotate(Radians(tilt));
            if self.mode == Mode::Strict {
                draw_boat_strict(f, self.palette);
            } else {
                draw_boat(f, self.palette);
            }
        });

        vec![static_geo, boat_frame.into_geometry()]
    }
}

fn apply_scale(frame: &mut Frame, cx: f32) {
    frame.translate(Vector::new(cx, 74.0));
    frame.scale(1.3);
    frame.translate(Vector::new(-cx, -74.0));
}

// ── Static layer: waves + dock + anchor ──────────────────────────────────────

fn draw_static(frame: &mut Frame, cx: f32, palette: &'static Palette) {
    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.6_f32 } else { 1.0_f32 };
    let stroke_alpha = if is_dark { 0.55_f32 } else { 0.5_f32 };
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
    let sc_solid = |a: f32, w: f32| Stroke::default().with_color(sc(a)).with_width(w);

    draw_waves(frame, cx, &solid, &a1);
    draw_dock(frame, cx, &sc, &sc_solid);
    draw_anchor(frame, cx, &sc, &a2, &sc_solid);
}

fn draw_static_strict(frame: &mut Frame, cx: f32, palette: &'static Palette) {
    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let sa = if is_dark { 0.45_f32 } else { 0.4_f32 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let sc_solid = |a: f32, w: f32| Stroke::default().with_color(sc(a)).with_width(w);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // ── Locked water: dense flat grid ─────────────────────────────────────────
    for (y, a) in [
        (128.0_f32, 0.45_f32),
        (134.0, 0.35),
        (140.0, 0.28),
        (146.0, 0.20),
        (152.0, 0.14),
        (158.0, 0.09),
    ] {
        let line = Path::new(|b| {
            b.move_to(Point::new(cx - 105.0, y));
            b.line_to(Point::new(cx + 125.0, y));
        });
        frame.stroke(&line, solid(t(a), 1.0));
    }

    // ── Harbor chain boom with center padlock ─────────────────────────────────
    // Left chain half
    for i in 0..5 {
        let x = cx - 90.0 + i as f32 * 18.0;
        let link = Path::new(|b| {
            b.move_to(Point::new(x, 124.0));
            b.quadratic_curve_to(Point::new(x + 5.0, 120.0), Point::new(x + 9.0, 124.0));
        });
        frame.stroke(&link, solid(tc, 2.2));
    }
    // Right chain half
    for i in 0..6 {
        let x = cx + 12.0 + i as f32 * 18.0;
        let link = Path::new(|b| {
            b.move_to(Point::new(x, 124.0));
            b.quadratic_curve_to(Point::new(x + 5.0, 120.0), Point::new(x + 9.0, 124.0));
        });
        frame.stroke(&link, solid(tc, 2.2));
    }
    // Center padlock on the chain
    draw_lock(frame, Point::new(cx, 120.0), &solid, &t);

    // ── Dock with iron grating ─────────────────────────────────────────────────
    // Posts
    for x in [cx - 87.0, cx - 69.0] {
        let post = Path::new(|b| {
            b.move_to(Point::new(x, 118.0));
            b.line_to(Point::new(x, 148.0));
        });
        frame.stroke(&post, sc_solid(0.65, 3.0));
    }
    // Plank top
    let plank = Path::new(|b| {
        b.move_to(Point::new(cx - 97.0, 116.0));
        b.line_to(Point::new(cx - 61.0, 116.0));
        b.line_to(Point::new(cx - 61.0, 122.0));
        b.line_to(Point::new(cx - 97.0, 122.0));
        b.close();
    });
    frame.fill(&plank, t(0.15));
    frame.stroke(&plank, solid(tc, 1.3));
    // Iron grating bars below plank
    for x in [cx - 90.0, cx - 80.0, cx - 70.0] {
        let bar = Path::new(|b| {
            b.move_to(Point::new(x, 122.0));
            b.line_to(Point::new(x, 148.0));
        });
        frame.stroke(&bar, solid(t(0.45), 1.2));
    }
    // Horizontal rail across grating
    let rail = Path::new(|b| {
        b.move_to(Point::new(cx - 97.0, 135.0));
        b.line_to(Point::new(cx - 61.0, 135.0));
    });
    frame.stroke(&rail, solid(t(0.35), 1.0));

    draw_anchor_strict(frame, cx, &sc, &t, &solid, &sc_solid);
}

// ── Boat body: drawn relative to pivot (0,0) = (cx, PIVOT_Y) ────────────────

fn draw_boat(frame: &mut Frame, palette: &'static Palette) {
    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.6_f32 } else { 1.0_f32 };
    let stroke_alpha = if is_dark { 0.55_f32 } else { 0.5_f32 };
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
    let sc_solid = |a: f32, w: f32| Stroke::default().with_color(sc(a)).with_width(w);

    // Hull (pivot-relative: PIVOT_Y=120, deck at 110→-10, hull bottom at 134→+14)
    let hull = Path::new(|b| {
        b.move_to(Point::new(-35.0, 4.0));
        b.quadratic_curve_to(Point::new(0.0, 14.0), Point::new(35.0, 4.0));
        b.line_to(Point::new(25.0, -10.0));
        b.line_to(Point::new(-25.0, -10.0));
        b.close();
    });
    frame.fill(&hull, sc(0.15));
    frame.stroke(&hull, sc_solid(0.6, 2.0));

    let deck = Path::new(|b| {
        b.move_to(Point::new(-25.0, -10.0));
        b.line_to(Point::new(25.0, -10.0));
    });
    frame.stroke(&deck, sc_solid(0.4, 0.8));

    // Mast (deck at -10, tip at -88)
    let mast = Path::new(|b| {
        b.move_to(Point::new(0.0, -10.0));
        b.line_to(Point::new(0.0, -88.0));
    });
    frame.stroke(&mast, sc_solid(0.7, 2.0));

    // Sail
    let sail = Path::new(|b| {
        b.move_to(Point::new(0.0, -84.0));
        b.line_to(Point::new(37.0, -18.0));
        b.line_to(Point::new(0.0, -12.0));
        b.close();
    });
    frame.fill(&sail, a1(0.3));
    frame.stroke(&sail, solid(A1, 1.8));

    let sail_inner = Path::new(|b| {
        b.move_to(Point::new(0.0, -70.0));
        b.line_to(Point::new(27.0, -24.0));
        b.quadratic_curve_to(Point::new(13.0, -25.0), Point::new(0.0, -24.0));
        b.close();
    });
    frame.fill(&sail_inner, a1(0.12));

    // Halyard stub above mast tip
    let halyard = Path::new(|b| {
        b.move_to(Point::new(0.0, -88.0));
        b.line_to(Point::new(0.0, -92.0));
    });
    frame.stroke(&halyard, sc_solid(0.6, 1.2));

    // Pennant at mast tip — rocks with the boat.
    frame.with_save(|f| {
        f.translate(Vector::new(0.0, -88.0));
        draw_pennant(f, palette, Mode::Standard);
    });
}

fn draw_boat_strict(frame: &mut Frame, palette: &'static Palette) {
    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let sa = if is_dark { 0.45_f32 } else { 0.4_f32 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);
    let sc_solid = |a: f32, w: f32| Stroke::default().with_color(sc(a)).with_width(w);

    // ── Armored hull with reinforcement stripes ───────────────────────────────
    let hull = Path::new(|b| {
        b.move_to(Point::new(-35.0, 4.0));
        b.quadratic_curve_to(Point::new(0.0, 14.0), Point::new(35.0, 4.0));
        b.line_to(Point::new(25.0, -10.0));
        b.line_to(Point::new(-25.0, -10.0));
        b.close();
    });
    frame.fill(&hull, t(0.18));
    frame.stroke(&hull, solid(tc, 2.2));

    // Hull plating lines — armored look
    for y in [-4.0_f32, 1.0] {
        let stripe = Path::new(|b| {
            b.move_to(Point::new(-28.0, y));
            b.line_to(Point::new(28.0, y));
        });
        frame.stroke(&stripe, solid(t(0.3), 0.8));
    }

    // ── Bare mast — no sail ───────────────────────────────────────────────────
    let mast = Path::new(|b| {
        b.move_to(Point::new(0.0, -10.0));
        b.line_to(Point::new(0.0, -88.0));
    });
    frame.stroke(&mast, sc_solid(0.65, 2.2));

    // ── Lashed cross-spars (secured for quarantine) ───────────────────────────
    // Upper spar
    let spar_top = Path::new(|b| {
        b.move_to(Point::new(-20.0, -75.0));
        b.line_to(Point::new(20.0, -75.0));
    });
    frame.stroke(&spar_top, solid(tc, 2.0));

    // Lower spar
    let spar_low = Path::new(|b| {
        b.move_to(Point::new(-30.0, -45.0));
        b.line_to(Point::new(30.0, -45.0));
    });
    frame.stroke(&spar_low, solid(tc, 2.0));

    // Lashing knots at spar–mast junctions
    for (sy, r) in [(-75.0_f32, 3.5_f32), (-45.0, 4.0)] {
        let knot = Path::circle(Point::new(0.0, sy), r);
        frame.fill(&knot, t(0.35));
        frame.stroke(&knot, solid(tc, 1.5));
    }

    // Rigging lines from spars down to hull corners (taut, sealed)
    for (sx, sy, hx) in [(-20.0_f32, -75.0_f32, -25.0_f32), (20.0, -75.0, 25.0)] {
        let rig = Path::new(|b| {
            b.move_to(Point::new(sx, sy));
            b.line_to(Point::new(hx, -10.0));
        });
        frame.stroke(&rig, solid(t(0.3), 0.8));
    }
    for (sx, sy, hx) in [(-30.0_f32, -45.0_f32, -25.0_f32), (30.0, -45.0, 25.0)] {
        let rig = Path::new(|b| {
            b.move_to(Point::new(sx, sy));
            b.line_to(Point::new(hx, -10.0));
        });
        frame.stroke(&rig, solid(t(0.25), 0.7));
    }

    // No pennant — embargoed vessel flies nothing.
}

// ── Pennant: drawn at origin, caller rotates toward cursor ────────────────────

fn draw_pennant(frame: &mut Frame, palette: &'static Palette, mode: Mode) {
    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.6_f32 } else { 1.0_f32 };
    let (fill_col, stroke_col) = if mode == Mode::Strict {
        let [tr, tg, tb, _] = crate::design::palette::STRICT;
        let tc = Color::from_rgb(tr, tg, tb);
        (Color { a: 0.85, ..tc }, tc)
    } else {
        (
            Color {
                a: (0.9 * dim).min(1.0),
                ..A2
            },
            A2,
        )
    };
    let pennant = Path::new(|b| {
        b.move_to(Point::ORIGIN);
        b.line_to(Point::new(16.0, -5.0));
        b.line_to(Point::new(0.0, 7.0));
        b.close();
    });
    frame.fill(&pennant, fill_col);
    frame.stroke(
        &pennant,
        Stroke::default().with_color(stroke_col).with_width(1.0),
    );
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn draw_waves(
    frame: &mut Frame,
    cx: f32,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    a1: &impl Fn(f32) -> Color,
) {
    let wave1 = Path::new(|b| {
        b.move_to(Point::new(cx - 105.0, 132.0));
        b.quadratic_curve_to(Point::new(cx - 80.0, 124.0), Point::new(cx - 55.0, 132.0));
        b.quadratic_curve_to(Point::new(cx - 30.0, 140.0), Point::new(cx - 5.0, 132.0));
        b.quadratic_curve_to(Point::new(cx + 20.0, 124.0), Point::new(cx + 45.0, 132.0));
        b.quadratic_curve_to(Point::new(cx + 70.0, 140.0), Point::new(cx + 95.0, 132.0));
        b.quadratic_curve_to(Point::new(cx + 115.0, 126.0), Point::new(cx + 125.0, 130.0));
    });
    frame.stroke(&wave1, solid(a1(0.6), 1.5));

    let wave2 = Path::new(|b| {
        b.move_to(Point::new(cx - 105.0, 142.0));
        b.quadratic_curve_to(Point::new(cx - 80.0, 134.0), Point::new(cx - 55.0, 142.0));
        b.quadratic_curve_to(Point::new(cx - 30.0, 150.0), Point::new(cx - 5.0, 142.0));
        b.quadratic_curve_to(Point::new(cx + 20.0, 134.0), Point::new(cx + 45.0, 142.0));
        b.quadratic_curve_to(Point::new(cx + 70.0, 150.0), Point::new(cx + 95.0, 142.0));
        b.quadratic_curve_to(Point::new(cx + 115.0, 136.0), Point::new(cx + 125.0, 140.0));
    });
    frame.stroke(&wave2, solid(a1(0.35), 1.0));

    let wave3 = Path::new(|b| {
        b.move_to(Point::new(cx - 85.0, 152.0));
        b.quadratic_curve_to(Point::new(cx - 60.0, 144.0), Point::new(cx - 35.0, 152.0));
        b.quadratic_curve_to(Point::new(cx - 10.0, 160.0), Point::new(cx + 15.0, 152.0));
    });
    frame.stroke(&wave3, solid(a1(0.2), 0.8));
}

fn draw_dock(
    frame: &mut Frame,
    cx: f32,
    sc: &impl Fn(f32) -> Color,
    sc_solid: &impl Fn(f32, f32) -> Stroke<'static>,
) {
    for x in [cx - 87.0, cx - 69.0] {
        let post = Path::new(|b| {
            b.move_to(Point::new(x, 118.0));
            b.line_to(Point::new(x, 148.0));
        });
        frame.stroke(&post, sc_solid(0.65, 3.0));
    }
    let plank = Path::new(|b| {
        b.move_to(Point::new(cx - 97.0, 116.0));
        b.line_to(Point::new(cx - 61.0, 116.0));
        b.line_to(Point::new(cx - 61.0, 122.0));
        b.line_to(Point::new(cx - 97.0, 122.0));
        b.close();
    });
    frame.fill(&plank, sc(0.18));
    frame.stroke(&plank, sc_solid(0.5, 1.2));
    let grain = Path::new(|b| {
        b.move_to(Point::new(cx - 97.0, 119.0));
        b.line_to(Point::new(cx - 61.0, 119.0));
    });
    frame.stroke(&grain, sc_solid(0.3, 0.6));
}

fn draw_dock_strict(
    frame: &mut Frame,
    cx: f32,
    sc: &impl Fn(f32) -> Color,
    sc_solid: &impl Fn(f32, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
) {
    for x in [cx - 87.0, cx - 69.0] {
        let post = Path::new(|b| {
            b.move_to(Point::new(x, 118.0));
            b.line_to(Point::new(x, 148.0));
        });
        frame.stroke(&post, sc_solid(0.65, 3.0));
    }
    let plank = Path::new(|b| {
        b.move_to(Point::new(cx - 97.0, 116.0));
        b.line_to(Point::new(cx - 61.0, 116.0));
        b.line_to(Point::new(cx - 61.0, 122.0));
        b.line_to(Point::new(cx - 97.0, 122.0));
        b.close();
    });
    frame.fill(&plank, t(0.15));
    frame.stroke(&plank, solid(sc(0.5), 1.2));
}

fn draw_anchor(
    frame: &mut Frame,
    cx: f32,
    _sc: &impl Fn(f32) -> Color,
    a2: &impl Fn(f32) -> Color,
    sc_solid: &impl Fn(f32, f32) -> Stroke<'static>,
) {
    let ax = cx + 75.0;
    let ay = 80.0_f32;

    let ring = Path::circle(Point::new(ax, ay - 20.0), 6.0);
    frame.fill(&ring, a2(0.22));
    frame.stroke(&ring, Stroke::default().with_color(a2(0.8)).with_width(1.8));

    let shank = Path::new(|b| {
        b.move_to(Point::new(ax, ay - 14.0));
        b.line_to(Point::new(ax, ay + 16.0));
    });
    frame.stroke(&shank, sc_solid(0.65, 2.0));

    let stock = Path::new(|b| {
        b.move_to(Point::new(ax - 14.0, ay - 10.0));
        b.line_to(Point::new(ax + 14.0, ay - 10.0));
    });
    frame.stroke(&stock, sc_solid(0.65, 1.8));

    let flukes = Path::new(|b| {
        b.move_to(Point::new(ax - 16.0, ay + 8.0));
        b.quadratic_curve_to(
            Point::new(ax - 18.0, ay + 20.0),
            Point::new(ax - 6.0, ay + 22.0),
        );
        b.quadratic_curve_to(Point::new(ax, ay + 23.0), Point::new(ax + 6.0, ay + 22.0));
        b.quadratic_curve_to(
            Point::new(ax + 18.0, ay + 20.0),
            Point::new(ax + 16.0, ay + 8.0),
        );
    });
    frame.fill(&flukes, a2(0.15));
    frame.stroke(&flukes, sc_solid(0.55, 1.8));

    let fluke_inner = Path::new(|b| {
        b.move_to(Point::new(ax - 10.0, ay + 14.0));
        b.quadratic_curve_to(Point::new(ax - 6.0, ay + 18.0), Point::new(ax, ay + 18.0));
        b.quadratic_curve_to(
            Point::new(ax + 6.0, ay + 18.0),
            Point::new(ax + 10.0, ay + 14.0),
        );
    });
    frame.stroke(&fluke_inner, sc_solid(0.35, 1.0));
}

fn draw_anchor_strict(
    frame: &mut Frame,
    cx: f32,
    _sc: &impl Fn(f32) -> Color,
    t: &impl Fn(f32) -> Color,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    sc_solid: &impl Fn(f32, f32) -> Stroke<'static>,
) {
    let ax = cx + 75.0;
    let ay = 80.0_f32;

    let ring = Path::circle(Point::new(ax, ay - 20.0), 6.0);
    frame.fill(&ring, t(0.2));
    frame.stroke(&ring, solid(t(1.0), 1.8));

    let shank = Path::new(|b| {
        b.move_to(Point::new(ax, ay - 14.0));
        b.line_to(Point::new(ax, ay + 16.0));
    });
    frame.stroke(&shank, sc_solid(0.65, 2.0));

    let stock = Path::new(|b| {
        b.move_to(Point::new(ax - 14.0, ay - 10.0));
        b.line_to(Point::new(ax + 14.0, ay - 10.0));
    });
    frame.stroke(&stock, sc_solid(0.65, 1.8));

    let flukes = Path::new(|b| {
        b.move_to(Point::new(ax - 16.0, ay + 8.0));
        b.quadratic_curve_to(
            Point::new(ax - 18.0, ay + 20.0),
            Point::new(ax - 6.0, ay + 22.0),
        );
        b.quadratic_curve_to(Point::new(ax, ay + 23.0), Point::new(ax + 6.0, ay + 22.0));
        b.quadratic_curve_to(
            Point::new(ax + 18.0, ay + 20.0),
            Point::new(ax + 16.0, ay + 8.0),
        );
    });
    frame.fill(&flukes, t(0.15));
    frame.stroke(&flukes, sc_solid(0.55, 1.8));
}

fn draw_lock(
    frame: &mut Frame,
    pos: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    use iced::widget::canvas::path::Arc;
    let x = pos.x;
    let y = pos.y;

    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 6.0, y - 4.0));
        b.line_to(Point::new(x - 6.0, y - 10.0));
        b.arc(Arc {
            center: Point::new(x, y - 10.0),
            radius: 6.0,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 6.0, y - 4.0));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.8));

    let body = Path::new(|b| {
        b.move_to(Point::new(x - 9.0, y - 4.0));
        b.line_to(Point::new(x + 9.0, y - 4.0));
        b.line_to(Point::new(x + 9.0, y + 8.0));
        b.line_to(Point::new(x - 9.0, y + 8.0));
        b.close();
    });
    frame.fill(&body, t(0.18));
    frame.stroke(&body, solid(t(0.85), 1.6));

    let khole = Path::circle(Point::new(x, y + 1.5), 2.5);
    frame.fill(&khole, t(0.7));
}
