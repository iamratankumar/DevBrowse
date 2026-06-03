//! Atlas doodle — globe wireframe, mountain ridge, flight arc, storm cell.
//!
//! Accent colours: steel teal #2596a3 (A1) + warm gold #d4a04a (A2).
//! Cursor-driven: airplane slides along the flight arc as cursor moves left/right.
//! Static cache holds globe + mountain + arc path + storm; airplane is uncached.
//! Animation stops in Strict mode.

use std::f32::consts::TAU;

use iced::widget::canvas::path::arc::Elliptical;
use iced::widget::canvas::{self, Cache, Frame, LineDash, Path, Stroke};
use iced::{Color, Point, Radians, Rectangle, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.145,
    g: 0.588,
    b: 0.639,
    a: 1.0,
}; // #2596a3 steel teal
const A2: Color = Color {
    r: 0.831,
    g: 0.627,
    b: 0.290,
    a: 1.0,
}; // #d4a04a warm gold

const DASH_SHORT: &[f32] = &[3.0, 4.0]; // latitude lines
const DASH_LONG: &[f32] = &[6.0, 4.0]; // flight arc

// Flight arc bezier offsets from (cx, cy).
const P0: (f32, f32) = (-49.0, 30.0); // origin
const P1: (f32, f32) = (-25.0, -48.0); // control
const P2: (f32, f32) = (50.0, -20.0); // destination

pub struct AtlasCache {
    pub cache: Cache,
}

impl AtlasCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for AtlasCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AtlasCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AtlasCache")
    }
}

pub struct AtlasProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
    pub cursor_pos: Point,
}

impl canvas::Program<NewTabMsg> for AtlasProgram<'_> {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &iced::Renderer,
        _theme: &iced::Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry<iced::Renderer>> {
        let size = bounds.size();
        let cx = size.width / 2.0;

        let static_geo = self.cache.draw(renderer, size, |frame| {
            if self.mode == Mode::Standard {
                draw_static(frame, size, self.palette);
            } else {
                draw_strict(frame, size, self.palette);
            }
        });

        if self.mode == Mode::Strict {
            return vec![static_geo];
        }

        // Uncached layer: airplane position driven by cursor X.
        let mut plane_frame = Frame::new(renderer, size);
        apply_scale(&mut plane_frame, cx);
        draw_plane(&mut plane_frame, size, self.palette, self.cursor_pos);

        vec![static_geo, plane_frame.into_geometry()]
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn apply_scale(frame: &mut Frame, cx: f32) {
    frame.translate(Vector::new(cx, 95.0));
    frame.scale(1.3);
    frame.translate(Vector::new(-cx, -95.0));
}

/// Quadratic bezier point at parameter t (offsets from cx,cy).
fn bezier_point(t: f32) -> (f32, f32) {
    let u = 1.0 - t;
    let x = u * u * P0.0 + 2.0 * t * u * P1.0 + t * t * P2.0;
    let y = u * u * P0.1 + 2.0 * t * u * P1.1 + t * t * P2.1;
    (x, y)
}

/// Quadratic bezier tangent direction at t (offsets).
fn bezier_tangent(t: f32) -> (f32, f32) {
    let u = 1.0 - t;
    let dx = 2.0 * u * (P1.0 - P0.0) + 2.0 * t * (P2.0 - P1.0);
    let dy = 2.0 * u * (P1.1 - P0.1) + 2.0 * t * (P2.1 - P1.1);
    (dx, dy)
}

// ── Standard static layer ─────────────────────────────────────────────────────

fn draw_static(frame: &mut Frame, size: iced::Size, palette: &'static Palette) {
    let cx = size.width / 2.0;
    let cy = 95.0_f32;

    apply_scale(frame, cx);

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

    // Globe fill + outer ring
    let globe = Path::circle(Point::new(cx, cy), 56.0);
    frame.fill(&globe, a1(0.07));
    frame.stroke(&globe, solid(a1(1.0), 2.2));

    // Meridians
    for rx in [22.0_f32, 44.0] {
        let m = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx, cy),
                radii: Vector::new(rx, 56.0),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        let a = if rx < 30.0 { 0.5 } else { 0.4 };
        frame.stroke(&m, solid(sc(a), 1.0));
    }

    // Equator
    let equator = Path::new(|b| {
        b.ellipse(Elliptical {
            center: Point::new(cx, cy),
            radii: Vector::new(56.0, 18.0),
            rotation: Radians(0.0),
            start_angle: Radians(0.0),
            end_angle: Radians(TAU),
        })
    });
    frame.stroke(&equator, solid(a1(0.8), 1.8));

    // Latitude lines (dashed)
    for (center_y, ry, a) in [
        (cy, 38.0_f32, 0.30_f32),
        (cy - 20.0, 14.0, 0.25),
        (cy + 20.0, 14.0, 0.25),
    ] {
        let lat = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx, center_y),
                radii: Vector::new(if ry > 20.0 { 56.0 } else { 52.0 }, ry),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        frame.stroke(
            &lat,
            Stroke {
                line_dash: LineDash {
                    segments: DASH_SHORT,
                    offset: 0,
                },
                ..solid(sc(a), if ry > 20.0 { 0.8 } else { 0.7 })
            },
        );
    }

    // Mountain ridge
    let ridge = Path::new(|b| {
        b.move_to(Point::new(cx - 37.0, cy - 6.0));
        b.line_to(Point::new(cx - 27.0, cy - 18.0));
        b.line_to(Point::new(cx - 17.0, cy - 10.0));
        b.line_to(Point::new(cx - 9.0, cy - 26.0));
        b.line_to(Point::new(cx - 1.0, cy - 16.0));
        b.line_to(Point::new(cx + 7.0, cy - 28.0));
        b.line_to(Point::new(cx + 17.0, cy - 18.0));
        b.line_to(Point::new(cx + 27.0, cy - 6.0));
        b.line_to(Point::new(cx + 37.0, cy));
    });
    frame.stroke(
        &ridge,
        Stroke::default()
            .with_color(a2(1.0))
            .with_width(2.0)
            .with_line_join(canvas::LineJoin::Round),
    );

    let peak = Path::new(|b| {
        b.move_to(Point::new(cx + 7.0, cy - 28.0));
        b.line_to(Point::new(cx + 9.0, cy - 36.0));
        b.line_to(Point::new(cx + 5.0, cy - 36.0));
        b.close();
    });
    frame.fill(&peak, a2(1.0));
    frame.fill(&Path::circle(Point::new(cx + 7.0, cy - 28.0), 4.5), a2(0.4));
    frame.fill(&Path::circle(Point::new(cx + 7.0, cy - 28.0), 2.5), a2(1.0));

    // Flight arc (dashed) — no airplane here, it's in the uncached layer.
    let arc = Path::new(|b| {
        b.move_to(Point::new(cx + P0.0, cy + P0.1));
        b.quadratic_curve_to(
            Point::new(cx + P1.0, cy + P1.1),
            Point::new(cx + P2.0, cy + P2.1),
        );
    });
    frame.stroke(
        &arc,
        Stroke {
            line_dash: LineDash {
                segments: DASH_LONG,
                offset: 0,
            },
            ..solid(a1(0.65), 1.5)
        },
    );

    // Route endpoint dots
    frame.fill(
        &Path::circle(Point::new(cx + P0.0, cy + P0.1), 3.5),
        a1(0.7),
    );
    frame.fill(
        &Path::circle(Point::new(cx + P2.0, cy + P2.1), 3.5),
        a1(0.7),
    );

    // Storm cell spiral
    let storm = Path::new(|b| {
        b.move_to(Point::new(cx + 27.0, cy + 20.0));
        b.quadratic_curve_to(
            Point::new(cx + 37.0, cy + 10.0),
            Point::new(cx + 33.0, cy + 20.0),
        );
        b.quadratic_curve_to(
            Point::new(cx + 27.0, cy + 30.0),
            Point::new(cx + 17.0, cy + 26.0),
        );
        b.quadratic_curve_to(
            Point::new(cx + 9.0, cy + 20.0),
            Point::new(cx + 15.0, cy + 12.0),
        );
        b.quadratic_curve_to(
            Point::new(cx + 21.0, cy + 6.0),
            Point::new(cx + 27.0, cy + 10.0),
        );
        b.quadratic_curve_to(
            Point::new(cx + 33.0, cy + 14.0),
            Point::new(cx + 29.0, cy + 20.0),
        );
    });
    frame.stroke(&storm, solid(a2(0.55), 1.3));
    frame.fill(
        &Path::circle(Point::new(cx + 23.0, cy + 20.0), 2.5),
        a2(0.5),
    );

    // Axis ticks
    for (p1, p2) in [
        (Point::new(cx, cy - 56.0), Point::new(cx, cy - 64.0)),
        (Point::new(cx, cy + 56.0), Point::new(cx, cy + 70.0)),
        (Point::new(cx - 56.0, cy), Point::new(cx - 62.0, cy)),
        (Point::new(cx + 56.0, cy), Point::new(cx + 62.0, cy)),
    ] {
        let tick = Path::new(|b| {
            b.move_to(p1);
            b.line_to(p2);
        });
        frame.stroke(&tick, solid(a1(0.45), 1.2));
    }
}

// ── Cursor-driven airplane ────────────────────────────────────────────────────

fn draw_plane(frame: &mut Frame, size: iced::Size, palette: &'static Palette, cursor_pos: Point) {
    let cx = size.width / 2.0;
    let cy = 95.0_f32;

    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.65_f32 } else { 1.0 };
    let a1 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A1
    };
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Map cursor X [0, width] → bezier t [0.08, 0.92].
    let t = (cursor_pos.x / size.width).clamp(0.0, 1.0) * 0.84 + 0.08;

    let (bx, by) = bezier_point(t);
    let (dx, dy) = bezier_tangent(t);

    // Rotation: align nose (local 0,-8) with tangent (dx, dy).
    // Iced uses standard math rotation (counterclockwise positive, y-down appears clockwise).
    // atan2(dx, -dy) aligns local (0,-1) with normalized (dx, dy) in screen coords.
    let angle = dx.atan2(-dy);

    frame.with_save(|f| {
        f.translate(Vector::new(cx + bx, cy + by));
        f.rotate(Radians(angle));

        let body = Path::new(|b| {
            b.move_to(Point::new(0.0, -8.0));
            b.line_to(Point::new(2.0, 0.0));
            b.line_to(Point::new(0.0, 2.0));
            b.line_to(Point::new(-2.0, 0.0));
            b.close();
        });
        f.fill(&body, a1(0.9));

        let wing = Path::new(|b| {
            b.move_to(Point::new(-6.0, 0.0));
            b.line_to(Point::new(6.0, 0.0));
        });
        f.stroke(
            &wing,
            solid(a1(0.9), 1.8).with_line_cap(canvas::LineCap::Round),
        );

        let tail = Path::new(|b| {
            b.move_to(Point::new(-3.0, 3.0));
            b.line_to(Point::new(3.0, 3.0));
        });
        f.stroke(
            &tail,
            solid(a1(0.9), 1.2).with_line_cap(canvas::LineCap::Round),
        );
    });
}

// ── Strict ────────────────────────────────────────────────────────────────────

fn draw_strict(frame: &mut Frame, size: iced::Size, palette: &'static Palette) {
    let cx = size.width / 2.0;
    let cy = 95.0_f32;

    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let sa = if is_dark { 0.45_f32 } else { 0.40 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Scan lines before scale so they cover the full canvas.
    let mut y = 0.0_f32;
    while y < size.height {
        let line = Path::new(|b| {
            b.move_to(Point::new(0.0, y));
            b.line_to(Point::new(size.width, y));
        });
        frame.stroke(&line, solid(t(0.06), 0.5));
        y += 6.0;
    }

    apply_scale(frame, cx);

    // Globe
    let globe = Path::circle(Point::new(cx, cy), 56.0);
    frame.fill(&globe, t(0.07));
    frame.stroke(&globe, solid(tc, 2.2));

    // Meridians (grayscale)
    for (rx, a) in [(22.0_f32, 0.4_f32), (44.0, 0.3)] {
        let m = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx, cy),
                radii: Vector::new(rx, 56.0),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        frame.stroke(&m, solid(sc(a), 1.0));
    }

    // Equator (terracotta)
    let equator = Path::new(|b| {
        b.ellipse(Elliptical {
            center: Point::new(cx, cy),
            radii: Vector::new(56.0, 18.0),
            rotation: Radians(0.0),
            start_angle: Radians(0.0),
            end_angle: Radians(TAU),
        })
    });
    frame.stroke(&equator, solid(t(0.7), 1.8));

    let mid_lat = Path::new(|b| {
        b.ellipse(Elliptical {
            center: Point::new(cx, cy),
            radii: Vector::new(56.0, 38.0),
            rotation: Radians(0.0),
            start_angle: Radians(0.0),
            end_angle: Radians(TAU),
        })
    });
    frame.stroke(
        &mid_lat,
        Stroke {
            line_dash: LineDash {
                segments: DASH_SHORT,
                offset: 0,
            },
            ..solid(sc(0.25), 0.8)
        },
    );

    // Fortification wall replacing mountain ridge
    let wall_y = cy - 10.0;
    let wall_base = Path::new(|b| {
        b.move_to(Point::new(cx - 44.0, wall_y));
        b.line_to(Point::new(cx + 44.0, wall_y));
    });
    frame.stroke(&wall_base, solid(tc, 2.0));
    for i in 0..6_i32 {
        let x = cx - 42.0 + i as f32 * 16.0;
        let tooth = Path::new(|b| {
            b.move_to(Point::new(x, wall_y));
            b.line_to(Point::new(x, wall_y - 8.0));
            b.line_to(Point::new(x + 9.0, wall_y - 8.0));
            b.line_to(Point::new(x + 9.0, wall_y));
        });
        frame.stroke(&tooth, solid(tc, 1.8));
    }

    // No-fly zone arc
    let blocked = Path::new(|b| {
        b.move_to(Point::new(cx + P0.0, cy + P0.1));
        b.quadratic_curve_to(
            Point::new(cx + P1.0, cy + P1.1),
            Point::new(cx + P2.0, cy + P2.1),
        );
    });
    frame.stroke(&blocked, solid(t(0.30), 1.5));

    let pr = 8.0_f32;
    let pc = Point::new(cx + 3.0, cy - 42.0);
    frame.stroke(&Path::circle(pc, pr), solid(tc, 1.8));
    let d = pr * std::f32::consts::FRAC_1_SQRT_2;
    let slash = Path::new(|b| {
        b.move_to(Point::new(pc.x - d, pc.y - d));
        b.line_to(Point::new(pc.x + d, pc.y + d));
    });
    frame.stroke(&slash, solid(tc, 1.8));

    frame.fill(
        &Path::circle(Point::new(cx + P0.0, cy + P0.1), 3.0),
        t(0.35),
    );
    frame.fill(
        &Path::circle(Point::new(cx + P2.0, cy + P2.1), 3.0),
        t(0.35),
    );

    // Padlock replacing storm cell
    draw_lock(frame, Point::new(cx + 23.0, cy + 15.0), &solid, &t);

    // Axis ticks
    for (p1, p2, a) in [
        (
            Point::new(cx, cy - 56.0),
            Point::new(cx, cy - 64.0),
            0.5_f32,
        ),
        (Point::new(cx - 56.0, cy), Point::new(cx - 62.0, cy), 0.4),
        (Point::new(cx + 56.0, cy), Point::new(cx + 62.0, cy), 0.4),
    ] {
        let tick = Path::new(|b| {
            b.move_to(p1);
            b.line_to(p2);
        });
        frame.stroke(&tick, solid(t(a), 1.2));
    }
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

    frame.fill(&Path::circle(Point::new(x, y + 1.5), 2.5), t(0.7));
}
