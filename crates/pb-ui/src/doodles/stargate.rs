//! Stargate doodle — vortex spiral gateway, singularity core, stretched stars.
//!
//! Accent colours: cyan #22d3ee (A1) + violet #a78bfa (A2).
//! Static: cache cleared only on palette swap.
//! Strict: chaotic vortex sealed into containment rings; singularity locked.

use std::f32::consts::TAU;

use iced::widget::canvas::{self, path::arc::Elliptical, Cache, Frame, LineDash, Path, Stroke};
use iced::{mouse, Color, Point, Radians, Rectangle, Size, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.133,
    g: 0.827,
    b: 0.933,
    a: 1.0,
}; // #22d3ee cyan
const A2: Color = Color {
    r: 0.655,
    g: 0.545,
    b: 0.980,
    a: 1.0,
}; // #a78bfa violet

const DASH_RIPPLE: &[f32] = &[3.0, 8.0];

pub struct StargateCache {
    pub cache: Cache,
}

impl StargateCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for StargateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for StargateCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StargateCache")
    }
}

pub struct StargateProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
}

impl canvas::Program<NewTabMsg> for StargateProgram<'_> {
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
    let cx = size.width / 2.0;
    let cy = 78.0_f32;

    // 1.25x scale to fit the tall spiral arms within the 190px zone
    frame.translate(Vector::new(cx, 95.0));
    frame.scale(1.25);
    frame.translate(Vector::new(-cx, -95.0));

    let is_dark = palette.is_dark();
    let dim = if is_dark { 0.65_f32 } else { 1.0 };
    let sa = if is_dark { 0.45_f32 } else { 0.40 };
    let [sr, sg, sb, _] = palette.text_primary;
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let a1 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A1
    };
    let a2 = |a: f32| Color {
        a: (a * dim).min(1.0),
        ..A2
    };
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Outer event-horizon ring (faint)
    frame.fill(&Path::circle(Point::new(cx, cy), 58.0), a2(0.05));
    frame.stroke(
        &Path::circle(Point::new(cx, cy), 58.0),
        Stroke {
            line_dash: LineDash {
                segments: DASH_RIPPLE,
                offset: 0,
            },
            ..solid(sc(0.30), 2.5)
        },
    );

    // Vortex spiral arms — 5 nested closed bezier paths converging to center.
    // Offsets are from (cx, cy) = (cx, 78); each arm is a rotated asymmetric oval.
    type Arm = (&'static [(f32, f32, f32, f32)], Color, f32);
    let spirals: &[Arm] = &[
        // (ctrl_x, ctrl_y, end_x, end_y) relative to (cx, cy); each segment pair is one Q
        (
            &[
                (63.0, -54.0, 70.0, 0.0),
                (73.0, 54.0, 20.0, 70.0),
                (-45.0, 80.0, -70.0, 37.0),
                (-95.0, -6.0, -57.0, -40.0),
                (-35.0, -58.0, 0.0, -58.0),
            ],
            a1(0.7),
            1.8,
        ),
        (
            &[
                (53.0, -42.0, 58.0, 0.0),
                (61.0, 42.0, 17.0, 56.0),
                (-37.0, 66.0, -59.0, 30.0),
                (-79.0, -4.0, -47.0, -30.0),
                (-27.0, -46.0, 0.0, -46.0),
            ],
            a1(0.55),
            1.4,
        ),
        (
            &[
                (41.0, -28.0, 45.0, 0.0),
                (47.0, 29.0, 13.0, 40.0),
                (-27.0, 50.0, -45.0, 22.0),
                (-62.0, -4.0, -37.0, -22.0),
                (-22.0, -34.0, 0.0, -32.0),
            ],
            a1(0.40),
            1.1,
        ),
        (
            &[
                (27.0, -16.0, 29.0, 0.0),
                (31.0, 16.0, 13.0, 24.0),
                (-13.0, 32.0, -29.0, 16.0),
                (-43.0, 0.0, -29.0, -14.0),
                (-17.0, -22.0, 0.0, -18.0),
            ],
            a2(0.5),
            1.0,
        ),
        (
            &[
                (15.0, -8.0, 16.0, 0.0),
                (17.0, 10.0, 7.0, 14.0),
                (-7.0, 18.0, -17.0, 8.0),
                (-25.0, 0.0, -17.0, -10.0),
                (-10.0, -16.0, 0.0, -10.0),
            ],
            a2(0.45),
            0.9,
        ),
    ];

    for (segs, color, width) in spirals {
        let path = Path::new(|b| {
            // Start at the last endpoint (which closes back to the first point)
            let last = segs[segs.len() - 1];
            b.move_to(Point::new(cx + last.2, cy + last.3));
            for &(cpx, cpy, epx, epy) in segs.iter() {
                b.quadratic_curve_to(
                    Point::new(cx + cpx, cy + cpy),
                    Point::new(cx + epx, cy + epy),
                );
            }
        });
        frame.stroke(&path, solid(*color, *width));
    }

    // Singularity core (4 nested circles)
    let core = Point::new(cx, cy);
    frame.fill(&Path::circle(core, 16.0), a2(0.10));
    frame.fill(&Path::circle(core, 8.0), a2(0.20));
    frame.fill(&Path::circle(core, 4.0), a2(0.70));
    frame.fill(&Path::circle(core, 2.0), a1(0.90));

    // Stretched stars being pulled in (elongated ellipses at corners)
    let star_data: &[(f32, f32, f32, f32, f32, f32)] = &[
        // dx, dy, rx, ry, rotation_deg, alpha; accent 1
        (-85.0, -46.0, 9.0, 2.5, -28.0, 0.50),
        (85.0, -54.0, 7.0, 2.0, 18.0, 0.40),
    ];
    for &(dx, dy, rx, ry, rot_deg, a) in star_data {
        let star = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx + dx, cy + dy),
                radii: Vector::new(rx, ry),
                rotation: Radians(rot_deg.to_radians()),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        frame.fill(&star, a1(a));
    }
    let star_data2: &[(f32, f32, f32, f32, f32, f32)] = &[
        (-93.0, 50.0, 8.0, 2.2, 32.0, 0.45),
        (93.0, 56.0, 7.0, 2.0, -22.0, 0.40),
    ];
    for &(dx, dy, rx, ry, rot_deg, a) in star_data2 {
        let star = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx + dx, cy + dy),
                radii: Vector::new(rx, ry),
                rotation: Radians(rot_deg.to_radians()),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        frame.fill(&star, a2(a));
    }

    // Distortion ripple (outermost faint dashed ring)
    frame.stroke(
        &Path::circle(Point::new(cx, cy), 68.0),
        Stroke {
            line_dash: LineDash {
                segments: DASH_RIPPLE,
                offset: 0,
            },
            ..solid(a1(0.20), 0.7)
        },
    );

    let _ = sc;
}

// ── Strict — quarantine seal: containment rings, locked core, no transit ──────

fn draw_strict(frame: &mut Frame, size: Size, palette: &'static Palette) {
    let cx = size.width / 2.0;
    let cy = 78.0_f32;

    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let sa = if is_dark { 0.45_f32 } else { 0.38 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Scan lines before scale
    let mut sy = 0.0_f32;
    while sy < size.height {
        let sl = Path::new(|b| {
            b.move_to(Point::new(0.0, sy));
            b.line_to(Point::new(size.width, sy));
        });
        frame.stroke(&sl, solid(t(0.06), 0.5));
        sy += 6.0;
    }

    frame.translate(Vector::new(cx, 95.0));
    frame.scale(1.25);
    frame.translate(Vector::new(-cx, -95.0));

    let core = Point::new(cx, cy);

    // Containment rings (replacing the chaotic vortex spirals)
    // Orderly, evenly spaced concentric rings in terracotta
    for (r, a, w) in [
        (58.0_f32, 0.65_f32, 1.8_f32),
        (46.0, 0.55, 1.5),
        (34.0, 0.45, 1.3),
        (22.0, 0.40, 1.1),
        (11.0, 0.35, 1.0),
    ] {
        frame.stroke(&Path::circle(core, r), solid(t(a), w));
        // Cardinal lock-marks on each ring (short tick at 4 compass points)
        for i in 0..4_usize {
            let angle = i as f32 * TAU / 4.0;
            let (sa_v, ca_v) = (angle.sin(), angle.cos());
            let tick = Path::new(|b| {
                b.move_to(Point::new(
                    core.x + sa_v * (r - 3.0),
                    core.y - ca_v * (r - 3.0),
                ));
                b.line_to(Point::new(
                    core.x + sa_v * (r + 3.0),
                    core.y - ca_v * (r + 3.0),
                ));
            });
            frame.stroke(&tick, solid(t(a * 0.8), w));
        }
    }

    // Faint grayscale fill inside outermost ring
    frame.fill(&Path::circle(core, 57.0), sc(0.04));

    // Singularity core replaced by a vault lock
    frame.fill(&Path::circle(core, 14.0), t(0.10));
    frame.stroke(&Path::circle(core, 14.0), solid(tc, 1.8));
    draw_lock_strict(frame, core, &solid, &t);

    // Star positions replaced by slash (×) marks — transit denied
    let cross_pts: &[(f32, f32)] = &[
        (cx - 85.0, cy - 46.0),
        (cx + 85.0, cy - 54.0),
        (cx - 93.0, cy + 50.0),
        (cx + 93.0, cy + 56.0),
    ];
    for &(x, y) in cross_pts {
        for (dx, dy) in [(-5.0_f32, -3.5), (5.0, 3.5)] {
            let arm = Path::new(|b| {
                b.move_to(Point::new(x + dx, y + dy));
                b.line_to(Point::new(x - dx, y - dy));
            });
            frame.stroke(&arm, solid(t(0.40), 1.2));
        }
        for (dx, dy) in [(5.0_f32, -3.5), (-5.0, 3.5)] {
            let arm = Path::new(|b| {
                b.move_to(Point::new(x + dx, y + dy));
                b.line_to(Point::new(x - dx, y - dy));
            });
            frame.stroke(&arm, solid(t(0.40), 1.2));
        }
    }

    // Outer perimeter warning ring (dashed)
    frame.stroke(
        &Path::circle(core, 68.0),
        Stroke {
            line_dash: LineDash {
                segments: &[4.0, 6.0],
                offset: 0,
            },
            ..solid(t(0.25), 0.8)
        },
    );

    let _ = sc;
}

fn draw_lock_strict(
    frame: &mut Frame,
    center: Point,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    use iced::widget::canvas::path::Arc;
    let x = center.x;
    let y = center.y;

    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 5.5, y - 1.5));
        b.line_to(Point::new(x - 5.5, y - 7.0));
        b.arc(Arc {
            center: Point::new(x, y - 7.0),
            radius: 5.5,
            start_angle: Radians(std::f32::consts::PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 5.5, y - 1.5));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.6));

    let body = Path::new(|b| {
        b.move_to(Point::new(x - 8.0, y - 1.5));
        b.line_to(Point::new(x + 8.0, y - 1.5));
        b.line_to(Point::new(x + 8.0, y + 8.0));
        b.line_to(Point::new(x - 8.0, y + 8.0));
        b.close();
    });
    frame.fill(&body, t(0.18));
    frame.stroke(&body, solid(t(0.85), 1.6));
    frame.fill(&Path::circle(Point::new(x, y + 2.0), 2.0), t(0.7));
}
