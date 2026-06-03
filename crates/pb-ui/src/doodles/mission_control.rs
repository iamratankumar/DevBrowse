//! Mission Control doodle — Saturn, rocket, spacewalking astronaut.
//!
//! Accent colours: cyan teal #5eead4 (A1) + warm orange #fb923c (A2).
//! Cursor-driven: astronaut drifts + tilts with cursor (zero-g float). Static in Strict.

use std::f32::consts::{PI, TAU};

use iced::widget::canvas::path::arc::Elliptical;
use iced::widget::canvas::{self, Cache, Frame, Path, Stroke};
use iced::{Color, Point, Radians, Rectangle, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.369,
    g: 0.918,
    b: 0.831,
    a: 1.0,
}; // #5eead4 cyan teal
const A2: Color = Color {
    r: 0.984,
    g: 0.573,
    b: 0.235,
    a: 1.0,
}; // #fb923c warm orange

const PLANET_Y: f32 = 82.0;
const ROCKET_DX: f32 = -95.0; // x offset from cx
const ROCKET_Y: f32 = 47.0;
const ASTRO_DX: f32 = 89.0; // x offset from cx
const ASTRO_Y: f32 = 115.0;

pub struct MissionControlCache {
    pub cache: Cache,
}

impl MissionControlCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
        }
    }
}

impl Default for MissionControlCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MissionControlCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MissionControlCache")
    }
}

pub struct MissionControlProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
    pub cursor_pos: Point,
}

impl canvas::Program<NewTabMsg> for MissionControlProgram<'_> {
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

        // Uncached: astronaut drifts + tilts with cursor (zero-g float).
        let mut astro_frame = Frame::new(renderer, size);
        apply_scale(&mut astro_frame, cx);
        draw_astronaut_floating(&mut astro_frame, size, self.palette, self.cursor_pos);

        vec![static_geo, astro_frame.into_geometry()]
    }
}

fn apply_scale(frame: &mut Frame, cx: f32) {
    frame.translate(Vector::new(cx, 95.0));
    frame.scale(1.3);
    frame.translate(Vector::new(-cx, -95.0));
}

// ── Standard static layer ─────────────────────────────────────────────────────

fn draw_static(frame: &mut Frame, size: iced::Size, palette: &'static Palette) {
    let cx = size.width / 2.0;
    let cy = PLANET_Y;

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

    // ── Saturn rings ──────────────────────────────────────────────────────────
    let ring1 = Path::new(|b| {
        b.ellipse(Elliptical {
            center: Point::new(cx, cy),
            radii: Vector::new(70.0, 20.0),
            rotation: Radians(0.0),
            start_angle: Radians(0.0),
            end_angle: Radians(TAU),
        })
    });
    frame.stroke(&ring1, solid(a1(0.55), 1.5));

    // Second ring tilted -8°
    frame.with_save(|f| {
        f.translate(Vector::new(cx, cy));
        f.rotate(Radians(-8.0 * PI / 180.0));
        f.translate(Vector::new(-cx, -cy));
        let ring2 = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx, cy),
                radii: Vector::new(70.0, 20.0),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        f.stroke(&ring2, solid(a1(0.30), 1.0));
    });

    // ── Planet ────────────────────────────────────────────────────────────────
    let planet = Path::circle(Point::new(cx, cy), 42.0);
    frame.fill(&planet, a1(0.08));
    frame.stroke(&planet, solid(a1(1.0), 2.2));

    // Surface latitude curves
    let upper = Path::new(|b| {
        b.move_to(Point::new(cx - 27.0, cy - 15.0));
        b.quadratic_curve_to(
            Point::new(cx - 13.0, cy - 19.0),
            Point::new(cx + 3.0, cy - 15.0),
        );
    });
    frame.stroke(&upper, solid(a1(0.5), 1.0));

    let lower = Path::new(|b| {
        b.move_to(Point::new(cx - 15.0, cy + 13.0));
        b.quadratic_curve_to(
            Point::new(cx + 5.0, cy + 19.0),
            Point::new(cx + 23.0, cy + 13.0),
        );
    });
    frame.stroke(&lower, solid(a1(0.5), 1.0));

    frame.fill(
        &Path::circle(Point::new(cx - 13.0, cy - 7.0), 3.0),
        a1(0.30),
    );
    frame.fill(
        &Path::circle(Point::new(cx + 13.0, cy + 7.0), 2.5),
        a1(0.25),
    );

    // ── Rocket (static, fixed angle) ──────────────────────────────────────────
    frame.with_save(|f| {
        f.translate(Vector::new(cx + ROCKET_DX, ROCKET_Y));
        f.rotate(Radians(-PI / 6.0)); // ~-30°, matching original mock orientation
        draw_rocket_body(f, &a2, &solid);
    });

    // ── Stars ─────────────────────────────────────────────────────────────────
    draw_star(frame, Point::new(cx - 115.0, 125.0), 5.0, a1(0.45));
    draw_star(frame, Point::new(cx + 110.0, 45.0), 4.5, a2(0.40));
    draw_star(frame, Point::new(cx + 45.0, 25.0), 3.5, sc(0.35));
}

// ── Cursor-driven astronaut (zero-g float) ────────────────────────────────────

fn draw_astronaut_floating(
    frame: &mut Frame,
    size: iced::Size,
    palette: &'static Palette,
    cursor_pos: Point,
) {
    let cx = size.width / 2.0;
    let cy = 95.0_f32;

    // Drift: cursor offset from canvas centre maps to a gentle positional shift.
    let norm_x = ((cursor_pos.x - cx) / cx).clamp(-1.0, 1.0);
    let norm_y = ((cursor_pos.y - cy) / cy).clamp(-1.0, 1.0);
    let drift_x = norm_x * 18.0;
    let drift_y = norm_y * 10.0;
    // Slight body tilt — astronaut leans into the drift direction.
    let tilt = norm_x * 0.08; // ±~4.6°

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

    // Rotate the astronaut around their waist before translating so the tilt
    // is applied in local space.
    frame.with_save(|f| {
        f.translate(Vector::new(cx + ASTRO_DX + drift_x, ASTRO_Y + drift_y));
        f.rotate(Radians(tilt));
        f.translate(Vector::new(
            -(cx + ASTRO_DX + drift_x),
            -(ASTRO_Y + drift_y),
        ));
        draw_astronaut(
            f,
            cx + ASTRO_DX + drift_x,
            ASTRO_Y + drift_y,
            &sc,
            &a1,
            &a2,
            &solid,
        );
    });
}

fn draw_rocket_body(
    frame: &mut Frame,
    a2: &impl Fn(f32) -> Color,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
) {
    // Body: nose at (0,−22), base at y=14.
    let body = Path::new(|b| {
        b.move_to(Point::new(0.0, -22.0));
        b.quadratic_curve_to(Point::new(6.0, -22.0), Point::new(8.0, -10.0));
        b.line_to(Point::new(8.0, 10.0));
        b.quadratic_curve_to(Point::new(8.0, 14.0), Point::new(4.0, 14.0));
        b.line_to(Point::new(-4.0, 14.0));
        b.quadratic_curve_to(Point::new(-8.0, 14.0), Point::new(-8.0, 10.0));
        b.line_to(Point::new(-8.0, -10.0));
        b.quadratic_curve_to(Point::new(-6.0, -22.0), Point::new(0.0, -22.0));
        b.close();
    });
    frame.fill(&body, a2(0.18));
    frame.stroke(&body, solid(a2(1.0), 2.0));

    // Porthole
    frame.stroke(
        &Path::circle(Point::new(0.0, -6.0), 4.0),
        solid(a2(1.0), 1.4),
    );

    // Fins
    for sign in [-1.0_f32, 1.0] {
        let fin = Path::new(|b| {
            b.move_to(Point::new(sign * 8.0, 6.0));
            b.line_to(Point::new(sign * 14.0, 16.0));
            b.line_to(Point::new(sign * 4.0, 14.0));
            b.close();
        });
        frame.fill(&fin, a2(0.5));
        frame.stroke(&fin, solid(a2(1.0), 1.2));
    }

    // Exhaust plumes
    let ex1 = Path::new(|b| {
        b.move_to(Point::new(-3.0, 14.0));
        b.quadratic_curve_to(Point::new(0.0, 24.0), Point::new(3.0, 14.0));
    });
    frame.stroke(&ex1, solid(a2(0.45), 1.5));

    let ex2 = Path::new(|b| {
        b.move_to(Point::new(-2.0, 22.0));
        b.quadratic_curve_to(Point::new(0.0, 30.0), Point::new(2.0, 22.0));
    });
    frame.stroke(&ex2, solid(a2(0.30), 1.2));
}

// ── Astronaut ─────────────────────────────────────────────────────────────────

fn draw_astronaut(
    frame: &mut Frame,
    ax: f32,
    ay: f32,
    sc: &impl Fn(f32) -> Color,
    a1: &impl Fn(f32) -> Color,
    a2: &impl Fn(f32) -> Color,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
) {
    frame.with_save(|f| {
        f.translate(Vector::new(ax, ay));

        // Backpack (draw first, behind torso)
        let backpack = Path::new(|b| {
            b.move_to(Point::new(8.0, -7.0));
            b.line_to(Point::new(17.0, -7.0));
            b.line_to(Point::new(17.0, 9.0));
            b.line_to(Point::new(8.0, 9.0));
            b.close();
        });
        f.fill(&backpack, sc(0.15));
        f.stroke(&backpack, solid(sc(0.5), 1.0));

        // Torso
        let torso = Path::new(|b| {
            b.move_to(Point::new(-12.0, -6.0));
            b.line_to(Point::new(10.0, -6.0));
            b.line_to(Point::new(10.0, 16.0));
            b.line_to(Point::new(-12.0, 16.0));
            b.close();
        });
        f.fill(&torso, sc(0.15));
        f.stroke(&torso, solid(sc(0.60), 1.8));

        // Chest display
        let chest = Path::new(|b| {
            b.move_to(Point::new(-6.0, -2.0));
            b.line_to(Point::new(7.0, -2.0));
            b.line_to(Point::new(7.0, 7.0));
            b.line_to(Point::new(-6.0, 7.0));
            b.close();
        });
        f.fill(&chest, a1(0.22));
        f.stroke(&chest, solid(a1(0.6), 1.0));
        f.fill(&Path::circle(Point::new(-3.0, 1.5), 1.5), a2(0.80));
        f.fill(&Path::circle(Point::new(1.0, 1.5), 1.5), a1(0.80));
        f.fill(&Path::circle(Point::new(5.0, 1.5), 1.5), sc(0.60));

        // Left arm + glove
        let arm_l = Path::new(|b| {
            b.move_to(Point::new(-12.0, 0.0));
            b.line_to(Point::new(-22.0, 9.0));
            b.line_to(Point::new(-20.0, 14.0));
        });
        f.stroke(
            &arm_l,
            solid(sc(0.70), 3.5)
                .with_line_cap(canvas::LineCap::Round)
                .with_line_join(canvas::LineJoin::Round),
        );
        f.fill(&Path::circle(Point::new(-20.0, 14.0), 4.5), sc(0.28));
        f.stroke(
            &Path::circle(Point::new(-20.0, 14.0), 4.5),
            solid(sc(0.50), 1.3),
        );

        // Flag patch on left arm
        let flag = Path::new(|b| {
            b.move_to(Point::new(-26.0, 2.0));
            b.line_to(Point::new(-17.0, 2.0));
            b.line_to(Point::new(-17.0, 8.0));
            b.line_to(Point::new(-26.0, 8.0));
            b.close();
        });
        f.fill(&flag, a2(0.45));
        f.stroke(&flag, solid(a2(0.70), 0.5));
        for fy in [4.0_f32, 6.0] {
            let stripe = Path::new(|b| {
                b.move_to(Point::new(-26.0, fy));
                b.line_to(Point::new(-17.0, fy));
            });
            f.stroke(&stripe, solid(sc(0.50), 0.5));
        }

        // Right arm + glove (outstretched)
        let arm_r = Path::new(|b| {
            b.move_to(Point::new(10.0, 0.0));
            b.line_to(Point::new(21.0, 7.0));
            b.line_to(Point::new(23.0, 13.0));
        });
        f.stroke(
            &arm_r,
            solid(sc(0.70), 3.5)
                .with_line_cap(canvas::LineCap::Round)
                .with_line_join(canvas::LineJoin::Round),
        );
        f.fill(&Path::circle(Point::new(23.0, 13.0), 4.5), sc(0.28));
        f.stroke(
            &Path::circle(Point::new(23.0, 13.0), 4.5),
            solid(sc(0.50), 1.3),
        );

        // Legs
        let leg_l = Path::new(|b| {
            b.move_to(Point::new(-5.0, 16.0));
            b.line_to(Point::new(-7.0, 30.0));
        });
        f.stroke(
            &leg_l,
            solid(sc(0.65), 4.0).with_line_cap(canvas::LineCap::Round),
        );
        let leg_r = Path::new(|b| {
            b.move_to(Point::new(5.0, 16.0));
            b.line_to(Point::new(7.0, 30.0));
        });
        f.stroke(
            &leg_r,
            solid(sc(0.65), 4.0).with_line_cap(canvas::LineCap::Round),
        );

        // Boots
        for bx in [-7.0_f32, 7.0] {
            let boot = Path::new(|b| {
                b.ellipse(Elliptical {
                    center: Point::new(bx, 31.0),
                    radii: Vector::new(7.0, 3.5),
                    rotation: Radians(0.0),
                    start_angle: Radians(0.0),
                    end_angle: Radians(TAU),
                })
            });
            f.fill(&boot, sc(0.30));
            f.stroke(&boot, solid(sc(0.50), 1.2));
        }

        // Helmet (drawn after torso so it overlaps the collar)
        let helmet = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(0.0, -20.0),
                radii: Vector::new(12.0, 14.0),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        f.fill(&helmet, sc(0.18));
        f.stroke(&helmet, solid(sc(0.60), 1.8));

        // Gold visor
        let visor = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(1.0, -21.0),
                radii: Vector::new(8.0, 9.0),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        f.fill(&visor, a2(0.28));
        f.stroke(&visor, solid(a2(0.60), 1.0));

        // Visor highlight
        let hl = Path::new(|b| {
            b.move_to(Point::new(-4.0, -27.0));
            b.line_to(Point::new(-2.0, -24.0));
        });
        f.stroke(&hl, solid(sc(0.75), 1.3));
    });
}

// ── Stars ─────────────────────────────────────────────────────────────────────

fn draw_star(frame: &mut Frame, center: Point, size: f32, col: Color) {
    let star = Path::new(|b| {
        let inner = size * 0.38;
        for i in 0..8_u32 {
            let angle = i as f32 * std::f32::consts::FRAC_PI_4;
            let r = if i % 2 == 0 { size } else { inner };
            let p = Point::new(center.x + r * angle.sin(), center.y - r * angle.cos());
            if i == 0 {
                b.move_to(p);
            } else {
                b.line_to(p);
            }
        }
        b.close();
    });
    frame.fill(&star, col);
}

// ── Strict ────────────────────────────────────────────────────────────────────

fn draw_strict(frame: &mut Frame, size: iced::Size, palette: &'static Palette) {
    let cx = size.width / 2.0;
    let cy = PLANET_Y;

    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let sa = if is_dark { 0.45_f32 } else { 0.40 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    // Denser scan lines — reinforces surveillance feel.
    let mut y = 0.0_f32;
    while y < size.height {
        let line = Path::new(|b| {
            b.move_to(Point::new(0.0, y));
            b.line_to(Point::new(size.width, y));
        });
        frame.stroke(&line, solid(t(0.09), 0.5));
        y += 5.0;
    }

    apply_scale(frame, cx);

    // ── Exclusion-zone rings (heavier, terracotta) ────────────────────────────
    for (rx, ry, w, a) in [
        (70.0_f32, 20.0_f32, 2.5_f32, 1.0_f32),
        (78.0, 22.0, 1.0, 0.35),
    ] {
        let ring = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx, cy),
                radii: Vector::new(rx, ry),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        frame.stroke(&ring, solid(t(a), w));
    }
    // Tick marks around outer ring — quarantine perimeter markers.
    for i in 0..12_u32 {
        let angle = i as f32 * TAU / 12.0;
        let (sa, ca) = angle.sin_cos();
        let tick = Path::new(|b| {
            b.move_to(Point::new(cx + 78.0 * sa, cy - 22.0 * ca));
            b.line_to(Point::new(cx + 85.0 * sa, cy - 26.0 * ca));
        });
        frame.stroke(&tick, solid(t(0.5), 1.2));
    }

    // ── Planet with aggressive targeting overlay ──────────────────────────────
    let planet = Path::circle(Point::new(cx, cy), 42.0);
    frame.fill(&planet, t(0.08));
    frame.stroke(&planet, solid(tc, 2.2));

    // Full-span crosshairs through planet
    for (dx, dy) in [(56.0_f32, 0.0_f32), (0.0, 56.0)] {
        let crosshair = Path::new(|b| {
            b.move_to(Point::new(cx - dx, cy - dy));
            b.line_to(Point::new(cx + dx, cy + dy));
        });
        frame.stroke(&crosshair, solid(t(0.35), 0.9));
    }

    // Inner reticle + corner brackets at 45° positions
    frame.stroke(&Path::circle(Point::new(cx, cy), 20.0), solid(tc, 1.4));
    frame.stroke(&Path::circle(Point::new(cx, cy), 8.0), solid(t(0.6), 1.0));
    for i in [1_u32, 3, 5, 7] {
        let angle = i as f32 * std::f32::consts::FRAC_PI_4;
        let (sa, ca) = angle.sin_cos();
        let bracket = Path::new(|b| {
            b.move_to(Point::new(cx + 18.0 * sa, cy - 18.0 * ca));
            b.line_to(Point::new(cx + 24.0 * sa, cy - 24.0 * ca));
        });
        frame.stroke(&bracket, solid(tc, 1.8));
    }

    // ── Surveillance satellite ────────────────────────────────────────────────
    // Positioned at upper-right of scene
    let sx = cx + 60.0;
    let sy = cy - 52.0;
    // Body
    let sat_body = Path::new(|b| {
        b.move_to(Point::new(sx - 7.0, sy - 5.0));
        b.line_to(Point::new(sx + 7.0, sy - 5.0));
        b.line_to(Point::new(sx + 7.0, sy + 5.0));
        b.line_to(Point::new(sx - 7.0, sy + 5.0));
        b.close();
    });
    frame.fill(&sat_body, t(0.20));
    frame.stroke(&sat_body, solid(tc, 1.6));
    // Solar panels (left + right wings)
    for sx_off in [-18.0_f32, 10.0] {
        let panel = Path::new(|b| {
            b.move_to(Point::new(sx + sx_off, sy - 3.0));
            b.line_to(Point::new(sx + sx_off + 8.0, sy - 3.0));
            b.line_to(Point::new(sx + sx_off + 8.0, sy + 3.0));
            b.line_to(Point::new(sx + sx_off, sy + 3.0));
            b.close();
        });
        frame.fill(&panel, t(0.15));
        frame.stroke(&panel, solid(t(0.6), 1.0));
        // Panel divider
        let div = Path::new(|b| {
            b.move_to(Point::new(sx + sx_off + 4.0, sy - 3.0));
            b.line_to(Point::new(sx + sx_off + 4.0, sy + 3.0));
        });
        frame.stroke(&div, solid(t(0.35), 0.7));
    }
    // Signal arc from satellite to planet
    let sig = Path::new(|b| {
        b.move_to(Point::new(sx, sy + 5.0));
        b.quadratic_curve_to(
            Point::new(cx + 30.0, cy - 30.0),
            Point::new(cx + 20.0, cy - 38.0),
        );
    });
    frame.stroke(&sig, solid(t(0.40), 1.0));
    // Dish antenna on satellite body
    let dish = Path::new(|b| {
        b.move_to(Point::new(sx, sy + 5.0));
        b.line_to(Point::new(sx - 4.0, sy + 11.0));
        b.quadratic_curve_to(Point::new(sx, sy + 14.0), Point::new(sx + 4.0, sy + 11.0));
    });
    frame.stroke(&dish, solid(tc, 1.2));

    // ── ICBM (sealed, no exhaust) ─────────────────────────────────────────────
    frame.with_save(|f| {
        f.translate(Vector::new(cx + ROCKET_DX, ROCKET_Y));
        f.rotate(Radians(-PI * 0.4));

        let body = Path::new(|b| {
            b.move_to(Point::new(0.0, -22.0));
            b.quadratic_curve_to(Point::new(6.0, -22.0), Point::new(8.0, -10.0));
            b.line_to(Point::new(8.0, 10.0));
            b.quadratic_curve_to(Point::new(8.0, 14.0), Point::new(4.0, 14.0));
            b.line_to(Point::new(-4.0, 14.0));
            b.quadratic_curve_to(Point::new(-8.0, 14.0), Point::new(-8.0, 10.0));
            b.line_to(Point::new(-8.0, -10.0));
            b.quadratic_curve_to(Point::new(-6.0, -22.0), Point::new(0.0, -22.0));
            b.close();
        });
        f.fill(&body, t(0.20));
        f.stroke(&body, solid(tc, 2.2));

        // Warning chevron bands
        for y_band in [-8.0_f32, 0.0, 8.0] {
            let band = Path::new(|b| {
                b.move_to(Point::new(-8.0, y_band));
                b.line_to(Point::new(8.0, y_band));
            });
            f.stroke(&band, solid(t(0.45), 1.0));
        }

        // Fins
        for sign in [-1.0_f32, 1.0] {
            let fin = Path::new(|b| {
                b.move_to(Point::new(sign * 8.0, 6.0));
                b.line_to(Point::new(sign * 14.0, 16.0));
                b.line_to(Point::new(sign * 4.0, 14.0));
                b.close();
            });
            f.fill(&fin, t(0.35));
            f.stroke(&fin, solid(tc, 1.4));
        }
    });

    // ── Tethered astronaut (controlled, not free) ─────────────────────────────
    let ax = cx + ASTRO_DX;
    let ay = ASTRO_Y;

    // Tether line from waist to planet edge — they're anchored, not floating free.
    let tether = Path::new(|b| {
        b.move_to(Point::new(ax - 12.0, ay + 5.0));
        b.quadratic_curve_to(
            Point::new(cx + 10.0, cy + 20.0),
            Point::new(cx + 42.0, cy + 10.0),
        );
    });
    frame.stroke(&tether, solid(t(0.55), 1.2));

    // Astronaut body (same structure, terracotta visor + padlock chest)
    draw_astronaut_strict(frame, ax, ay, &sc, &t, &solid);
}

fn draw_astronaut_strict(
    frame: &mut Frame,
    ax: f32,
    ay: f32,
    sc: &impl Fn(f32) -> Color,
    t: &impl Fn(f32) -> Color,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
) {
    frame.with_save(|f| {
        f.translate(Vector::new(ax, ay));

        let backpack = Path::new(|b| {
            b.move_to(Point::new(8.0, -7.0));
            b.line_to(Point::new(17.0, -7.0));
            b.line_to(Point::new(17.0, 9.0));
            b.line_to(Point::new(8.0, 9.0));
            b.close();
        });
        f.fill(&backpack, sc(0.12));
        f.stroke(&backpack, solid(sc(0.40), 1.0));

        let torso = Path::new(|b| {
            b.move_to(Point::new(-12.0, -6.0));
            b.line_to(Point::new(10.0, -6.0));
            b.line_to(Point::new(10.0, 16.0));
            b.line_to(Point::new(-12.0, 16.0));
            b.close();
        });
        f.fill(&torso, sc(0.12));
        f.stroke(&torso, solid(sc(0.55), 1.8));

        // Padlock on chest
        draw_chest_lock(f, solid, t);

        // Arms down (subdued, not outstretched)
        let arm_l = Path::new(|b| {
            b.move_to(Point::new(-12.0, 0.0));
            b.line_to(Point::new(-18.0, 12.0));
            b.line_to(Point::new(-16.0, 18.0));
        });
        f.stroke(
            &arm_l,
            solid(sc(0.60), 3.5)
                .with_line_cap(canvas::LineCap::Round)
                .with_line_join(canvas::LineJoin::Round),
        );
        f.fill(&Path::circle(Point::new(-16.0, 18.0), 4.5), sc(0.22));
        f.stroke(
            &Path::circle(Point::new(-16.0, 18.0), 4.5),
            solid(sc(0.45), 1.3),
        );

        let arm_r = Path::new(|b| {
            b.move_to(Point::new(10.0, 0.0));
            b.line_to(Point::new(16.0, 12.0));
            b.line_to(Point::new(14.0, 18.0));
        });
        f.stroke(
            &arm_r,
            solid(sc(0.60), 3.5)
                .with_line_cap(canvas::LineCap::Round)
                .with_line_join(canvas::LineJoin::Round),
        );
        f.fill(&Path::circle(Point::new(14.0, 18.0), 4.5), sc(0.22));
        f.stroke(
            &Path::circle(Point::new(14.0, 18.0), 4.5),
            solid(sc(0.45), 1.3),
        );

        // Legs + boots
        let leg_l = Path::new(|b| {
            b.move_to(Point::new(-5.0, 16.0));
            b.line_to(Point::new(-7.0, 30.0));
        });
        f.stroke(
            &leg_l,
            solid(sc(0.60), 4.0).with_line_cap(canvas::LineCap::Round),
        );
        let leg_r = Path::new(|b| {
            b.move_to(Point::new(5.0, 16.0));
            b.line_to(Point::new(7.0, 30.0));
        });
        f.stroke(
            &leg_r,
            solid(sc(0.60), 4.0).with_line_cap(canvas::LineCap::Round),
        );

        for bx in [-7.0_f32, 7.0] {
            let boot = Path::new(|b| {
                b.ellipse(Elliptical {
                    center: Point::new(bx, 31.0),
                    radii: Vector::new(7.0, 3.5),
                    rotation: Radians(0.0),
                    start_angle: Radians(0.0),
                    end_angle: Radians(TAU),
                })
            });
            f.fill(&boot, sc(0.25));
            f.stroke(&boot, solid(sc(0.45), 1.2));
        }

        // Helmet + solid terracotta visor (blacked out — identity concealed)
        let helmet = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(0.0, -20.0),
                radii: Vector::new(12.0, 14.0),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        f.fill(&helmet, sc(0.15));
        f.stroke(&helmet, solid(sc(0.55), 1.8));

        let visor = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(1.0, -21.0),
                radii: Vector::new(8.0, 9.0),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        f.fill(&visor, t(0.55)); // opaque — identity blacked out
        f.stroke(&visor, solid(t(0.85), 1.2));
    });
}

fn draw_chest_lock(
    frame: &mut Frame,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    t: &impl Fn(f32) -> Color,
) {
    use iced::widget::canvas::path::Arc;
    let (x, y) = (0.0_f32, 3.0_f32); // centred on torso

    let shackle = Path::new(|b| {
        b.move_to(Point::new(x - 4.5, y - 3.0));
        b.line_to(Point::new(x - 4.5, y - 7.0));
        b.arc(Arc {
            center: Point::new(x, y - 7.0),
            radius: 4.5,
            start_angle: Radians(PI),
            end_angle: Radians(0.0),
        });
        b.line_to(Point::new(x + 4.5, y - 3.0));
    });
    frame.stroke(&shackle, solid(t(0.85), 1.6));

    let body = Path::new(|b| {
        b.move_to(Point::new(x - 6.0, y - 3.0));
        b.line_to(Point::new(x + 6.0, y - 3.0));
        b.line_to(Point::new(x + 6.0, y + 6.0));
        b.line_to(Point::new(x - 6.0, y + 6.0));
        b.close();
    });
    frame.fill(&body, t(0.20));
    frame.stroke(&body, solid(t(0.85), 1.4));
    frame.fill(&Path::circle(Point::new(x, y + 1.5), 2.0), t(0.70));
}
