//! Launchpad doodle — rocket on gantry with one-shot launch sequence.
//!
//! Accent colours: orange #f97316 (A1) + sky blue #60a5fa (A2).
//! One-shot animation: 2 s idle → T-3 → T-2 → T-1 → launched (static).
//! Driven by canvas State + Action::request_redraw() — no subscription.
//! Strict: chained rocket, HOLD display, no animation.

use std::f32::consts::TAU;
use std::time::Instant;

use iced::widget::canvas::path::arc::Elliptical;
use iced::widget::canvas::{self, Cache, Frame, Path, Stroke, Text};
use iced::{Color, Font, Point, Radians, Rectangle, Vector};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

const A1: Color = Color {
    r: 0.976,
    g: 0.451,
    b: 0.086,
    a: 1.0,
}; // #f97316 orange
const A2: Color = Color {
    r: 0.376,
    g: 0.647,
    b: 0.980,
    a: 1.0,
}; // #60a5fa sky blue

const GANTRY_Y: f32 = 138.0;
const ROCKET_CY: f32 = 75.0;
const ROCKET_BOT: f32 = 112.0;

// Phase thresholds (seconds from canvas creation).
const T_START: f32 = 2.0; // begin countdown
const T_T3: f32 = 3.0;
const T_T2: f32 = 4.0;
const T_LAUNCH: f32 = 5.0;
const LAUNCH_DUR: f32 = 1.3; // seconds for rocket to fly off canvas
                             // Lift needed to push the entire rocket (nose to fin) off the top of the canvas.
                             // At 1.3x scale, nose starts at ~y=8; ~130px lift clears fins above y=0.
const MAX_LIFT: f32 = 130.0;

/// `start` lives here so it resets on every new tab (LaunchpadCache::new()).
/// Iced canvas State is keyed by widget position and can survive tab switches;
/// putting the Instant in the cache avoids that.
pub struct LaunchpadCache {
    pub cache: Cache,
    pub start: Instant,
}

impl LaunchpadCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::new(),
            start: Instant::now(),
        }
    }
}

impl Default for LaunchpadCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LaunchpadCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaunchpadCache")
    }
}

fn elapsed_phase(start: Instant) -> u8 {
    let e = start.elapsed().as_secs_f32();
    if e < T_START {
        0
    } else if e < T_T3 {
        1
    } else if e < T_T2 {
        2
    } else if e < T_LAUNCH {
        3
    } else if e < T_LAUNCH + LAUNCH_DUR {
        4
    } else {
        5
    }
}

fn launch_progress(start: Instant) -> f32 {
    let e = start.elapsed().as_secs_f32();
    ((e - T_LAUNCH) / LAUNCH_DUR).clamp(0.0, 1.0)
}

pub struct LaunchpadProgram<'a> {
    pub cache: &'a Cache,
    pub palette: &'static Palette,
    pub mode: Mode,
    pub start: Instant,
}

impl canvas::Program<NewTabMsg> for LaunchpadProgram<'_> {
    type State = ();

    fn update(
        &self,
        _state: &mut (),
        _event: &iced::Event,
        _bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Option<canvas::Action<NewTabMsg>> {
        if self.mode != Mode::Standard {
            return None;
        }
        if elapsed_phase(self.start) < 5 {
            Some(canvas::Action::request_redraw())
        } else {
            None
        }
    }

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

        if self.mode == Mode::Strict {
            let geo = self.cache.draw(renderer, size, |frame| {
                draw_strict(frame, size, self.palette);
            });
            return vec![geo];
        }

        let phase = elapsed_phase(self.start);

        if phase >= 5 {
            let geo = self.cache.draw(renderer, size, |frame| {
                apply_scale(frame, cx);
                draw_launched(frame, size, self.palette);
            });
            return vec![geo];
        }

        let mut frame = Frame::new(renderer, size);
        apply_scale(&mut frame, cx);
        if phase == 4 {
            let lift = launch_progress(self.start).powi(2) * MAX_LIFT;
            draw_launching(&mut frame, size, self.palette, lift);
        } else {
            draw_animating(&mut frame, size, self.palette, phase);
        }
        vec![frame.into_geometry()]
    }
}

fn apply_scale(frame: &mut Frame, cx: f32) {
    frame.translate(Vector::new(cx, 95.0));
    frame.scale(1.3);
    frame.translate(Vector::new(-cx, -95.0));
}

// ── Shared geometry helpers ───────────────────────────────────────────────────

fn draw_gantry(
    frame: &mut Frame,
    cx: f32,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
    sc: &impl Fn(f32) -> Color,
) {
    let arm = Path::new(|b| {
        b.move_to(Point::new(cx - 45.0, GANTRY_Y));
        b.line_to(Point::new(cx + 45.0, GANTRY_Y));
    });
    frame.stroke(
        &arm,
        solid(sc(0.7), 2.0).with_line_cap(canvas::LineCap::Round),
    );

    for (x1, x2) in [(cx - 30.0, cx - 50.0), (cx + 30.0, cx + 50.0)] {
        let leg = Path::new(|b| {
            b.move_to(Point::new(x1, GANTRY_Y));
            b.line_to(Point::new(x2, GANTRY_Y + 30.0));
        });
        frame.stroke(
            &leg,
            solid(sc(0.65), 1.8).with_line_cap(canvas::LineCap::Round),
        );
    }

    let pole = Path::new(|b| {
        b.move_to(Point::new(cx, ROCKET_BOT));
        b.line_to(Point::new(cx, GANTRY_Y));
    });
    frame.stroke(&pole, solid(sc(0.45), 1.5));
}

fn draw_rocket(
    frame: &mut Frame,
    cx: f32,
    lift: f32,
    a1: &impl Fn(f32) -> Color,
    a2: &impl Fn(f32) -> Color,
    sc: &impl Fn(f32) -> Color,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
) {
    let cy = ROCKET_CY - lift;
    let bot = ROCKET_BOT - lift;

    let body = Path::new(|b| {
        b.ellipse(Elliptical {
            center: Point::new(cx, cy),
            radii: Vector::new(16.0, 32.0),
            rotation: Radians(0.0),
            start_angle: Radians(0.0),
            end_angle: Radians(TAU),
        })
    });
    frame.fill(&body, a1(0.12));
    frame.stroke(&body, solid(a1(1.0), 2.2));

    let nose = Path::new(|b| {
        b.move_to(Point::new(cx - 16.0, cy - 25.0));
        b.quadratic_curve_to(Point::new(cx, cy - 47.0), Point::new(cx + 16.0, cy - 25.0));
        b.close();
    });
    frame.fill(&nose, a1(0.22));
    frame.stroke(&nose, solid(a1(1.0), 2.0));

    frame.stroke(
        &Path::circle(Point::new(cx, cy - 5.0), 6.0),
        solid(a2(1.0), 1.6),
    );
    frame.fill(&Path::circle(Point::new(cx, cy - 5.0), 2.5), a2(0.60));

    for (dx1, dx2) in [(-8.0_f32, -4.0_f32), (8.0, 4.0)] {
        let strut = Path::new(|b| {
            b.move_to(Point::new(cx + dx1, bot - 24.0));
            b.line_to(Point::new(cx + dx2, bot - 12.0));
        });
        frame.stroke(&strut, solid(a1(0.5), 1.0));
    }

    for (dx1, dx2, dx3) in [(-16.0_f32, -28.0_f32, -12.0_f32), (16.0, 28.0, 12.0)] {
        let fin = Path::new(|b| {
            b.move_to(Point::new(cx + dx1, bot - 14.0));
            b.line_to(Point::new(cx + dx2, bot + 8.0));
            b.line_to(Point::new(cx + dx3, bot));
            b.close();
        });
        frame.fill(&fin, a1(0.20));
        frame.stroke(&fin, solid(a1(1.0), 1.5));
    }

    let _ = sc; // gantry uses sc; rocket doesn't but helper signature is uniform
}

#[allow(clippy::too_many_arguments)]
fn draw_countdown_display(
    frame: &mut Frame,
    cx: f32,
    label: &str,
    text_col: Color,
    bg_col: Color,
    border_col: Color,
    sc: &impl Fn(f32) -> Color,
    solid: &impl Fn(Color, f32) -> Stroke<'static>,
) {
    let box_x = cx + 70.0;
    let box_y = 42.0_f32;
    let disp = Path::new(|b| {
        b.move_to(Point::new(box_x, box_y));
        b.line_to(Point::new(box_x + 48.0, box_y));
        b.line_to(Point::new(box_x + 48.0, box_y + 32.0));
        b.line_to(Point::new(box_x, box_y + 32.0));
        b.close();
    });
    frame.fill(&disp, bg_col);
    frame.stroke(&disp, solid(border_col, 1.5));
    frame.fill_text(Text {
        content: label.to_string(),
        position: Point::new(box_x + 24.0, box_y + 16.0),
        color: text_col,
        size: iced::Pixels(13.0),
        font: Font::MONOSPACE,
        align_x: iced::alignment::Horizontal::Center.into(),
        align_y: iced::alignment::Vertical::Center,
        line_height: iced::widget::text::LineHeight::default(),
        shaping: iced::widget::text::Shaping::Basic,
        max_width: f32::INFINITY,
    });
    for dy in [32.0_f32, 38.0] {
        let dline = Path::new(|b| {
            b.move_to(Point::new(box_x + 4.0, box_y + dy));
            b.line_to(Point::new(box_x + 44.0, box_y + dy));
        });
        frame.stroke(&dline, solid(sc(0.25), 1.0));
    }
}

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

// ── Animation phases (0-3, uncached) ─────────────────────────────────────────

fn draw_animating(frame: &mut Frame, size: iced::Size, palette: &'static Palette, phase: u8) {
    let cx = size.width / 2.0;

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

    draw_gantry(frame, cx, &solid, &sc);
    draw_rocket(frame, cx, 0.0, &a1, &a2, &sc, &solid);

    let (label, text_col, bg_col, border_col) = match phase {
        0 => ("---", sc(0.35), a2(0.04), sc(0.30)),
        1 => ("T-3", a1(0.90), a1(0.08), sc(0.55)),
        2 => ("T-2", a1(0.95), a1(0.10), sc(0.60)),
        _ => ("T-1", a1(1.0), a1(0.14), a1(0.70)),
    };
    draw_countdown_display(frame, cx, label, text_col, bg_col, border_col, &sc, &solid);

    draw_star(frame, Point::new(cx - 115.0, 60.0), 5.0, a2(0.40));
    draw_star(frame, Point::new(cx - 110.0, 110.0), 4.0, sc(0.30));
}

// ── Phase 4: rocket flying upward (uncached) ──────────────────────────────────

fn draw_launching(frame: &mut Frame, size: iced::Size, palette: &'static Palette, lift: f32) {
    let cx = size.width / 2.0;

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

    let lift_frac = (lift / MAX_LIFT).clamp(0.0, 1.0);

    draw_gantry(frame, cx, &solid, &sc);

    let rocket_bot = ROCKET_BOT - lift;

    // Exhaust follows the rocket bottom — expands as lift increases.
    let scale = 1.0 + lift_frac * 0.9;
    for (y_off, rx, ry, base_a) in [
        (12.0_f32, 14.0_f32, 6.0_f32, 0.60_f32),
        (28.0, 10.0, 5.5, 0.40),
        (46.0, 7.0, 4.0, 0.25),
    ] {
        let plume = Path::new(|b| {
            b.ellipse(Elliptical {
                center: Point::new(cx, rocket_bot + y_off),
                radii: Vector::new(rx * scale, ry * scale),
                rotation: Radians(0.0),
                start_angle: Radians(0.0),
                end_angle: Radians(TAU),
            })
        });
        frame.fill(&plume, a1(base_a));
    }

    // Rocket rises — only draw while still partially on canvas.
    if ROCKET_CY - lift > -60.0 {
        draw_rocket(frame, cx, lift, &a1, &a2, &sc, &solid);
    }

    // Display shows "T-0" while rocket is rising.
    draw_countdown_display(frame, cx, "T-0", a1(1.0), a1(0.16), a1(0.80), &sc, &solid);

    draw_star(frame, Point::new(cx - 115.0, 60.0), 5.0, a2(0.40));
    draw_star(frame, Point::new(cx - 110.0, 110.0), 4.0, sc(0.30));
}

// ── Phase 5: gone (cached) ────────────────────────────────────────────────────

fn draw_launched(frame: &mut Frame, size: iced::Size, palette: &'static Palette) {
    let cx = size.width / 2.0;

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

    draw_gantry(frame, cx, &solid, &sc);

    // Display shows "GO!" — rocket is gone.
    draw_countdown_display(frame, cx, "GO!", a1(1.0), a1(0.14), a1(0.70), &sc, &solid);

    draw_star(frame, Point::new(cx - 115.0, 60.0), 5.0, a2(0.40));
    draw_star(frame, Point::new(cx - 110.0, 110.0), 4.0, sc(0.30));
}

// ── Strict (cached, no animation) ────────────────────────────────────────────

fn draw_strict(frame: &mut Frame, size: iced::Size, palette: &'static Palette) {
    let cx = size.width / 2.0;

    let [tr, tg, tb, _] = crate::design::palette::STRICT;
    let tc = Color::from_rgb(tr, tg, tb);
    let t = |a: f32| Color { a, ..tc };
    let [sr, sg, sb, _] = palette.text_primary;
    let is_dark = palette.is_dark();
    let sa = if is_dark { 0.45_f32 } else { 0.40 };
    let sc = |a: f32| Color::from_rgba(sr, sg, sb, a * sa / 0.45);
    let solid = |col: Color, w: f32| Stroke::default().with_color(col).with_width(w);

    apply_scale(frame, cx);

    let mut y = 0.0_f32;
    while y < size.height {
        let line = Path::new(|b| {
            b.move_to(Point::new(0.0, y));
            b.line_to(Point::new(size.width, y));
        });
        frame.stroke(&line, solid(t(0.06), 1.0));
        y += 6.0;
    }

    // Gantry
    let arm = Path::new(|b| {
        b.move_to(Point::new(cx - 45.0, GANTRY_Y));
        b.line_to(Point::new(cx + 45.0, GANTRY_Y));
    });
    frame.stroke(
        &arm,
        solid(sc(0.65), 2.0).with_line_cap(canvas::LineCap::Round),
    );
    for (x1, x2) in [(cx - 30.0, cx - 50.0), (cx + 30.0, cx + 50.0)] {
        let leg = Path::new(|b| {
            b.move_to(Point::new(x1, GANTRY_Y));
            b.line_to(Point::new(x2, GANTRY_Y + 30.0));
        });
        frame.stroke(
            &leg,
            solid(sc(0.60), 1.8).with_line_cap(canvas::LineCap::Round),
        );
    }
    let pole = Path::new(|b| {
        b.move_to(Point::new(cx, ROCKET_BOT));
        b.line_to(Point::new(cx, GANTRY_Y));
    });
    frame.stroke(&pole, solid(sc(0.40), 1.5));

    // Rocket (terracotta)
    let cy = ROCKET_CY;
    let bot = ROCKET_BOT;
    let body = Path::new(|b| {
        b.ellipse(Elliptical {
            center: Point::new(cx, cy),
            radii: Vector::new(16.0, 32.0),
            rotation: Radians(0.0),
            start_angle: Radians(0.0),
            end_angle: Radians(TAU),
        })
    });
    frame.fill(&body, t(0.12));
    frame.stroke(&body, solid(tc, 2.2));
    let nose = Path::new(|b| {
        b.move_to(Point::new(cx - 16.0, cy - 25.0));
        b.quadratic_curve_to(Point::new(cx, cy - 47.0), Point::new(cx + 16.0, cy - 25.0));
        b.close();
    });
    frame.fill(&nose, t(0.18));
    frame.stroke(&nose, solid(tc, 2.0));
    for (dx1, dx2, dx3) in [(-16.0_f32, -28.0_f32, -12.0_f32), (16.0, 28.0, 12.0)] {
        let fin = Path::new(|b| {
            b.move_to(Point::new(cx + dx1, bot - 14.0));
            b.line_to(Point::new(cx + dx2, bot + 8.0));
            b.line_to(Point::new(cx + dx3, bot));
            b.close();
        });
        frame.fill(&fin, t(0.15));
        frame.stroke(&fin, solid(tc, 1.5));
    }

    // Chains with padlocks
    for chain_y in [cy - 15.0, cy, cy + 15.0] {
        for side in [-1.0_f32, 1.0] {
            let mut lx = cx + side * 16.0;
            let end_x = cx + side * 36.0;
            while (end_x - lx) * side > 0.0 {
                let link = Path::new(|b| {
                    b.move_to(Point::new(lx, chain_y));
                    b.quadratic_curve_to(
                        Point::new(lx + side * 3.0, chain_y - 3.0),
                        Point::new(lx + side * 6.0, chain_y),
                    );
                });
                frame.stroke(&link, solid(tc, 1.8));
                lx += side * 6.0;
            }
        }
        let lock = Path::new(|b| {
            b.move_to(Point::new(cx - 5.0, chain_y - 2.0));
            b.line_to(Point::new(cx + 5.0, chain_y - 2.0));
            b.line_to(Point::new(cx + 5.0, chain_y + 4.0));
            b.line_to(Point::new(cx - 5.0, chain_y + 4.0));
            b.close();
        });
        frame.fill(&lock, t(0.20));
        frame.stroke(&lock, solid(tc, 1.4));
    }

    // Countdown: HOLD
    let box_x = cx + 70.0;
    let box_y = 42.0_f32;
    let disp = Path::new(|b| {
        b.move_to(Point::new(box_x, box_y));
        b.line_to(Point::new(box_x + 48.0, box_y));
        b.line_to(Point::new(box_x + 48.0, box_y + 32.0));
        b.line_to(Point::new(box_x, box_y + 32.0));
        b.close();
    });
    frame.fill(&disp, t(0.10));
    frame.stroke(&disp, solid(tc, 1.5));
    frame.fill_text(Text {
        content: "HOLD".to_string(),
        position: Point::new(box_x + 24.0, box_y + 16.0),
        color: tc,
        size: iced::Pixels(10.0),
        font: Font::MONOSPACE,
        align_x: iced::alignment::Horizontal::Center.into(),
        align_y: iced::alignment::Vertical::Center,
        line_height: iced::widget::text::LineHeight::default(),
        shaping: iced::widget::text::Shaping::Basic,
        max_width: f32::INFINITY,
    });
    for dy in [32.0_f32, 38.0] {
        let dline = Path::new(|b| {
            b.move_to(Point::new(box_x + 4.0, box_y + dy));
            b.line_to(Point::new(box_x + 44.0, box_y + dy));
        });
        frame.stroke(&dline, solid(sc(0.25), 1.0));
    }
}
