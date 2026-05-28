//! Build script — Module 42 design-token codegen.
//!
//! Reads `design/tokens.json` (workspace root) and emits
//! `$OUT_DIR/tokens.rs` containing typed Rust constants consumed by every
//! Phase 8 module via `pb_ui::tokens`.
//!
//! The same JSON is the single source of truth for Phase 12 Swift/Kotlin
//! shells; those codegen passes run outside Cargo and are not handled here.

use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let tokens_json = manifest.join("../../design/tokens.json");

    // Tell Cargo to re-run this script only when tokens.json changes.
    println!("cargo:rerun-if-changed={}", tokens_json.display());

    let raw = fs::read_to_string(&tokens_json).unwrap_or_else(|e| {
        panic!(
            "build.rs: cannot read tokens.json at {}: {e}",
            tokens_json.display()
        )
    });

    let tokens: serde_json::Value =
        serde_json::from_str(&raw).expect("build.rs: tokens.json is not valid JSON");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("tokens.rs");

    let mut out = String::from("// AUTO-GENERATED — do not edit by hand.\n// Source: design/tokens.json (Phase 8 Module 42 codegen)\n\n");

    emit_palette(&mut out, &tokens["palette"]);
    emit_radius(&mut out, &tokens["radius"]);
    emit_space(&mut out, &tokens["space"]);
    emit_type_scale(&mut out, &tokens["type_scale"]);
    emit_motion(&mut out, &tokens["motion"]);
    emit_layout(&mut out, &tokens["layout"]);
    emit_glass_params(&mut out, &tokens["glass"]);

    fs::write(&out_path, out).expect("build.rs: cannot write tokens.rs");
}

fn hex_to_rgba(hex: &str) -> (f32, f32, f32, f32) {
    let hex = hex.trim_start_matches('#');
    let r = u8::from_str_radix(&hex[0..2], 16).unwrap_or(0) as f32 / 255.0;
    let g = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0) as f32 / 255.0;
    let b = u8::from_str_radix(&hex[4..6], 16).unwrap_or(0) as f32 / 255.0;
    let a = if hex.len() == 8 {
        u8::from_str_radix(&hex[6..8], 16).unwrap_or(255) as f32 / 255.0
    } else {
        1.0
    };
    (r, g, b, a)
}

fn emit_color_const(out: &mut String, name: &str, hex: &str) {
    let (r, g, b, a) = hex_to_rgba(hex);
    out.push_str(&format!(
        "pub const {name}: [f32; 4] = [{r:.4}, {g:.4}, {b:.4}, {a:.4}];\n"
    ));
}

fn emit_palette(out: &mut String, p: &serde_json::Value) {
    out.push_str("pub mod palette {\n");

    // Wallpaper gradient stops
    for key in &[
        "bg_deep_dark_start",
        "bg_deep_dark_end",
        "bg_deep_light_start",
        "bg_deep_light_end",
        "glass_reduced_dark",
        "glass_reduced_light",
        "text_primary_dark",
        "text_primary_light",
        "text_muted_dark",
        "text_muted_light",
        "text_dim_dark",
        "text_dim_light",
        "accent",
        "accent_bright",
        "strict",
        "strict_bright",
        "standard_active",
        "status_ok",
        "status_warn",
        "status_danger",
        "strict_wallpaper_start",
        "standard_wallpaper_solid",
    ] {
        if let Some(hex) = p[key].as_str() {
            let const_name = key.to_uppercase();
            emit_color_const(out, &const_name, hex);
        }
    }

    // Glass tint (dark) — built from RGBA components
    let r = p["glass_tint_dark_r"].as_f64().unwrap_or(20.0) as f32 / 255.0;
    let g = p["glass_tint_dark_g"].as_f64().unwrap_or(28.0) as f32 / 255.0;
    let b = p["glass_tint_dark_b"].as_f64().unwrap_or(44.0) as f32 / 255.0;
    let a = p["glass_tint_dark_a"].as_f64().unwrap_or(0.65) as f32;
    out.push_str(&format!(
        "pub const GLASS_TINT_DARK: [f32; 4] = [{r:.4}, {g:.4}, {b:.4}, {a:.4}];\n"
    ));

    // Glass tint (light)
    let r = p["glass_tint_light_r"].as_f64().unwrap_or(255.0) as f32 / 255.0;
    let g = p["glass_tint_light_g"].as_f64().unwrap_or(253.0) as f32 / 255.0;
    let b = p["glass_tint_light_b"].as_f64().unwrap_or(247.0) as f32 / 255.0;
    let a = p["glass_tint_light_a"].as_f64().unwrap_or(0.78) as f32;
    out.push_str(&format!(
        "pub const GLASS_TINT_LIGHT: [f32; 4] = [{r:.4}, {g:.4}, {b:.4}, {a:.4}];\n"
    ));

    // Strict glow
    let r = p["strict_glow_r"].as_f64().unwrap_or(232.0) as f32 / 255.0;
    let g = p["strict_glow_g"].as_f64().unwrap_or(186.0) as f32 / 255.0;
    let b = p["strict_glow_b"].as_f64().unwrap_or(160.0) as f32 / 255.0;
    let a = p["strict_glow_a"].as_f64().unwrap_or(0.7) as f32;
    out.push_str(&format!(
        "pub const STRICT_GLOW: [f32; 4] = [{r:.4}, {g:.4}, {b:.4}, {a:.4}];\n"
    ));

    out.push_str("}\n\n");
}

fn emit_radius(out: &mut String, r: &serde_json::Value) {
    out.push_str("pub mod radius {\n");
    for (key, const_name) in &[
        ("pill", "PILL"),
        ("capsule", "CAPSULE"),
        ("panel", "PANEL"),
        ("button", "BUTTON"),
        ("tile", "TILE"),
        ("input", "INPUT"),
        ("fav", "FAV"),
        ("zero", "ZERO"),
    ] {
        let v = r[key].as_f64().unwrap_or(0.0) as f32;
        out.push_str(&format!("pub const {const_name}_PX: f32 = {v:.1};\n"));
    }
    out.push_str("}\n\n");
}

fn emit_space(out: &mut String, s: &serde_json::Value) {
    out.push_str("pub mod space {\n");
    for (key, const_name) in &[
        ("s1", "S1"),
        ("s2", "S2"),
        ("s3", "S3"),
        ("s4", "S4"),
        ("s5", "S5"),
        ("s6", "S6"),
        ("s7", "S7"),
        ("s8", "S8"),
        ("s10", "S10"),
        ("s12", "S12"),
    ] {
        let v = s[key].as_f64().unwrap_or(0.0) as f32;
        out.push_str(&format!("pub const {const_name}: f32 = {v:.1};\n"));
    }
    out.push_str("}\n\n");
}

fn emit_type_scale(out: &mut String, t: &serde_json::Value) {
    out.push_str("pub mod type_scale {\n");
    for (key, const_name) in &[
        ("hero_px", "HERO"),
        ("h1_px", "H1"),
        ("h2_px", "H2"),
        ("body_lg_px", "BODY_LG"),
        ("body_px", "BODY"),
        ("body_sm_px", "BODY_SM"),
        ("label_px", "LABEL"),
        ("label_upper_px", "LABEL_UPPER"),
    ] {
        let v = t[key].as_f64().unwrap_or(12.0) as f32;
        out.push_str(&format!("pub const {const_name}_PX: f32 = {v:.1};\n"));
    }
    out.push_str("}\n\n");
}

fn emit_motion(out: &mut String, m: &serde_json::Value) {
    out.push_str("pub mod motion {\n");
    for (key, const_name) in &[
        ("spring_ms", "SPRING_MS"),
        ("fade_ms", "FADE_MS"),
        ("morph_ms", "MORPH_MS"),
        ("spring_strict_ms", "SPRING_STRICT_MS"),
        ("fade_strict_ms", "FADE_STRICT_MS"),
        ("morph_strict_ms", "MORPH_STRICT_MS"),
        ("mode_convert_ms", "MODE_CONVERT_MS"),
    ] {
        let v = m[key].as_f64().unwrap_or(0.0) as u32;
        out.push_str(&format!("pub const {const_name}: u32 = {v};\n"));
    }
    out.push_str("}\n\n");
}

fn emit_layout(out: &mut String, l: &serde_json::Value) {
    out.push_str("pub mod layout {\n");
    for (key, const_name) in &[
        ("top_bar_height_px", "TOP_BAR_HEIGHT"),
        ("top_bar_top_px", "TOP_BAR_TOP"),
        ("sidebar_collapsed_px", "SIDEBAR_COLLAPSED"),
        ("sidebar_expanded_px", "SIDEBAR_EXPANDED"),
        ("url_bar_width_px", "URL_BAR_WIDTH"),
        ("url_bar_control_height_px", "URL_BAR_CONTROL_HEIGHT"),
        ("tab_bar_height_px", "TAB_BAR_HEIGHT"),
        ("traffic_light_inset_px", "TRAFFIC_LIGHT_INSET"),
        ("strict_border_px", "STRICT_BORDER"),
    ] {
        let v = l[key].as_f64().unwrap_or(0.0) as f32;
        out.push_str(&format!("pub const {const_name}_PX: f32 = {v:.1};\n"));
    }
    out.push_str("}\n\n");
}

fn emit_glass_params(out: &mut String, g: &serde_json::Value) {
    out.push_str("pub mod glass {\n");
    for (key, const_name) in &[
        ("url_bar_blur_sigma_px", "URL_BAR_BLUR_SIGMA"),
        ("panel_blur_sigma_px", "PANEL_BLUR_SIGMA"),
        ("sidebar_blur_sigma_px", "SIDEBAR_BLUR_SIGMA"),
        ("popover_blur_sigma_px", "POPOVER_BLUR_SIGMA"),
        ("url_bar_saturate", "URL_BAR_SATURATE"),
        ("panel_saturate", "PANEL_SATURATE"),
    ] {
        let v = g[key].as_f64().unwrap_or(0.0) as f32;
        out.push_str(&format!("pub const {const_name}: f32 = {v:.4};\n"));
    }

    // Strict inset glow
    let r = g["strict_inset_glow_r"].as_f64().unwrap_or(184.0) as f32 / 255.0;
    let gr = g["strict_inset_glow_g"].as_f64().unwrap_or(90.0) as f32 / 255.0;
    let b = g["strict_inset_glow_b"].as_f64().unwrap_or(60.0) as f32 / 255.0;
    let a = g["strict_inset_glow_a"].as_f64().unwrap_or(0.18) as f32;
    out.push_str(&format!(
        "pub const STRICT_INSET_GLOW: [f32; 4] = [{r:.4}, {gr:.4}, {b:.4}, {a:.4}];\n"
    ));
    let spread = g["strict_inset_glow_spread_px"].as_f64().unwrap_or(60.0) as f32;
    out.push_str(&format!(
        "pub const STRICT_INSET_GLOW_SPREAD_PX: f32 = {spread:.1};\n"
    ));

    out.push_str("}\n");
}
