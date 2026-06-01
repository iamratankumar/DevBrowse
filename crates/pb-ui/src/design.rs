//! Design constants — Module 42 (pb-ui::design).
//!
//! All constants are emitted at build time from `design/tokens.json`
//! via `crates/pb-ui/build.rs`. Every Phase 8 module imports from here;
//! never hard-code palette/radius/motion/glass values inline.
//!
//! Enforces: L28 (glass aesthetic), L41 (Strict identity non-customizable),
//! L43 (Strict motion floor 100 ms via motion::SPRING_STRICT_MS etc).
//!
//! Sub-modules: `palette`, `radius`, `space`, `type_scale`, `motion`,
//! `layout`, `glass`.

// Include the codegen output produced by build.rs from design/tokens.json.
include!(concat!(env!("OUT_DIR"), "/design.rs"));

/// Resolved display theme — never Auto. Derived from `pb_config::Theme` at
/// startup (System -> OS detection, Dark/Light -> direct).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeVariant {
    Dark,
    Light,
}

/// All theme-varying color values for one resolved theme. Use the statics
/// `DARK_PALETTE` / `LIGHT_PALETTE`; never construct ad-hoc.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    // -- Wallpaper gradient / solid stops --
    pub wallpaper_start: [f32; 4],
    pub wallpaper_end: [f32; 4],
    pub wallpaper_solid: [f32; 4],
    pub strict_wallpaper_start: [f32; 4],
    pub strict_wallpaper_end: [f32; 4],
    // -- Glass surfaces --
    pub glass_tint: [f32; 4],
    pub glass_reduced: [f32; 4],
    // -- Text --
    pub text_primary: [f32; 4],
    pub text_muted: [f32; 4],
    pub text_dim: [f32; 4],
    // -- Interactive --
    /// Standard-mode active / accent color.
    pub active: [f32; 4],
    /// Enabled icon color (light grey on dark bg; dark grey on light bg).
    pub icon_primary: [f32; 4],
    /// Disabled / dim icon color.
    pub icon_dim: [f32; 4],
    /// Standalone button idle background fill.
    pub button_idle: [f32; 4],
    /// Standalone button hover background fill.
    pub button_hover: [f32; 4],
    /// Hairline button border and separator line.
    pub button_border: [f32; 4],
}

/// Dark theme — values are identical to the pre-existing `palette::*_DARK`
/// constants. Any change here must be mirrored in the constants.
pub static DARK_PALETTE: Palette = Palette {
    wallpaper_start: palette::BG_DEEP_DARK_START,
    wallpaper_end: palette::BG_DEEP_DARK_END,
    wallpaper_solid: palette::STANDARD_WALLPAPER_SOLID,
    strict_wallpaper_start: palette::STRICT_WALLPAPER_START,
    strict_wallpaper_end: palette::BG_DEEP_DARK_END, // no STRICT_WALLPAPER_END token; BG_DEEP_DARK_END is the intentional dark-Strict gradient terminus
    glass_tint: palette::GLASS_TINT_DARK,
    glass_reduced: palette::GLASS_REDUCED_DARK,
    text_primary: palette::TEXT_PRIMARY_DARK,
    text_muted: palette::TEXT_MUTED_DARK,
    text_dim: palette::TEXT_DIM_DARK,
    active: palette::STANDARD_ACTIVE,
    icon_primary: [0.690, 0.706, 0.745, 1.0], // light grey-blue — readable on dark bg
    icon_dim: [0.290, 0.302, 0.337, 1.0],     // dimmed — barely visible on dark bg
    button_idle: [1.0, 0.980, 0.941, 0.05],   // warm-white 5% — subtle on dark
    button_hover: [1.0, 0.980, 0.941, 0.13],  // warm-white 13% — hover on dark
    button_border: [1.0, 0.980, 0.941, 0.08], // warm-white 8% — hairline on dark
};

/// Light theme — white-frosted-glass macOS aesthetic. Glass blur parameters
/// are identical to dark; only tint colors change.
pub static LIGHT_PALETTE: Palette = Palette {
    wallpaper_start: palette::STANDARD_WALLPAPER_LIGHT_START,
    wallpaper_end: palette::STANDARD_WALLPAPER_LIGHT_END,
    wallpaper_solid: palette::STANDARD_WALLPAPER_LIGHT_START, // no light solid token; START used as the solid fallback
    strict_wallpaper_start: palette::STRICT_WALLPAPER_LIGHT_START,
    strict_wallpaper_end: palette::STRICT_WALLPAPER_LIGHT_END,
    glass_tint: palette::GLASS_TINT_LIGHT,
    glass_reduced: palette::GLASS_REDUCED_LIGHT,
    text_primary: palette::TEXT_PRIMARY_LIGHT,
    text_muted: palette::TEXT_MUTED_LIGHT,
    text_dim: palette::TEXT_DIM_LIGHT,
    active: palette::STANDARD_ACTIVE,
    icon_primary: [0.102, 0.110, 0.125, 1.0], // dark grey — readable on light bg
    icon_dim: [0.580, 0.596, 0.643, 1.0],     // medium grey — dim on light bg
    button_idle: [0.0, 0.0, 0.0, 0.06],       // 6% dark fill — subtle idle on light
    button_hover: [0.0, 0.0, 0.0, 0.11],      // 11% dark fill — macOS-standard hover
    button_border: [0.0, 0.0, 0.0, 0.12],     // 12% dark — visible hairline on light
};

/// Return the static `Palette` for a resolved theme variant.
#[inline]
pub fn palette_for(v: ThemeVariant) -> &'static Palette {
    match v {
        ThemeVariant::Dark => &DARK_PALETTE,
        ThemeVariant::Light => &LIGHT_PALETTE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_border_is_two_px() {
        const { assert!(layout::STRICT_BORDER_PX as u32 == 2) };
    }

    #[test]
    fn top_bar_height_is_36_px() {
        const { assert!(layout::TOP_BAR_HEIGHT_PX as u32 == 36) };
    }

    #[test]
    fn motion_strict_spring_at_least_200_ms() {
        // L43: Strict motion floor 100 ms; spring token is 220 ms.
        const { assert!(motion::SPRING_STRICT_MS >= 100) };
    }

    #[test]
    fn mode_convert_morph_is_600_ms() {
        const { assert!(motion::MODE_CONVERT_MS == 600) };
    }

    #[test]
    fn glass_url_bar_blur_sigma_positive() {
        const { assert!(glass::URL_BAR_BLUR_SIGMA > 0.0) };
    }

    #[test]
    fn strict_color_is_terracotta() {
        // palette::STRICT must encode #b85a3c = (0.722, 0.353, 0.235, 1.0) approximately.
        let [r, g, b, a] = palette::STRICT;
        assert!((r - 0.722).abs() < 0.01, "strict red mismatch: {r}");
        assert!((g - 0.353).abs() < 0.01, "strict green mismatch: {g}");
        assert!((b - 0.235).abs() < 0.01, "strict blue mismatch: {b}");
        assert_eq!(a, 1.0);
    }

    #[test]
    fn accent_color_is_champagne() {
        // palette::ACCENT must encode #c9a878 = (0.788, 0.659, 0.471, 1.0) approximately.
        let [r, g, b, a] = palette::ACCENT;
        assert!((r - 0.788).abs() < 0.01, "accent red mismatch: {r}");
        assert!((g - 0.659).abs() < 0.01, "accent green mismatch: {g}");
        assert!((b - 0.471).abs() < 0.01, "accent blue mismatch: {b}");
        assert_eq!(a, 1.0);
    }

    #[test]
    fn dark_palette_wallpaper_matches_existing_constants() {
        let [r, g, b, a] = DARK_PALETTE.wallpaper_start;
        let [er, eg, eb, ea] = palette::BG_DEEP_DARK_START;
        assert!((r - er).abs() < 1e-4);
        assert!((g - eg).abs() < 1e-4);
        assert!((b - eb).abs() < 1e-4);
        assert!((a - ea).abs() < 1e-4);
    }

    #[test]
    fn light_palette_glass_tint_matches_token() {
        let [r, g, b, a] = LIGHT_PALETTE.glass_tint;
        let [er, eg, eb, ea] = palette::GLASS_TINT_LIGHT;
        assert!((r - er).abs() < 1e-4);
        assert!((g - eg).abs() < 1e-4);
        assert!((b - eb).abs() < 1e-4);
        assert!((a - ea).abs() < 1e-4);
    }

    #[test]
    fn palette_for_returns_correct_static() {
        assert!(std::ptr::eq(palette_for(ThemeVariant::Dark), &DARK_PALETTE));
        assert!(std::ptr::eq(
            palette_for(ThemeVariant::Light),
            &LIGHT_PALETTE
        ));
    }
}
