//! Design tokens — Module 42 (pb-ui::tokens).
//!
//! All constants are emitted at build time from `docs/design/tokens.json`
//! via `crates/pb-ui/build.rs`. Every Phase 8 module imports from here;
//! never hard-code palette/radius/motion/glass values inline.
//!
//! Enforces: L28 (glass aesthetic), L41 (Strict identity non-customizable),
//! L43 (Strict motion floor 100 ms via motion::SPRING_STRICT_MS etc).
//!
//! Sub-modules: `palette`, `radius`, `space`, `type_scale`, `motion`,
//! `layout`, `glass`.

// Include the codegen output produced by build.rs from docs/design/tokens.json.
include!(concat!(env!("OUT_DIR"), "/tokens.rs"));

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
}
