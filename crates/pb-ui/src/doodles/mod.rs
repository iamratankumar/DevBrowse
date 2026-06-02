//! NTP doodle illustrations — one per session, chosen at boot.
//!
//! Each doodle is a `canvas::Program` drawn once and cached. The cache is
//! invalidated only on theme change (palette swap) or, for Base Camp, on
//! cursor movement inside the doodle zone.
//!
//! Implementation order: compass → waypoint → sanctuary → dock → atlas →
//!   launchpad → control_tower → bridge → helipad → base_camp →
//!   mission_control → command_center → nexus → stargate → observatory

mod compass;

use iced::widget::Canvas;
use iced::{Element, Length};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

pub use compass::CompassCache;

/// Height of the doodle illustration zone in pixels.
pub const DOODLE_H: f32 = 148.0;

/// One doodle variant per session. Selected randomly at boot.
#[derive(Debug)]
pub enum Doodle {
    Compass(CompassCache),
    // remaining variants added one by one as implemented
    Unimplemented,
}

impl Doodle {
    /// Pick a random doodle for the session.
    /// Add new match arms as variants are implemented; bump the modulus.
    pub fn random() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0);
        // Only Compass is implemented — always returns Compass.
        // Once more variants land, add them here and replace the match.
        let _ = nanos;
        Self::Compass(CompassCache::new())
    }

    /// Display name shown as the dim session label above the greeting.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Compass(_) => "Compass",
            Self::Unimplemented => "",
        }
    }

    /// Invalidate the cache — call when the palette changes.
    pub fn clear_cache(&mut self) {
        match self {
            Self::Compass(c) => c.cache.clear(),
            Self::Unimplemented => {}
        }
    }

    /// Build the Canvas element for this doodle.
    pub fn view<'a>(&'a self, palette: &'static Palette, mode: Mode) -> Element<'a, NewTabMsg> {
        match self {
            Self::Compass(c) => Canvas::new(compass::CompassProgram {
                cache: &c.cache,
                palette,
                mode,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Unimplemented => iced::widget::Space::new()
                .width(Length::Fill)
                .height(Length::Fixed(DOODLE_H))
                .into(),
        }
    }
}
