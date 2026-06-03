//! NTP doodle illustrations — one per session, chosen at boot.
//!
//! Each doodle is a `canvas::Program` drawn once and cached. The cache is
//! invalidated only on theme change (palette swap) or, for Base Camp, on
//! cursor movement inside the doodle zone.
//!
//! Implementation order: compass → waypoint → sanctuary → dock → atlas →
//!   launchpad → control_tower → bridge → helipad → base_camp →
//!   mission_control → command_center → nexus → stargate → observatory

mod atlas;
mod base_camp;
mod bridge;
mod compass;
mod dock;
mod launchpad;
mod mission_control;
mod sanctuary;
mod stargate;
mod waypoint;

use iced::widget::Canvas;
use iced::{Element, Length};

use crate::design::Palette;
use crate::new_tab_screen::NewTabMsg;
use crate::shell::Mode;

pub use atlas::AtlasCache;
pub use base_camp::BaseCampCache;
pub use bridge::BridgeCache;
pub use compass::CompassCache;
pub use dock::DockCache;
pub use launchpad::LaunchpadCache;
pub use mission_control::MissionControlCache;
pub use sanctuary::SanctuaryCache;
pub use stargate::StargateCache;
pub use waypoint::WaypointCache;

/// Height of the doodle illustration zone in pixels.
pub const DOODLE_H: f32 = 190.0;

/// One doodle variant per session. Selected randomly at boot.
#[derive(Debug)]
pub enum Doodle {
    Atlas(AtlasCache),
    BaseCamp(BaseCampCache),
    Bridge(BridgeCache),
    Compass(CompassCache),
    Dock(DockCache),
    Launchpad(LaunchpadCache),
    MissionControl(MissionControlCache),
    Sanctuary(SanctuaryCache),
    Stargate(StargateCache),
    Waypoint(WaypointCache),
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
        match nanos % 10 {
            0 => Self::Compass(CompassCache::new()),
            1 => Self::Waypoint(WaypointCache::new()),
            2 => Self::Sanctuary(SanctuaryCache::new()),
            3 => Self::Dock(DockCache::new()),
            4 => Self::Atlas(AtlasCache::new()),
            5 => Self::MissionControl(MissionControlCache::new()),
            6 => Self::Launchpad(LaunchpadCache::new()),
            7 => Self::Bridge(BridgeCache::new()),
            8 => Self::BaseCamp(BaseCampCache::new()),
            _ => Self::Stargate(StargateCache::new()),
        }
    }

    /// Display name shown as the dim session label above the greeting.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Atlas(_) => "Atlas",
            Self::BaseCamp(_) => "Base Camp",
            Self::Bridge(_) => "The Bridge",
            Self::Compass(_) => "Compass",
            Self::Dock(_) => "The Dock",
            Self::Launchpad(_) => "Launchpad",
            Self::MissionControl(_) => "Mission Control",
            Self::Sanctuary(_) => "Sanctuary",
            Self::Stargate(_) => "Stargate",
            Self::Waypoint(_) => "Waypoint",
            Self::Unimplemented => "",
        }
    }

    /// Invalidate the cache — call when the palette changes.
    pub fn clear_cache(&mut self) {
        match self {
            Self::Atlas(c) => c.cache.clear(),
            Self::BaseCamp(c) => c.cache.clear(),
            Self::Bridge(c) => c.cache.clear(),
            Self::Compass(c) => c.cache.clear(),
            Self::Dock(c) => c.cache.clear(),
            Self::Launchpad(c) => c.cache.clear(),
            Self::MissionControl(c) => c.cache.clear(),
            Self::Sanctuary(c) => c.cache.clear(),
            Self::Stargate(c) => c.cache.clear(),
            Self::Waypoint(c) => c.cache.clear(),
            Self::Unimplemented => {}
        }
    }

    /// Build the Canvas element for this doodle.
    pub fn view<'a>(
        &'a self,
        palette: &'static Palette,
        mode: Mode,
        cursor_pos: iced::Point,
    ) -> Element<'a, NewTabMsg> {
        match self {
            Self::Atlas(c) => Canvas::new(atlas::AtlasProgram {
                cache: &c.cache,
                palette,
                mode,
                cursor_pos,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Compass(c) => Canvas::new(compass::CompassProgram {
                cache: &c.cache,
                palette,
                mode,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Waypoint(c) => Canvas::new(waypoint::WaypointProgram {
                cache: &c.cache,
                palette,
                mode,
                cursor_pos,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Sanctuary(c) => Canvas::new(sanctuary::SanctuaryProgram {
                cache: &c.cache,
                palette,
                mode,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Dock(c) => Canvas::new(dock::DockProgram {
                cache: &c.cache,
                palette,
                mode,
                cursor_pos,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Launchpad(c) => Canvas::new(launchpad::LaunchpadProgram {
                cache: &c.cache,
                palette,
                mode,
                start: c.start,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::MissionControl(c) => Canvas::new(mission_control::MissionControlProgram {
                cache: &c.cache,
                palette,
                mode,
                cursor_pos,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Bridge(c) => Canvas::new(bridge::BridgeProgram {
                cache: &c.cache,
                palette,
                mode,
                cursor_pos,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::BaseCamp(c) => Canvas::new(base_camp::BaseCampProgram {
                cache: &c.cache,
                palette,
                mode,
                cursor_pos,
            })
            .width(Length::Fill)
            .height(Length::Fixed(DOODLE_H))
            .into(),

            Self::Stargate(c) => Canvas::new(stargate::StargateProgram {
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
