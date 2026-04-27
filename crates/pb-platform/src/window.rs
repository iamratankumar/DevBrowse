//! WindowAdapter — Module 2.
//!
//! Concrete backends (X11/Wayland/macOS/Windows/Android) deferred to v2 and live
//! outside this crate. This trait locks the surface they must implement.
//!
//! SECURITY INVARIANT — never change without explicit decision:
//!   Every method on this trait that returns geometry, DPR, or window position
//!   returns RAW OS values. None of these may reach content JS without first
//!   passing through pb-fingerprint bucketing (Module 25). Bucketing rules:
//!     * screen / window size → bucketed to coarse grid
//!     * device pixel ratio   → bucketed to {1.0, 1.5, 2.0, 3.0}
//!     * window position      → never exposed to content JS at all (chrome only)
//!   Backends MUST NOT add side channels (e.g. drag-drop file paths, raw
//!   monitor IDs) without explicit architectural review.

use crate::PlatformError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WindowId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone)]
pub struct WindowOptions {
    pub title: String,
    pub size: Size,
    pub resizable: bool,
}

pub trait WindowAdapter: Send + Sync {
    fn create(&self, opts: WindowOptions) -> Result<WindowId, PlatformError>;
    fn destroy(&self, id: WindowId) -> Result<(), PlatformError>;
    fn set_title(&self, id: WindowId, title: &str) -> Result<(), PlatformError>;
    fn set_size(&self, id: WindowId, size: Size) -> Result<(), PlatformError>;
    fn focus(&self, id: WindowId) -> Result<(), PlatformError>;

    /// Raw screen size. Bucket via pb-fingerprint before content exposure.
    fn screen_size(&self) -> Result<Size, PlatformError>;

    /// Raw device-pixel-ratio. Bucket via pb-fingerprint before content exposure.
    /// Returned as f32 × 1000 (e.g. 1500 = 1.5x) so the trait stays integer-only;
    /// avoids float-equality fingerprint surfaces leaking through the trait.
    fn device_pixel_ratio_milli(&self, id: WindowId) -> Result<u32, PlatformError>;

    /// Raw window position on the virtual desktop. Chrome-only — MUST NOT be
    /// exposed to content JS in any form, bucketed or otherwise (multi-monitor
    /// layout is itself a fingerprint).
    fn window_position(&self, id: WindowId) -> Result<Position, PlatformError>;
}
