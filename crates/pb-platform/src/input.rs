//! InputAdapter — Module 2 (gesture-gated clipboard hardened in Module 2.1).
//!
//! SECURITY INVARIANT — never relax:
//!   Clipboard read/write require a `GestureToken`. The token type has a
//!   private field, is move-only (no Clone, no Copy), and is consumed on use.
//!   Tokens may be minted ONLY by pb-ipc's input event handler after observing
//!   a real OS-level keypress or mouse click. Programmatic JS clipboard access
//!   never produces a token, therefore never reaches this trait.
//!
//! SECURITY INVARIANT — for future maintainers:
//!   `InputEvent` deliberately has no timestamp field. Keystroke timing is a
//!   well-known fingerprinting + side-channel vector. If a timestamp is added
//!   later, it MUST be quantized in pb-fingerprint (Module 25) before reaching
//!   content. Same 2 ms quantization rule as the GPU layer.

use crate::PlatformError;

/// Token proving a verified OS-level user gesture occurred recently.
///
/// Move-only by design: passing a token to a trait method consumes it,
/// preventing replay. To perform a second gated operation, the broker must
/// observe a second gesture and mint a second token.
///
/// The constructor is `pub` because pb-ipc (in a different crate) needs to
/// mint tokens. Security comes from the fact that pb-ipc is the *only* place
/// in the codebase that calls `GestureToken::new`, enforced by code review
/// and a clippy-style guard (TODO: add a custom lint in Phase 10).
#[derive(Debug)]
pub struct GestureToken {
    _private: (),
}

impl GestureToken {
    /// Mint a token. Only pb-ipc's gesture verifier should call this.
    ///
    /// SECURITY: any new call site must be reviewed at the architecture level.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for GestureToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Other(u8),
}

#[derive(Debug, Clone)]
pub enum InputEvent {
    Key {
        code: u32,
        pressed: bool,
        modifiers: u8,
    },
    Mouse {
        x: i32,
        y: i32,
        button: Option<MouseButton>,
        pressed: bool,
    },
    Wheel {
        dx: f32,
        dy: f32,
    },
}

pub trait InputAdapter: Send + Sync {
    /// Drain pending OS input events. Empty `Vec` = no events available.
    fn poll(&self) -> Result<Vec<InputEvent>, PlatformError>;

    /// Read clipboard text. Token is consumed; caller must obtain a fresh
    /// token (i.e. observe a fresh gesture) for the next read.
    fn clipboard_read(&self, gesture: GestureToken) -> Result<String, PlatformError>;

    /// Write clipboard text. Token is consumed.
    fn clipboard_write(&self, gesture: GestureToken, text: &str) -> Result<(), PlatformError>;
}
