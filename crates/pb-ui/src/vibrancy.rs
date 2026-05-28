//! pb-ui::vibrancy — Module 42 OS vibrancy adapter stub.
//!
//! Phase 8 ships opaque windows + in-app glass only. This trait stubs the
//! abstraction so the shell and glass module have a stable call site.
//!
//! The real implementation wires `window-vibrancy` crate behind a Settings
//! toggle in Phase 8.5 or post-v1 (architecture v1.24 §Future OS vibrancy).
//! Platforms: macOS `NSVisualEffectView`, Windows `DWM Mica`.
//!
//! Enforces: L28 (glass aesthetic — real OS vibrancy is an enhancement, not
//! a replacement; the shell falls back gracefully when `is_active()` is false).
//!
//! TODO Module 42 impl: wire `window-vibrancy` crate when OS vibrancy toggle
//! lands in Module 52 (Settings). Expose a `MacOsVibrancy` and `WindowsMica`
//! impl behind `#[cfg(target_os = ...)]` guards. Keep public API identical
//! across all platforms per architecture cross-platform principle.

/// OS-level window vibrancy adapter.
///
/// When `is_active()` returns `false` (the default for `NoOpVibrancy`), all
/// glass surfaces use the in-app WGSL blur path from `pb_ui::glass`. When
/// `is_active()` returns `true`, the shell sets `window::Settings::transparent`
/// and skips the in-app blur pass in favour of the OS compositor effect.
pub trait VibrancyAdapter: Send + Sync + 'static {
    /// Returns `true` if OS vibrancy is active for the given window.
    fn is_active(&self) -> bool;

    /// Apply vibrancy to the window. Called once after window creation.
    ///
    /// Returns `Ok(())` on success or when the platform does not support
    /// vibrancy (a no-op is always correct). Never panics; a non-fatal
    /// error is logged at `tracing::warn` level.
    fn apply(&self, _window_id: u64) -> Result<(), VibrancyError> {
        Ok(())
    }

    /// Remove vibrancy from the window (e.g., when the Settings toggle is
    /// disabled at runtime).
    fn remove(&self, _window_id: u64) -> Result<(), VibrancyError> {
        Ok(())
    }
}

/// Error type for vibrancy operations. Opaque display per L27.
#[derive(Debug, thiserror::Error)]
pub enum VibrancyError {
    #[error("vibrancy not supported on this platform")]
    Unsupported,
    #[error("vibrancy operation failed")]
    Failed,
}

/// Default no-op implementation. Phase 8 always returns `false` from
/// `is_active()` so the in-app glass path is used unconditionally.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpVibrancy;

impl VibrancyAdapter for NoOpVibrancy {
    fn is_active(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_vibrancy_is_never_active() {
        let v = NoOpVibrancy;
        assert!(!v.is_active());
    }

    #[test]
    fn noop_apply_returns_ok() {
        let v = NoOpVibrancy;
        assert!(v.apply(0).is_ok());
    }

    #[test]
    fn noop_remove_returns_ok() {
        let v = NoOpVibrancy;
        assert!(v.remove(0).is_ok());
    }

    #[test]
    fn vibrancy_error_display_is_opaque() {
        let e = VibrancyError::Unsupported;
        let s = e.to_string();
        // Must not expose platform detail — message is generic per L27.
        assert!(!s.contains("macos") && !s.contains("windows"));
        assert!(!s.is_empty());
    }
}
