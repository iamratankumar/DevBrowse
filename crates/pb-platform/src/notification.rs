//! NotificationAdapter — Module 2.
//!
//! Permission state is owned per identity profile (pb-identity, Module 7) and
//! consulted before this trait is invoked. This trait does not persist grants.
//!
//! [`IconRef`] is the cross-platform icon reference. Desktop adapters
//! (Linux / macOS) consume the [`IconRef::File`] variant; mobile adapters
//! land in Phase 12 — iOS uses [`IconRef::Bundle`] (asset-catalog name),
//! Android uses [`IconRef::Drawable`] (resource id). Modeling all three at
//! the trait surface now keeps Phase 12 a code addition rather than a
//! breaking-change refactor (cross-platform principle, CLAUDE.md feedback).

use crate::PlatformError;
use std::path::PathBuf;

/// Cross-platform notification icon reference.
///
/// Variants are gated only by what the platform-specific adapter does at
/// runtime — every variant compiles on every target so the trait surface
/// stays uniform. An adapter that does not understand a given variant
/// returns [`PlatformError::Unsupported`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IconRef {
    /// Filesystem path to an icon file. Used by desktop adapters.
    File(PathBuf),
    /// iOS asset-catalog name (`UIImage(named:)`). Used by Phase 12 iOS adapter.
    Bundle(&'static str),
    /// Android drawable resource id (`R.drawable.*`). Used by Phase 12 Android adapter.
    Drawable(i32),
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub title: String,
    pub body: String,
    pub icon: Option<IconRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionState {
    Granted,
    Denied,
    Prompt,
}

pub trait NotificationAdapter: Send + Sync {
    fn permission(&self) -> Result<PermissionState, PlatformError>;
    fn request_permission(&self) -> Result<PermissionState, PlatformError>;
    fn show(&self, n: Notification) -> Result<(), PlatformError>;
}
