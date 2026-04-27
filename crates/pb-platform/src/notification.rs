//! NotificationAdapter — Module 2.
//!
//! Permission state is owned per identity profile (pb-identity, Module 7) and
//! consulted before this trait is invoked. This trait does not persist grants.

use crate::PlatformError;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Notification {
    pub title: String,
    pub body: String,
    pub icon: Option<PathBuf>,
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
