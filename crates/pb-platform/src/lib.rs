//! OS adapter trait definitions — Layer 5. Concrete implementations deferred to v2.
//!
//! Module 2 locks the trait surface for all five adapters. Backends
//! (Linux X11/Wayland, macOS, Windows, Android) are injected at process
//! startup by pb-browser and are NOT part of this crate.
//!
//! Architecture rule: pb-platform has zero pb-* imports. It is a leaf crate.

#![forbid(unsafe_code)]

pub mod error;
pub mod filesystem;
pub mod input;
pub mod network;
pub mod notification;
pub mod window;

pub use error::PlatformError;
pub use filesystem::{FileHandle, FilePickerOptions, FileSystemAdapter};
pub use input::{GestureToken, InputAdapter, InputEvent, MouseButton};
pub use network::{Connectivity, NetworkAdapter, ProxyConfig};
pub use notification::{Notification, NotificationAdapter, PermissionState};
pub use window::{Position, Size, WindowAdapter, WindowId, WindowOptions};
