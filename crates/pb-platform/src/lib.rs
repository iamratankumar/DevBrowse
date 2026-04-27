//! OS adapter trait definitions — Layer 5, deferred to v2.
//!
//! All five adapter traits are defined here as stubs.
//! Concrete Linux/macOS/Windows/Android implementations inject these at startup.

pub mod filesystem;
pub mod input;
pub mod network;
pub mod notification;
pub mod window;
