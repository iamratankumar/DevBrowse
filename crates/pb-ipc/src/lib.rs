//! Shared IPC contract for the DevBrowse process model.
//!
//! Dependency rule (L12): any crate may import this one for message types only.
//! This crate must never import any other pb-* crate.

#![forbid(unsafe_code)]

pub mod messages;
// transport.rs handles platform gating internally; always declare the module.
pub mod transport;

// IpcError and MAX_MESSAGE_BYTES are defined unconditionally in transport.rs.
pub use transport::{IpcError, MAX_MESSAGE_BYTES};

// Platform-specific connection types — present on Unix and Windows only.
#[cfg(any(unix, windows))]
pub use transport::{IpcConnection, IpcListener, IpcReadHalf, IpcWriteHalf};
