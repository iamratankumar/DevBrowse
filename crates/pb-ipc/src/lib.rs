//! Shared IPC contract for the DevBrowse process model.
//!
//! Dependency rule (L12): any crate may import this one for message types only.
//! This crate must never import any other pb-* crate.

#![forbid(unsafe_code)]

pub mod messages;
// transport.rs handles platform gating internally; always declare the module.
pub mod transport;

pub use transport::{
    IpcConnection, IpcError, IpcListener, IpcReadHalf, IpcWriteHalf, MAX_MESSAGE_BYTES,
};
