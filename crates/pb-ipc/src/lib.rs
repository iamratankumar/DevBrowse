//! Shared IPC contract for the DevBrowse process model.
//!
//! Dependency rule: any crate may import this one for message types only.
//! This crate must never import any other pb-* crate.

pub mod messages;
pub mod transport;
