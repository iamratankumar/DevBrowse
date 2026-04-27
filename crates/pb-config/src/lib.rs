//! Shared config contract for the DevBrowse process model.
//!
//! Dependency rule: any crate may import this one for config structs only.
//! This crate must never import any other pb-* crate.

#![forbid(unsafe_code)]

pub mod loader;
pub mod permissions;
pub mod schema;
