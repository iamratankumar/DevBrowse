//! Storage process — Layer 2, Phase 3 (Modules 12–17).
//!
//! The storage process is the sole gatekeeper for all persistent state.
//! Partition key checked on every read/write — no exceptions.

pub mod gatekeeper;
pub mod partition_key;
pub mod primitives;
pub mod process;
pub mod service_worker;
pub mod strict_wipe;
