//! pb-browser — DevBrowse orchestrator binary.
//!
//! Spawns and manages all child processes (identity, storage, network, GPU).
//! Communicates with them exclusively via IPC (pb-ipc). Never imports their
//! crates directly — zero exceptions to this rule.

mod shutdown;
mod startup;

fn main() {
    // Phase 11 (Module 70): full startup sequence + graceful shutdown.
}
