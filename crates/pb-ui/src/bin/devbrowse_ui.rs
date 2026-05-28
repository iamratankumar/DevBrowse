//! DevBrowse UI development binary — Phase 8 (Module 42+).
//!
//! Launches the Iced application shell directly for UI development.
//! In production this entry point is replaced by `pb-browser` (Phase 11
//! Module 80 orchestrator) which starts all crates via IPC.
//!
//! Usage: cargo run -p pb-ui --bin devbrowse_ui

fn main() -> iced::Result {
    pb_ui::shell::run()
}
