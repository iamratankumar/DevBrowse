//! Browser UI — Phase 8 (Modules 42–64).
//!
//! Technology: Iced 0.14 (wgpu backend, architecture v1.24 stack lock).
//! Desktop targets: Linux, macOS, Windows.
//! Mobile UI shells (iOS SwiftUI, Android Jetpack Compose) land in Phase 12.
//!
//! Module 42 deliverables (this session):
//!   - `design`  — design constants emitted from design/tokens.json.
//!   - `glass`   — frosted-glass Iced canvas widget + shaders/glass.wgsl.
//!   - `shell`   — Iced application root (wallpaper, mode identity, command bus).
//!   - `vibrancy`— OS vibrancy adapter stub (Phase 8 = NoOpVibrancy).
//!
//! Modules 43-64 are pending; their source stubs exist but contain no
//! implementation. Each will be implemented in order in subsequent sessions.

#![forbid(unsafe_code)]
#![allow(dead_code)] // stubs for pending modules 43-64

// ── UI regression scenarios (test-only, zero production overhead) ──────────
#[cfg(test)]
mod regression;

// ── Module 42 — UI shell (done) ────────────────────────────────────────────
pub mod design; // design constants (codegen from design/tokens.json)
pub mod glass; // GlassPanel widget + glass.wgsl
pub mod shell; // Iced application root (Mode, AppState, run())
pub mod vibrancy; // VibrancyAdapter trait + NoOpVibrancy stub

// ── Modules 43-64 — pending; stubs only ────────────────────────────────────
pub mod address_bar;
pub mod bookmarks;
pub mod card_view;
pub mod devtools;
pub mod downloads;
pub mod file_picker;
pub mod find;
pub mod history;
pub mod network_viewer;
pub mod doodles;
pub mod new_tab_screen;
pub mod notifications;
pub mod pdf_viewer;
pub mod permission_center;
pub mod pip;
pub mod print;
pub mod reader_mode;
pub mod settings;
pub mod sidebar;
pub mod site_customizer;
pub mod strict_popup;
pub mod tab_bar;
pub mod tab_search;
pub mod wizard;
pub mod zoom;
