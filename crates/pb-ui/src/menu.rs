//! Native system menu bar — deferred to OS-specific phases.
//!
//! Phase 8 delivers history via Cmd+Y (full-screen content-area panel).
//! Native OS menu bars ship per-platform in their dedicated phases using
//! each platform's own API — no cross-platform abstraction wrapper needed.
//!
//! TODO Phase 11.9 (Windows — Modules 93+):
//!   Win32 `CreateMenu` / `SetMenu(hwnd, hmenu)` via `windows-sys` crate.
//!   History submenu items: Back (Alt+Left), Forward (Alt+Right),
//!   Reopen Last Closed Tab (Ctrl+Shift+T), recent entries, Show All (Ctrl+Y).
//!
//! TODO Phase 12 (macOS — Module 97+):
//!   `NSMenu` / `NSApp.setMainMenu` via `objc2` + `objc2-app-kit` crates.
//!   Works with decorations:false frameless windows (sets the app-level menu,
//!   not the window chrome). History submenu accelerators: Cmd+[, Cmd+],
//!   Cmd+Shift+T, Cmd+Y.
//!
//! TODO Phase 12 (Linux/GNOME — Module 97+):
//!   `GtkMenuBar` via `gtk4` crate. Only for GNOME/GTK compositors.
//!
//! TODO Phase 12 (Linux/KDE — Module 97+):
//!   D-Bus `com.canonical.AppMenu.Registrar` for KDE Plasma's global menu.
//!   `QMenuBar` via Qt bindings is the alternative for KDE-native look.
//!
//! Command-bar integration (TODO Module 64.13):
//!   `h/`  or `history/` — filter history inline in the command bar.
//!   `t/`  or `tabs/`    — filter open tabs inline in the command bar.
//!   When the native menu "Show All History" fires (any platform), it should
//!   also offer to focus the command bar with `history/` pre-filled.
