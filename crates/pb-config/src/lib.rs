//! Shared config contract for the DevBrowse process model — Module 3.
//!
//! Dependency rule (architecture L12): any crate may import this one for
//! config structs only. This crate must never import any other pb-* crate.
//!
//! What lives here:
//!   * `schema` — typed `Config` struct + sub-structs + enums + defaults
//!   * `loader` — TOML parse, schema validation, atomic save
//!   * `permissions` — owner-only file mode enforcement (Unix; Windows TBD)
//!
//! Defaults reflect the privacy posture locked in `docs/architecture.md`:
//!   * L18 — DuckDuckGo default search, suggestions ON via chosen engine
//!   * L20 — translation / spellcheck OFF
//!   * L21 — sync OFF until the wizard configures a backend
//!   * §1.3 — telemetry always OFF (field exists only for the wizard)

#![forbid(unsafe_code)]

pub mod loader;
pub mod permissions;
pub mod schema;

pub use loader::{load, save, validate, ConfigError};
pub use schema::{
    Config, FingerprintLevel, GpuConfig, HistoryConfig, HistoryRetention, LoggingConfig, Mode,
    NetworkConfig, PrivacyConfig, SearchConfig, SearchEngine, StorageConfig, SyncBackend,
    SyncConfig, TabLayout, TelemetryConfig, Theme, UiConfig, WizardConfig, CURRENT_SCHEMA_VERSION,
};
