//! Typed config structs — Module 3.
//!
//! Strict serde schema: unknown fields are a load error, never silently
//! ignored. Defaults reflect the privacy-first posture (L18, L20, L21):
//! DuckDuckGo search, translation/spellcheck OFF, sync OFF until the wizard
//! configures it, telemetry OFF (always — field exists only so the wizard
//! L23 can ask once and persist "no").
//!
//! TOML field naming: `snake_case` everywhere (Rust convention). Enum tags
//! use explicit per-variant `rename` so the on-disk strings are short and
//! human-readable (`"webdav"`, `"google_drive"`, `"duckduckgo"`).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Bump when the schema changes in a non-compatible way. Migrations from
/// older schema versions are handled by the loader (currently: only v1).
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub privacy: PrivacyConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub search: SearchConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub history: HistoryConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub wizard: WizardConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CURRENT_SCHEMA_VERSION,
            privacy: PrivacyConfig::default(),
            network: NetworkConfig::default(),
            storage: StorageConfig::default(),
            search: SearchConfig::default(),
            ui: UiConfig::default(),
            history: HistoryConfig::default(),
            logging: LoggingConfig::default(),
            wizard: WizardConfig::default(),
            sync: SyncConfig::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

/// Privacy posture for new IdentityProfiles.
///
/// SECURITY INVARIANT (architecture §3.1): a profile's mode is locked at
/// creation. `default_mode` here only controls the **default** the UI
/// suggests for the next new profile — it does NOT retroactively change any
/// existing profile's mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Standard,
    Strict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FingerprintLevel {
    /// Coarse bucketing (Standard mode default — architecture §3.2 / §5.5).
    #[default]
    Standard,
    /// Tight bucketing, full hardware identifier normalization (§3.3 / §5.5).
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PrivacyConfig {
    pub default_mode: Mode,
    pub fingerprint_level: FingerprintLevel,
    /// L20: OFF by default. When ON, must be local-only (no remote service).
    pub translation_enabled: bool,
    /// L20: OFF by default. When ON, must be local-only.
    pub spellcheck_enabled: bool,
}

/// Curated DoH provider whitelist (L25).
///
/// L25 (v1.3): **Quad9 is the locked default.** Alternates: NextDNS,
/// Cloudflare, or a user-specified `Custom` HTTPS URL. `System` (OS resolver,
/// no DoH) is allowed ONLY in Standard mode per architecture §3.2 and is
/// rejected at config load when `privacy.default_mode = Strict` (§3.3
/// mandates DoH-only).
///
/// NextDNS personalization (L25 wizard rule): NextDNS's privacy benefit comes
/// from a per-account config ID embedded in the endpoint URL
/// (`https://dns.nextdns.io/<id>`). The first-launch wizard (Module 64)
/// enforces this: if a user picks NextDNS, they MUST enter their config ID;
/// the wizard then persists the choice as `Custom { url: <full URL> }`. If
/// the user declines to provide an ID, the wizard falls back to Quad9. The
/// bare `NextDns` variant remains available for advanced users editing TOML
/// directly (it resolves to NextDNS's generic anycast endpoint with no
/// account-level filtering).
///
/// Self-hosted DNS path: users running their own DoH resolver pick
/// `Custom { url }`. The validator (loader.rs) enforces HTTPS-only
/// (or http://localhost / http://127.0.0.1 for local self-host development).
///
/// The full provider whitelist (with concrete endpoint URLs and revocation
/// posture) is enforced by Module 20 (`pb-network/src/dns/whitelist.rs`).
/// pb-config only carries the user's choice; pb-network is the single
/// source of truth for endpoint URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind")]
pub enum DohProvider {
    /// L25 default: Quad9 (no-log, includes malware blocklist).
    #[default]
    #[serde(rename = "quad9")]
    Quad9,
    /// Generic NextDNS endpoint. Wizard-driven flow upgrades to
    /// `Custom { url }` once the user supplies their config ID.
    #[serde(rename = "nextdns")]
    NextDns,
    #[serde(rename = "cloudflare")]
    Cloudflare,
    /// OS resolver (no DoH). Standard mode only; rejected when
    /// `privacy.default_mode = Strict`.
    #[serde(rename = "system")]
    System,
    /// User-specified HTTPS DoH URL. Validated at config load: must be
    /// https://. Used for personalized NextDNS, self-hosted resolvers, or
    /// any other operator the user chooses to trust.
    #[serde(rename = "custom")]
    Custom { url: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// L25: DoH provider for new IdentityProfiles. Default = Quad9.
    pub provider: DohProvider,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// `None` = OS default (e.g. `~/.local/share/devbrowse` on Linux,
    /// `~/Library/Application Support/DevBrowse` on macOS,
    /// `%APPDATA%\DevBrowse` on Windows). Resolved by pb-storage at startup.
    pub data_dir: Option<PathBuf>,
    /// Architecture §3.3: Strict-mode tabs wipe their partition on tab close.
    /// Always true in v1.
    #[serde(default = "default_true")]
    pub strict_wipe_on_close: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            strict_wipe_on_close: true,
        }
    }
}

/// Default search engine. `Custom` URLs must be HTTPS and contain a
/// `{query}` placeholder; validated at config load.
///
/// L18: DuckDuckGo is the locked default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind")]
pub enum SearchEngine {
    #[default]
    #[serde(rename = "duckduckgo")]
    DuckDuckGo,
    #[serde(rename = "startpage")]
    Startpage,
    #[serde(rename = "brave")]
    BraveSearch,
    #[serde(rename = "mojeek")]
    Mojeek,
    #[serde(rename = "custom")]
    Custom { url: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchConfig {
    pub default_engine: SearchEngine,
    /// L18: ON by default — but suggestions are issued only via the user's
    /// chosen engine. There is no separate suggestion provider.
    pub suggestions_enabled: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            default_engine: SearchEngine::default(),
            suggestions_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiConfig {
    pub theme: Theme,
    /// UX flagship feature (architecture §8): identity selector visible in
    /// the tab strip. Default ON; user can hide via settings.
    pub show_identity_in_tab_bar: bool,
    /// L28: tab/sidebar layout. Default = SidebarHover (locked v1 UX).
    pub tab_layout: TabLayout,
    /// L28 accessibility floor: when true, the UI honours the OS
    /// "reduce transparency / reduce motion" setting and disables vibrancy
    /// effects in favour of solid backgrounds with WCAG AA contrast.
    pub reduce_transparency: bool,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: Theme::default(),
            show_identity_in_tab_bar: true,
            tab_layout: TabLayout::default(),
            reduce_transparency: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WizardConfig {
    /// Has the user completed the first-launch wizard (L23)? Until true,
    /// the orchestrator routes startup through `pb-wizard` (Module 64).
    pub completed: bool,
    /// Schema version at which the wizard was last completed. `None` until
    /// completion. Used to re-prompt only when newly added settings need a
    /// user choice on schema upgrade.
    pub completed_at_version: Option<u32>,
}

/// BYO-cloud sync backend (L21). Cloud impls land in Phase 11.5; the config
/// shape is stable from v1 so settings persist across versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum SyncBackend {
    #[serde(rename = "webdav")]
    WebDav { url: String },
    #[serde(rename = "google_drive")]
    GoogleDrive,
    #[serde(rename = "icloud")]
    ICloud,
    #[serde(rename = "dropbox")]
    Dropbox,
    #[serde(rename = "onedrive")]
    OneDrive,
    /// L24: local file backup/import (no cloud round-trip).
    #[serde(rename = "local_file")]
    LocalFile { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    /// L21: BYO-cloud sync. OFF by default; opted in via wizard.
    pub enabled: bool,
    /// MUST be `Some(_)` whenever `enabled = true` (validated at load).
    pub backend: Option<SyncBackend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Anti-goal §1.3: telemetry of any user-identifying data is forbidden.
    /// This field exists ONLY so the wizard (L23) can ask once and persist
    /// the user's "no" without re-prompting. No code path reads this as `true`.
    pub enabled: bool,
}

/// Tab strip layout variants (L28).
///
/// `SidebarHover` is the locked v1 default (left sidebar that opens on hover
/// from a hamburger affordance). `TopHorizontal` and `FullVertical` are
/// opt-in alternatives the user can select in Settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TabLayout {
    /// Default (L28): left sidebar that appears on hover.
    #[default]
    SidebarHover,
    /// Classic top horizontal tab bar.
    TopHorizontal,
    /// Always-visible vertical tab list on the left.
    FullVertical,
}

/// History data retention policy (L29, Standard mode only).
///
/// Strict mode never writes history regardless of this setting (§3.3).
/// The daily sweep in pb-storage auto-purges entries older than the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HistoryRetention {
    /// L29 default: keep history indefinitely.
    #[default]
    Forever,
    /// Wipe history at session end.
    Session,
    /// Keep only the last 7 days.
    Week,
    /// Keep only the last 30 days.
    Month,
}

/// History settings (L29).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HistoryConfig {
    /// Retention window. Standard mode only — Strict never writes history.
    pub retention: HistoryRetention,
}

/// Disk logging opt-in (L27).
///
/// Default: logs stay in a RAM ring buffer and are dropped at exit (L27).
/// When `disk_logging_enabled = true`, logs are written to disk with
/// auto-redaction of URLs, form bodies, identity names, and partition keys
/// before any write. No log line crosses the network without per-session
/// explicit user consent (e.g. attaching to a bug report).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// L27: default false — ephemeral RAM ring buffer.
    pub disk_logging_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_locked_policy() {
        let c = Config::default();
        assert_eq!(c.version, CURRENT_SCHEMA_VERSION);
        assert_eq!(c.privacy.default_mode, Mode::Standard);
        assert_eq!(c.privacy.fingerprint_level, FingerprintLevel::Standard);
        assert!(
            !c.privacy.translation_enabled,
            "L20: translation OFF by default"
        );
        assert!(
            !c.privacy.spellcheck_enabled,
            "L20: spellcheck OFF by default"
        );
        assert_eq!(
            c.network.provider,
            DohProvider::Quad9,
            "L25 (v1.3): Quad9 is the locked default DoH provider; NextDNS \
             requires a wizard-supplied config ID and is persisted as Custom"
        );
        assert!(
            c.storage.strict_wipe_on_close,
            "Strict-wipe is mandatory (§3.3)"
        );
        assert_eq!(
            c.search.default_engine,
            SearchEngine::DuckDuckGo,
            "L18: DDG default"
        );
        assert!(
            c.search.suggestions_enabled,
            "L18: suggestions ON via chosen engine"
        );
        assert!(
            c.ui.show_identity_in_tab_bar,
            "Identity selector is a flagship UX (§8)"
        );
        assert_eq!(
            c.ui.tab_layout,
            TabLayout::SidebarHover,
            "L28: sidebar-hover is the locked v1 default layout"
        );
        assert!(
            !c.ui.reduce_transparency,
            "L28: transparency not forced off by default; user opts in via OS setting"
        );
        assert_eq!(
            c.history.retention,
            HistoryRetention::Forever,
            "L29: history retention default is forever"
        );
        assert!(
            !c.logging.disk_logging_enabled,
            "L27: logs stay in RAM by default; disk opt-in only"
        );
        assert!(!c.wizard.completed);
        assert!(c.wizard.completed_at_version.is_none());
        assert!(!c.sync.enabled, "L21: sync OFF until wizard");
        assert!(c.sync.backend.is_none());
        assert!(!c.telemetry.enabled, "Anti-goal: telemetry forbidden");
    }

    #[test]
    fn toml_round_trip_default() {
        let c = Config::default();
        let s = toml::to_string(&c).expect("serialize");
        let c2: Config = toml::from_str(&s).expect("deserialize");
        assert_eq!(c, c2);
    }

    #[test]
    fn unknown_field_at_top_level_rejected() {
        let s = r#"
            version = 1
            mystery_setting = "should fail"
        "#;
        let r: Result<Config, _> = toml::from_str(s);
        assert!(r.is_err(), "deny_unknown_fields must reject unknown fields");
    }

    #[test]
    fn unknown_field_in_subsection_rejected() {
        let s = r#"
            version = 1

            [privacy]
            default_mode = "standard"
            fingerprint_level = "standard"
            translation_enabled = false
            spellcheck_enabled = false
            mystery_field = true
        "#;
        let r: Result<Config, _> = toml::from_str(s);
        assert!(r.is_err(), "subsections must also deny unknown fields");
    }

    #[test]
    fn mode_serializes_lowercase() {
        let mut c = Config::default();
        c.privacy.default_mode = Mode::Strict;
        let s = toml::to_string(&c).expect("serialize");
        assert!(
            s.contains("default_mode = \"strict\""),
            "expected lowercase 'strict', got:\n{s}"
        );
    }

    #[test]
    fn search_engine_custom_round_trip() {
        let mut c = Config::default();
        c.search.default_engine = SearchEngine::Custom {
            url: "https://search.example/?q={query}".to_string(),
        };
        let s = toml::to_string(&c).expect("serialize");
        let c2: Config = toml::from_str(&s).expect("deserialize");
        assert_eq!(c, c2);
    }

    #[test]
    fn sync_backend_webdav_round_trip() {
        let c = Config {
            sync: SyncConfig {
                enabled: true,
                backend: Some(SyncBackend::WebDav {
                    url: "https://dav.example/devbrowse".to_string(),
                }),
            },
            ..Config::default()
        };
        let s = toml::to_string(&c).expect("serialize");
        let c2: Config = toml::from_str(&s).expect("deserialize");
        assert_eq!(c, c2);
    }

    #[test]
    fn omitted_subsections_use_defaults() {
        // Only `version` is required; every section is `#[serde(default)]`.
        let s = "version = 1\n";
        let c: Config = toml::from_str(s).expect("deserialize minimal");
        assert_eq!(c, Config::default());
    }

    #[test]
    fn version_is_required() {
        let s = "";
        let r: Result<Config, _> = toml::from_str(s);
        assert!(r.is_err(), "version must be required at the top level");
    }
}
