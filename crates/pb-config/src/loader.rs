//! TOML config loader + validation — Module 3.
//!
//! Loading sequence:
//!   1. `permissions::ensure_owner_only(path)` — reject group/world-readable
//!      or -writable files (Unix; Windows TBD when its backend lands).
//!   2. Read file → parse TOML → `Config` (rejects unknown fields by schema).
//!   3. `validate()` — schema-level invariants (version match, URL shape,
//!      sync.enabled implies sync.backend, etc.).
//!
//! Saving uses an atomic write-and-rename pattern: write to `<path>.tmp`,
//! lock its mode to 0600, then rename over the original. A crash mid-write
//! leaves the previous config intact; the temp file inherits the same
//! owner-only permission posture.

use crate::permissions;
use crate::schema::{Config, DohProvider, Mode, SearchEngine, SyncBackend, CURRENT_SCHEMA_VERSION};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("config TOML parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("config TOML serialize error: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("config schema version mismatch: file has {found}, this binary expects {expected}")]
    SchemaVersion { found: u32, expected: u32 },

    #[error("config validation error: {0}")]
    Validation(String),

    #[error("config file permission error: {0}")]
    Permission(String),
}

/// Load, parse, validate, and permission-check a config file.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    permissions::ensure_owner_only(path).map_err(|e| ConfigError::Permission(e.to_string()))?;
    let bytes = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&bytes)?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Atomically save a config to disk with owner-only permissions (0600 on Unix).
pub fn save(path: &Path, config: &Config) -> Result<(), ConfigError> {
    validate(config)?;
    let s = toml::to_string_pretty(config)?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, s)?;
    permissions::lock_owner_only(&tmp).map_err(|e| ConfigError::Permission(e.to_string()))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    s.into()
}

/// Schema-level invariants checked on every load and save.
///
/// pb-config does **not** check semantic things that require other crates
/// (e.g. whether the DoH host is in the whitelist — that's Module 20). It
/// catches shape errors early so the rest of the system gets a known-good
/// `Config`.
pub fn validate(cfg: &Config) -> Result<(), ConfigError> {
    if cfg.version != CURRENT_SCHEMA_VERSION {
        return Err(ConfigError::SchemaVersion {
            found: cfg.version,
            expected: CURRENT_SCHEMA_VERSION,
        });
    }

    // L25: System DNS forbidden when default mode is Strict (§3.3 DoH-only).
    if cfg.privacy.default_mode == Mode::Strict
        && matches!(cfg.network.provider, DohProvider::System)
    {
        return Err(ConfigError::Validation(
            "network.provider = system is not allowed when privacy.default_mode = strict (architecture §3.3)".to_string(),
        ));
    }

    if let DohProvider::Custom { url } = &cfg.network.provider {
        if !url.starts_with("https://") {
            return Err(ConfigError::Validation(format!(
                "network.provider custom URL must be https://, got {url:?}"
            )));
        }
    }

    if let SearchEngine::Custom { url } = &cfg.search.default_engine {
        if !url.starts_with("https://") {
            return Err(ConfigError::Validation(format!(
                "search.default_engine custom URL must be https://, got {url:?}"
            )));
        }
        if !url.contains("{query}") {
            return Err(ConfigError::Validation(
                "search.default_engine custom URL must contain a {query} placeholder".to_string(),
            ));
        }
    }

    if cfg.sync.enabled && cfg.sync.backend.is_none() {
        return Err(ConfigError::Validation(
            "sync.enabled = true requires sync.backend to be set".to_string(),
        ));
    }

    if let Some(SyncBackend::WebDav { url }) = &cfg.sync.backend {
        let is_localhost_http =
            url.starts_with("http://localhost") || url.starts_with("http://127.0.0.1");
        if !(url.starts_with("https://") || is_localhost_http) {
            return Err(ConfigError::Validation(format!(
                "sync.backend webdav.url must be https:// (or http://localhost for self-host), got {url:?}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Config, DohProvider, Mode, SyncBackend, SyncConfig};

    #[test]
    fn validate_default_config_passes() {
        let cfg = Config::default();
        validate(&cfg).expect("default config must pass validation");
    }

    #[test]
    fn validate_rejects_http_custom_doh() {
        let mut cfg = Config::default();
        cfg.network.provider = DohProvider::Custom {
            url: "http://insecure.example/dns-query".into(),
        };
        match validate(&cfg) {
            Err(ConfigError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_system_dns_with_strict_default() {
        let mut cfg = Config::default();
        cfg.privacy.default_mode = Mode::Strict;
        cfg.network.provider = DohProvider::System;
        match validate(&cfg) {
            Err(ConfigError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_system_dns_with_standard_default() {
        let mut cfg = Config::default();
        cfg.network.provider = DohProvider::System;
        validate(&cfg).expect("system DNS is allowed in Standard mode (§3.2)");
    }

    #[test]
    fn validate_accepts_curated_doh_providers() {
        for provider in [
            DohProvider::NextDns,
            DohProvider::Cloudflare,
            DohProvider::Quad9,
        ] {
            let mut cfg = Config::default();
            cfg.network.provider = provider.clone();
            validate(&cfg)
                .unwrap_or_else(|e| panic!("curated provider {provider:?} must validate: {e}"));
        }
    }

    #[test]
    fn validate_rejects_custom_search_without_https() {
        let mut cfg = Config::default();
        cfg.search.default_engine = SearchEngine::Custom {
            url: "http://example.com/?q={query}".into(),
        };
        match validate(&cfg) {
            Err(ConfigError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_custom_search_without_query_placeholder() {
        let mut cfg = Config::default();
        cfg.search.default_engine = SearchEngine::Custom {
            url: "https://example.com/no-placeholder".into(),
        };
        match validate(&cfg) {
            Err(ConfigError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_sync_enabled_without_backend() {
        let cfg = Config {
            sync: SyncConfig {
                enabled: true,
                backend: None,
            },
            ..Config::default()
        };
        match validate(&cfg) {
            Err(ConfigError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_http_webdav() {
        let cfg = Config {
            sync: SyncConfig {
                enabled: true,
                backend: Some(SyncBackend::WebDav {
                    url: "http://evil.example/dav".into(),
                }),
            },
            ..Config::default()
        };
        match validate(&cfg) {
            Err(ConfigError::Validation(_)) => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_localhost_webdav_for_self_host() {
        let cfg = Config {
            sync: SyncConfig {
                enabled: true,
                backend: Some(SyncBackend::WebDav {
                    url: "http://localhost:8080/dav".into(),
                }),
            },
            ..Config::default()
        };
        validate(&cfg).expect("self-hosted localhost WebDAV must be allowed");
    }

    #[test]
    fn validate_rejects_wrong_schema_version() {
        let cfg = Config {
            version: 9999,
            ..Config::default()
        };
        match validate(&cfg) {
            Err(ConfigError::SchemaVersion {
                found: 9999,
                expected,
            }) => assert_eq!(expected, CURRENT_SCHEMA_VERSION),
            other => panic!("expected SchemaVersion error, got {other:?}"),
        }
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let path = dir.join(format!("pb-config-test-{pid}-save_load.toml"));
        let _ = std::fs::remove_file(&path);

        let original = Config::default();
        save(&path, &original).expect("save must succeed");

        let loaded = load(&path).expect("load must succeed");
        assert_eq!(loaded, original);

        let _ = std::fs::remove_file(&path);
    }
}
