//! Identity warnings, Module 11.
//!
//! Advisory signals from the identity layer to the UI. Warnings NEVER gate
//! isolation: a Strict tab refusing DevTools is enforced at the policy
//! point; the warning is just the breadcrumb that tells the UI to show a
//! toast / counter / badge.
//!
//! The proto schema (Module 5) defines `pb_ipc::IdentityWarning` with three
//! string fields: `profile_id`, `code`, `message`. This module gives those
//! fields strong types: a [`WarningCode`] enum (machine-readable) and a
//! [`Warning`] struct (typed mirror of the proto). Conversions in both
//! directions are provided; unknown codes from the wire are rejected
//! ([`WarningParseError::UnknownCode`]) so the UI never silently drops a
//! warning whose code rolled forward in a newer build.
//!
//! The orchestrator (Module 80, deferred) is responsible for *emitting*
//! warnings. Lifecycle / scheduler do not call into this module; that
//! coupling would mix policy enforcement with policy reporting.
//!
//! [`WarningCounter`] is a per-profile tally for the "Strict tab soft
//! warning" badge: count how many warnings of each kind a profile has seen
//! so the UI can render a single number without re-walking a log.
//!
//! TODO(Module 80, orchestrator): wire emission. The orchestrator owns
//!   what to do with a Warning (push to UI via IPC, increment counter,
//!   record telemetry per L27 redaction rules).
//! TODO(L27 redaction): when warnings are persisted, the `message` field
//!   may contain user-visible URL fragments. Disk-side logging needs to
//!   redact per the L27 contract before write. RAM-only is fine as-is.

use crate::profile::IdentityProfile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

/// Machine-readable warning code. The string form (snake_case) is what
/// crosses IPC; the enum form is what Rust call sites match on.
///
/// New codes are added by extending this enum AND updating
/// [`WarningCode::as_str`] / [`WarningCode::from_str`] in lockstep. The
/// match in `from_str` is exhaustive on purpose so adding a variant is a
/// compile error until both directions are wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    /// User attempted DevTools in a Strict tab; blocked per L16.
    StrictDevToolsBlocked,
    /// Extension activation attempted in a Strict tab; blocked per §3.3.
    StrictExtensionBlocked,
    /// Translation / spellcheck attempted in a Strict tab; blocked per L20.
    StrictTranslationBlocked,
    /// Internal mismatch caught at attach time: a tab tried to land in a
    /// renderer whose mode/profile did not match. Reported as a warning
    /// so the UI can flag the bug; the attach itself is rejected.
    MixedModeShareAttempt,
}

impl WarningCode {
    /// Wire-form (snake_case) string used in `pb_ipc::IdentityWarning.code`.
    pub fn as_str(self) -> &'static str {
        match self {
            WarningCode::StrictDevToolsBlocked => "strict_devtools_blocked",
            WarningCode::StrictExtensionBlocked => "strict_extension_blocked",
            WarningCode::StrictTranslationBlocked => "strict_translation_blocked",
            WarningCode::MixedModeShareAttempt => "mixed_mode_share_attempt",
        }
    }
}

/// Parse the wire-form string. Unknown codes return
/// [`WarningParseError::UnknownCode`] so the UI never silently drops a
/// rolled-forward variant.
impl FromStr for WarningCode {
    type Err = WarningParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict_devtools_blocked" => Ok(WarningCode::StrictDevToolsBlocked),
            "strict_extension_blocked" => Ok(WarningCode::StrictExtensionBlocked),
            "strict_translation_blocked" => Ok(WarningCode::StrictTranslationBlocked),
            "mixed_mode_share_attempt" => Ok(WarningCode::MixedModeShareAttempt),
            other => Err(WarningParseError::UnknownCode(other.to_string())),
        }
    }
}

/// Errors raised when decoding a `pb_ipc::IdentityWarning` into a typed
/// [`Warning`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WarningParseError {
    /// The `profile_id` field on the wire was not a valid UUID.
    #[error("invalid profile_id: {0}")]
    InvalidProfileId(String),
    /// The `code` field on the wire was not a known [`WarningCode`].
    #[error("unknown warning code: {0}")]
    UnknownCode(String),
}

/// Typed mirror of `pb_ipc::IdentityWarning`. Identity-layer code creates
/// `Warning`; the orchestrator converts to the proto type at the IPC
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub profile_id: Uuid,
    pub code: WarningCode,
    pub message: String,
}

impl Warning {
    /// Construct a warning for the given profile, code, and human-readable
    /// detail. `message` is what the UI ultimately renders; keep it short
    /// and free of secrets (see L27 TODO at the module level).
    pub fn new(profile: &IdentityProfile, code: WarningCode, message: impl Into<String>) -> Self {
        Self {
            profile_id: profile.profile_id(),
            code,
            message: message.into(),
        }
    }
}

impl From<Warning> for pb_ipc::messages::IdentityWarning {
    fn from(w: Warning) -> Self {
        pb_ipc::messages::IdentityWarning {
            profile_id: w.profile_id.to_string(),
            code: w.code.as_str().to_string(),
            message: w.message,
        }
    }
}

impl TryFrom<pb_ipc::messages::IdentityWarning> for Warning {
    type Error = WarningParseError;

    fn try_from(w: pb_ipc::messages::IdentityWarning) -> Result<Self, Self::Error> {
        let profile_id = Uuid::parse_str(&w.profile_id)
            .map_err(|_| WarningParseError::InvalidProfileId(w.profile_id))?;
        let code = WarningCode::from_str(&w.code)?;
        Ok(Warning {
            profile_id,
            code,
            message: w.message,
        })
    }
}

/// Per-profile tally of warning counts. Used by the UI to render a single
/// "n issues" badge without re-walking a log.
///
/// Counts are in-memory only. Persistence (if any) is the orchestrator's
/// job; per L27 the default is RAM-only.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WarningCounter {
    counts: HashMap<Uuid, HashMap<WarningCode, u64>>,
}

impl WarningCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the count for `(profile_id, code)`. Returns the new count.
    pub fn record(&mut self, profile_id: Uuid, code: WarningCode) -> u64 {
        let per_code = self.counts.entry(profile_id).or_default();
        let entry = per_code.entry(code).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Count of a specific warning code for a profile. `0` if never seen.
    pub fn count_for(&self, profile_id: Uuid, code: WarningCode) -> u64 {
        self.counts
            .get(&profile_id)
            .and_then(|m| m.get(&code))
            .copied()
            .unwrap_or(0)
    }

    /// Sum across all codes for a profile. `0` if profile has no warnings.
    pub fn total_for(&self, profile_id: Uuid) -> u64 {
        self.counts
            .get(&profile_id)
            .map(|m| m.values().sum())
            .unwrap_or(0)
    }

    /// Drop all counts for a profile (e.g., on tab close). No-op if the
    /// profile is not tracked.
    pub fn reset(&mut self, profile_id: Uuid) {
        self.counts.remove(&profile_id);
    }

    /// True if any profile has any recorded warning.
    pub fn is_empty(&self) -> bool {
        self.counts.values().all(|m| m.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{IdentityProfileBuilder, Mode};

    fn sample_profile() -> IdentityProfile {
        IdentityProfileBuilder::new()
            .name("Personal")
            .mode(Mode::Strict)
            .build()
            .unwrap()
    }

    #[test]
    fn warning_code_round_trips_through_string() {
        for c in [
            WarningCode::StrictDevToolsBlocked,
            WarningCode::StrictExtensionBlocked,
            WarningCode::StrictTranslationBlocked,
            WarningCode::MixedModeShareAttempt,
        ] {
            let s = c.as_str();
            let back = WarningCode::from_str(s).unwrap();
            assert_eq!(c, back, "round-trip failed for {s}");
        }
    }

    #[test]
    fn unknown_code_is_rejected() {
        let err = WarningCode::from_str("rolled_forward_in_v2").unwrap_err();
        assert_eq!(
            err,
            WarningParseError::UnknownCode("rolled_forward_in_v2".into())
        );
    }

    #[test]
    fn warning_to_proto_uses_snake_case_code() {
        let p = sample_profile();
        let w = Warning::new(&p, WarningCode::StrictDevToolsBlocked, "blocked here");
        let proto: pb_ipc::messages::IdentityWarning = w.clone().into();
        assert_eq!(proto.profile_id, p.profile_id().to_string());
        assert_eq!(proto.code, "strict_devtools_blocked");
        assert_eq!(proto.message, "blocked here");
    }

    #[test]
    fn proto_to_warning_round_trip() {
        let p = sample_profile();
        let original = Warning::new(&p, WarningCode::MixedModeShareAttempt, "details");
        let proto: pb_ipc::messages::IdentityWarning = original.clone().into();
        let back: Warning = proto.try_into().unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn proto_to_warning_rejects_invalid_uuid() {
        let proto = pb_ipc::messages::IdentityWarning {
            profile_id: "not-a-uuid".into(),
            code: "strict_devtools_blocked".into(),
            message: String::new(),
        };
        let err = Warning::try_from(proto).unwrap_err();
        assert_eq!(
            err,
            WarningParseError::InvalidProfileId("not-a-uuid".into())
        );
    }

    #[test]
    fn proto_to_warning_rejects_unknown_code() {
        let p = sample_profile();
        let proto = pb_ipc::messages::IdentityWarning {
            profile_id: p.profile_id().to_string(),
            code: "future_code".into(),
            message: String::new(),
        };
        let err = Warning::try_from(proto).unwrap_err();
        assert_eq!(err, WarningParseError::UnknownCode("future_code".into()));
    }

    #[test]
    fn counter_starts_empty() {
        let c = WarningCounter::new();
        assert!(c.is_empty());
        assert_eq!(
            c.count_for(Uuid::nil(), WarningCode::StrictDevToolsBlocked),
            0
        );
        assert_eq!(c.total_for(Uuid::nil()), 0);
    }

    #[test]
    fn counter_record_increments_and_returns_new_count() {
        let mut c = WarningCounter::new();
        let p = Uuid::new_v4();
        assert_eq!(c.record(p, WarningCode::StrictDevToolsBlocked), 1);
        assert_eq!(c.record(p, WarningCode::StrictDevToolsBlocked), 2);
        assert_eq!(c.record(p, WarningCode::StrictExtensionBlocked), 1);
        assert_eq!(c.count_for(p, WarningCode::StrictDevToolsBlocked), 2);
        assert_eq!(c.count_for(p, WarningCode::StrictExtensionBlocked), 1);
        assert_eq!(c.total_for(p), 3);
        assert!(!c.is_empty());
    }

    #[test]
    fn counter_isolates_profiles() {
        let mut c = WarningCounter::new();
        let p1 = Uuid::new_v4();
        let p2 = Uuid::new_v4();
        c.record(p1, WarningCode::StrictDevToolsBlocked);
        c.record(p1, WarningCode::StrictDevToolsBlocked);
        c.record(p2, WarningCode::StrictDevToolsBlocked);
        assert_eq!(c.total_for(p1), 2);
        assert_eq!(c.total_for(p2), 1);
    }

    #[test]
    fn counter_reset_clears_only_one_profile() {
        let mut c = WarningCounter::new();
        let p1 = Uuid::new_v4();
        let p2 = Uuid::new_v4();
        c.record(p1, WarningCode::StrictDevToolsBlocked);
        c.record(p2, WarningCode::StrictDevToolsBlocked);
        c.reset(p1);
        assert_eq!(c.total_for(p1), 0);
        assert_eq!(c.total_for(p2), 1);
    }

    #[test]
    fn counter_reset_unknown_profile_is_noop() {
        let mut c = WarningCounter::new();
        c.reset(Uuid::new_v4());
        assert!(c.is_empty());
    }
}
