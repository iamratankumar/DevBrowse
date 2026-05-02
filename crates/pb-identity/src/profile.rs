//! IdentityProfile struct + builder + validation, Module 6.
//!
//! SECURITY INVARIANTS (architecture §3.1):
//!   * `profile_id` is minted once at build time and is immutable for the
//!     profile's lifetime. To "switch" identity, the lifecycle layer
//!     (Module 9) tears down and respawns; the existing profile is never
//!     mutated.
//!   * `mode` is locked at creation. There is no public setter.
//!
//! Consumed by:
//!   * Module 7  (registry):  Serialize/Deserialize for on-disk persistence.
//!   * Module 8  (scheduler): `mode` + `profile_id` drive the renderer
//!     *sharing rule (§3.4).
//!   * Module 9  (lifecycle): IdentityProfile is the spawn token.
//!   * Module 12 (sandbox):   `mode` selects the kernel sandbox profile.
//!
//! TODO(Module 27 / 82): redactor must use `redacted_label()` in any log or
//!   crash-report write per L27 + §5.10. Default Debug shows the user-visible
//!   name and is acceptable inside the trusted broker; it must NOT survive a
//!   redaction pass without being rewritten.
//! TODO(Module 27): consider salting `redacted_label()`'s id prefix with a
//!   per-session value if cross-line correlation in opt-in disk logs becomes
//!   a concern.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Maximum byte length for `IdentityProfile.name` after trimming.
///
/// Tight enough to fit in tab-strip UI without truncation while still
/// allowing genuinely descriptive labels.
pub const MAX_NAME_LEN: usize = 64;

/// Privacy posture for an IdentityProfile.
///
/// Mirrors `pb_config::Mode`; conversion adapters live below. pb-identity
/// owns the runtime semantics of Mode (renderer-sharing rule §3.4, sandbox
/// profile selection in Module 12). pb-config owns the on-disk representation.
///
/// `Copy` is intentional: Mode is a single byte and is moved across IPC and
/// process boundaries (orchestrator -> renderer harness -> storage broker)
/// many times per tab spawn. Cloning would be free; copying is the same
/// instruction with stricter borrow-check semantics. Treat it as a value
/// type, never a handle. Pairs with the architecture §3.1 invariant that
/// a profile's Mode is locked at creation: there is no setter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// §3.2: renderers may be shared across tabs of the same `profile_id`,
    /// extensions allowed, DevTools allowed, DoH preferred but system DNS
    /// permitted as fallback.
    #[default]
    Standard,
    /// §3.3: per-tab renderer (never shared), extensions blocked, DevTools
    /// blocked, DoH-only, max fingerprint normalization, strict-wipe on close.
    Strict,
}

impl From<pb_config::Mode> for Mode {
    fn from(m: pb_config::Mode) -> Self {
        match m {
            pb_config::Mode::Standard => Mode::Standard,
            pb_config::Mode::Strict => Mode::Strict,
        }
    }
}

impl From<Mode> for pb_config::Mode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Standard => pb_config::Mode::Standard,
            Mode::Strict => pb_config::Mode::Strict,
        }
    }
}

/// Validation errors produced by [`IdentityProfileBuilder::build`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("identity profile name is empty after trimming")]
    EmptyName,
    #[error("identity profile name exceeds {} bytes", MAX_NAME_LEN)]
    NameTooLong,
}

/// A privacy identity (architecture §3.1).
///
/// Construct via [`IdentityProfile::builder`]. All fields are private; the
/// only mutating path is the builder, which mints `profile_id` exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProfile {
    profile_id: Uuid,
    name: String,
    mode: Mode,
}

impl IdentityProfile {
    /// Start a new builder. Equivalent to [`IdentityProfileBuilder::new`].
    pub fn builder() -> IdentityProfileBuilder {
        IdentityProfileBuilder::new()
    }

    /// Stable identifier (UUID v4, CSPRNG per L7). Immutable for the
    /// profile's lifetime (§3.1).
    pub fn profile_id(&self) -> Uuid {
        self.profile_id
    }

    /// User-visible label. Already validated and trimmed.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Mode locked at creation (§3.1, §3.4).
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Non-leaking label for log / crash-report contexts (L27, §5.10).
    ///
    /// Returns `"identity:<first-8-hex-of-profile-id>"`. Does NOT contain
    /// the user-visible name, so it is safe to write to opt-in disk logs
    /// or crash reports after redaction.
    pub fn redacted_label(&self) -> String {
        let id = self.profile_id.simple().to_string();
        format!("identity:{}", &id[..8])
    }
}

/// Builder for [`IdentityProfile`].
///
/// Defaults: `mode = Mode::Standard` (matches `pb_config::Mode::default()`).
/// `name` is required; calling `build()` without a name returns
/// [`ProfileError::EmptyName`].
#[derive(Debug, Default)]
pub struct IdentityProfileBuilder {
    name: Option<String>,
    mode: Mode,
}

impl IdentityProfileBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Validate inputs and mint a fresh profile.
    ///
    /// `profile_id` is generated here via `Uuid::new_v4()`; this is the only
    /// path that produces an `IdentityProfile`, so §3.1 immutability follows
    /// from the absence of any other constructor and the private fields.
    pub fn build(self) -> Result<IdentityProfile, ProfileError> {
        let raw = self.name.unwrap_or_default();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ProfileError::EmptyName);
        }
        if trimmed.len() > MAX_NAME_LEN {
            return Err(ProfileError::NameTooLong);
        }
        Ok(IdentityProfile {
            profile_id: Uuid::new_v4(),
            name: trimmed.to_string(),
            mode: self.mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_happy_path() {
        let p = IdentityProfile::builder()
            .name("Personal")
            .mode(Mode::Standard)
            .build()
            .expect("valid profile");
        assert_eq!(p.name(), "Personal");
        assert_eq!(p.mode(), Mode::Standard);
        // L7: profile_id is a v4 UUID (CSPRNG-backed).
        assert_eq!(p.profile_id().get_version_num(), 4);
    }

    #[test]
    fn default_mode_is_standard() {
        let p = IdentityProfile::builder()
            .name("Work")
            .build()
            .expect("valid profile");
        assert_eq!(p.mode(), Mode::Standard);
    }

    #[test]
    fn empty_name_rejected() {
        let err = IdentityProfile::builder().name("").build().unwrap_err();
        assert_eq!(err, ProfileError::EmptyName);
    }

    #[test]
    fn whitespace_only_name_rejected() {
        let err = IdentityProfile::builder()
            .name("   \t  ")
            .build()
            .unwrap_err();
        assert_eq!(err, ProfileError::EmptyName);
    }

    #[test]
    fn missing_name_rejected() {
        let err = IdentityProfileBuilder::new().build().unwrap_err();
        assert_eq!(err, ProfileError::EmptyName);
    }

    #[test]
    fn name_at_max_length_accepted() {
        let name: String = "a".repeat(MAX_NAME_LEN);
        let p = IdentityProfile::builder()
            .name(name.clone())
            .build()
            .expect("max-length name should be accepted");
        assert_eq!(p.name(), name);
    }

    #[test]
    fn name_over_max_length_rejected() {
        let name: String = "a".repeat(MAX_NAME_LEN + 1);
        let err = IdentityProfile::builder().name(name).build().unwrap_err();
        assert_eq!(err, ProfileError::NameTooLong);
    }

    #[test]
    fn name_is_trimmed_on_build() {
        let p = IdentityProfile::builder()
            .name("  Personal  ")
            .build()
            .unwrap();
        assert_eq!(p.name(), "Personal");
    }

    #[test]
    fn profile_ids_are_unique_across_builds() {
        let a = IdentityProfile::builder().name("A").build().unwrap();
        let b = IdentityProfile::builder().name("A").build().unwrap();
        assert_ne!(a.profile_id(), b.profile_id());
    }

    #[test]
    fn mode_locked_at_creation() {
        // Invariant (§3.1): no public path mutates `mode` post-build.
        // The `mode` field is private and there is no `set_mode`. This test
        // pins the build-time value; future maintainers grep this name when
        // changing the API surface.
        let p = IdentityProfile::builder()
            .name("Strict-tab")
            .mode(Mode::Strict)
            .build()
            .unwrap();
        assert_eq!(p.mode(), Mode::Strict);
    }

    #[test]
    fn mode_conversion_round_trip() {
        for m in [Mode::Standard, Mode::Strict] {
            let cfg: pb_config::Mode = m.into();
            let back: Mode = cfg.into();
            assert_eq!(m, back);
        }
        for m in [pb_config::Mode::Standard, pb_config::Mode::Strict] {
            let id: Mode = m.into();
            let back: pb_config::Mode = id.into();
            assert_eq!(m, back);
        }
    }

    #[test]
    fn redacted_label_does_not_leak_name() {
        let p = IdentityProfile::builder()
            .name("Bank Account")
            .build()
            .unwrap();
        let label = p.redacted_label();
        assert!(
            !label.contains("Bank"),
            "redacted label leaked the user-visible name: {label}"
        );
        assert!(
            label.starts_with("identity:"),
            "expected 'identity:' prefix, got: {label}"
        );
        assert_eq!(label.len(), "identity:".len() + 8);
    }
}
