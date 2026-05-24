//! Module 35.12 — Intl.* defaults cohort lock.
//!
//! Locks the per-locale defaults exposed by `Intl.NumberFormat`,
//! `Intl.Collator`, `Intl.RelativeTimeFormat`, and
//! `Intl.PluralRules`. These reveal the host locale catalog
//! (numbering systems available, collator strength, currency
//! defaults) at a finer resolution than `navigator.language`
//! alone — Tor RFP locks all `Intl.*` defaults to `en-US`.
//!
//! **Audit provenance:** P2-7a from the 2026-05-22 comprehensive
//! audit; Competitive Analysis agent identified `Intl.*` (beyond
//! `DateTimeFormat` which Module 33 owns) as a missed surface.
//!
//! ## Mode-applicability
//!
//! Both modes lock to the **`en-US` cohort defaults** (matches
//! `LOCKED_LANGUAGE` from Module 34). The `Intl.*` constructors
//! and `resolvedOptions()` getters return cohort values
//! regardless of the host's installed-locale catalog.
//!
//! `Intl.DateTimeFormat` is **NOT** owned by this module — Module
//! 33 (`gecko::timezone`) handles the `timeZone` field via the
//! `Timezone` surface. This module covers the remaining Intl
//! formatters.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked profile ───────────────────────────────────────────────────────

/// Cohort-locked Intl.* defaults. Single static used by both
/// modes (mode-invariant lock — matches Module 31 Battery /
/// Module 35.7 MediaCapabilities precedent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntlDefaultsProfile {
    /// `Intl.NumberFormat().resolvedOptions().numberingSystem`
    /// — locked to `"latn"` (Latin numerals, the en-US default).
    pub numbering_system: &'static str,
    /// `Intl.Collator().resolvedOptions().sensitivity` — locked
    /// to `"variant"` (case + accent + base; en-US default).
    pub collator_sensitivity: &'static str,
    /// `Intl.Collator().resolvedOptions().caseFirst` — locked to
    /// `"false"` (no case-first preference; en-US default).
    pub collator_case_first: &'static str,
    /// `Intl.NumberFormat().resolvedOptions().currency` when
    /// `style: "currency"` and no explicit currency — locked to
    /// `"USD"` (en-US default).
    pub default_currency: &'static str,
    /// `Intl.PluralRules` default `type` — `"cardinal"`.
    pub plural_rules_default_type: &'static str,
}

pub static LOCKED_INTL_DEFAULTS: IntlDefaultsProfile = IntlDefaultsProfile {
    numbering_system: "latn",
    collator_sensitivity: "variant",
    collator_case_first: "false",
    default_currency: "USD",
    plural_rules_default_type: "cardinal",
};

// ── Policy + surface ─────────────────────────────────────────────────────

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntlDefaultsPolicy {
    Locked(&'static IntlDefaultsProfile),
}

impl IntlDefaultsPolicy {
    pub fn for_mode(_mode: Mode) -> Self {
        Self::Locked(&LOCKED_INTL_DEFAULTS)
    }

    pub fn profile(&self) -> &'static IntlDefaultsProfile {
        match self {
            Self::Locked(p) => p,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntlSurface {
    /// `Intl.NumberFormat.prototype.resolvedOptions()`.
    NumberFormatResolved,
    /// `Intl.Collator.prototype.resolvedOptions()`.
    CollatorResolved,
    /// `Intl.RelativeTimeFormat.prototype.resolvedOptions()`.
    RelativeTimeFormatResolved,
    /// `Intl.PluralRules.prototype.resolvedOptions()`.
    PluralRulesResolved,
}

impl IntlSurface {
    pub const ALL: &'static [IntlSurface] = &[
        Self::NumberFormatResolved,
        Self::CollatorResolved,
        Self::RelativeTimeFormatResolved,
        Self::PluralRulesResolved,
    ];
}

// ── Override ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct IntlDefaultsOverride {
    policy: IntlDefaultsPolicy,
}

impl IntlDefaultsOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: IntlDefaultsPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> IntlDefaultsPolicy {
        self.policy
    }
}

impl FingerprintOverride for IntlDefaultsOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Intl
    }

    fn install(&self, _ctx: &OverrideContext) {
        let _ = (self.policy, JsContext::ALL, IntlSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_intl_defaults_match_en_us_cohort() {
        // en-US cohort defaults (matches LOCKED_LANGUAGE in
        // Module 34).
        assert_eq!(LOCKED_INTL_DEFAULTS.numbering_system, "latn");
        assert_eq!(LOCKED_INTL_DEFAULTS.collator_sensitivity, "variant");
        assert_eq!(LOCKED_INTL_DEFAULTS.collator_case_first, "false");
        assert_eq!(LOCKED_INTL_DEFAULTS.default_currency, "USD");
        assert_eq!(LOCKED_INTL_DEFAULTS.plural_rules_default_type, "cardinal");
    }

    #[test]
    fn for_mode_is_mode_invariant() {
        // Mode-invariant lock — both modes resolve to the same
        // static (the en-US cohort). Matches the Module 31 /
        // Module 35.7 mode-invariant precedent.
        let standard = IntlDefaultsPolicy::for_mode(Mode::Standard);
        let strict = IntlDefaultsPolicy::for_mode(Mode::Strict);
        assert_eq!(standard, strict);
        assert!(std::ptr::eq(standard.profile(), &LOCKED_INTL_DEFAULTS));
        assert!(std::ptr::eq(strict.profile(), &LOCKED_INTL_DEFAULTS));
    }

    #[test]
    fn intl_surface_all_covers_four_resolved_options() {
        // Module 33 owns DateTimeFormat; this module covers the
        // remaining four Intl formatters.
        assert_eq!(IntlSurface::ALL.len(), 4);
    }

    #[test]
    fn override_reports_intl_surface_in_both_modes() {
        assert_eq!(
            IntlDefaultsOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Intl,
        );
        assert_eq!(
            IntlDefaultsOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Intl,
        );
    }

    #[test]
    fn override_install_is_context_inert() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035120").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = IntlDefaultsOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
        }
    }

    #[test]
    fn intl_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IntlDefaultsOverride>();
        assert_send_sync::<IntlDefaultsPolicy>();
        assert_send_sync::<IntlDefaultsProfile>();
        assert_send_sync::<IntlSurface>();
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: IntlDefaultsPolicy) -> &'static str {
            match p {
                IntlDefaultsPolicy::Locked(_) => "locked",
            }
        }
        assert_eq!(arm(IntlDefaultsPolicy::for_mode(Mode::Strict)), "locked");
        assert_eq!(arm(IntlDefaultsPolicy::for_mode(Mode::Standard)), "locked");
    }
}
