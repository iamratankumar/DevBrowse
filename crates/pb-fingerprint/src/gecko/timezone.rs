//! Module 33 — Timezone normalization.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the timezone
//!     accessor (`mozilla::intl::TimeZone`) is intercepted below the
//!     JS surface so worker / iframe / service-worker scopes share
//!     a single timezone view.
//!   * **L9 / §3.3 / §3.2 / L41** — locked tri-policy:
//!       * **Strict** — `LOCKED_TIMEZONE_PROFILE` (IANA `"UTC"`,
//!         offset 0, DST never observed). **Non-configurable** by
//!         any user setting — matches Tor Browser / Mullvad Browser's
//!         locked-UTC posture. L41 enforcement: even when a user
//!         supplies a non-UTC selection (via the Standard-mode
//!         API), Strict mode short-circuits and returns
//!         `NormalizedUtc(&LOCKED_TIMEZONE_PROFILE)` regardless.
//!       * **Standard** — **configurable** (Firefox-style). Default
//!         is `NativePassThrough` (host timezone via OS clock).
//!         When the user explicitly selects a timezone from the
//!         curated `COMMON_TIMEZONES` list, the policy becomes
//!         `UserConfigured(&'static TimezoneProfile)` and the
//!         libxul accessor returns the selected profile uniformly
//!         across every renderer for that IdentityProfile.
//!         Per-identity storage of the selection lives in
//!         pb-identity (Module 6) when that path lands; Module 33
//!         ships the policy surface today.
//!   * **§5.5** — central fingerprint bucketing: every timezone
//!     readback routes through one `TimezoneProfile`.
//!   * **threat-model A1** — `Date.getTimezoneOffset()` +
//!     `Intl.DateTimeFormat().resolvedOptions().timeZone` are the
//!     two highest-signal locale leaks short of `navigator.language`
//!     (a per-host signal that splits the global cohort into ~400
//!     IANA timezones). UTC collapses the Strict cohort to one
//!     bucket; Standard accepts the per-host signal as part of the
//!     §3.2 tradeoff.
//!
//! ## Locked decision (phase-5 Goal + §5.5 matrix v1.0)
//!
//! **Strict locks UTC; Standard preserves the native Gecko
//! timezone resolver.** Same cohort-by-choice posture as Modules
//! 25 (WebRTC) / 27 (Canvas) / 28 (WebGL) / 29 (Audio). Strict's
//! UTC is the cohort-correct value: it matches Tor Browser's
//! `privacy.resistFingerprinting` floor and gives every Strict
//! DevBrowse user the same `getTimezoneOffset` answer regardless
//! of host TZ. Standard inherits the host setting because timezone
//! is signal-light when combined with the §3.2 cohort overlap
//! (UA / Accept-Language are already exposed; timezone adds
//! ~log2(400) bits on a population already partitioned by
//! language).
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * `LOCKED_TIMEZONE_PROFILE` static — the cohort-locked UTC
//!     parameters the libxul-side timezone accessor returns under
//!     Strict.
//!   * `TimezoneSurface::ALL` covering every JS pathway:
//!     `Intl.DateTimeFormat.resolvedOptions().timeZone`,
//!     `Date.prototype.getTimezoneOffset`, `Date.prototype.toString`
//!     (the locale string embeds the TZ offset),
//!     `Date.prototype.toLocaleString` (locale-aware formatting
//!     embeds the TZ), and `Intl.Locale` defaults.
//!   * A `FingerprintOverride` impl for `WebIdlSurface::Timezone`;
//!     `install()` is a no-op pending the libxul accessor hook.
//!
//! It IS NOT:
//!   * The per-identity custom timezone path (phase-file Goal).
//!     That feature lives in pb-identity (per-profile config) and
//!     pb-ui (settings page); Module 33 ships only the per-Mode
//!     default. Standard renderers with a custom-tz IdentityProfile
//!     will route the override through pb-identity first; this
//!     module's `NativePassThrough` is the v1 fallback.
//!   * `navigator.language` / `Accept-Language` / `Intl.NumberFormat`
//!     defaults. Those are Module 34 (Navigator) territory; this
//!     module pins only the timezone surface.
//
// TODO(Module 1 / libxul): the timezone accessor lives at
//   `mozilla::intl::TimeZone` (or the analogous nsRFPService entry
//   point on the current libxul tag). Wire it to consult
//   `TimezoneOverride::profile()` so Strict-mode renderers always
//   answer with `LOCKED_TIMEZONE_PROFILE`. Standard renderers
//   leave the accessor untouched (the host TZ stays in place).
// TODO(Module 6 / pb-identity, future): the per-identity storage of
//   the user's selected timezone is a Standard-only setting that
//   will live in IdentityProfile. Module 33 already ships the
//   policy surface (`for_mode_with_user_selection`); pb-identity
//   will call into it. Strict ignores the selection per L41 —
//   asserted by `tests::strict_ignores_user_timezone_selection`.
// TODO(Phase 5.5 / Module 35.4): the L41 settings-lock enforcement
//   layer asserts that no settings path can produce a non-UTC
//   timezone for a Strict-mode renderer. Module 35.4 reads
//   `LOCKED_TIMEZONE_PROFILE` and verifies the assertion.
// TODO(Phase 10 / Module 71+): the CreepJS / FPStandard timezone
//   probe checks `Intl.DateTimeFormat().resolvedOptions().timeZone`
//   + `new Date().getTimezoneOffset()` + `new Date().toString()`
//   for cross-host consistency. Strict probes assert "UTC" / 0 /
//   "GMT+0000" regardless of host TZ; Standard probes are not
//   asserted (host TZ varies and is permitted).
// TODO(Module 27 / canvas cross-coupling, future): canvas rendering
//   that embeds time strings via `fillText(new Date().toString(), ...)`
//   currently routes through Module 27's locked rasterizer plus
//   the (mode-divergent) date string. Strict's canvas + UTC
//   string is fully deterministic; Standard's canvas + host-TZ
//   string is host-divergent, but the canvas rasterizer pass-through
//   in Standard already makes this acceptable per the §3.2 cohort.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked timezone profile (Strict cohort) ───────────────────────────────

/// Cohort-locked timezone parameters for Strict mode. The libxul
/// timezone accessor returns these values to JS regardless of host
/// OS timezone setting.
///
/// `Copy` + `Eq` + `Hash` because every field is a fixed-size
/// primitive or `&'static str`. The address-identity invariant
/// uses `ptr::eq` against `LOCKED_TIMEZONE_PROFILE` for the
/// cohort-singleton check (same shape as `LOCKED_CANVAS_PROFILE` /
/// `LOCKED_WEBGL_PROFILE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimezoneProfile {
    /// IANA timezone identifier (`Intl.DateTimeFormat.resolvedOptions().timeZone`).
    pub iana_name: &'static str,
    /// Offset from UTC in minutes (`Date.getTimezoneOffset()` returns
    /// the *negated* value; the override negates at the libxul
    /// boundary so this struct carries the natural sign).
    pub offset_minutes: i32,
    /// Whether DST applies. UTC never observes DST; locking `false`
    /// here forbids the libxul accessor from ever reporting a DST
    /// transition in Strict.
    pub dst_observed: bool,
    /// Short abbreviation used in `Date.toString` output ("GMT",
    /// "UTC", etc.). Locked to "UTC" for the Strict cohort.
    pub abbreviation: &'static str,
}

/// The v1 Strict-cohort timezone profile: UTC with no DST.
///
/// `static` (not `const`): cohort consumers (libxul accessor +
/// Phase 5.5 Module 35.4) compare by address. See canvas.rs /
/// fonts.rs / audio.rs / timers.rs for the rationale.
pub static LOCKED_TIMEZONE_PROFILE: TimezoneProfile = TimezoneProfile {
    iana_name: "UTC",
    offset_minutes: 0,
    dst_observed: false,
    abbreviation: "UTC",
};

// ── Curated list of common timezones for Standard mode ────────────────────
//
// Standard mode users may explicitly select a timezone from this list via
// the UI (future Module 64 wizard / pb-ui settings page). The list is
// curated rather than free-form so that:
//   1. Every user-selected TZ is a `&'static TimezoneProfile` (cohort
//      cohorts can still be analyzed; no arbitrary IANA names land in
//      the cohort surface).
//   2. The cohort of "users who selected America/New_York" is well-defined
//      and uniformly normalized across every Standard renderer.
//   3. `offset_minutes` is the standard-time baseline; the libxul-side
//      IANA database resolves DST at request time. The `dst_observed`
//      flag indicates whether the libxul resolver may add a DST offset.
//
// Adding a timezone to this list is a UX / cohort decision; the test
// `curated_timezone_list_covers_major_regions` documents the rationale.

/// US Eastern Time (EST / EDT). Standard offset UTC-05:00; DST observed.
pub static AMERICA_NEW_YORK: TimezoneProfile = TimezoneProfile {
    iana_name: "America/New_York",
    offset_minutes: -300,
    dst_observed: true,
    abbreviation: "EST",
};

/// US Central Time (CST / CDT). Standard offset UTC-06:00; DST observed.
pub static AMERICA_CHICAGO: TimezoneProfile = TimezoneProfile {
    iana_name: "America/Chicago",
    offset_minutes: -360,
    dst_observed: true,
    abbreviation: "CST",
};

/// US Pacific Time (PST / PDT). Standard offset UTC-08:00; DST observed.
pub static AMERICA_LOS_ANGELES: TimezoneProfile = TimezoneProfile {
    iana_name: "America/Los_Angeles",
    offset_minutes: -480,
    dst_observed: true,
    abbreviation: "PST",
};

/// UK / Ireland (GMT / BST). Standard offset UTC+00:00; DST observed.
pub static EUROPE_LONDON: TimezoneProfile = TimezoneProfile {
    iana_name: "Europe/London",
    offset_minutes: 0,
    dst_observed: true,
    abbreviation: "GMT",
};

/// Central European Time (CET / CEST). Standard offset UTC+01:00;
/// DST observed.
pub static EUROPE_BERLIN: TimezoneProfile = TimezoneProfile {
    iana_name: "Europe/Berlin",
    offset_minutes: 60,
    dst_observed: true,
    abbreviation: "CET",
};

/// India Standard Time. Standard offset UTC+05:30; no DST.
pub static ASIA_KOLKATA: TimezoneProfile = TimezoneProfile {
    iana_name: "Asia/Kolkata",
    offset_minutes: 330,
    dst_observed: false,
    abbreviation: "IST",
};

/// Singapore / Malaysia / Western China (HKT / SGT). Standard offset
/// UTC+08:00; no DST.
pub static ASIA_SINGAPORE: TimezoneProfile = TimezoneProfile {
    iana_name: "Asia/Singapore",
    offset_minutes: 480,
    dst_observed: false,
    abbreviation: "SGT",
};

/// Japan Standard Time. Standard offset UTC+09:00; no DST.
pub static ASIA_TOKYO: TimezoneProfile = TimezoneProfile {
    iana_name: "Asia/Tokyo",
    offset_minutes: 540,
    dst_observed: false,
    abbreviation: "JST",
};

/// Australian Eastern Time (AEST / AEDT). Standard offset UTC+10:00;
/// DST observed.
pub static AUSTRALIA_SYDNEY: TimezoneProfile = TimezoneProfile {
    iana_name: "Australia/Sydney",
    offset_minutes: 600,
    dst_observed: true,
    abbreviation: "AEST",
};

/// The curated set Standard-mode users may pick from. Same address-
/// identity discipline as the per-profile statics above: every
/// Standard renderer of a given selection points at one of these
/// `&'static` entries.
///
/// `LOCKED_TIMEZONE_PROFILE` (UTC) is the first entry so users
/// landing on UTC in Standard share the exact same static as
/// every Strict renderer — the canvas / fonts cross-module cohort-
/// unification pattern extended to timezone.
pub static COMMON_TIMEZONES: &[&TimezoneProfile] = &[
    &LOCKED_TIMEZONE_PROFILE,
    &AMERICA_LOS_ANGELES,
    &AMERICA_CHICAGO,
    &AMERICA_NEW_YORK,
    &EUROPE_LONDON,
    &EUROPE_BERLIN,
    &ASIA_KOLKATA,
    &ASIA_SINGAPORE,
    &ASIA_TOKYO,
    &AUSTRALIA_SYDNEY,
];

// ── Per-mode policy ───────────────────────────────────────────────────────

/// Per-mode timezone policy.
///
///   * **Strict** always resolves to `NormalizedUtc(&LOCKED_TIMEZONE_PROFILE)`
///     — non-configurable (Tor / Mullvad-style).
///   * **Standard** defaults to `NativePassThrough` (host timezone)
///     and may be set to `UserConfigured(...)` when the user
///     explicitly picks an entry from `COMMON_TIMEZONES`.
///
/// L41 enforcement is baked into `for_mode_with_user_selection`:
/// Strict ignores any user supplied timezone and returns the locked
/// UTC profile.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimezonePolicy {
    /// Standard default: native Gecko timezone resolver (host TZ).
    /// The override registers but `install` is a no-op so the
    /// libxul accessor is untouched.
    NativePassThrough,
    /// Standard with an explicit user selection from
    /// `COMMON_TIMEZONES`. The libxul accessor returns the
    /// referenced profile's values for every readback in the
    /// renderer. Every Standard renderer of the same IdentityProfile
    /// shares this selection.
    UserConfigured(&'static TimezoneProfile),
    /// Strict: the libxul accessor returns
    /// `LOCKED_TIMEZONE_PROFILE` for every readback. Non-loosenable
    /// (L41) — supplied user selections are ignored by
    /// `for_mode_with_user_selection`.
    NormalizedUtc(&'static TimezoneProfile),
}

impl TimezonePolicy {
    /// Locked default snapshot for `mode`:
    ///   * `Mode::Standard` -> `NativePassThrough` (host TZ)
    ///   * `Mode::Strict`   -> `NormalizedUtc(&LOCKED_TIMEZONE_PROFILE)`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::NativePassThrough,
            Mode::Strict => Self::NormalizedUtc(&LOCKED_TIMEZONE_PROFILE),
        }
    }

    /// User-configurable variant. The caller (future pb-identity)
    /// passes the user's selection from `COMMON_TIMEZONES`.
    ///
    ///   * `Mode::Standard, Some(tz)` -> `UserConfigured(tz)`
    ///   * `Mode::Standard, None`     -> `NativePassThrough`
    ///   * `Mode::Strict, _`          -> `NormalizedUtc(&LOCKED_TIMEZONE_PROFILE)`
    ///     **regardless of the supplied selection** (L41).
    ///
    /// The Strict-ignores-selection behavior is the L41 enforcement;
    /// asserted by `tests::strict_ignores_user_timezone_selection`.
    pub fn for_mode_with_user_selection(
        mode: Mode,
        user_tz: Option<&'static TimezoneProfile>,
    ) -> Self {
        match (mode, user_tz) {
            (Mode::Strict, _) => Self::NormalizedUtc(&LOCKED_TIMEZONE_PROFILE),
            (Mode::Standard, Some(tz)) => Self::UserConfigured(tz),
            (Mode::Standard, None) => Self::NativePassThrough,
        }
    }

    /// `Some(profile)` iff the policy carries a normalized profile
    /// (either Strict-locked UTC or Standard-user-selected). `None`
    /// for Standard's native pass-through.
    pub fn profile(&self) -> Option<&'static TimezoneProfile> {
        match *self {
            Self::NativePassThrough => None,
            Self::UserConfigured(p) => Some(p),
            Self::NormalizedUtc(p) => Some(p),
        }
    }

    /// True iff the libxul accessor hook will be activated (either
    /// Strict-locked or Standard with user selection). Equivalent
    /// to `profile().is_some()`; named predicate for call-site
    /// readability.
    pub fn normalizes(&self) -> bool {
        !matches!(self, Self::NativePassThrough)
    }
}

// ── Surface enumeration ───────────────────────────────────────────────────

/// Every JS pathway that exposes the timezone.
///
/// The libxul bridge MUST register the override behind every
/// variant — missing one leaves a residual leak even with the
/// obvious entry points (`getTimezoneOffset`,
/// `resolvedOptions().timeZone`) locked. `Intl.Locale` defaults
/// are included because the resolved locale on systems with
/// non-default `LC_TIME` carries the timezone hint.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimezoneSurface {
    /// `Intl.DateTimeFormat().resolvedOptions().timeZone` — the
    /// IANA name (most direct fingerprint leak).
    IntlDateTimeFormatResolvedTimeZone,
    /// `Date.prototype.getTimezoneOffset()` — offset in minutes.
    DateGetTimezoneOffset,
    /// `Date.prototype.toString()` — the default string
    /// representation embeds the timezone offset + abbreviation
    /// (`"Mon Oct 16 2023 12:00:00 GMT+0000 (UTC)"` in Strict).
    DateToString,
    /// `Date.prototype.toLocaleString()` /
    /// `toLocaleDateString` / `toLocaleTimeString` — locale-aware
    /// formatting that respects the timezone. Includes
    /// `Intl.DateTimeFormat.format()` and `.formatToParts()`.
    DateToLocaleString,
    /// `Intl.Locale` defaults — `new Intl.Locale('en')` resolves
    /// against host locale settings which carry timezone hints
    /// via `LC_TIME` / Windows region settings.
    IntlLocaleDefaults,
}

impl TimezoneSurface {
    /// Every surface the bridge must wire. Asserted against the
    /// phase-file edge-case list by
    /// `tests::timezone_surface_all_covers_edge_cases`.
    pub const ALL: &'static [TimezoneSurface] = &[
        Self::IntlDateTimeFormatResolvedTimeZone,
        Self::DateGetTimezoneOffset,
        Self::DateToString,
        Self::DateToLocaleString,
        Self::IntlLocaleDefaults,
    ];
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Timezone`.
///
/// Construct with `TimezoneOverride::new(mode)` so the policy is
/// resolved once at construction; the override is then registered
/// by the libxul bridge into every `JsContext` for the renderer.
///
/// Mode-divergent behavior is in the *policy*, not the *trait*:
/// every renderer registers a `TimezoneOverride`, but Strict-mode
/// `install` activates the UTC accessor and Standard-mode
/// `install` is a no-op. Same uniform-registration pattern as
/// Modules 27 / 28 / 29.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data, so `install(&OverrideContext)` produces
/// observationally identical state regardless of `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct TimezoneOverride {
    policy: TimezonePolicy,
}

impl TimezoneOverride {
    /// Construct with the mode-default policy (no user selection).
    /// Standard maps to `NativePassThrough` (host TZ); Strict maps
    /// to `NormalizedUtc(&LOCKED_TIMEZONE_PROFILE)`.
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: TimezonePolicy::for_mode(mode),
        }
    }

    /// Construct with an explicit user-selected timezone (Standard
    /// only; Strict ignores the selection per L41 and returns the
    /// locked UTC profile).
    pub fn with_user_selection(mode: Mode, user_tz: Option<&'static TimezoneProfile>) -> Self {
        Self {
            policy: TimezonePolicy::for_mode_with_user_selection(mode, user_tz),
        }
    }

    pub fn policy(&self) -> TimezonePolicy {
        self.policy
    }

    /// `Some(profile)` iff the override carries a normalized
    /// profile (Strict-locked UTC OR Standard user-selected).
    /// `None` for Standard pass-through to host TZ.
    pub fn profile(&self) -> Option<&'static TimezoneProfile> {
        self.policy.profile()
    }
}

impl FingerprintOverride for TimezoneOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Timezone
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect on any branch. The libxul timezone
        // accessor hook is not yet wired (see crate-level TODO).
        // When the FFI lands:
        //   * NormalizedUtc(p)     -> register a per-renderer
        //     accessor returning the profile (Strict-locked UTC).
        //   * UserConfigured(p)    -> register a per-renderer
        //     accessor returning the user-selected profile
        //     (Standard with explicit selection).
        //   * NativePassThrough    -> remain a no-op; native
        //     accessor stays in place (Standard default, host TZ).
        let _ = (self.policy, JsContext::ALL);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_profile_matches_strict_utc_definition() {
        // The v1 Strict-cohort timezone definition. Any change is
        // a cohort shift through the Adaptation protocol.
        assert_eq!(LOCKED_TIMEZONE_PROFILE.iana_name, "UTC");
        assert_eq!(LOCKED_TIMEZONE_PROFILE.offset_minutes, 0);
        assert!(!LOCKED_TIMEZONE_PROFILE.dst_observed);
        assert_eq!(LOCKED_TIMEZONE_PROFILE.abbreviation, "UTC");
    }

    #[test]
    fn standard_returns_native_pass_through() {
        let p = TimezonePolicy::for_mode(Mode::Standard);
        assert!(matches!(p, TimezonePolicy::NativePassThrough));
        assert_eq!(p.profile(), None);
        assert!(!p.normalizes());
    }

    #[test]
    fn strict_returns_normalized_utc_with_locked_profile() {
        let p = TimezonePolicy::for_mode(Mode::Strict);
        assert!(matches!(p, TimezonePolicy::NormalizedUtc(_)));
        let profile = p.profile().expect("Strict policy MUST carry a profile");
        // Address identity: every Strict renderer reads the same
        // singleton.
        assert!(std::ptr::eq(profile, &LOCKED_TIMEZONE_PROFILE));
        assert!(p.normalizes());
    }

    #[test]
    fn timezone_surface_all_covers_edge_cases() {
        // Phase-file edge cases for Module 33:
        //   - Intl.DateTimeFormat resolvedOptions().timeZone
        //     (IntlDateTimeFormatResolvedTimeZone)
        //   - Date.prototype.getTimezoneOffset
        //     (DateGetTimezoneOffset)
        //   - Intl.Locale defaults (IntlLocaleDefaults)
        // Plus the implicit-via-toString paths (DateToString +
        // DateToLocaleString) which embed timezone metadata in
        // the formatted output.
        assert_eq!(TimezoneSurface::ALL.len(), 5);
        for v in [
            TimezoneSurface::IntlDateTimeFormatResolvedTimeZone,
            TimezoneSurface::DateGetTimezoneOffset,
            TimezoneSurface::DateToString,
            TimezoneSurface::DateToLocaleString,
            TimezoneSurface::IntlLocaleDefaults,
        ] {
            assert!(
                TimezoneSurface::ALL.contains(&v),
                "missing surface: {:?}",
                v
            );
        }
    }

    #[test]
    fn timezone_override_reports_timezone_surface_under_both_modes() {
        assert_eq!(
            TimezoneOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Timezone
        );
        assert_eq!(
            TimezoneOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Timezone
        );
    }

    #[test]
    fn standard_override_has_no_profile_strict_does() {
        let standard = TimezoneOverride::new(Mode::Standard);
        let strict = TimezoneOverride::new(Mode::Strict);
        assert_eq!(standard.profile(), None);
        let p = strict.profile().expect("Strict MUST carry a profile");
        assert!(std::ptr::eq(p, &LOCKED_TIMEZONE_PROFILE));
    }

    #[test]
    fn timezone_override_install_is_context_inert() {
        // Worker / iframe / service-worker scopes must observe the
        // same timezone as the top frame (otherwise the divergence
        // itself becomes a side channel — a worker that sees a
        // different `getTimezoneOffset` from the top frame can be
        // used to confirm a renderer-sharing decision).
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000033").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = TimezoneOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Timezone);
        }
    }

    #[test]
    fn timezone_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<TimezoneOverride>();
        assert_send_sync::<TimezonePolicy>();
        assert_send_sync::<TimezoneProfile>();
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        // The bridge MUST match without a `_` arm so a new variant
        // (e.g. a hypothetical `IntlSegmenterDefaults` if Intl gains
        // a new timezone-carrying surface) fails compilation until
        // the bridge wires it.
        fn route(s: TimezoneSurface) -> &'static str {
            match s {
                TimezoneSurface::IntlDateTimeFormatResolvedTimeZone => {
                    "intl-date-time-format-resolved-time-zone"
                }
                TimezoneSurface::DateGetTimezoneOffset => "date-get-timezone-offset",
                TimezoneSurface::DateToString => "date-to-string",
                TimezoneSurface::DateToLocaleString => "date-to-locale-string",
                TimezoneSurface::IntlLocaleDefaults => "intl-locale-defaults",
            }
        }
        for s in TimezoneSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        // Three-variant exhaustive match: the bridge MUST grow an
        // arm for any new variant. `UserConfigured` is the
        // Standard-mode-configurable path; future variants (e.g.
        // a `FixedOffset(i32)` for arbitrary offsets) would land
        // here and trip the bridge compile.
        fn arm(p: TimezonePolicy) -> &'static str {
            match p {
                TimezonePolicy::NativePassThrough => "native",
                TimezonePolicy::UserConfigured(_) => "user-configured",
                TimezonePolicy::NormalizedUtc(_) => "utc",
            }
        }
        assert_eq!(arm(TimezonePolicy::for_mode(Mode::Standard)), "native");
        assert_eq!(arm(TimezonePolicy::for_mode(Mode::Strict)), "utc");
        assert_eq!(
            arm(TimezonePolicy::for_mode_with_user_selection(
                Mode::Standard,
                Some(&ASIA_TOKYO)
            )),
            "user-configured"
        );
    }

    // ── Configurability tests ─────────────────────────────────────────────
    //
    // The user-facing contract: Strict is locked to UTC (Tor / Mullvad-
    // style), Standard is user-configurable (Firefox-style). The tests
    // below pin both halves of that contract — particularly the L41
    // "Strict ignores user selection" enforcement which is the privacy-
    // critical part.

    #[test]
    fn strict_ignores_user_timezone_selection() {
        // L41: Strict cannot be loosened by user settings. Even if
        // the caller (a future pb-identity, a hostile config blob,
        // a recovered backup with tampered settings) supplies a
        // non-UTC timezone for a Strict-mode renderer, the policy
        // MUST resolve to NormalizedUtc(&LOCKED_TIMEZONE_PROFILE).
        for tz in [&ASIA_TOKYO, &AMERICA_NEW_YORK, &EUROPE_BERLIN] {
            let p = TimezonePolicy::for_mode_with_user_selection(Mode::Strict, Some(tz));
            // Variant is NormalizedUtc, NOT UserConfigured.
            assert!(matches!(p, TimezonePolicy::NormalizedUtc(_)));
            // And the profile is the locked UTC singleton.
            let profile = p.profile().expect("Strict carries a profile");
            assert!(std::ptr::eq(profile, &LOCKED_TIMEZONE_PROFILE));
            assert_eq!(profile.iana_name, "UTC");
        }
        // Same when no selection is provided.
        let p = TimezonePolicy::for_mode_with_user_selection(Mode::Strict, None);
        assert!(matches!(p, TimezonePolicy::NormalizedUtc(_)));
    }

    #[test]
    fn standard_uses_user_selection_when_provided() {
        // Firefox-style configurability: a Standard-mode renderer
        // with an explicit user selection routes its timezone
        // readbacks through the selected profile.
        let p = TimezonePolicy::for_mode_with_user_selection(Mode::Standard, Some(&ASIA_TOKYO));
        assert!(matches!(p, TimezonePolicy::UserConfigured(_)));
        let profile = p.profile().expect("UserConfigured carries a profile");
        assert!(std::ptr::eq(profile, &ASIA_TOKYO));
        assert_eq!(profile.iana_name, "Asia/Tokyo");
        assert!(p.normalizes());
    }

    #[test]
    fn standard_without_selection_passes_through_to_host() {
        // Default Standard behavior: no user selection means the
        // libxul accessor returns the host TZ (NativePassThrough).
        let p = TimezonePolicy::for_mode_with_user_selection(Mode::Standard, None);
        assert!(matches!(p, TimezonePolicy::NativePassThrough));
        assert_eq!(p.profile(), None);
        assert!(!p.normalizes());
    }

    #[test]
    fn override_with_user_selection_respects_l41_for_strict() {
        // The high-level `TimezoneOverride::with_user_selection`
        // helper threads the same L41 enforcement as the policy
        // function. Strict + any user TZ MUST still report
        // `Some(&LOCKED_TIMEZONE_PROFILE)`.
        let ovr = TimezoneOverride::with_user_selection(Mode::Strict, Some(&AMERICA_LOS_ANGELES));
        let p = ovr.profile().expect("Strict carries a profile");
        assert!(std::ptr::eq(p, &LOCKED_TIMEZONE_PROFILE));
        assert_eq!(ovr.surface(), WebIdlSurface::Timezone);
    }

    #[test]
    fn override_with_user_selection_threads_choice_for_standard() {
        let ovr = TimezoneOverride::with_user_selection(Mode::Standard, Some(&EUROPE_LONDON));
        let p = ovr.profile().expect("UserConfigured carries a profile");
        assert!(std::ptr::eq(p, &EUROPE_LONDON));
        assert_eq!(ovr.surface(), WebIdlSurface::Timezone);
    }

    #[test]
    fn curated_timezone_list_covers_major_regions() {
        // The COMMON_TIMEZONES list is the user-visible curated set;
        // adding / removing an entry is a UX decision. Assert the
        // v1 set covers the major commercial regions so a future
        // accidental deletion is caught here.
        assert_eq!(COMMON_TIMEZONES.len(), 10);

        // UTC must be the first entry so users selecting UTC in
        // Standard share the exact same static as every Strict
        // renderer (cohort unification).
        assert!(std::ptr::eq(COMMON_TIMEZONES[0], &LOCKED_TIMEZONE_PROFILE));

        // Every entry must have a non-empty IANA name and a sane
        // offset (-12h..=+14h covers every real-world TZ).
        for tz in COMMON_TIMEZONES {
            assert!(!tz.iana_name.is_empty(), "empty iana_name");
            assert!(
                tz.offset_minutes >= -720 && tz.offset_minutes <= 840,
                "offset out of range for {}: {}",
                tz.iana_name,
                tz.offset_minutes
            );
            assert!(!tz.abbreviation.is_empty(), "empty abbreviation");
        }
    }

    #[test]
    fn common_timezones_carry_correct_offsets() {
        // Cohort lock: each curated profile's standard-time offset
        // is part of the v1 definition. A future tz-database
        // update that shifted any of these (a country changing
        // its standard offset, e.g. Russia 2010, Samoa 2011) is
        // a cohort shift and must go through the Adaptation
        // protocol.
        assert_eq!(AMERICA_NEW_YORK.offset_minutes, -300);
        assert_eq!(AMERICA_CHICAGO.offset_minutes, -360);
        assert_eq!(AMERICA_LOS_ANGELES.offset_minutes, -480);
        assert_eq!(EUROPE_LONDON.offset_minutes, 0);
        assert_eq!(EUROPE_BERLIN.offset_minutes, 60);
        assert_eq!(ASIA_KOLKATA.offset_minutes, 330);
        assert_eq!(ASIA_SINGAPORE.offset_minutes, 480);
        assert_eq!(ASIA_TOKYO.offset_minutes, 540);
        assert_eq!(AUSTRALIA_SYDNEY.offset_minutes, 600);
    }
}
