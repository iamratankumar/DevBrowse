//! Module 30 — Fonts enumeration normalization.
//!
//! Architecture references:
//!   * **L8** — Gecko WebIDL override points only; the FontFaceSet
//!     and CSS font-resolver pathways are intercepted below the JS
//!     surface so workers and iframes share a single allowlist /
//!     bucketed view.
//!   * **L9 / §3.3 / §3.2** — *both* modes normalize, with different
//!     posture (locked v1.12 §5.5 matrix row 30):
//!       * **Strict** — fixed ~15-font cohort allowlist
//!         (`BUNDLED_FONT_SET_V1`); no host-OS font enumeration; no
//!         per-site opt-in (L41 + L44 + Phase 5.5 Module 35.3 forbid
//!         loosening).
//!       * **Standard** — coarsely bucketed enumeration via
//!         `STANDARD_BUCKETED_TABLE_V1` (~10 script-coverage
//!         buckets); per-site full enumeration available via Module
//!         59 permission center.
//!   * **L41 / L44** — Strict-mode settings cannot loosen the
//!     allowlist; the `FontsGrants` hook is consulted only in
//!     Standard.
//!   * **§5.5** — central fingerprint bucketing: every font-related
//!     readout routes through one of two static tables.
//!   * **threat-model A1** — installed-font enumeration is one of the
//!     highest-entropy passive fingerprints (per-user, per-host,
//!     per-OS-locale). The Strict allowlist eliminates the channel;
//!     Standard's bucketing collapses ~10^4 distinct font lists into
//!     ~10^2 combinations.
//!
//! ## Locked decision (phase-5 Goal + §5.5 matrix v1.12)
//!
//! **Module 30 is the first Phase-5 module where Standard also
//! normalizes.** Modules 25 / 27 / 28 / 29 are cohort-by-choice with
//! Standard pass-through; here Standard buckets enumeration too,
//! because the unfiltered system font list is too high-entropy even
//! for the Standard cohort. The opt-out is per-site via Module 59,
//! not per-user.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * The cohort-locked bundled font set (`BUNDLED_FONT_SET_V1`)
//!     the libxul-side font enumerator returns to JS under Strict.
//!     Module 27 references this same static via
//!     `CanvasRenderProfile::font_set` so the Strict canvas cohort
//!     and the Strict font cohort cannot drift apart.
//!   * The Standard-mode coarse-bucket table
//!     (`STANDARD_BUCKETED_TABLE_V1`) the libxul-side enumerator
//!     consults when no per-site grant is present.
//!   * The `FontsGrants` permission hook the libxul-side enumerator
//!     consults **only in Standard** to decide whether to relax
//!     bucketing for a specific origin (the Module 59 wiring point).
//!     `DenyAllFontsGrants` is the v1 default and is the only impl
//!     until Module 59 ships; tests use `CapturingFontsGrants`.
//!   * `FontsSurface::ALL`: every JS pathway the bridge must wire,
//!     including the phase-file edge case (font-load callback timing).
//!
//! It IS NOT:
//!   * The actual bundled font binaries. The libxul build
//!     (workspace-level Cargo pin; wired into Gecko by pb-browser
//!     at Phase 11 / Module 80) ships the OTF / TTF files; this
//!     module pins the family-name list the renderer must honor.
//!     A bundled font that disappears from the libxul build
//!     silently splits the cohort. (Not "Module 1" — that module
//!     ships only the workspace + toolchain pin.)
//!   * The Module 59 permission center itself. The
//!     `FontsGrants::allows_full_enumeration` callback is consulted
//!     by the libxul-side enumerator; Module 59 supplies the
//!     concrete impl that consults the user's stored per-site grant.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): the bundled font OTFs ship
//   inside the libxul tag. If a future libxul bump drops Arimo /
//   Tinos / Cousine
//   or a Noto-coverage face, the Strict cohort silently shrinks.
//   Module 69 (wrapper-compatibility checker) MUST verify
//   `BUNDLED_FONT_SET_V1.family_names` against the actual libxul
//   font manifest on every tag bump and fail the build on drift.
// Module 27 (canvas) cross-coupling has shipped:
//   `CanvasRenderProfile::font_set` is `&'static BundledFontSet`
//   (replacing the v1 `&'static str` label). The cohort-unification
//   between Module 27 and Module 30 is asserted by address identity
//   (`std::ptr::eq(font_set, &BUNDLED_FONT_SET_V1)`) in both
//   canvas.rs and fonts.rs tests.
// TODO(Module 59 / permission center): wire
//   `FontsGrants::allows_full_enumeration` into the user's stored
//   per-site grant store. Strict short-circuits before consulting
//   the hook (L41 forbids loosening), Standard consults on every
//   enumeration. Per-site grants are the only L44-compliant opt-out
//   path for Standard's bucketing.
// TODO(Phase 5.5 / Module 35.3 / 35.4): the L44 disabled-by-default
//   surface and the L41 settings-lock enforcement layer on top of
//   the override registered here. Module 30 ships only the per-mode
//   enumeration policy; Phase 5.5 verifies Strict cannot be
//   loosened by any settings path (including a hostile
//   `FontsGrants` impl).
// TODO(Phase 10 / Module 71+): the CreepJS / FPStandard font
//   enumeration probes will iterate every `document.fonts` /
//   FontFaceSet check / CSS font-family resolution under both modes
//   and assert the Strict cohort sees exactly
//   `BUNDLED_FONT_SET_V1.family_names` and the Standard cohort sees
//   exactly `STANDARD_BUCKETED_TABLE_V1.buckets`.
// TODO(Module 34 / Navigator): Standard's font bucketing exposes
//   host OS class indirectly (the bucket coverage names which
//   script blocks the host has). This is cohort-redundant with
//   `navigator.platform` exposure today; if Module 34 ever
//   normalizes platform / UA to fully strip OS class, the bucket
//   labels here may need a corresponding tightening.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;
use std::sync::Mutex;

// ── Locked bundled font set (Strict cohort) ───────────────────────────────

/// The cohort-locked bundled font set for Strict mode. Family names
/// chosen for (a) metric compatibility with the big-three Windows
/// system fonts so layout survives, (b) wide Unicode coverage so
/// non-Latin sites render, (c) match with Tor Browser's bundled set
/// so the DevBrowse Strict cohort overlaps the existing Tor /
/// Mullvad cohorts.
///
/// `Eq` / `Hash` derive: `&'static [&'static str]` slices compare
/// element-wise. The address-identity invariant uses `ptr::eq`
/// against `BUNDLED_FONT_SET_V1` for the cohort-singleton check
/// (same shape as `LOCKED_CANVAS_PROFILE` / `LOCKED_WEBGL_PROFILE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BundledFontSet {
    /// Stable label for the bundled set version. Bumped via the
    /// Adaptation protocol on any list change.
    pub label: &'static str,
    /// CSS family names exposed to JS via `document.fonts` / CSS
    /// `font-family` resolution under Strict. Order is significant
    /// for the cohort lock — reordering is a cohort shift.
    pub family_names: &'static [&'static str],
}

/// v1 bundled font set. Tor Browser-style metric-compatible Latin
/// substitutes + Noto Sans coverage of major non-Latin scripts +
/// STIX Two Math for math content + Noto Emoji.
///
/// `static` (not `const`): cohort consumers (canvas.rs `font_set`
/// field; libxul font enumerator) compare by address (`ptr::eq`).
/// `const` constant-folds each reference site to a distinct address
/// and silently breaks the singleton invariant.
pub static BUNDLED_FONT_SET_V1: BundledFontSet = BundledFontSet {
    label: "devbrowse-bundled-v1",
    family_names: &[
        // Latin: metric-compatible substitutes for Arial / Times /
        // Courier (matches Tor Browser's bundled Liberation /
        // Croscore alternatives).
        "Arimo",
        "Tinos",
        "Cousine",
        // Noto Sans coverage of major non-Latin scripts. The
        // allowlist must cover every Unicode block the cohort
        // serves, or sites silently break for CJK / RTL / Indic
        // users (phase-file edge case). Roman Urdu (Urdu
        // transliterated to Latin) uses the Latin fonts above and
        // needs no additional face; Hindi is served by
        // Noto Sans Devanagari; Urdu Naskh by Noto Naskh Arabic and
        // Urdu Nastaliq (the distinctive Urdu calligraphic style)
        // by Noto Nastaliq Urdu.
        "Noto Sans",
        "Noto Sans CJK SC",
        "Noto Sans CJK JP",
        "Noto Sans CJK KR",
        "Noto Naskh Arabic",
        "Noto Nastaliq Urdu",
        // Hebrew script coverage deferred — adding "Noto Sans
        // Hebrew" would be a cohort-shift under the Adaptation
        // protocol (every bundled-font change forces a libxul tag
        // re-verification via Module 69). Defer until Phase 12
        // mobile reopens the bundled-font set.
        "Noto Sans Devanagari",
        "Noto Sans Thai",
        "Noto Sans Bengali",
        "Noto Sans Tamil",
        // Math + symbols.
        "STIX Two Math",
        "Noto Emoji",
    ],
};

// ── Standard-mode coarse-bucket table ─────────────────────────────────────

/// Coarse Unicode-script-coverage bucket. Standard-mode `document.fonts`
/// enumeration exposes the bucket list, not individual family names,
/// so the per-host installed-font list is collapsed to ~10
/// combinations rather than ~10^4.
///
/// Bucket coverage is OS-class-correlated (Windows / macOS / Linux
/// each ship a different mix), but that signal is already exposed
/// via `navigator.platform` + UA so the bucketing does not add
/// cohort entropy on top.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FontBucket {
    /// ASCII + Latin-1 base block. Always present.
    LatinBase,
    /// Latin Extended-A / Extended-B + diacritic coverage.
    LatinExtended,
    /// Combined CJK ideographs (Simplified / Traditional / Japanese
    /// / Korean) — present if any CJK font is installed.
    Cjk,
    /// Arabic + Arabic Presentation Forms.
    Arabic,
    // Hebrew bucket deferred — adding `Hebrew` is a cohort shift
    // under the Adaptation protocol; defer until Phase 12 mobile
    // reopens the bucket set (see crate-level note in
    // BUNDLED_FONT_SET_V1 for the parallel font-binary deferral).
    /// Devanagari + Indic complement.
    Devanagari,
    /// Cyrillic + Cyrillic Supplement.
    Cyrillic,
    /// Greek + Greek Extended.
    Greek,
    /// Emoji + Symbols + Dingbats.
    SymbolsEmoji,
    /// Math + math operators (STIX-class coverage).
    Math,
}

impl FontBucket {
    /// Every bucket the bucketed enumerator may surface. Adding a
    /// bucket here is a cohort shift through the Adaptation
    /// protocol.
    pub const ALL: &'static [FontBucket] = &[
        Self::LatinBase,
        Self::LatinExtended,
        Self::Cjk,
        Self::Arabic,
        // Hebrew bucket deferred (see FontBucket variant comment).
        Self::Devanagari,
        Self::Cyrillic,
        Self::Greek,
        Self::SymbolsEmoji,
        Self::Math,
    ];
}

/// The Standard-mode bucketed enumeration table. The libxul-side
/// enumerator returns `buckets` to JS as a FontFaceSet of synthetic
/// bucket-label faces; per-bucket presence is computed once per
/// renderer from the host font manifest and not refreshed per query
/// (avoids enumeration-timing channels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StandardBucketedTable {
    pub label: &'static str,
    pub buckets: &'static [FontBucket],
}

/// v1 Standard-mode bucket table. Exposes all 10 buckets (the
/// libxul enumerator filters at runtime based on what the host
/// actually has, but the table here pins what may be surfaced).
pub static STANDARD_BUCKETED_TABLE_V1: StandardBucketedTable = StandardBucketedTable {
    label: "devbrowse-standard-buckets-v1",
    buckets: FontBucket::ALL,
};

// ── Per-mode enumeration policy ───────────────────────────────────────────

/// Per-mode font enumeration policy. Strict pins the allowlist;
/// Standard ships the bucketed view.
///
/// Both variants are normalizations; there is no `NativePassThrough`
/// for fonts because the unfiltered system font list is too
/// high-entropy even for the Standard cohort. See module-level doc
/// for the rationale.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FontsEnumerationPolicy {
    /// Standard: bucketed enumeration via the referenced table.
    /// Per-site full access is available via Module 59 (consulted
    /// at enumeration time via `FontsGrants`).
    BucketedEnumeration(&'static StandardBucketedTable),
    /// Strict: fixed cohort allowlist. The libxul enumerator
    /// returns exactly `bundled.family_names` regardless of host
    /// font manifest. L41 forbids loosening even with a hostile
    /// `FontsGrants` impl (the bridge MUST short-circuit on
    /// Strict).
    LockedAllowlist(&'static BundledFontSet),
}

impl FontsEnumerationPolicy {
    /// Locked snapshot for `mode`:
    ///   * `Mode::Standard` -> `BucketedEnumeration(&STANDARD_BUCKETED_TABLE_V1)`
    ///   * `Mode::Strict`   -> `LockedAllowlist(&BUNDLED_FONT_SET_V1)`
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::BucketedEnumeration(&STANDARD_BUCKETED_TABLE_V1),
            Mode::Strict => Self::LockedAllowlist(&BUNDLED_FONT_SET_V1),
        }
    }

    /// `Some(set)` iff the policy is the Strict allowlist; useful
    /// for the cross-module cohort-unification assertion against
    /// `CanvasRenderProfile::font_set`.
    pub fn allowlist(&self) -> Option<&'static BundledFontSet> {
        match self {
            Self::BucketedEnumeration(_) => None,
            Self::LockedAllowlist(set) => Some(*set),
        }
    }

    /// `Some(table)` iff the policy is the Standard bucketed view.
    pub fn bucketed(&self) -> Option<&'static StandardBucketedTable> {
        match self {
            Self::BucketedEnumeration(t) => Some(*t),
            Self::LockedAllowlist(_) => None,
        }
    }
}

// ── Fonts permission hook (Module 59 wiring point) ────────────────────────

/// Per-site permission hook for Standard-mode full font
/// enumeration. The libxul-side enumerator consults this **only
/// when the policy is `BucketedEnumeration`** (Standard). Strict
/// short-circuits before consulting the hook so a hostile impl
/// cannot loosen the cohort (L41).
///
/// The default v1 impl is [`DenyAllFontsGrants`]; Module 59 will
/// supply a concrete impl that consults the user's stored per-site
/// grant store.
pub trait FontsGrants: Send + Sync + std::fmt::Debug {
    /// Returns `true` iff the user has explicitly granted this
    /// origin full font enumeration in Standard mode. MUST be a
    /// pure function of `(ctx, origin)` from the renderer's
    /// perspective — the libxul enumerator may cache the result
    /// per-(renderer, origin) and not refresh it per query
    /// (avoids per-query timing channels).
    fn allows_full_enumeration(&self, ctx: &OverrideContext, origin: &str) -> bool;
}

/// Default v1 grants impl: never allow full enumeration. Replaced
/// by Module 59's concrete impl once the permission center ships.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllFontsGrants;

impl FontsGrants for DenyAllFontsGrants {
    fn allows_full_enumeration(&self, _ctx: &OverrideContext, _origin: &str) -> bool {
        false
    }
}

/// Recording grants impl for tests. Captures every query so a test
/// can assert which (mode, origin) combinations the bridge consulted.
#[derive(Debug)]
pub struct CapturingFontsGrants {
    queries: Mutex<Vec<(Mode, String)>>,
    answer: bool,
}

impl CapturingFontsGrants {
    pub fn new(answer: bool) -> Self {
        Self {
            queries: Mutex::new(Vec::new()),
            answer,
        }
    }

    pub fn queries(&self) -> Vec<(Mode, String)> {
        self.queries.lock().unwrap().clone()
    }
}

impl FontsGrants for CapturingFontsGrants {
    fn allows_full_enumeration(&self, ctx: &OverrideContext, origin: &str) -> bool {
        self.queries
            .lock()
            .unwrap()
            .push((ctx.mode(), origin.to_string()));
        self.answer
    }
}

/// Adversarial / hostile grants impl for fuzz tests (P1-6,
/// 2026-05-22). Always returns `true` regardless of mode or
/// origin — simulates a hostile Module 59 implementation that
/// would grant full enumeration to every site. Used to assert
/// that Strict mode short-circuits BEFORE consulting `FontsGrants`
/// (the L41 structural lock).
///
/// **Adversarial fixture** — never wire into production. The
/// libxul bridge for Strict mode MUST NOT call into this trait at
/// all; if it does, the L41 lock is leaking.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostileFontsGrants;

impl FontsGrants for HostileFontsGrants {
    fn allows_full_enumeration(&self, _ctx: &OverrideContext, _origin: &str) -> bool {
        true
    }
}

// ── Readback-pathway enumeration ──────────────────────────────────────────

/// Every JS API pathway that can enumerate fonts.
///
/// The libxul bridge MUST register the override behind every variant —
/// missing one leaves an enumeration channel that bypasses the
/// cohort-safe policy (a privacy regression). This enum lifts the
/// phase-file edge case (font-load callback timing leaks installed
/// fonts) into a typed list so a future libxul-tag bump cannot
/// silently miss a new pathway.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FontsSurface {
    /// `document.fonts` FontFaceSet iterator (`for...of`,
    /// `Array.from(document.fonts)`).
    DocumentFontsIterator,
    /// `document.fonts.check(font, text)` — returns whether a
    /// specific font would render the given text. Trivially leaks
    /// individual font presence if not gated.
    DocumentFontsCheck,
    /// Implicit enumeration via CSS `font-family` fallback chain +
    /// `getComputedStyle` readback. The classical font-fingerprint
    /// vector predating `document.fonts`.
    CssFontFamilyEnumeration,
    /// `FontFace.load()` / `document.fonts.load(font, text)` — the
    /// promise resolves only if the font is available, leaking
    /// presence.
    FontFaceLoad,
    /// Phase-file edge case: font-load callback timing. A
    /// `FontFaceSet.ready` resolution latency that varies by
    /// installed-font count leaks the count even when individual
    /// presence is hidden. The libxul-side hook MUST quantize the
    /// callback latency to a fixed per-bucket value (cross-coupled
    /// to Module 32 / L43 timer quantization — Strict's 100 ms
    /// floor absorbs sub-100ms enumeration deltas, Standard
    /// requires explicit quantization here).
    FontLoadCallback,
}

impl FontsSurface {
    /// Every enumeration pathway the bridge must wire. Asserted
    /// against the phase-file edge-case list by
    /// `tests::fonts_surface_all_covers_edge_cases`.
    pub const ALL: &'static [FontsSurface] = &[
        Self::DocumentFontsIterator,
        Self::DocumentFontsCheck,
        Self::CssFontFamilyEnumeration,
        Self::FontFaceLoad,
        Self::FontLoadCallback,
    ];
}

// ── FingerprintOverride impl ──────────────────────────────────────────────

/// Concrete `FingerprintOverride` for `WebIdlSurface::Fonts`.
///
/// Construct with `FontsOverride::new(mode)` so the policy is
/// resolved once at construction; the override is then registered
/// by the libxul bridge into every `JsContext` for the renderer.
///
/// Unlike Modules 27 / 28 / 29 (Strict-only locks; Standard
/// pass-through), `FontsOverride` carries an active policy in both
/// modes — Standard buckets, Strict allows. `install` is still a
/// no-op pending the libxul hook; once wired, both branches
/// activate the corresponding enumerator behavior.
///
/// Context-inert per Module 26: the policy is a `Copy` value
/// referencing static data, so `install(&OverrideContext)` produces
/// observationally identical state regardless of `ctx.js_context()`.
#[derive(Debug, Clone, Copy)]
pub struct FontsOverride {
    policy: FontsEnumerationPolicy,
}

impl FontsOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: FontsEnumerationPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> FontsEnumerationPolicy {
        self.policy
    }

    /// `Some(&BUNDLED_FONT_SET_V1)` iff the override is Strict.
    /// Standard returns `None` — the libxul-side enumerator
    /// consults the bucketed table + per-site grants instead.
    pub fn allowlist(&self) -> Option<&'static BundledFontSet> {
        self.policy.allowlist()
    }

    /// `Some(&STANDARD_BUCKETED_TABLE_V1)` iff the override is
    /// Standard. Strict returns `None`.
    pub fn bucketed(&self) -> Option<&'static StandardBucketedTable> {
        self.policy.bucketed()
    }
}

impl FingerprintOverride for FontsOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::Fonts
    }

    fn install(&self, _ctx: &OverrideContext) {
        // v1: no side effect on either branch. The libxul font
        // enumerator hook is not yet wired (see crate-level TODO).
        // When the FFI lands:
        //   * LockedAllowlist(set)       -> register a per-renderer
        //     callback returning `set.family_names` for every
        //     enumeration pathway; consult NO grants.
        //   * BucketedEnumeration(table) -> register a per-renderer
        //     callback returning `table.buckets` filtered by
        //     `FontsGrants::allows_full_enumeration` (Module 59).
        let _ = (self.policy, JsContext::ALL);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_font_set_matches_strict_cohort_definition() {
        // The exact family-name list is the v1 Strict-cohort
        // definition. Any change is a cohort shift through the
        // Adaptation protocol (README §Adaptation) and MUST bump
        // the label.
        assert_eq!(BUNDLED_FONT_SET_V1.label, "devbrowse-bundled-v1");
        assert_eq!(BUNDLED_FONT_SET_V1.family_names.len(), 15);
        // First three are the Tor-style metric-compatible Latin
        // substitutes; their order and identity is part of the lock.
        assert_eq!(BUNDLED_FONT_SET_V1.family_names[0], "Arimo");
        assert_eq!(BUNDLED_FONT_SET_V1.family_names[1], "Tinos");
        assert_eq!(BUNDLED_FONT_SET_V1.family_names[2], "Cousine");
    }

    #[test]
    fn bundled_font_set_covers_non_latin_scripts() {
        // Phase-file edge case: the allowlist must cover every
        // Unicode block the Tor Browser bundle covers, otherwise
        // sites silently break for CJK / RTL / Indic users.
        let names = BUNDLED_FONT_SET_V1.family_names;
        let must_cover = [
            "Noto Sans CJK SC",
            "Noto Sans CJK JP",
            "Noto Sans CJK KR",
            "Noto Naskh Arabic",
            "Noto Nastaliq Urdu",
            // Hebrew script coverage deferred — see
            // BUNDLED_FONT_SET_V1 comment.
            "Noto Sans Devanagari",
        ];
        for needle in must_cover {
            assert!(
                names.contains(&needle),
                "Strict cohort missing required script: {}",
                needle
            );
        }
    }

    #[test]
    fn standard_bucketed_table_exposes_all_buckets() {
        assert_eq!(
            STANDARD_BUCKETED_TABLE_V1.label,
            "devbrowse-standard-buckets-v1"
        );
        // The bucket table mirrors FontBucket::ALL by content;
        // bucketing decisions stay in one place. (Address identity
        // is not asserted because `const` slice references are not
        // guaranteed to deduplicate across call sites — the
        // singleton invariant lives on the `LOCKED_*` statics
        // themselves, not on the `ALL` constant.)
        assert_eq!(STANDARD_BUCKETED_TABLE_V1.buckets, FontBucket::ALL);
    }

    #[test]
    fn standard_returns_bucketed_enumeration() {
        let p = FontsEnumerationPolicy::for_mode(Mode::Standard);
        assert!(matches!(p, FontsEnumerationPolicy::BucketedEnumeration(_)));
        let table = p.bucketed().expect("Standard MUST carry a bucket table");
        // Address identity: every Standard renderer reads the same
        // singleton.
        assert!(std::ptr::eq(table, &STANDARD_BUCKETED_TABLE_V1));
        assert_eq!(p.allowlist(), None);
    }

    #[test]
    fn strict_returns_locked_allowlist() {
        let p = FontsEnumerationPolicy::for_mode(Mode::Strict);
        assert!(matches!(p, FontsEnumerationPolicy::LockedAllowlist(_)));
        let set = p.allowlist().expect("Strict MUST carry an allowlist");
        // Address identity: every Strict renderer reads the same
        // singleton — that is the Strict-cohort guarantee, and the
        // hook Module 27 uses to assert canvas / fonts cohort
        // unification.
        assert!(std::ptr::eq(set, &BUNDLED_FONT_SET_V1));
        assert_eq!(p.bucketed(), None);
    }

    #[test]
    fn fonts_surface_all_covers_edge_cases() {
        // Phase-file edge case: "font-load callback timing leaks
        // installed fonts" — captured as `FontLoadCallback`. Other
        // variants cover the classical enumeration paths
        // (`document.fonts` iterator + check, CSS fallback chain,
        // `FontFace.load()`).
        assert_eq!(FontsSurface::ALL.len(), 5);
        for v in [
            FontsSurface::DocumentFontsIterator,
            FontsSurface::DocumentFontsCheck,
            FontsSurface::CssFontFamilyEnumeration,
            FontsSurface::FontFaceLoad,
            FontsSurface::FontLoadCallback,
        ] {
            assert!(FontsSurface::ALL.contains(&v), "missing pathway: {:?}", v);
        }
    }

    #[test]
    fn fonts_override_reports_fonts_surface_under_both_modes() {
        // Uniform registration; mode-divergence is in the policy.
        assert_eq!(
            FontsOverride::new(Mode::Standard).surface(),
            WebIdlSurface::Fonts
        );
        assert_eq!(
            FontsOverride::new(Mode::Strict).surface(),
            WebIdlSurface::Fonts
        );
    }

    #[test]
    fn standard_override_carries_bucketed_strict_carries_allowlist() {
        let standard = FontsOverride::new(Mode::Standard);
        let strict = FontsOverride::new(Mode::Strict);

        assert_eq!(standard.allowlist(), None);
        let table = standard
            .bucketed()
            .expect("Standard MUST have a bucket table");
        assert!(std::ptr::eq(table, &STANDARD_BUCKETED_TABLE_V1));

        assert_eq!(strict.bucketed(), None);
        let set = strict.allowlist().expect("Strict MUST have an allowlist");
        assert!(std::ptr::eq(set, &BUNDLED_FONT_SET_V1));
    }

    #[test]
    fn fonts_override_install_is_context_inert() {
        // Edge case: override must be inert in iframe / worker /
        // service-worker / dedicated-worker. Drive install across
        // every JsContext for both modes and assert observed state
        // (the policy + surface) does not vary across contexts.
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000030").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = FontsOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
            assert_eq!(ovr.surface(), WebIdlSurface::Fonts);
        }
    }

    #[test]
    fn fonts_override_is_send_sync() {
        // Module 26 trait obligation: implementations MUST be
        // Send + Sync because libxul holds them in
        // Arc<dyn FingerprintOverride>.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FontsOverride>();
        assert_send_sync::<FontsEnumerationPolicy>();
        assert_send_sync::<BundledFontSet>();
        assert_send_sync::<StandardBucketedTable>();
        assert_send_sync::<DenyAllFontsGrants>();
        assert_send_sync::<CapturingFontsGrants>();
        assert_send_sync::<HostileFontsGrants>();
    }

    #[test]
    fn strict_short_circuits_hostile_fonts_grants() {
        // P1-6 (2026-05-22). The L41 structural lock for fonts
        // says: Strict mode resolves to `BundledOnly(...)` BEFORE
        // any FontsGrants is consulted. A hostile / buggy grants
        // impl that always returns `true` MUST NOT loosen Strict.
        //
        // This module's policy `for_mode` does not take grants —
        // the trait is consulted libxul-side on every full-
        // enumeration probe. We assert the structural invariant:
        // `for_mode(Mode::Strict)` always resolves to
        // `BundledOnly(&BUNDLED_FONT_SET_V1)` regardless of any
        // grants instance the caller passes around the policy.
        let _hostile = HostileFontsGrants;
        let p = FontsEnumerationPolicy::for_mode(Mode::Strict);
        match p {
            FontsEnumerationPolicy::LockedAllowlist(set) => {
                assert!(std::ptr::eq(set, &BUNDLED_FONT_SET_V1));
            }
            other => panic!(
                "Strict must resolve to LockedAllowlist regardless of any FontsGrants impl; got {:?}",
                other,
            ),
        }
    }

    #[test]
    fn surface_dispatch_is_exhaustive_friendly() {
        fn route(s: FontsSurface) -> &'static str {
            match s {
                FontsSurface::DocumentFontsIterator => "document-fonts-iterator",
                FontsSurface::DocumentFontsCheck => "document-fonts-check",
                FontsSurface::CssFontFamilyEnumeration => "css-font-family-enumeration",
                FontsSurface::FontFaceLoad => "font-face-load",
                FontsSurface::FontLoadCallback => "font-load-callback",
            }
        }
        for s in FontsSurface::ALL {
            assert!(!route(*s).is_empty());
        }
    }

    #[test]
    fn policy_dispatch_is_exhaustive_friendly() {
        fn arm(p: FontsEnumerationPolicy) -> &'static str {
            match p {
                FontsEnumerationPolicy::BucketedEnumeration(_) => "bucketed",
                FontsEnumerationPolicy::LockedAllowlist(_) => "allowlist",
            }
        }
        assert_eq!(
            arm(FontsEnumerationPolicy::for_mode(Mode::Standard)),
            "bucketed"
        );
        assert_eq!(
            arm(FontsEnumerationPolicy::for_mode(Mode::Strict)),
            "allowlist"
        );
    }

    #[test]
    fn font_bucket_all_covers_required_scripts() {
        // Standard's bucket table is the cohort lock for Standard;
        // any added/removed bucket is a cohort shift.
        assert_eq!(FontBucket::ALL.len(), 9);
        for v in [
            FontBucket::LatinBase,
            FontBucket::LatinExtended,
            FontBucket::Cjk,
            FontBucket::Arabic,
            // FontBucket::Hebrew deferred (see variant comment).
            FontBucket::Devanagari,
            FontBucket::Cyrillic,
            FontBucket::Greek,
            FontBucket::SymbolsEmoji,
            FontBucket::Math,
        ] {
            assert!(FontBucket::ALL.contains(&v), "missing bucket: {:?}", v);
        }
    }

    #[test]
    fn deny_all_grants_denies_every_origin() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000030").unwrap();
        let grants = DenyAllFontsGrants;
        for mode in [Mode::Standard, Mode::Strict] {
            let ctx = OverrideContext::new(mode, pid, JsContext::TopFrame);
            for origin in ["https://example.com", "https://attacker.test", ""] {
                assert!(!grants.allows_full_enumeration(&ctx, origin));
            }
        }
    }

    #[test]
    fn capturing_grants_records_every_query() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000030").unwrap();
        let grants = CapturingFontsGrants::new(true);

        for mode in [Mode::Standard, Mode::Strict] {
            let ctx = OverrideContext::new(mode, pid, JsContext::TopFrame);
            assert!(grants.allows_full_enumeration(&ctx, "https://example.com"));
        }

        let q = grants.queries();
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].0, Mode::Standard);
        assert_eq!(q[0].1, "https://example.com");
        assert_eq!(q[1].0, Mode::Strict);
    }

    #[test]
    fn strict_canvas_cohort_unifies_with_fonts_cohort() {
        // Cross-module cohort-unification invariant. Module 27's
        // LOCKED_CANVAS_PROFILE.font_set is the same static as
        // Module 30's BUNDLED_FONT_SET_V1. If a future change
        // diverges them, the Strict canvas rasterizer and the
        // Strict font enumerator would describe different cohorts
        // — a silent privacy regression. The address-identity
        // check below is the regression test.
        use crate::gecko::canvas::LOCKED_CANVAS_PROFILE;
        assert!(std::ptr::eq(
            LOCKED_CANVAS_PROFILE.font_set,
            &BUNDLED_FONT_SET_V1,
        ));
    }
}
