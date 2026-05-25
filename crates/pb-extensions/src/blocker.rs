//! Module 40 — Extension blocker (Strict mode enforcement).
//!
//! In Strict mode every extension API surface is dark:
//! `browser.*` / `chrome.*` are absent globals, content scripts do
//! not load, background contexts are never spawned, declarative net
//! request rules are dropped at manifest parse, and legacy bootstrap
//! manifests are refused.
//!
//! ## Why both `browser` and `chrome` globals are darked
//!
//! DevBrowse runs the Gecko engine (L1). Gecko's WebExtensions
//! implementation intentionally exposes **two** API namespaces:
//!   * **`browser.*`** — the Mozilla-native, promise-based
//!     namespace (the primary surface for extensions written for
//!     Firefox).
//!   * **`chrome.*`** — a Chrome-compat shim that mirrors the same
//!     surface with callback-based signatures, so Chrome-Web-Store
//!     extensions ported to Firefox run unchanged.
//!
//! Darking only `browser` would leave a fully functional probe and
//! API surface under `chrome.*`. Strict darks both; the
//! `web_extension_globals_enumerates_both_namespaces` test pins
//! the pair.
//!
//! **Strict is extension-free regardless of allowlist membership.**
//! An extension the user installed in a Standard profile cannot
//! leak any state into a Strict-mode tab because (a) identity
//! profiles are mode-locked at creation per §3.1, (b) Strict tabs
//! are per-tab renderers with no shared extension context per §3.3,
//! and (c) [`block_for_mode`] structurally returns
//! [`BlockerPolicy::AllBlocked`] for `Mode::Strict` with no input
//! channel that could weaken it.
//!
//! Architecture references:
//!   * **L9** — Strict mode is extension-free; process model is
//!     identity-grouped with per-tab renderers in Strict.
//!   * **L40** — Renderer-network isolation. The network broker has
//!     no extension hook surface in either mode. Module 40 darks
//!     the Strict-side API surface; the broker-side lock is
//!     enforced in pb-network.
//!   * **L41** — Strict-mode settings lock. No user setting, wizard
//!     opt-in, per-site permission, or allowlist entry can
//!     re-enable extensions in Strict.
//!   * **§3.2** — Standard mode: curated allowlist (Module 41).
//!   * **§3.3** — Strict mode: per-tab renderer; extensions blocked.
//!
//! ## Mode-applicability
//!
//!   * **Strict** — [`surfaces_blocked_for_mode`] with `Mode::Strict`
//!     returns the full [`ExtensionApiSurface::ALL`] slice. The
//!     libxul bridge iterates the list at renderer spawn and applies
//!     the per-surface block via the variant's [`BlockMechanism`].
//!   * **Standard** — [`surfaces_blocked_for_mode`] with
//!     `Mode::Standard` returns the empty slice. Standard extension
//!     loading is gated by Module 41 (allowlist + signature +
//!     version constraint + xpi hash check). Module 40's
//!     responsibility ends at "what does Strict dark".
//!
//! ## Delegation to Module 41 (no redundant state)
//!
//!   * Allowlist parsing, `.xpi` signature verification, manifest
//!     hash check, install / update / removal lifecycle, and the
//!     Module 11 warning surface for rejected installs are all
//!     owned by **Module 41** (`controller.rs` + `allowlist.rs`).
//!     Module 40 does NOT re-enumerate any of that.
//!   * The architecture v1.10 **`webRequest` lock** (no extension
//!     hook into pb-network) is enforced at the pb-network broker
//!     boundary, NOT at this module's enumeration. `webRequest` is
//!     therefore absent from [`ExtensionApiSurface::ALL`]; a
//!     regression test (`web_request_is_not_in_this_list`) pins
//!     the boundary, mirroring the Module 35.3 / WebRTC pattern.
//!
//! ## Edge cases (phase-file lock)
//!
//!   * **Legacy bootstrap manifests** — encoded as
//!     [`ExtensionApiSurface::BootstrappedManifest`]; refused at
//!     manifest parse via [`BlockMechanism::ManifestEntryRefused`].
//!   * **Declarative net request rules** — encoded as
//!     [`ExtensionApiSurface::DeclarativeNetRequest`]; dropped at
//!     manifest parse via [`BlockMechanism::ManifestEntryRefused`]
//!     so the rules never reach the pb-network broker.
//!   * **Allowlisted extension carrying Standard state into Strict
//!     tab** — structurally impossible: `block_for_mode` is a pure
//!     function of `Mode` with no extension-id, allowlist-handle,
//!     or settings input. Test
//!     `block_for_mode_strict_is_pure_on_mode_only` pins this.
//
// TODO(libxul FFI bridge — pb-browser Phase 11 / Module 80;
//   verified by Module 69 in Phase 9): per-surface block wiring
//   lands alongside the libxul tag. Sketch:
//     - ApiGlobalAbsent: WebExtension XPCOM bridge skips `chrome` /
//       `browser` global installation in Strict-renderer JS scopes.
//     - RuntimeContextNotSpawned: extension manager's content-script
//       injector + background-context spawner check the tab's Mode
//       and bail before creating any runtime context.
//     - ManifestEntryRefused: extension loader's manifest parser
//       rejects `declarative_net_request` rule_resources and
//       legacy bootstrap fields when the active profile is Strict
//       (and surfaces a Module 11 warning at install time, not at
//       tab-spawn time).
//   The bridge MUST iterate `ExtensionApiSurface::ALL` so adding a
//   new surface here forces a bridge-side handshake.
// TODO(Module 41 — Phase 7, next): Standard-mode allowlist
//   enforcement + signature verification + manifest hash check.
//   When Module 41 lands, this module's `webRequest` boundary test
//   should grow a paired test in Module 41 asserting the allowlist
//   manifest schema rejects any entry whose declared permissions
//   include `webRequest` / `webRequestBlocking` / `webNavigation.*`.
// TODO(pb-testkit cross-phase Phase 7 fixture — lands with
//   Module 41): wrap Module 40 + Module 41 into a
//   `extensions_bundle()` fixture so Phase 8+ tests can drive
//   "Strict tab spawned with allowlisted extension installed shows
//   `chrome === undefined`" end-to-end without re-deriving the
//   setup.

use pb_config::Mode;

// ── Block mechanism ──────────────────────────────────────────────────────

/// How the libxul bridge wires a particular Strict block.
///
/// Distinct from "what's blocked" ([`ExtensionApiSurface`]) so the
/// libxul-side patching can dispatch on the mechanism even when the
/// WebExtension API surface name differs per platform. Adding a
/// variant is an FFI-bridge handshake — the bridge MUST exhaustively
/// match.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockMechanism {
    /// The `browser` (Mozilla-native, promise-based) and `chrome`
    /// (Chrome-compat shim, callback-based) namespaces are both
    /// absent globals in the renderer JS scope:
    ///
    /// ```text
    /// typeof browser === "undefined"   &&   "browser" in globalThis === false
    /// typeof chrome  === "undefined"   &&   "chrome"  in globalThis === false
    /// ```
    ///
    /// Setting them to `undefined` is insufficient — sites and
    /// probing extensions use the `in`-reflection pattern. Both
    /// namespaces are darked because Gecko ships the `chrome.*`
    /// shim by default for Chrome-extension portability; darking
    /// only `browser` would leave a fully functional probe surface.
    ApiGlobalAbsent,
    /// The runtime context that would host the extension's code is
    /// never created: content-script injection is skipped at
    /// document-load time, and background pages / event pages /
    /// extension service workers are never spawned. No JS scope
    /// for extension code to run in.
    RuntimeContextNotSpawned,
    /// The manifest field is refused at parse time so its effects
    /// never reach the runtime: declarative net request
    /// `rule_resources` are dropped before the rule list is handed
    /// to the pb-network broker; legacy bootstrap descriptors fail
    /// validation with a Module 11 warning. Refusal happens at
    /// install/parse, NOT lazily at tab spawn.
    ManifestEntryRefused,
}

// ── Extension API surface enumeration ────────────────────────────────────

/// The extension API surfaces Strict darks.
///
/// Each variant corresponds to a logical surface family; the
/// individual WebExtension API names / manifest keys / runtime
/// context types are returned by
/// [`ExtensionApiSurface::js_surfaces`].
///
/// The list is intentionally small (5 families). Module 41 owns
/// per-extension gating in Standard; Module 40 owns the structural
/// Strict darks. `webRequest` is NOT a variant — its block is
/// enforced at the pb-network broker per architecture v1.10 (see
/// crate-level "Delegation to Module 41" doc + the
/// `web_request_is_not_in_this_list` regression).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionApiSurface {
    /// The `browser.*` (Mozilla-native) and `chrome.*` (Chrome-
    /// compat shim) WebExtension API namespaces. Both are absent
    /// globals in Strict renderer scopes; defense-in-depth for
    /// the case where a misconfigured renderer somehow gets a
    /// runtime context spawned anyway.
    WebExtensionGlobals,
    /// Manifest `content_scripts` array + programmatic injection
    /// via `browser.scripting.executeScript` (MV3 Firefox-native),
    /// `browser.tabs.executeScript` (MV2 legacy), and their
    /// `chrome.*` Chrome-compat-shim equivalents. In Strict, no
    /// content script is ever injected into any document.
    ContentScripts,
    /// Background pages, persistent background scripts, event
    /// pages, and extension service workers. In Strict, no
    /// background context is ever spawned.
    BackgroundContexts,
    /// Declarative net request: manifest `declarative_net_request`
    /// rule_resources + dynamic rules via
    /// `browser.declarativeNetRequest.updateDynamicRules` /
    /// `updateSessionRules` and their `chrome.*` Chrome-compat-
    /// shim equivalents. In Strict, the rule list is refused at
    /// manifest parse so it never reaches the pb-network broker.
    /// Phase-file edge case.
    DeclarativeNetRequest,
    /// Legacy bootstrap manifests: bootstrap.js / "restartless"
    /// extensions / the pre-WebExtension XPCOM-based plugin
    /// architecture. In Strict, the manifest fails validation
    /// with a Module 11 warning. Phase-file edge case.
    BootstrappedManifest,
}

impl ExtensionApiSurface {
    /// Every extension API surface family Strict darks.
    ///
    /// 5 variants: 3 runtime surfaces (globals + content scripts +
    /// background contexts) + 2 manifest-entry surfaces (DNR +
    /// bootstrap). The libxul bridge iterates this list at
    /// renderer spawn and applies the per-variant
    /// [`BlockMechanism`].
    pub const ALL: &'static [ExtensionApiSurface] = &[
        Self::WebExtensionGlobals,
        Self::ContentScripts,
        Self::BackgroundContexts,
        Self::DeclarativeNetRequest,
        Self::BootstrappedManifest,
    ];

    /// The individual WebExtension API names / manifest keys /
    /// runtime context types this family covers. The libxul bridge
    /// iterates this list per variant to apply the per-name patch.
    ///
    /// Convention: `browser.*` (Mozilla-native, Gecko-primary)
    /// entries come before their `chrome.*` Chrome-compat-shim
    /// counterparts. Every JS-namespaced surface is paired so the
    /// libxul bridge cannot accidentally patch only one of the
    /// two namespaces.
    pub fn js_surfaces(&self) -> &'static [&'static str] {
        match self {
            Self::WebExtensionGlobals => &["browser", "chrome"],
            Self::ContentScripts => &[
                "manifest.content_scripts",
                "browser.scripting.executeScript",
                "browser.tabs.executeScript",
                "chrome.scripting.executeScript",
                "chrome.tabs.executeScript",
            ],
            Self::BackgroundContexts => &[
                "manifest.background.page",
                "manifest.background.scripts",
                "manifest.background.service_worker",
                "manifest.background.persistent",
            ],
            Self::DeclarativeNetRequest => &[
                "manifest.declarative_net_request",
                "browser.declarativeNetRequest.updateDynamicRules",
                "browser.declarativeNetRequest.updateSessionRules",
                "chrome.declarativeNetRequest.updateDynamicRules",
                "chrome.declarativeNetRequest.updateSessionRules",
            ],
            Self::BootstrappedManifest => &[
                "manifest.bootstrap",
                "manifest.legacy",
                "manifest.type=bootstrap",
            ],
        }
    }

    /// How the libxul bridge wires this family's block.
    pub fn block_mechanism(&self) -> BlockMechanism {
        match self {
            Self::WebExtensionGlobals => BlockMechanism::ApiGlobalAbsent,
            Self::ContentScripts | Self::BackgroundContexts => {
                BlockMechanism::RuntimeContextNotSpawned
            }
            Self::DeclarativeNetRequest | Self::BootstrappedManifest => {
                BlockMechanism::ManifestEntryRefused
            }
        }
    }
}

// ── Per-Mode resolver ────────────────────────────────────────────────────

/// The mode-level extension policy.
///
/// Structural L41 lock: there is no constructor that accepts a
/// "loosen for Strict" parameter; [`block_for_mode`] is the only
/// public way to obtain a `BlockerPolicy` and it is a pure function
/// of `Mode`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockerPolicy {
    /// Strict mode. Every [`ExtensionApiSurface`] variant is
    /// blocked. Allowlist state is irrelevant.
    AllBlocked,
    /// Standard mode. Per-extension gating is delegated to
    /// Module 41 (allowlist + signature + version + hash check).
    /// This module darks no surface in Standard.
    StandardSubjectToAllowlist,
}

/// Resolve the mode-level extension policy.
///
/// Structural L41 lock: `Mode::Strict` always resolves to
/// [`BlockerPolicy::AllBlocked`]; `Mode::Standard` always resolves
/// to [`BlockerPolicy::StandardSubjectToAllowlist`]. No settings,
/// allowlist, per-site permission, or wizard opt-in can change
/// either resolution.
pub fn block_for_mode(mode: Mode) -> BlockerPolicy {
    match mode {
        Mode::Standard => BlockerPolicy::StandardSubjectToAllowlist,
        Mode::Strict => BlockerPolicy::AllBlocked,
    }
}

/// The extension API surfaces this module darks in the given mode.
///
/// Strict returns the full [`ExtensionApiSurface::ALL`] slice.
/// Standard returns the empty slice — per-extension gating is
/// delegated to Module 41 and does NOT enumerate surfaces here.
pub fn surfaces_blocked_for_mode(mode: Mode) -> &'static [ExtensionApiSurface] {
    match mode {
        Mode::Standard => &[],
        Mode::Strict => ExtensionApiSurface::ALL,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Enumeration coverage ─────────────────────────────────────────────

    #[test]
    fn all_enumerates_five_strict_blocked_families() {
        // 3 runtime surfaces (globals + content scripts + background
        // contexts) + 2 manifest-entry surfaces (DNR + bootstrap).
        assert_eq!(ExtensionApiSurface::ALL.len(), 5);
    }

    #[test]
    fn all_covers_every_phase_file_named_family() {
        // Phase 7 / Module 40 phase-file goal:
        //   - chrome.* / browser.* undefined  -> WebExtensionGlobals
        //   - content scripts do not load     -> ContentScripts
        //   - background contexts             -> BackgroundContexts
        // Edge cases:
        //   - legacy bootstrap manifests      -> BootstrappedManifest
        //   - declarative net request rules   -> DeclarativeNetRequest
        let all = ExtensionApiSurface::ALL;
        assert!(all.contains(&ExtensionApiSurface::WebExtensionGlobals));
        assert!(all.contains(&ExtensionApiSurface::ContentScripts));
        assert!(all.contains(&ExtensionApiSurface::BackgroundContexts));
        assert!(all.contains(&ExtensionApiSurface::DeclarativeNetRequest));
        assert!(all.contains(&ExtensionApiSurface::BootstrappedManifest));
    }

    #[test]
    fn legacy_bootstrap_manifest_is_a_blocked_family() {
        // Phase-file edge case.
        assert!(ExtensionApiSurface::ALL.contains(&ExtensionApiSurface::BootstrappedManifest));
        assert_eq!(
            ExtensionApiSurface::BootstrappedManifest.block_mechanism(),
            BlockMechanism::ManifestEntryRefused,
            "bootstrap manifests must be refused at parse, not lazily at tab spawn",
        );
    }

    #[test]
    fn declarative_net_request_is_a_blocked_family() {
        // Phase-file edge case.
        assert!(ExtensionApiSurface::ALL.contains(&ExtensionApiSurface::DeclarativeNetRequest));
        assert_eq!(
            ExtensionApiSurface::DeclarativeNetRequest.block_mechanism(),
            BlockMechanism::ManifestEntryRefused,
            "DNR rules must be dropped at manifest parse so they never reach pb-network broker",
        );
    }

    // ── webRequest boundary (mirrors disabled_apis.rs WebRTC pattern) ────

    #[test]
    fn web_request_is_not_in_this_list() {
        // Architecture v1.10 lock: the `webRequest`-style hook into
        // pb-network is forbidden in BOTH modes (no extension hook
        // surface on the network broker, period). The block is
        // enforced at the pb-network broker boundary; this module
        // MUST NOT re-enumerate it, or there are two sources of
        // truth and the no-redundant-state lock is violated.
        //
        // Substring match catches both `webRequest` and any future
        // variant naming that includes the surface as a substring.
        for surface in ExtensionApiSurface::ALL {
            for js_name in surface.js_surfaces() {
                let lower = js_name.to_lowercase();
                assert!(
                    !lower.contains("webrequest"),
                    "Module 40 must not enumerate webRequest ({js_name:?} in {surface:?}); \
                     pb-network broker owns the block per architecture v1.10",
                );
                assert!(
                    !lower.contains("webnavigation"),
                    "Module 40 must not enumerate webNavigation ({js_name:?} in {surface:?}); \
                     network observation surfaces are pb-network broker territory",
                );
            }
        }
    }

    // ── Per-mode resolver (L41 structural lock) ──────────────────────────

    #[test]
    fn block_for_mode_strict_returns_all_blocked() {
        assert_eq!(block_for_mode(Mode::Strict), BlockerPolicy::AllBlocked);
    }

    #[test]
    fn block_for_mode_standard_delegates_to_module_41() {
        assert_eq!(
            block_for_mode(Mode::Standard),
            BlockerPolicy::StandardSubjectToAllowlist,
        );
    }

    #[test]
    fn block_for_mode_strict_is_pure_on_mode_only() {
        // L41 structural lock: `block_for_mode` accepts only Mode.
        // No extension-id, no allowlist handle, no settings
        // parameter. An allowlisted extension that the user
        // installed in a Standard profile cannot leak into a
        // Strict-mode tab because there is no public API to make
        // Strict return anything other than `AllBlocked`.
        //
        // This test is a tripwire: if a future signature change
        // adds a non-Mode parameter to `block_for_mode`, this
        // test stops compiling and forces a 35.4-style settings-
        // lock audit.
        for _ in 0..16 {
            assert_eq!(block_for_mode(Mode::Strict), BlockerPolicy::AllBlocked);
        }
    }

    #[test]
    fn surfaces_blocked_for_mode_strict_returns_full_all() {
        let strict = surfaces_blocked_for_mode(Mode::Strict);
        assert_eq!(strict.len(), ExtensionApiSurface::ALL.len());
        // Content equality (not `std::ptr::eq`): `ALL` is a
        // `pub const` and consts are inlined per use-site, so
        // pointer identity is not guaranteed by the language.
        // The structural invariant Strict consumers depend on is
        // "Strict returns the exact same ordered list as ALL",
        // which content equality captures.
        assert_eq!(strict, ExtensionApiSurface::ALL);
    }

    #[test]
    fn surfaces_blocked_for_mode_standard_returns_empty() {
        // Standard delegates per-extension gating to Module 41.
        // This module darks no surface in Standard.
        assert!(surfaces_blocked_for_mode(Mode::Standard).is_empty());
    }

    // ── Completeness regressions (libxul bridge handshake) ───────────────

    #[test]
    fn every_family_has_a_block_mechanism() {
        // No `_ => ...` catch-all in `block_mechanism()`; adding a
        // new variant without a mechanism mapping is a compile
        // error. This test only asserts the call doesn't panic.
        for surface in ExtensionApiSurface::ALL {
            let _ = surface.block_mechanism();
        }
    }

    #[test]
    fn every_family_has_at_least_one_js_surface() {
        for surface in ExtensionApiSurface::ALL {
            let names = surface.js_surfaces();
            assert!(
                !names.is_empty(),
                "{surface:?} must enumerate at least one WebExtension API name / manifest key",
            );
            for name in names {
                assert!(
                    !name.is_empty(),
                    "{surface:?} js_surface name must be non-empty",
                );
            }
        }
    }

    #[test]
    fn block_mechanism_cluster_assignment_matches_design() {
        // Document the (3 mechanism, 5 family) mapping as a
        // tripwire test. Changing the mapping requires touching
        // both this test and the libxul bridge documentation in
        // the file-level TODO; the test failure makes the
        // bridge-side handshake mandatory.
        use BlockMechanism::*;
        assert_eq!(
            ExtensionApiSurface::WebExtensionGlobals.block_mechanism(),
            ApiGlobalAbsent,
        );
        assert_eq!(
            ExtensionApiSurface::ContentScripts.block_mechanism(),
            RuntimeContextNotSpawned,
        );
        assert_eq!(
            ExtensionApiSurface::BackgroundContexts.block_mechanism(),
            RuntimeContextNotSpawned,
        );
        assert_eq!(
            ExtensionApiSurface::DeclarativeNetRequest.block_mechanism(),
            ManifestEntryRefused,
        );
        assert_eq!(
            ExtensionApiSurface::BootstrappedManifest.block_mechanism(),
            ManifestEntryRefused,
        );
    }

    #[test]
    fn web_extension_globals_enumerates_both_namespaces() {
        // The Mozilla `browser.*` namespace and the Chrome-compat
        // `chrome.*` shim are both reachable in libxul-based
        // engines; missing either leaves a probing surface.
        let names = ExtensionApiSurface::WebExtensionGlobals.js_surfaces();
        assert!(names.contains(&"browser"));
        assert!(names.contains(&"chrome"));
    }

    #[test]
    fn every_browser_namespaced_surface_has_chrome_compat_pair() {
        // Gecko ships `chrome.*` as a Chrome-compat shim for every
        // `browser.*` API. A Strict block that darks only one of
        // the two leaves the other as a fully functional probe +
        // API surface. This test pins the pairing invariant: for
        // every `browser.<rest>` entry across `ExtensionApiSurface
        // ::ALL × js_surfaces()`, there must be a matching
        // `chrome.<rest>` entry in the same family's list (and
        // vice versa). Manifest-keyed (`manifest.*`) and bare
        // namespace globals are excluded — those are
        // representation-level, not API-call entries.
        for surface in ExtensionApiSurface::ALL {
            if matches!(surface, ExtensionApiSurface::WebExtensionGlobals) {
                // The bare globals are tested by
                // `web_extension_globals_enumerates_both_namespaces`.
                continue;
            }
            let names = surface.js_surfaces();
            let browser_calls: Vec<&str> = names
                .iter()
                .filter(|n| n.starts_with("browser."))
                .copied()
                .collect();
            let chrome_calls: Vec<&str> = names
                .iter()
                .filter(|n| n.starts_with("chrome."))
                .copied()
                .collect();
            for b in &browser_calls {
                let tail = b.strip_prefix("browser.").unwrap();
                let expected = format!("chrome.{tail}");
                assert!(
                    chrome_calls.iter().any(|c| *c == expected),
                    "{surface:?} lists {b:?} (Firefox-native) but is missing its Chrome-compat shim {expected:?}; \
                     Gecko exposes both — darking only one leaves a probe surface",
                );
            }
            for c in &chrome_calls {
                let tail = c.strip_prefix("chrome.").unwrap();
                let expected = format!("browser.{tail}");
                assert!(
                    browser_calls.iter().any(|b| *b == expected),
                    "{surface:?} lists {c:?} (Chrome-compat shim) but is missing its Firefox-native pair {expected:?}",
                );
            }
        }
    }
}
