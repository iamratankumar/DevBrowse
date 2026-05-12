//! Blocklist rule + manifest types, Module 21.
//!
//! Architecture references:
//!   * L26 — counters surfaced via the Network Viewer (Module 60).
//!   * L27 — every error / display string is opaque; rule hostnames
//!     never reach Display.
//!   * L32 — URL parameter strip list ships through the same update
//!     channel as the host blocklist (separate sub-track inside the
//!     same [`Manifest`]).
//!   * L37 — cookie-banner auto-decline rules are a third sub-track on
//!     the manifest, opt-in at the wizard.
//!
//! Rules carry a `BlockKind` (Ad / Tracker / FingerprintAttempt) so
//! the network viewer (Module 60) can break out per-tab counts by
//! reason. Each rule defaults to subdomain-inclusive matching: a
//! rule for `example.com` blocks `tracker.example.com` too. This
//! mirrors most production hostfile blocklists (Hagezi, EasyList,
//! StevenBlack, Pi-hole). Subdomain-exclusive rules are still
//! representable for cases where a parent hostname is benign but a
//! child is hostile.

use std::fmt;

/// Reason a rule blocks. Surfaced to the Network Viewer (Module 60)
/// per L26.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockKind {
    /// Ad-serving / ad-tech infrastructure.
    Ad,
    /// Cross-site / behavioural tracker.
    Tracker,
    /// Fingerprinting probe (canvas / audio / WebGL hash beacons,
    /// device-class enumerators, etc.). Distinct from "tracker" so
    /// the viewer can flag the higher-severity probe class.
    FingerprintAttempt,
}

impl BlockKind {
    /// Stable string label for diagnostic surfaces.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ad => "ad",
            Self::Tracker => "tracker",
            Self::FingerprintAttempt => "fingerprint-attempt",
        }
    }
}

/// One blocklist rule. v1 covers hostname rules only; path / query
/// regex rules (the second arm in the spec) ship in a follow-up
/// commit alongside Module 60's per-request classified-event view.
///
/// SECURITY INVARIANT (L27): `Debug` is hand-rolled to redact the
/// hostname. The full hostname is reachable via [`Rule::hostname`]
/// for trusted in-process use only.
#[derive(Clone, PartialEq, Eq)]
pub struct Rule {
    hostname: String,
    kind: BlockKind,
    applies_to_subdomains: bool,
}

impl Rule {
    /// Build a subdomain-inclusive rule (the common case).
    pub fn host(hostname: impl Into<String>, kind: BlockKind) -> Self {
        Self {
            hostname: hostname.into().to_ascii_lowercase(),
            kind,
            applies_to_subdomains: true,
        }
    }

    /// Build a rule that matches the exact hostname only.
    pub fn host_exact(hostname: impl Into<String>, kind: BlockKind) -> Self {
        Self {
            hostname: hostname.into().to_ascii_lowercase(),
            kind,
            applies_to_subdomains: false,
        }
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn kind(&self) -> BlockKind {
        self.kind
    }

    pub fn applies_to_subdomains(&self) -> bool {
        self.applies_to_subdomains
    }
}

impl fmt::Debug for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L27: hostname is sensitive; surface only the kind +
        // subdomain flag in Debug.
        f.debug_struct("Rule")
            .field("kind", &self.kind)
            .field("subdomains", &self.applies_to_subdomains)
            .finish()
    }
}

/// URL-parameter-strip rule (L32). The rule ships through the same
/// update channel as host rules, in a separate sub-track inside the
/// manifest. v1 carries the parameter name only; future revisions
/// may add a host-restricted variant for cases where a parameter is
/// only tracking on certain sites.
#[derive(Clone, PartialEq, Eq)]
pub struct UrlParamRule {
    name: String,
}

impl UrlParamRule {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into().to_ascii_lowercase(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for UrlParamRule {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L27: even param names can be telling ("affiliate_id_xxx").
        // Print only the type tag.
        _f.debug_struct("UrlParamRule").finish()
    }
}

/// Cookie-banner auto-decline rule (L37). Stub shape — actual
/// banner-detection logic lives in the renderer / fingerprint phase;
/// this type is the on-the-wire shape of the sub-track entry.
///
/// `selector` identifies the DOM element to dismiss / refuse on
/// match. Real consumers will be the renderer-side script that runs
/// at content load time when [`crate::Mode`] is Standard and the
/// wizard recorded the auto-decline opt-in.
#[derive(Clone, PartialEq, Eq)]
pub struct CookieBannerRule {
    pub site_pattern: String,
    pub selector: String,
}

impl fmt::Debug for CookieBannerRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L27: site_pattern can be revealing; print only the type tag
        // and selector length (a coarse-grained debug aid).
        f.debug_struct("CookieBannerRule")
            .field("selector_len", &self.selector.len())
            .finish()
    }
}

/// Full blocklist manifest. The three sub-tracks ship together so a
/// single signed-update fetch (Module 67) refreshes all of them
/// atomically — "host rules updated, URL strip list out of date" is
/// a state we never want.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Format version of the on-wire manifest. Bumped when the
    /// schema changes incompatibly.
    pub format_version: u32,
    /// Monotonic content version. The scheduler uses this to detect
    /// "no new content" and skip a swap.
    pub content_version: u64,
    /// Unix-epoch seconds when the upstream signer minted the
    /// manifest. Diagnostic / freshness surface only; we still trust
    /// the signature, not this field.
    pub generated_at_unix: u64,
    /// Host rules. Subdomain-inclusive by default.
    pub host_rules: Vec<Rule>,
    /// URL parameter strip list (L32 sub-track).
    pub url_param_rules: Vec<UrlParamRule>,
    /// Cookie-banner auto-decline rules (L37 sub-track). v1 ships
    /// the type only; renderer-side consumption lands later.
    pub cookie_banner_rules: Vec<CookieBannerRule>,
}

impl Manifest {
    /// Empty manifest. Used as the initial state of a [`Blocklist`]
    /// before the first successful loader run.
    pub fn empty() -> Self {
        Self {
            format_version: 1,
            content_version: 0,
            generated_at_unix: 0,
            host_rules: Vec::new(),
            url_param_rules: Vec::new(),
            cookie_banner_rules: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.host_rules.is_empty()
            && self.url_param_rules.is_empty()
            && self.cookie_banner_rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_kind_labels() {
        assert_eq!(BlockKind::Ad.label(), "ad");
        assert_eq!(BlockKind::Tracker.label(), "tracker");
        assert_eq!(BlockKind::FingerprintAttempt.label(), "fingerprint-attempt");
    }

    #[test]
    fn host_rule_lowercases_hostname() {
        let r = Rule::host("Tracker.Example.COM", BlockKind::Tracker);
        assert_eq!(r.hostname(), "tracker.example.com");
        assert!(r.applies_to_subdomains());
    }

    #[test]
    fn host_exact_rule_does_not_apply_to_subdomains() {
        let r = Rule::host_exact("example.com", BlockKind::Ad);
        assert!(!r.applies_to_subdomains());
    }

    #[test]
    fn rule_debug_redacts_hostname() {
        let r = Rule::host("very-secret.example", BlockKind::Tracker);
        let dbg = format!("{r:?}");
        assert!(
            !dbg.contains("very-secret"),
            "Rule Debug must not echo the hostname, got: {dbg}"
        );
        assert!(dbg.contains("kind"));
    }

    #[test]
    fn url_param_rule_lowercases() {
        let p = UrlParamRule::new("UTM_Source");
        assert_eq!(p.name(), "utm_source");
    }

    #[test]
    fn url_param_rule_debug_redacts_name() {
        let p = UrlParamRule::new("very_secret_param");
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("very_secret"));
    }

    #[test]
    fn cookie_banner_rule_debug_redacts_pattern() {
        let r = CookieBannerRule {
            site_pattern: "secret-site.example".to_string(),
            selector: "#consent-banner".to_string(),
        };
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("secret-site"));
        assert!(!dbg.contains("#consent-banner"));
    }

    #[test]
    fn empty_manifest_is_empty() {
        let m = Manifest::empty();
        assert!(m.is_empty());
        assert_eq!(m.format_version, 1);
        assert_eq!(m.content_version, 0);
    }
}
