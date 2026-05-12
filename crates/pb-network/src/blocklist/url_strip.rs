//! URL tracking-parameter strip (L32), Module 21.
//!
//! Architecture L32: known tracker parameters (`utm_*`, `gclid`,
//! `fbclid`, ...) are removed from outbound URLs at the broker
//! before any other route stage runs. The curated list ships
//! through the same Module 67 update channel as the host blocklist
//! (separate sub-track in [`crate::blocklist::Manifest`]).
//!
//! v1 ships:
//!   * [`DEFAULT_TRACKING_PARAMS`] — bootstrap list compiled into
//!     the binary, used until the first Module 67 manifest lands.
//!   * [`UrlParamStripList`] — the live, hot-swappable strip set.
//!   * [`strip_tracking_params`] — pure function that takes a URL
//!     and a strip list, returns the URL with matching parameters
//!     removed.
//!
//! ## Parsing scope
//!
//! v1 parses query-string structure only: split at the first `?`,
//! split the query at any `#`, then split parts on `&`. This is
//! enough for the L32 contract (which targets known parameter names
//! that are never percent-encoded in practice). It does NOT do full
//! RFC 3986 normalization; future revisions may swap in a full URL
//! parser if Module 22 needs richer surface.
//!
//! ## Why no `url` crate dep
//!
//! Adding a parser dep doubles the network-broker compile time for
//! a 50-line operation. The v1 hand-rolled parser is bounded
//! (rejects URLs > 4096 chars, defends against integer overflow,
//! tested for trailing-`?` cleanup), and the route-path call site
//! is the only consumer. If Module 22 (header scrubbing) needs URL
//! parsing later, the dep can land then.

use crate::blocklist::rule::UrlParamRule;
use std::collections::HashSet;

/// Hard cap on URL length the strip function will process. Longer
/// inputs are returned unchanged (the route path treats this as
/// "stripper opted out"; the URL still hits the host-rule matcher
/// and L30 HTTPS-only enforcement). 4096 covers > 99.9% of real
/// URLs and keeps the strip pass O(1)-ish.
pub const MAX_STRIPPABLE_URL_LEN: usize = 4096;

/// Compile-time default strip list. Used by
/// [`UrlParamStripList::default_bootstrap`] until Module 67 lands a
/// signed manifest.
///
/// Curated for false-positive safety: every entry is well-known
/// across the public web as a tracking parameter that the publisher
/// (not the user) added. We do NOT strip ambiguous params like
/// `q`, `id`, `s`, or `ref` (unqualified) because plenty of
/// non-tracking sites use those for navigation.
pub const DEFAULT_TRACKING_PARAMS: &[&str] = &[
    // Google Analytics (UTM). The full set, including the less
    // common `_id`/`_name` variants.
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_name",
    // Google Ads click identifiers.
    "gclid",
    "gclsrc",
    "dclid",
    // Facebook / Meta.
    "fbclid",
    // Microsoft / Bing.
    "msclkid",
    // Yandex.
    "yclid",
    // Mailchimp campaign id.
    "mc_eid",
    // Adobe / Marketo.
    "mkt_tok",
    // Instagram share id.
    "igshid",
    // HubSpot.
    "hsctatracking",
    "hsenc",
    // Twitter / X click identifier.
    "twclid",
    // Snapchat click identifier.
    "scid",
    // Pinterest.
    "epik",
    // Generic publisher referer breadcrumbs that are widely treated
    // as tracking. Kept narrowly named to avoid false positives.
    "ref_src",
    "ref_url",
];

/// Set-shaped strip list. Lookup is `O(1)` per parameter.
#[derive(Debug, Clone)]
pub struct UrlParamStripList {
    names: HashSet<String>,
}

impl UrlParamStripList {
    pub fn empty() -> Self {
        Self {
            names: HashSet::new(),
        }
    }

    /// Build a list from a [`UrlParamRule`] slice (e.g. the
    /// `url_param_rules` track of a [`crate::blocklist::Manifest`]).
    pub fn from_rules(rules: &[UrlParamRule]) -> Self {
        Self {
            names: rules.iter().map(|r| r.name().to_string()).collect(),
        }
    }

    /// Bootstrap list compiled into the binary. The scheduler swaps
    /// this out after the first successful manifest load.
    pub fn default_bootstrap() -> Self {
        Self {
            names: DEFAULT_TRACKING_PARAMS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// True iff `name` (case-insensitive) is on the strip list.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(&name.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Strip every parameter on `list` from `url`'s query string.
/// Returns the rewritten URL, or `url` unchanged if there is
/// nothing to strip (no query, no match, or oversized input).
///
/// Order of remaining parameters is preserved.
pub fn strip_tracking_params(url: &str, list: &UrlParamStripList) -> String {
    if url.len() > MAX_STRIPPABLE_URL_LEN || list.is_empty() {
        return url.to_string();
    }
    let Some(q_pos) = url.find('?') else {
        return url.to_string();
    };
    let prefix = &url[..q_pos];
    let after_q = &url[q_pos + 1..];
    let (query, fragment) = match after_q.find('#') {
        Some(i) => (&after_q[..i], Some(&after_q[i..])), // fragment includes leading '#'
        None => (after_q, None),
    };
    if query.is_empty() {
        return url.to_string();
    }
    let mut kept = Vec::new();
    let mut stripped_any = false;
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        let key = match part.find('=') {
            Some(i) => &part[..i],
            None => part,
        };
        if list.contains(key) {
            stripped_any = true;
            continue;
        }
        kept.push(part);
    }
    if !stripped_any {
        return url.to_string();
    }
    let mut out = String::with_capacity(url.len());
    out.push_str(prefix);
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    if let Some(frag) = fragment {
        out.push_str(frag);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_with(names: &[&str]) -> UrlParamStripList {
        UrlParamStripList {
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn default_bootstrap_includes_utm_source() {
        let list = UrlParamStripList::default_bootstrap();
        assert!(list.contains("utm_source"));
        assert!(list.contains("UTM_SOURCE"), "lookup is case-insensitive");
        assert!(list.contains("gclid"));
        assert!(list.contains("fbclid"));
    }

    #[test]
    fn list_does_not_include_ambiguous_params() {
        let list = UrlParamStripList::default_bootstrap();
        // These are common navigation params; stripping them would
        // break legitimate sites.
        assert!(!list.contains("q"));
        assert!(!list.contains("id"));
        assert!(!list.contains("ref"));
    }

    #[test]
    fn strip_returns_unchanged_when_no_query() {
        let list = list_with(&["utm_source"]);
        assert_eq!(
            strip_tracking_params("https://example.com/path", &list),
            "https://example.com/path"
        );
    }

    #[test]
    fn strip_returns_unchanged_when_query_empty() {
        let list = list_with(&["utm_source"]);
        assert_eq!(
            strip_tracking_params("https://example.com/path?", &list),
            "https://example.com/path?"
        );
    }

    #[test]
    fn strip_removes_single_matching_param() {
        let list = list_with(&["utm_source"]);
        assert_eq!(
            strip_tracking_params("https://example.com/?utm_source=x", &list),
            "https://example.com/"
        );
    }

    #[test]
    fn strip_preserves_non_tracking_params() {
        let list = list_with(&["utm_source"]);
        assert_eq!(
            strip_tracking_params(
                "https://example.com/search?q=hello&utm_source=ad&page=2",
                &list
            ),
            "https://example.com/search?q=hello&page=2"
        );
    }

    #[test]
    fn strip_removes_multiple_matching_params() {
        let list = list_with(&["utm_source", "utm_medium", "fbclid"]);
        assert_eq!(
            strip_tracking_params(
                "https://example.com/?q=hi&utm_source=a&utm_medium=b&fbclid=c&page=2",
                &list
            ),
            "https://example.com/?q=hi&page=2"
        );
    }

    #[test]
    fn strip_drops_question_mark_when_all_params_removed() {
        let list = list_with(&["utm_source", "fbclid"]);
        assert_eq!(
            strip_tracking_params("https://example.com/path?utm_source=a&fbclid=b", &list),
            "https://example.com/path"
        );
    }

    #[test]
    fn strip_preserves_fragment() {
        let list = list_with(&["utm_source"]);
        assert_eq!(
            strip_tracking_params("https://example.com/?utm_source=x#section", &list),
            "https://example.com/#section"
        );
        assert_eq!(
            strip_tracking_params("https://example.com/?q=hi&utm_source=x#section", &list),
            "https://example.com/?q=hi#section"
        );
    }

    #[test]
    fn strip_handles_param_without_value() {
        let list = list_with(&["fbclid"]);
        // Some links omit `=value`. The strip should still match.
        assert_eq!(
            strip_tracking_params("https://example.com/?fbclid&q=hi", &list),
            "https://example.com/?q=hi"
        );
    }

    #[test]
    fn strip_is_case_insensitive_on_param_names() {
        let list = list_with(&["utm_source"]);
        assert_eq!(
            strip_tracking_params("https://example.com/?UTM_SOURCE=x", &list),
            "https://example.com/"
        );
    }

    #[test]
    fn strip_unchanged_when_no_match() {
        let list = list_with(&["utm_source"]);
        let in_url = "https://example.com/?q=hello&page=2";
        assert_eq!(strip_tracking_params(in_url, &list), in_url);
    }

    #[test]
    fn strip_skips_oversized_url() {
        let list = list_with(&["utm_source"]);
        let big = format!(
            "https://example.com/?utm_source=x&{}",
            "x".repeat(MAX_STRIPPABLE_URL_LEN)
        );
        // Oversized: the strip function returns the input unchanged.
        assert_eq!(strip_tracking_params(&big, &list), big);
    }

    #[test]
    fn strip_with_empty_list_returns_unchanged() {
        let list = UrlParamStripList::empty();
        let url = "https://example.com/?utm_source=x";
        assert_eq!(strip_tracking_params(url, &list), url);
    }

    #[test]
    fn strip_preserves_param_order() {
        let list = list_with(&["utm_source"]);
        assert_eq!(
            strip_tracking_params("https://example.com/?a=1&b=2&utm_source=x&c=3&d=4", &list),
            "https://example.com/?a=1&b=2&c=3&d=4"
        );
    }

    #[test]
    fn from_rules_uses_lowercased_names() {
        let rules = vec![UrlParamRule::new("UTM_SOURCE"), UrlParamRule::new("FBCLID")];
        let list = UrlParamStripList::from_rules(&rules);
        assert!(list.contains("utm_source"));
        assert!(list.contains("UTM_SOURCE"));
        assert!(list.contains("fbclid"));
        assert_eq!(list.len(), 2);
    }
}
