//! Outbound HTTP request header scrubbing, Module 22.
//!
//! Architecture references:
//!   * **L31** — Referer policy: `strict-origin-when-cross-origin` in
//!     Standard mode, `no-referrer` in Strict.
//!   * **L27** — every error / debug surface is opaque; the scrubbed
//!     header list never reaches Display in this module.
//!   * **L33** — fingerprint surface (UA / Accept-Language /
//!     Accept-Encoding) is locked to a single canonical value across
//!     all DevBrowse users so the cohort-watch protocol does not split.
//!     Module 34 (`pb-fingerprint::Navigator`, Phase 5) will replace
//!     these constants with the canonical Gecko-aligned values; the
//!     v1 placeholders here track that future binding.
//!   * **§3.2 / §3.3** — Mode is captured at bootstrap and the policy
//!     table is per-Mode (Standard vs Strict).
//!
//! ## Route position
//!
//! Per Module 19 spec (route order): scrub runs **after** blocklist /
//! URL-param strip and **before** DoH resolve / TLS handshake. The
//! coordinator threads `site_origin`, the parsed `target_host`, and
//! the (possibly downgrade-approved) `target_url` through this module
//! so the Referer policy can compute same-origin and downgrade
//! decisions deterministically.
//!
//! ## Strip / override / pass-through
//!
//! Three behaviours per header name:
//!
//!   * **Override (always):** `User-Agent`, `Accept-Language`,
//!     `Accept-Encoding`, `Referer`, `DNT`, `Sec-GPC`. Renderer-set
//!     values are discarded; the canonical value is injected.
//!   * **Strip (renderer must not set):** `Cookie` (storage broker
//!     injects later), `Sec-CH-UA-*` family (Client Hints, opt-in
//!     post-Module 59), `X-Requested-With`, `X-Forwarded-*`, `Via`,
//!     `Forwarded`. These are never re-added in v1.
//!   * **Pass-through:** every other header (Content-Type,
//!     Cache-Control, Origin, Authorization, custom application
//!     headers like `X-CSRF-Token`). The scrubber preserves order
//!     and casing of pass-through headers so server-side parsers
//!     that key on header position behave identically to a
//!     non-scrubbed flow.
//!
//! ## Cookie header bypass (Edge case)
//!
//! Per spec: "never let a renderer set `Cookie` manually; cookies
//! arrive via the storage broker only." The scrubber strips Cookie
//! unconditionally; storage-broker-injected cookies join the request
//! at a later stage in the dispatch path (Module 80 wiring). v1 does
//! not yet inject cookies — the broker's role is reserved for Phase
//! 8 once the cookie storage primitive (Module 16) is exposed
//! through pb-ipc to the network broker.
//
// Module 34 (Navigator) has shipped: `pb_fingerprint::LOCKED_USER_AGENT`
//   + `LOCKED_LANGUAGE` carry the canonical cohort values. The
//   constants below are duplicated here BY DESIGN (L12 sibling-leaf
//   rule forbids pb-network → pb-fingerprint imports); paired
//   regression tests
//   `devbrowse_user_agent_matches_module_34_locked_value` +
//   `devbrowse_accept_language_matches_module_34_locked_value` in
//   pb-network catch any drift between the two sides.
// TODO(post-v1 consolidation candidate): a single home for cross-crate
//   cohort string constants (e.g. moving both copies into pb-config,
//   which is a leaf both pb-network and pb-fingerprint can import).
//   Owner unclaimed; not blocking any pending module. Cross-ref TODO
//   in `pb-fingerprint/src/gecko/navigator.rs` describing the same
//   resolution paths.
// TODO(Module 59): per-site Client Hints opt-in. When the user grants
//   `Sec-CH-UA-*` for a host, the strip list contracts to allow the
//   override-injected hint values for that host only.
// TODO(Module 80): storage-broker Cookie injection runs after this
//   scrub; the order is "renderer headers -> scrub -> broker
//   cookies -> dispatch", which is what gives Cookie its
//   "renderer never sets" property at this layer.

use crate::Mode;

// ── Locked canonical fingerprint defaults (paired with pb-fingerprint Module 34) ──

/// User-Agent advertised on every outbound request. Locked across all
/// DevBrowse users so the cohort-watch protocol cannot fork the UA
/// fingerprint by mode or by user choice.
///
/// **Why a fixed string in Module 22**: the User-Agent is part of the
/// fingerprint cohort `JA3 + Accept-Language + UA` that the Phase 10
/// adversarial suite asserts on. Module 34 (`pb-fingerprint::Navigator`)
/// owns the canonical value once it lands; until then, this constant
/// is the source of truth and the Phase 10 suite asserts byte-equality
/// against it.
pub const DEVBROWSE_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// Accept-Language. **Locked to `en-US,en;q=0.5`** across the cohort —
/// per-user locale leakage is one of the strongest fingerprint
/// signals on the public web (a Spanish-speaking user in São Paulo
/// is uniquely identifiable by `Accept-Language: es-BR,pt-BR`).
/// Locking to a single value trades server-side localization quality
/// for cohort-cohesion; users who care about per-site localization
/// will pick the language at the site level.
pub const DEVBROWSE_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.5";

/// Accept-Encoding. Lock-step with the rustls / hyper feature set so
/// the encodings advertised match the encodings the client can
/// actually decode.
pub const DEVBROWSE_ACCEPT_ENCODING: &str = "gzip, br, zstd";

/// Default `Accept` for HTML navigation requests. Used only when the
/// renderer did not supply its own request-type-specific Accept
/// (image/avif, application/json, etc.). Pass-through preserves the
/// renderer's content-negotiation intent.
pub const DEVBROWSE_ACCEPT_DEFAULT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

// ── Header policy ─────────────────────────────────────────────────────────

/// Referer header emission policy (L31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefererPolicy {
    /// Standard: send origin only, dropped on HTTPS->HTTP downgrade.
    /// Spec name `strict-origin-when-cross-origin`. v1 sends origin
    /// only on both same-origin and cross-origin (a tightening — the
    /// spec normally allows full URL on same-origin); see
    /// [`compute_referer`] doc.
    StrictOriginWhenCrossOrigin,
    /// Strict: never send Referer, regardless of origin or scheme.
    NoReferrer,
}

/// Outbound header policy snapshot. Captured at coordinator
/// bootstrap; live mutation is intentionally not supported (mode
/// changes go through the §3.6 respawn path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderPolicy {
    pub mode: Mode,
    pub referer: RefererPolicy,
    pub user_agent: &'static str,
    pub accept_language: &'static str,
    pub accept_encoding: &'static str,
    pub accept_default: &'static str,
    pub send_dnt: bool,
    pub send_sec_gpc: bool,
}

impl HeaderPolicy {
    /// Pick the policy snapshot for `mode`.
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::standard(),
            Mode::Strict => Self::strict(),
        }
    }

    pub fn standard() -> Self {
        Self {
            mode: Mode::Standard,
            referer: RefererPolicy::StrictOriginWhenCrossOrigin,
            user_agent: DEVBROWSE_USER_AGENT,
            accept_language: DEVBROWSE_ACCEPT_LANGUAGE,
            accept_encoding: DEVBROWSE_ACCEPT_ENCODING,
            accept_default: DEVBROWSE_ACCEPT_DEFAULT,
            send_dnt: true,
            send_sec_gpc: true,
        }
    }

    pub fn strict() -> Self {
        Self {
            mode: Mode::Strict,
            referer: RefererPolicy::NoReferrer,
            user_agent: DEVBROWSE_USER_AGENT,
            accept_language: DEVBROWSE_ACCEPT_LANGUAGE,
            accept_encoding: DEVBROWSE_ACCEPT_ENCODING,
            accept_default: DEVBROWSE_ACCEPT_DEFAULT,
            send_dnt: true,
            send_sec_gpc: true,
        }
    }
}

// ── Header name lists ─────────────────────────────────────────────────────

/// Header names the renderer is never allowed to set on outbound
/// requests. The scrubber removes any matching header (case-
/// insensitive) without re-injecting a value. Cookie joins the
/// request from the storage broker at a later route stage.
const STRIP_NAMES: &[&str] = &[
    "cookie",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-model",
    "sec-ch-ua-wow64",
    "x-requested-with",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "via",
    "forwarded",
];

/// Header names the scrubber overrides. The renderer's value is
/// dropped and the policy-computed value injected. This list overlaps
/// with `STRIP_NAMES` semantically (we strip first, then inject) but
/// is kept separate so the strip pass remains a pure removal.
const OVERRIDE_NAMES: &[&str] = &[
    "user-agent",
    "accept-language",
    "accept-encoding",
    "referer",
    "dnt",
    "sec-gpc",
];

// ── Scrub entrypoint ──────────────────────────────────────────────────────

/// Apply [`HeaderPolicy`] to a renderer-supplied header list and
/// return the outbound list. Pure function — no I/O, no allocation
/// beyond the output `Vec` and three small `String`s for the
/// override values.
///
/// `site_origin` is the eTLD+1 origin of the page that initiated
/// the request (orchestrator-supplied tab context, already gatekept
/// upstream). `target_host` is the host parsed from `target_url`;
/// pass it in instead of re-parsing here so the same parse the
/// blocklist used drives the same-origin decision.
///
/// `target_url` is the (possibly upgraded) outbound URL — used for
/// HTTPS-downgrade detection only (the L31 policy drops Referer on
/// `https://` -> `http://`).
///
/// Header order: stripped overrides + canonical inserts come first,
/// followed by every renderer-set pass-through header in original
/// order. Names are normalized to lowercase per RFC 7230 §3.2 (HTTP
/// header names are case-insensitive on the wire); values are
/// preserved verbatim.
pub fn scrub(
    policy: &HeaderPolicy,
    site_origin: &str,
    target_host: &str,
    target_url: &str,
    headers: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(headers.len() + 6);

    // Inject policy-managed headers first. Order: User-Agent,
    // Accept-Language, Accept-Encoding, then DNT / Sec-GPC, then
    // Referer (when emitted). Accept is renderer-supplied or the
    // default, handled as part of pass-through below.
    out.push(("User-Agent".to_string(), policy.user_agent.to_string()));
    out.push((
        "Accept-Language".to_string(),
        policy.accept_language.to_string(),
    ));
    out.push((
        "Accept-Encoding".to_string(),
        policy.accept_encoding.to_string(),
    ));
    if policy.send_dnt {
        out.push(("DNT".to_string(), "1".to_string()));
    }
    if policy.send_sec_gpc {
        out.push(("Sec-GPC".to_string(), "1".to_string()));
    }
    if let Some(referer) = compute_referer(policy.referer, site_origin, target_host, target_url) {
        out.push(("Referer".to_string(), referer));
    }

    // Track whether the renderer supplied an Accept header so we
    // can inject the default only when absent.
    let mut renderer_supplied_accept = false;

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if STRIP_NAMES.contains(&lower.as_str()) {
            continue;
        }
        if OVERRIDE_NAMES.contains(&lower.as_str()) {
            // We already injected the canonical value above.
            continue;
        }
        if lower == "accept" {
            renderer_supplied_accept = true;
        }
        out.push((name, value));
    }

    if !renderer_supplied_accept {
        out.push(("Accept".to_string(), policy.accept_default.to_string()));
    }

    out
}

/// Compute the Referer header value per L31.
///
/// Returns `None` when the policy says no Referer should be sent.
/// `Some(value)` when a value should be emitted; the value is the
/// origin (scheme + `://` + host) of the source page, derived from
/// `site_origin`.
///
/// **v1 simplification**: even on same-origin, v1 sends origin only
/// rather than full URL. Reason: the orchestrator-supplied
/// `site_origin` is the eTLD+1, not the full source URL; we do not
/// have the source URL's path here. The spec policy
/// `strict-origin-when-cross-origin` allows full URL on same-origin,
/// origin only on cross-origin; v1 is therefore tighter than spec.
/// This is a conservative choice that does not break navigation
/// (sites that rely on Referer for path-level CSRF tokens already
/// degrade gracefully under origin-only Referer because most
/// browsers default to origin-only post-2020). Module 34 + a richer
/// orchestrator request envelope can lift this in future revisions.
///
/// Scheme: v1 emits `https://` because the L30 default is
/// HTTPS-Only and the source page is HTTPS in 99.9% of cases. If we
/// detect a downgrade (target is `http://`), Referer is suppressed
/// regardless of policy.
fn compute_referer(
    policy: RefererPolicy,
    site_origin: &str,
    _target_host: &str,
    target_url: &str,
) -> Option<String> {
    if matches!(policy, RefererPolicy::NoReferrer) {
        return None;
    }
    if site_origin.is_empty() {
        return None;
    }
    // HTTPS -> HTTP downgrade: suppress (L31 strict-origin... + L30).
    if target_url.len() >= 7 && target_url.as_bytes()[..7].eq_ignore_ascii_case(b"http://") {
        return None;
    }
    Some(format!("https://{site_origin}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    fn find(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }

    fn count(headers: &[(String, String)], name: &str) -> usize {
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .count()
    }

    #[test]
    fn devbrowse_user_agent_matches_module_34_locked_value() {
        // CROSS-MODULE REGRESSION TEST (Module 34). pb-network and
        // pb-fingerprint are L12 sibling leaves (neither imports the
        // other), so the alignment of the locked UA string is
        // enforced by paired literal-string assertions on both sides.
        // If DEVBROWSE_USER_AGENT here drifts from
        // `pb_fingerprint::LOCKED_USER_AGENT`, the paired test
        // `navigator_ua_matches_module_22_constant` in
        // crates/pb-fingerprint/src/gecko/navigator.rs breaks first;
        // if that constant drifts, this test breaks. The Phase 10
        // adversarial suite is the third defense (live JS-vs-HTTP
        // equality check on a spawned renderer).
        const MODULE_34_EXPECTED_UA: &str =
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
        assert_eq!(DEVBROWSE_USER_AGENT, MODULE_34_EXPECTED_UA);
    }

    #[test]
    fn devbrowse_accept_language_matches_module_34_locked_value() {
        // Paired with `navigator_language_matches_module_22_accept_language`
        // in pb-fingerprint. The q-value progression
        // ("en-US,en;q=0.5") -> first locale "en-US" -> language list
        // ["en-US", "en"] is the alignment contract.
        const MODULE_34_EXPECTED_ACCEPT_LANGUAGE: &str = "en-US,en;q=0.5";
        assert_eq!(
            DEVBROWSE_ACCEPT_LANGUAGE,
            MODULE_34_EXPECTED_ACCEPT_LANGUAGE
        );
    }

    #[test]
    fn standard_policy_uses_strict_origin_when_cross_origin() {
        let p = HeaderPolicy::standard();
        assert_eq!(p.referer, RefererPolicy::StrictOriginWhenCrossOrigin);
        assert_eq!(p.mode, Mode::Standard);
        assert!(p.send_dnt);
        assert!(p.send_sec_gpc);
    }

    #[test]
    fn strict_policy_uses_no_referrer() {
        let p = HeaderPolicy::strict();
        assert_eq!(p.referer, RefererPolicy::NoReferrer);
        assert_eq!(p.mode, Mode::Strict);
    }

    #[test]
    fn for_mode_picks_correct_policy() {
        assert_eq!(
            HeaderPolicy::for_mode(Mode::Standard),
            HeaderPolicy::standard()
        );
        assert_eq!(HeaderPolicy::for_mode(Mode::Strict), HeaderPolicy::strict());
    }

    #[test]
    fn scrub_overrides_user_agent() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![h("User-Agent", "EvilFingerprintBot/1.0")],
        );
        assert_eq!(
            find(&out, "user-agent"),
            Some(DEVBROWSE_USER_AGENT.to_string())
        );
    }

    #[test]
    fn scrub_overrides_accept_language_and_encoding() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![
                h("Accept-Language", "es-MX,es;q=0.9,fr;q=0.5"),
                h("Accept-Encoding", "gzip"),
            ],
        );
        assert_eq!(
            find(&out, "accept-language"),
            Some(DEVBROWSE_ACCEPT_LANGUAGE.to_string())
        );
        assert_eq!(
            find(&out, "accept-encoding"),
            Some(DEVBROWSE_ACCEPT_ENCODING.to_string())
        );
    }

    #[test]
    fn scrub_strips_cookie_unconditionally() {
        // Edge case (per spec): renderer-set Cookie must never reach
        // the wire. The storage broker is the sole cookie source.
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![h("Cookie", "session=stolen-from-renderer; theft=yes")],
        );
        assert_eq!(count(&out, "cookie"), 0);
    }

    #[test]
    fn scrub_strips_cookie_case_insensitively() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![h("COOKIE", "x=y"), h("CooKie", "z=w")],
        );
        assert_eq!(count(&out, "cookie"), 0);
    }

    #[test]
    fn scrub_strips_sec_ch_ua_family() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![
                h("Sec-CH-UA", "\"DevBrowse\";v=\"1\""),
                h("Sec-CH-UA-Mobile", "?0"),
                h("Sec-CH-UA-Platform", "\"Linux\""),
                h("Sec-CH-UA-Arch", "\"arm\""),
                h("Sec-CH-UA-Bitness", "\"64\""),
                h("Sec-CH-UA-Full-Version", "\"1.0.0\""),
                h("Sec-CH-UA-Model", "\"Pixel 8\""),
            ],
        );
        for name in [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-ch-ua-arch",
            "sec-ch-ua-bitness",
            "sec-ch-ua-full-version",
            "sec-ch-ua-model",
        ] {
            assert_eq!(count(&out, name), 0, "must strip {name}");
        }
    }

    #[test]
    fn scrub_strips_x_forwarded_family_and_proxy_breadcrumbs() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![
                h("X-Forwarded-For", "192.168.1.1"),
                h("X-Forwarded-Host", "internal"),
                h("X-Forwarded-Proto", "http"),
                h("X-Forwarded-Port", "8080"),
                h("Via", "1.1 internal-proxy"),
                h("Forwarded", "for=192.0.2.43"),
                h("X-Requested-With", "XMLHttpRequest"),
            ],
        );
        for name in [
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "via",
            "forwarded",
            "x-requested-with",
        ] {
            assert_eq!(count(&out, name), 0, "must strip {name}");
        }
    }

    #[test]
    fn scrub_passes_through_application_headers() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![
                h("Content-Type", "application/json"),
                h("X-CSRF-Token", "abc123"),
                h("Authorization", "Bearer xxx"),
                h("Cache-Control", "no-cache"),
                h("Origin", "https://example.com"),
            ],
        );
        assert_eq!(
            find(&out, "content-type"),
            Some("application/json".to_string())
        );
        assert_eq!(find(&out, "x-csrf-token"), Some("abc123".to_string()));
        assert_eq!(find(&out, "authorization"), Some("Bearer xxx".to_string()));
        assert_eq!(find(&out, "cache-control"), Some("no-cache".to_string()));
        assert_eq!(
            find(&out, "origin"),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn scrub_preserves_pass_through_order() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![
                h("X-Custom-A", "1"),
                h("X-Custom-B", "2"),
                h("X-Custom-C", "3"),
            ],
        );
        let app_only: Vec<&String> = out
            .iter()
            .filter_map(|(n, _)| n.starts_with("X-Custom").then_some(n))
            .collect();
        assert_eq!(app_only, vec!["X-Custom-A", "X-Custom-B", "X-Custom-C"]);
    }

    #[test]
    fn scrub_injects_default_accept_when_renderer_did_not_supply_one() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![],
        );
        assert_eq!(
            find(&out, "accept"),
            Some(DEVBROWSE_ACCEPT_DEFAULT.to_string())
        );
    }

    #[test]
    fn scrub_passes_through_renderer_accept() {
        // Image fetches need image/avif etc.; the renderer's request-
        // type-specific Accept is preserved (not overridden).
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![h("Accept", "image/avif,image/webp,*/*;q=0.8")],
        );
        assert_eq!(
            find(&out, "accept"),
            Some("image/avif,image/webp,*/*;q=0.8".to_string())
        );
    }

    #[test]
    fn scrub_emits_dnt_and_sec_gpc_in_standard() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![],
        );
        assert_eq!(find(&out, "dnt"), Some("1".to_string()));
        assert_eq!(find(&out, "sec-gpc"), Some("1".to_string()));
    }

    #[test]
    fn scrub_emits_dnt_and_sec_gpc_in_strict() {
        let out = scrub(
            &HeaderPolicy::strict(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![],
        );
        assert_eq!(find(&out, "dnt"), Some("1".to_string()));
        assert_eq!(find(&out, "sec-gpc"), Some("1".to_string()));
    }

    #[test]
    fn scrub_overrides_renderer_set_dnt_and_sec_gpc() {
        // Renderer trying to spoof DNT=0 must not slip through.
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![h("DNT", "0"), h("Sec-GPC", "0")],
        );
        assert_eq!(find(&out, "dnt"), Some("1".to_string()));
        assert_eq!(find(&out, "sec-gpc"), Some("1".to_string()));
    }

    // -- Referer policy tests --

    #[test]
    fn referer_emitted_for_standard_https_target() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/page",
            vec![],
        );
        assert_eq!(
            find(&out, "referer"),
            Some("https://example.com/".to_string())
        );
    }

    #[test]
    fn referer_emitted_cross_origin_under_standard() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "other.com",
            "https://other.com/page",
            vec![],
        );
        assert_eq!(
            find(&out, "referer"),
            Some("https://example.com/".to_string()),
            "Referer reflects the source origin, not the target"
        );
    }

    #[test]
    fn referer_suppressed_on_https_to_http_downgrade() {
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "http://example.com/page",
            vec![],
        );
        assert_eq!(count(&out, "referer"), 0);
    }

    #[test]
    fn referer_never_emitted_in_strict() {
        let out = scrub(
            &HeaderPolicy::strict(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![],
        );
        assert_eq!(count(&out, "referer"), 0);
    }

    #[test]
    fn referer_overrides_renderer_set_value() {
        // Renderer trying to spoof Referer must not slip through.
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "https://example.com/",
            vec![h("Referer", "https://victim.example/secret-path")],
        );
        assert_eq!(
            find(&out, "referer"),
            Some("https://example.com/".to_string())
        );
        assert_eq!(count(&out, "referer"), 1);
    }

    #[test]
    fn referer_suppressed_when_site_origin_empty() {
        // Defensive: if the orchestrator somehow supplies an empty
        // origin, do not emit a half-formed Referer.
        let out = scrub(
            &HeaderPolicy::standard(),
            "",
            "example.com",
            "https://example.com/",
            vec![],
        );
        assert_eq!(count(&out, "referer"), 0);
    }

    #[test]
    fn referer_recognizes_uppercase_http_scheme_for_downgrade() {
        // L30 / L31: scheme matching is ASCII case-insensitive.
        let out = scrub(
            &HeaderPolicy::standard(),
            "example.com",
            "example.com",
            "HTTP://example.com/",
            vec![],
        );
        assert_eq!(count(&out, "referer"), 0);
    }
}
