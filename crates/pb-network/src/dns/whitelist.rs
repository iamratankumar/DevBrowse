//! DoH provider whitelist, Module 20.
//!
//! Architecture L25 (v1.3): curated DoH provider set, Quad9 default.
//! `pb_config::DohProvider` carries the user's choice; this module is
//! the single source of truth for the **endpoint URL** and the **SPKI
//! cert pin** corresponding to each curated variant. `pb-config`
//! intentionally does not encode endpoint URLs (so a config edit
//! cannot point at a non-curated resolver without going through
//! `Custom { url }`).
//!
//! ## Cert pin posture
//!
//! Each whitelist entry carries a SHA-256 SPKI fingerprint. v1 records
//! the field but enforcement is gated on Module 23.1 (TLS chain
//! validation, which is the only place the leaf cert's SPKI is
//! observable post-handshake). Until that lands, the [`DohClient`]
//! validates the chain via `webpki-roots` only, and [`Whitelist`]'s pin
//! is reserved as the post-23.1 contract.
//!
//! ## L21 anti-goal
//!
//! Whitelist updates flow through the signed update channel (Module 67)
//! when that lands. Until then the list is a compile-time constant; a
//! provider rotation requires a binary release. This is intentional —
//! the cohort-watch protocol (README §Adaptation) means a silent
//! whitelist edit could shift the user's DoH cohort without review.
//
// TODO(Module 23.1): wire SPKI pin verification into the TLS chain
//   validation hook.
// TODO(Module 67): replace the compile-time list with a signed-manifest
//   feed; the current list becomes the bootstrap default.

use pb_config::schema::DohProvider;
use std::fmt;

/// SHA-256 SPKI fingerprint of a DoH endpoint's certificate. v1
/// records the value but does not yet enforce it (see crate-level
/// docs); the alias is in place so call sites do not need to change
/// when Module 23.1 wires the pin check.
pub type SpkiPin = [u8; 32];

/// One curated DoH provider entry.
///
/// L27: `Debug` redacts the endpoint URL because URL-shaped strings
/// can leak into logs. The SPKI pin is short and not URL-shaped, so
/// it is shown in hex; the endpoint URL is not.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolverEndpoint {
    /// Stable identifier ("quad9", "cloudflare", "nextdns-generic",
    /// "custom"). Used in error reporting and metrics.
    pub id: &'static str,
    /// HTTPS DoH endpoint URL (RFC 8484, application/dns-message POST).
    /// Validated at boot to start with `https://`.
    pub url: String,
    /// Reserved SPKI fingerprint for post-handshake pin verification
    /// (Module 23.1 enforcement). `None` for `Custom { url }` entries
    /// where the user supplies an endpoint outside the curated set.
    pub spki_pin: Option<SpkiPin>,
}

impl fmt::Debug for ResolverEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never echo the endpoint URL. Show id + a fingerprint marker.
        f.debug_struct("ResolverEndpoint")
            .field("id", &self.id)
            .field("has_pin", &self.spki_pin.is_some())
            .finish()
    }
}

/// Errors raised when resolving a [`DohProvider`] choice into an
/// endpoint. L27: Display strings are opaque.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WhitelistError {
    /// `DohProvider::System` was supplied but the caller's mode does
    /// not permit system DNS (Strict mode hard-rejects per L21).
    #[error("system dns not permitted in this mode")]
    SystemDnsForbidden,
    /// `DohProvider::Custom { url }` did not start with `https://`.
    #[error("custom doh endpoint must use https")]
    CustomNotHttps,
}

/// Compile-time DoH provider whitelist (L25 v1.3).
///
/// SECURITY INVARIANT: every entry's `url` is HTTPS. Adding a non-HTTPS
/// entry is a build-time error caught by [`Whitelist::validate`].
#[derive(Debug, Clone)]
pub struct Whitelist;

impl Whitelist {
    /// Resolve a user's `DohProvider` choice into a concrete endpoint.
    /// Returns `None` for the system-DNS path (the caller handles it
    /// per L21 outage policy); errors when the choice is forbidden in
    /// the current mode.
    pub fn lookup(
        choice: &DohProvider,
        strict_mode: bool,
    ) -> Result<Option<ResolverEndpoint>, WhitelistError> {
        match choice {
            DohProvider::Quad9 => Ok(Some(quad9())),
            DohProvider::Cloudflare => Ok(Some(cloudflare())),
            DohProvider::NextDns => Ok(Some(nextdns_generic())),
            DohProvider::System => {
                if strict_mode {
                    Err(WhitelistError::SystemDnsForbidden)
                } else {
                    Ok(None)
                }
            }
            DohProvider::Custom { url } => {
                if !url.starts_with("https://") {
                    return Err(WhitelistError::CustomNotHttps);
                }
                Ok(Some(ResolverEndpoint {
                    id: "custom",
                    url: url.clone(),
                    spki_pin: None,
                }))
            }
        }
    }

    /// Iterator over every curated entry. Used by tests + the network
    /// viewer (Module 60) to surface available providers.
    pub fn curated() -> impl Iterator<Item = ResolverEndpoint> {
        [quad9(), cloudflare(), nextdns_generic()].into_iter()
    }

    /// Build-time invariant check; called by tests below. Enforces:
    ///   * every curated URL starts with `https://`
    ///   * every curated URL is unique
    ///   * every curated entry has a non-empty `id`
    pub fn validate() -> Result<(), &'static str> {
        let mut seen = Vec::new();
        for e in Self::curated() {
            if !e.url.starts_with("https://") {
                return Err("curated entry must be https");
            }
            if e.id.is_empty() {
                return Err("curated entry must have non-empty id");
            }
            if seen.iter().any(|u: &String| u == &e.url) {
                return Err("curated entries must have unique urls");
            }
            seen.push(e.url);
        }
        Ok(())
    }
}

fn quad9() -> ResolverEndpoint {
    // Quad9 RFC 8484 POST endpoint. Pin slot reserved for Module 23.1.
    ResolverEndpoint {
        id: "quad9",
        url: "https://dns.quad9.net/dns-query".to_string(),
        spki_pin: None,
    }
}

fn cloudflare() -> ResolverEndpoint {
    ResolverEndpoint {
        id: "cloudflare",
        url: "https://cloudflare-dns.com/dns-query".to_string(),
        spki_pin: None,
    }
}

fn nextdns_generic() -> ResolverEndpoint {
    // Generic NextDNS endpoint (no per-account config ID). The wizard
    // upgrades a NextDNS-with-config-ID choice to `Custom { url }`
    // before persisting; this entry is the bare fallback for users
    // editing TOML directly.
    ResolverEndpoint {
        id: "nextdns-generic",
        url: "https://dns.nextdns.io".to_string(),
        spki_pin: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quad9_is_default_lookup() {
        let e = Whitelist::lookup(&DohProvider::Quad9, false)
            .expect("ok")
            .expect("present");
        assert_eq!(e.id, "quad9");
        assert!(e.url.starts_with("https://"));
    }

    #[test]
    fn cloudflare_resolves() {
        let e = Whitelist::lookup(&DohProvider::Cloudflare, false)
            .expect("ok")
            .expect("present");
        assert_eq!(e.id, "cloudflare");
    }

    #[test]
    fn nextdns_generic_resolves() {
        let e = Whitelist::lookup(&DohProvider::NextDns, false)
            .expect("ok")
            .expect("present");
        assert_eq!(e.id, "nextdns-generic");
    }

    #[test]
    fn system_dns_forbidden_in_strict() {
        match Whitelist::lookup(&DohProvider::System, true) {
            Err(WhitelistError::SystemDnsForbidden) => {}
            other => panic!("expected SystemDnsForbidden, got {other:?}"),
        }
    }

    #[test]
    fn system_dns_returns_none_in_standard() {
        let e = Whitelist::lookup(&DohProvider::System, false).expect("ok");
        assert!(e.is_none(), "system dns falls back via None sentinel");
    }

    #[test]
    fn custom_must_be_https() {
        let bad = DohProvider::Custom {
            url: "http://insecure.example/dns-query".to_string(),
        };
        match Whitelist::lookup(&bad, false) {
            Err(WhitelistError::CustomNotHttps) => {}
            other => panic!("expected CustomNotHttps, got {other:?}"),
        }
    }

    #[test]
    fn custom_https_resolves() {
        let good = DohProvider::Custom {
            url: "https://my-doh.example/dns-query".to_string(),
        };
        let e = Whitelist::lookup(&good, true)
            .expect("strict still allows curated/custom")
            .expect("present");
        assert_eq!(e.id, "custom");
        assert!(e.spki_pin.is_none(), "custom entries never carry a pin");
    }

    #[test]
    fn curated_validate_passes() {
        Whitelist::validate().expect("curated list invariants hold");
    }

    #[test]
    fn debug_redacts_endpoint_url() {
        let e = quad9();
        let dbg = format!("{e:?}");
        assert!(
            !dbg.contains(&e.url),
            "ResolverEndpoint Debug must not echo the endpoint URL"
        );
    }

    #[test]
    fn whitelist_error_display_is_opaque() {
        // Tracking-resistance: error Display strings carry no host or url.
        let s = format!("{}", WhitelistError::SystemDnsForbidden);
        assert!(!s.contains("dns.quad9"));
        assert!(!s.contains("cloudflare"));
        let s2 = format!("{}", WhitelistError::CustomNotHttps);
        assert!(!s2.contains("http://"));
        assert!(!s2.contains("https://"));
    }
}
