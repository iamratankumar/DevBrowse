//! ClientHello pin (cohort-locked JA3), Module 24.1.
//!
//! Architecture references:
//!   * **L8 / §5.5** — fingerprint normalization. The TLS ClientHello is
//!     one of the most easily-readable wire-level fingerprints (JA3
//!     hash); pinning it across every DevBrowse install collapses the
//!     TLS-side cohort to a single value.
//!   * **§3.4 (mirrored) / Module 23 doc invariant** — Standard and
//!     Strict ship the **same** ClientHello on the wire. Mode-divergent
//!     JA3 would itself be a fingerprint, so Mode separation lives at
//!     the *application* layer (DoH whitelist, header policy, partition
//!     keys) and never at the rustls-config layer. This module enforces
//!     that invariant by exposing exactly one pinned provider; every
//!     `ChainValidator` constructor flows through it regardless of the
//!     Mode the surrounding tab will run in.
//!   * **Adaptation protocol cohort-watch (README)** — `rustls` is on
//!     the cohort-watch dependency list because a 0.23.x bump can shift
//!     the cipher-suite ordering, the extension set, or the supported
//!     groups list, any of which change the JA3 hash. The constants
//!     below are the contract: a rustls bump that shifts the JA3 must
//!     update them in lock-step or be held under the protocol.
//!   * **L7 / L22** — audited primitives. The locked suite list draws
//!     only from `rustls::crypto::ring`, which uses *ring* under the
//!     hood (the Cargo.toml feature pin enables `ring`; `aws-lc-rs` is
//!     deliberately not enabled).
//!
//! ## What "pinning" means here
//!
//! `rustls::ClientConfig::builder()` defaults to:
//!   * cipher suites = `ring::default_provider().cipher_suites`
//!   * kx_groups = `ring::default_provider().kx_groups`
//!   * protocol versions = `ALL_VERSIONS` (TLS 1.3 + TLS 1.2)
//!
//! Those defaults shift on every rustls minor bump (a new suite added,
//! an old suite re-ordered, a kx group re-sorted). For a privacy
//! browser, the *content* of those lists shifting is acceptable
//! (it must — see Adaptation protocol "cohort-shift" outcomes), but
//! the lists must shift **in lockstep across every DevBrowse install**.
//! That requires our own explicit list, not the rustls default.
//!
//! The pin therefore replaces the provider's `cipher_suites` and
//! `kx_groups` slots with explicit ordered lists ([`LOCKED_CIPHER_SUITES`]
//! / [`LOCKED_KX_GROUPS`]), and feeds an explicit
//! [`LOCKED_PROTOCOL_VERSIONS`] into the builder so v1 cohort assertions
//! (count, order, version set) hold deterministically.
//!
//! Signature algorithms, extension ordering, and the post-quantum kx
//! group `MLKEM768` are intentionally **not** part of this v1 pin:
//!
//!   * **Signature algorithms** — rustls 0.23 derives the
//!     `signature_verification_algorithms` slot from the same provider
//!     and DevBrowse does not currently override it. The slot moves
//!     in lockstep with the provider, so a rustls bump that shifts the
//!     sig-algs list still triggers Adaptation-protocol review (it
//!     shifts the JA3 the same way a suite-list change would).
//!   * **Extension ordering** — rustls's ClientHello extension order
//!     is internal to the rustls handshake state machine. There is no
//!     public API in 0.23 to reorder extensions. A future minor bump
//!     that *does* reorder is treated as a cohort-shift under the
//!     Adaptation protocol; the JA3-drift CI in Module 24.2 catches it
//!     before merge.
//!   * **MLKEM768 / hybrid kx** — rustls 0.23 supports it behind the
//!     `prefer-post-quantum` feature flag; DevBrowse does not enable
//!     that flag in v1 (would split the cohort against installs whose
//!     rustls binary is unaware). When PQ kx becomes a uniform
//!     cohort default, it joins [`LOCKED_KX_GROUPS`] in a release-
//!     gated cohort-shift.
//!
//! ## Cohort-locking properties enforced by this module
//!
//! The tests in this file pin (via `#[test]`) every property the JA3
//! probe in Module 24.2 will check at runtime:
//!
//!   1. The cipher-suite *count* is the same across every build.
//!   2. The cipher-suite *order* matches [`LOCKED_CIPHER_SUITES`].
//!   3. The kx-group *count* and *order* match [`LOCKED_KX_GROUPS`].
//!   4. Both [`pinned_crypto_provider`] and the resulting
//!      `ClientConfig` cipher-suite list are deterministic across
//!      successive calls (no PRNG-based reordering, no time-of-day
//!      branch).
//!   5. The protocol versions are exactly TLS 1.3 + TLS 1.2 (no TLS
//!      1.1 / 1.0 fallback, no QUIC/0-RTT in v1 — those are Module 88
//!      territory).
//
// Module 24.2 cohort-drift CI is live: `tests/cohort/ja3.rs`
// consumes `LOCKED_CIPHER_SUITES` / `LOCKED_KX_GROUPS` as the
// canonical reference, and `.github/workflows/ja3-drift.yml` runs
// it nightly + on PRs touching cohort-watch files. The Ja3Probe
// fixture lives in `pb-testkit` (Module 0.5).
//
// TODO(Module 88 / sync over QUIC): when QUIC ships, the QUIC
//   transport gains its own ClientHello pin (quinn config). That
//   pin lives in `pb-sync`, not here, but cross-references the
//   same suite/kx ordering rules so the JA3 cohort and the QUIC
//   handshake fingerprint stay symmetric.
// TODO(Module 24.1 follow-up — post-quantum): when MLKEM768 hybrid
//   kx is uniformly available, add `&MLKEM768X25519` to the front
//   of `LOCKED_KX_GROUPS` as a cohort-shift release-gated bump.
// TODO(Adaptation protocol): on every rustls 0.23.x patch bump,
//   re-run the JA3-drift probe (Module 24.2) before merging the
//   `Cargo.lock` change.

use rustls::client::WantsClientCert;
use rustls::crypto::ring;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::version::{TLS12, TLS13};
use rustls::{
    ClientConfig, ConfigBuilder, RootCertStore, SupportedCipherSuite, SupportedProtocolVersion,
};
use std::sync::Arc;

// ── Locked TLS protocol versions ──────────────────────────────────────────

/// The TLS protocol versions DevBrowse advertises in its ClientHello.
/// Order is preference (highest first).
///
/// **Cohort note:** this list is identical to rustls's `ALL_VERSIONS`
/// in 0.23 (TLS 1.3 then TLS 1.2). The pin is explicit so a rustls
/// minor bump that adds e.g. TLS 1.4 to `ALL_VERSIONS` does not
/// silently expand DevBrowse's ClientHello — that change is a
/// cohort-shift under the Adaptation protocol.
pub static LOCKED_PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13, &TLS12];

// ── Locked cipher suites ──────────────────────────────────────────────────

/// The cipher suites DevBrowse advertises in its ClientHello, in
/// preference order (highest first).
///
/// Three TLS 1.3 suites + six TLS 1.2 ECDHE suites. The TLS 1.3 head
/// of the list is rustls's default ordering as of 0.23.39
/// (`AES_128_GCM_SHA256` first matches BoringSSL/Chrome's order; this
/// is intentional: a smaller deviation from the dominant TLS-1.3
/// cohort is a smaller fingerprint contribution).
///
/// The TLS 1.2 tail mirrors a typical browser advertisement:
/// ECDHE_ECDSA before ECDHE_RSA at each AEAD strength, AES-128-GCM
/// then CHACHA20 then AES-256-GCM (Mozilla's "Modern" guidance).
///
/// **DH_RSA / static-RSA / 3DES / RC4 / CBC modes** are deliberately
/// absent. rustls 0.23 does not implement any of them; the list above
/// is the full rustls 0.23 ring catalog reordered for cohort-locking,
/// not a subset.
pub static LOCKED_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS 1.3.
    ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
    ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2 ECDHE_ECDSA.
    ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    // TLS 1.2 ECDHE_RSA.
    ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

// ── Locked key exchange groups ────────────────────────────────────────────

/// The (EC)DHE key exchange groups DevBrowse advertises in its
/// ClientHello key_share / supported_groups extensions, in preference
/// order.
///
/// X25519 first matches the Chrome/Firefox cohort default; the two
/// NIST curves follow as standard fallback for servers that have not
/// enabled X25519. `SECP521R1`, `FFDHE*`, and (in v1) `MLKEM768X25519`
/// are deliberately absent — see crate-level doc.
pub static LOCKED_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    ring::kx_group::X25519,
    ring::kx_group::SECP256R1,
    ring::kx_group::SECP384R1,
];

// ── ClientHelloPin façade ─────────────────────────────────────────────────

/// Façade over the locked-pin construction. Exists primarily as a
/// namespace + documented surface; all methods are static / pure
/// because the pin itself is process-wide.
///
/// **Mode-invariance:** every method on this type is Mode-agnostic.
/// Standard and Strict tabs both flow through the same
/// [`ClientHelloPin::pinned_crypto_provider`] and the same
/// [`ClientHelloPin::pinned_client_config_builder`]. Any future
/// per-mode parameter on this type would be the bug; the §3.4 mirror
/// invariant exists exactly to forbid it.
#[derive(Debug, Default, Clone, Copy)]
pub struct ClientHelloPin;

impl ClientHelloPin {
    /// Build the locked [`Arc<CryptoProvider>`] that backs every
    /// DevBrowse TLS handshake. Constructed afresh on each call;
    /// callers who hold a hot path should cache the `Arc` themselves
    /// (the [`ChainValidator`](crate::tls::ChainValidator) already
    /// does — its `build_client_config` returns
    /// `Arc<ClientConfig>` so the inner provider is shared by Arc
    /// clone).
    pub fn pinned_crypto_provider() -> Arc<CryptoProvider> {
        // Start from ring's default provider so the auxiliary slots
        // (signature_verification_algorithms, secure_random,
        // key_provider) stay aligned with the rest of the rustls /
        // ring stack. Replace only the cohort-visible slots.
        let base = ring::default_provider();
        Arc::new(CryptoProvider {
            cipher_suites: LOCKED_CIPHER_SUITES.to_vec(),
            kx_groups: LOCKED_KX_GROUPS.to_vec(),
            ..base
        })
    }

    /// Build a [`ConfigBuilder`] one step short of trust-anchor
    /// installation. Callers add their root store + client-cert
    /// policy on top; v1 only ever uses
    /// [`ClientHelloPin::pinned_client_config_with_roots`] below, but
    /// the lower-level entry point is exposed so future call sites
    /// (e.g. `pb-update` Module 65 fetching signed manifests over
    /// HTTPS) can opt into a pinned root store of their own.
    ///
    /// **Cohort lock:** this is the single entry point through which
    /// every DevBrowse `ClientConfig` is built. A future call site
    /// that constructs `ClientConfig::builder()` directly would
    /// silently bypass the pin; do not introduce one.
    pub fn pinned_client_config_builder() -> ConfigBuilder<ClientConfig, WantsClientCert> {
        // `unwrap()` is sound because:
        //   * `LOCKED_CIPHER_SUITES` is non-empty and contains both
        //     a TLS 1.3 suite (TLS13_AES_128_GCM_SHA256) and a TLS
        //     1.2 suite (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
        //     so `with_protocol_versions(LOCKED_PROTOCOL_VERSIONS)`
        //     finds at least one usable suite per version.
        //   * `LOCKED_KX_GROUPS` is non-empty.
        // The `expect` panic message is opaque (L27) — it never
        // includes suite or group identifiers.
        let provider = Self::pinned_crypto_provider();
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(LOCKED_PROTOCOL_VERSIONS)
            .expect("pinned ClientHello: locked suites + versions disagree")
            // `WebPkiServerVerifier` is installed by the chain
            // validator's caller via `with_root_certificates`; we
            // stop one stage short here so the pin module owns no
            // root-store policy. Callers can install their roots and
            // then `.with_no_client_auth()` (the v1 default).
            .with_root_certificates(RootCertStore::empty())
    }

    /// Convenience: build the locked
    /// [`ConfigBuilder<ClientConfig, WantsClientCert>`] with the
    /// caller-supplied [`RootCertStore`] in place. Used by
    /// [`crate::tls::ChainValidator::build_client_config`] so the
    /// pin and the trust anchor selection compose cleanly.
    pub fn pinned_client_config_with_roots(
        roots: RootCertStore,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let provider = Self::pinned_crypto_provider();
        ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(LOCKED_PROTOCOL_VERSIONS)
            .expect("pinned ClientHello: locked suites + versions disagree")
            .with_root_certificates(roots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Cohort-lock counts (rustls bump tripwire) --

    /// The cohort-lock contract: exactly nine cipher suites
    /// (3 TLS 1.3 + 6 TLS 1.2 ECDHE). A rustls bump that adds a new
    /// suite to ring's catalog must NOT auto-extend this list.
    #[test]
    fn locked_cipher_suite_count_is_nine() {
        assert_eq!(LOCKED_CIPHER_SUITES.len(), 9);
    }

    /// The cohort-lock contract: exactly three kx groups
    /// (X25519, SECP256R1, SECP384R1). A rustls bump that adds e.g.
    /// MLKEM768 to ring's catalog must NOT auto-extend this list.
    #[test]
    fn locked_kx_group_count_is_three() {
        assert_eq!(LOCKED_KX_GROUPS.len(), 3);
    }

    /// TLS 1.3 + TLS 1.2 only.
    #[test]
    fn locked_protocol_versions_are_13_and_12() {
        assert_eq!(LOCKED_PROTOCOL_VERSIONS.len(), 2);
        // Order matters: TLS 1.3 advertised before TLS 1.2.
        assert_eq!(LOCKED_PROTOCOL_VERSIONS[0].version, TLS13.version);
        assert_eq!(LOCKED_PROTOCOL_VERSIONS[1].version, TLS12.version);
    }

    // -- Cipher suite ordering --

    /// The TLS 1.3 head of the suite list comes before any TLS 1.2
    /// suite. Reverse ordering would break browser-typical
    /// advertisement and, more importantly, signal a cohort-shift.
    #[test]
    fn tls13_suites_precede_tls12_suites() {
        let mut seen_tls12 = false;
        for suite in LOCKED_CIPHER_SUITES {
            match suite {
                SupportedCipherSuite::Tls13(_) => {
                    assert!(
                        !seen_tls12,
                        "found TLS 1.3 suite after a TLS 1.2 suite — order broken",
                    );
                }
                SupportedCipherSuite::Tls12(_) => {
                    seen_tls12 = true;
                }
            }
        }
    }

    /// The first advertised suite is TLS13_AES_128_GCM_SHA256. Pinning
    /// the *first* suite in particular protects the JA3 hash from
    /// reordering bugs (the head dominates the per-suite contribution
    /// in JA3's 0xc02b,0xc02f,... encoded list).
    #[test]
    fn first_suite_is_tls13_aes_128_gcm() {
        assert_eq!(
            LOCKED_CIPHER_SUITES[0].suite(),
            ring::cipher_suite::TLS13_AES_128_GCM_SHA256.suite(),
        );
    }

    // -- Kx group ordering --

    #[test]
    fn first_kx_group_is_x25519() {
        // X25519 first matches the Chrome / Firefox cohort default.
        // Distance from that default = JA3 surface, so this is the
        // single most cohort-impactful constant in the module.
        assert_eq!(LOCKED_KX_GROUPS[0].name(), ring::kx_group::X25519.name(),);
    }

    #[test]
    fn kx_groups_in_locked_order() {
        let names: Vec<_> = LOCKED_KX_GROUPS.iter().map(|g| g.name()).collect();
        assert_eq!(
            names,
            vec![
                ring::kx_group::X25519.name(),
                ring::kx_group::SECP256R1.name(),
                ring::kx_group::SECP384R1.name(),
            ]
        );
    }

    // -- Pinned provider --

    #[test]
    fn pinned_provider_carries_locked_suites_in_order() {
        let p = ClientHelloPin::pinned_crypto_provider();
        assert_eq!(p.cipher_suites.len(), LOCKED_CIPHER_SUITES.len());
        for (i, suite) in p.cipher_suites.iter().enumerate() {
            assert_eq!(
                suite.suite(),
                LOCKED_CIPHER_SUITES[i].suite(),
                "cipher suite at index {i} drifted from the lock",
            );
        }
    }

    #[test]
    fn pinned_provider_carries_locked_kx_groups_in_order() {
        let p = ClientHelloPin::pinned_crypto_provider();
        assert_eq!(p.kx_groups.len(), LOCKED_KX_GROUPS.len());
        for (i, group) in p.kx_groups.iter().enumerate() {
            assert_eq!(
                group.name(),
                LOCKED_KX_GROUPS[i].name(),
                "kx group at index {i} drifted from the lock",
            );
        }
    }

    /// Two successive calls must produce providers whose
    /// cohort-visible slots are byte-identical. A regression here
    /// would mean the pin took a dependency on time / RNG / env.
    #[test]
    fn pinned_provider_is_deterministic() {
        let p1 = ClientHelloPin::pinned_crypto_provider();
        let p2 = ClientHelloPin::pinned_crypto_provider();
        let names1: Vec<_> = p1.cipher_suites.iter().map(|s| s.suite()).collect();
        let names2: Vec<_> = p2.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(names1, names2);
        let kx1: Vec<_> = p1.kx_groups.iter().map(|g| g.name()).collect();
        let kx2: Vec<_> = p2.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(kx1, kx2);
    }

    // -- Pinned ClientConfig --

    #[test]
    fn pinned_client_config_builder_constructs() {
        // The builder must reach the WantsClientCert state without
        // panicking — this is the existence proof that
        // LOCKED_CIPHER_SUITES + LOCKED_PROTOCOL_VERSIONS are
        // self-consistent (every advertised version has at least one
        // matching suite).
        let _ = ClientHelloPin::pinned_client_config_builder();
    }

    #[test]
    fn pinned_client_config_with_roots_finishes_with_no_client_auth() {
        let cfg = ClientHelloPin::pinned_client_config_with_roots(RootCertStore::empty())
            .with_no_client_auth();
        // Provider's cipher_suites slot must equal the lock.
        assert_eq!(
            cfg.crypto_provider().cipher_suites.len(),
            LOCKED_CIPHER_SUITES.len(),
        );
        for (i, suite) in cfg.crypto_provider().cipher_suites.iter().enumerate() {
            assert_eq!(suite.suite(), LOCKED_CIPHER_SUITES[i].suite());
        }
    }

    // -- Mode invariance (§3.4 mirrored) --

    /// The pin is Mode-agnostic by construction (no Mode parameter).
    /// The test pins this property explicitly so a future refactor
    /// adding a Mode parameter trips here first. Mode-divergent JA3
    /// would split the cohort the pin exists to lock.
    #[test]
    fn pin_has_no_mode_parameter() {
        // Compile-time assertion: every public method is Mode-free.
        let _: fn() -> Arc<CryptoProvider> = ClientHelloPin::pinned_crypto_provider;
        let _: fn() -> ConfigBuilder<ClientConfig, WantsClientCert> =
            ClientHelloPin::pinned_client_config_builder;
        let _: fn(RootCertStore) -> ConfigBuilder<ClientConfig, WantsClientCert> =
            ClientHelloPin::pinned_client_config_with_roots;
    }

    // -- Send + Sync --

    #[test]
    fn pin_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ClientHelloPin>();
        // The Arc<CryptoProvider> we hand out must also be Send +
        // Sync because it is shared across handshake tasks.
        assert_send_sync::<Arc<CryptoProvider>>();
    }
}
