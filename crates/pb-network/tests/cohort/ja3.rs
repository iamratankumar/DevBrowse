//! JA3 cohort-drift detection — Module 24.2.
//!
//! Drives the production [`pb_network::ChainValidator`] through the
//! [`pb_testkit::fixture::Ja3Probe`] capture path, parses the resulting
//! ClientHello bytes, and pins the cohort-locked fields that any
//! rustls / quinn / dependency bump would shift.
//!
//! ## Why no full JA3-string pin
//!
//! Rustls 0.23 deliberately randomizes the ClientHello extension order
//! per connection (a fresh `extension_order_seed` from the provider's
//! `secure_random`). This is itself an anti-fingerprinting measure:
//! every connection presents a slightly different JA3 to a passive
//! observer, defeating naive JA3-list-based middlebox classifiers.
//!
//! The cohort signal we *can* pin (and therefore must, to catch drift)
//! is the set of fields rustls emits *deterministically* given a fixed
//! `ClientConfig`:
//!   * legacy_version field
//!   * cipher_suites list (order + content; SCSV included)
//!   * supported_groups list (order + content)
//!   * ec_point_formats list (order + content)
//!   * the **set** of extensions advertised (sorted to canonicalize
//!     across the per-connection permutation)
//!
//! A change to any of those is a real cohort drift; a change to the
//! transient extension *order* is the by-design rustls behaviour and
//! is not pinned.
//!
//! ## CI contract
//!
//! `.github/workflows/ja3-drift.yml` runs `cargo test -p pb-network
//! --test cohort` nightly. A green run is the only signal that the
//! cohort has not split. Per Module 24.2 edge case ("CI runs a
//! retry-with-backoff but never auto-marks pass on retry failure —
//! only a green probe is green"), the assertions below are strict
//! equality and infrastructure flap retries do not mask a real drift.

use pb_network::{ChainValidator, LOCKED_CIPHER_SUITES, LOCKED_KX_GROUPS};
use pb_testkit::fixture::{Ja3, Ja3Probe};

/// Pinned cipher_suites list as rustls 0.23.39 + ring + tls12 emits
/// it: the nine `LOCKED_CIPHER_SUITES` in order, then `0x00FF`
/// (`TLS_EMPTY_RENEGOTIATION_INFO_SCSV`, RFC 5746 secure-renegotiation
/// signal).
///
/// Decoded:
///   * `0x1301`/`0x1302`/`0x1303` = TLS 1.3 trio
///   * `0xC02B`/`0xCCA9`/`0xC02C` = TLS 1.2 ECDHE_ECDSA trio
///   * `0xC02F`/`0xCCA8`/`0xC030` = TLS 1.2 ECDHE_RSA trio
///   * `0x00FF` = SCSV
const PINNED_CIPHER_SUITES: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xC02B, 0xCCA9, 0xC02C, 0xC02F, 0xCCA8, 0xC030, 0x00FF,
];

/// Pinned supported_groups list — `LOCKED_KX_GROUPS` in order.
/// `0x001D` = X25519, `0x0017` = SECP256R1, `0x0018` = SECP384R1.
const PINNED_SUPPORTED_GROUPS: &[u16] = &[0x001D, 0x0017, 0x0018];

/// Pinned ec_point_formats list. `0x00` = uncompressed (the only
/// format any modern browser advertises).
const PINNED_EC_POINT_FORMATS: &[u8] = &[0x00];

/// Pinned **sorted** extension set. Rustls 0.23.39 + our pin emits
/// these ten extensions per ClientHello (order randomized per
/// connection):
///   * 0   = server_name
///   * 5   = status_request
///   * 10  = supported_groups
///   * 11  = ec_point_formats
///   * 13  = signature_algorithms
///   * 23  = extended_master_secret
///   * 35  = session_ticket
///   * 43  = supported_versions
///   * 45  = psk_key_exchange_modes
///   * 51  = key_share
///
/// Drift cases that flip this constant:
///   * rustls bump adds a new extension (e.g. `compress_certificate`,
///     `application_settings`) — sorted set grows.
///   * rustls bump removes one — sorted set shrinks.
///   * Workspace feature flag enables a new extension surface (e.g.
///     `prefer-post-quantum` would add MLKEM key_share groups).
///   * Module 24.1 starts using a new ECH / HSTS / etc. flag that
///     causes rustls to advertise an extension we did not before.
const PINNED_EXTENSIONS_SORTED: &[u16] = &[0, 5, 10, 11, 13, 23, 35, 43, 45, 51];

const PINNED_LEGACY_VERSION: u16 = 0x0303;

fn capture() -> Ja3 {
    let validator = ChainValidator::default();
    let config = validator.build_client_config();
    let bytes = Ja3Probe::capture_client_hello(config, "example.com")
        .expect("Ja3Probe must capture rustls ClientHello bytes");
    Ja3::from_client_hello(&bytes).expect("captured bytes must parse as ClientHello")
}

#[test]
fn legacy_version_pinned() {
    // RFC 8446 §4.1.2: legacy_version is always 0x0303 (TLS 1.2 wire).
    // TLS 1.3 negotiates via the supported_versions extension.
    let ja3 = capture();
    assert_eq!(ja3.legacy_version, PINNED_LEGACY_VERSION);
}

#[test]
fn cipher_suites_pinned() {
    let ja3 = capture();
    assert_eq!(
        ja3.cipher_suites, PINNED_CIPHER_SUITES,
        "cipher_suites drift",
    );
    // Cross-check the pin-side count: PINNED_CIPHER_SUITES is exactly
    // LOCKED_CIPHER_SUITES + SCSV.
    assert_eq!(PINNED_CIPHER_SUITES.len(), LOCKED_CIPHER_SUITES.len() + 1);
}

#[test]
fn supported_groups_pinned() {
    let ja3 = capture();
    assert_eq!(
        ja3.supported_groups, PINNED_SUPPORTED_GROUPS,
        "supported_groups drift",
    );
    // Cross-check: matches LOCKED_KX_GROUPS length.
    assert_eq!(PINNED_SUPPORTED_GROUPS.len(), LOCKED_KX_GROUPS.len());
}

#[test]
fn ec_point_formats_pinned() {
    let ja3 = capture();
    assert_eq!(
        ja3.ec_point_formats, PINNED_EC_POINT_FORMATS,
        "ec_point_formats drift",
    );
}

#[test]
fn extensions_sorted_set_pinned() {
    // Rustls randomizes extension *order* per connection but the set
    // is deterministic. Sorting collapses the per-connection
    // permutation so a real drift (set growth / shrink) trips here
    // while the by-design permutation does not.
    let ja3 = capture();
    let mut sorted = ja3.extensions.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, PINNED_EXTENSIONS_SORTED, "extensions set drifted",);
}

#[test]
fn extension_count_is_stable_across_captures() {
    // Pin determinism of the *count* across two successive captures.
    // A regression where the count flapped run-to-run would mean the
    // pin took a dependency on time / connection-context that escapes
    // the cohort lock.
    let a = capture();
    let b = capture();
    assert_eq!(a.extensions.len(), b.extensions.len());
    assert_eq!(a.cipher_suites, b.cipher_suites);
    assert_eq!(a.supported_groups, b.supported_groups);
    assert_eq!(a.ec_point_formats, b.ec_point_formats);
    assert_eq!(a.legacy_version, b.legacy_version);
}

#[test]
fn first_supported_group_is_x25519() {
    // X25519 first matches the Chrome / Firefox dominant cohort. The
    // single most cohort-impactful kx-group choice — pinning the head
    // of the supported_groups list explicitly catches a future
    // refactor that reorders LOCKED_KX_GROUPS.
    let ja3 = capture();
    assert_eq!(
        ja3.supported_groups.first().copied(),
        Some(0x001D),
        "first supported_group must be X25519 (0x001D)",
    );
}

#[test]
fn first_cipher_suite_is_tls13_aes_128_gcm() {
    // The first advertised suite dominates the per-suite contribution
    // in the captured ClientHello shape. Cross-cohort comparability
    // depends on the head-of-list match; pin it explicitly.
    let ja3 = capture();
    assert_eq!(ja3.cipher_suites.first().copied(), Some(0x1301));
}
