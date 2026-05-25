//! Module 41 (data + verifier) — signed extension allowlist + install gate.
//!
//! This module owns:
//!   * the on-disk wire format ([`AllowlistManifestFile`] / JSON)
//!   * the typed in-memory shape ([`AllowlistManifest`] +
//!     [`AllowlistEntry`])
//!   * the install-time verification gate ([`verify_install`]) that
//!     enforces all four subtask-2 checks: id-on-allowlist,
//!     version-satisfies-constraint, xpi-hash-matches,
//!     signature-validates.
//!   * the [`SignatureVerifier`] trait the production / test
//!     implementations satisfy (real Ed25519 wiring lands with
//!     Module 65 or Module 87 per the Module 21
//!     `SignedManifestLoader` precedent).
//!
//! [`controller`](crate::controller) owns the lifecycle state
//! machine (atomic manifest swap, install / update / remove
//! decisions) on top of this module's pure functions.
//!
//! ## Wire format
//!
//! Two on-disk artifacts per allowlist version:
//!
//!   * `allowlist.v1.json` — UTF-8 JSON body, schema below.
//!   * `allowlist.v1.json.sig` — 64-byte raw Ed25519 signature
//!     over the **literal bytes** of the JSON file (NOT over a
//!     re-serialized parse). This sidesteps JSON canonicalization
//!     entirely: verify reads the same bytes, computes the same
//!     signature input.
//!
//! ```json
//! {
//!   "format_version": 1,
//!   "manifest_version": 42,
//!   "entries": [
//!     {
//!       "extension_id": "uBlock0@raymondhill.net",
//!       "version_constraint": ">=1.50.0",
//!       "sha256_of_xpi": "a1b2c3..." (hex, 64 chars),
//!       "signing_pubkey": "BASE64..." (32 raw Ed25519 bytes, b64)
//!     }
//!   ]
//! }
//! ```
//!
//! ## Architecture references
//!   * **§3.2** — Standard mode: curated, signed allowlist; no AMO;
//!     no manual .xpi side-load; no webRequest.
//!   * **L7 / L22** — audited primitives only (Ed25519 sig + SHA-256
//!     content hash). No homemade crypto.
//!   * **L24** — versioned vault / on-wire formats: `format_version`
//!     gates incompatible changes; the parser rejects unknown
//!     `format_version` rather than guessing.
//!   * **L27** — forensic redaction: `Display` for every error type
//!     is opaque; details flow only through `Error::source()`.
//!
//! ## Delegation
//!   * Module 40 owns the Strict darks. The
//!     `extensions_blocked_in_strict_regardless_of_allowlist` test
//!     here pins the boundary: a Strict-mode caller MUST consult
//!     `blocker::block_for_mode(Strict) == AllBlocked` and NEVER
//!     reach `verify_install`.
//!   * Module 65 (Phase 9, pending) delivers the signed manifest
//!     bytes; this module accepts bytes-in via
//!     [`parse_allowlist_manifest`] and is otherwise unaware of
//!     delivery.
//!   * Module 11 warnings are emitted by the controller layer
//!     (and ultimately the Phase 11 orchestrator) per L12 — this
//!     module returns typed errors.
//
// TODO(Module 65 update pipeline, Phase 9): replace the
//   [`SignatureVerifier`] trait's production stub
//   [`RejectAllVerifier`] with a real Ed25519 verifier wired to
//   `ed25519-dalek` (workspace dep lands alongside the first real
//   consumer — either Module 65 or Module 87 LAN pairing). The
//   trait surface stays stable; only the impl swaps.
// TODO(Module 87 LAN pairing, Phase 11.5): if Module 87 lands
//   before Module 65, the ed25519-dalek dep lands with Module 87
//   and this module's verifier can swap then.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Wire-format version (L24) ────────────────────────────────────────────

/// Current allowlist manifest wire format version.
///
/// Bumping this is an on-wire-incompatible change per L24. Any
/// parsed manifest whose `format_version` does not match is
/// rejected with [`AllowlistParseError::UnsupportedFormatVersion`];
/// the controller's atomic-swap path treats that as "keep the
/// previous manifest live" rather than auto-disabling installed
/// extensions on a format-rev rollout race.
pub const ALLOWLIST_FORMAT_VERSION: u32 = 1;

// ── Strong identifiers (zero-cost newtypes) ──────────────────────────────

/// Extension id as it appears in a WebExtension manifest (e.g.
/// `uBlock0@raymondhill.net` for an MV2-style id, or the lowercased
/// `{uuid}` form for an MV3 id). Treated as opaque by this module:
/// equality is exact-string, no normalization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtensionId(pub String);

impl ExtensionId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SemVer-ish version as it appears in a WebExtension manifest's
/// `version` field (Mozilla allows `MAJOR.MINOR.PATCH` + optional
/// 4th component, all u32). Parser is intentionally narrow — only
/// the shapes Module 41 actually constrains against.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse(s: &str) -> Result<Self, VersionParseError> {
        let parts: Vec<&str> = s.split('.').collect();
        // Mozilla allows 1-4 components; we accept 1-3 and pad with 0.
        if parts.is_empty() || parts.len() > 3 {
            return Err(VersionParseError);
        }
        let parse_u32 = |p: &&str| p.parse::<u32>().map_err(|_| VersionParseError);
        let major = parse_u32(&parts[0])?;
        let minor = if parts.len() > 1 {
            parse_u32(&parts[1])?
        } else {
            0
        };
        let patch = if parts.len() > 2 {
            parse_u32(&parts[2])?
        } else {
            0
        };
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl TryFrom<String> for Version {
    type Error = VersionParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<Version> for String {
    fn from(v: Version) -> String {
        v.to_string()
    }
}

/// Opaque (L27) parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid version")]
pub struct VersionParseError;

/// Version constraint syntax (DevBrowse-narrow per locked decision):
///   * `=X.Y.Z`  — exact pin
///   * `>=X.Y.Z` — floor
///
/// No semver-range deps; no caret / tilde / wildcard. If a known-bad
/// version needs to be excluded, publish a new manifest that floors
/// above the bad version. The smaller surface keeps the wire
/// schema unambiguous and the parser auditable in one screen.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum VersionConstraint {
    Exact(Version),
    AtLeast(Version),
}

impl VersionConstraint {
    pub fn parse(s: &str) -> Result<Self, VersionConstraintParseError> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix(">=") {
            let v = Version::parse(rest.trim()).map_err(|_| VersionConstraintParseError)?;
            Ok(Self::AtLeast(v))
        } else if let Some(rest) = s.strip_prefix('=') {
            let v = Version::parse(rest.trim()).map_err(|_| VersionConstraintParseError)?;
            Ok(Self::Exact(v))
        } else {
            Err(VersionConstraintParseError)
        }
    }

    pub fn satisfies(&self, v: &Version) -> bool {
        match self {
            Self::Exact(want) => v == want,
            Self::AtLeast(floor) => v >= floor,
        }
    }
}

impl std::fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact(v) => write!(f, "={v}"),
            Self::AtLeast(v) => write!(f, ">={v}"),
        }
    }
}

impl TryFrom<String> for VersionConstraint {
    type Error = VersionConstraintParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<VersionConstraint> for String {
    fn from(c: VersionConstraint) -> String {
        c.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid version constraint")]
pub struct VersionConstraintParseError;

// ── Hashes + keys + signatures (raw bytes, opaque wire encoding) ─────────

/// Raw SHA-256 of the full `.xpi` bytes (Mozilla's signing artifact
/// is the entire ZIP). Wire form is lowercase hex (64 chars).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash(pub [u8; 32]);

impl Sha256Hash {
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self(h.finalize().into())
    }

    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn from_hex(s: &str) -> Result<Self, HexParseError> {
        if s.len() != 64 {
            return Err(HexParseError);
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn hex_nibble(b: u8) -> Result<u8, HexParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexParseError),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid hex")]
pub struct HexParseError;

impl Serialize for Sha256Hash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Hash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Raw 32-byte Ed25519 verifying key (per RFC 8032 §5.1.2). Wire
/// form is unpadded URL-safe base64 to keep the manifest copy-
/// pasteable, but a small in-house base64 codec is used so we
/// don't need a workspace base64 dep just for the allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PubKeyBytes(pub [u8; 32]);

/// Raw 64-byte Ed25519 signature (per RFC 8032 §5.1.6). Detached;
/// covers the literal on-disk bytes of the manifest file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519SigBytes(pub [u8; 64]);

impl Serialize for Ed25519PubKeyBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Ed25519PubKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s: String = String::deserialize(d)?;
        let v = b64_decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = v.try_into().map_err(|_| {
            serde::de::Error::custom("ed25519 verifying key must decode to 32 bytes")
        })?;
        Ok(Self(arr))
    }
}

/// Minimal base64 encoder (unpadded, URL-safe alphabet — RFC 4648
/// §5). No dep needed; 30 lines of code, audit-trivial.
fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        }
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    fn val(c: u8) -> Result<u32, &'static str> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err("invalid base64 character"),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &b in chunk {
            n = (n << 6) | val(b)?;
            bits += 6;
        }
        let pad = 4 - chunk.len();
        n <<= 6 * pad;
        bits -= 2 * pad;
        let take = bits / 8;
        if take >= 1 {
            out.push(((n >> 16) & 0xFF) as u8);
        }
        if take >= 2 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if take >= 3 {
            out.push((n & 0xFF) as u8);
        }
    }
    Ok(out)
}

// ── Allowlist entry + manifest ───────────────────────────────────────────

/// One blessed extension in the curated allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    pub extension_id: ExtensionId,
    pub version_constraint: VersionConstraint,
    pub sha256_of_xpi: Sha256Hash,
    pub signing_pubkey: Ed25519PubKeyBytes,
}

/// In-memory shape of a parsed signed allowlist manifest. Held by
/// the controller behind `RwLock<Arc<AllowlistManifest>>` so install
/// gating reads a stable snapshot while manifest updates swap
/// atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistManifest {
    /// L24 wire-format version. Mismatch is a parser-level reject.
    pub format_version: u32,
    /// Monotonic counter incremented on every published revision.
    /// The controller refuses a manifest swap whose
    /// `manifest_version` is not strictly greater than the live
    /// manifest's (prevents accidental rollback to a recalled
    /// version).
    pub manifest_version: u64,
    pub entries: Vec<AllowlistEntry>,
}

impl AllowlistManifest {
    /// O(1)-amortized lookup by id. The manifest is small (tens of
    /// entries); a linear scan would be fine, but explicit lookup
    /// keeps install-path complexity bounded as the allowlist grows.
    pub fn entry_for(&self, id: &ExtensionId) -> Option<&AllowlistEntry> {
        self.entries.iter().find(|e| &e.extension_id == id)
    }
}

/// Parser-level errors. L27: every `Display` is opaque.
#[derive(Debug, thiserror::Error)]
pub enum AllowlistParseError {
    #[error("allowlist: invalid json")]
    InvalidJson,
    #[error("allowlist: unsupported format_version")]
    UnsupportedFormatVersion,
    #[error("allowlist: duplicate extension id")]
    DuplicateExtensionId,
}

/// Parse the JSON bytes of an allowlist manifest. Rejects unknown
/// `format_version` (L24) and duplicate ids (data-model invariant).
/// Does NOT verify the detached signature — call
/// [`verify_manifest_signature`] separately on the same byte slice.
pub fn parse_allowlist_manifest(bytes: &[u8]) -> Result<AllowlistManifest, AllowlistParseError> {
    let manifest: AllowlistManifest =
        serde_json::from_slice(bytes).map_err(|_| AllowlistParseError::InvalidJson)?;
    if manifest.format_version != ALLOWLIST_FORMAT_VERSION {
        return Err(AllowlistParseError::UnsupportedFormatVersion);
    }
    // Reject duplicate ids before the controller ever sees the
    // manifest. Two entries for the same id would mean the
    // install-time `entry_for` lookup returns one arbitrarily,
    // and only one signing key would be honored.
    let mut seen = std::collections::HashSet::with_capacity(manifest.entries.len());
    for e in &manifest.entries {
        if !seen.insert(&e.extension_id) {
            return Err(AllowlistParseError::DuplicateExtensionId);
        }
    }
    Ok(manifest)
}

// ── SignatureVerifier trait (Module 21 SignedManifestLoader precedent) ───

/// Signature verification surface. Production wiring deferred to
/// Module 65 (Phase 9) or Module 87 (Phase 11.5) — whichever lands
/// first introduces `ed25519-dalek` and a real verifier.
///
/// Tests use [`InMemoryTrustedVerifier`] to configure exactly which
/// `(pubkey, msg, sig)` triples succeed; production gets
/// [`RejectAllVerifier`] until the orchestrator wires the real impl.
pub trait SignatureVerifier: Send + Sync + std::fmt::Debug {
    fn verify_ed25519(
        &self,
        pubkey: &Ed25519PubKeyBytes,
        msg: &[u8],
        sig: &Ed25519SigBytes,
    ) -> Result<(), SignatureVerifyError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureVerifyError {
    /// Production stub — `RejectAllVerifier` returns this until
    /// Module 65 / 87 wires the real impl. The controller treats
    /// this the same as a real signature mismatch: install
    /// rejected, manifest swap rejected.
    #[error("allowlist verifier: module 65 / 87 not ready")]
    ModuleNotReady,
    #[error("allowlist verifier: signature mismatch")]
    Mismatch,
}

/// Production stub. Refuses every signature check until Module 65
/// (or Module 87) wires the real `ed25519-dalek` verifier via the
/// orchestrator at boot. Mirrors Module 21's
/// `SignedManifestLoader::ModuleNotReady` posture exactly.
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectAllVerifier;

impl SignatureVerifier for RejectAllVerifier {
    fn verify_ed25519(
        &self,
        _pubkey: &Ed25519PubKeyBytes,
        _msg: &[u8],
        _sig: &Ed25519SigBytes,
    ) -> Result<(), SignatureVerifyError> {
        Err(SignatureVerifyError::ModuleNotReady)
    }
}

/// Test verifier: a map of pre-trusted `(pubkey, msg, sig)` triples.
/// Any unrecognized triple is rejected with `Mismatch`. Constructed
/// via [`InMemoryTrustedVerifier::trust`].
#[derive(Debug, Default, Clone)]
pub struct InMemoryTrustedVerifier {
    trusted: Vec<(Ed25519PubKeyBytes, Vec<u8>, Ed25519SigBytes)>,
}

impl InMemoryTrustedVerifier {
    pub fn new() -> Self {
        Self::default()
    }
    /// Pre-trust a `(pubkey, msg, sig)` triple. Subsequent
    /// `verify_ed25519` calls with the same arguments will return
    /// `Ok(())`; any other triple returns `Err(Mismatch)`.
    pub fn trust(
        mut self,
        pubkey: Ed25519PubKeyBytes,
        msg: impl Into<Vec<u8>>,
        sig: Ed25519SigBytes,
    ) -> Self {
        self.trusted.push((pubkey, msg.into(), sig));
        self
    }
}

impl SignatureVerifier for InMemoryTrustedVerifier {
    fn verify_ed25519(
        &self,
        pubkey: &Ed25519PubKeyBytes,
        msg: &[u8],
        sig: &Ed25519SigBytes,
    ) -> Result<(), SignatureVerifyError> {
        if self
            .trusted
            .iter()
            .any(|(p, m, s)| p == pubkey && m.as_slice() == msg && s == sig)
        {
            Ok(())
        } else {
            Err(SignatureVerifyError::Mismatch)
        }
    }
}

/// Verify a detached signature over the literal bytes of an
/// allowlist manifest file. The manifest-update root key is
/// orchestrator-provided (Module 65 / 87 ownership); this module
/// stays agnostic about key provisioning.
pub fn verify_manifest_signature(
    verifier: &dyn SignatureVerifier,
    root_pubkey: &Ed25519PubKeyBytes,
    manifest_bytes: &[u8],
    sig: &Ed25519SigBytes,
) -> Result<(), SignatureVerifyError> {
    verifier.verify_ed25519(root_pubkey, manifest_bytes, sig)
}

// ── Install-time verification gate (subtask 2) ───────────────────────────

/// Everything Module 41 needs to gate an `.xpi` install candidate
/// against the active allowlist. The caller (controller / install
/// UI / Module 64 wizard) constructs this from the candidate file
/// plus the manifest version the extension self-reports.
#[derive(Debug, Clone)]
pub struct InstallCandidate<'a> {
    pub extension_id: ExtensionId,
    pub version: Version,
    /// Raw `.xpi` ZIP bytes. Hashed by [`verify_install`].
    pub xpi_bytes: &'a [u8],
    /// The detached signature shipped alongside the `.xpi`
    /// (Mozilla's signing pipeline emits this; for DevBrowse's
    /// curated allowlist, the publisher signs the `.xpi` SHA-256
    /// digest with the entry's `signing_pubkey`).
    pub xpi_signature: Ed25519SigBytes,
}

/// Why an install candidate was rejected. The four variants
/// correspond 1:1 to the phase-file subtask-2 gates (a)-(d). Each
/// variant carries the structured context the controller needs to
/// emit the right Module 11 warning (via the [`crate::controller`]
/// layer's WarningIntent translation).
#[derive(Debug, thiserror::Error)]
pub enum InstallVerifyError {
    /// (a) Extension id is not on the active allowlist.
    /// User attempted to side-load an off-allowlist `.xpi`.
    #[error("install: extension id not on allowlist")]
    NotOnAllowlist,
    /// (b) Candidate version does not satisfy the allowlist entry's
    /// `version_constraint`.
    #[error("install: version does not satisfy allowlist constraint")]
    VersionConstraintUnsatisfied,
    /// (c) SHA-256 of candidate `.xpi` bytes does not match the
    /// allowlist entry's `sha256_of_xpi`. Tampered or wrong-file.
    #[error("install: xpi hash mismatch")]
    XpiHashMismatch,
    /// (d) Detached signature does not validate against the
    /// allowlist entry's `signing_pubkey`. Covers both
    /// `SignatureVerifyError::Mismatch` and `ModuleNotReady` (the
    /// production stub treats not-ready as not-trusted).
    #[error("install: signature mismatch")]
    SignatureMismatch,
}

/// Gate an install candidate against the active allowlist. All
/// four phase-file subtask-2 checks must pass:
///   (a) id on allowlist
///   (b) version satisfies constraint
///   (c) `.xpi` SHA-256 matches manifest entry
///   (d) detached signature validates against entry pubkey
///
/// On success returns the matched [`AllowlistEntry`] so the
/// controller can record the install metadata without re-doing the
/// lookup. On failure returns the first-failing check (gates are
/// evaluated in order — id-on-allowlist before version, etc. — so
/// a probing attacker learns the minimum about why their candidate
/// was rejected).
pub fn verify_install<'m>(
    candidate: &InstallCandidate<'_>,
    manifest: &'m AllowlistManifest,
    verifier: &dyn SignatureVerifier,
) -> Result<&'m AllowlistEntry, InstallVerifyError> {
    // (a) id-on-allowlist
    let entry = manifest
        .entry_for(&candidate.extension_id)
        .ok_or(InstallVerifyError::NotOnAllowlist)?;
    // (b) version-satisfies-constraint
    if !entry.version_constraint.satisfies(&candidate.version) {
        return Err(InstallVerifyError::VersionConstraintUnsatisfied);
    }
    // (c) xpi hash
    let actual = Sha256Hash::of(candidate.xpi_bytes);
    if actual != entry.sha256_of_xpi {
        return Err(InstallVerifyError::XpiHashMismatch);
    }
    // (d) signature
    verifier
        .verify_ed25519(
            &entry.signing_pubkey,
            candidate.xpi_bytes,
            &candidate.xpi_signature,
        )
        .map_err(|_| InstallVerifyError::SignatureMismatch)?;
    Ok(entry)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key_a() -> Ed25519PubKeyBytes {
        Ed25519PubKeyBytes([0x11; 32])
    }
    fn key_b() -> Ed25519PubKeyBytes {
        Ed25519PubKeyBytes([0x22; 32])
    }
    fn sig_a() -> Ed25519SigBytes {
        Ed25519SigBytes([0xAA; 64])
    }
    fn sig_b() -> Ed25519SigBytes {
        Ed25519SigBytes([0xBB; 64])
    }

    fn sample_manifest() -> AllowlistManifest {
        let xpi_bytes: &[u8] = b"<<fake xpi bytes for ublock>>";
        AllowlistManifest {
            format_version: ALLOWLIST_FORMAT_VERSION,
            manifest_version: 1,
            entries: vec![AllowlistEntry {
                extension_id: ExtensionId::new("uBlock0@raymondhill.net"),
                version_constraint: VersionConstraint::AtLeast(Version::new(1, 50, 0)),
                sha256_of_xpi: Sha256Hash::of(xpi_bytes),
                signing_pubkey: key_a(),
            }],
        }
    }

    // ── Version + VersionConstraint ──────────────────────────────────────

    #[test]
    fn version_parses_three_components() {
        assert_eq!(Version::parse("1.2.3").unwrap(), Version::new(1, 2, 3));
        assert_eq!(Version::parse("1").unwrap(), Version::new(1, 0, 0));
        assert_eq!(Version::parse("1.2").unwrap(), Version::new(1, 2, 0));
    }

    #[test]
    fn version_rejects_garbage() {
        assert!(Version::parse("").is_err());
        assert!(Version::parse("a.b.c").is_err());
        assert!(Version::parse("1.2.3.4").is_err());
        assert!(Version::parse("1..2").is_err());
    }

    #[test]
    fn version_constraint_exact_pin_satisfies_only_exact() {
        let c = VersionConstraint::parse("=1.2.3").unwrap();
        assert!(c.satisfies(&Version::new(1, 2, 3)));
        assert!(!c.satisfies(&Version::new(1, 2, 4)));
        assert!(!c.satisfies(&Version::new(1, 2, 2)));
    }

    #[test]
    fn version_constraint_at_least_floor() {
        let c = VersionConstraint::parse(">=1.50.0").unwrap();
        assert!(c.satisfies(&Version::new(1, 50, 0)));
        assert!(c.satisfies(&Version::new(1, 50, 1)));
        assert!(c.satisfies(&Version::new(2, 0, 0)));
        assert!(!c.satisfies(&Version::new(1, 49, 99)));
    }

    #[test]
    fn version_constraint_rejects_unsupported_syntax() {
        // No caret, tilde, wildcard, or open-range; DevBrowse-narrow
        // syntax per the locked decision.
        assert!(VersionConstraint::parse("^1.2.3").is_err());
        assert!(VersionConstraint::parse("~1.2").is_err());
        assert!(VersionConstraint::parse("*").is_err());
        assert!(VersionConstraint::parse("<2.0.0").is_err());
        assert!(VersionConstraint::parse(">=1.0.0, <2.0.0").is_err());
        assert!(VersionConstraint::parse("1.2.3").is_err());
    }

    #[test]
    fn version_constraint_roundtrips_through_display() {
        for s in [">=1.50.0", "=1.62.0"] {
            let c = VersionConstraint::parse(s).unwrap();
            assert_eq!(c.to_string(), s);
        }
    }

    // ── Sha256 + Ed25519 wire encoding ───────────────────────────────────

    #[test]
    fn sha256_hex_roundtrip() {
        let h = Sha256Hash::of(b"DevBrowse");
        let s = h.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(Sha256Hash::from_hex(&s).unwrap(), h);
    }

    #[test]
    fn sha256_from_hex_rejects_wrong_length_and_bad_chars() {
        assert!(Sha256Hash::from_hex("").is_err());
        assert!(Sha256Hash::from_hex(&"a".repeat(63)).is_err());
        assert!(Sha256Hash::from_hex(&"a".repeat(65)).is_err());
        let mut bad = "a".repeat(64);
        bad.replace_range(0..1, "z");
        assert!(Sha256Hash::from_hex(&bad).is_err());
    }

    #[test]
    fn b64_roundtrip_for_pubkey() {
        let key = Ed25519PubKeyBytes([0x42; 32]);
        let encoded = b64_encode(&key.0);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(&decoded[..], &key.0[..]);
    }

    // ── Manifest parse ───────────────────────────────────────────────────

    #[test]
    fn parse_round_trips_via_serde() {
        let m = sample_manifest();
        let json = serde_json::to_vec(&m).unwrap();
        let parsed = parse_allowlist_manifest(&json).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn parse_rejects_unknown_format_version() {
        let mut m = sample_manifest();
        m.format_version = 999;
        let json = serde_json::to_vec(&m).unwrap();
        match parse_allowlist_manifest(&json) {
            Err(AllowlistParseError::UnsupportedFormatVersion) => {}
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_invalid_json() {
        match parse_allowlist_manifest(b"not json") {
            Err(AllowlistParseError::InvalidJson) => {}
            other => panic!("expected InvalidJson, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_duplicate_extension_id() {
        let mut m = sample_manifest();
        m.entries.push(m.entries[0].clone());
        let json = serde_json::to_vec(&m).unwrap();
        match parse_allowlist_manifest(&json) {
            Err(AllowlistParseError::DuplicateExtensionId) => {}
            other => panic!("expected DuplicateExtensionId, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_unknown_fields_deny_unknown_fields() {
        // L24 wire-version discipline: unknown fields are a hard
        // reject (not silently dropped) so a future schema can't
        // be partially-parsed and silently mis-interpreted.
        let bad = br#"{"format_version":1,"manifest_version":1,"entries":[],"future_field":"x"}"#;
        match parse_allowlist_manifest(bad) {
            Err(AllowlistParseError::InvalidJson) => {}
            other => panic!("expected InvalidJson (unknown field), got {other:?}"),
        }
    }

    // ── L27 forensic-redaction posture ───────────────────────────────────

    #[test]
    fn error_display_is_opaque_l27() {
        // No URL, profile id, host, signature hex, or key bytes
        // may appear in the Display impl. Detail flows through
        // Error::source() only.
        let displays = [
            format!("{}", AllowlistParseError::InvalidJson),
            format!("{}", AllowlistParseError::UnsupportedFormatVersion),
            format!("{}", AllowlistParseError::DuplicateExtensionId),
            format!("{}", InstallVerifyError::NotOnAllowlist),
            format!("{}", InstallVerifyError::VersionConstraintUnsatisfied),
            format!("{}", InstallVerifyError::XpiHashMismatch),
            format!("{}", InstallVerifyError::SignatureMismatch),
            format!("{}", SignatureVerifyError::ModuleNotReady),
            format!("{}", SignatureVerifyError::Mismatch),
        ];
        for d in &displays {
            assert!(!d.contains("@"), "{d:?} leaks extension id format");
            assert!(!d.contains("uBlock"), "{d:?} leaks specific extension name");
            assert!(!d.contains("0x"), "{d:?} leaks raw bytes");
            assert!(!d.contains("AA"), "{d:?} leaks sig hex");
            assert!(d.is_ascii(), "{d:?} must be plain ascii for log redaction");
        }
    }

    // ── SignatureVerifier ────────────────────────────────────────────────

    #[test]
    fn reject_all_verifier_returns_module_not_ready() {
        let v = RejectAllVerifier;
        let res = v.verify_ed25519(&key_a(), b"any", &sig_a());
        assert!(matches!(res, Err(SignatureVerifyError::ModuleNotReady)));
    }

    #[test]
    fn in_memory_trusted_only_accepts_pre_trusted_triple() {
        let v = InMemoryTrustedVerifier::new().trust(key_a(), b"msg-a".to_vec(), sig_a());
        assert!(v.verify_ed25519(&key_a(), b"msg-a", &sig_a()).is_ok());
        // Wrong key
        assert!(matches!(
            v.verify_ed25519(&key_b(), b"msg-a", &sig_a()),
            Err(SignatureVerifyError::Mismatch)
        ));
        // Wrong msg
        assert!(matches!(
            v.verify_ed25519(&key_a(), b"msg-b", &sig_a()),
            Err(SignatureVerifyError::Mismatch)
        ));
        // Wrong sig
        assert!(matches!(
            v.verify_ed25519(&key_a(), b"msg-a", &sig_b()),
            Err(SignatureVerifyError::Mismatch)
        ));
    }

    // ── verify_install: all 4 gates ──────────────────────────────────────

    fn verifier_trusting(xpi: &[u8]) -> InMemoryTrustedVerifier {
        InMemoryTrustedVerifier::new().trust(key_a(), xpi.to_vec(), sig_a())
    }

    #[test]
    fn verify_install_happy_path() {
        let xpi: &[u8] = b"<<fake xpi bytes for ublock>>";
        let m = sample_manifest();
        let v = verifier_trusting(xpi);
        let c = InstallCandidate {
            extension_id: ExtensionId::new("uBlock0@raymondhill.net"),
            version: Version::new(1, 51, 0),
            xpi_bytes: xpi,
            xpi_signature: sig_a(),
        };
        let entry = verify_install(&c, &m, &v).expect("happy path should pass all four gates");
        assert_eq!(entry.extension_id.as_str(), "uBlock0@raymondhill.net");
    }

    #[test]
    fn verify_install_a_not_on_allowlist() {
        let xpi: &[u8] = b"<<other xpi>>";
        let m = sample_manifest();
        let v = verifier_trusting(xpi);
        let c = InstallCandidate {
            extension_id: ExtensionId::new("malicious@nowhere.test"),
            version: Version::new(1, 0, 0),
            xpi_bytes: xpi,
            xpi_signature: sig_a(),
        };
        assert!(matches!(
            verify_install(&c, &m, &v),
            Err(InstallVerifyError::NotOnAllowlist)
        ));
    }

    #[test]
    fn verify_install_b_version_constraint_unsatisfied() {
        let xpi: &[u8] = b"<<fake xpi bytes for ublock>>";
        let m = sample_manifest();
        let v = verifier_trusting(xpi);
        let c = InstallCandidate {
            extension_id: ExtensionId::new("uBlock0@raymondhill.net"),
            version: Version::new(1, 0, 0), // floor is >=1.50.0
            xpi_bytes: xpi,
            xpi_signature: sig_a(),
        };
        assert!(matches!(
            verify_install(&c, &m, &v),
            Err(InstallVerifyError::VersionConstraintUnsatisfied)
        ));
    }

    #[test]
    fn verify_install_c_xpi_hash_mismatch() {
        let manifest_xpi: &[u8] = b"<<fake xpi bytes for ublock>>";
        let m = sample_manifest();
        let tampered: &[u8] = b"<<TAMPERED bytes>>";
        let v = verifier_trusting(manifest_xpi);
        let c = InstallCandidate {
            extension_id: ExtensionId::new("uBlock0@raymondhill.net"),
            version: Version::new(1, 50, 0),
            xpi_bytes: tampered,
            xpi_signature: sig_a(),
        };
        assert!(matches!(
            verify_install(&c, &m, &v),
            Err(InstallVerifyError::XpiHashMismatch)
        ));
    }

    #[test]
    fn verify_install_d_signature_mismatch() {
        let xpi: &[u8] = b"<<fake xpi bytes for ublock>>";
        let m = sample_manifest();
        let v = verifier_trusting(xpi); // trusts sig_a()
        let c = InstallCandidate {
            extension_id: ExtensionId::new("uBlock0@raymondhill.net"),
            version: Version::new(1, 51, 0),
            xpi_bytes: xpi,
            xpi_signature: sig_b(), // wrong sig
        };
        assert!(matches!(
            verify_install(&c, &m, &v),
            Err(InstallVerifyError::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_install_with_reject_all_verifier_fails_at_signature() {
        // Production stub: every install fails at gate (d) until
        // Module 65 / 87 wires the real verifier. Earlier gates
        // still execute, so (a) (b) (c) failures are returned
        // first — Module 11 warning fidelity is preserved.
        let xpi: &[u8] = b"<<fake xpi bytes for ublock>>";
        let m = sample_manifest();
        let v = RejectAllVerifier;
        let c = InstallCandidate {
            extension_id: ExtensionId::new("uBlock0@raymondhill.net"),
            version: Version::new(1, 51, 0),
            xpi_bytes: xpi,
            xpi_signature: sig_a(),
        };
        assert!(matches!(
            verify_install(&c, &m, &v),
            Err(InstallVerifyError::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_install_gate_order_id_before_version() {
        // A probing attacker who side-loads a wrong-id with a
        // wrong-version learns only "not on allowlist", not
        // "id is on allowlist but version wrong" — minimizes the
        // info disclosed to side-load attempts.
        let xpi: &[u8] = b"<<irrelevant>>";
        let m = sample_manifest();
        let v = verifier_trusting(xpi);
        let c = InstallCandidate {
            extension_id: ExtensionId::new("unknown@nowhere.test"),
            version: Version::new(0, 0, 0), // also fails (b) if (a) somehow passed
            xpi_bytes: xpi,
            xpi_signature: sig_a(),
        };
        assert!(matches!(
            verify_install(&c, &m, &v),
            Err(InstallVerifyError::NotOnAllowlist)
        ));
    }

    // ── Manifest signature surface ───────────────────────────────────────

    #[test]
    fn manifest_signature_verifies_with_matching_triple() {
        let bytes: &[u8] = b"<<canonical manifest bytes>>";
        let v = InMemoryTrustedVerifier::new().trust(key_a(), bytes.to_vec(), sig_a());
        assert!(verify_manifest_signature(&v, &key_a(), bytes, &sig_a()).is_ok());
    }

    #[test]
    fn manifest_signature_rejects_wrong_root_key() {
        let bytes: &[u8] = b"<<canonical manifest bytes>>";
        let v = InMemoryTrustedVerifier::new().trust(key_a(), bytes.to_vec(), sig_a());
        assert!(matches!(
            verify_manifest_signature(&v, &key_b(), bytes, &sig_a()),
            Err(SignatureVerifyError::Mismatch)
        ));
    }
}
