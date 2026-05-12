//! Network broker error type, Module 19.
//!
//! Architecture invariants:
//!   * L27 forensic redaction — every `Display` string is opaque. Hostnames,
//!     paths, query strings, partition-key bytes, and any other identifying
//!     material never reach Display. Detail flows through
//!     [`std::error::Error::source`] only and consumers in the trusted
//!     broker process MUST respect L27 before logging the source chain.
//!   * L30 HTTPS-Only — the [`NetworkError::HttpsOnlyDowngrade`] variant
//!     is the hard rejection when an `http://` URL reaches the dispatch
//!     path without an explicit user-confirmation downgrade approval.
//!   * §5.2 partition-key gatekeeping — [`NetworkError::PartitionMismatch`]
//!     is the §5.2-equivalent rejection on the network side; mirrors
//!     `pb_storage::gatekeeper::GatekeeperError::KeyMismatch`.
//!
//! Reserved sub-system variants (`Resolve`, `Tls`, `Blocked`, `Cancelled`)
//! exist in v1 so call sites in Modules 20-25 do not need to re-define
//! error shapes when they wire in. v1 returns only `PartitionMismatch`,
//! `HttpsOnlyDowngrade`, `Sandbox`, `Ipc`, `Config`, and `Cancelled`.
//
// TODO(Module 80): orchestrator-side log subscriber must walk the
//   `Error::source()` chain and apply L27 redaction before any disk
//   or wire egress. The opacity guarantee here only covers `Display`.

use pb_ipc::IpcError;
use pb_sandbox::SandboxError;
use thiserror::Error;

/// Errors raised by the network broker (Module 19) and its sub-systems.
///
/// Display contract: every variant produces a fixed, non-parametric
/// string. No host, no path, no key bytes, no PII reaches Display.
///
/// ## Clone semantics
///
/// `NetworkError` is `Clone`. **Cloning collapses any wrapped source**
/// (`Ipc(_)` and `Sandbox(_)`) onto the generic [`NetworkError::Resolve`]
/// shape because the underlying error types (`std::io::Error`,
/// `pb_ipc::IpcError`'s `Io` arm) are not `Clone`. This is the
/// pragmatic shape the in-process cache and single-flight wrapper both
/// need. Source chains are tracing-only per L27, so dropping them on
/// clone is consistent with the L27 contract; if you need the source,
/// do not clone — call `Error::source()` on the original instance.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// §5.2 mirror: declared partition key did not match the key derived
    /// from the (origin, profile, context) triple supplied by the
    /// originating tab's identity context. Terminal — the caller must
    /// construct a fresh request with the correct triple.
    #[error("network request rejected: partition key mismatch")]
    PartitionMismatch,

    /// L30: an `http://` URL reached the dispatch path without an
    /// explicit per-host downgrade approval (recorded by the user-
    /// confirmation modal in pb-ui). The coordinator never silently
    /// downgrades; this variant is the hard error.
    #[error("network request rejected: https-only downgrade not approved")]
    HttpsOnlyDowngrade,

    /// IPC framing / connection error from pb-ipc. The wrapped
    /// [`IpcError`] is reachable via `source()` for in-process tracing.
    #[error("network ipc error")]
    Ipc(#[source] IpcError),

    /// Sandbox profile application failed at bootstrap. Wrapped error
    /// reachable via `source()`.
    #[error("network sandbox error")]
    Sandbox(#[source] SandboxError),

    /// Bootstrap or runtime configuration violated an invariant
    /// (e.g. coordinator received a non-Network sandbox class). Carries
    /// only an opaque label, never the offending value.
    #[error("network configuration error")]
    Config,

    /// URL parse rejected the target (malformed or scheme not in the
    /// HTTPS / HTTP set). The original URL is never echoed back.
    #[error("network request rejected: invalid url")]
    InvalidUrl,

    /// Outstanding request was cancelled by the lifecycle layer (tab
    /// close mid-flight). Reserved for the cancellation-safe path.
    #[error("network request cancelled")]
    Cancelled,

    /// Reserved for Module 21: blocklist match. v1 never produces this.
    #[error("network request blocked")]
    Blocked,

    /// Generic resolve failure (Module 20). Reserved for shapes that
    /// do not fit the more specific variants below; cache wrappers use
    /// it as the collapse target when squashing source-bearing errors.
    #[error("dns resolution failed")]
    Resolve,

    /// Module 20: upstream returned NXDOMAIN. Cached at most
    /// [`crate::dns::resolver::MAX_NEGATIVE_TTL`] seconds.
    #[error("dns resolution: nxdomain")]
    ResolveNxDomain,

    /// Module 20: upstream returned a malformed DNS message (parse
    /// failed or fields rejected by the wire decoder).
    #[error("dns resolution: protocol error")]
    ResolveProtocol,

    /// Module 20: resolution timed out before the upstream answered.
    #[error("dns resolution: timeout")]
    ResolveTimeout,

    /// Module 20: HTTPS transport error reaching the DoH endpoint
    /// (TCP / TLS / HTTP). Sub-errors are intentionally not wrapped
    /// so the type stays cheaply cloneable in the cache.
    #[error("dns resolution: transport error")]
    ResolveTransport,

    /// Module 20: SPKI cert pin verification failed at handshake.
    /// Reserved for Module 23.1 enforcement; never produced by v1.
    #[error("dns resolution: cert pin mismatch")]
    ResolveCertPin,

    /// Module 20: DoH outage and the per-mode fallback policy
    /// (L21) refused to fall back. Strict mode produces this on
    /// any upstream failure.
    #[error("dns resolution: outage with no permitted fallback")]
    ResolveOutage,

    /// Module 20: response contained a private / loopback / link-local
    /// address that the rebinding filter rejected (defense in depth).
    #[error("dns resolution: rebinding-filtered response")]
    ResolveRebinding,

    /// Reserved for Module 23: TLS handshake / chain validation failure.
    /// v1 never produces this.
    #[error("tls handshake failed")]
    Tls,

    /// Module 23.2: Certificate Transparency policy rejected the
    /// chain. Only produced when [`crate::tls::CtPolicy::HardFail`] +
    /// a [`crate::tls::CtVerificationOutcome::Failed`] outcome
    /// combine into [`crate::tls::CtDecision::Block`]. Display is
    /// opaque; the [`crate::tls::CtFailureKind`] discriminant is
    /// reachable through the source chain only.
    #[error("tls handshake rejected: certificate transparency policy")]
    TlsCtFailed,

    /// Module 23.3: Encrypted Client Hello policy rejected the
    /// handshake. Only produced when
    /// [`crate::tls::EchPolicy::Mandatory`] (Strict) + a
    /// [`crate::tls::EchVerificationOutcome::Failed`] outcome
    /// combine into [`crate::tls::EchDecision::Block`] (i.e. the
    /// server *did* offer an ECH config but the attempt failed
    /// for any reason other than `ech_required` retry). Display
    /// is opaque; the [`crate::tls::EchFailureKind`] discriminant
    /// is reachable through the source chain only.
    #[error("tls handshake rejected: encrypted client hello policy")]
    TlsEchFailed,
}

impl From<IpcError> for NetworkError {
    fn from(e: IpcError) -> Self {
        Self::Ipc(e)
    }
}

impl From<SandboxError> for NetworkError {
    fn from(e: SandboxError) -> Self {
        Self::Sandbox(e)
    }
}

impl Clone for NetworkError {
    fn clone(&self) -> Self {
        match self {
            Self::PartitionMismatch => Self::PartitionMismatch,
            Self::HttpsOnlyDowngrade => Self::HttpsOnlyDowngrade,
            Self::Config => Self::Config,
            Self::InvalidUrl => Self::InvalidUrl,
            Self::Cancelled => Self::Cancelled,
            Self::Blocked => Self::Blocked,
            Self::Resolve => Self::Resolve,
            Self::ResolveNxDomain => Self::ResolveNxDomain,
            Self::ResolveProtocol => Self::ResolveProtocol,
            Self::ResolveTimeout => Self::ResolveTimeout,
            Self::ResolveTransport => Self::ResolveTransport,
            Self::ResolveCertPin => Self::ResolveCertPin,
            Self::ResolveOutage => Self::ResolveOutage,
            Self::ResolveRebinding => Self::ResolveRebinding,
            Self::Tls => Self::Tls,
            Self::TlsCtFailed => Self::TlsCtFailed,
            Self::TlsEchFailed => Self::TlsEchFailed,
            // Source-bearing variants collapse to `Resolve`. This is
            // the documented Clone behaviour (see crate-level doc on
            // NetworkError); call sites that need source chains must
            // not clone.
            Self::Ipc(_) => Self::Resolve,
            Self::Sandbox(_) => Self::Resolve,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[test]
    fn display_is_opaque_for_partition_mismatch() {
        let err = NetworkError::PartitionMismatch;
        let msg = format!("{err}");
        // Static string: no formatting placeholders, no inputs.
        assert_eq!(msg, "network request rejected: partition key mismatch");
    }

    #[test]
    fn display_is_opaque_for_https_only_downgrade() {
        let err = NetworkError::HttpsOnlyDowngrade;
        let msg = format!("{err}");
        assert!(!msg.contains("http://"), "Display must not echo schemes");
        assert!(!msg.contains("https://"), "Display must not echo schemes");
    }

    #[test]
    fn display_is_opaque_for_invalid_url() {
        // L27: even for malformed-input rejection, the Display must not
        // include the offending input. The variant is fieldless so this
        // is enforced by construction; the test pins the contract.
        let err = NetworkError::InvalidUrl;
        let msg = format!("{err}");
        assert_eq!(msg, "network request rejected: invalid url");
    }

    #[test]
    fn display_does_not_leak_inner_io_text() {
        // Ipc Display is a fixed label; the underlying `IpcError` is
        // reachable only via `source()`. A subscriber that walks the
        // source chain is responsible for redacting per L27.
        let inner = IpcError::ConnectionClosed;
        let err = NetworkError::Ipc(inner);
        let msg = format!("{err}");
        assert_eq!(msg, "network ipc error");
        // Confirm the inner is reachable for trusted tracing.
        let src = err.source().expect("Ipc must expose source");
        let _ = src.to_string();
    }

    #[test]
    fn from_ipc_error_wraps_unchanged() {
        let e: NetworkError = IpcError::ConnectionClosed.into();
        match e {
            NetworkError::Ipc(IpcError::ConnectionClosed) => {}
            other => panic!("expected NetworkError::Ipc(ConnectionClosed), got {other:?}"),
        }
    }

    #[test]
    fn from_sandbox_error_wraps_unchanged() {
        let e: NetworkError = SandboxError::Unsupported.into();
        match e {
            NetworkError::Sandbox(SandboxError::Unsupported) => {}
            other => panic!("expected NetworkError::Sandbox(Unsupported), got {other:?}"),
        }
    }

    #[test]
    fn reserved_variants_render_static_strings() {
        // Reserved variants must already produce L27-clean Display so
        // that when Modules 20-25 start producing them, no wire / disk
        // egress accidentally includes resolver names, hostnames, etc.
        assert_eq!(
            format!("{}", NetworkError::Resolve),
            "dns resolution failed"
        );
        assert_eq!(format!("{}", NetworkError::Tls), "tls handshake failed");
        assert_eq!(
            format!("{}", NetworkError::TlsCtFailed),
            "tls handshake rejected: certificate transparency policy"
        );
        assert_eq!(
            format!("{}", NetworkError::TlsEchFailed),
            "tls handshake rejected: encrypted client hello policy"
        );
        assert_eq!(
            format!("{}", NetworkError::Blocked),
            "network request blocked"
        );
        assert_eq!(
            format!("{}", NetworkError::Cancelled),
            "network request cancelled"
        );
    }

    #[test]
    fn dns_variants_display_is_opaque() {
        // Module 20 introduces several DNS-shaped variants. None of them
        // may echo qname / endpoint URL / record bytes via Display.
        for (e, expected) in [
            (NetworkError::ResolveNxDomain, "dns resolution: nxdomain"),
            (
                NetworkError::ResolveProtocol,
                "dns resolution: protocol error",
            ),
            (NetworkError::ResolveTimeout, "dns resolution: timeout"),
            (
                NetworkError::ResolveTransport,
                "dns resolution: transport error",
            ),
            (
                NetworkError::ResolveCertPin,
                "dns resolution: cert pin mismatch",
            ),
            (
                NetworkError::ResolveOutage,
                "dns resolution: outage with no permitted fallback",
            ),
            (
                NetworkError::ResolveRebinding,
                "dns resolution: rebinding-filtered response",
            ),
        ] {
            let s = format!("{e}");
            assert_eq!(s, expected);
            assert!(!s.contains("example"));
            assert!(!s.contains("https://"));
        }
    }
}
