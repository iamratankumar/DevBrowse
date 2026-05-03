//! DoH outage fallback policy, Module 20.
//!
//! Architecture L21:
//!   * Strict mode is **DoH-only**. Any upstream failure surfaces as
//!     [`NetworkError::ResolveOutage`]; the resolver MUST NOT silently
//!     fall back to system DNS.
//!   * Standard mode permits **system DNS only when the user opted in
//!     via the first-launch wizard** (`pb_config::PrivacyConfig` /
//!     wizard-recorded flag). Without that opt-in, Standard fails the
//!     same way Strict does.
//!
//! ## v1 scope
//!
//! v1 ships the policy decision table fully. The actual system-DNS
//! lookup path (`platform.system_dns_servers()` + a UDP/TCP DNS
//! resolver against the OS resolver list) is gated on
//! [`crate::PlatformContext`] gaining a `system_dns_servers()`
//! method, which is currently empty. Module 80 (orchestrator) wires
//! the platform-side resolver in alongside Module 20's DoH client; the
//! follow-up commit replaces the [`FallbackOutcome::SystemDns`] arm's
//! comment-only TODO with a real lookup.
//!
//! ## Why not silently fall back
//!
//! Silent fallback would defeat the L21 anti-fingerprint guarantee —
//! the user's DNS traffic would suddenly appear in the system
//! resolver's cohort instead of the DoH provider's, which is observable
//! to a passive attacker (and to the OS resolver). The wizard opt-in
//! is the user's affirmative choice that this trade-off is acceptable
//! for their threat model.
//
// TODO(PlatformContext): extend `PlatformContext` with a
//   `fn system_dns_servers(&self) -> Result<Vec<IpAddr>, _>` method
//   sourced from `pb_platform::NetworkAdapter`. The orchestrator
//   (which owns both pb-network and pb-platform) provides the impl.
// TODO(Module 80): wire FallbackPolicy into the production resolver
//   stack so Standard-mode outages with wizard opt-in resolve via the
//   system path.

use crate::error::NetworkError;
use crate::Mode;

/// Source of the failed DoH attempt the policy is evaluating.
///
/// `PartialEq` not derived: the [`DohFailureKind::Definitive`] arm
/// carries a [`NetworkError`] which is not `PartialEq`. Match on
/// `DohFailureKind` with `match` / `matches!`.
#[derive(Debug, Clone)]
pub enum DohFailureKind {
    /// Network transport failure (TCP / TLS / HTTP).
    Transport,
    /// Upstream sent a malformed DNS message.
    Protocol,
    /// Resolution did not complete inside the per-query budget.
    Timeout,
    /// Upstream responded with a non-success RCODE that the policy may
    /// still treat as definitive (NXDOMAIN, ServFail). Strict mode
    /// surfaces these unchanged; system DNS would not produce a
    /// different answer.
    Definitive(NetworkError),
}

/// Compiled outage policy snapshot. Constructed from
/// `pb_config::Config` at coordinator bootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackPolicy {
    /// True iff the user opted into system-DNS fallback through the
    /// first-launch wizard. Strict mode ignores this flag (always
    /// fails closed).
    pub system_dns_opt_in: bool,
}

/// What the resolver should do after a failed DoH attempt.
///
/// `PartialEq` is intentionally not derived — `NetworkError` is not
/// `PartialEq` (it carries non-`PartialEq` source-bearing variants).
/// Tests compare `FallbackOutcome` via `matches!`.
#[derive(Debug, Clone)]
pub enum FallbackOutcome {
    /// Surface the original error (definitive failures and DoH-only
    /// modes land here).
    Surface(NetworkError),
    /// Surface [`NetworkError::ResolveOutage`]. Distinct from
    /// `Surface(...)` so the caller can tell "DoH had a transient
    /// problem and no fallback is allowed" apart from "DoH said NX".
    Outage,
    /// Re-attempt resolution against system DNS. v1: caller TODO
    /// (the system-DNS lookup path is gated on PlatformContext
    /// gaining a `system_dns_servers()` method).
    SystemDns,
}

impl FallbackPolicy {
    /// Apply the policy to a [`DohFailureKind`] under `mode`.
    pub fn decide(&self, mode: Mode, failure: DohFailureKind) -> FallbackOutcome {
        // Definitive failures (NXDOMAIN / ServFail) are never overridden
        // by a system-DNS retry; the upstream answer is final.
        if let DohFailureKind::Definitive(e) = failure {
            return FallbackOutcome::Surface(e);
        }
        // Strict mode is DoH-only regardless of any opt-in flag.
        if mode == Mode::Strict {
            return FallbackOutcome::Outage;
        }
        // Standard mode: only the wizard opt-in unlocks system DNS.
        if self.system_dns_opt_in {
            FallbackOutcome::SystemDns
        } else {
            FallbackOutcome::Outage
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_opt_in() -> FallbackPolicy {
        FallbackPolicy {
            system_dns_opt_in: false,
        }
    }

    fn opted_in() -> FallbackPolicy {
        FallbackPolicy {
            system_dns_opt_in: true,
        }
    }

    #[test]
    fn strict_mode_never_falls_back_to_system_dns() {
        for f in [
            DohFailureKind::Transport,
            DohFailureKind::Protocol,
            DohFailureKind::Timeout,
        ] {
            assert!(
                matches!(opted_in().decide(Mode::Strict, f), FallbackOutcome::Outage),
                "Strict mode ignores system_dns_opt_in"
            );
        }
    }

    #[test]
    fn strict_definitive_failures_surface_unchanged() {
        let outcome = no_opt_in().decide(
            Mode::Strict,
            DohFailureKind::Definitive(NetworkError::ResolveNxDomain),
        );
        match outcome {
            FallbackOutcome::Surface(NetworkError::ResolveNxDomain) => {}
            other => panic!("expected Surface(NxDomain), got {other:?}"),
        }
    }

    #[test]
    fn standard_without_opt_in_returns_outage() {
        for f in [
            DohFailureKind::Transport,
            DohFailureKind::Protocol,
            DohFailureKind::Timeout,
        ] {
            assert!(matches!(
                no_opt_in().decide(Mode::Standard, f),
                FallbackOutcome::Outage
            ));
        }
    }

    #[test]
    fn standard_with_opt_in_falls_back_to_system_dns() {
        for f in [
            DohFailureKind::Transport,
            DohFailureKind::Protocol,
            DohFailureKind::Timeout,
        ] {
            assert!(matches!(
                opted_in().decide(Mode::Standard, f),
                FallbackOutcome::SystemDns
            ));
        }
    }

    #[test]
    fn standard_definitive_surface_regardless_of_opt_in() {
        for opt in [no_opt_in(), opted_in()] {
            let outcome = opt.decide(
                Mode::Standard,
                DohFailureKind::Definitive(NetworkError::ResolveNxDomain),
            );
            match outcome {
                FallbackOutcome::Surface(NetworkError::ResolveNxDomain) => {}
                other => panic!(
                    "definitive failures must surface, even with opt_in={:?}; got {other:?}",
                    opt.system_dns_opt_in
                ),
            }
        }
    }
}
