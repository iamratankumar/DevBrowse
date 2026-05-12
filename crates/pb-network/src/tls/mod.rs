//! TLS / cert policy subsystem (Modules 23.1 - 23.4 + 24.1).
//!
//! Module 23 in the project plan is a subsystem split across four
//! independently shippable sub-modules. The files inside this module:
//!
//!   * `chain.rs` — Module 23.1: trust anchor choice +
//!     `rustls::ClientConfig` factory + [`SelfSignedGrants`] hook.
//!   * `ct.rs` — Module 23.2: Certificate Transparency policy + verifier
//!     surface (production verifier deferred).
//!   * `ech.rs` — Module 23.3: Encrypted Client Hello policy + verifier
//!     surface (production verifier deferred).
//!   * `hsts.rs` — Module 23.4: HSTS preload + pin store (deferred).
//!   * `client_hello.rs` — Module 24.1: JA3-pinned ClientHello
//!     (deferred).
//!
//! All modes share the same ClientConfig (Module 24.1 invariant).
//! Mode-locked policy decisions (CT hard-fail / ECH mandatory) live
//! in the per-sub-module bundles consulted *after* the rustls
//! handshake, never at the rustls-config layer.

pub mod chain;
pub mod ct;
pub mod ech;

pub use chain::{
    CapturingGrants, ChainValidator, DenyAllGrants, SelfSignedGrants, TrustAnchorChoice,
};
pub use ct::{
    CapturingVerifier as CapturingCtVerifier, CtDecision, CtFailureKind, CtPolicy, CtPolicyBundle,
    CtVerificationOutcome, CtVerifier, NoOpVerifier as NoOpCtVerifier, KNOWN_CT_LOG_NAMES,
};
pub use ech::{
    CapturingEchVerifier, EchDecision, EchFailureKind, EchPolicy, EchPolicyBundle,
    EchVerificationOutcome, EchVerifier, EchWarning, NoOpEchVerifier,
};
