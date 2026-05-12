//! Network broker — Phase 4 (Modules 19-25).
//!
//! Layer 2 process: identity-aware request routing for HTTP(S), DoH,
//! and (later) WebRTC. Sub-systems plug into the [`coordinator`]
//! (Module 19); the coordinator owns the route order and the
//! per-partition egress state map.
//!
//! ## Architecture invariants enforced at this crate boundary
//!
//!   * **§3.5 / §5.2 (mirrored):** every outbound request is gated by a
//!     partition-key check that recomputes the canonical key from the
//!     orchestrator-supplied identity context and rejects renderer-
//!     declared keys that disagree. Mirrored from `pb_storage` because
//!     §4.1 forbids `pb-network -> pb-storage` imports; see
//!     [`partition_key`] for the lock-step canary.
//!   * **L30 HTTPS-Only:** `http://` outbounds without an explicit user-
//!     confirmation downgrade approval hard-error in
//!     [`coordinator::NetworkCoordinator::route`].
//!   * **L33 per-partition network state:** cache, DNS cache, connection
//!     pool, HSTS pin store, ALT-SVC table all keyed by `PartitionKey`.
//!     Bounded LRU at `MAX_PARTITIONS = 16` per the perf-contract row
//!     for Module 19 in `project-plan/README.md`.
//!   * **L27 forensic redaction:** every [`error::NetworkError`]
//!     `Display` is opaque; detail flows through `Error::source()` only.
//!
//! ## v1 surface
//!
//! Module 19 ships the bootstrap, the partition-key gate, the L30
//! enforcement, the per-partition egress map, and the trait shape for
//! the orchestrator's platform-context bridge. Modules 20-25 extend
//! the coordinator with DoH, blocklist, header scrubbing, TLS, JA3
//! pinning, and WebRTC constraints.

#![forbid(unsafe_code)]

pub mod blocklist;
pub mod client_hello;
pub mod coordinator;
pub mod dns;
pub mod error;
pub mod headers;
pub mod partition_key;
pub mod tls;
pub mod webrtc;

pub use blocklist::{
    strip_tracking_params, BlockEventSink, BlockKind, BlockedEvent, Blocklist, CapturingSink,
    CookieBannerRule, InMemoryLoader, Loader, LoaderError, Manifest, NoopSink, RadixTree, Rule,
    SignedManifestLoader, UrlParamRule, UrlParamStripList, DEFAULT_TRACKING_PARAMS,
};
pub use client_hello::{
    ClientHelloPin, LOCKED_CIPHER_SUITES, LOCKED_KX_GROUPS, LOCKED_PROTOCOL_VERSIONS,
};
pub use coordinator::{
    bootstrap, CancellationFlag, EgressState, Mode, NetworkCoordinator, PlatformContext, Request,
    RoutedRequest, MAX_PARTITIONS,
};
pub use dns::{
    DnsCache, DnsRecord, DohClient, DohFailureKind, DohTransport, FallbackOutcome, FallbackPolicy,
    HyperDohTransport, QueryType, ResolveQuery, ResolveResult, Resolver, ResolverEndpoint,
    SingleFlightResolver, Whitelist, WhitelistError,
};
pub use error::NetworkError;
pub use headers::{
    scrub as scrub_headers, HeaderPolicy, RefererPolicy, DEVBROWSE_ACCEPT_DEFAULT,
    DEVBROWSE_ACCEPT_ENCODING, DEVBROWSE_ACCEPT_LANGUAGE, DEVBROWSE_USER_AGENT,
};
pub use partition_key::{
    derive as derive_partition_key, PartitionKey, PARTITION_KEY_DOMAIN, PARTITION_KEY_LEN,
};
pub use tls::{
    CapturingCtVerifier, CapturingEchVerifier, CapturingGrants, ChainValidator, CtDecision,
    CtFailureKind, CtPolicy, CtPolicyBundle, CtVerificationOutcome, CtVerifier, DenyAllGrants,
    EchDecision, EchFailureKind, EchPolicy, EchPolicyBundle, EchVerificationOutcome, EchVerifier,
    EchWarning, NoOpCtVerifier, NoOpEchVerifier, SelfSignedGrants, TrustAnchorChoice,
};
pub use webrtc::{
    CapturingWebRtcGrants, DenyAllWebRtcGrants, FilterOutcome, FilteredIceCandidate, IceCandidate,
    IceCandidateFilter, IceCandidateType, IceFilterReason, IceTransport, MdnsHostnameGenerator,
    MdnsHostnameMap, WebRtcConstraint, WebRtcDecision, WebRtcDenyReason, WebRtcGrants,
    WebRtcPolicy,
};
