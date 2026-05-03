//! DNS subsystem (Module 20).
//!
//! Resolves outbound names exclusively through DoH (architecture L21
//! / §3.2 / §3.3) with a curated provider whitelist (L25). All
//! caching is per-partition (L33) and TTL-bounded; concurrent calls
//! for the same `(partition, qname, qtype)` triple are coalesced via
//! [`SingleFlightResolver`].
//!
//! Outage policy:
//!   * Strict mode is DoH-only -> any failure surfaces as
//!     [`crate::NetworkError::ResolveOutage`].
//!   * Standard mode falls back to system DNS only when the user
//!     opted in via the wizard (L21).
//!
//! See [`fallback::FallbackPolicy`] for the decision table.

pub mod cache;
pub mod doh_client;
pub mod fallback;
pub mod rebinding;
pub mod resolver;
pub mod single_flight;
pub mod whitelist;
pub mod wire;

pub use cache::{DnsCache, MAX_ENTRIES_PER_PARTITION, MAX_NEGATIVE_TTL};
pub use doh_client::{DohClient, DohTransport, HyperDohTransport};
pub use fallback::{DohFailureKind, FallbackOutcome, FallbackPolicy};
pub use rebinding::{classify, is_public, AddressClass};
pub use resolver::{
    DnsRecord, QueryType, ResolveFuture, ResolveQuery, ResolveResult, Resolver, MAX_POSITIVE_TTL,
};
pub use single_flight::SingleFlightResolver;
pub use whitelist::{ResolverEndpoint, SpkiPin, Whitelist, WhitelistError};
pub use wire::{decode_response, encode_query, DecodedAnswer, WireError, MAX_DNS_MESSAGE_BYTES};
