//! DNS resolver trait + value types, Module 20.
//!
//! `pb-network` resolves names exclusively through DoH (architecture L21
//! / §3.2 / §3.3). System DNS is allowed only as a wizard-gated fallback
//! in Standard mode; Strict mode is DoH-only. The [`Resolver`] trait is
//! the abstract surface; production wiring is the [`DohClient`] (this
//! module's `doh_client.rs`); tests inject mock impls.
//!
//! ## Forensic redaction (L27)
//!
//! Implementations MUST NOT echo `query.qname` in any returned error's
//! `Display` output. Detail is reachable through `Error::source()` only.
//! Tests below pin this contract.
//
// TODO(Module 80): orchestrator owns the live `Arc<dyn Resolver>` and
//   passes it to the `NetworkCoordinator` at bootstrap. v1 stores
//   `Option<Arc<dyn Resolver>>` so the coordinator compiles before the
//   resolver is wired.

use crate::error::NetworkError;
use crate::partition_key::PartitionKey;
use crate::Mode;
use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

/// Resolution future used by [`Resolver::resolve`]. Boxed so the trait
/// stays object-safe; the in-process orchestrator (Module 80) holds an
/// `Arc<dyn Resolver>` and dispatches across many concurrent resolves.
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ResolveResult, NetworkError>> + Send + 'a>>;

/// DNS query class supported by Module 20. Only A and AAAA are required
/// for the current request flow; CNAME / SRV / TXT are future work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryType {
    /// IPv4 address record (RFC 1035 §3.4.1, type code 1).
    A,
    /// IPv6 address record (RFC 3596, type code 28).
    Aaaa,
}

impl QueryType {
    pub const fn type_code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// One resolved record. Module 20 returns only address records to the
/// coordinator; CNAME chasing is performed inside the resolver and
/// flattened away before the result reaches this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
}

/// Resolver request envelope. The `partition_key` is supplied by the
/// coordinator (already authorized by §5.2 mirror); the resolver uses
/// it to key the per-partition DNS cache (L33). `mode` is supplied so
/// the resolver can enforce the L21 outage policy (Strict = fail
/// closed; Standard = system DNS only on wizard opt-in).
#[derive(Debug, Clone)]
pub struct ResolveQuery {
    pub partition_key: PartitionKey,
    pub qname: String,
    pub qtype: QueryType,
    pub mode: Mode,
}

/// Resolution result. `ttl_seconds` is the **effective** TTL (the
/// minimum of all record TTLs returned by the upstream resolver, capped
/// at [`MAX_POSITIVE_TTL`]). The cache wrapper uses it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveResult {
    pub records: Vec<DnsRecord>,
    pub ttl_seconds: u32,
}

/// Maximum TTL the cache will honour for a positive answer. Caps a
/// hostile upstream from pinning a record into the cache forever.
pub const MAX_POSITIVE_TTL: u32 = 24 * 60 * 60; // 24h

/// Maximum TTL the cache will honour for a negative answer (NXDOMAIN
/// / empty). Capped low so an attacker-controlled query stream cannot
/// bloat the cache via repeated negative entries.
pub const MAX_NEGATIVE_TTL: u32 = 60;

/// Object-safe DNS resolver. Implementations MUST be `Send + Sync` so
/// the coordinator can hold them in an `Arc<dyn Resolver>` and dispatch
/// across concurrent route tasks.
///
/// Display of any returned error MUST be opaque (no qname / endpoint /
/// resolver hostname leakage); this is the L27 contract.
pub trait Resolver: Send + Sync + fmt::Debug {
    fn resolve<'a>(&'a self, query: ResolveQuery) -> ResolveFuture<'a>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition_key;
    use std::sync::Arc;
    use uuid::Uuid;

    fn pk() -> PartitionKey {
        partition_key::derive("example.com", Uuid::from_u128(1), Uuid::from_u128(2))
    }

    #[derive(Debug)]
    struct StubResolver;
    impl Resolver for StubResolver {
        fn resolve<'a>(&'a self, _query: ResolveQuery) -> ResolveFuture<'a> {
            Box::pin(async move {
                Ok(ResolveResult {
                    records: vec![DnsRecord::A(Ipv4Addr::new(93, 184, 216, 34))],
                    ttl_seconds: 60,
                })
            })
        }
    }

    #[tokio::test]
    async fn boxed_resolver_dispatches() {
        let r: Arc<dyn Resolver> = Arc::new(StubResolver);
        let q = ResolveQuery {
            partition_key: pk(),
            qname: "example.com".to_string(),
            qtype: QueryType::A,
            mode: Mode::Standard,
        };
        let res = r.resolve(q).await.expect("resolve ok");
        assert_eq!(res.records.len(), 1);
        assert_eq!(res.ttl_seconds, 60);
    }

    #[test]
    fn query_type_codes() {
        assert_eq!(QueryType::A.type_code(), 1);
        assert_eq!(QueryType::Aaaa.type_code(), 28);
    }
}
