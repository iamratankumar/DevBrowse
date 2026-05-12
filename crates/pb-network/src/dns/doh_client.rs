//! DoH client (Module 20).
//!
//! Drives an `application/dns-message` POST against a whitelisted DoH
//! endpoint, decodes the response via [`crate::dns::wire`], runs the
//! [`crate::dns::rebinding`] filter over returned addresses, and
//! returns a [`ResolveResult`].
//!
//! ## Layering
//!
//!   * **Wire format** (`wire.rs`): hand-rolled RFC 1035 + 8484
//!     encoder / decoder.
//!   * **Transport** ([`DohTransport`]): trait abstracting the actual
//!     HTTPS POST. Tests inject mock transports; production uses
//!     [`HyperDohTransport`] over `hyper-rustls`.
//!   * **Outage policy** ([`super::FallbackPolicy`]): consulted on
//!     transport / protocol / timeout failures to decide whether to
//!     surface, declare an outage, or fall back to system DNS.
//!
//! ## Cert pinning
//!
//! v1 validates the chain via `webpki-roots` only. The
//! [`ResolverEndpoint::spki_pin`] field is recorded but enforced in
//! Module 23.1 (TLS chain validation hook), where leaf-cert SPKI is
//! observable post-handshake. Until that lands, a curated DoH endpoint
//! is trusted to the same level as any other public CA-anchored host.
//!
//! ## DoH POST shape
//!
//! Per RFC 8484 §4.1:
//!   * Method: POST
//!   * Content-Type: application/dns-message
//!   * Accept: application/dns-message
//!   * Body: application/dns-message bytes (output of
//!     [`crate::dns::wire::encode_query`]).
//!
//! GET-with-base64url-body is also supported by RFC 8484 but DevBrowse
//! prefers POST so qnames never appear in URL paths or in caches.
//
// TODO(Module 23.1 follow-up): wire SPKI pin verification through the
//   TLS chain validator. Until then, `ResolverEndpoint.spki_pin` is
//   reserved metadata. The chain validator is live (`with_validator`
//   below) but does not yet consult the SPKI pin on handshake.

use crate::dns::rebinding;
use crate::dns::resolver::{
    DnsRecord, QueryType, ResolveFuture, ResolveQuery, ResolveResult, Resolver, MAX_POSITIVE_TTL,
};
use crate::dns::whitelist::ResolverEndpoint;
use crate::dns::wire::{decode_response, encode_query, WireError};
use crate::error::NetworkError;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Per-query timeout. DoH POSTs that take longer than this are
/// rejected and routed through the fallback policy. Tight enough that
/// a stuck endpoint cannot stall a tab indefinitely; loose enough that
/// a typical < 100 ms round trip never trips it.
pub const DOH_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTPS transport for the DoH POST. Production uses
/// [`HyperDohTransport`]; tests inject any implementor.
///
/// Implementations MUST:
///   * use HTTPS only (`https://...` URLs)
///   * never echo the request body or response body in any error's
///     `Display` (L27)
///   * surface specific failure kinds via the typed `NetworkError`
///     variants (`ResolveTransport`, `ResolveTimeout`, etc.).
pub trait DohTransport: Send + Sync + std::fmt::Debug {
    fn post_dns_message<'a>(
        &'a self,
        endpoint: &'a ResolverEndpoint,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, NetworkError>> + Send + 'a>>;
}

/// Production hyper-rustls transport. Single shared `Client` instance
/// reused across queries (connection pooling is per-endpoint inside
/// hyper-util).
pub struct HyperDohTransport {
    client: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl std::fmt::Debug for HyperDohTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HyperDohTransport").finish_non_exhaustive()
    }
}

impl HyperDohTransport {
    /// Build a fresh transport with the locked trust anchors per
    /// L25 / Module 23.1 (webpki-roots). Equivalent to
    /// [`HyperDohTransport::with_validator`] called with the default
    /// [`crate::ChainValidator`].
    pub fn new() -> Result<Self, NetworkError> {
        Self::with_validator(&crate::ChainValidator::default())
    }

    /// Build a transport using the supplied [`ChainValidator`] for
    /// trust anchors. The orchestrator (Module 80) constructs a
    /// single shared validator at boot and hands it to every TLS
    /// site (DoH client, production HTTPS dispatch path, future ECH
    /// hook) so the cohort-watch posture cannot fork by call site.
    ///
    /// HTTP/2 only — RFC 8484 strongly recommends it; HTTP/1.1 is
    /// allowed but produces an inferior cohort.
    pub fn with_validator(validator: &crate::ChainValidator) -> Result<Self, NetworkError> {
        let tls_config = validator.build_client_config();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config((*tls_config).clone())
            .https_only()
            .enable_http2()
            .build();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { client })
    }
}

impl DohTransport for HyperDohTransport {
    fn post_dns_message<'a>(
        &'a self,
        endpoint: &'a ResolverEndpoint,
        body: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, NetworkError>> + Send + 'a>> {
        Box::pin(async move {
            let uri: Uri = endpoint
                .url
                .parse()
                .map_err(|_| NetworkError::ResolveTransport)?;
            let req = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(Full::new(body))
                .map_err(|_| NetworkError::ResolveTransport)?;
            let fut = self.client.request(req);
            let resp = match tokio::time::timeout(DOH_QUERY_TIMEOUT, fut).await {
                Ok(r) => r.map_err(|_| NetworkError::ResolveTransport)?,
                Err(_) => return Err(NetworkError::ResolveTimeout),
            };
            if !resp.status().is_success() {
                return Err(NetworkError::ResolveTransport);
            }
            let collected = resp
                .into_body()
                .collect()
                .await
                .map_err(|_| NetworkError::ResolveTransport)?;
            Ok(collected.to_bytes())
        })
    }
}

/// DoH-backed [`Resolver`]. Bind the chosen endpoint at construction;
/// the user may switch DoH provider only by re-bootstrapping the
/// network broker (matches the rest of the broker's "no live mutation"
/// posture; the orchestrator-driven respawn pattern is in §3.6).
#[derive(Debug)]
pub struct DohClient<T: DohTransport> {
    endpoint: ResolverEndpoint,
    transport: Arc<T>,
}

impl<T: DohTransport> DohClient<T> {
    pub fn new(endpoint: ResolverEndpoint, transport: Arc<T>) -> Self {
        Self {
            endpoint,
            transport,
        }
    }

    pub fn endpoint(&self) -> &ResolverEndpoint {
        &self.endpoint
    }
}

impl<T: DohTransport + 'static> Resolver for DohClient<T> {
    fn resolve<'a>(&'a self, query: ResolveQuery) -> ResolveFuture<'a> {
        let endpoint = &self.endpoint;
        let transport = self.transport.clone();
        Box::pin(async move {
            let body = encode_query(&query.qname, query.qtype).map_err(map_wire_error)?;
            let resp_bytes = transport
                .post_dns_message(endpoint, Bytes::from(body))
                .await?;
            let answer = decode_response(&resp_bytes).map_err(map_wire_error)?;
            // L33 / DNS rebinding: any rejected address poisons the answer.
            for rec in &answer.records {
                let ip = match rec {
                    DnsRecord::A(v4) => std::net::IpAddr::V4(*v4),
                    DnsRecord::Aaaa(v6) => std::net::IpAddr::V6(*v6),
                };
                if !rebinding::is_public(ip) {
                    return Err(NetworkError::ResolveRebinding);
                }
            }
            // Type-filter the response against what the caller asked for:
            // a hostile resolver should not be able to slip an AAAA in
            // when an A was requested (or vice versa).
            let filtered: Vec<DnsRecord> = match query.qtype {
                QueryType::A => answer
                    .records
                    .into_iter()
                    .filter(|r| matches!(r, DnsRecord::A(_)))
                    .collect(),
                QueryType::Aaaa => answer
                    .records
                    .into_iter()
                    .filter(|r| matches!(r, DnsRecord::Aaaa(_)))
                    .collect(),
            };
            if filtered.is_empty() {
                return Err(NetworkError::ResolveNxDomain);
            }
            let ttl = answer.min_ttl.clamp(1, MAX_POSITIVE_TTL);
            Ok(ResolveResult {
                records: filtered,
                ttl_seconds: ttl,
            })
        })
    }
}

/// Map `wire::WireError` into the typed `NetworkError` shape callers
/// observe. NXDOMAIN gets its own variant; everything else collapses
/// to `ResolveProtocol` since the caller cannot meaningfully act on
/// the wire-level distinction.
fn map_wire_error(e: WireError) -> NetworkError {
    match e {
        WireError::NxDomain => NetworkError::ResolveNxDomain,
        WireError::ServerFailure | WireError::FormatError => NetworkError::ResolveTransport,
        _ => NetworkError::ResolveProtocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::QueryType;
    use crate::dns::whitelist::Whitelist;
    use crate::dns::wire::encode_query;
    use crate::partition_key;
    use crate::Mode;
    use pb_config::schema::DohProvider;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use uuid::Uuid;

    fn pk() -> crate::PartitionKey {
        partition_key::derive("example.com", Uuid::from_u128(1), Uuid::from_u128(2))
    }

    fn endpoint() -> ResolverEndpoint {
        Whitelist::lookup(&DohProvider::Quad9, false)
            .unwrap()
            .unwrap()
    }

    /// Mock transport that replays a fixed response. Captures the
    /// request body so tests can assert on the wire-encoded query.
    #[derive(Debug)]
    struct MockTransport {
        last_body: Mutex<Option<Bytes>>,
        reply: Mutex<Option<Result<Bytes, NetworkError>>>,
    }

    impl MockTransport {
        fn ok(reply: Bytes) -> Arc<Self> {
            Arc::new(Self {
                last_body: Mutex::new(None),
                reply: Mutex::new(Some(Ok(reply))),
            })
        }

        fn err(e: NetworkError) -> Arc<Self> {
            Arc::new(Self {
                last_body: Mutex::new(None),
                reply: Mutex::new(Some(Err(e))),
            })
        }
    }

    impl DohTransport for MockTransport {
        fn post_dns_message<'a>(
            &'a self,
            _endpoint: &'a ResolverEndpoint,
            body: Bytes,
        ) -> Pin<Box<dyn Future<Output = Result<Bytes, NetworkError>> + Send + 'a>> {
            *self.last_body.lock().unwrap() = Some(body);
            let r = self.reply.lock().unwrap().take().expect("reply slot");
            Box::pin(async move { r })
        }
    }

    fn build_a_response(qname: &str, ip: Ipv4Addr, ttl: u32) -> Bytes {
        let mut msg = vec![0u8; 12];
        // Flags: QR=1, RD=1, RA=1, RCODE=0.
        msg[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        msg[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        msg[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
                                                        // Question.
        for label in qname.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                                                    // Answer.
        for label in qname.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&ip.octets());
        Bytes::from(msg)
    }

    fn query(qn: &str, qt: QueryType) -> ResolveQuery {
        ResolveQuery {
            partition_key: pk(),
            qname: qn.to_string(),
            qtype: qt,
            mode: Mode::Standard,
        }
    }

    #[tokio::test]
    async fn resolve_returns_a_records() {
        let reply = build_a_response("example.com", Ipv4Addr::new(93, 184, 216, 34), 300);
        let t = MockTransport::ok(reply);
        let c = DohClient::new(endpoint(), t.clone());
        let r = c.resolve(query("example.com", QueryType::A)).await.unwrap();
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.ttl_seconds, 300);
        assert!(t.last_body.lock().unwrap().is_some(), "body sent");
    }

    #[tokio::test]
    async fn resolve_filters_rebinding_addresses() {
        let reply = build_a_response("evil.example.com", Ipv4Addr::new(192, 168, 1, 1), 60);
        let t = MockTransport::ok(reply);
        let c = DohClient::new(endpoint(), t);
        match c.resolve(query("evil.example.com", QueryType::A)).await {
            Err(NetworkError::ResolveRebinding) => {}
            other => panic!("expected ResolveRebinding, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_filters_loopback() {
        let reply = build_a_response("local.example.com", Ipv4Addr::new(127, 0, 0, 1), 60);
        let t = MockTransport::ok(reply);
        let c = DohClient::new(endpoint(), t);
        match c.resolve(query("local.example.com", QueryType::A)).await {
            Err(NetworkError::ResolveRebinding) => {}
            other => panic!("expected ResolveRebinding, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_qtype_filters_unwanted_records() {
        // Build a response that contains AAAA records but the query
        // asked for A. Result should be NxDomain (no matching records).
        let qname = "example.com";
        let mut msg = vec![0u8; 12];
        msg[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        msg[4..6].copy_from_slice(&1u16.to_be_bytes());
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        for label in qname.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        msg.extend_from_slice(&1u16.to_be_bytes());
        // Answer is AAAA, not A.
        for label in qname.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&28u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&16u16.to_be_bytes());
        // 2606:4700:4700::1111 (public; passes rebinding filter so the
        // qtype filter is the only thing that can reject it).
        msg.extend_from_slice(&[
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ]);
        let t = MockTransport::ok(Bytes::from(msg));
        let c = DohClient::new(endpoint(), t);
        match c.resolve(query(qname, QueryType::A)).await {
            Err(NetworkError::ResolveNxDomain) => {}
            other => panic!("expected NxDomain when no matching records, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_propagates_transport_error() {
        let t = MockTransport::err(NetworkError::ResolveTransport);
        let c = DohClient::new(endpoint(), t);
        match c.resolve(query("example.com", QueryType::A)).await {
            Err(NetworkError::ResolveTransport) => {}
            other => panic!("expected ResolveTransport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_caps_ttl_at_max() {
        let reply = build_a_response(
            "example.com",
            Ipv4Addr::new(93, 184, 216, 34),
            30 * 24 * 3600, // 30 days
        );
        let t = MockTransport::ok(reply);
        let c = DohClient::new(endpoint(), t);
        let r = c.resolve(query("example.com", QueryType::A)).await.unwrap();
        assert_eq!(r.ttl_seconds, MAX_POSITIVE_TTL);
    }

    #[tokio::test]
    async fn body_bytes_match_wire_encoder() {
        let reply = build_a_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 60);
        let t = MockTransport::ok(reply);
        let c = DohClient::new(endpoint(), t.clone());
        c.resolve(query("example.com", QueryType::A)).await.unwrap();
        let sent = t.last_body.lock().unwrap().clone().unwrap();
        let expected = encode_query("example.com", QueryType::A).unwrap();
        assert_eq!(&sent[..], &expected[..]);
    }
}
