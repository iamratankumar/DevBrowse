//! WebRTC constraint surface, Module 25.
//!
//! Architecture references:
//!   * **L35** — WebRTC: explicit per-site permission required;
//!     ICE candidates use mDNS hostnames only; private / link-local
//!     addresses never reach JS; fully disabled in Strict.
//!   * **§3.5 / §5.2** — partition keys: an mDNS hostname registered
//!     in partition P is resolvable only inside P. Cross-partition
//!     resolution is the L35 "DNS-rebinding via mDNS hostname"
//!     edge-case mitigation.
//!   * **L25** — DoH whitelist does not apply to mDNS lookups.
//!     mDNS hostnames are link-local (RFC 6762) and resolved via the
//!     OS / WebRTC stack's own multicast responder, not pb-network's
//!     DoH client.
//!   * **L27** — `WebRtcDenyReason`, `IceFilterReason`,
//!     `WebRtcDecision::Deny` carry typed discriminants only; no
//!     hostname / IP / origin string ever reaches a `Display` impl.
//!   * **§5.5 / threat-model A1** — WebRTC IP-leak is a classic
//!     fingerprint surface (the navigator API readouts list calls
//!     it out alongside canvas / WebGL / audio). The mDNS-only
//!     replacement in this module is the structural mitigation;
//!     the per-site permission gate is the consent layer.
//!
//! ## What this module is and is not
//!
//! It IS:
//!   * The policy + ICE-candidate-filter + mDNS-hostname-management
//!     surface that the Gecko WebRTC stack consults at the broker
//!     boundary. The renderer (untrusted; Strict-mode-isolated) calls
//!     into the broker; the broker enforces the L35 invariants.
//!   * Mode-locked: `Mode::Strict` collapses every decision to
//!     `WebRtcDecision::Deny(StrictModeDisabled)` regardless of
//!     grants, regardless of caller — the L35 "fully disabled in
//!     Strict" lock.
//!   * Partition-aware: [`MdnsHostnameMap`] is constructed for one
//!     partition and refuses to resolve a hostname to a different
//!     partition's caller.
//!
//! It IS NOT:
//!   * A WebRTC stack. The actual SDP / ICE / DTLS-SRTP / SCTP
//!     machinery lives in Gecko (Module 1's libxul). This module
//!     pre-filters what Gecko's WebRTC stack is allowed to expose
//!     to JS.
//!   * A real mDNS responder. v1 carries the per-PC mDNS-hostname
//!     -> IP map structurally; the mDNS responder that actually
//!     announces those records on the link is in pb-platform
//!     (deferred, see TODO below).
//!   * The permission-grant UI. The Module 59 permission center
//!     supplies a [`WebRtcGrants`] impl; this module owns only the
//!     trait surface + the v1 default-deny [`DenyAllWebRtcGrants`].
//!
//! ## Decision table (per L35)
//!
//! | Mode     | grants.is_granted(origin) | Decision                 |
//! |----------|---------------------------|--------------------------|
//! | Strict   | (irrelevant — never consulted) | Deny(StrictModeDisabled) |
//! | Standard | true                      | Allow                    |
//! | Standard | false                     | Deny(NoPermissionGrant)  |
//!
//! ## ICE candidate filter (per L35)
//!
//! Host candidates: address replaced with a fresh mDNS hostname,
//! always. The local interface IP — public or private — never
//! reaches the peer. Only the registered hostname does.
//!
//! ServerReflexive (STUN-discovered) / Relayed (TURN) /
//! PeerReflexive (handshake-discovered): public-address gate. Any
//! non-public address class (per [`crate::dns::rebinding::classify`])
//! is dropped with the matching [`IceFilterReason`]. This catches
//! the multi-NIC edge case the spec calls out: a secondary interface
//! that exposes a private address never produces a usable srflx
//! candidate.
//
// TODO(Module 59 / permission center): real `WebRtcGrants` impl
//   wiring per-site grants from the permission UI. Until then,
//   `DenyAllWebRtcGrants` is the production default and Standard-mode
//   WebRTC is effectively off (deny-by-default).
// TODO(pb-platform / mdns-responder): announce the
//   `MdnsHostnameMap`'s registered hostnames on the link via an
//   actual RFC 6762 multicast responder. v1 carries the structural
//   binding; the responder is a separate Phase 4-or-later module.
// TODO(coordinator wiring): once Module 59 + pb-platform's mDNS
//   responder land, the orchestrator (Module 80) constructs
//   `WebRtcConstraint::with_grants(...)` at boot and exposes it
//   through `NetworkCoordinator` so renderers can consult one
//   shared decision authority.

use crate::dns::rebinding::{classify, AddressClass};
use crate::partition_key::PartitionKey;
use crate::Mode;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

// ── Policy ────────────────────────────────────────────────────────────────

/// Per-mode WebRTC enforcement policy. Mode mapping (locked):
///   * `Mode::Strict`   -> `Disabled`         (L35 "fully disabled")
///   * `Mode::Standard` -> `PerSitePermission`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebRtcPolicy {
    /// Strict mode: WebRTC fully disabled. The
    /// `RTCPeerConnection` / `RTCDataChannel` / etc. JS surface
    /// returns "not supported"; the broker rejects every
    /// constraint evaluation regardless of grants.
    Disabled,
    /// Standard mode: per-site permission required (Module 59).
    /// Until a grant arrives via [`WebRtcGrants`], the decision
    /// is [`WebRtcDecision::Deny`] with reason `NoPermissionGrant`.
    PerSitePermission,
}

impl WebRtcPolicy {
    /// Locked snapshot for `mode`. Strict = `Disabled`,
    /// Standard = `PerSitePermission`.
    pub fn for_mode(mode: Mode) -> Self {
        match mode {
            Mode::Standard => Self::PerSitePermission,
            Mode::Strict => Self::Disabled,
        }
    }
}

// ── Permission grants (Module 59 hook) ────────────────────────────────────

/// Hook for per-site WebRTC permission grants (Module 59 permission
/// center). Implementations MUST be `Send + Sync` so the constraint
/// surface can hold them inside an `Arc<dyn WebRtcGrants>`.
///
/// L27: implementations MUST NOT echo the origin string in any
/// returned error / Display surface. Grants are membership tests
/// only.
pub trait WebRtcGrants: Send + Sync + fmt::Debug {
    /// True iff the user has granted WebRTC permission for `origin`.
    /// `origin` is the canonicalized HTTPS origin
    /// (`https://example.com:443` shape) the constraint will key on.
    fn is_granted(&self, origin: &str) -> bool;
}

/// Default grants impl — denies every origin. Used in v1 + every
/// test that wants to confirm the default-deny posture.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllWebRtcGrants;

impl WebRtcGrants for DenyAllWebRtcGrants {
    fn is_granted(&self, _origin: &str) -> bool {
        false
    }
}

/// Capturing test grants impl. Records every origin lookup and
/// returns whatever the test staged.
#[derive(Debug, Default)]
pub struct CapturingWebRtcGrants {
    granted: std::sync::Mutex<Vec<String>>,
    lookups: std::sync::Mutex<Vec<String>>,
}

impl CapturingWebRtcGrants {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-grant `origin` so the next `is_granted(origin)` returns true.
    pub fn grant(&self, origin: impl Into<String>) {
        self.granted
            .lock()
            .expect("granted lock")
            .push(origin.into());
    }

    /// Snapshot of every `is_granted` invocation in order.
    pub fn observed_lookups(&self) -> Vec<String> {
        self.lookups.lock().expect("lookups lock").clone()
    }
}

impl WebRtcGrants for CapturingWebRtcGrants {
    fn is_granted(&self, origin: &str) -> bool {
        self.lookups
            .lock()
            .expect("lookups lock")
            .push(origin.to_string());
        self.granted
            .lock()
            .expect("granted lock")
            .iter()
            .any(|g| g == origin)
    }
}

// ── Decision ──────────────────────────────────────────────────────────────

/// What the constraint surface decided for a given (mode, origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcDecision {
    /// Allow `RTCPeerConnection` to construct + ICE gathering to
    /// proceed (subject to the per-candidate [`IceCandidateFilter`]).
    Allow,
    /// Reject `RTCPeerConnection` construction. Carries the typed
    /// reason for the telemetry-safe surface in Module 60.
    Deny(WebRtcDenyReason),
}

/// Why the constraint surface denied a request. Display strings
/// are opaque (L27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebRtcDenyReason {
    /// L35 lock: WebRTC is fully disabled in Strict.
    StrictModeDisabled,
    /// Standard mode + no per-site permission grant from Module 59.
    NoPermissionGrant,
}

impl fmt::Display for WebRtcDenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::StrictModeDisabled => "webrtc: disabled in strict mode",
            Self::NoPermissionGrant => "webrtc: no per-site permission grant",
        };
        f.write_str(label)
    }
}

// ── ICE candidate types ──────────────────────────────────────────────────

/// ICE candidate type per RFC 8445 §5.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IceCandidateType {
    /// Local interface address. Always replaced with an mDNS
    /// hostname before reaching JS (L35).
    Host,
    /// STUN-discovered server-reflexive candidate. Public address
    /// only; private addresses dropped by the filter.
    ServerReflexive,
    /// TURN-allocated relayed candidate. Public address only.
    Relayed,
    /// Discovered during connectivity check. Public address only.
    PeerReflexive,
}

/// ICE transport per RFC 8445.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IceTransport {
    Udp,
    Tcp,
}

/// ICE candidate emitted by the WebRTC stack (pre-filter).
///
/// The fields mirror the relevant subset of an SDP `a=candidate`
/// line. Foundation / priority / component are kept verbatim because
/// the filter does not transform them; only the address surface is
/// normalised (Host -> mDNS hostname; non-Host -> public-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    pub candidate_type: IceCandidateType,
    pub address: IpAddr,
    pub port: u16,
    pub component: u8,
    pub foundation: String,
    pub priority: u32,
    pub transport: IceTransport,
}

/// ICE candidate as it leaves the broker for JS / the wire.
///
/// `Mdns` carries the registered hostname; the underlying IP is
/// retrievable only through the [`MdnsHostnameMap`] the broker
/// holds, and only by the partition that registered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilteredIceCandidate {
    /// Host candidate normalised to its mDNS hostname.
    Mdns {
        hostname: String,
        port: u16,
        component: u8,
        foundation: String,
        priority: u32,
        transport: IceTransport,
    },
    /// Non-Host candidate that passed the public-address gate.
    Public(IceCandidate),
}

/// Outcome of running [`IceCandidateFilter::filter`] on one
/// candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOutcome {
    /// Candidate normalized + safe to emit. The wrapped
    /// [`FilteredIceCandidate`] is what reaches JS / the peer.
    Replace(FilteredIceCandidate),
    /// Candidate dropped. Carries the typed reason.
    Drop(IceFilterReason),
}

/// Why an ICE candidate was dropped. Display strings are opaque (L27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IceFilterReason {
    /// RFC 1918 / RFC 6598 / fc00::/7 — LAN address.
    PrivateAddress,
    /// 127.0.0.0/8 / ::1 — loopback.
    LoopbackAddress,
    /// 169.254.0.0/16 / fe80::/10 — link-local.
    LinkLocalAddress,
    /// 224.0.0.0/4 / ff00::/8 — multicast.
    MulticastAddress,
    /// 0.0.0.0 / :: — unspecified.
    UnspecifiedAddress,
    /// 192.0.2.0/24 / 198.51.100.0/24 / 203.0.113.0/24 / 2001:db8::/32.
    DocumentationAddress,
    /// 240.0.0.0/4 / 0.0.0.0/8 — reserved.
    ReservedAddress,
}

impl fmt::Display for IceFilterReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::PrivateAddress => "ice: private address dropped",
            Self::LoopbackAddress => "ice: loopback address dropped",
            Self::LinkLocalAddress => "ice: link-local address dropped",
            Self::MulticastAddress => "ice: multicast address dropped",
            Self::UnspecifiedAddress => "ice: unspecified address dropped",
            Self::DocumentationAddress => "ice: documentation address dropped",
            Self::ReservedAddress => "ice: reserved address dropped",
        };
        f.write_str(label)
    }
}

// ── ICE candidate filter ──────────────────────────────────────────────────

/// Stateless façade over the ICE candidate filter logic. The actual
/// per-PeerConnection state (the mDNS hostname registry) lives in
/// [`MdnsHostnameMap`], which the caller threads through.
#[derive(Debug, Default, Clone, Copy)]
pub struct IceCandidateFilter;

impl IceCandidateFilter {
    /// Apply L35 to one candidate.
    ///
    /// **Host candidates:** address replaced with a fresh mDNS
    /// hostname registered into `mdns`. Always — even when the
    /// underlying address is public, because revealing a host's
    /// specific IP through the host candidate type defeats the
    /// privacy purpose of the host/srflx separation.
    ///
    /// **ServerReflexive / Relayed / PeerReflexive:** public address
    /// only. Any non-public class is dropped with the matching
    /// [`IceFilterReason`]. This is the L35 "private / link-local
    /// addresses never reach JS" lock.
    pub fn filter(candidate: IceCandidate, mdns: &mut MdnsHostnameMap) -> FilterOutcome {
        match candidate.candidate_type {
            IceCandidateType::Host => {
                let hostname = mdns.register(candidate.address);
                FilterOutcome::Replace(FilteredIceCandidate::Mdns {
                    hostname,
                    port: candidate.port,
                    component: candidate.component,
                    foundation: candidate.foundation,
                    priority: candidate.priority,
                    transport: candidate.transport,
                })
            }
            IceCandidateType::ServerReflexive
            | IceCandidateType::Relayed
            | IceCandidateType::PeerReflexive => {
                let class = classify(candidate.address);
                match class {
                    AddressClass::Public => {
                        FilterOutcome::Replace(FilteredIceCandidate::Public(candidate))
                    }
                    AddressClass::Loopback => FilterOutcome::Drop(IceFilterReason::LoopbackAddress),
                    AddressClass::LinkLocal => {
                        FilterOutcome::Drop(IceFilterReason::LinkLocalAddress)
                    }
                    AddressClass::Private => FilterOutcome::Drop(IceFilterReason::PrivateAddress),
                    AddressClass::Multicast => {
                        FilterOutcome::Drop(IceFilterReason::MulticastAddress)
                    }
                    AddressClass::Unspecified => {
                        FilterOutcome::Drop(IceFilterReason::UnspecifiedAddress)
                    }
                    AddressClass::Documentation => {
                        FilterOutcome::Drop(IceFilterReason::DocumentationAddress)
                    }
                    AddressClass::Reserved => FilterOutcome::Drop(IceFilterReason::ReservedAddress),
                }
            }
        }
    }
}

// ── mDNS hostname generation ──────────────────────────────────────────────

/// Stateless mDNS hostname generator. RFC 6762 specifies `.local`
/// as the link-local domain; draft-ietf-mmusic-mdns-ice-candidates
/// nails down the WebRTC-specific "random UUID + .local" shape.
///
/// Every call returns a fresh hostname. Callers who need stable
/// host identifiers across re-registrations are doing the wrong
/// thing — the whole point of the L35 mDNS scheme is that the
/// hostname is opaque and per-PC.
#[derive(Debug, Default, Clone, Copy)]
pub struct MdnsHostnameGenerator;

impl MdnsHostnameGenerator {
    /// Generate a fresh `<uuid>.local` hostname using a CSPRNG-
    /// backed UUID v4 (L7: audited primitive).
    pub fn generate() -> String {
        format!("{}.local", Uuid::new_v4())
    }
}

// ── mDNS hostname map (per-partition) ─────────────────────────────────────

/// Per-PeerConnection mDNS hostname registry, bound to one
/// [`PartitionKey`].
///
/// Constructing a [`MdnsHostnameMap`] declares the partition that
/// the registered hostnames belong to. [`MdnsHostnameMap::resolve`]
/// rejects any lookup whose `requesting_partition` does not match;
/// this is the L35 "DNS-rebinding via mDNS hostname: bind candidate
/// to its PeerConnection's partition; reject cross-partition use"
/// edge-case mitigation.
#[derive(Debug, Clone)]
pub struct MdnsHostnameMap {
    partition: PartitionKey,
    map: HashMap<String, IpAddr>,
}

impl MdnsHostnameMap {
    /// Construct a fresh map bound to `partition`. The map is the
    /// authority for hostname -> IP resolution within that
    /// partition; resolutions from other partitions return `None`.
    pub fn new(partition: PartitionKey) -> Self {
        Self {
            partition,
            map: HashMap::new(),
        }
    }

    /// Partition this map serves.
    pub fn partition(&self) -> &PartitionKey {
        &self.partition
    }

    /// Number of registered hostnames.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True iff no hostnames are registered.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Register a fresh mDNS hostname for `ip` and return it.
    ///
    /// Each call generates a new hostname, even when the same IP
    /// is registered twice — multiple PeerConnections to the same
    /// host produce distinct hostnames so an off-link observer
    /// cannot correlate sessions by hostname.
    pub fn register(&mut self, ip: IpAddr) -> String {
        let hostname = MdnsHostnameGenerator::generate();
        self.map.insert(hostname.clone(), ip);
        hostname
    }

    /// Resolve a previously-registered hostname to its underlying
    /// IP — but only when `requesting_partition` matches the
    /// partition this map was constructed for.
    ///
    /// Cross-partition lookups return `None` (L35 DNS-rebinding
    /// mitigation); unknown hostnames return `None`.
    pub fn resolve(&self, hostname: &str, requesting_partition: &PartitionKey) -> Option<IpAddr> {
        if requesting_partition != &self.partition {
            return None;
        }
        self.map.get(hostname).copied()
    }
}

// ── Constraint façade ─────────────────────────────────────────────────────

/// Top-level WebRTC constraint façade. Holds the [`WebRtcGrants`]
/// hook + applies [`WebRtcPolicy::for_mode`] on every evaluation.
///
/// The orchestrator (Module 80) constructs one of these at boot and
/// hands it to renderer-broker bridges so each renderer process
/// consults the same authority. v1 default is
/// [`DenyAllWebRtcGrants`] (Standard-mode WebRTC effectively off
/// until Module 59 wires real grants in via
/// [`WebRtcConstraint::with_grants`]).
///
/// **Why no `Bundle` type here:** [`crate::tls::CtPolicyBundle`] and
/// [`crate::tls::EchPolicyBundle`] bundle their verifier with a
/// per-mode policy snapshot because the verifier is itself a piece of
/// pinned policy (a CT-log key set, an ECH config). WebRTC's
/// `WebRtcGrants` is *not* policy: it is a runtime user-consent
/// authority owned by Module 59. Bundling it with the per-mode policy
/// would imply the grants set is part of the cohort-locked surface,
/// which it is not — grants change per-site, per-prompt. The
/// constraint façade therefore holds the grants hook directly.
#[derive(Clone)]
pub struct WebRtcConstraint {
    grants: Arc<dyn WebRtcGrants>,
}

impl WebRtcConstraint {
    /// Construct with the locked default: deny-all grants.
    pub fn new() -> Self {
        Self {
            grants: Arc::new(DenyAllWebRtcGrants),
        }
    }

    /// Construct with a custom grants hook (production wiring path).
    pub fn with_grants(grants: Arc<dyn WebRtcGrants>) -> Self {
        Self { grants }
    }

    /// Snapshot of the wired grants hook. Tests use this to confirm
    /// the constraint consults the hook with the right arguments.
    pub fn grants(&self) -> &Arc<dyn WebRtcGrants> {
        &self.grants
    }

    /// Apply the L35 decision table to `(mode, origin)`. Pure
    /// function modulo the grants hook's `is_granted` call.
    ///
    /// Strict short-circuits to `Deny(StrictModeDisabled)` *without*
    /// consulting the grants hook — the L35 lock is non-bypassable.
    pub fn evaluate(&self, mode: Mode, origin: &str) -> WebRtcDecision {
        match WebRtcPolicy::for_mode(mode) {
            WebRtcPolicy::Disabled => WebRtcDecision::Deny(WebRtcDenyReason::StrictModeDisabled),
            WebRtcPolicy::PerSitePermission => {
                if self.grants.is_granted(origin) {
                    WebRtcDecision::Allow
                } else {
                    WebRtcDecision::Deny(WebRtcDenyReason::NoPermissionGrant)
                }
            }
        }
    }
}

impl Default for WebRtcConstraint {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WebRtcConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebRtcConstraint").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition_key::{derive as derive_partition_key, PartitionKey};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use uuid::Uuid;

    fn pk(seed: u8) -> PartitionKey {
        // Two distinct partitions for cross-partition tests.
        let profile = Uuid::from_bytes([seed; 16]);
        let context = Uuid::from_bytes([seed.wrapping_add(1); 16]);
        derive_partition_key("https://example.test", profile, context)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    fn ice(t: IceCandidateType, address: IpAddr) -> IceCandidate {
        IceCandidate {
            candidate_type: t,
            address,
            port: 49152,
            component: 1,
            foundation: "0".into(),
            priority: 1,
            transport: IceTransport::Udp,
        }
    }

    // -- WebRtcPolicy::for_mode --

    #[test]
    fn standard_mode_is_per_site_permission() {
        assert_eq!(
            WebRtcPolicy::for_mode(Mode::Standard),
            WebRtcPolicy::PerSitePermission
        );
    }

    #[test]
    fn strict_mode_is_disabled() {
        assert_eq!(WebRtcPolicy::for_mode(Mode::Strict), WebRtcPolicy::Disabled);
    }

    // -- Decision table --

    #[test]
    fn strict_always_denies_with_strict_disabled() {
        // Even with a "grant everything" hook, Strict short-circuits
        // before consulting it. L35 lock is non-bypassable.
        let grants = Arc::new(CapturingWebRtcGrants::new());
        grants.grant("https://example.com");
        let c = WebRtcConstraint::with_grants(grants.clone());
        assert_eq!(
            c.evaluate(Mode::Strict, "https://example.com"),
            WebRtcDecision::Deny(WebRtcDenyReason::StrictModeDisabled),
        );
        // Hook must NOT have been consulted (otherwise Strict could
        // be bypassed by a hostile grants impl).
        assert!(grants.observed_lookups().is_empty());
    }

    #[test]
    fn standard_with_grant_allows() {
        let grants = Arc::new(CapturingWebRtcGrants::new());
        grants.grant("https://example.com");
        let c = WebRtcConstraint::with_grants(grants.clone());
        assert_eq!(
            c.evaluate(Mode::Standard, "https://example.com"),
            WebRtcDecision::Allow,
        );
        assert_eq!(
            grants.observed_lookups(),
            vec!["https://example.com".to_string()],
        );
    }

    #[test]
    fn standard_without_grant_denies_with_no_grant_reason() {
        let c = WebRtcConstraint::new();
        assert_eq!(
            c.evaluate(Mode::Standard, "https://example.com"),
            WebRtcDecision::Deny(WebRtcDenyReason::NoPermissionGrant),
        );
    }

    #[test]
    fn deny_all_grants_denies_every_origin() {
        let g = DenyAllWebRtcGrants;
        assert!(!g.is_granted("https://example.com"));
        assert!(!g.is_granted(""));
        assert!(!g.is_granted("https://evil.test"));
    }

    #[test]
    fn capturing_grants_records_lookups_and_grants() {
        let g = CapturingWebRtcGrants::new();
        g.grant("https://allowed.test");
        assert!(g.is_granted("https://allowed.test"));
        assert!(!g.is_granted("https://other.test"));
        assert_eq!(
            g.observed_lookups(),
            vec![
                "https://allowed.test".to_string(),
                "https://other.test".to_string(),
            ]
        );
    }

    // -- ICE candidate filter: Host -> mDNS --

    #[test]
    fn host_candidate_replaced_with_mdns_hostname() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::Host, v4(192, 168, 1, 5));
        let outcome = IceCandidateFilter::filter(cand.clone(), &mut mdns);
        match outcome {
            FilterOutcome::Replace(FilteredIceCandidate::Mdns { hostname, port, .. }) => {
                assert!(hostname.ends_with(".local"));
                // UUID + ".local" = 36 + 6 = 42 chars.
                assert_eq!(hostname.len(), 42);
                assert_eq!(port, 49152);
            }
            other => panic!("expected Mdns replacement, got {other:?}"),
        }
        // The IP was registered into the mDNS map.
        assert_eq!(mdns.len(), 1);
    }

    #[test]
    fn host_candidate_with_public_ip_still_replaced_with_mdns() {
        // Even a public address gets mDNS treatment for Host type:
        // revealing the local interface's specific IP is the leak we
        // are preventing, irrespective of the IP's class.
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::Host, v4(93, 184, 216, 34));
        let outcome = IceCandidateFilter::filter(cand, &mut mdns);
        assert!(matches!(
            outcome,
            FilterOutcome::Replace(FilteredIceCandidate::Mdns { .. })
        ));
    }

    #[test]
    fn each_host_candidate_gets_a_fresh_hostname() {
        // Two registrations of the same IP produce two distinct
        // hostnames. An off-link observer cannot correlate sessions
        // by hostname.
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let h1 = mdns.register(v4(192, 168, 1, 5));
        let h2 = mdns.register(v4(192, 168, 1, 5));
        assert_ne!(h1, h2);
        assert_eq!(mdns.len(), 2);
    }

    // -- ICE candidate filter: srflx / relay / prflx public-only --

    #[test]
    fn server_reflexive_with_public_v4_passes() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v4(93, 184, 216, 34));
        let outcome = IceCandidateFilter::filter(cand.clone(), &mut mdns);
        assert_eq!(
            outcome,
            FilterOutcome::Replace(FilteredIceCandidate::Public(cand))
        );
    }

    #[test]
    fn server_reflexive_with_public_v6_passes() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(
            IceCandidateType::ServerReflexive,
            v6("2606:4700:4700::1111"),
        );
        let outcome = IceCandidateFilter::filter(cand.clone(), &mut mdns);
        assert_eq!(
            outcome,
            FilterOutcome::Replace(FilteredIceCandidate::Public(cand))
        );
    }

    #[test]
    fn relay_with_public_address_passes() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::Relayed, v4(8, 8, 8, 8));
        let outcome = IceCandidateFilter::filter(cand.clone(), &mut mdns);
        assert_eq!(
            outcome,
            FilterOutcome::Replace(FilteredIceCandidate::Public(cand))
        );
    }

    #[test]
    fn peer_reflexive_with_public_address_passes() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::PeerReflexive, v4(93, 184, 216, 34));
        let outcome = IceCandidateFilter::filter(cand.clone(), &mut mdns);
        assert_eq!(
            outcome,
            FilterOutcome::Replace(FilteredIceCandidate::Public(cand))
        );
    }

    #[test]
    fn srflx_with_private_v4_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v4(192, 168, 1, 5));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::PrivateAddress),
        );
    }

    #[test]
    fn srflx_with_loopback_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v4(127, 0, 0, 1));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::LoopbackAddress),
        );
    }

    #[test]
    fn srflx_with_link_local_v4_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v4(169, 254, 1, 1));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::LinkLocalAddress),
        );
    }

    #[test]
    fn srflx_with_link_local_v6_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v6("fe80::1"));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::LinkLocalAddress),
        );
    }

    #[test]
    fn srflx_with_ula_v6_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v6("fd00::1"));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::PrivateAddress),
        );
    }

    #[test]
    fn srflx_with_multicast_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v4(224, 0, 0, 1));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::MulticastAddress),
        );
    }

    #[test]
    fn srflx_with_unspecified_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v4(0, 0, 0, 0));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::UnspecifiedAddress),
        );
    }

    #[test]
    fn srflx_with_documentation_dropped() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let cand = ice(IceCandidateType::ServerReflexive, v4(192, 0, 2, 1));
        assert_eq!(
            IceCandidateFilter::filter(cand, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::DocumentationAddress),
        );
    }

    // -- Multi-NIC edge case --

    #[test]
    fn multi_nic_each_interface_gets_its_own_mdns() {
        // Multi-NIC host: two separate Host candidates, each on a
        // different local interface. Each gets a fresh mDNS hostname;
        // no two hostnames collide.
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let c1 = ice(IceCandidateType::Host, v4(192, 168, 1, 5));
        let c2 = ice(IceCandidateType::Host, v4(10, 0, 0, 5));
        let r1 = IceCandidateFilter::filter(c1, &mut mdns);
        let r2 = IceCandidateFilter::filter(c2, &mut mdns);
        let h1 = match r1 {
            FilterOutcome::Replace(FilteredIceCandidate::Mdns { hostname, .. }) => hostname,
            _ => panic!("expected mDNS replacement for first NIC"),
        };
        let h2 = match r2 {
            FilterOutcome::Replace(FilteredIceCandidate::Mdns { hostname, .. }) => hostname,
            _ => panic!("expected mDNS replacement for second NIC"),
        };
        assert_ne!(h1, h2);
        assert_eq!(mdns.len(), 2);
    }

    #[test]
    fn multi_nic_secondary_with_public_srflx_keeps_only_public() {
        // Combined edge case: a multi-NIC host where the secondary
        // interface produces a srflx candidate. If that srflx is
        // private (interior interface), the filter drops it; if
        // public, it passes. Either way, no leak through the
        // secondary interface.
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let private_srflx = ice(IceCandidateType::ServerReflexive, v4(10, 0, 0, 5));
        let public_srflx = ice(IceCandidateType::ServerReflexive, v4(8, 8, 8, 8));
        assert!(matches!(
            IceCandidateFilter::filter(private_srflx, &mut mdns),
            FilterOutcome::Drop(IceFilterReason::PrivateAddress)
        ));
        assert!(matches!(
            IceCandidateFilter::filter(public_srflx, &mut mdns),
            FilterOutcome::Replace(FilteredIceCandidate::Public(_))
        ));
    }

    // -- mDNS partition binding (DNS-rebinding edge case) --

    #[test]
    fn mdns_resolve_returns_ip_within_owning_partition() {
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let ip = v4(192, 168, 1, 5);
        let hostname = mdns.register(ip);
        let resolved = mdns.resolve(&hostname, &pk(0));
        assert_eq!(resolved, Some(ip));
    }

    #[test]
    fn mdns_resolve_rejects_cross_partition_lookup() {
        // L35 DNS-rebinding mitigation: a different partition cannot
        // pivot on this map's registered hostnames.
        let mut mdns = MdnsHostnameMap::new(pk(0));
        let ip = v4(192, 168, 1, 5);
        let hostname = mdns.register(ip);
        let resolved = mdns.resolve(&hostname, &pk(2));
        assert_eq!(resolved, None);
    }

    #[test]
    fn mdns_resolve_unknown_hostname_returns_none() {
        let mdns = MdnsHostnameMap::new(pk(0));
        let resolved = mdns.resolve("never-registered.local", &pk(0));
        assert_eq!(resolved, None);
    }

    // -- mDNS hostname generator --

    #[test]
    fn mdns_generator_returns_uuid_local() {
        let h = MdnsHostnameGenerator::generate();
        assert!(h.ends_with(".local"));
        let uuid_part = &h[..h.len() - 6];
        // UUID v4 string form is 36 chars (8-4-4-4-12 + 4 hyphens).
        assert_eq!(uuid_part.len(), 36);
        // Parses as a UUID.
        Uuid::parse_str(uuid_part).expect("hostname prefix must parse as UUID");
    }

    #[test]
    fn mdns_generator_produces_distinct_values() {
        // CSPRNG-backed: two successive calls collide with
        // probability ~2^-122.
        let h1 = MdnsHostnameGenerator::generate();
        let h2 = MdnsHostnameGenerator::generate();
        assert_ne!(h1, h2);
    }

    // -- L27 / Display opacity --

    #[test]
    fn webrtc_deny_reason_display_is_opaque() {
        for (reason, expected) in [
            (
                WebRtcDenyReason::StrictModeDisabled,
                "webrtc: disabled in strict mode",
            ),
            (
                WebRtcDenyReason::NoPermissionGrant,
                "webrtc: no per-site permission grant",
            ),
        ] {
            let s = format!("{reason}");
            assert_eq!(s, expected);
            // Must never echo origin / hostname / IP.
            assert!(!s.contains("https://"));
            assert!(!s.contains("example"));
        }
    }

    #[test]
    fn ice_filter_reason_display_is_opaque() {
        for (reason, expected) in [
            (
                IceFilterReason::PrivateAddress,
                "ice: private address dropped",
            ),
            (
                IceFilterReason::LoopbackAddress,
                "ice: loopback address dropped",
            ),
            (
                IceFilterReason::LinkLocalAddress,
                "ice: link-local address dropped",
            ),
            (
                IceFilterReason::MulticastAddress,
                "ice: multicast address dropped",
            ),
            (
                IceFilterReason::UnspecifiedAddress,
                "ice: unspecified address dropped",
            ),
            (
                IceFilterReason::DocumentationAddress,
                "ice: documentation address dropped",
            ),
            (
                IceFilterReason::ReservedAddress,
                "ice: reserved address dropped",
            ),
        ] {
            let s = format!("{reason}");
            assert_eq!(s, expected);
            assert!(!s.contains("192.168"));
            assert!(!s.contains("127."));
        }
    }

    // -- Send + Sync --

    #[test]
    fn surface_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WebRtcConstraint>();
        assert_send_sync::<MdnsHostnameMap>();
        assert_send_sync::<IceCandidate>();
        assert_send_sync::<FilteredIceCandidate>();
        assert_send_sync::<FilterOutcome>();
        assert_send_sync::<WebRtcDecision>();
    }
}
