//! DNS rebinding mitigation, Module 20.
//!
//! Architecture context:
//!   * §3.5 / L33 — every outbound carries a partition key; cross-
//!     partition state reuse is impossible by construction.
//!   * L35 — WebRTC ICE candidates use mDNS hostnames only; private /
//!     link-local addresses never reach JS.
//!   * Module 20 (this filter) — DNS resolution responses are filtered
//!     so a public-facing name cannot resolve to a private address
//!     mid-session ("DNS rebinding"), which would let an external
//!     attacker pivot a victim's browser into the LAN.
//!
//! The filter is conservative: any response containing a private,
//! loopback, link-local, multicast, or unspecified address is
//! rejected as a whole. We do not "fall back" to remaining records
//! because a hostile resolver can always interleave a public address
//! with a private one to bypass partial filtering — the safer policy
//! is "any private address poisons the answer".
//!
//! ## Allow-listing for local development
//!
//! v1 ships no allow-list path. Self-hosted services on `localhost`
//! or RFC1918 ranges that the user wants to reach via a public-facing
//! name require an explicit override. The override surface lives in
//! Module 25 / 59 (per-site permission) when WebRTC and similar
//! features land; until then, hand-edited `/etc/hosts` is the
//! supported escape hatch and the filter is unconditional.
//
// TODO(Module 25): expose an allow-list hook for self-hosted local
//   services once the per-site permission center surface lands.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Address class for [`classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// Globally routable (or unrecognized — treated as public for the
    /// purpose of rebinding mitigation, which is a defense in depth
    /// against the LAN-pivot shape, not a complete public-IP test).
    Public,
    Loopback,
    LinkLocal,
    Private,
    Multicast,
    Unspecified,
    Documentation,
    Reserved,
}

impl AddressClass {
    /// True for every class the rebinding filter rejects in production.
    pub fn is_rejected(self) -> bool {
        !matches!(self, Self::Public)
    }
}

/// Classify an [`IpAddr`] for the rebinding filter.
pub fn classify(addr: IpAddr) -> AddressClass {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(v4: Ipv4Addr) -> AddressClass {
    if v4.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if v4.is_loopback() {
        return AddressClass::Loopback;
    }
    if v4.is_link_local() {
        return AddressClass::LinkLocal;
    }
    if v4.is_private() {
        return AddressClass::Private;
    }
    if v4.is_multicast() {
        return AddressClass::Multicast;
    }
    if v4.is_broadcast() {
        return AddressClass::Reserved;
    }
    if v4.is_documentation() {
        return AddressClass::Documentation;
    }
    let octets = v4.octets();
    // 100.64.0.0/10 — Carrier-grade NAT (RFC 6598). Treat as Private.
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return AddressClass::Private;
    }
    // 0.0.0.0/8 (already covered by unspecified for 0.0.0.0; rest reserved).
    if octets[0] == 0 {
        return AddressClass::Reserved;
    }
    AddressClass::Public
}

fn classify_v6(v6: Ipv6Addr) -> AddressClass {
    if v6.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if v6.is_loopback() {
        return AddressClass::Loopback;
    }
    if v6.is_multicast() {
        return AddressClass::Multicast;
    }
    let segs = v6.segments();
    // fe80::/10 — Link-Local Unicast (RFC 4291).
    if (segs[0] & 0xFFC0) == 0xFE80 {
        return AddressClass::LinkLocal;
    }
    // fc00::/7 — Unique Local (RFC 4193).
    if (segs[0] & 0xFE00) == 0xFC00 {
        return AddressClass::Private;
    }
    // 2001:db8::/32 — Documentation (RFC 3849).
    if segs[0] == 0x2001 && segs[1] == 0x0DB8 {
        return AddressClass::Documentation;
    }
    AddressClass::Public
}

/// True if the address is safe to expose to the request-dispatch path.
/// Equivalent to `!classify(addr).is_rejected()`.
pub fn is_public(addr: IpAddr) -> bool {
    !classify(addr).is_rejected()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn classifies_public_v4() {
        assert_eq!(classify(v4(93, 184, 216, 34)), AddressClass::Public);
        assert_eq!(classify(v4(8, 8, 8, 8)), AddressClass::Public);
    }

    #[test]
    fn classifies_loopback_v4() {
        assert_eq!(classify(v4(127, 0, 0, 1)), AddressClass::Loopback);
    }

    #[test]
    fn classifies_unspecified_v4() {
        assert_eq!(classify(v4(0, 0, 0, 0)), AddressClass::Unspecified);
    }

    #[test]
    fn classifies_link_local_v4() {
        assert_eq!(classify(v4(169, 254, 1, 1)), AddressClass::LinkLocal);
    }

    #[test]
    fn classifies_rfc1918_v4() {
        assert_eq!(classify(v4(10, 0, 0, 1)), AddressClass::Private);
        assert_eq!(classify(v4(172, 16, 0, 1)), AddressClass::Private);
        assert_eq!(classify(v4(192, 168, 1, 1)), AddressClass::Private);
    }

    #[test]
    fn classifies_rfc6598_carrier_grade_nat() {
        // 100.64.0.0/10 — outside RFC1918 but still effectively LAN.
        assert_eq!(classify(v4(100, 64, 0, 1)), AddressClass::Private);
        assert_eq!(classify(v4(100, 127, 255, 254)), AddressClass::Private);
    }

    #[test]
    fn classifies_documentation_v4() {
        // TEST-NET-1 is 192.0.2.0/24.
        assert_eq!(classify(v4(192, 0, 2, 7)), AddressClass::Documentation);
    }

    #[test]
    fn classifies_reserved_zero_block() {
        assert_eq!(classify(v4(0, 1, 2, 3)), AddressClass::Reserved);
    }

    #[test]
    fn classifies_broadcast_v4() {
        assert_eq!(classify(v4(255, 255, 255, 255)), AddressClass::Reserved);
    }

    #[test]
    fn classifies_multicast_v4() {
        assert_eq!(classify(v4(224, 0, 0, 1)), AddressClass::Multicast);
    }

    #[test]
    fn classifies_public_v6() {
        // 2606:4700:4700::1111 (Cloudflare DNS).
        assert_eq!(classify(v6("2606:4700:4700::1111")), AddressClass::Public);
    }

    #[test]
    fn classifies_loopback_v6() {
        assert_eq!(classify(v6("::1")), AddressClass::Loopback);
    }

    #[test]
    fn classifies_link_local_v6() {
        assert_eq!(classify(v6("fe80::1")), AddressClass::LinkLocal);
    }

    #[test]
    fn classifies_ula_v6() {
        // Unique-local: fc00::/7 — both fc.. and fd.. blocks.
        assert_eq!(classify(v6("fd00::1")), AddressClass::Private);
        assert_eq!(classify(v6("fc00::1")), AddressClass::Private);
    }

    #[test]
    fn classifies_documentation_v6() {
        assert_eq!(classify(v6("2001:db8::1")), AddressClass::Documentation);
    }

    #[test]
    fn classifies_unspecified_v6() {
        assert_eq!(classify(v6("::")), AddressClass::Unspecified);
    }

    #[test]
    fn is_public_only_passes_public() {
        assert!(is_public(v4(93, 184, 216, 34)));
        assert!(!is_public(v4(127, 0, 0, 1)));
        assert!(!is_public(v4(192, 168, 1, 1)));
        assert!(!is_public(v6("fe80::1")));
        assert!(is_public(v6("2606:4700:4700::1111")));
    }

    #[test]
    fn is_rejected_helper_inverts() {
        assert!(!AddressClass::Public.is_rejected());
        assert!(AddressClass::Private.is_rejected());
        assert!(AddressClass::Loopback.is_rejected());
        assert!(AddressClass::LinkLocal.is_rejected());
        assert!(AddressClass::Multicast.is_rejected());
        assert!(AddressClass::Unspecified.is_rejected());
        assert!(AddressClass::Documentation.is_rejected());
        assert!(AddressClass::Reserved.is_rejected());
    }
}
