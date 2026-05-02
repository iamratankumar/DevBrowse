//! LAN discovery — Module 86.
//!
//! mDNS / DNS-SD service announce + browse. A DevBrowse instance with
//! at least one paired peer publishes a service record on the local
//! network. Other paired peers in the same cluster see the announcement,
//! resolve the device's current IP, and connect via Module 88.
//!
//! Discovery is also how the pairing flow (Module 87) shows a list of
//! "devices waiting to pair on this network" before any cryptographic
//! identity has been established.
//!
//! TODO(Module 86):
//!   * Service type: pick a stable label (e.g. `_devbrowse._udp.local.`)
//!     and document it; all clusters everywhere use the same label.
//!     Cluster membership is enforced cryptographically (pairing), not
//!     by service-name uniqueness.
//!   * TXT record carries: protocol_version, device_id (Ed25519 pubkey
//!     fingerprint, NOT pubkey itself), advertised pairing-state flag.
//!   * Two service modes. "synced peer" announces a device's identity
//!     so paired peers can resolve and reconnect. "pairing slot"
//!     announces a temporary identity only while the user has an
//!     active 6-digit pairing code (Module 87); withdrawn the moment
//!     pairing finishes or the code expires.
//!   * No persistent identifiers in the announcement (rotating
//!     short-lived nonces) so an attacker cannot fingerprint the user
//!     by mDNS traffic alone.
//!   * Cross-platform mDNS: the `mdns-sd` crate is the current pick.
//!     iOS uses NetService for App Store compatibility; abstract
//!     behind a trait so the platform-specific implementation drops
//!     in without changing callers (cross-platform principle from
//!     CLAUDE.md feedback).
