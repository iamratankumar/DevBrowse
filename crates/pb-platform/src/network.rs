//! NetworkAdapter — Module 2. OS-level network state only.
//!
//! NOT for HTTP. See pb-network (Modules 18–24) for connection multiplexing,
//! TLS via rustls, and request execution. This trait reports OS state that
//! pb-network reads at startup and on connectivity-change events.
//!
//! SECURITY INVARIANT — for future maintainers:
//!   `ProxyConfig::Manual { host, port }` returned from this trait MUST be
//!   pre-validated by the user-facing config layer (pb-config) before it
//!   reaches a backend. Validation includes: ASCII or punycode host, no
//!   control characters, port in 1..=65535. A backend receiving an unvalidated
//!   manual proxy must reject it, not pass it to hyper.

use crate::PlatformError;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    Online,
    Offline,
    CaptivePortal,
}

#[derive(Debug, Clone)]
pub enum ProxyConfig {
    Direct,
    System,
    /// `host` is pre-validated by pb-config (ASCII / punycode, no control chars).
    Manual {
        host: String,
        port: u16,
    },
}

pub trait NetworkAdapter: Send + Sync {
    fn connectivity(&self) -> Result<Connectivity, PlatformError>;
    fn proxy_config(&self) -> Result<ProxyConfig, PlatformError>;

    /// System-configured DNS resolvers. pb-network may override with DoH.
    fn system_dns_servers(&self) -> Result<Vec<IpAddr>, PlatformError>;
}
