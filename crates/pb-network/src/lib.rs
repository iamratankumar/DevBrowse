//! Network process — Layer 2, Phase 4 (Modules 18–23).
//!
//! Identity-aware request routing. All DNS uses DoH; system DNS never used
//! in strict mode. Ad/tracker blocking always on for all modes.

pub mod blocklist;
pub mod coordinator;
pub mod dns;
pub mod headers;
