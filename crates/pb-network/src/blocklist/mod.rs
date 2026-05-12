//! Always-on blocklist subsystem (Module 21).
//!
//! Three sub-tracks ship through one Module 67 update channel:
//!
//!   * **Host rules** -> [`RadixTree`] + [`Blocklist::match_host`]
//!     classify outbound requests as Ad / Tracker /
//!     FingerprintAttempt (L26).
//!   * **URL parameter strip list** -> [`UrlParamStripList`] +
//!     [`url_strip::strip_tracking_params`] remove known tracker
//!     params (L32) at the broker before any other route stage.
//!   * **Cookie-banner auto-decline rules** -> [`CookieBannerRule`]
//!     ship through the same channel; renderer-side consumption
//!     lands in a later phase (L37, wizard opt-in).
//!
//! Architecture invariants enforced here:
//!   * **L26** classified events emitted to a [`BlockEventSink`].
//!   * **L27** all error / debug strings opaque (no qname / URL /
//!     selector leakage).
//!   * **L32** URL-param strip is part of the route order (between
//!     blocklist match and header scrub per Module 19 spec).
//!   * **L33** match operates on the raw hostname; partition keying
//!     happens elsewhere (the coordinator wraps both stages).

#[allow(clippy::module_inception)]
pub mod blocklist;
pub mod events;
pub mod loader;
pub mod radix_tree;
pub mod rule;
pub mod scheduler;
pub mod url_strip;

pub use blocklist::Blocklist;
pub use events::{BlockEventSink, BlockedEvent, CapturingSink, NoopSink};
pub use loader::{InMemoryLoader, LoadFuture, Loader, LoaderError, SignedManifestLoader};
pub use radix_tree::RadixTree;
pub use rule::{BlockKind, CookieBannerRule, Manifest, Rule, UrlParamRule};
pub use scheduler::{
    spawn as spawn_scheduler, tick_once, warning_codes, CapturingWarningSink, NoopWarningSink,
    SchedulerHandle, TickOutcome, WarningSink, REFRESH_INTERVAL, REFRESH_JITTER,
};
pub use url_strip::{
    strip_tracking_params, UrlParamStripList, DEFAULT_TRACKING_PARAMS, MAX_STRIPPABLE_URL_LEN,
};
