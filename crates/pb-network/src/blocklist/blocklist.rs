//! Live blocklist wrapper with atomic hot-swap, Module 21.
//!
//! Holds the compiled [`RadixTree`] (host rules), the
//! [`UrlParamStripList`] (L32), and the cookie-banner sub-track
//! (L37) behind a single `RwLock<Arc<...>>` so that:
//!
//!   * **Reads** clone the inner `Arc` under the read lock and drop
//!     the guard before doing any matching work — the lock is held
//!     for one atomic-increment's worth of time.
//!   * **Writes** (the scheduler / loader, ~once per hour) take the
//!     write lock, build the new state, swap the inner `Arc`, and
//!     drop the guard. Active matchers holding old `Arc`s finish
//!     against the old tree, which is safe (immutable) and bounded
//!     in lifetime.
//!
//! The "drop the guard before matching" pattern is what keeps the
//! match path off any lock at all in the steady state, satisfying
//! the < 100 µs P99 perf budget without arc-swap as a dep.
//!
//! ## Initial state
//!
//! [`Blocklist::empty`] returns a wrapper whose host tree, URL strip
//! list, and cookie-banner list are all empty. The route path
//! against an empty blocklist always returns `None` from
//! `match_host` — i.e. the network broker is fail-open until the
//! scheduler lands a real manifest. This is intentional: a startup
//! that fails to load a blocklist must not break navigation, only
//! lose its anti-tracking benefit. The scheduler emits a Module 11
//! warning when this happens (TODO: warning subscriber).

use crate::blocklist::events::{BlockEventSink, NoopSink};
use crate::blocklist::radix_tree::RadixTree;
use crate::blocklist::rule::{BlockKind, CookieBannerRule, Manifest};
use crate::blocklist::url_strip::UrlParamStripList;
use std::sync::{Arc, RwLock};

/// Snapshot of all three sub-tracks. Held inside the [`Blocklist`]
/// behind a write-lock so the scheduler can swap all three together.
#[derive(Debug)]
struct State {
    hosts: Arc<RadixTree>,
    url_strip: Arc<UrlParamStripList>,
    cookie_banner: Arc<Vec<CookieBannerRule>>,
    content_version: u64,
}

impl State {
    fn empty() -> Self {
        Self {
            hosts: Arc::new(RadixTree::empty()),
            url_strip: Arc::new(UrlParamStripList::empty()),
            cookie_banner: Arc::new(Vec::new()),
            content_version: 0,
        }
    }

    fn from_manifest(m: &Manifest) -> Self {
        Self {
            hosts: Arc::new(RadixTree::from_rules(&m.host_rules)),
            url_strip: Arc::new(UrlParamStripList::from_rules(&m.url_param_rules)),
            cookie_banner: Arc::new(m.cookie_banner_rules.clone()),
            content_version: m.content_version,
        }
    }
}

/// Live blocklist held by the network coordinator. Cloning the
/// outer `Arc<Blocklist>` is the canonical way to share the live
/// view across tasks.
pub struct Blocklist {
    state: RwLock<State>,
    sink: RwLock<Arc<dyn BlockEventSink>>,
}

impl Blocklist {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(State::empty()),
            sink: RwLock::new(Arc::new(NoopSink)),
        })
    }

    pub fn from_manifest(m: &Manifest) -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(State::from_manifest(m)),
            sink: RwLock::new(Arc::new(NoopSink)),
        })
    }

    /// Replace the live state with one built from `m`. Returns the
    /// previous content version for diagnostic surfaces (the
    /// scheduler logs it when verifying that it picked up a fresher
    /// manifest).
    pub fn swap(&self, m: &Manifest) -> u64 {
        let new_state = State::from_manifest(m);
        let mut guard = self.state.write().expect("blocklist write");
        let prev = guard.content_version;
        *guard = new_state;
        prev
    }

    /// Wire a [`BlockEventSink`] (Module 60 in production; tests
    /// inject a capturing sink). Replacing the sink while routes are
    /// in flight is safe — every emit pulls a fresh `Arc` clone.
    pub fn set_sink(&self, sink: Arc<dyn BlockEventSink>) {
        let mut guard = self.sink.write().expect("blocklist sink write");
        *guard = sink;
    }

    /// Match a hostname against the host-rule tree.
    pub fn match_host(&self, host: &str) -> Option<BlockKind> {
        let tree = {
            let g = self.state.read().expect("blocklist read");
            g.hosts.clone()
        };
        tree.match_host(host)
    }

    /// Snapshot of the current URL-param strip list. Cheap to call
    /// (one `Arc` clone); held by the route-path stage so a single
    /// snapshot covers the whole strip pass.
    pub fn url_param_strip_list(&self) -> Arc<UrlParamStripList> {
        self.state.read().expect("blocklist read").url_strip.clone()
    }

    /// Snapshot of the cookie-banner rule list (L37). Stub
    /// consumer — the renderer-side script (later phase) will pull
    /// this when the wizard recorded an opt-in.
    pub fn cookie_banner_rules(&self) -> Arc<Vec<CookieBannerRule>> {
        self.state
            .read()
            .expect("blocklist read")
            .cookie_banner
            .clone()
    }

    /// Diagnostic: monotonic content version of the live manifest.
    pub fn content_version(&self) -> u64 {
        self.state.read().expect("blocklist read").content_version
    }

    /// Diagnostic: number of host rules in the live tree.
    pub fn host_rule_count(&self) -> usize {
        let tree = {
            let g = self.state.read().expect("blocklist read");
            g.hosts.clone()
        };
        tree.rule_count()
    }

    /// Snapshot of the current event sink. Used by the route-path
    /// stage to fan a `BlockedEvent` out to subscribers without
    /// holding any lock during the fan-out.
    pub fn sink(&self) -> Arc<dyn BlockEventSink> {
        self.sink.read().expect("blocklist sink read").clone()
    }
}

impl std::fmt::Debug for Blocklist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blocklist")
            .field("content_version", &self.content_version())
            .field("host_rule_count", &self.host_rule_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::events::CapturingSink;
    use crate::blocklist::rule::{BlockKind, Rule, UrlParamRule};
    use crate::partition_key;
    use uuid::Uuid;

    fn manifest_v1() -> Manifest {
        Manifest {
            format_version: 1,
            content_version: 1,
            generated_at_unix: 1_700_000_000,
            host_rules: vec![
                Rule::host("ads.example.com", BlockKind::Ad),
                Rule::host("tracker.example.org", BlockKind::Tracker),
            ],
            url_param_rules: vec![UrlParamRule::new("utm_source")],
            cookie_banner_rules: vec![],
        }
    }

    fn manifest_v2() -> Manifest {
        Manifest {
            format_version: 1,
            content_version: 2,
            generated_at_unix: 1_700_003_600,
            host_rules: vec![Rule::host("evil.example", BlockKind::FingerprintAttempt)],
            url_param_rules: vec![UrlParamRule::new("gclid")],
            cookie_banner_rules: vec![],
        }
    }

    #[test]
    fn empty_blocklist_matches_nothing() {
        let bl = Blocklist::empty();
        assert!(bl.match_host("ads.example.com").is_none());
        assert_eq!(bl.host_rule_count(), 0);
        assert_eq!(bl.content_version(), 0);
    }

    #[test]
    fn from_manifest_populates_all_tracks() {
        let bl = Blocklist::from_manifest(&manifest_v1());
        assert_eq!(bl.match_host("ads.example.com"), Some(BlockKind::Ad));
        assert_eq!(
            bl.match_host("tracker.example.org"),
            Some(BlockKind::Tracker)
        );
        assert!(bl.url_param_strip_list().contains("utm_source"));
        assert_eq!(bl.content_version(), 1);
        assert_eq!(bl.host_rule_count(), 2);
    }

    #[test]
    fn swap_replaces_all_tracks_atomically() {
        let bl = Blocklist::from_manifest(&manifest_v1());
        let prev = bl.swap(&manifest_v2());
        assert_eq!(prev, 1);
        // v1 rules gone, v2 rules present.
        assert!(bl.match_host("ads.example.com").is_none());
        assert_eq!(
            bl.match_host("evil.example"),
            Some(BlockKind::FingerprintAttempt)
        );
        assert!(!bl.url_param_strip_list().contains("utm_source"));
        assert!(bl.url_param_strip_list().contains("gclid"));
        assert_eq!(bl.content_version(), 2);
    }

    #[test]
    fn swap_to_empty_manifest_clears_state() {
        let bl = Blocklist::from_manifest(&manifest_v1());
        bl.swap(&Manifest::empty());
        assert_eq!(bl.host_rule_count(), 0);
        assert_eq!(bl.content_version(), 0);
        assert!(bl.match_host("ads.example.com").is_none());
    }

    #[test]
    fn match_host_drops_lock_before_matching() {
        // Smoke test: holding two `Arc<Blocklist>` clones and matching
        // concurrently doesn't deadlock.
        let bl = Blocklist::from_manifest(&manifest_v1());
        let bl2 = bl.clone();
        let h = std::thread::spawn(move || bl2.match_host("ads.example.com"));
        let local = bl.match_host("ads.example.com");
        let other = h.join().unwrap();
        assert_eq!(local, Some(BlockKind::Ad));
        assert_eq!(other, Some(BlockKind::Ad));
    }

    #[test]
    fn set_sink_replaces_active_sink() {
        let bl = Blocklist::from_manifest(&manifest_v1());
        let sink = Arc::new(CapturingSink::default());
        bl.set_sink(sink.clone());
        let pk = partition_key::derive("example.com", Uuid::from_u128(1), Uuid::from_u128(2));
        bl.sink().on_block(crate::blocklist::events::BlockedEvent {
            kind: BlockKind::Ad,
            partition_key: pk,
        });
        assert_eq!(sink.len(), 1);
    }
}
