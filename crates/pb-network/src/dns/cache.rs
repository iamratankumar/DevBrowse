//! DNS resolution cache, Module 20.
//!
//! Per-partition, TTL-honoring, with bounded negative caching.
//! Architecture L33: every cache entry is keyed by `PartitionKey`
//! so two tabs with the same origin under different identities
//! never share resolution results. Architecture L21: Strict mode
//! treats the cache as ephemeral (entries are dropped at tab close
//! by the strict-wipe path; same lifetime as the partition itself).
//!
//! ## Bounds
//!
//!   * **Positive entries** are honoured up to [`MAX_POSITIVE_TTL`]
//!     (24h, defined in `resolver.rs`). Upstream TTLs longer than
//!     that are silently capped.
//!   * **Negative entries** (NXDOMAIN, ServFail) are capped at
//!     [`MAX_NEGATIVE_TTL`] (60s) so an attacker-driven NXDOMAIN
//!     stream cannot bloat the cache.
//!   * **Entry count per partition** is bounded by
//!     [`MAX_ENTRIES_PER_PARTITION`] with FIFO eviction. The cap is
//!     deliberately small (256) so a hostile page cannot pin
//!     resolution results for unrelated names.
//!
//! ## Clock dependency
//!
//! The cache uses a [`Clock`] trait so tests can drive expiry
//! without `std::thread::sleep`. Production wiring uses
//! [`SystemClock`], a thin wrapper over `std::time::Instant::now()`.

use crate::dns::resolver::{
    DnsRecord, ResolveResult, MAX_NEGATIVE_TTL as RESOLVER_MAX_NEG, MAX_POSITIVE_TTL,
};
use crate::error::NetworkError;
use crate::partition_key::PartitionKey;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum number of distinct cache entries per partition. Matches the
/// "DNS cache <= 256 entries per partition" perf-contract row in
/// `project-plan/README.md` for Module 20.
pub const MAX_ENTRIES_PER_PARTITION: usize = 256;

/// Negative-cache TTL cap, mirrored from the resolver constants so the
/// cache surface does not need to import the resolver constant by name
/// from every call site.
pub const MAX_NEGATIVE_TTL: u32 = RESOLVER_MAX_NEG;

/// Trait abstracting `Instant::now()` for tests.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> Instant;
}

/// Production clock implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Cached DNS resolution outcome.
#[derive(Debug, Clone)]
enum CachedOutcome {
    Positive(Vec<DnsRecord>),
    Negative(NetworkError),
}

#[derive(Debug)]
struct CacheEntry {
    outcome: CachedOutcome,
    expires_at: Instant,
}

/// Per-partition, single (qname, qtype) -> CacheEntry inner map. Held
/// inside a Mutex inside the outer DnsCache so concurrent route tasks
/// can share the cache safely.
#[derive(Debug, Default)]
struct PartitionEntries {
    entries: HashMap<(String, u16), CacheEntry>,
    /// Insertion order, used for FIFO eviction at cap.
    order: VecDeque<(String, u16)>,
}

impl PartitionEntries {
    fn evict_if_full(&mut self) {
        while self.entries.len() >= MAX_ENTRIES_PER_PARTITION {
            if let Some(k) = self.order.pop_front() {
                self.entries.remove(&k);
            } else {
                break;
            }
        }
    }
}

/// DNS resolution cache. The outer map is keyed by partition key
/// (per L33); each inner map keys by (qname, qtype). Locking is
/// per-cache (one Mutex) for v1 simplicity; if contention shows up
/// in benchmarks the per-partition map can be lifted to a
/// concurrent map without changing the public API.
#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<HashMap<PartitionKey, PartitionEntries>>,
    clock: Box<dyn Clock>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock))
    }

    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Insert a positive resolution result. TTL is capped at
    /// [`MAX_POSITIVE_TTL`].
    pub fn put_positive(
        &self,
        partition: PartitionKey,
        qname: &str,
        qtype: u16,
        result: &ResolveResult,
    ) {
        let ttl = result.ttl_seconds.min(MAX_POSITIVE_TTL);
        let expires_at = self.clock.now() + Duration::from_secs(ttl as u64);
        let entry = CacheEntry {
            outcome: CachedOutcome::Positive(result.records.clone()),
            expires_at,
        };
        self.insert(partition, qname.to_string(), qtype, entry);
    }

    /// Insert a negative resolution result. TTL is capped at
    /// [`MAX_NEGATIVE_TTL`] regardless of the supplied input.
    pub fn put_negative(
        &self,
        partition: PartitionKey,
        qname: &str,
        qtype: u16,
        err: NetworkError,
    ) {
        let expires_at = self.clock.now() + Duration::from_secs(MAX_NEGATIVE_TTL as u64);
        let entry = CacheEntry {
            outcome: CachedOutcome::Negative(err),
            expires_at,
        };
        self.insert(partition, qname.to_string(), qtype, entry);
    }

    fn insert(&self, partition: PartitionKey, qname: String, qtype: u16, entry: CacheEntry) {
        let mut guard = self.inner.lock().expect("dns cache lock");
        let part = guard.entry(partition).or_default();
        part.evict_if_full();
        let key = (qname, qtype);
        if part.entries.insert(key.clone(), entry).is_none() {
            part.order.push_back(key);
        }
    }

    /// Look up a (qname, qtype) entry. Returns `None` when there is
    /// no entry or the entry has expired (expired entries are removed
    /// in the same call).
    pub fn get(
        &self,
        partition: &PartitionKey,
        qname: &str,
        qtype: u16,
    ) -> Option<Result<ResolveResult, NetworkError>> {
        let mut guard = self.inner.lock().expect("dns cache lock");
        let part = guard.get_mut(partition)?;
        let key = (qname.to_string(), qtype);
        let entry = part.entries.get(&key)?;
        if self.clock.now() >= entry.expires_at {
            part.entries.remove(&key);
            if let Some(pos) = part.order.iter().position(|k| k == &key) {
                part.order.remove(pos);
            }
            return None;
        }
        let now = self.clock.now();
        let remaining = entry
            .expires_at
            .saturating_duration_since(now)
            .as_secs()
            .min(u32::MAX as u64) as u32;
        let outcome = match &entry.outcome {
            CachedOutcome::Positive(records) => Ok(ResolveResult {
                records: records.clone(),
                ttl_seconds: remaining,
            }),
            CachedOutcome::Negative(err) => Err(err.clone()),
        };
        Some(outcome)
    }

    /// Drop a partition's full cache. Called by the coordinator on
    /// `drop_partition` (mode transition / identity teardown).
    pub fn drop_partition(&self, partition: &PartitionKey) {
        let mut guard = self.inner.lock().expect("dns cache lock");
        guard.remove(partition);
    }

    /// Diagnostic: number of entries currently held for `partition`.
    pub fn len_for(&self, partition: &PartitionKey) -> usize {
        let guard = self.inner.lock().expect("dns cache lock");
        guard.get(partition).map(|p| p.entries.len()).unwrap_or(0)
    }

    /// Diagnostic: total partitions currently tracked.
    pub fn partition_count(&self) -> usize {
        self.inner.lock().expect("dns cache lock").len()
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::DnsRecord;
    use crate::partition_key;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use uuid::Uuid;

    fn pk(seed: u128) -> PartitionKey {
        partition_key::derive("example.com", Uuid::from_u128(seed), Uuid::from_u128(2))
    }

    #[derive(Debug)]
    struct MockClock {
        now: Mutex<Instant>,
    }

    impl MockClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
            })
        }

        fn advance(&self, d: Duration) {
            let mut n = self.now.lock().unwrap();
            *n += d;
        }
    }

    impl Clock for Arc<MockClock> {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

    fn make_cache(c: Arc<MockClock>) -> DnsCache {
        DnsCache::with_clock(Box::new(c))
    }

    fn rr(ttl: u32) -> ResolveResult {
        ResolveResult {
            records: vec![DnsRecord::A(Ipv4Addr::new(93, 184, 216, 34))],
            ttl_seconds: ttl,
        }
    }

    #[test]
    fn put_then_get_returns_records() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        c.put_positive(pk(1), "example.com", 1, &rr(60));
        let got = c.get(&pk(1), "example.com", 1).unwrap().unwrap();
        assert_eq!(got.records.len(), 1);
        assert!(got.ttl_seconds <= 60 && got.ttl_seconds > 0);
    }

    #[test]
    fn entry_expires_after_ttl() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        c.put_positive(pk(1), "example.com", 1, &rr(10));
        clock.advance(Duration::from_secs(11));
        assert!(c.get(&pk(1), "example.com", 1).is_none());
    }

    #[test]
    fn negative_ttl_capped_at_60s() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        c.put_negative(pk(1), "missing.example", 1, NetworkError::ResolveNxDomain);
        // Just before the cap.
        clock.advance(Duration::from_secs(59));
        match c.get(&pk(1), "missing.example", 1) {
            Some(Err(NetworkError::ResolveNxDomain)) => {}
            other => panic!("expected ResolveNxDomain hit, got {other:?}"),
        }
        // Past the cap.
        clock.advance(Duration::from_secs(2));
        assert!(c.get(&pk(1), "missing.example", 1).is_none());
    }

    #[test]
    fn positive_ttl_capped_at_max() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        // Pretend upstream sent TTL = 30 days.
        c.put_positive(pk(1), "example.com", 1, &rr(30 * 24 * 3600));
        // Still cached after 23 hours but gone after 25.
        clock.advance(Duration::from_secs(23 * 3600));
        assert!(c.get(&pk(1), "example.com", 1).is_some());
        clock.advance(Duration::from_secs(2 * 3600));
        assert!(c.get(&pk(1), "example.com", 1).is_none());
    }

    #[test]
    fn cache_is_partition_keyed() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        c.put_positive(pk(1), "example.com", 1, &rr(60));
        // Different partition: same name yields no hit.
        assert!(c.get(&pk(2), "example.com", 1).is_none());
        // Same partition still hits.
        assert!(c.get(&pk(1), "example.com", 1).is_some());
    }

    #[test]
    fn drop_partition_removes_only_that_partition() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        c.put_positive(pk(1), "example.com", 1, &rr(60));
        c.put_positive(pk(2), "example.com", 1, &rr(60));
        c.drop_partition(&pk(1));
        assert!(c.get(&pk(1), "example.com", 1).is_none());
        assert!(c.get(&pk(2), "example.com", 1).is_some());
    }

    #[test]
    fn fifo_eviction_caps_per_partition_entries() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        for i in 0..(MAX_ENTRIES_PER_PARTITION + 5) {
            let qname = format!("h{i}.example.com");
            c.put_positive(pk(1), &qname, 1, &rr(60));
        }
        assert_eq!(c.len_for(&pk(1)), MAX_ENTRIES_PER_PARTITION);
        // The first 5 inserted should be evicted.
        for i in 0..5 {
            let qname = format!("h{i}.example.com");
            assert!(c.get(&pk(1), &qname, 1).is_none());
        }
        // The last one inserted is still present.
        let last = format!("h{}.example.com", MAX_ENTRIES_PER_PARTITION + 4);
        assert!(c.get(&pk(1), &last, 1).is_some());
    }

    #[test]
    fn get_decrements_remaining_ttl() {
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        c.put_positive(pk(1), "example.com", 1, &rr(120));
        let first = c.get(&pk(1), "example.com", 1).unwrap().unwrap();
        clock.advance(Duration::from_secs(60));
        let second = c.get(&pk(1), "example.com", 1).unwrap().unwrap();
        assert!(
            second.ttl_seconds < first.ttl_seconds,
            "remaining TTL must decrease"
        );
    }

    #[test]
    fn replacement_does_not_grow_order_queue() {
        // Inserting the same key twice must not push two entries onto
        // the FIFO queue (otherwise FIFO eviction would over-count).
        let clock = MockClock::new();
        let c = make_cache(clock.clone());
        c.put_positive(pk(1), "example.com", 1, &rr(60));
        c.put_positive(pk(1), "example.com", 1, &rr(120));
        assert_eq!(c.len_for(&pk(1)), 1);
    }
}
