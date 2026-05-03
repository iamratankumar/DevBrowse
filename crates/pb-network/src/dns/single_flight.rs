//! Single-flight DNS resolution dedup, Module 20.
//!
//! Concurrent calls for the same `(partition_key, qname, qtype)` join
//! a single in-flight resolution. The first caller becomes the **leader**
//! and runs the underlying [`Resolver`]; any concurrent **follower**
//! caller registers a `oneshot::Receiver`, drops the dispatch lock, and
//! awaits the leader's result. When the leader finishes, it drains the
//! waiter list and sends the `Result` to each follower.
//!
//! ## Why this matters
//!
//!   * Anti-fingerprint: identical concurrent lookups for the same name
//!     would otherwise produce N parallel handshakes / DoH POSTs to the
//!     resolver, observable to a network attacker. Single-flight makes
//!     the resolver-side traffic match the user's logical workload.
//!   * Performance contract (README §13 perf row): "<= 256 entries per
//!     partition" cache + dedup keeps per-name resolver cost bounded
//!     even under fan-out.
//!
//! ## Cancellation behaviour
//!
//! If the leader is cancelled (its future is dropped) before it sends a
//! result, the follower's `oneshot::Receiver` resolves to `Err(_)`. The
//! follower then synthesizes [`NetworkError::Cancelled`] and returns —
//! it never silently retries, which would re-do the work the user asked
//! to abort.

use crate::dns::resolver::{ResolveQuery, ResolveResult, Resolver};
use crate::error::NetworkError;
use crate::partition_key::PartitionKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

type Key = (PartitionKey, String, u16);
type Outcome = Result<ResolveResult, NetworkError>;

/// In-flight slot held in the dispatch map. The leader owns no entry
/// here other than its presence; followers append `oneshot::Sender`s.
#[derive(Default)]
struct Slot {
    waiters: Vec<oneshot::Sender<Outcome>>,
}

/// Single-flight wrapper around any [`Resolver`].
///
/// `inner` does the actual resolution; this wrapper only mediates
/// duplicate concurrent calls. It is safe to wrap any resolver that
/// is itself `Send + Sync`.
pub struct SingleFlightResolver<R: Resolver + 'static> {
    inner: Arc<R>,
    inflight: Arc<Mutex<HashMap<Key, Slot>>>,
}

impl<R: Resolver + 'static> SingleFlightResolver<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner: Arc::new(inner),
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Number of in-flight resolution groups currently being
    /// coalesced. Diagnostic / test surface only.
    pub fn inflight_count(&self) -> usize {
        self.inflight.lock().expect("single-flight lock").len()
    }
}

impl<R: Resolver + 'static> std::fmt::Debug for SingleFlightResolver<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingleFlightResolver")
            .field("inflight", &self.inflight_count())
            .finish()
    }
}

impl<R: Resolver + 'static> Resolver for SingleFlightResolver<R> {
    fn resolve<'a>(&'a self, query: ResolveQuery) -> crate::dns::resolver::ResolveFuture<'a> {
        let key: Key = (
            query.partition_key,
            query.qname.clone(),
            query.qtype.type_code(),
        );
        let inflight = self.inflight.clone();
        let inner = self.inner.clone();

        // Fast path: register either as leader or follower while holding
        // the map lock; release the lock before any await.
        let role = {
            let mut guard = inflight.lock().expect("single-flight lock");
            if let Some(slot) = guard.get_mut(&key) {
                let (tx, rx) = oneshot::channel();
                slot.waiters.push(tx);
                Role::Follower(rx)
            } else {
                guard.insert(key.clone(), Slot::default());
                Role::Leader
            }
        };

        Box::pin(async move {
            match role {
                Role::Follower(rx) => match rx.await {
                    Ok(outcome) => outcome,
                    Err(_) => Err(NetworkError::Cancelled),
                },
                Role::Leader => {
                    let outcome = inner.resolve(query).await;
                    let waiters = {
                        let mut guard = inflight.lock().expect("single-flight lock");
                        guard.remove(&key).map(|s| s.waiters).unwrap_or_default()
                    };
                    // Fan out to followers. We clone the result for each;
                    // if there are zero followers this is a no-op.
                    for tx in waiters {
                        let _ = tx.send(outcome.clone());
                    }
                    outcome
                }
            }
        })
    }
}

enum Role {
    Leader,
    Follower(oneshot::Receiver<Outcome>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::resolver::{DnsRecord, QueryType, ResolveFuture};
    use crate::partition_key;
    use crate::Mode;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::Notify;
    use uuid::Uuid;

    fn pk(seed: u128) -> PartitionKey {
        partition_key::derive("example.com", Uuid::from_u128(seed), Uuid::from_u128(2))
    }

    fn query(qn: &str, partition: PartitionKey) -> ResolveQuery {
        ResolveQuery {
            partition_key: partition,
            qname: qn.to_string(),
            qtype: QueryType::A,
            mode: Mode::Standard,
        }
    }

    /// Counting resolver that blocks on a `Notify` until released, so a
    /// test can drive concurrent followers piling up before the leader
    /// completes.
    #[derive(Debug)]
    struct GatedResolver {
        calls: AtomicU32,
        gate: Arc<Notify>,
        outcome: Outcome,
    }

    impl GatedResolver {
        fn new(outcome: Outcome) -> (Arc<Self>, Arc<Notify>) {
            let gate = Arc::new(Notify::new());
            let r = Arc::new(Self {
                calls: AtomicU32::new(0),
                gate: gate.clone(),
                outcome,
            });
            (r, gate)
        }
    }

    impl Resolver for Arc<GatedResolver> {
        fn resolve<'a>(&'a self, _q: ResolveQuery) -> ResolveFuture<'a> {
            let me = self.clone();
            Box::pin(async move {
                me.calls.fetch_add(1, Ordering::SeqCst);
                me.gate.notified().await;
                me.outcome.clone()
            })
        }
    }

    fn ok_result() -> Outcome {
        Ok(ResolveResult {
            records: vec![DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4))],
            ttl_seconds: 60,
        })
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_inner_resolution() {
        let (inner, gate) = GatedResolver::new(ok_result());
        let sf = Arc::new(SingleFlightResolver::new(inner.clone()));

        let q = query("example.com", pk(1));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let sf = sf.clone();
            let q = q.clone();
            handles.push(tokio::spawn(async move { sf.resolve(q).await }));
        }
        // Yield until all 8 are queued. Tokio's notified().await grabs
        // a permit slot; we want them all parked first.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        // Release the gate. notify_waiters wakes only currently-parked
        // waiters; the leader is the sole one parked here because
        // followers await a oneshot (not the gate).
        gate.notify_waiters();
        let mut outcomes = Vec::new();
        for h in handles {
            outcomes.push(h.await.unwrap());
        }
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            1,
            "exactly one inner call"
        );
        for o in outcomes {
            let r = o.expect("ok");
            assert_eq!(r.records.len(), 1);
        }
        assert_eq!(sf.inflight_count(), 0, "slot freed after fan-out");
    }

    #[tokio::test]
    async fn distinct_keys_do_not_dedup() {
        let (inner, gate) = GatedResolver::new(ok_result());
        let sf = Arc::new(SingleFlightResolver::new(inner.clone()));

        let h1 = {
            let sf = sf.clone();
            let q = query("a.example.com", pk(1));
            tokio::spawn(async move { sf.resolve(q).await })
        };
        let h2 = {
            let sf = sf.clone();
            let q = query("b.example.com", pk(1));
            tokio::spawn(async move { sf.resolve(q).await })
        };
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        gate.notify_waiters();
        let _ = h1.await.unwrap();
        let _ = h2.await.unwrap();
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "different qnames produce two inner calls"
        );
    }

    #[tokio::test]
    async fn distinct_partitions_do_not_dedup() {
        let (inner, gate) = GatedResolver::new(ok_result());
        let sf = Arc::new(SingleFlightResolver::new(inner.clone()));

        let h1 = {
            let sf = sf.clone();
            let q = query("example.com", pk(1));
            tokio::spawn(async move { sf.resolve(q).await })
        };
        let h2 = {
            let sf = sf.clone();
            let q = query("example.com", pk(2));
            tokio::spawn(async move { sf.resolve(q).await })
        };
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        gate.notify_waiters();
        h1.await.unwrap().unwrap();
        h2.await.unwrap().unwrap();
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            2,
            "different partition keys produce two inner calls"
        );
    }

    #[tokio::test]
    async fn followers_observe_leader_error() {
        let (inner, gate) = GatedResolver::new(Err(NetworkError::ResolveNxDomain));
        let sf = Arc::new(SingleFlightResolver::new(inner));

        let q = query("missing.example.com", pk(1));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let sf = sf.clone();
            let q = q.clone();
            handles.push(tokio::spawn(async move { sf.resolve(q).await }));
        }
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        gate.notify_waiters();
        for h in handles {
            match h.await.unwrap() {
                Err(NetworkError::ResolveNxDomain) => {}
                other => panic!("expected NxDomain fan-out, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn slot_clears_after_leader_completes() {
        let (inner, gate) = GatedResolver::new(ok_result());
        let sf = Arc::new(SingleFlightResolver::new(inner));

        let q = query("example.com", pk(1));
        let h = {
            let sf = sf.clone();
            tokio::spawn(async move { sf.resolve(q).await })
        };
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(sf.inflight_count(), 1);
        gate.notify_waiters();
        h.await.unwrap().unwrap();
        assert_eq!(sf.inflight_count(), 0);
    }
}
