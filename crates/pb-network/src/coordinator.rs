//! Network broker coordinator, Module 19.
//!
//! Process bootstrap and request-routing entry point for `pb-network`.
//! Every outbound HTTP(S), DoH, and (eventually) WebRTC call passes
//! through this coordinator. Single ownership of:
//!
//!   * the per-partition egress state map (cache / DNS cache / connection
//!     pool / ALT-SVC / HSTS pin set, all keyed by [`PartitionKey`] per
//!     L33 — §3.5)
//!   * the route-by-partition-key dispatch table (Modules 20-25 plug in
//!     via the trait-object slots on this struct)
//!   * the §5.2 mirror partition-key gatekeeping (mirrored from
//!     `pb_storage::gatekeeper`; pb-network cannot import pb-storage per
//!     §4.1, see [`crate::partition_key`])
//!
//! ## Architecture invariants enforced here
//!
//!   * **§3.5 / §5.2 (mirrored):** partition keys are recomputed from
//!     orchestrator-supplied tab metadata on every request and compared
//!     to the renderer-declared key. The renderer is never trusted for
//!     identity context.
//!   * **L30 HTTPS-Only:** any `http://` outbound that did not arrive
//!     with `downgrade_approved == true` (set only by the user-confirm
//!     modal in pb-ui) is rejected with [`NetworkError::HttpsOnlyDowngrade`].
//!     There is no silent downgrade path.
//!   * **L33 network-state isolation:** per-partition egress state is
//!     keyed by [`PartitionKey`]; two tabs with the same origin but
//!     different identities never share network state. Mode-transition
//!     (§3.6 Standard → Strict) calls [`NetworkCoordinator::drop_partition`]
//!     to mint a fresh egress state for the new partition.
//!   * **L27 forensic redaction:** every [`NetworkError`] Display is
//!     opaque (see `error.rs`). Source-chain detail is reachable only
//!     for trusted in-process tracing.
//!
//! ## Per-partition pool sizing
//!
//! `MAX_PARTITIONS` is **16** (perf budget Module 19, README §13). On
//! overflow the coordinator drops the least-recently-used partition's
//! egress state. Active in-flight requests for an evicted partition are
//! not interrupted (they own [`Arc`] handles to whatever sub-system
//! state they pulled at route time); only fresh lookups for the evicted
//! partition rebuild fresh egress state, which is correct: the §3.5 rule
//! is per-request derivation, no fast paths.
//!
//! ## v1 scope
//!
//! v1 ships:
//!   * partition-key authorize + L30 HTTPS-Only enforcement
//!   * per-partition egress state map with bounded LRU eviction
//!   * mode-transition drop hook
//!   * trait-object slots for Modules 20-24 (currently `None`); when a
//!     slot is `None`, the corresponding route-order step is a no-op
//!     and the request envelope passes through unchanged
//!   * cancellation flag plumbed through the route path so a tab close
//!     mid-flight produces [`NetworkError::Cancelled`] without doing I/O
//!
//! v1 does **not** ship the IPC accept loop (`IpcListener::accept`) —
//! that is wired by Module 80 (orchestrator), which owns the listener
//! and dispatches received `NetworkRequest` envelopes into
//! [`NetworkCoordinator::route`]. The coordinator is `Send + Sync` and
//! lives behind `Arc<tokio::sync::Mutex<_>>` so the orchestrator can
//! share it across accept tasks.
//
// TODO(Module 80): orchestrator owns the `IpcListener` and the
//   `Arc<Mutex<NetworkCoordinator>>`. Per-accept tasks deserialize the
//   `NetworkRequest` protobuf, attach orchestrator-held tab metadata
//   (identity_profile_id / context_id / declared_key / mode), and call
//   `route()`. The orchestrator also wires the live ChainValidator
//   (Modules 23.1 + 23.2 + 23.3 + 24.1, all live) into a coordinator-
//   level `tls` slot at the same boot step; today that validator is
//   consumed directly by the DoH transport (Module 20) and via
//   `crate::ChainValidator::default()` everywhere else, so a single
//   pinned ClientHello reaches every TLS site even before the slot
//   lands here.
// TODO(Module 23.4): once the signed preload track ships in Module 68,
//   wire `HstsSlot` lookups against it; the slot is already on
//   `EgressState` (per L33).
// TODO(Module 25 wiring): WebRTC constraint surface is in
//   `crate::webrtc`. The constraint is consulted at the renderer-broker
//   boundary (separate from `route()`), so a coordinator-level slot is
//   only needed once the orchestrator wants one shared instance — that
//   ride-along lands with Module 80.
// TODO(Module 60): network viewer subscribes to per-request classified
//   events; wire an event channel here once the viewer surface lands.

use crate::blocklist::events::BlockedEvent;
use crate::blocklist::url_strip::strip_tracking_params;
use crate::blocklist::Blocklist;
use crate::dns::fallback::FallbackPolicy;
use crate::dns::resolver::{QueryType, ResolveQuery, ResolveResult, Resolver};
use crate::dns::DnsCache;
use crate::error::NetworkError;
use crate::headers::{self, HeaderPolicy};
use crate::partition_key::{self, PartitionKey};
use pb_config::{Config, Mode as ConfigMode, NetworkConfig};
use pb_sandbox::{SandboxClass, SandboxProfile};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Maximum number of distinct partitions tracked in the egress map.
/// Documented in the perf-contract row for Module 19 in `project-plan/README.md`.
pub const MAX_PARTITIONS: usize = 16;

/// Network-side privacy mode. Mirrors `pb_config::Mode` so the coordinator
/// does not leak the config enum into IPC-shaped types. Conversion is
/// trivial and explicit; pb-network does not depend on the IPC enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Standard,
    Strict,
}

impl From<ConfigMode> for Mode {
    fn from(m: ConfigMode) -> Self {
        match m {
            ConfigMode::Standard => Mode::Standard,
            ConfigMode::Strict => Mode::Strict,
        }
    }
}

/// Bridge to OS-level network state (proxy config, system DNS for
/// the wizard-gated Standard fallback, connectivity events).
///
/// `pb-network` cannot import `pb-platform` per §4.1, so the bridging
/// impl lives in the orchestrator binary (`pb-browser`), which has
/// access to both crates. v1 keeps the trait empty so the API surface
/// is shaped now and Module 20 (DoH) can extend it without breaking
/// callers.
pub trait PlatformContext: Send + Sync + fmt::Debug {}

/// Cancellation flag plumbed onto every [`Request`]. The lifecycle layer
/// (Module 80, tab close) flips this to `true`; the coordinator checks
/// at every phase boundary in [`NetworkCoordinator::route`].
///
/// v1 uses an `Arc<AtomicBool>`. Future versions may swap to
/// `tokio_util::sync::CancellationToken` for awaiter wake-up; the
/// public API surface (`new`, `cancel`, `is_cancelled`) stays the same.
#[derive(Debug, Clone, Default)]
pub struct CancellationFlag(Arc<AtomicBool>);

impl CancellationFlag {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Outbound network request envelope crossing the coordinator.
///
/// Fields fall into two groups:
///
///   * **Identity context** (`site_origin`, `identity_profile_id`,
///     `context_id`, `declared_key`, `mode`): supplied by the
///     orchestrator from trusted tab state. The coordinator recomputes
///     `declared_key` from `(site_origin, identity_profile_id,
///     context_id)` and rejects on mismatch (§5.2 mirror).
///   * **Request payload** (`url`, `method`, `headers`, `body`): may
///     originate from the renderer and is therefore untrusted until
///     each transformation phase has run.
///
/// `downgrade_approved` is the L30 user-confirm-modal stamp; only
/// pb-ui sets it `true`. Renderers cannot influence this field —
/// they never reach the in-process [`Request`] type, only the
/// `pb_ipc::NetworkRequest` protobuf which has no such field.
#[derive(Debug, Clone)]
pub struct Request {
    pub site_origin: String,
    pub identity_profile_id: Uuid,
    pub context_id: Uuid,
    pub declared_key: PartitionKey,
    pub mode: Mode,
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// L30: only `true` when the user clicked through the explicit
    /// HTTPS-Only downgrade confirmation modal in pb-ui for the host
    /// of `url`. Default `false`. Renderers cannot set this.
    pub downgrade_approved: bool,
    pub cancel: CancellationFlag,
}

/// Output of [`NetworkCoordinator::route`]. v1 carries the canonical
/// authorized partition key, the (possibly upgraded) final URL, and the
/// mode under which the request will be dispatched. Modules 20-25 will
/// extend this type with sub-system decisions (resolved addresses,
/// TLS session tickets, etc.) as they wire into the route order.
#[derive(Debug, Clone)]
pub struct RoutedRequest {
    pub partition_key: PartitionKey,
    pub mode: Mode,
    pub final_url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Per-partition egress state. Slots are typed as they wire in; v1
/// of Module 19 shipped placeholders, Module 20 replaced the
/// `dns_cache` placeholder with a partition-keyed [`DnsCache`] held
/// at the coordinator level (the cache itself indexes by
/// `PartitionKey` internally, so it does not need a per-partition
/// instance here).
///
/// SECURITY INVARIANT (L33): two distinct partition keys MUST end up
/// with two distinct `EgressState` instances. This struct is therefore
/// `!Clone` so a future refactor cannot accidentally fan one state out
/// to multiple partitions.
#[derive(Debug, Default)]
pub struct EgressState {
    /// Module 19 / 23.4 — per-partition connection pool slot.
    pub conn_pool: ConnPoolSlot,
    /// Module 23.4 — HSTS pin set for this partition.
    pub hsts: HstsSlot,
    /// Module 23.x — ALT-SVC table.
    pub alt_svc: AltSvcSlot,
    /// HTTP cache slot (currently routed through pb-storage primitives;
    /// kept here as a placeholder to make it explicit that the cache is
    /// also partition-keyed per L33).
    pub http_cache: HttpCacheSlot,
}

#[derive(Debug, Default)]
pub struct ConnPoolSlot;
#[derive(Debug, Default)]
pub struct HstsSlot;
#[derive(Debug, Default)]
pub struct AltSvcSlot;
#[derive(Debug, Default)]
pub struct HttpCacheSlot;

/// Bounded LRU map for per-partition egress state. Cap = [`MAX_PARTITIONS`].
///
/// True LRU semantics: every read or write of a key moves it to the back
/// of the recency queue. On overflow the front (least-recently-used) key
/// is evicted. Eviction does NOT touch in-flight requests that already
/// pulled their state out of the map — they hold their own references.
struct PartitionLru {
    map: HashMap<PartitionKey, EgressState>,
    order: VecDeque<PartitionKey>,
    cap: usize,
}

impl PartitionLru {
    fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    fn touch_to_back(&mut self, key: &PartitionKey) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            if let Some(k) = self.order.remove(pos) {
                self.order.push_back(k);
            }
        }
    }

    fn get_or_insert_default(&mut self, key: PartitionKey) -> &mut EgressState {
        if self.map.contains_key(&key) {
            self.touch_to_back(&key);
            return self.map.get_mut(&key).expect("present per contains_key");
        }
        if self.order.len() >= self.cap {
            if let Some(evicted) = self.order.pop_front() {
                self.map.remove(&evicted);
            }
        }
        self.order.push_back(key);
        self.map.entry(key).or_default()
    }

    fn remove(&mut self, key: &PartitionKey) -> Option<EgressState> {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.map.remove(key)
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn contains(&self, key: &PartitionKey) -> bool {
        self.map.contains_key(key)
    }
}

impl fmt::Debug for PartitionLru {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L27: never dump the inner map; partition keys are sensitive.
        f.debug_struct("PartitionLru")
            .field("len", &self.map.len())
            .field("cap", &self.cap)
            .finish()
    }
}

/// Live network broker handle. Held by the orchestrator behind
/// `Arc<tokio::sync::Mutex<_>>` (see [`bootstrap`]).
///
/// SECURITY INVARIANT: the `sandbox` field captures the profile applied
/// at bootstrap. The coordinator refuses to bootstrap with any sandbox
/// class other than [`SandboxClass::Network`] — a bug in the spawning
/// code that hands the wrong class is caught immediately rather than
/// loosening the broker's privilege posture.
pub struct NetworkCoordinator {
    /// Snapshot of the network-relevant config at bootstrap. Re-bootstrap
    /// to pick up changes; live mutation is intentionally not supported
    /// (settings change goes through orchestrator-driven respawn).
    /// Read by the diagnostic accessor below; Modules 20+ wire it into
    /// the DoH client at sub-system spawn time.
    network_cfg: NetworkConfig,

    /// Default privacy mode at bootstrap. Per-request `Request.mode`
    /// always wins; this is only the fall-back snapshot for diagnostic
    /// surfaces and for the L30 default posture.
    default_mode: Mode,

    /// Sandbox profile applied at bootstrap (Module 12). Held so future
    /// hooks (audit, re-apply on fork) can inspect it.
    #[allow(dead_code)]
    sandbox: SandboxProfile,

    /// Bridge to OS-level network state. v1: empty trait, Module 20+
    /// extends with `system_dns_servers()` etc.
    #[allow(dead_code)]
    platform: Arc<dyn PlatformContext>,

    /// L33 per-partition egress state, bounded LRU.
    egress: PartitionLru,

    /// Module 20 — partition-keyed DNS cache. Held at the coordinator
    /// level (not inside `EgressState`) because the [`DnsCache`] itself
    /// indexes by `PartitionKey` and supports a single-instance
    /// per-process design with internal partition isolation.
    dns_cache: Arc<DnsCache>,

    /// Module 20 — DoH resolver. `None` until the orchestrator wires
    /// one in via [`NetworkCoordinator::set_resolver`]. When `None`,
    /// [`NetworkCoordinator::resolve`] returns
    /// [`NetworkError::ResolveOutage`].
    resolver: Option<Arc<dyn Resolver>>,

    /// Module 20 — outage fallback policy. Snapshot derived from the
    /// wizard-recorded system-DNS opt-in flag at bootstrap. v1 always
    /// snapshots `system_dns_opt_in = false` until the wizard surface
    /// (Module 64) records the user's choice.
    fallback: FallbackPolicy,

    /// Module 21 — always-on blocklist. Bootstrap initializes with
    /// [`Blocklist::empty`]; the orchestrator (Module 80) wires the
    /// [`crate::blocklist::Loader`] / scheduler (and a real Module 60
    /// event sink) before any tab opens. Because the blocklist
    /// matches nothing while empty, an unwired broker is fail-open
    /// for blocking — see "Initial state" in
    /// [`crate::blocklist::Blocklist`] for the full rationale.
    blocklist: Arc<Blocklist>,

    /// Module 22 — Standard-mode header scrub policy snapshot.
    /// Cached at bootstrap so the per-request route path doesn't
    /// re-derive `HeaderPolicy::standard()` on every call.
    header_policy_standard: HeaderPolicy,

    /// Module 22 — Strict-mode header scrub policy snapshot. Same
    /// cache rationale as `header_policy_standard`.
    header_policy_strict: HeaderPolicy,
    // Module 23.1 + 23.2 + 23.3 + 24.1 ship via `crate::ChainValidator`
    // (held by the DoH transport today and consumed directly elsewhere
    // through `ChainValidator::default()`). A coordinator-level
    // `tls: Arc<crate::ChainValidator>` slot will land with Module 80
    // once the orchestrator wants one shared instance for non-DoH
    // dispatch + future WebSocket / fetch paths. Module 23.4 (HSTS pin
    // store) populates the per-partition `EgressState::hsts` slot
    // when Module 68's signed preload track ships.
}

impl fmt::Debug for NetworkCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // L27: do not echo network_cfg fields verbatim; the URL-shaped
        // `Custom { url }` provider variant is sensitive.
        f.debug_struct("NetworkCoordinator")
            .field("default_mode", &self.default_mode)
            .field("egress", &self.egress)
            .field("sandbox_class", &self.sandbox.class)
            .finish()
    }
}

/// Boot the network broker.
///
/// Steps, in order:
///
///   1. Validate the supplied [`SandboxProfile`] is `Network`-class.
///      A wrong class is a bug in the spawning code; bootstrap fails
///      with [`NetworkError::Config`] rather than loosening the posture.
///   2. Apply the sandbox profile (`profile.apply()` — v1 desktop is a
///      tracing warn per `pb_sandbox`; Module 12.1 lands real
///      enforcement).
///   3. Snapshot the relevant config sub-sections.
///   4. Construct the empty per-partition egress map.
///   5. Wrap in `Arc<tokio::sync::Mutex<_>>` for the orchestrator.
///
/// Idempotent only in the "no global state" sense — the function does
/// not touch process-global state. Callers may bootstrap repeatedly in
/// tests; production has exactly one network broker per orchestrator.
pub fn bootstrap(
    config: &Config,
    sandbox: SandboxProfile,
    platform: Arc<dyn PlatformContext>,
) -> Result<Arc<Mutex<NetworkCoordinator>>, NetworkError> {
    if sandbox.class != SandboxClass::Network {
        return Err(NetworkError::Config);
    }
    sandbox.apply()?;
    let coord = NetworkCoordinator {
        network_cfg: config.network.clone(),
        default_mode: config.privacy.default_mode.into(),
        sandbox,
        platform,
        egress: PartitionLru::new(MAX_PARTITIONS),
        dns_cache: Arc::new(DnsCache::new()),
        resolver: None,
        fallback: FallbackPolicy {
            // Wizard opt-in is the only path that flips this true.
            // v1: until Module 64 wizard records the user's choice,
            // `Standard` mode treats DoH outages as outages.
            system_dns_opt_in: false,
        },
        blocklist: Blocklist::empty(),
        header_policy_standard: HeaderPolicy::standard(),
        header_policy_strict: HeaderPolicy::strict(),
    };
    Ok(Arc::new(Mutex::new(coord)))
}

impl NetworkCoordinator {
    /// Default mode captured at bootstrap. Diagnostic only — per-request
    /// `Request.mode` is always authoritative.
    pub fn default_mode(&self) -> Mode {
        self.default_mode
    }

    /// Snapshot of the configured DoH provider. Diagnostic surface for
    /// tests and Module 20 wiring.
    pub fn doh_provider(&self) -> &pb_config::schema::DohProvider {
        &self.network_cfg.provider
    }

    /// Number of partitions currently held in the egress map.
    pub fn tracked_partition_count(&self) -> usize {
        self.egress.len()
    }

    /// True iff the egress map currently holds state for `key`.
    /// Diagnostic / test surface only.
    pub fn tracks_partition(&self, key: &PartitionKey) -> bool {
        self.egress.contains(key)
    }

    /// §5.2 mirror: recompute the partition key from
    /// `(site_origin, identity_profile_id, context_id)` and reject if
    /// it differs from the renderer-declared key. Returns the canonical
    /// (recomputed) key on success — callers should use that value
    /// downstream as the single source of truth.
    pub fn authorize(&self, req: &Request) -> Result<PartitionKey, NetworkError> {
        let expected =
            partition_key::derive(&req.site_origin, req.identity_profile_id, req.context_id);
        if expected == req.declared_key {
            Ok(expected)
        } else {
            Err(NetworkError::PartitionMismatch)
        }
    }

    /// Drop a partition's egress state. Called by the orchestrator on
    /// §3.6 mode transition (Standard -> Strict mints a fresh
    /// `context_id` and therefore a fresh partition key; the old
    /// partition's state must not bleed into the new one). Also called
    /// on identity-profile teardown (Module 10). Cascades to the
    /// per-partition DNS cache (Module 20).
    pub fn drop_partition(&mut self, key: &PartitionKey) {
        let _ = self.egress.remove(key);
        self.dns_cache.drop_partition(key);
    }

    /// Wire a [`Resolver`] into the coordinator. The orchestrator
    /// (Module 80) constructs the production resolver stack
    /// (`SingleFlightResolver` over `DohClient` over
    /// `HyperDohTransport`) and hands it over via this method.
    pub fn set_resolver(&mut self, resolver: Arc<dyn Resolver>) {
        self.resolver = Some(resolver);
    }

    /// True when a resolver has been wired in via [`set_resolver`].
    pub fn has_resolver(&self) -> bool {
        self.resolver.is_some()
    }

    /// Snapshot of the configured outage fallback policy.
    pub fn fallback_policy(&self) -> FallbackPolicy {
        self.fallback
    }

    /// Override the outage fallback policy. Called by the orchestrator
    /// when the first-launch wizard (Module 64) records the user's
    /// system-DNS opt-in choice.
    pub fn set_fallback_policy(&mut self, policy: FallbackPolicy) {
        self.fallback = policy;
    }

    /// Module 20 entry: resolve `qname` for `partition` under `mode`,
    /// honouring the per-partition DNS cache. On a cache miss, the
    /// wired-in resolver is invoked; the result is cached (positive
    /// or negative) before returning.
    ///
    /// Returns [`NetworkError::ResolveOutage`] when no resolver is
    /// wired (the orchestrator must call [`set_resolver`] before any
    /// route work). Production wiring guarantees this; the variant
    /// exists so a misconfigured test does not silently bypass DoH.
    pub async fn resolve(
        &self,
        partition: PartitionKey,
        qname: &str,
        qtype: QueryType,
        mode: Mode,
    ) -> Result<ResolveResult, NetworkError> {
        let qtype_code = qtype.type_code();
        if let Some(cached) = self.dns_cache.get(&partition, qname, qtype_code) {
            return cached;
        }
        let resolver = self.resolver.as_ref().ok_or(NetworkError::ResolveOutage)?;
        let query = ResolveQuery {
            partition_key: partition,
            qname: qname.to_string(),
            qtype,
            mode,
        };
        match resolver.resolve(query).await {
            Ok(res) => {
                self.dns_cache
                    .put_positive(partition, qname, qtype_code, &res);
                Ok(res)
            }
            Err(e) => {
                // Cache only the cacheable shapes (NX / definitive failures).
                // Transport / timeout / outage are transient; do not poison
                // the cache with them.
                if matches!(e, NetworkError::ResolveNxDomain) {
                    self.dns_cache
                        .put_negative(partition, qname, qtype_code, e.clone());
                }
                Err(e)
            }
        }
    }

    /// Route a request through the v1 surface:
    ///
    ///   1. authorize (§5.2 mirror — partition-key gate)
    ///   2. cancellation check
    ///   3. HTTPS-Only enforcement (L30)
    ///   4. cancellation check
    ///   5. ensure egress state for the canonical partition exists
    ///      (LRU touch / insert)
    ///   6. produce a [`RoutedRequest`]
    ///
    /// Modules 20-25 will insert their stages between steps 3 and 5
    /// (blocklist, URL-param strip, header scrub, DoH resolve, TLS
    /// handshake, JA3-reduced ClientHello). Until they wire in, this
    /// is the full route surface; the request is structurally valid
    /// for dispatch but no I/O has been issued.
    pub fn route(&mut self, req: Request) -> Result<RoutedRequest, NetworkError> {
        let canonical = self.authorize(&req)?;
        if req.cancel.is_cancelled() {
            return Err(NetworkError::Cancelled);
        }
        let final_url = enforce_https_only(&req.url, req.downgrade_approved)?;
        if req.cancel.is_cancelled() {
            return Err(NetworkError::Cancelled);
        }
        // Module 21 — blocklist match. Extract the host from the
        // (possibly-upgraded) URL and consult the live tree. On hit,
        // emit a classified event (Module 60 surface) and return
        // NetworkError::Blocked. The match path drops the read lock
        // before doing any matching work.
        let host = parse_host(&final_url).ok_or(NetworkError::InvalidUrl)?;
        if let Some(kind) = self.blocklist.match_host(&host) {
            self.blocklist.sink().on_block(BlockedEvent {
                kind,
                partition_key: canonical,
            });
            return Err(NetworkError::Blocked);
        }
        // Module 21 — URL parameter strip (L32). The strip pass runs
        // after the host-rule check so a blocked host short-circuits
        // before we allocate a rewritten URL.
        let strip_list = self.blocklist.url_param_strip_list();
        let final_url = strip_tracking_params(&final_url, &strip_list);
        if req.cancel.is_cancelled() {
            return Err(NetworkError::Cancelled);
        }
        // Module 22 — header scrub. Runs after URL strip so the
        // Referer-policy decision sees the stripped URL (preventing
        // tracking params from leaking into Referer on cross-origin
        // sub-resource requests).
        let policy = self.header_policy_for(req.mode);
        let scrubbed_headers =
            headers::scrub(policy, &req.site_origin, &host, &final_url, req.headers);
        if req.cancel.is_cancelled() {
            return Err(NetworkError::Cancelled);
        }
        // Ensure egress state exists for this partition. Side-effect:
        // touches LRU recency. The borrow is dropped before the
        // RoutedRequest is constructed so the &mut self borrow is
        // unambiguous.
        let _ = self.egress.get_or_insert_default(canonical);
        Ok(RoutedRequest {
            partition_key: canonical,
            mode: req.mode,
            final_url,
            method: req.method,
            headers: scrubbed_headers,
            body: req.body,
        })
    }

    /// Snapshot of the header scrub policy for `mode`. Cached at
    /// bootstrap; the orchestrator may also override the cached
    /// snapshot via [`set_header_policy`] for tests / managed
    /// deployments.
    pub fn header_policy_for(&self, mode: Mode) -> &HeaderPolicy {
        match mode {
            Mode::Standard => &self.header_policy_standard,
            Mode::Strict => &self.header_policy_strict,
        }
    }

    /// Override the cached header-policy snapshot for `mode`. Used
    /// by tests + managed-policy harnesses; production wiring takes
    /// the bootstrap defaults.
    pub fn set_header_policy(&mut self, policy: HeaderPolicy) {
        match policy.mode {
            Mode::Standard => self.header_policy_standard = policy,
            Mode::Strict => self.header_policy_strict = policy,
        }
    }

    /// Snapshot of the live [`Blocklist`]. Cloning the `Arc` is the
    /// canonical way for the orchestrator (Module 80) to hand the
    /// same live blocklist to the scheduler.
    pub fn blocklist(&self) -> Arc<Blocklist> {
        self.blocklist.clone()
    }

    /// Replace the live [`Blocklist`]. The orchestrator calls this at
    /// boot before any tab opens (the empty default is fail-open for
    /// blocking, which is intentional but undesirable in steady state).
    pub fn set_blocklist(&mut self, blocklist: Arc<Blocklist>) {
        self.blocklist = blocklist;
    }
}

/// L30 HTTPS-Only enforcement. Returns the final URL string the
/// dispatcher will use:
///
///   * `https://...` → returned unchanged.
///   * `http://...` with `downgrade_approved == true` → returned
///     unchanged. The user explicitly clicked through the per-host
///     downgrade modal; no further check here.
///   * `http://...` with `downgrade_approved == false` →
///     [`NetworkError::HttpsOnlyDowngrade`]. Never silently upgraded
///     either: silent upgrade would mask a misconfigured caller.
///   * any other scheme → [`NetworkError::InvalidUrl`].
///
/// v1 does only scheme-level inspection; full URL parsing (host,
/// path, query) lands in Module 21 alongside URL-parameter stripping.
fn enforce_https_only(url: &str, downgrade_approved: bool) -> Result<String, NetworkError> {
    // ASCII case-insensitive match on the scheme prefix. URLs with a
    // mixed-case scheme are unusual but legal; treat them uniformly.
    if has_ascii_prefix_ci(url, "https://") {
        Ok(url.to_string())
    } else if has_ascii_prefix_ci(url, "http://") {
        if downgrade_approved {
            Ok(url.to_string())
        } else {
            Err(NetworkError::HttpsOnlyDowngrade)
        }
    } else {
        Err(NetworkError::InvalidUrl)
    }
}

fn has_ascii_prefix_ci(haystack: &str, needle: &str) -> bool {
    haystack.len() >= needle.len()
        && haystack.as_bytes()[..needle.len()].eq_ignore_ascii_case(needle.as_bytes())
}

/// Extract the bare hostname from `url`. Hand-rolled scheme-aware
/// parser scoped to the route-path's needs (host extraction for the
/// blocklist match). Returns `None` for malformed inputs; callers
/// translate that into [`NetworkError::InvalidUrl`].
///
/// v1 handles `scheme://[userinfo@]host[:port][/path][?query][#frag]`.
/// IPv6 brackets (`[::1]`) are preserved verbatim because the
/// blocklist match keys on hostnames; the rebinding filter
/// (Module 20) is what guards against literal-IP probes.
fn parse_host(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after_scheme = &url[scheme_end + 3..];
    // Strip optional userinfo prefix.
    let after_userinfo = match after_scheme.find('@') {
        // Only accept '@' that comes before any '/' / '?' / '#' so a
        // mailto-shaped path in the path component does not eat the
        // host.
        Some(i)
            if !after_scheme[..i].contains('/')
                && !after_scheme[..i].contains('?')
                && !after_scheme[..i].contains('#') =>
        {
            &after_scheme[i + 1..]
        }
        _ => after_scheme,
    };
    // Find the end of the authority component: first '/' / '?' / '#'.
    let end = after_userinfo
        .bytes()
        .position(|b| b == b'/' || b == b'?' || b == b'#')
        .unwrap_or(after_userinfo.len());
    let authority = &after_userinfo[..end];
    if authority.is_empty() {
        return None;
    }
    // Strip the port. IPv6 literals are wrapped in `[...]` so a `:`
    // inside the bracket is part of the address, not a port marker.
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        let bracket_end = stripped.find(']')?;
        &stripped[..bracket_end]
    } else if let Some(colon) = authority.find(':') {
        &authority[..colon]
    } else {
        authority
    };
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_config::{Mode as ConfigMode, PrivacyConfig};
    use pb_sandbox::SandboxProfile;

    #[derive(Debug)]
    struct NullPlatform;
    impl PlatformContext for NullPlatform {}

    fn config_with_mode(default_mode: ConfigMode) -> Config {
        Config {
            privacy: PrivacyConfig {
                default_mode,
                ..PrivacyConfig::default()
            },
            ..Config::default()
        }
    }

    fn id(seed: u128) -> Uuid {
        Uuid::from_u128(seed)
    }

    fn good_request(profile: Uuid, ctx: Uuid, mode: Mode) -> Request {
        let key = partition_key::derive("example.com", profile, ctx);
        Request {
            site_origin: "example.com".to_string(),
            identity_profile_id: profile,
            context_id: ctx,
            declared_key: key,
            mode,
            url: "https://example.com/index.html".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            downgrade_approved: false,
            cancel: CancellationFlag::new(),
        }
    }

    async fn coord(default_mode: ConfigMode) -> Arc<Mutex<NetworkCoordinator>> {
        bootstrap(
            &config_with_mode(default_mode),
            SandboxProfile::strict_network(),
            Arc::new(NullPlatform),
        )
        .expect("bootstrap")
    }

    #[tokio::test]
    async fn bootstrap_succeeds_with_network_sandbox_class() {
        let c = coord(ConfigMode::Standard).await;
        let g = c.lock().await;
        assert_eq!(g.default_mode(), Mode::Standard);
    }

    #[tokio::test]
    async fn bootstrap_rejects_non_network_sandbox_class() {
        let cfg = Config::default();
        // Renderer profile is the wrong class for the network broker.
        let r = bootstrap(
            &cfg,
            SandboxProfile::strict_renderer(),
            Arc::new(NullPlatform),
        );
        match r {
            Err(NetworkError::Config) => {}
            other => panic!("expected NetworkError::Config, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorize_accepts_matching_declared_key() {
        let c = coord(ConfigMode::Standard).await;
        let req = good_request(id(1), id(2), Mode::Standard);
        let g = c.lock().await;
        let key = g.authorize(&req).expect("authorize");
        assert_eq!(key, req.declared_key);
    }

    #[tokio::test]
    async fn authorize_rejects_compromised_renderer_lying_about_origin() {
        // Renderer ships a key derived from "example.com" but claims the
        // request's origin is "evil.com". Coordinator recomputes from
        // "evil.com" and the keys diverge — partition mismatch.
        let c = coord(ConfigMode::Standard).await;
        let truthful_key = partition_key::derive("example.com", id(1), id(2));
        let req = Request {
            site_origin: "evil.com".to_string(),
            identity_profile_id: id(1),
            context_id: id(2),
            declared_key: truthful_key,
            mode: Mode::Standard,
            url: "https://evil.com/".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            downgrade_approved: false,
            cancel: CancellationFlag::new(),
        };
        let g = c.lock().await;
        match g.authorize(&req) {
            Err(NetworkError::PartitionMismatch) => {}
            other => panic!("expected PartitionMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authorize_rejects_compromised_renderer_lying_about_identity() {
        // Renderer presents a key for profile=1 but claims context profile=99.
        let c = coord(ConfigMode::Standard).await;
        let truthful_key = partition_key::derive("example.com", id(1), id(2));
        let req = Request {
            site_origin: "example.com".to_string(),
            identity_profile_id: id(99),
            context_id: id(2),
            declared_key: truthful_key,
            mode: Mode::Standard,
            url: "https://example.com/".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            downgrade_approved: false,
            cancel: CancellationFlag::new(),
        };
        let g = c.lock().await;
        assert!(matches!(
            g.authorize(&req),
            Err(NetworkError::PartitionMismatch)
        ));
    }

    #[tokio::test]
    async fn route_rejects_bare_http_when_no_downgrade_approval() {
        // L30: an `http://` URL without `downgrade_approved` must hard-error.
        let c = coord(ConfigMode::Standard).await;
        let mut req = good_request(id(1), id(2), Mode::Standard);
        req.url = "http://example.com/index.html".to_string();
        // Recompute the declared key for the still-correct origin.
        let mut g = c.lock().await;
        match g.route(req) {
            Err(NetworkError::HttpsOnlyDowngrade) => {}
            other => panic!("expected HttpsOnlyDowngrade, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn route_allows_http_when_downgrade_approved() {
        let c = coord(ConfigMode::Standard).await;
        let mut req = good_request(id(1), id(2), Mode::Standard);
        req.url = "http://example.com/index.html".to_string();
        req.downgrade_approved = true;
        let mut g = c.lock().await;
        let routed = g.route(req).expect("approved http downgrade routes");
        assert_eq!(routed.final_url, "http://example.com/index.html");
    }

    #[tokio::test]
    async fn route_rejects_non_http_scheme() {
        let c = coord(ConfigMode::Standard).await;
        let mut req = good_request(id(1), id(2), Mode::Standard);
        req.url = "ftp://example.com/file".to_string();
        let mut g = c.lock().await;
        assert!(matches!(g.route(req), Err(NetworkError::InvalidUrl)));
    }

    #[tokio::test]
    async fn route_passes_https_through_unchanged() {
        let c = coord(ConfigMode::Standard).await;
        let req = good_request(id(1), id(2), Mode::Standard);
        let original_url = req.url.clone();
        let mut g = c.lock().await;
        let routed = g.route(req).expect("https routes");
        assert_eq!(routed.final_url, original_url);
    }

    #[tokio::test]
    async fn route_creates_per_partition_egress_state() {
        // Routing populates the egress map for the canonical key.
        let c = coord(ConfigMode::Standard).await;
        let req = good_request(id(1), id(2), Mode::Standard);
        let key = req.declared_key;
        let mut g = c.lock().await;
        assert!(!g.tracks_partition(&key));
        g.route(req).expect("route ok");
        assert!(g.tracks_partition(&key));
        assert_eq!(g.tracked_partition_count(), 1);
    }

    #[tokio::test]
    async fn mode_transition_drops_old_partition_state() {
        // §3.6: Standard → Strict mints a fresh context_id; the old
        // partition's egress state must not be carried over. The
        // orchestrator drops the old partition explicitly.
        let c = coord(ConfigMode::Standard).await;
        let std_ctx = id(2);
        let strict_ctx = id(0xDEAD_BEEF);
        let std_req = good_request(id(1), std_ctx, Mode::Standard);
        let std_key = std_req.declared_key;
        let strict_req = good_request(id(1), strict_ctx, Mode::Strict);
        let strict_key = strict_req.declared_key;
        assert_ne!(std_key, strict_key);

        let mut g = c.lock().await;
        g.route(std_req).expect("std route");
        assert!(g.tracks_partition(&std_key));

        // Mode-transition handoff: orchestrator drops the old key.
        g.drop_partition(&std_key);
        assert!(!g.tracks_partition(&std_key));

        // Strict request mints fresh state.
        g.route(strict_req).expect("strict route");
        assert!(g.tracks_partition(&strict_key));
        assert!(!g.tracks_partition(&std_key));
    }

    #[tokio::test]
    async fn route_returns_cancelled_when_flag_is_set() {
        let c = coord(ConfigMode::Standard).await;
        let req = good_request(id(1), id(2), Mode::Standard);
        req.cancel.cancel();
        let mut g = c.lock().await;
        match g.route(req) {
            Err(NetworkError::Cancelled) => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancellation_flag_is_observable_across_clones() {
        let f = CancellationFlag::new();
        let g = f.clone();
        assert!(!g.is_cancelled());
        f.cancel();
        assert!(g.is_cancelled());
    }

    #[tokio::test]
    async fn egress_map_evicts_least_recently_used_at_cap() {
        // Drive 17 distinct partitions through `route` and confirm the
        // map stays at MAX_PARTITIONS. The very first partition
        // inserted (the LRU at the moment of overflow) must be gone.
        let c = coord(ConfigMode::Standard).await;
        let mut keys = Vec::with_capacity(MAX_PARTITIONS + 1);
        let mut g = c.lock().await;
        for i in 0..(MAX_PARTITIONS + 1) {
            let profile = id(1);
            let ctx = id(100 + i as u128);
            let req = good_request(profile, ctx, Mode::Standard);
            keys.push(req.declared_key);
            g.route(req).expect("route");
        }
        assert_eq!(g.tracked_partition_count(), MAX_PARTITIONS);
        assert!(
            !g.tracks_partition(&keys[0]),
            "least-recently-used partition should have been evicted"
        );
        assert!(
            g.tracks_partition(&keys[MAX_PARTITIONS]),
            "most-recently-used partition must still be tracked"
        );
    }

    #[tokio::test]
    async fn egress_map_recency_protects_lru_winner() {
        // After filling to cap, re-touch the very first key and then
        // overflow once more. The re-touched key must NOT be evicted;
        // the next-oldest key goes instead.
        let c = coord(ConfigMode::Standard).await;
        let mut keys = Vec::with_capacity(MAX_PARTITIONS + 1);
        let mut g = c.lock().await;
        for i in 0..MAX_PARTITIONS {
            let profile = id(1);
            let ctx = id(200 + i as u128);
            let req = good_request(profile, ctx, Mode::Standard);
            keys.push(req.declared_key);
            g.route(req).expect("route");
        }
        // Re-touch keys[0]: route again with the same triple bumps it
        // to most-recently-used.
        let touch_req = good_request(id(1), id(200), Mode::Standard);
        g.route(touch_req).expect("re-touch");
        // Now overflow with a fresh partition.
        let overflow = good_request(id(1), id(999), Mode::Standard);
        let overflow_key = overflow.declared_key;
        g.route(overflow).expect("overflow");
        assert!(
            g.tracks_partition(&keys[0]),
            "re-touched partition must survive eviction"
        );
        assert!(
            !g.tracks_partition(&keys[1]),
            "second-oldest (now LRU) must be evicted"
        );
        assert!(g.tracks_partition(&overflow_key));
        assert_eq!(g.tracked_partition_count(), MAX_PARTITIONS);
    }

    #[tokio::test]
    async fn config_mode_into_network_mode() {
        assert_eq!(Mode::from(ConfigMode::Standard), Mode::Standard);
        assert_eq!(Mode::from(ConfigMode::Strict), Mode::Strict);
    }

    #[tokio::test]
    async fn coordinator_doh_provider_reflects_config_default() {
        let c = coord(ConfigMode::Standard).await;
        let g = c.lock().await;
        assert_eq!(g.doh_provider(), &pb_config::schema::DohProvider::Quad9);
    }

    #[test]
    fn https_only_passes_uppercase_scheme() {
        let out = enforce_https_only("HTTPS://example.com/", false).expect("upper-case https ok");
        assert_eq!(out, "HTTPS://example.com/");
    }

    #[test]
    fn https_only_rejects_uppercase_http_without_approval() {
        match enforce_https_only("HTTP://example.com/", false) {
            Err(NetworkError::HttpsOnlyDowngrade) => {}
            other => panic!("expected HttpsOnlyDowngrade, got {other:?}"),
        }
    }

    #[test]
    fn https_only_rejects_unknown_scheme() {
        match enforce_https_only("data:text/plain,hi", false) {
            Err(NetworkError::InvalidUrl) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn https_only_rejects_empty_url() {
        match enforce_https_only("", false) {
            Err(NetworkError::InvalidUrl) => {}
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    // -- Module 20 integration tests --

    #[derive(Debug)]
    struct CountingResolver {
        calls: std::sync::atomic::AtomicU32,
    }

    impl crate::dns::Resolver for CountingResolver {
        fn resolve<'a>(&'a self, _q: crate::dns::ResolveQuery) -> crate::dns::ResolveFuture<'a> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                Ok(crate::dns::ResolveResult {
                    records: vec![crate::dns::DnsRecord::A(std::net::Ipv4Addr::new(
                        93, 184, 216, 34,
                    ))],
                    ttl_seconds: 60,
                })
            })
        }
    }

    #[tokio::test]
    async fn coordinator_resolve_caches_positive_results() {
        let c = coord(ConfigMode::Standard).await;
        let resolver = Arc::new(CountingResolver {
            calls: std::sync::atomic::AtomicU32::new(0),
        });
        {
            let mut g = c.lock().await;
            g.set_resolver(resolver.clone());
        }
        let key = partition_key::derive("example.com", id(1), id(2));
        let g = c.lock().await;
        let r1 = g
            .resolve(key, "example.com", crate::dns::QueryType::A, Mode::Standard)
            .await
            .expect("resolve ok");
        assert_eq!(r1.records.len(), 1);
        let r2 = g
            .resolve(key, "example.com", crate::dns::QueryType::A, Mode::Standard)
            .await
            .expect("resolve ok");
        assert_eq!(r2.records.len(), 1);
        assert_eq!(
            resolver.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "second resolve must hit the cache, not the resolver"
        );
    }

    #[tokio::test]
    async fn coordinator_resolve_outage_when_no_resolver_wired() {
        let c = coord(ConfigMode::Standard).await;
        let g = c.lock().await;
        let key = partition_key::derive("example.com", id(1), id(2));
        match g
            .resolve(key, "example.com", crate::dns::QueryType::A, Mode::Standard)
            .await
        {
            Err(NetworkError::ResolveOutage) => {}
            other => panic!("expected ResolveOutage when no resolver, got {other:?}"),
        }
    }

    #[derive(Debug)]
    struct ScriptedResolver {
        calls: std::sync::atomic::AtomicU32,
        outcome: std::sync::Mutex<Result<crate::dns::ResolveResult, NetworkError>>,
    }

    impl ScriptedResolver {
        fn new(outcome: Result<crate::dns::ResolveResult, NetworkError>) -> Self {
            Self {
                calls: std::sync::atomic::AtomicU32::new(0),
                outcome: std::sync::Mutex::new(outcome),
            }
        }

        fn call_count(&self) -> u32 {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::dns::Resolver for ScriptedResolver {
        fn resolve<'a>(&'a self, _q: crate::dns::ResolveQuery) -> crate::dns::ResolveFuture<'a> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let staged = self.outcome.lock().expect("scripted lock").clone();
            Box::pin(async move { staged })
        }
    }

    #[tokio::test]
    async fn coordinator_resolve_isolates_partitions() {
        // L33: same qname, two partitions — must invoke the resolver
        // twice. A cache hit across partitions would be a §3.5
        // partition-key gate violation.
        let c = coord(ConfigMode::Standard).await;
        let resolver = Arc::new(CountingResolver {
            calls: std::sync::atomic::AtomicU32::new(0),
        });
        {
            let mut g = c.lock().await;
            g.set_resolver(resolver.clone());
        }
        let key_a = partition_key::derive("example.com", id(1), id(2));
        let key_b = partition_key::derive("example.com", id(3), id(4));
        assert_ne!(key_a, key_b, "fixture must produce distinct keys");
        {
            let g = c.lock().await;
            g.resolve(
                key_a,
                "example.com",
                crate::dns::QueryType::A,
                Mode::Standard,
            )
            .await
            .unwrap();
            g.resolve(
                key_b,
                "example.com",
                crate::dns::QueryType::A,
                Mode::Standard,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            resolver.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "cross-partition resolves must NOT share a cache entry",
        );
    }

    #[tokio::test]
    async fn coordinator_resolve_caches_nxdomain_negatively() {
        // Module 20 spec: NXDOMAIN is cached at most MAX_NEGATIVE_TTL
        // seconds. The first resolve hits the upstream; the second
        // resolve under the same partition+qname must NOT.
        let c = coord(ConfigMode::Standard).await;
        let resolver = Arc::new(ScriptedResolver::new(Err(NetworkError::ResolveNxDomain)));
        {
            let mut g = c.lock().await;
            g.set_resolver(resolver.clone());
        }
        let key = partition_key::derive("example.com", id(1), id(2));
        let g = c.lock().await;
        let r1 = g
            .resolve(
                key,
                "missing.example",
                crate::dns::QueryType::A,
                Mode::Standard,
            )
            .await;
        assert!(matches!(r1, Err(NetworkError::ResolveNxDomain)));
        let r2 = g
            .resolve(
                key,
                "missing.example",
                crate::dns::QueryType::A,
                Mode::Standard,
            )
            .await;
        assert!(matches!(r2, Err(NetworkError::ResolveNxDomain)));
        assert_eq!(
            resolver.call_count(),
            1,
            "NXDOMAIN must be negatively cached so the second lookup does not re-invoke the resolver",
        );
    }

    #[tokio::test]
    async fn coordinator_resolve_does_not_cache_transient_errors() {
        // Transport / timeout / outage are transient; caching them
        // would lock a partition out of resolution for the negative
        // TTL window. The second resolve must re-invoke.
        let c = coord(ConfigMode::Standard).await;
        let resolver = Arc::new(ScriptedResolver::new(Err(NetworkError::ResolveTransport)));
        {
            let mut g = c.lock().await;
            g.set_resolver(resolver.clone());
        }
        let key = partition_key::derive("example.com", id(1), id(2));
        let g = c.lock().await;
        let _ = g
            .resolve(key, "example.com", crate::dns::QueryType::A, Mode::Standard)
            .await;
        let _ = g
            .resolve(key, "example.com", crate::dns::QueryType::A, Mode::Standard)
            .await;
        assert_eq!(
            resolver.call_count(),
            2,
            "transient errors must NOT be cached — every retry re-invokes the resolver",
        );
    }

    #[tokio::test]
    async fn coordinator_drop_partition_clears_dns_cache() {
        let c = coord(ConfigMode::Standard).await;
        let resolver = Arc::new(CountingResolver {
            calls: std::sync::atomic::AtomicU32::new(0),
        });
        {
            let mut g = c.lock().await;
            g.set_resolver(resolver.clone());
        }
        let key = partition_key::derive("example.com", id(1), id(2));
        // Populate the cache.
        {
            let g = c.lock().await;
            g.resolve(key, "example.com", crate::dns::QueryType::A, Mode::Standard)
                .await
                .unwrap();
        }
        // Drop the partition (mode-transition handoff).
        {
            let mut g = c.lock().await;
            g.drop_partition(&key);
        }
        // Next resolve must invoke the resolver again — cache was cleared.
        {
            let g = c.lock().await;
            g.resolve(key, "example.com", crate::dns::QueryType::A, Mode::Standard)
                .await
                .unwrap();
        }
        assert_eq!(
            resolver.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "drop_partition must evict cache so the next resolve re-invokes"
        );
    }

    #[tokio::test]
    async fn coordinator_default_fallback_is_no_opt_in() {
        let c = coord(ConfigMode::Standard).await;
        let g = c.lock().await;
        assert!(
            !g.fallback_policy().system_dns_opt_in,
            "default fallback policy is fail-closed until wizard records opt-in"
        );
    }

    #[tokio::test]
    async fn coordinator_fallback_policy_can_be_overridden() {
        let c = coord(ConfigMode::Standard).await;
        {
            let mut g = c.lock().await;
            g.set_fallback_policy(FallbackPolicy {
                system_dns_opt_in: true,
            });
        }
        let g = c.lock().await;
        assert!(g.fallback_policy().system_dns_opt_in);
    }

    // -- Module 21 integration tests --

    use crate::blocklist::events::CapturingSink as BlockCapturingSink;
    use crate::blocklist::rule::{
        BlockKind as BK, Manifest as BlocklistManifest, Rule as BlockRule, UrlParamRule,
    };
    use crate::blocklist::Blocklist;

    fn manifest_blocking(host: &str, kind: BK) -> BlocklistManifest {
        BlocklistManifest {
            format_version: 1,
            content_version: 1,
            generated_at_unix: 0,
            host_rules: vec![BlockRule::host(host, kind)],
            url_param_rules: vec![],
            cookie_banner_rules: vec![],
        }
    }

    fn manifest_strip(params: &[&str]) -> BlocklistManifest {
        BlocklistManifest {
            format_version: 1,
            content_version: 1,
            generated_at_unix: 0,
            host_rules: vec![],
            url_param_rules: params.iter().map(|p| UrlParamRule::new(*p)).collect(),
            cookie_banner_rules: vec![],
        }
    }

    fn req_to(url: &str) -> Request {
        let key = partition_key::derive("example.com", id(1), id(2));
        Request {
            site_origin: "example.com".to_string(),
            identity_profile_id: id(1),
            context_id: id(2),
            declared_key: key,
            mode: Mode::Standard,
            url: url.to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            downgrade_approved: false,
            cancel: CancellationFlag::new(),
        }
    }

    #[tokio::test]
    async fn route_blocks_hostname_on_blocklist_hit() {
        let c = coord(ConfigMode::Standard).await;
        let bl = Blocklist::from_manifest(&manifest_blocking("ads.example.com", BK::Ad));
        let sink = Arc::new(BlockCapturingSink::default());
        bl.set_sink(sink.clone());
        {
            let mut g = c.lock().await;
            g.set_blocklist(bl);
        }
        let req = req_to("https://ads.example.com/banner.png");
        let mut g = c.lock().await;
        match g.route(req) {
            Err(NetworkError::Blocked) => {}
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert_eq!(sink.len(), 1, "blocked event must fan out");
        let snap = sink.snapshot();
        assert_eq!(snap[0].kind, BK::Ad);
    }

    #[tokio::test]
    async fn route_blocks_subdomain_via_subdomain_inclusive_rule() {
        let c = coord(ConfigMode::Standard).await;
        let bl = Blocklist::from_manifest(&manifest_blocking("example.com", BK::Tracker));
        let sink = Arc::new(BlockCapturingSink::default());
        bl.set_sink(sink.clone());
        {
            let mut g = c.lock().await;
            g.set_blocklist(bl);
        }
        let req = req_to("https://tracker.example.com/pixel.gif");
        let mut g = c.lock().await;
        match g.route(req) {
            Err(NetworkError::Blocked) => {}
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert_eq!(sink.snapshot()[0].kind, BK::Tracker);
    }

    #[tokio::test]
    async fn route_passes_unblocked_hosts() {
        let c = coord(ConfigMode::Standard).await;
        let bl = Blocklist::from_manifest(&manifest_blocking("ads.example.com", BK::Ad));
        {
            let mut g = c.lock().await;
            g.set_blocklist(bl);
        }
        let req = req_to("https://example.com/page");
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        assert_eq!(routed.final_url, "https://example.com/page");
    }

    #[tokio::test]
    async fn route_strips_tracking_params() {
        let c = coord(ConfigMode::Standard).await;
        let bl = Blocklist::from_manifest(&manifest_strip(&["utm_source", "fbclid"]));
        {
            let mut g = c.lock().await;
            g.set_blocklist(bl);
        }
        let req = req_to("https://example.com/page?q=hi&utm_source=ad&fbclid=x&page=2");
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        assert_eq!(routed.final_url, "https://example.com/page?q=hi&page=2");
    }

    #[tokio::test]
    async fn route_strip_runs_after_blocklist_check() {
        // A blocked host short-circuits before the strip pass — no
        // RoutedRequest is produced and the original URL is never
        // rewritten. (Emit-once-per-block check.)
        let c = coord(ConfigMode::Standard).await;
        let bl = Blocklist::from_manifest(&BlocklistManifest {
            format_version: 1,
            content_version: 1,
            generated_at_unix: 0,
            host_rules: vec![BlockRule::host("ads.example.com", BK::Ad)],
            url_param_rules: vec![UrlParamRule::new("utm_source")],
            cookie_banner_rules: vec![],
        });
        let sink = Arc::new(BlockCapturingSink::default());
        bl.set_sink(sink.clone());
        {
            let mut g = c.lock().await;
            g.set_blocklist(bl);
        }
        let req = req_to("https://ads.example.com/?utm_source=x&q=hi");
        let mut g = c.lock().await;
        match g.route(req) {
            Err(NetworkError::Blocked) => {}
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert_eq!(sink.len(), 1);
    }

    #[tokio::test]
    async fn route_with_empty_blocklist_passes_everything() {
        let c = coord(ConfigMode::Standard).await;
        // Default coordinator already starts with Blocklist::empty().
        let req = req_to("https://example.com/page?utm_source=x&q=hi");
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        // Empty blocklist → no strip list → URL passes through unchanged.
        assert_eq!(
            routed.final_url,
            "https://example.com/page?utm_source=x&q=hi"
        );
    }

    // -- Module 22 integration tests --

    #[tokio::test]
    async fn route_scrubs_renderer_set_user_agent() {
        let c = coord(ConfigMode::Standard).await;
        let mut req = req_to("https://example.com/");
        req.headers
            .push(("User-Agent".to_string(), "EvilBot/1.0".to_string()));
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        let ua = routed
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.clone());
        assert_eq!(ua.as_deref(), Some(crate::headers::DEVBROWSE_USER_AGENT));
    }

    #[tokio::test]
    async fn route_strips_renderer_set_cookie() {
        let c = coord(ConfigMode::Standard).await;
        let mut req = req_to("https://example.com/");
        req.headers
            .push(("Cookie".to_string(), "stolen=true".to_string()));
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        let count = routed
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("cookie"))
            .count();
        assert_eq!(count, 0, "Cookie must never reach the wire from a renderer");
    }

    #[tokio::test]
    async fn route_emits_referer_for_cross_origin_in_standard() {
        let c = coord(ConfigMode::Standard).await;
        let req = req_to("https://other.example/page");
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        let referer = routed
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("referer"))
            .map(|(_, v)| v.clone());
        assert_eq!(referer.as_deref(), Some("https://example.com/"));
    }

    #[tokio::test]
    async fn route_omits_referer_in_strict_mode() {
        let c = coord(ConfigMode::Strict).await;
        let mut req = req_to("https://example.com/");
        req.mode = Mode::Strict;
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        let referer_count = routed
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("referer"))
            .count();
        assert_eq!(referer_count, 0);
    }

    #[tokio::test]
    async fn route_omits_referer_on_https_to_http_downgrade() {
        let c = coord(ConfigMode::Standard).await;
        let mut req = req_to("http://example.com/");
        req.downgrade_approved = true;
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        let referer_count = routed
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("referer"))
            .count();
        assert_eq!(
            referer_count, 0,
            "L31: HTTPS->HTTP downgrade suppresses Referer"
        );
    }

    #[tokio::test]
    async fn route_uses_strict_policy_for_strict_mode_requests() {
        // Mixed-mode coordinator: Standard default but a Strict tab
        // emits no Referer / different policy snapshot. Confirms the
        // per-request mode field wins over the bootstrap default.
        let c = coord(ConfigMode::Standard).await;
        let mut std_req = req_to("https://target.example/page");
        std_req.mode = Mode::Standard;
        let mut strict_req = req_to("https://target.example/page");
        strict_req.mode = Mode::Strict;
        let mut g = c.lock().await;
        let std_out = g.route(std_req).expect("std");
        let strict_out = g.route(strict_req).expect("strict");
        let std_has_referer = std_out
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("referer"));
        let strict_has_referer = strict_out
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("referer"));
        assert!(std_has_referer, "Standard mode emits Referer");
        assert!(!strict_has_referer, "Strict mode omits Referer");
    }

    #[tokio::test]
    async fn route_runs_scrub_after_url_strip() {
        // Verify ordering: a tracking param in the URL is stripped
        // before the URL is observable for Referer computation.
        // (Cross-origin Referer is origin-only by v1 design, so the
        // stripped param doesn't influence the value either way --
        // this test checks that the route path completes for a URL
        // that requires both transformations.)
        let c = coord(ConfigMode::Standard).await;
        let bl = Blocklist::from_manifest(&manifest_strip(&["utm_source"]));
        {
            let mut g = c.lock().await;
            g.set_blocklist(bl);
        }
        let req = req_to("https://other.example/path?utm_source=x&q=hi");
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        assert_eq!(routed.final_url, "https://other.example/path?q=hi");
        let referer = routed
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("referer"))
            .map(|(_, v)| v.clone());
        assert_eq!(referer.as_deref(), Some("https://example.com/"));
    }

    #[tokio::test]
    async fn route_passes_through_app_headers() {
        let c = coord(ConfigMode::Standard).await;
        let mut req = req_to("https://example.com/");
        req.headers.extend(vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-CSRF-Token".to_string(), "token-123".to_string()),
        ]);
        let mut g = c.lock().await;
        let routed = g.route(req).expect("route ok");
        let ct = routed
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());
        let csrf = routed
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("x-csrf-token"))
            .map(|(_, v)| v.clone());
        assert_eq!(ct.as_deref(), Some("application/json"));
        assert_eq!(csrf.as_deref(), Some("token-123"));
    }

    #[tokio::test]
    async fn coordinator_caches_per_mode_header_policy() {
        let c = coord(ConfigMode::Standard).await;
        let g = c.lock().await;
        let std = g.header_policy_for(Mode::Standard);
        let strict = g.header_policy_for(Mode::Strict);
        assert_eq!(
            std.referer,
            crate::headers::RefererPolicy::StrictOriginWhenCrossOrigin
        );
        assert_eq!(strict.referer, crate::headers::RefererPolicy::NoReferrer);
    }

    #[tokio::test]
    async fn coordinator_set_header_policy_overrides_cache() {
        let c = coord(ConfigMode::Standard).await;
        let mut custom = HeaderPolicy::standard();
        custom.send_dnt = false;
        {
            let mut g = c.lock().await;
            g.set_header_policy(custom);
        }
        let g = c.lock().await;
        assert!(!g.header_policy_for(Mode::Standard).send_dnt);
        // Strict policy snapshot is untouched.
        assert!(g.header_policy_for(Mode::Strict).send_dnt);
    }

    #[tokio::test]
    async fn coordinator_blocklist_can_be_swapped_at_runtime() {
        let c = coord(ConfigMode::Standard).await;
        let v1 = Blocklist::from_manifest(&manifest_blocking("a.example", BK::Ad));
        {
            let mut g = c.lock().await;
            g.set_blocklist(v1);
        }
        let req1 = req_to("https://a.example/x");
        {
            let mut g = c.lock().await;
            assert!(matches!(g.route(req1), Err(NetworkError::Blocked)));
        }
        let v2 = Blocklist::from_manifest(&manifest_blocking("b.example", BK::Tracker));
        {
            let mut g = c.lock().await;
            g.set_blocklist(v2);
        }
        // a.example is no longer blocked, b.example now is.
        let req2 = req_to("https://a.example/x");
        let req3 = req_to("https://b.example/x");
        let mut g = c.lock().await;
        assert!(g.route(req2).is_ok());
        assert!(matches!(g.route(req3), Err(NetworkError::Blocked)));
    }

    #[test]
    fn parse_host_basic() {
        assert_eq!(
            parse_host("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_host("https://example.com:8443/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_host("https://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_host("https://example.com?q=1"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_host("https://example.com#frag"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn parse_host_strips_userinfo() {
        assert_eq!(
            parse_host("https://user:pass@example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_host("https://user@example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn parse_host_handles_ipv6_literal() {
        assert_eq!(
            parse_host("https://[2001:db8::1]/path"),
            Some("2001:db8::1".to_string())
        );
        assert_eq!(
            parse_host("https://[2001:db8::1]:8443/path"),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn parse_host_rejects_invalid() {
        assert_eq!(parse_host(""), None);
        assert_eq!(parse_host("not-a-url"), None);
        assert_eq!(parse_host("https://"), None);
        assert_eq!(parse_host("https:///path"), None);
    }

    #[tokio::test]
    async fn coordinator_has_resolver_reflects_wiring() {
        let c = coord(ConfigMode::Standard).await;
        {
            let g = c.lock().await;
            assert!(!g.has_resolver(), "fresh coordinator has no resolver");
        }
        let resolver = Arc::new(CountingResolver {
            calls: std::sync::atomic::AtomicU32::new(0),
        });
        {
            let mut g = c.lock().await;
            g.set_resolver(resolver);
        }
        let g = c.lock().await;
        assert!(g.has_resolver());
    }
}
