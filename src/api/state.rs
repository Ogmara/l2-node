//! Shared application state for the API layer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use bytes::Bytes;
use moka::future::Cache;
use tokio::sync::{broadcast, mpsc, oneshot};

use super::media_limiter::PerIpSemaphore;

use crate::ipfs::client::IpfsClient;
use crate::trusted_proxies::TrustedProxies;
use crate::messages::router::MessageRouter;
use crate::metrics::counters::NetworkCounters;
use crate::metrics::ring_buffer::RingBuffer;
use crate::metrics::MetricsSnapshot;
use crate::notifications::alerts::SharedAlertHistory;
use crate::notifications::engine::NotificationEngine;
use crate::pow::PowManager;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;

/// Which bootstrap tier produced a connected peer's dial chain *this
/// session*. Set when libp2p Identify completes for the peer. The
/// session-time property has no persisted byte — peers are not "from
/// the book" until they actually connect on a subsequent startup,
/// even if `PEER_DIRECTORY` holds an entry.
///
/// Spec 13 §4.1 / §8: drives the dashboard Network-tab peer-source
/// breakdown column and the `bootstrap-candidates` REST response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoverySource {
    /// Tier 1 — peer was in `PEER_DIRECTORY` at startup (persisted
    /// from a prior session) and connected on this startup.
    Book,
    /// Tier 2 — peer was in `[network] bootstrap_nodes` config and
    /// connected from that dial.
    Config,
    /// Tier 3 — peer was added by sc_discovery (§4.3) this session.
    Sc,
    /// Tier 4 — peer was learned at runtime: Kademlia DHT, mDNS,
    /// peer-exchange, or accepted as an inbound dial.
    Runtime,
}

/// Info about a connected Ogmara peer (from libp2p Identify).
#[derive(Debug, Clone)]
pub struct ConnectedPeerInfo {
    /// Agent version string (e.g. "ogmara-node/0.21.0").
    pub agent_version: String,
    /// Which bootstrap tier produced this peer's dial chain this
    /// session (spec 13 §4.1). Set on Identify::Received.
    pub source: DiscoverySource,
}

// --- Media handler tunables (v0.39, config-driven in v0.40) ----------------
//
// These caps shape the memory footprint of `/api/v1/media/:cid`. The
// rationale is documented in CHANGELOG v0.39.0 — short version: the
// pre-0.39 handler buffered the full IPFS blob on every request with
// no concurrency cap, which made the endpoint a candidate DoS vector
// under sustained load (200 concurrent clients × 50 MB ≈ 10 GB RSS).
//
// `cache_total_bytes` bounds the moka LRU's total weight; entries are
// evicted least-recently-used when adding pushes over the cap.
// `cache_item_bytes` skips caching files larger than this (large
// videos are streamed from IPFS each time — the content-addressed
// property means Apache + browser caches still help on repeated
// viewers, and a single video doesn't push out hundreds of small
// thumbnails).
//
// `handler_permits` caps concurrent media handlers; further requests
// queue on the semaphore. Combined with the per-fetch
// `max_upload_bytes`, peak transient RSS is bounded at
// permits × max_upload. With defaults (32 × 50 MB = 1.6 GB) this is
// comfortably below a single-node OOM threshold.

/// Default total bytes the media LRU is allowed to hold across all
/// entries (used when no `IpfsConfig::media_cache_total_mb` is set).
pub const DEFAULT_MEDIA_CACHE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Default per-item cache cap.
pub const DEFAULT_MEDIA_CACHE_ITEM_BYTES: usize = 16 * 1024 * 1024;

/// Default concurrent media handler permits.
pub const DEFAULT_MEDIA_HANDLER_PERMITS: usize = 32;

/// Default per-IP concurrent media handler permits.
pub const DEFAULT_MEDIA_PER_IP_PERMITS: usize = 4;

/// Default hard cap on distinct IP buckets tracked by the per-IP
/// limiter (v0.42). 65,536 entries at ~150 bytes apiece ≈ 10 MiB
/// of resident DashMap state under worst-case fill — comfortable for
/// any deployment that already provisioned enough RAM for the media
/// cache. The cap engages only under adversarial /24 rotation; honest
/// nodes typically sit well under 1,000 distinct buckets.
pub const DEFAULT_MEDIA_MAX_TRACKED_IPS: usize = 65_536;

/// Runtime values for media-handler resource caps. Built from
/// `IpfsConfig` at node startup and passed into `AppState`; tests use
/// `MediaTuning::default()` to get the documented defaults without
/// dragging `IpfsConfig` into the test surface.
#[derive(Debug, Clone, Copy)]
pub struct MediaTuning {
    /// Total LRU weight in bytes.
    pub cache_total_bytes: u64,
    /// Per-item cache cap in bytes.
    pub cache_item_bytes: usize,
    /// Concurrent media handler permits (global cap).
    pub handler_permits: usize,
    /// Per-IP sub-cap on the global permits (v0.41). One client IP
    /// can hold at most this many permits at once. Caps the
    /// single-IP DoS surface that the v0.39 audit flagged.
    pub per_ip_permits: usize,
    /// Hard cap on the per-IP limiter's tracking map (v0.42). Bounds
    /// memory growth under an adversarial /24-rotation flood that
    /// would otherwise inflate the DashMap between the 5-minute
    /// background sweeps.
    pub max_tracked_ips: usize,
}

impl Default for MediaTuning {
    fn default() -> Self {
        Self {
            cache_total_bytes: DEFAULT_MEDIA_CACHE_TOTAL_BYTES,
            cache_item_bytes: DEFAULT_MEDIA_CACHE_ITEM_BYTES,
            handler_permits: DEFAULT_MEDIA_HANDLER_PERMITS,
            per_ip_permits: DEFAULT_MEDIA_PER_IP_PERMITS,
            max_tracked_ips: DEFAULT_MEDIA_MAX_TRACKED_IPS,
        }
    }
}

/// One cached media body + its sniffed Content-Type. Caching the type
/// alongside the bytes avoids re-running `detect_content_type` on
/// every cache hit AND avoids a second IPFS round-trip in the
/// stream-range path (where the requested range may not start at byte
/// 0 — without a cached type we'd otherwise have to fetch a 16-byte
/// prefix just to sniff). The `Bytes` is reference-counted so cloning
/// is O(1).
///
/// `last_modified` records when the entry was first cached. Used to
/// emit `Last-Modified` on responses and to match `If-Range`
/// HTTP-date validators (v0.42). CIDs are immutable so semantically
/// the value is "when this node first observed the content"; on cache
/// eviction + re-fetch the value updates, which means a client that
/// got `Last-Modified: T1` from a previous request and tries to
/// resume with `If-Range: T1` after eviction will see no match and
/// fall back to a fresh 200 — correct per RFC 7233 §3.2.
#[derive(Clone)]
pub struct CachedMedia {
    pub bytes: Bytes,
    pub content_type: String,
    pub last_modified: std::time::SystemTime,
}

/// Shared state accessible to all API handlers.
pub struct AppState {
    /// Persistent storage.
    pub storage: Storage,
    /// Message router for processing incoming envelopes.
    pub router: MessageRouter,
    /// Node ID.
    pub node_id: String,
    /// When the node started.
    pub started_at: Instant,
    /// Connected peer count (shared with the network layer).
    peers: Arc<AtomicU32>,
    /// Broadcast channel for forwarding messages to WebSocket clients.
    pub ws_broadcast: broadcast::Sender<String>,
    /// Klever network name ("testnet" or "mainnet"), derived from config.
    pub klever_network: String,
    /// Klever node RPC URL (e.g. https://node.testnet.klever.org). Used
    /// by admin handlers that need to make SC view calls — the node
    /// itself anchors via the same URL but holds it inside
    /// `StateAnchorer`, not in `AppState`.
    pub klever_node_url: String,
    /// Shared `reqwest::Client` for outbound Klever VM view calls from
    /// admin handlers. One pooled client across all handlers — avoids
    /// the per-request TLS-pool reallocation that the v0.43.0 code
    /// audit flagged. 15s timeout matches the rest of the codebase.
    pub klever_view_http: reqwest::Client,
    /// Ogmara KApp smart contract address (from config).
    pub contract_address: String,
    /// Node's Klever wallet address (klv1...).
    pub node_address: String,
    /// IPFS client for media upload/retrieval (None if IPFS not configured).
    pub ipfs: Option<IpfsClient>,
    /// Device-to-wallet identity resolver (cached lookups).
    pub identity: IdentityResolver,
    /// Public URL where this node's API is reachable (from config).
    pub public_url: Option<String>,
    /// Notification engine for mention detection and push delivery.
    /// `None` if push gateway is not configured.
    pub notification_engine: Option<Arc<NotificationEngine>>,
    /// Channel to trigger an immediate state anchor from the admin API.
    /// `None` if anchoring is not enabled.
    pub anchor_trigger: Option<mpsc::Sender<oneshot::Sender<Result<String, String>>>>,
    /// Channel to publish messages to GossipSub via the network layer.
    /// Sends (topic_string, raw_envelope_bytes).
    pub gossip_tx: tokio::sync::mpsc::UnboundedSender<(String, Vec<u8>)>,
    /// Connected Ogmara peers (keyed by node_id), updated by the network layer.
    /// Used by `/api/v1/network/nodes` to include peers that haven't announced yet.
    pub connected_peers: Arc<RwLock<HashMap<String, ConnectedPeerInfo>>>,
    /// Shared network counters for metrics collection (dashboard spec §6.2).
    pub counters: Arc<NetworkCounters>,
    /// Latest metrics snapshot from the MetricsCollector (dashboard spec §6).
    pub metrics_latest: Arc<RwLock<MetricsSnapshot>>,
    /// Metrics history ring buffer (24h at 1-min resolution).
    pub metrics_history: Arc<RwLock<RingBuffer<MetricsSnapshot>>>,
    /// Shared alert history from the AlertEngine (spec 10-dashboard.md §9).
    pub alert_history: SharedAlertHistory,
    /// PoW anti-spam manager (None = PoW disabled).
    pub pow: Option<Arc<PowManager>>,
    /// Shared snapshot cache (spec 11-snapshot-sync.md). Populated by the
    /// background cache builder; read by `/admin/snapshot/status`.
    /// Inner option is `None` until the first build completes.
    pub snapshot_cache: crate::network::snapshot::SharedSnapshotCache,
    /// LRU cache of fully-fetched media (body + sniffed content-type),
    /// keyed by CID. Hot media (small thumbnails, frequently-accessed
    /// images) serves from memory; items above
    /// `media_cache_item_bytes` are never inserted and stream-from-IPFS
    /// on every request. Bounded total weight at
    /// `IpfsConfig::media_cache_total_mb` (in `with_broadcast`).
    pub media_cache: Cache<String, CachedMedia>,
    /// Per-IP-bounded semaphore limiting concurrent
    /// `/api/v1/media/:cid` handlers (v0.41). Each request needs one
    /// per-IP slot AND one global slot. Per-IP exhaustion → 429;
    /// global exhaustion → FIFO queue. Closes the single-IP DoS
    /// surface that the v0.39 audit flagged on the global-only design.
    pub media_limiter: Arc<PerIpSemaphore>,
    /// Per-item cache cap (bytes). Items above this size are NOT
    /// inserted into `media_cache`; they're streamed from IPFS each
    /// time. Read by `get_media` to decide between full-fetch and
    /// stream-range paths. Set from `IpfsConfig::media_cache_item_mb`.
    pub media_cache_item_bytes: usize,
    /// Trusted-proxy set for client-IP resolution (v0.42). Built
    /// from `api.trusted_proxies` at startup. The per-IP media
    /// limiter and any future trust-the-proxy surface consult this
    /// alongside the implicit loopback trust. Arc'd because handlers
    /// hold cheap clones.
    pub trusted_proxies: Arc<TrustedProxies>,
    /// Consecutive canonicalized heights at which our submitted root
    /// disagreed with the on-chain canonical root (spec 12 §6.1).
    /// Reset to 0 on every match; reaching `anchor_divergence_consecutive`
    /// trips the `anchor_divergence` alert. Written by the divergence
    /// watcher in `chain::anchoring::StateAnchorer::check_divergence`,
    /// read by both the metrics collector (into `MetricsSnapshot`) and
    /// the admin registration endpoint.
    pub anchor_divergence_counter: Arc<AtomicU32>,
    /// Lifetime count of our submissions that reached canonical
    /// (quorum-confirmed) status. Increments per match observed by
    /// the divergence watcher. Resets across node restarts —
    /// process-local counter, not persisted.
    pub anchor_canonical_counter: Arc<AtomicU64>,
    /// libp2p listen port from `[network] listen_port`. Used by the
    /// `/admin/node/metadata` endpoint to auto-derive the published
    /// multiaddr when `[anchoring.metadata]` enables publish without
    /// explicit multiaddrs (spec 12 §2.10 + spec 13 §6.1).
    pub network_listen_port: u16,
    /// Local libp2p peer-id (base58, e.g. `12D3KooW...`). Required by
    /// the `[anchoring.metadata]` auto-derive path so the published
    /// multiaddr includes `/p2p/<peer_id>` — without it,
    /// `sc_discovery::persist_multiaddr` rejects the entry at the
    /// consumer side (v0.45.0 → 0.45.1 hotfix: every consumer of the
    /// multiaddr needs the peer_id at storage-key time).
    pub network_peer_id: String,
    /// Snapshot of `[anchoring.metadata]` (publish flag + explicit
    /// multiaddrs). Drives `GET /admin/node/metadata`'s effective vs.
    /// on-chain diff. Cloned at startup — operators must restart to
    /// change.
    pub anchor_metadata_config: crate::config::AnchorMetadataConfig,
    /// Snapshot of `[anchoring] pause_on_shutdown`. Drives the
    /// pause-status payload's `pause_on_shutdown` field. Cloned at
    /// startup — operators must restart to change.
    pub anchor_pause_on_shutdown: bool,
    /// Whether `[anchoring] wallet_key` (or the
    /// `OGMARA_ANCHOR_WALLET_KEY` env var) was set at startup. The
    /// SIGTERM handler only signs `pauseNode` when this is true AND
    /// `pause_on_shutdown` is true; the dashboard surfaces it so the
    /// operator sees why a `pause_on_shutdown = true` config is inert.
    /// Never holds the key itself.
    pub anchor_wallet_key_configured: bool,
    /// Cached `bootstrap-candidates` payload body + age tracking.
    /// Spec 13 §4.5 — 5-min positive TTL, 60-s negative TTL.
    ///
    /// `tokio::sync::RwLock` so concurrent cache-hit readers never
    /// serialize behind each other (Security Audit W2 + Code Audit
    /// W1). Refresh writers also acquire write here, but only briefly
    /// at the END of regeneration — the SC RPC fan-out happens
    /// LOCK-FREE under the separate `bootstrap_candidates_refresh`
    /// mutex below.
    pub bootstrap_candidates_cache:
        Arc<tokio::sync::RwLock<Option<CachedBootstrapCandidates>>>,
    /// Single-flight gate for `bootstrap-candidates` regeneration.
    /// Held across SC RPC calls; one regeneration in flight at a
    /// time. Cache-hit readers do NOT touch this — they use the
    /// RwLock above. Concurrent miss-readers serialize here, but the
    /// one that wins the lock typically completes within seconds;
    /// the rest re-check the cache after acquiring and skip the
    /// fan-out if a sibling refresh populated it in the meantime.
    pub bootstrap_candidates_refresh: Arc<tokio::sync::Mutex<()>>,
    /// Snapshot of `[network.discovery] max_peer_staleness_days`,
    /// converted to seconds. Used by the bootstrap-candidates handler
    /// to filter out registry entries whose last anchor is too old to
    /// be a useful dial target (spec 13 §7 + spec 13 §6.3 cap).
    pub max_peer_staleness_secs: u64,
    /// Snapshot of `[network] bootstrap_nodes` at startup. Powers the
    /// tier-2 source in the `bootstrap-candidates` REST union (spec 13
    /// §4.5). Cloned once — operators must restart to change.
    pub bootstrap_nodes: Vec<String>,
    /// Shared drift snapshot written by the
    /// [`crate::chain::metadata_reconcile::MetadataReconciler`] task
    /// (spec 13 §6.1) and read by the `node_metadata` admin endpoint.
    /// `None` when no drift has been observed, when the reconciler is
    /// not spawned (anchoring or publish disabled), or when the most
    /// recent reconcile pass found the on-chain list in sync.
    pub metadata_drift: crate::chain::metadata_reconcile::SharedMetadataDrift,
}

/// Cached bootstrap-candidates response (spec 13 §4.5).
///
/// Wraps the rendered JSON and the wall-clock generation timestamp.
/// TTL check in the handler uses tokio's monotonic `Instant` for
/// drift-immunity; the `generated_at_unix` field is the body's own
/// timestamp so consumers can compute cache-age.
#[derive(Clone)]
pub struct CachedBootstrapCandidates {
    /// Body of the cached response — already rendered. Cloned on
    /// cache hit so the response handler never re-serializes.
    pub payload: serde_json::Value,
    /// `Instant` at generation — used for TTL comparison.
    pub generated_at: Instant,
    /// Unix-seconds at generation — embedded in `payload.generated_at`.
    pub generated_at_unix: u64,
}

impl AppState {
    /// Simplified test constructor. **Production goes through
    /// `with_broadcast`** because that's where the StateAnchorer and
    /// MetricsCollector get clones of the same shared counters / channels.
    /// Anchor-divergence and canonical counters created here are
    /// process-local to the returned AppState — writers (StateAnchorer,
    /// not constructed by this fn) won't share them, so the dashboard
    /// will always read 0. Fine for tests; do not use in production.
    pub fn new(
        storage: Storage,
        router: MessageRouter,
        node_id: String,
        klever_network: String,
        klever_node_url: String,
        contract_address: String,
        ipfs: Option<IpfsClient>,
        identity: IdentityResolver,
        public_url: Option<String>,
        notification_engine: Option<Arc<NotificationEngine>>,
        anchor_trigger: Option<mpsc::Sender<oneshot::Sender<Result<String, String>>>>,
    ) -> Self {
        let (ws_broadcast, _) = broadcast::channel(1024);
        let (gossip_tx, _) = tokio::sync::mpsc::unbounded_channel();
        let counters = Arc::new(NetworkCounters::new());
        let metrics_latest = Arc::new(RwLock::new(MetricsSnapshot::default()));
        let metrics_history = Arc::new(RwLock::new(RingBuffer::new(1440)));
        let alert_history = Arc::new(RwLock::new(std::collections::VecDeque::new()));
        let anchor_divergence_counter = Arc::new(AtomicU32::new(0));
        let anchor_canonical_counter = Arc::new(AtomicU64::new(0));
        Self::with_broadcast(
            storage,
            router,
            node_id,
            klever_network,
            klever_node_url,
            contract_address,
            ipfs,
            identity,
            public_url,
            notification_engine,
            ws_broadcast,
            anchor_trigger,
            Arc::new(AtomicU32::new(0)),
            gossip_tx,
            Arc::new(RwLock::new(HashMap::new())),
            counters,
            metrics_latest,
            metrics_history,
            alert_history,
            None, // PoW disabled in test/simplified constructor
            String::new(), // node_address not needed in test constructor
            Arc::new(RwLock::new(None)), // snapshot cache — empty in tests
            MediaTuning::default(),
            Arc::new(TrustedProxies::default()),
            anchor_divergence_counter,
            anchor_canonical_counter,
            0,                                              // network_listen_port — unused in tests
            String::new(),                                  // network_peer_id — unused in tests
            crate::config::AnchorMetadataConfig::default(), // anchor_metadata_config
            false,                                          // anchor_pause_on_shutdown
            false,                                          // anchor_wallet_key_configured
            7 * 24 * 3600,                                  // max_peer_staleness_secs — 7d default
            Vec::new(),                                     // bootstrap_nodes — empty in tests
            crate::chain::metadata_reconcile::shared_metadata_drift(),
        )
    }

    /// Create AppState with an externally provided broadcast channel.
    ///
    /// Used when the notification engine needs to share the same broadcast
    /// channel as the WebSocket layer.
    #[allow(clippy::too_many_arguments)]
    pub fn with_broadcast(
        storage: Storage,
        router: MessageRouter,
        node_id: String,
        klever_network: String,
        klever_node_url: String,
        contract_address: String,
        ipfs: Option<IpfsClient>,
        identity: IdentityResolver,
        public_url: Option<String>,
        notification_engine: Option<Arc<NotificationEngine>>,
        ws_broadcast: broadcast::Sender<String>,
        anchor_trigger: Option<mpsc::Sender<oneshot::Sender<Result<String, String>>>>,
        peer_count: Arc<AtomicU32>,
        gossip_tx: tokio::sync::mpsc::UnboundedSender<(String, Vec<u8>)>,
        connected_peers: Arc<RwLock<HashMap<String, ConnectedPeerInfo>>>,
        counters: Arc<NetworkCounters>,
        metrics_latest: Arc<RwLock<MetricsSnapshot>>,
        metrics_history: Arc<RwLock<RingBuffer<MetricsSnapshot>>>,
        alert_history: SharedAlertHistory,
        pow: Option<Arc<PowManager>>,
        node_address: String,
        snapshot_cache: crate::network::snapshot::SharedSnapshotCache,
        media_tuning: MediaTuning,
        trusted_proxies: Arc<TrustedProxies>,
        anchor_divergence_counter: Arc<AtomicU32>,
        anchor_canonical_counter: Arc<AtomicU64>,
        network_listen_port: u16,
        network_peer_id: String,
        anchor_metadata_config: crate::config::AnchorMetadataConfig,
        anchor_pause_on_shutdown: bool,
        anchor_wallet_key_configured: bool,
        max_peer_staleness_secs: u64,
        bootstrap_nodes: Vec<String>,
        metadata_drift: crate::chain::metadata_reconcile::SharedMetadataDrift,
    ) -> Self {
        // moka LRU with size-weighted eviction. `weigher` returns the
        // byte count of each value's body (content-type string is
        // negligible); once `max_capacity` is reached, moka evicts
        // least-recently-used entries until the new insert fits. The
        // `try_into().unwrap_or(u32::MAX)` is defensive — we already
        // gate inserts at `media_cache_item_bytes` so values can't
        // exceed u32::MAX, but a future bug that bypasses the gate
        // should saturate rather than panic on the cast.
        let media_cache: Cache<String, CachedMedia> = Cache::builder()
            .weigher(|_k: &String, v: &CachedMedia| {
                v.bytes.len().try_into().unwrap_or(u32::MAX)
            })
            .max_capacity(media_tuning.cache_total_bytes)
            .build();
        let media_limiter = PerIpSemaphore::new(
            media_tuning.handler_permits,
            media_tuning.per_ip_permits,
            media_tuning.max_tracked_ips,
        );
        // Pool one HTTP client for all admin-side Klever view calls.
        // Falls back to `Client::new()` if the configured client fails
        // to build (extremely unlikely — only known cause is missing
        // TLS backend; default reqwest features include `default-tls`).
        let klever_view_http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            storage,
            router,
            node_id,
            started_at: Instant::now(),
            peers: peer_count,
            ws_broadcast,
            klever_network,
            klever_node_url,
            klever_view_http,
            contract_address,
            node_address,
            ipfs,
            identity,
            public_url,
            notification_engine,
            anchor_trigger,
            gossip_tx,
            connected_peers,
            counters,
            metrics_latest,
            metrics_history,
            alert_history,
            pow,
            snapshot_cache,
            media_cache,
            media_limiter,
            media_cache_item_bytes: media_tuning.cache_item_bytes,
            trusted_proxies,
            anchor_divergence_counter,
            anchor_canonical_counter,
            network_listen_port,
            network_peer_id,
            anchor_metadata_config,
            anchor_pause_on_shutdown,
            anchor_wallet_key_configured,
            bootstrap_candidates_cache: Arc::new(tokio::sync::RwLock::new(None)),
            bootstrap_candidates_refresh: Arc::new(tokio::sync::Mutex::new(())),
            max_peer_staleness_secs,
            bootstrap_nodes,
            metadata_drift,
        }
    }

    pub fn peer_count(&self) -> u32 {
        self.peers.load(Ordering::Relaxed)
    }

    pub fn set_peer_count(&self, count: u32) {
        self.peers.store(count, Ordering::Relaxed);
    }
}
