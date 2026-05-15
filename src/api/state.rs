//! Shared application state for the API layer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use bytes::Bytes;
use moka::future::Cache;
use tokio::sync::{broadcast, mpsc, oneshot, Semaphore};

use crate::ipfs::client::IpfsClient;
use crate::messages::router::MessageRouter;
use crate::metrics::counters::NetworkCounters;
use crate::metrics::ring_buffer::RingBuffer;
use crate::metrics::MetricsSnapshot;
use crate::notifications::alerts::SharedAlertHistory;
use crate::notifications::engine::NotificationEngine;
use crate::pow::PowManager;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;

/// Info about a connected Ogmara peer (from libp2p Identify).
#[derive(Debug, Clone)]
pub struct ConnectedPeerInfo {
    /// Agent version string (e.g. "ogmara-node/0.21.0").
    pub agent_version: String,
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
    /// Concurrent media handler permits.
    pub handler_permits: usize,
}

impl Default for MediaTuning {
    fn default() -> Self {
        Self {
            cache_total_bytes: DEFAULT_MEDIA_CACHE_TOTAL_BYTES,
            cache_item_bytes: DEFAULT_MEDIA_CACHE_ITEM_BYTES,
            handler_permits: DEFAULT_MEDIA_HANDLER_PERMITS,
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
#[derive(Clone)]
pub struct CachedMedia {
    pub bytes: Bytes,
    pub content_type: String,
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
    /// Semaphore bounding concurrent `/api/v1/media/:cid` handlers.
    /// Combined with per-fetch caps, this bounds peak transient RSS
    /// from the media endpoint to roughly
    /// `permits * max_upload_size_mb` MiB.
    pub media_semaphore: Arc<Semaphore>,
    /// Per-item cache cap (bytes). Items above this size are NOT
    /// inserted into `media_cache`; they're streamed from IPFS each
    /// time. Read by `get_media` to decide between full-fetch and
    /// stream-range paths. Set from `IpfsConfig::media_cache_item_mb`.
    pub media_cache_item_bytes: usize,
}

impl AppState {
    pub fn new(
        storage: Storage,
        router: MessageRouter,
        node_id: String,
        klever_network: String,
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
        Self::with_broadcast(
            storage,
            router,
            node_id,
            klever_network,
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
        let media_semaphore = Arc::new(Semaphore::new(media_tuning.handler_permits));
        Self {
            storage,
            router,
            node_id,
            started_at: Instant::now(),
            peers: peer_count,
            ws_broadcast,
            klever_network,
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
            media_semaphore,
            media_cache_item_bytes: media_tuning.cache_item_bytes,
        }
    }

    pub fn peer_count(&self) -> u32 {
        self.peers.load(Ordering::Relaxed)
    }

    pub fn set_peer_count(&self, count: u32) {
        self.peers.store(count, Ordering::Relaxed);
    }
}
