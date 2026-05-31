//! libp2p network layer — peer discovery, GossipSub, sync protocol.
//!
//! Handles all peer-to-peer communication using libp2p (spec 3.1).
//! Components:
//! - Peer discovery: mDNS (local), Kademlia DHT (global), bootstrap nodes
//! - GossipSub: pub/sub message propagation across topic channels
//! - Request/Response: sync protocol for on-demand content fetching
//! - Identify: peer identification and capability exchange

pub mod behaviour;
pub mod discovery;
pub mod gossip;
pub mod mesh_stats;
pub mod reconcile;
pub mod sc_discovery;
pub mod snapshot;
pub mod snapshot_client;
pub mod sync;
pub mod tor;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{kad, Multiaddr, PeerId, Swarm};
use tracing::{debug, error, info, warn};

use crate::api::state::ConnectedPeerInfo;
use crate::config::Config;
use crate::messages::envelope::Envelope;
use crate::messages::router::{MessageRouter, RouteResult};
use crate::metrics::counters::NetworkCounters;
use crate::notifications::engine::NotificationEngine;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;

use self::behaviour::{OgmaraBehaviour, OgmaraBehaviourEvent};
use self::gossip::TopicManager;
use self::snapshot::SharedSnapshotCache;

/// Peers queued for reconnection after disconnect, with exponential backoff.
struct ReconnectEntry {
    peer_id: PeerId,
    addr: Multiaddr,
    next_attempt: tokio::time::Instant,
    backoff_secs: u64,
    attempts: u32,
}

/// Maximum reconnection attempts before giving up on a peer.
const MAX_RECONNECT_ATTEMPTS: u32 = 10;
/// Base backoff for reconnection attempts (seconds).
const RECONNECT_BASE_SECS: u64 = 5;
/// Maximum backoff cap (seconds).
const RECONNECT_MAX_SECS: u64 = 300;

/// The running network layer.
pub struct NetworkService {
    /// The libp2p swarm managing all protocols.
    swarm: Swarm<OgmaraBehaviour>,
    /// GossipSub topic manager.
    pub topics: TopicManager,
    /// Message router for validation pipeline.
    router: MessageRouter,
    /// Storage reference for sync operations.
    storage: Storage,
    /// Notification engine for mention detection and push delivery.
    notification_engine: Option<Arc<NotificationEngine>>,
    /// Shared peer count (read by API health endpoint).
    peer_count: Arc<AtomicU32>,
    /// Node identity for signing announcements.
    signing_key: ed25519_dalek::SigningKey,
    /// Node ID (Base58).
    node_id: String,
    /// Public API URL (if configured).
    public_url: Option<String>,
    /// Connected Ogmara peers (shared with API layer for /network/nodes).
    connected_peers: Arc<RwLock<HashMap<String, ConnectedPeerInfo>>>,
    /// Internal mapping: libp2p PeerId → Ogmara node_id (for removal on disconnect).
    peer_node_ids: HashMap<PeerId, String>,
    /// Shared network counters for metrics dashboard (spec 10-dashboard.md §6.2).
    counters: Arc<NetworkCounters>,
    /// Bootstrap node addresses (for periodic redial when peers are low).
    bootstrap_addrs: Vec<Multiaddr>,
    /// Peers queued for reconnection after disconnect (with backoff).
    reconnect_queue: Vec<ReconnectEntry>,
    /// Known peer addresses from Identify (PeerId → best known address).
    /// Used to reconnect after disconnect.
    known_peer_addrs: HashMap<PeerId, Multiaddr>,
    /// Shared snapshot cache — populated by the background cache-builder
    /// task in `Node::run`. `None` until the first build completes.
    snapshot_cache: SharedSnapshotCache,
    /// Whether this node advertises and answers snapshot requests
    /// (mirrors `config.snapshot.serve_enabled` at startup).
    snapshot_serve_enabled: bool,
    /// Concurrency limiter for outbound `SnapshotResponse::Chunk` sends.
    /// `try_acquire`d in `handle_snapshot_event` for `GetChunk`. Sized from
    /// `config.snapshot.serve_max_concurrent_requests`. Phase 1 — exists
    /// to bound the working-set even if a peer pipelines many GetChunks.
    snapshot_chunk_semaphore: Arc<tokio::sync::Semaphore>,
    /// Inbound channel for snapshot-client commands (Phase 2). The
    /// bootstrap task constructs `SnapshotRequest`s and sends them via
    /// this channel; we forward each to the swarm and stash a oneshot
    /// sender keyed by the libp2p `OutboundRequestId` so the matching
    /// response (or failure) is delivered back to the caller.
    snapshot_client_rx: tokio::sync::mpsc::UnboundedReceiver<SnapshotClientCommand>,
    /// Outstanding outbound snapshot requests awaiting a response.
    pending_snapshot_requests:
        HashMap<libp2p::request_response::OutboundRequestId, tokio::sync::oneshot::Sender<SnapshotClientResult>>,
    /// Successful-Identify counter (spec 13 §4.3 stall trigger).
    /// Incremented every time we accept an Identify::Received event
    /// from a peer with our network protocol. Shared with
    /// `sc_discovery::ScDiscovery::run` so its 60s post-startup check
    /// can detect total isolation (zero peers identified ⇒ tier 1 +
    /// tier 2 came up empty ⇒ fire SC fan-out).
    identify_success_count: Arc<AtomicU64>,
    /// Snapshot of peer IDs present in `PEER_DIRECTORY` at startup —
    /// used to classify Identify::Received events as `book` tier
    /// (spec 13 §4.1). Not updated after startup: peers persisted
    /// later in the session were not "from the book" on this startup,
    /// they came from whichever tier produced their first dial.
    startup_book_peer_ids: HashSet<PeerId>,
    /// Peer IDs extracted from `[network] bootstrap_nodes` config —
    /// used to classify Identify::Received events as `config` tier.
    config_peer_ids: HashSet<PeerId>,
    /// Peer IDs that `sc_discovery::ScDiscovery::persist_multiaddr`
    /// has written to `PEER_DIRECTORY` this session. Cross-task
    /// shared so the Identify handler can classify them as `sc` tier
    /// (spec 13 §4.1 / §4.3). Population happens in sc_discovery, so
    /// the lock is acquired only briefly (HashSet insert / contains).
    sc_added_peer_ids: Arc<RwLock<HashSet<PeerId>>>,
    /// Cumulative publish-failure counters, partitioned by
    /// `PublishError` variant (spec 10 §9.2, l2-node 0.46.6+). Shared
    /// with `AppState` so the `/admin/network/mesh-stats` endpoint
    /// reads live values without blocking the publish hot path.
    publish_failure_counters: mesh_stats::PublishFailureCounters,
    /// Shared mesh-state snapshot, refreshed by this task every
    /// `MESH_STATS_REFRESH_INTERVAL` (30s). Single writer (this
    /// task), many readers (admin endpoint, future dashboards).
    mesh_stats: mesh_stats::SharedMeshStats,
    /// Optional alert sender — `None` when `[alerts] enabled =
    /// false`. Used to fire the `publish_failed_insufficient_peers`
    /// alert when a publish hits `NoPeersSubscribedToTopic`. The
    /// cooldown engine deduplicates re-fires.
    alert_event_tx: Option<crate::notifications::alerts::AlertEventSender>,
    /// Snapshot of `[backfill]` (spec 1 §channel-history-reconciliation,
    /// l2-node 0.47.0+). Drives the cold-join trigger in
    /// `subscribe_channel` and the responder-side rate limits.
    backfill_config: crate::config::BackfillConfig,
    /// Server-side rate-limit state for inbound `ReconcileRequest`s.
    /// Bounded by `[backfill] server_max_concurrent_per_peer` and
    /// `server_max_concurrent_per_channel`.
    reconcile_limits: Arc<reconcile::ResponderLimits>,
    /// Outstanding outbound reconciliation requests, keyed by
    /// libp2p `OutboundRequestId`. Resolves to a `(peer_id,
    /// channel_id)` pair so the response handler can route the
    /// envelopes to the right channel and either request the next
    /// cursor batch or finish.
    pending_reconcile_requests: HashMap<
        libp2p::request_response::OutboundRequestId,
        ReconcilePending,
    >,
    /// Channel IDs the local node has triggered backfill for AT
    /// LEAST once during the current process lifetime. Stops
    /// repeated `subscribe_channel` calls (chain-scanner sends one
    /// per discovered channel) from spamming reconciliation when
    /// the local index is still empty for a different reason
    /// (e.g., the channel is genuinely silent). Cleared on process
    /// restart.
    reconcile_triggered: HashSet<u64>,
}

/// Per-pending-outbound-reconciliation state.
#[derive(Debug, Clone)]
struct ReconcilePending {
    peer_id: PeerId,
    channel_id: u64,
}

/// Cross-channel smuggling defense (Security Audit W1, 0.47.0).
/// Returns `true` iff the envelope's payload claims the same
/// `channel_id` we are reconciling. Envelopes that target a
/// different channel are dropped before routing — a malicious
/// responder cannot use our reconcile request to seed arbitrary
/// channel content into our local indexes.
///
/// We do not need to be fully strict here: the worst that happens
/// on a false-positive (we accept an envelope whose payload doesn't
/// even have a `channel_id` field) is that the envelope goes through
/// the standard router and is rejected by payload-specific
/// validation. The cheap pre-check just keeps the obvious smuggle
/// out of the router pipeline.
fn envelope_targets_channel(env_bytes: &[u8], expected_channel: u64) -> bool {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::MessageType;
    let envelope: Envelope = match rmp_serde::from_slice(env_bytes) {
        Ok(e) => e,
        Err(_) => return false,
    };
    match envelope.msg_type {
        MessageType::ChatMessage
        | MessageType::ChatEdit
        | MessageType::ChatDelete
        | MessageType::ChatReaction
        | MessageType::ChannelPinMessage
        | MessageType::ChannelUnpinMessage
        | MessageType::ChannelJoin
        | MessageType::ChannelLeave => {
            let payload: serde_json::Value =
                match rmp_serde::from_slice(&envelope.payload) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
            payload
                .get("channel_id")
                .and_then(|v| v.as_u64())
                .map(|cid| cid == expected_channel)
                .unwrap_or(false)
        }
        // Non-channel message types should not appear in
        // CHANNEL_MSGS, but be conservative — accept them and let
        // the router decide.
        _ => true,
    }
}

/// How often `NetworkService` refreshes the shared `MeshStatsSnapshot`.
/// Short enough that an operator running `watch -n5
/// 'curl /admin/network/mesh-stats'` sees fresh data every other
/// poll; long enough that the periodic gossipsub introspection
/// doesn't compete with the publish hot path.
pub const MESH_STATS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Result delivered back to the snapshot client for one outbound request.
pub type SnapshotClientResult = Result<self::snapshot::SnapshotResponse, SnapshotClientError>;

/// Error variants surfaced to the snapshot client. Cheap to construct, no I/O.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SnapshotClientError {
    #[error("snapshot outbound failure: {0}")]
    OutboundFailure(String),
    #[error("network task dropped before response arrived")]
    Cancelled,
}

/// Command sent from the snapshot-client task to the network event loop.
///
/// The bootstrap orchestrator runs as a separate task (so the event loop
/// stays responsive to gossip/sync/identify). It dispatches snapshot
/// requests through this channel and receives responses via the embedded
/// `oneshot::Sender`. See `network::snapshot_client::ClientHandle`.
pub enum SnapshotClientCommand {
    /// Send an outbound snapshot request to a specific peer.
    SendRequest {
        peer: PeerId,
        request: self::snapshot::SnapshotRequest,
        reply: tokio::sync::oneshot::Sender<SnapshotClientResult>,
    },
    /// List PeerIds of currently connected peers (the orchestrator filters
    /// down to snapshot-capable ones based on `NodeAnnouncement`).
    ListConnectedPeers {
        reply: tokio::sync::oneshot::Sender<Vec<PeerId>>,
    },
}

impl NetworkService {
    /// Create and start the network service.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: &Config,
        storage: Storage,
        identity: IdentityResolver,
        keypair: libp2p::identity::Keypair,
        notification_engine: Option<Arc<NotificationEngine>>,
        peer_count: Arc<AtomicU32>,
        signing_key: ed25519_dalek::SigningKey,
        node_id: String,
        connected_peers: Arc<RwLock<HashMap<String, ConnectedPeerInfo>>>,
        counters: Arc<NetworkCounters>,
        snapshot_cache: SharedSnapshotCache,
        snapshot_client_rx: tokio::sync::mpsc::UnboundedReceiver<SnapshotClientCommand>,
        identify_success_count: Arc<AtomicU64>,
        sc_added_peer_ids: Arc<RwLock<HashSet<PeerId>>>,
        publish_failure_counters: mesh_stats::PublishFailureCounters,
        mesh_stats: mesh_stats::SharedMeshStats,
        alert_event_tx: Option<crate::notifications::alerts::AlertEventSender>,
        backfill_config: crate::config::BackfillConfig,
    ) -> Result<Self> {
        let mut swarm = behaviour::build_swarm(config, keypair)
            .context("building libp2p swarm")?;

        // Listen on configured port (QUIC primary, TCP fallback)
        let quic_addr: Multiaddr = format!(
            "/ip4/0.0.0.0/udp/{}/quic-v1",
            config.network.listen_port
        )
        .parse()
        .context("parsing QUIC listen address")?;

        let tcp_addr: Multiaddr = format!(
            "/ip4/0.0.0.0/tcp/{}",
            config.network.listen_port
        )
        .parse()
        .context("parsing TCP listen address")?;

        swarm
            .listen_on(quic_addr.clone())
            .context("listening on QUIC")?;
        swarm
            .listen_on(tcp_addr.clone())
            .context("listening on TCP")?;

        // Inbound onion listen (spec 13 §6.4, l2-node 0.46.9+). When
        // the operator runs an external Tor daemon with a
        // HiddenServicePort directive forwarding to
        // 127.0.0.1:<listen_onion_port>, we open an extra loopback TCP
        // listener so the forwarded traffic terminates in our swarm
        // and goes through the standard Noise/yamux pipeline.
        //
        // The bind is loopback-only — the kernel's port is not exposed
        // on any external interface. Inbound traffic comes exclusively
        // from the Tor daemon's hidden-service forward (which the
        // operator configured to point here). Crucially, this means
        // even if the loopback address is wrong (e.g., Tor configured
        // to forward to a non-loopback port the operator typed by
        // mistake), the listener does NOT accept clearnet connections
        // — the misconfigured Tor service is what would carry them.
        if config.network.tor.enabled
            && !config.network.tor.listen_onion_hostname.is_empty()
            && config.network.tor.listen_onion_port != 0
        {
            let onion_local_addr: Multiaddr = format!(
                "/ip4/127.0.0.1/tcp/{}",
                config.network.tor.listen_onion_port
            )
            .parse()
            .context("parsing onion-inbound loopback listen address")?;
            match swarm.listen_on(onion_local_addr.clone()) {
                Ok(_) => info!(
                    onion_hostname = %config.network.tor.listen_onion_hostname,
                    loopback = %onion_local_addr,
                    "Onion inbound listener up (Tor hidden service forwards here)"
                ),
                Err(e) => warn!(
                    onion_hostname = %config.network.tor.listen_onion_hostname,
                    loopback = %onion_local_addr,
                    error = %e,
                    "Onion inbound listen failed; continuing without onion inbound"
                ),
            }
        }

        info!(
            quic = %quic_addr,
            tcp = %tcp_addr,
            onion_enabled = config.network.tor.enabled,
            "Network listening"
        );

        // Connect to bootstrap nodes and add them to Kademlia.
        // Peer IDs are accumulated into `config_peer_ids` for spec 13
        // §4.1 discovery-source classification — any Identify::Received
        // matching one of these PeerIds is tagged `config` tier.
        let mut bootstrap_addrs = Vec::new();
        let mut config_peer_ids: HashSet<PeerId> = HashSet::new();
        for addr_str in &config.network.bootstrap_nodes {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    // Extract peer ID from multiaddr (the /p2p/<peer_id> component)
                    let peer_id = addr.iter().find_map(|proto| {
                        if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                            Some(id)
                        } else {
                            None
                        }
                    });

                    // Add to Kademlia routing table so DHT bootstrap can find peers
                    if let Some(pid) = peer_id {
                        // Strip /p2p/ from addr for Kademlia (it wants transport-only addrs)
                        let transport_addr: Multiaddr = addr
                            .iter()
                            .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
                            .collect();
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&pid, transport_addr);
                        config_peer_ids.insert(pid);
                    }

                    if let Err(e) = swarm.dial(addr.clone()) {
                        warn!(addr = %addr, error = %e, "Failed to dial bootstrap node");
                    } else {
                        info!(addr = %addr, "Dialing bootstrap node");
                    }
                    bootstrap_addrs.push(addr);
                }
                Err(e) => {
                    warn!(addr = %addr_str, error = %e, "Invalid bootstrap node address");
                }
            }
        }

        // Snapshot PEER_DIRECTORY peer IDs for the `book` discovery-source
        // tier (spec 13 §4.1). One-shot at startup — peers persisted later
        // by sc_discovery this session do NOT belong to the book tier;
        // they belong to whichever tier put them there. Bounded by
        // PEER_DIRECTORY's own 256-entry cap so the HashSet stays small.
        let startup_book_peer_ids: HashSet<PeerId> = storage
            .prefix_iter_cf(
                crate::storage::schema::cf::PEER_DIRECTORY,
                b"pa:",
                256,
            )
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, _v)| {
                // Key format: `pa:<peer_id_str>`. Strip prefix and parse.
                let suffix = k.strip_prefix(b"pa:")?;
                let s = std::str::from_utf8(suffix).ok()?;
                s.parse::<PeerId>().ok()
            })
            .collect();
        debug!(
            count = startup_book_peer_ids.len(),
            config_count = config_peer_ids.len(),
            "Discovery-source snapshots captured (spec 13 §4.1)"
        );

        // Create topic manager and subscribe to default topics
        let mut topics = TopicManager::new(config.network_id());
        topics.subscribe_defaults(&mut swarm);

        // Create message router for P2P message processing (no PoW for gossip)
        let router = MessageRouter::new(storage.clone(), identity, None);

        let public_url = config.api.public_url.clone();

        let snapshot_serve_enabled = config.snapshot.serve_enabled;
        // Clamp to [1, 4096] — config can't disable the semaphore entirely
        // (we still want a backstop) and shouldn't request millions of permits.
        let snapshot_permits = config
            .snapshot
            .serve_max_concurrent_requests
            .clamp(1, 4096) as usize;
        let snapshot_chunk_semaphore = Arc::new(tokio::sync::Semaphore::new(snapshot_permits));

        Ok(Self {
            swarm,
            topics,
            router,
            storage,
            notification_engine,
            peer_count,
            signing_key,
            node_id,
            public_url,
            connected_peers,
            peer_node_ids: HashMap::new(),
            counters,
            bootstrap_addrs,
            reconnect_queue: Vec::new(),
            known_peer_addrs: HashMap::new(),
            snapshot_cache,
            snapshot_serve_enabled,
            snapshot_chunk_semaphore,
            snapshot_client_rx,
            pending_snapshot_requests: HashMap::new(),
            identify_success_count,
            startup_book_peer_ids,
            config_peer_ids,
            sc_added_peer_ids,
            publish_failure_counters,
            mesh_stats,
            alert_event_tx,
            backfill_config,
            reconcile_limits: Arc::new(reconcile::ResponderLimits::default()),
            pending_reconcile_requests: HashMap::new(),
            reconcile_triggered: HashSet::new(),
        })
    }

    /// Classify a connected peer by which bootstrap tier dialed it
    /// this session (spec 13 §4.1).
    ///
    /// Precedence — `config` > `book` > `sc` > `runtime`. Reasoning:
    ///   - `config` is the operator's explicit intent and the most
    ///     stable label across sessions; surface it when it applies.
    ///   - `book` is historical (carried over from a prior session);
    ///     preferred over sc when both apply because the book
    ///     supplied a working entry first.
    ///   - `sc` is the on-chain fallback for this session.
    ///   - `runtime` covers everything else (DHT, mDNS, inbound).
    fn classify_discovery_source(&self, peer_id: &PeerId) -> crate::api::state::DiscoverySource {
        use crate::api::state::DiscoverySource;
        if self.config_peer_ids.contains(peer_id) {
            return DiscoverySource::Config;
        }
        if self.startup_book_peer_ids.contains(peer_id) {
            return DiscoverySource::Book;
        }
        // sc_added_peer_ids is shared with sc_discovery — read lock is
        // held only for the contains() call. Lock poisoning is
        // tolerated by falling through to runtime; corruption-free
        // operation of this set is not a correctness requirement.
        if let Ok(sc_set) = self.sc_added_peer_ids.read() {
            if sc_set.contains(peer_id) {
                return DiscoverySource::Sc;
            }
        }
        DiscoverySource::Runtime
    }

    /// Get the local peer ID.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Subscribe to a channel's GossipSub topic.
    ///
    /// **Channel-history backfill trigger (spec 1, l2-node 0.47.0+).**
    /// If `[backfill] enabled` AND the local `CHANNEL_MSGS` index
    /// for `channel_id` is empty AND we have not already triggered
    /// reconciliation for this channel in the current process, the
    /// trigger fires: we pick up to `[backfill] fanout` candidate
    /// peers from the gossip mesh (falling back to SC-active nodes
    /// if mesh is sparse) and send each a `ReconcileRequest`. The
    /// first non-empty response wins; subsequent responses are
    /// dropped on arrival via the `pending_reconcile_requests` map
    /// (only the winning peer's continuation is tracked).
    pub fn subscribe_channel(&mut self, channel_id: u64) {
        self.topics
            .subscribe_channel(&mut self.swarm, channel_id);
        self.maybe_trigger_backfill(channel_id);
    }

    /// Unsubscribe from a channel's GossipSub topic.
    pub fn unsubscribe_channel(&mut self, channel_id: u64) {
        self.topics
            .unsubscribe_channel(&mut self.swarm, channel_id);
    }

    /// Subscribe to a user's DM topic.
    pub fn subscribe_dm(&mut self, address: &str) {
        self.topics
            .subscribe_dm(&mut self.swarm, address);
    }

    /// Publish a raw message to a GossipSub topic.
    pub fn publish(
        &mut self,
        topic: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let topic_hash = gossip::topic_hash(topic);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic_hash, data)
            .map_err(|e| anyhow::anyhow!("publish error: {}", e))?;
        Ok(())
    }

    /// Run the network event loop. Call this from a spawned task.
    ///
    /// Processes swarm events, routes messages to storage, and subscribes
    /// to new channel topics as they are discovered by the chain scanner.
    /// Periodically retries Kademlia bootstrap if peer count is low.
    pub async fn run(
        &mut self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        mut channel_rx: tokio::sync::mpsc::UnboundedReceiver<u64>,
        mut gossip_rx: tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>,
        // v0.44.0: sc_discovery sends `()` here when it persists new
        // multiaddrs from the on-chain registry. We respond by
        // running `dial_persisted_peers` out-of-cycle so SC-discovered
        // peers get dialed within seconds instead of waiting up to
        // 30s for the next periodic bootstrap tick. Spec 13 §4.3.
        mut sc_reconnect_rx: tokio::sync::mpsc::Receiver<()>,
    ) {
        info!(
            peer_id = %self.swarm.local_peer_id(),
            "Network event loop started"
        );

        // Dial persisted peers from previous sessions (survives restart)
        self.dial_persisted_peers();

        // Periodic Kademlia bootstrap + reconnection (every 30s).
        let mut bootstrap_interval = tokio::time::interval(Duration::from_secs(30));
        bootstrap_interval.tick().await; // skip the immediate first tick

        // Periodic NodeAnnouncement (every 5 minutes) — tells other nodes
        // we exist so they can list us in /api/v1/network/nodes.
        let mut announce_interval = tokio::time::interval(Duration::from_secs(300));
        announce_interval.tick().await; // skip immediate tick

        // Reconnection check interval (every 10s) — processes the reconnect queue.
        let mut reconnect_interval = tokio::time::interval(Duration::from_secs(10));
        reconnect_interval.tick().await;

        // Mesh-stats refresh (every 30s) — snapshots per-topic mesh
        // size + subscriber count into `self.mesh_stats` for the
        // `/admin/network/mesh-stats` endpoint (spec 10 §9.2,
        // l2-node 0.46.6+).
        let mut mesh_stats_interval =
            tokio::time::interval(MESH_STATS_REFRESH_INTERVAL);
        mesh_stats_interval.tick().await;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
                }
                Some(channel_id) = channel_rx.recv() => {
                    // Code Audit W2 (0.47.0): route chain-discovered
                    // channels through `Self::subscribe_channel` (not
                    // the bare `Topics::subscribe_channel`) so the
                    // empty-CHANNEL_MSGS cold-join backfill trigger
                    // fires. The trigger is idempotent via
                    // `reconcile_triggered`, so duplicate calls are
                    // safe.
                    self.subscribe_channel(channel_id);
                    info!(channel_id, "Auto-subscribed to channel topic (chain discovery)");
                }
                Some((topic, data)) = gossip_rx.recv() => {
                    let data_len = data.len() as u64;
                    let topic_obj = libp2p::gossipsub::IdentTopic::new(&topic);
                    match self.swarm.behaviour_mut().gossipsub.publish(topic_obj, data) {
                        Ok(_) => {
                            self.counters.add_bytes_out(data_len);
                            self.counters.inc_messages_relayed();
                            debug!(topic = %topic, "Published message to GossipSub");
                        }
                        Err(e) => self.report_publish_failure(&topic, &e),
                    }
                }
                _ = mesh_stats_interval.tick() => {
                    self.refresh_mesh_stats();
                }
                _ = announce_interval.tick() => {
                    self.publish_node_announcement();
                }
                _ = bootstrap_interval.tick() => {
                    self.periodic_bootstrap();
                }
                _ = reconnect_interval.tick() => {
                    self.process_reconnect_queue();
                }
                Some(_) = sc_reconnect_rx.recv() => {
                    // sc_discovery persisted new multiaddrs from the
                    // on-chain registry — dial them now. dial_persisted_peers
                    // is already deduplication-aware (libp2p drops dial
                    // attempts to peers we're already connected to).
                    debug!("sc_discovery signaled new peers; dialing from book out-of-cycle");
                    self.dial_persisted_peers();
                }
                Some(cmd) = self.snapshot_client_rx.recv() => {
                    self.handle_snapshot_client_command(cmd);
                }
                _ = shutdown_rx.recv() => {
                    info!("Network shutting down");
                    break;
                }
            }
        }
    }

    /// Handle a single swarm event.
    fn handle_swarm_event(&mut self, event: SwarmEvent<OgmaraBehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Message {
                    propagation_source,
                    message_id,
                    message,
                },
            )) => {
                debug!(
                    source = %propagation_source,
                    msg_id = %message_id,
                    topic = %message.topic,
                    bytes = message.data.len(),
                    "Received GossipSub message"
                );
                // Store the raw envelope bytes — full routing pipeline
                // will be wired in via the message router
                if let Err(e) = self.handle_gossip_message(&message.data) {
                    warn!(error = %e, "Failed to handle gossip message");
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Subscribed { peer_id, topic },
            )) => {
                debug!(peer = %peer_id, topic = %topic, "Peer subscribed to topic");
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Unsubscribed { peer_id, topic },
            )) => {
                debug!(peer = %peer_id, topic = %topic, "Peer unsubscribed from topic");
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::GossipsubNotSupported { peer_id },
            )) => {
                info!(peer = %peer_id, "Peer does not support GossipSub");
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Mdns(
                libp2p::mdns::Event::Discovered(peers),
            )) => {
                for (peer_id, addr) in peers {
                    debug!(peer = %peer_id, addr = %addr, "mDNS discovered peer");
                    // Only dial the peer — do NOT add to Kademlia or GossipSub yet.
                    // The Identify handler will promote same-network peers after
                    // verifying the protocol version. This prevents wrong-network
                    // peers (e.g., testnet+mainnet on the same LAN) from polluting
                    // the routing table or receiving GossipSub messages.
                    if let Err(e) = self.swarm.dial(addr) {
                        debug!(peer = %peer_id, error = %e, "Failed to dial mDNS peer");
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Mdns(
                libp2p::mdns::Event::Expired(peers),
            )) => {
                for (peer_id, _addr) in peers {
                    debug!(peer = %peer_id, "mDNS peer expired");
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Kademlia(event)) => {
                match &event {
                    kad::Event::RoutingUpdated {
                        peer, addresses, ..
                    } => {
                        info!(
                            peer = %peer,
                            addresses = addresses.len(),
                            "Kademlia routing table updated"
                        );
                    }
                    kad::Event::OutboundQueryProgressed { result, .. } => {
                        debug!(result = ?result, "Kademlia query progressed");
                    }
                    _ => {
                        debug!(event = ?event, "Kademlia event");
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, info, .. },
            )) => {
                // Network isolation: only accept peers on the same network.
                // Protocol version format: /ogmara/{network_id}/1.0.0
                let expected_prefix = format!("/ogmara/{}/", self.topics.network_id());
                let is_ogmara = info.protocol_version.starts_with(&expected_prefix);
                let agent_ver = info.agent_version.clone();

                // Reject peers that are not on our network — disconnect immediately.
                if !is_ogmara {
                    if info.protocol_version.starts_with("/ogmara/") {
                        warn!(
                            peer = %peer_id,
                            their_protocol = %info.protocol_version,
                            our_network = %self.topics.network_id(),
                            "Rejecting peer from different network — disconnecting"
                        );
                    } else {
                        debug!(
                            peer = %peer_id,
                            protocol_version = %info.protocol_version,
                            "Non-Ogmara peer identified — disconnecting"
                        );
                    }
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }

                info!(
                    peer = %peer_id,
                    protocol_version = %info.protocol_version,
                    agent_version = %agent_ver,
                    listen_addrs = info.listen_addrs.len(),
                    "Identified Ogmara peer"
                );
                // Spec 13 §4.3 stall-trigger signal: every successful
                // Ogmara Identify bumps this counter, which sc_discovery
                // reads at +60s post-startup. Zero ⇒ we are isolated
                // (tier 1 + 2 produced nothing) ⇒ fire SC fan-out.
                self.identify_success_count.fetch_add(1, Ordering::Relaxed);

                // Add identified peer's addresses to Kademlia and store the
                // first address for reconnection after disconnect.
                let mut first_addr = None;
                for addr in info.listen_addrs.into_iter().take(16) {
                    if first_addr.is_none() {
                        first_addr = Some(addr.clone());
                    }
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
                // Store address for reconnection (capped to prevent unbounded growth)
                if let Some(ref addr) = first_addr {
                    if self.known_peer_addrs.len() < 2048 || self.known_peer_addrs.contains_key(&peer_id) {
                        self.known_peer_addrs.insert(peer_id, addr.clone());
                    }
                }
                // Persist peer address to storage for reconnection after restart.
                if let Some(ref addr) = first_addr {
                    self.persist_peer_addr(&peer_id, addr);
                }
                // Remove from reconnect queue if it was pending (successfully connected)
                self.reconnect_queue.retain(|e| e.peer_id != peer_id);

                // Sync channel messages from this peer
                self.sync_channels_with_peer(peer_id);

                // Track this peer so it appears in /api/v1/network/nodes
                // even before its NodeAnnouncement arrives via GossipSub
                if let Ok(ed25519_pk) = info.public_key.try_into_ed25519() {
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(ed25519_pk.to_bytes());
                    let node_id = bs58::encode(&hash[..20]).into_string();
                    self.peer_node_ids.insert(peer_id, node_id.clone());
                    // Spec 13 §4.1 — classify which bootstrap tier
                    // produced this peer's dial chain this session.
                    let source = self.classify_discovery_source(&peer_id);
                    // Note: do not hold this lock across .await points
                    match self.connected_peers.write() {
                        Ok(mut peers) => {
                            // Defensive cap to prevent unbounded growth
                            if peers.len() < 1024 || peers.contains_key(&node_id) {
                                peers.insert(node_id, ConnectedPeerInfo {
                                    agent_version: if agent_ver.len() > 256 {
                                        agent_ver[..256].to_string()
                                    } else {
                                        agent_ver
                                    },
                                    source,
                                });
                            }
                        }
                        Err(e) => warn!("connected_peers lock poisoned: {e}"),
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::RequestResponse(event)) => {
                self.handle_request_response(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Snapshot(event)) => {
                self.handle_snapshot_event(event);
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Reconcile(event)) => {
                self.handle_reconcile_event(event);
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                info!(addr = %address, "Listening on new address");
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                endpoint,
                ..
            } => {
                let total_peers = self.swarm.connected_peers().count();
                self.peer_count.store(total_peers as u32, Ordering::Relaxed);
                info!(
                    peer = %peer_id,
                    connections = %num_established,
                    total_peers,
                    direction = if endpoint.is_dialer() { "outbound" } else { "inbound" },
                    remote_addr = %endpoint.get_remote_address(),
                    "Connection established"
                );
                // Trigger Kademlia bootstrap when we get our first peer
                if total_peers == 1 {
                    if let Err(e) = self.swarm.behaviour_mut().kademlia.bootstrap() {
                        debug!(error = %e, "Kademlia bootstrap not ready yet");
                    }
                    // Announce ourselves immediately so other nodes know we exist
                    self.publish_node_announcement();
                }
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                let total_peers = self.swarm.connected_peers().count();
                self.peer_count.store(total_peers as u32, Ordering::Relaxed);
                if let Some(ref err) = cause {
                    warn!(
                        peer = %peer_id,
                        remaining = %num_established,
                        total_peers,
                        cause = %err,
                        "Connection closed with error"
                    );
                } else {
                    info!(
                        peer = %peer_id,
                        remaining = %num_established,
                        total_peers,
                        "Connection closed"
                    );
                }
                // Remove from connected peers when last connection to this peer closes
                if num_established == 0 {
                    if let Some(node_id) = self.peer_node_ids.remove(&peer_id) {
                        match self.connected_peers.write() {
                            Ok(mut peers) => { peers.remove(&node_id); }
                            Err(e) => warn!("connected_peers lock poisoned: {e}"),
                        }
                    }
                    // Queue for reconnection with exponential backoff
                    self.queue_reconnect(peer_id);
                }
            }

            SwarmEvent::OutgoingConnectionError {
                peer_id,
                error,
                ..
            } => {
                warn!(
                    peer = ?peer_id,
                    error = %error,
                    "Outgoing connection failed"
                );
            }

            SwarmEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error,
                ..
            } => {
                warn!(
                    local_addr = %local_addr,
                    remote_addr = %send_back_addr,
                    error = %error,
                    "Incoming connection failed"
                );
            }

            SwarmEvent::Dialing { peer_id, .. } => {
                debug!(peer = ?peer_id, "Dialing peer");
            }

            _ => {}
        }
    }

    /// Key prefix for persisted peer addresses in PEER_DIRECTORY CF.
    /// Separates peer addrs from NodeAnnouncement entries which use no prefix.
    const PEER_ADDR_PREFIX: &'static [u8] = b"pa:";

    /// Persist a peer's multiaddr to storage for reconnection after restart.
    fn persist_peer_addr(&self, peer_id: &PeerId, addr: &Multiaddr) {
        // Cap stored peers at 256 to prevent unbounded growth
        let existing = self.storage.prefix_iter_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            Self::PEER_ADDR_PREFIX,
            257,
        ).map(|e| e.len()).unwrap_or(0);
        if existing >= 256 {
            return; // full — existing peers are retained, new ones skipped
        }

        let mut key = Vec::with_capacity(3 + 64);
        key.extend_from_slice(Self::PEER_ADDR_PREFIX);
        key.extend_from_slice(peer_id.to_string().as_bytes());
        let value = addr.to_string();
        if let Err(e) = self.storage.put_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            &key,
            value.as_bytes(),
        ) {
            warn!(error = %e, "Failed to persist peer address");
        }
    }

    /// Remove a peer's stored address (e.g., after giving up on reconnection).
    fn remove_persisted_peer(&self, peer_id: &PeerId) {
        let mut key = Vec::with_capacity(3 + 64);
        key.extend_from_slice(Self::PEER_ADDR_PREFIX);
        key.extend_from_slice(peer_id.to_string().as_bytes());
        if let Err(e) = self.storage.delete_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            &key,
        ) {
            debug!(error = %e, "Failed to remove persisted peer");
        }
    }

    /// Load persisted peer addresses from storage and dial them.
    ///
    /// Called once at startup to reconnect to previously-known peers
    /// without relying on bootstrap nodes.
    fn dial_persisted_peers(&mut self) {
        let entries = match self.storage.prefix_iter_cf(
            crate::storage::schema::cf::PEER_DIRECTORY,
            Self::PEER_ADDR_PREFIX,
            64, // cap to prevent dialing too many at once
        ) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "Failed to load persisted peers");
                return;
            }
        };

        if entries.is_empty() {
            return;
        }

        let mut dialed = 0u32;
        for (_key, value) in &entries {
            let addr_str = match std::str::from_utf8(value) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let addr: Multiaddr = match addr_str.parse() {
                Ok(a) => a,
                Err(_) => continue,
            };

            if let Err(e) = self.swarm.dial(addr.clone()) {
                debug!(addr = %addr, error = %e, "Failed to dial persisted peer");
            } else {
                dialed += 1;
            }
        }

        if dialed > 0 {
            info!(dialed, stored = entries.len(), "Dialing persisted peers from previous session");
        }
    }

    /// Periodic bootstrap: if peers are low, redial bootstrap nodes and run Kademlia bootstrap.
    ///
    /// Fixes the deadlock where Kademlia bootstrap was skipped when peer_count==0,
    /// preventing peer discovery from ever starting.
    fn periodic_bootstrap(&mut self) {
        let peer_count = self.swarm.connected_peers().count();

        if peer_count == 0 {
            // No peers at all — actively redial bootstrap nodes
            info!("No connected peers — redialing bootstrap nodes");
            for addr in self.bootstrap_addrs.clone() {
                // Check if we're already connected to this peer
                let peer_id = addr.iter().find_map(|proto| {
                    if let libp2p::multiaddr::Protocol::P2p(id) = proto {
                        Some(id)
                    } else {
                        None
                    }
                });
                let already_connected = peer_id
                    .map(|pid| self.swarm.is_connected(&pid))
                    .unwrap_or(false);

                if !already_connected {
                    if let Err(e) = self.swarm.dial(addr.clone()) {
                        warn!(addr = %addr, error = %e, "Bootstrap redial failed");
                    } else {
                        info!(addr = %addr, "Redialing bootstrap node");
                    }
                }
            }
        }

        // Always attempt Kademlia bootstrap regardless of peer count.
        // With 0 peers, Kademlia will use its routing table (which may
        // have bootstrap node entries even without active connections).
        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(_) => debug!(peer_count, "Kademlia bootstrap triggered"),
            Err(e) => debug!(error = %e, "Kademlia bootstrap skipped (no known peers in routing table)"),
        }
    }

    /// Report a GossipSub publish failure: classify the error variant,
    /// bump the appropriate counter, emit a per-failure `error!` log
    /// with the data that step 2 of the mainnet-blockers fix plan
    /// (B4 instrumentation) requires for diagnosis — peer count +
    /// per-topic subscriber count, both at the moment of failure —
    /// and fire `publish_failed_insufficient_peers` (cooldown-
    /// deduplicated by AlertEngine) when the variant is
    /// `NoPeersSubscribedToTopic`.
    ///
    /// Logging is `error!` not `warn!` because a silent publish failure
    /// is the hardest possible class of bug to diagnose post-hoc
    /// (messages just disappear). `warn!` previously buried this in
    /// the noise floor of "transient peer churn" — `error!` plus
    /// structured fields plus the new counters make the asymmetric-
    /// propagation case the plan calls out actually observable.
    fn report_publish_failure(
        &self,
        topic: &str,
        err: &libp2p::gossipsub::PublishError,
    ) {
        let fire_insufficient_peers_alert =
            self.publish_failure_counters.record(err);

        let connected_peers = self.swarm.connected_peers().count();
        let topic_hash = libp2p::gossipsub::IdentTopic::new(topic).hash();
        let topic_subscribers = self
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.iter().any(|t| **t == topic_hash))
            .count();
        let mesh_size = self
            .swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&topic_hash)
            .count();

        error!(
            topic = %topic,
            error = %err,
            connected_peers,
            topic_subscribers,
            mesh_size,
            "GossipSub publish failed"
        );

        if fire_insufficient_peers_alert {
            self.fire_publish_failed_alert(topic, connected_peers, topic_subscribers);
        }
    }

    /// Fire the `publish_failed_insufficient_peers` alert with the
    /// snapshot of state that diagnosis needs.
    ///
    /// **Topic redaction (Security Audit W1, 0.46.6).** The raw topic
    /// strings produced by `gossip::dm_topic` and `gossip::channel_topic`
    /// include the recipient wallet (`/ogmara/<network>/v1/dm/klv1...`)
    /// or channel ID. AlertEngine dispatches this `details` field to
    /// Telegram / Discord / webhook sinks — putting the plaintext
    /// topic in the payload would leak DM-recipient and channel
    /// metadata to whichever third-party messaging service the
    /// operator pointed alerts at. We render the topic as its
    /// `IdentTopic::hash()` (the same SHA-256-shaped rendering the
    /// `/admin/network/mesh-stats` snapshot uses) so the alert
    /// payload is correlateable with the local snapshot but does not
    /// expose plaintext topics to outbound dispatchers.
    ///
    /// Best-effort (`try_send`) — channel-full means the AlertEngine
    /// is stalled (capacity 1024), so dropping is correct; the engine
    /// either recovers and picks up the next event, or the operator
    /// has a separate observability problem.
    fn fire_publish_failed_alert(
        &self,
        topic: &str,
        connected_peers: usize,
        topic_subscribers: usize,
    ) {
        let Some(tx) = self.alert_event_tx.as_ref() else {
            return;
        };
        let topic_render =
            libp2p::gossipsub::IdentTopic::new(topic).hash().to_string();
        let event = crate::notifications::alerts::AlertEvent {
            alert_type:
                crate::notifications::alerts::AlertType::PublishFailedInsufficientPeers,
            details: format!(
                "publish failed: no peers subscribed (topic_hash={topic_render}, \
                 connected_peers={connected_peers}, \
                 topic_subscribers={topic_subscribers})"
            ),
        };
        if let Err(e) = tx.try_send(event) {
            debug!(error = %e, "publish-failed alert channel full or closed");
        }
    }

    /// Refresh the shared `MeshStatsSnapshot` from the current state of
    /// `gossipsub::Behaviour`. Called from the main loop on the 30s
    /// `mesh_stats_interval` tick. Lock-hold is sub-millisecond — we
    /// build the snapshot in a local, then swap it in under the
    /// `RwLock` write guard.
    fn refresh_mesh_stats(&self) {
        use std::collections::HashMap;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let gossipsub = &self.swarm.behaviour().gossipsub;

        // Walk every subscribed topic. `topics()` returns the topic
        // hashes we are subscribed to — we don't have the original
        // topic-string here without a side-table, so the snapshot
        // surfaces the hash rendering (operators recognise the
        // network_id / topic prefix in the rendering).
        let mut topic_entries: HashMap<String, mesh_stats::TopicMeshStats> = HashMap::new();
        let mut total_mesh_slots = 0usize;
        for topic_hash in gossipsub.topics() {
            let mesh_size = gossipsub.mesh_peers(topic_hash).count();
            total_mesh_slots += mesh_size;
            let subscribers = gossipsub
                .all_peers()
                .filter(|(_, topics)| topics.iter().any(|t| *t == topic_hash))
                .count();
            if mesh_size == 0 && subscribers == 0 {
                continue;
            }
            let topic_str = topic_hash.to_string();
            topic_entries.insert(
                topic_str.clone(),
                mesh_stats::TopicMeshStats {
                    topic: topic_str,
                    mesh_size,
                    subscribers,
                },
            );
        }

        let mut topics: Vec<mesh_stats::TopicMeshStats> =
            topic_entries.into_values().collect();
        topics.sort_by(|a, b| a.topic.cmp(&b.topic));

        let (total, no_peers, all_queues_full, other) =
            self.publish_failure_counters.snapshot();

        let new_snapshot = mesh_stats::MeshStatsSnapshot {
            generated_at_unix: now_unix,
            topics,
            total_mesh_slots,
            publish_failures_total: total,
            publish_failures_no_peers: no_peers,
            publish_failures_all_queues_full: all_queues_full,
            publish_failures_other: other,
        };

        match self.mesh_stats.write() {
            Ok(mut w) => *w = new_snapshot,
            Err(e) => warn!(error = %e, "mesh_stats RwLock poisoned"),
        }
    }

    /// Channel-history backfill trigger (spec 1, l2-node 0.47.0+).
    /// See [`Self::subscribe_channel`] for the full trigger contract.
    fn maybe_trigger_backfill(&mut self, channel_id: u64) {
        if !self.backfill_config.enabled {
            return;
        }
        if !self.reconcile_triggered.insert(channel_id) {
            // Already triggered this session — don't re-fire.
            return;
        }

        // Empty-check: does `CHANNEL_MSGS` have ANY row for this
        // channel? prefix_iter with limit=1 short-iters cheaply.
        let prefix = channel_id.to_be_bytes();
        let has_local = self
            .storage
            .prefix_iter_cf(
                crate::storage::schema::cf::CHANNEL_MSGS,
                &prefix,
                1,
            )
            .map(|rows| !rows.is_empty())
            .unwrap_or(false);

        let resync_active = self.backfill_config.force_resync_if_stale_days > 0;
        let need_backfill = if !has_local {
            true
        } else if resync_active {
            // Re-reconciliation knob: read the NEWEST local envelope
            // and compare timestamps. `prefix_iter` is sorted
            // ascending by (lamport_ts, msg_id); reading all rows is
            // O(N) and not worth it. Use a stat or skip for now.
            // v0.47.0 conservative: re-fire only on truly-empty;
            // staleness-driven resync is a v0.47.x refinement.
            false
        } else {
            false
        };
        if !need_backfill {
            // Remove from the triggered set so a future
            // unsubscribe + resubscribe (with the channel still
            // empty) can re-evaluate.
            self.reconcile_triggered.remove(&channel_id);
            return;
        }

        // Candidate selection: GossipSub mesh peers for this
        // channel's topic; fall back to ALL connected peers if the
        // mesh is sparse (cold-start case where the channel topic
        // has not yet propagated).
        let topic = libp2p::gossipsub::IdentTopic::new(gossip::channel_topic(
            self.topics.network_id(),
            channel_id,
        ));
        let topic_hash = topic.hash();
        let mut candidates: Vec<PeerId> = self
            .swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&topic_hash)
            .copied()
            .collect();
        if candidates.len() < self.backfill_config.fanout {
            // Augment with any connected peer that announced the
            // protocol (or just any connected peer — request-response
            // negotiation will refuse non-supporters cleanly).
            for p in self.swarm.connected_peers() {
                if !candidates.contains(p) {
                    candidates.push(*p);
                }
                if candidates.len() >= self.backfill_config.fanout * 2 {
                    break;
                }
            }
        }
        if candidates.is_empty() {
            debug!(
                channel_id,
                "backfill: no candidate peers; cold-start will retry on next subscribe"
            );
            // Allow a future re-trigger.
            self.reconcile_triggered.remove(&channel_id);
            return;
        }

        use rand::seq::SliceRandom;
        candidates.shuffle(&mut rand::thread_rng());
        candidates.truncate(self.backfill_config.fanout);

        let max_age_secs = if self.backfill_config.max_age_days == u64::MAX {
            u64::MAX
        } else {
            self.backfill_config
                .max_age_days
                .saturating_mul(24 * 3600)
        };
        let request = reconcile::ReconcileRequest {
            channel_id,
            max_age_secs,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };

        info!(
            channel_id,
            fanout = candidates.len(),
            max_age_days = self.backfill_config.max_age_days,
            "backfill: triggering channel-history reconciliation"
        );

        for peer in candidates {
            let id = self
                .swarm
                .behaviour_mut()
                .reconcile
                .send_request(&peer, request.clone());
            self.pending_reconcile_requests.insert(
                id,
                ReconcilePending {
                    peer_id: peer,
                    channel_id,
                },
            );
        }
    }

    /// Handle inbound + outbound reconcile request-response events.
    fn handle_reconcile_event(
        &mut self,
        event: libp2p::request_response::Event<
            reconcile::ReconcileRequest,
            reconcile::ReconcileResponse,
        >,
    ) {
        use libp2p::request_response::{Event, Message};
        match event {
            Event::Message {
                peer,
                message: Message::Request { request, channel, request_id: _ },
                connection_id: _,
            } => {
                // Server-side: rate-limit + cumulative cap, then
                // build + respond. The Audit C2 cumulative-envelopes
                // cap (`total_envelopes_cap`) is enforced through
                // `try_acquire`; on success, we call `add_served`
                // after `build_response` succeeded so the next
                // paginated request from the same peer sees the
                // updated total.
                let total_cap = self.backfill_config.total_envelopes_cap as u64;
                let guard = self.reconcile_limits.try_acquire(
                    peer,
                    request.channel_id,
                    self.backfill_config.server_max_concurrent_per_peer,
                    self.backfill_config.server_max_concurrent_per_channel,
                    total_cap,
                );
                let response = if guard.is_none() {
                    debug!(
                        peer = %peer,
                        channel_id = request.channel_id,
                        "reconcile: rate-limited or session-cap exhausted; \
                         responding server_capped"
                    );
                    reconcile::capped_response(&request)
                } else {
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    reconcile::build_response(
                        &self.storage,
                        &request,
                        self.backfill_config.max_envelopes_per_response,
                        now_unix,
                    )
                };
                let envelopes_sent = response.envelopes.len();
                let has_more = response.has_more;
                // Audit C2: only count toward the cumulative session
                // total when we actually served envelopes (skipping
                // the server_capped / private-channel refusal paths
                // keeps the cap from being burned on no-op
                // responses).
                if envelopes_sent > 0 {
                    self.reconcile_limits.add_served(
                        peer,
                        request.channel_id,
                        envelopes_sent as u64,
                    );
                }
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .reconcile
                    .send_response(channel, response)
                {
                    warn!(
                        peer = %peer,
                        channel_id = request.channel_id,
                        error = ?e,
                        "reconcile: send_response failed"
                    );
                }
                drop(guard);
                debug!(
                    peer = %peer,
                    channel_id = request.channel_id,
                    envelopes_sent,
                    has_more,
                    "reconcile: served request"
                );
            }
            Event::Message {
                peer,
                message: Message::Response { request_id, response },
                connection_id: _,
            } => {
                let Some(pending) = self.pending_reconcile_requests.remove(&request_id)
                else {
                    debug!(
                        peer = %peer,
                        ?request_id,
                        "reconcile: response for unknown request_id (race winner already served)"
                    );
                    return;
                };
                if response.server_capped {
                    debug!(
                        peer = %peer,
                        channel_id = pending.channel_id,
                        "reconcile: peer responded server_capped; ignoring (race siblings may succeed)"
                    );
                    return;
                }
                if response.envelopes.is_empty() && !response.has_more {
                    debug!(
                        peer = %peer,
                        channel_id = pending.channel_id,
                        "reconcile: peer responded empty + no more; ignoring"
                    );
                    return;
                }

                // Race-winner semantics: cancel sibling outbound
                // requests by dropping their pending entries. Any
                // late-arriving response for them will be logged at
                // debug above and ignored.
                self.pending_reconcile_requests.retain(|_, p| {
                    !(p.channel_id == pending.channel_id && p.peer_id != peer)
                });

                let env_count = response.envelopes.len();
                let mut admitted = 0usize;
                let mut cross_channel_dropped = 0usize;
                for env_bytes in response.envelopes {
                    // Security Audit W1 (0.47.0): cross-channel
                    // smuggling defense. The responder could otherwise
                    // stuff envelopes for channel B into a response
                    // we sent for channel A; signatures verify (the
                    // original authors really signed them) so the
                    // router would happily index them under B in our
                    // local CHANNEL_MSGS. Reject any envelope whose
                    // payload-extracted channel_id does not equal the
                    // channel we asked for. We can't fully validate
                    // until after the router has deserialised the
                    // payload, so we do a cheap pre-check on the
                    // payload bytes here.
                    if !envelope_targets_channel(
                        &env_bytes,
                        pending.channel_id,
                    ) {
                        cross_channel_dropped += 1;
                        continue;
                    }
                    match self.router.process_synced_message(&env_bytes) {
                        crate::messages::router::RouteResult::Accepted { .. } => {
                            admitted += 1;
                        }
                        crate::messages::router::RouteResult::Duplicate => {
                            // Already had this envelope locally —
                            // counted as "won the race" but no
                            // storage write needed.
                            admitted += 1;
                        }
                        crate::messages::router::RouteResult::Rejected(reason) => {
                            warn!(
                                peer = %peer,
                                channel_id = pending.channel_id,
                                reason = %reason,
                                "reconcile: peer envelope rejected by router"
                            );
                        }
                        crate::messages::router::RouteResult::PowRequired { .. } => {
                            // Sync messages are PoW-exempt — should
                            // not fire. Skip if it does.
                        }
                    }
                }
                info!(
                    peer = %peer,
                    channel_id = pending.channel_id,
                    received = env_count,
                    admitted,
                    cross_channel_dropped,
                    has_more = response.has_more,
                    "reconcile: applied response batch"
                );

                // Continue paging from the winning peer if the
                // responder signalled more data.
                if response.has_more {
                    if let Some(cursor) = response.next_cursor {
                        let max_age_secs = if self.backfill_config.max_age_days == u64::MAX {
                            u64::MAX
                        } else {
                            self.backfill_config
                                .max_age_days
                                .saturating_mul(24 * 3600)
                        };
                        let next_req = reconcile::ReconcileRequest {
                            channel_id: pending.channel_id,
                            max_age_secs,
                            cursor: Some(cursor),
                            fingerprint: Vec::new(),
                            epoch_root_known: None,
                            round: 0,
                        };
                        let next_id = self
                            .swarm
                            .behaviour_mut()
                            .reconcile
                            .send_request(&pending.peer_id, next_req);
                        self.pending_reconcile_requests.insert(
                            next_id,
                            ReconcilePending {
                                peer_id: pending.peer_id,
                                channel_id: pending.channel_id,
                            },
                        );
                    }
                }
            }
            Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if let Some(pending) =
                    self.pending_reconcile_requests.remove(&request_id)
                {
                    debug!(
                        peer = %peer,
                        channel_id = pending.channel_id,
                        error = ?error,
                        "reconcile: outbound failed; siblings may still succeed"
                    );
                }
            }
            Event::InboundFailure { peer, error, .. } => {
                debug!(
                    peer = %peer,
                    error = ?error,
                    "reconcile: inbound request handling failed"
                );
            }
            Event::ResponseSent { .. } => {
                // Successfully sent — nothing to do.
            }
        }
    }

    /// Process the reconnect queue: attempt to redial peers whose backoff has expired.
    fn process_reconnect_queue(&mut self) {
        if self.reconnect_queue.is_empty() {
            return;
        }

        let now = tokio::time::Instant::now();
        let mut i = 0;
        while i < self.reconnect_queue.len() {
            let entry = &self.reconnect_queue[i];
            if now < entry.next_attempt {
                i += 1;
                continue;
            }

            // Already reconnected? Remove from queue.
            if self.swarm.is_connected(&entry.peer_id) {
                self.reconnect_queue.swap_remove(i);
                continue;
            }

            // Max attempts exceeded? Give up and clean up.
            if entry.attempts >= MAX_RECONNECT_ATTEMPTS {
                let peer = entry.peer_id;
                debug!(
                    peer = %peer,
                    attempts = entry.attempts,
                    "Giving up on reconnection"
                );
                self.known_peer_addrs.remove(&peer);
                self.remove_persisted_peer(&peer);
                self.reconnect_queue.swap_remove(i);
                continue;
            }

            // Attempt redial
            let addr = entry.addr.clone();
            let peer = entry.peer_id;
            let attempts = entry.attempts + 1;
            let new_backoff = (entry.backoff_secs * 2).min(RECONNECT_MAX_SECS);

            match self.swarm.dial(addr.clone()) {
                Ok(_) => {
                    debug!(
                        peer = %peer,
                        attempt = attempts,
                        next_backoff = new_backoff,
                        "Reconnection attempt"
                    );
                }
                Err(e) => {
                    debug!(
                        peer = %peer,
                        error = %e,
                        "Reconnection dial failed"
                    );
                }
            }

            // Update backoff for next attempt
            self.reconnect_queue[i].attempts = attempts;
            self.reconnect_queue[i].backoff_secs = new_backoff;
            self.reconnect_queue[i].next_attempt =
                now + Duration::from_secs(new_backoff);
            i += 1;
        }
    }

    /// Queue a disconnected peer for reconnection with exponential backoff.
    fn queue_reconnect(&mut self, peer_id: PeerId) {
        // Don't queue if already in the queue
        if self.reconnect_queue.iter().any(|e| e.peer_id == peer_id) {
            return;
        }

        // Need a known address to reconnect
        let addr = match self.known_peer_addrs.get(&peer_id) {
            Some(a) => a.clone(),
            None => return, // no address known, can't reconnect
        };

        // Cap queue size to prevent unbounded growth from mass disconnections
        if self.reconnect_queue.len() >= 128 {
            debug!("Reconnect queue full, dropping entry");
            self.reconnect_queue.swap_remove(0); // O(1) vs O(n) for remove(0)
        }

        self.reconnect_queue.push(ReconnectEntry {
            peer_id,
            addr,
            next_attempt: tokio::time::Instant::now()
                + Duration::from_secs(RECONNECT_BASE_SECS),
            backoff_secs: RECONNECT_BASE_SECS,
            attempts: 0,
        });

        debug!(peer = %peer_id, "Queued peer for reconnection");
    }

    /// Handle a request-response event — sync protocol.
    ///
    /// Inbound requests: build response from local storage and send it back.
    /// Inbound responses: validate and store each message.
    fn handle_request_response(
        &mut self,
        event: libp2p::request_response::Event<sync::SyncRequest, sync::SyncResponse>,
    ) {
        use libp2p::request_response;

        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request,
                        channel,
                        ..
                    },
                ..
            } => {
                debug!(
                    peer = %peer,
                    request_type = ?request.request_type,
                    channel_id = ?request.channel_id,
                    "Received sync request"
                );

                let response = sync::build_sync_response(request, &self.storage);

                info!(
                    peer = %peer,
                    messages = response.messages.len(),
                    has_more = response.has_more,
                    "Sending sync response"
                );

                if self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response)
                    .is_err()
                {
                    warn!(peer = %peer, "Failed to send sync response (channel closed)");
                }
            }

            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        response,
                        ..
                    },
                ..
            } => {
                info!(
                    peer = %peer,
                    request_type = ?response.request_type,
                    messages = response.messages.len(),
                    has_more = response.has_more,
                    "Received sync response"
                );

                let mut accepted = 0u32;
                let mut rejected = 0u32;
                for msg_bytes in &response.messages {
                    self.counters.add_bytes_in(msg_bytes.len() as u64);
                    self.counters.inc_messages_received();
                    match self.router.process_synced_message(msg_bytes) {
                        RouteResult::Accepted { .. } => {
                            self.counters.inc_messages_stored();
                            accepted += 1;
                        }
                        RouteResult::Duplicate => {}
                        RouteResult::Rejected(reason) => {
                            self.counters.inc_failed_validations();
                            warn!(reason = %reason, "Rejected synced message");
                            rejected += 1;
                        }
                        RouteResult::PowRequired { .. } => {
                            // PoW not enforced for synced messages
                            rejected += 1;
                        }
                    }
                }
                if accepted > 0 || rejected > 0 {
                    info!(accepted, rejected, "Sync response processed");
                }
            }

            request_response::Event::OutboundFailure {
                peer, error, ..
            } => {
                warn!(peer = %peer, error = %error, "Sync request failed");
            }

            request_response::Event::InboundFailure {
                peer, error, ..
            } => {
                warn!(peer = %peer, error = %error, "Sync inbound failure");
            }

            _ => {}
        }
    }

    /// Handle an incoming snapshot-protocol request-response event
    /// (spec 11-snapshot-sync.md). Phase 1: serves cached chunks; the
    /// outbound (client) side is wired in Phase 2.
    fn handle_snapshot_event(
        &mut self,
        event: libp2p::request_response::Event<
            self::snapshot::SnapshotRequest,
            self::snapshot::SnapshotResponse,
        >,
    ) {
        use libp2p::request_response;

        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request,
                        channel,
                        ..
                    },
                ..
            } => {
                debug!(peer = %peer, request = ?request, "Received snapshot request");

                // Concurrency gate — only `GetChunk` is rate-limited (it's the
                // expensive arm; `Advertise` and `GetManifest` are cheap).
                // The permit is held until the response is sent to bound the
                // working set across the libp2p task. `try_acquire_owned` is
                // non-blocking — under load we return `RateLimited` immediately
                // so the peer falls over to a different mirror in Phase 2+.
                let _permit_guard = if matches!(request, self::snapshot::SnapshotRequest::GetChunk { .. }) {
                    match self.snapshot_chunk_semaphore.clone().try_acquire_owned() {
                        Ok(p) => Some(p),
                        Err(_) => {
                            warn!(
                                peer = %peer,
                                "Snapshot chunk request rate-limited (max concurrent reached)"
                            );
                            let resp = self::snapshot::SnapshotResponse::Error {
                                code: self::snapshot::SnapshotErrorCode::RateLimited,
                                message: "snapshot serve at capacity".into(),
                            };
                            if self
                                .swarm
                                .behaviour_mut()
                                .snapshot
                                .send_response(channel, resp)
                                .is_err()
                            {
                                warn!(peer = %peer, "Failed to send RateLimited response (channel closed)");
                            }
                            return;
                        }
                    }
                } else {
                    None
                };

                let response = self::snapshot::build_response(
                    &self.snapshot_cache,
                    self.snapshot_serve_enabled,
                    request,
                );

                if self
                    .swarm
                    .behaviour_mut()
                    .snapshot
                    .send_response(channel, response)
                    .is_err()
                {
                    warn!(peer = %peer, "Failed to send snapshot response (channel closed)");
                }
            }

            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        response,
                        request_id,
                        ..
                    },
                ..
            } => {
                // Phase 2: deliver the response back to the snapshot client
                // task waiting on this request_id. If we have no waiter, the
                // request was either issued by Phase 1 (no longer happens)
                // or the bootstrap task gave up and dropped the receiver.
                match self.pending_snapshot_requests.remove(&request_id) {
                    Some(reply) => {
                        let _ = reply.send(Ok(response));
                    }
                    None => {
                        debug!(peer = %peer, ?request_id, "Snapshot response without pending waiter (bootstrap timed out?)");
                    }
                }
            }

            request_response::Event::OutboundFailure { peer, error, request_id, .. } => {
                warn!(peer = %peer, error = %error, ?request_id, "Snapshot outbound request failed");
                if let Some(reply) = self.pending_snapshot_requests.remove(&request_id) {
                    let _ = reply.send(Err(SnapshotClientError::OutboundFailure(error.to_string())));
                }
            }

            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, error = %error, "Snapshot inbound failure");
            }

            _ => {}
        }
    }

    /// Dispatch a snapshot-client command onto the swarm.
    ///
    /// `SendRequest` parks the caller's `oneshot::Sender` in
    /// `pending_snapshot_requests` keyed by libp2p's `OutboundRequestId`;
    /// the response (or failure) arm of `handle_snapshot_event` resolves
    /// the oneshot. `ListConnectedPeers` answers synchronously.
    fn handle_snapshot_client_command(&mut self, cmd: SnapshotClientCommand) {
        match cmd {
            SnapshotClientCommand::SendRequest { peer, request, reply } => {
                // Bound the pending-request map. A malicious peer churn
                // pattern (connect, get many requests sent, disconnect,
                // repeat) can leak entries between dispatch and the libp2p
                // OutboundFailure event. The bootstrap path issues at most
                // a few thousand requests total, so 8192 is plenty of
                // headroom while still bounding the worst case.
                // (Audit finding Phase 2 Code W2.)
                const MAX_PENDING_SNAPSHOT_REQUESTS: usize = 8192;

                // Opportunistic GC: drop any entries whose receiver was
                // dropped (caller timed out and gave up). Cheap, runs on
                // every SendRequest to amortize cost across the bootstrap.
                self.pending_snapshot_requests
                    .retain(|_, sender| !sender.is_closed());

                if self.pending_snapshot_requests.len() >= MAX_PENDING_SNAPSHOT_REQUESTS {
                    warn!(
                        pending = self.pending_snapshot_requests.len(),
                        "Snapshot pending-request map at cap — dropping new request"
                    );
                    let _ = reply.send(Err(SnapshotClientError::OutboundFailure(
                        "snapshot client request cap reached".into(),
                    )));
                    return;
                }
                let id = self
                    .swarm
                    .behaviour_mut()
                    .snapshot
                    .send_request(&peer, request);
                self.pending_snapshot_requests.insert(id, reply);
            }
            SnapshotClientCommand::ListConnectedPeers { reply } => {
                let peers: Vec<PeerId> = self.swarm.connected_peers().copied().collect();
                let _ = reply.send(peers);
            }
        }
    }

    /// Initiate sync for all subscribed channels with a connected peer.
    ///
    /// Called when a new peer connection is established. Sends a SyncRequest
    /// for each channel the node is subscribed to, requesting messages after
    /// the latest message the node already has for that channel.
    fn sync_channels_with_peer(&mut self, peer_id: PeerId) {
        let channel_ids: Vec<u64> = self.topics.subscribed_channels().iter().copied().collect();

        if channel_ids.is_empty() {
            return;
        }

        info!(
            peer = %peer_id,
            channels = channel_ids.len(),
            "Starting sync with peer"
        );

        for channel_id in channel_ids {
            // Find the latest message timestamp for this channel to avoid re-fetching
            let after_timestamp = self
                .storage
                .latest_channel_timestamp(channel_id)
                .unwrap_or(None);

            let request = sync::SyncRequest {
                request_type: sync::SyncRequestType::ChannelMessages,
                channel_id: Some(channel_id),
                conversation_id: None,
                before_id: None,
                after_id: None,
                after_timestamp,
                limit: 500,
                requester: None,
                proof: None,
                proof_timestamp: None,
            };

            self.swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, request);
        }
    }

    /// Publish a NodeAnnouncement to the /ogmara/{network}/v1/network topic.
    ///
    /// Announces this node's presence, capabilities, and served channels
    /// so other nodes can discover it and the website can list it.
    fn publish_node_announcement(&mut self) {
        use crate::messages::envelope::{Envelope, PROTOCOL_VERSION};
        use crate::messages::types::{Capability, MessageType, NodeAnnouncementPayload};
        use ed25519_dalek::Signer;

        let channels: Vec<u64> = self.topics.subscribed_channels().iter().copied().collect();
        let user_count = self
            .storage
            .get_stat(crate::storage::schema::state_keys::TOTAL_USERS)
            .unwrap_or(0) as u32;

        // Snapshot fields are only set when the cache builder has produced
        // at least one snapshot. Older nodes that don't deserialize the
        // new fields fall through via `#[serde(default)]`.
        let (snapshot_height, snapshot_root) = match self.snapshot_cache.read() {
            Ok(guard) => match guard.as_ref() {
                Some(c) => (
                    Some(c.manifest.block_height),
                    Some(hex::encode(c.manifest.snapshot_root)),
                ),
                None => (None, None),
            },
            Err(_) => (None, None),
        };

        let payload = NodeAnnouncementPayload {
            node_id: self.node_id.clone(),
            channels,
            user_count,
            capabilities: vec![
                Capability::Chat,
                Capability::News,
                Capability::Sync,
            ],
            api_endpoint: self.public_url.clone(),
            ttl_seconds: 600, // 10 minutes
            snapshot_height,
            snapshot_root,
        };

        let payload_bytes = match rmp_serde::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize NodeAnnouncement");
                return;
            }
        };

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let author = match crate::crypto::pubkey_to_address(&self.signing_key.verifying_key()) {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "Failed to compute node address");
                return;
            }
        };

        // Compute msg_id: Keccak-256(author_pubkey + payload + timestamp)
        let pubkey_bytes = self.signing_key.verifying_key().to_bytes();
        let ts_bytes = now_ms.to_be_bytes();
        let mut preimage = Vec::with_capacity(32 + payload_bytes.len() + 8);
        preimage.extend_from_slice(&pubkey_bytes);
        preimage.extend_from_slice(&payload_bytes);
        preimage.extend_from_slice(&ts_bytes);
        let msg_id = crate::crypto::keccak256(&preimage);

        // Sign the msg_id
        let signature = self.signing_key.sign(&msg_id);

        let envelope = Envelope {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::NodeAnnouncement,
            msg_id,
            author,
            timestamp: now_ms,
            lamport_ts: 0, // announcements don't need causal ordering
            payload: payload_bytes,
            signature: signature.to_bytes().to_vec(),
            relay_path: Vec::new(),
        };

        let envelope_bytes = match rmp_serde::to_vec(&envelope) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "Failed to serialize announcement envelope");
                return;
            }
        };

        let topic = libp2p::gossipsub::IdentTopic::new(gossip::topic_network(self.topics.network_id()));
        match self.swarm.behaviour_mut().gossipsub.publish(topic, envelope_bytes) {
            Ok(_) => info!(node_id = %self.node_id, "Published NodeAnnouncement"),
            Err(e) => {
                // Bump counters for accurate stats (spec 10 §9.2) but
                // do not fire the `publish_failed_insufficient_peers`
                // alert from here — NodeAnnouncement is the periodic
                // self-advertisement, and a failure during the first
                // ~30s of operation (before any peer connects) is
                // structurally expected. The gossip-rx publish path
                // (application data) is where the alert matters.
                self.publish_failure_counters.record(&e);
                debug!(error = %e, "Failed to publish NodeAnnouncement (no peers yet?)");
            }
        }
    }

    /// Handle a received GossipSub message through the full validation pipeline.
    fn handle_gossip_message(&self, data: &[u8]) -> Result<()> {
        // Track incoming bytes and messages for dashboard metrics
        self.counters.add_bytes_in(data.len() as u64);
        self.counters.inc_messages_received();

        match self.router.process_message(data) {
            RouteResult::Accepted {
                msg_id,
                msg_type,
                raw_bytes,
            } => {
                debug!(
                    msg_id = %hex::encode(msg_id),
                    msg_type = ?msg_type,
                    "Message accepted from gossip"
                );

                self.counters.inc_messages_stored();

                // Feed to notification engine for mention detection (fire-and-forget)
                if let Some(ref engine) = self.notification_engine {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        if let Ok(envelope) = rmp_serde::from_slice::<Envelope>(&raw_bytes) {
                            engine.process(&envelope).await;
                        }
                    });
                }

                Ok(())
            }
            RouteResult::Duplicate => {
                debug!("Duplicate message from gossip, skipping");
                Ok(())
            }
            RouteResult::Rejected(reason) => {
                self.counters.inc_failed_validations();
                warn!(reason = %reason, "Rejected message from gossip");
                Ok(())
            }
            RouteResult::PowRequired { address } => {
                debug!(address = %address, "PoW required for gossip message (skipping)");
                Ok(())
            }
        }
    }
}
