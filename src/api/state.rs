//! Shared application state for the API layer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::ipfs::client::IpfsClient;
use crate::messages::router::MessageRouter;
use crate::notifications::engine::NotificationEngine;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;

/// Info about a connected Ogmara peer (from libp2p Identify).
#[derive(Debug, Clone)]
pub struct ConnectedPeerInfo {
    /// Agent version string (e.g. "ogmara-node/0.21.0").
    pub agent_version: String,
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
        )
    }

    /// Create AppState with an externally provided broadcast channel.
    ///
    /// Used when the notification engine needs to share the same broadcast
    /// channel as the WebSocket layer.
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
    ) -> Self {
        Self {
            storage,
            router,
            node_id,
            started_at: Instant::now(),
            peers: peer_count,
            ws_broadcast,
            klever_network,
            contract_address,
            ipfs,
            identity,
            public_url,
            notification_engine,
            anchor_trigger,
            gossip_tx,
            connected_peers,
        }
    }

    pub fn peer_count(&self) -> u32 {
        self.peers.load(Ordering::Relaxed)
    }

    pub fn set_peer_count(&self, count: u32) {
        self.peers.store(count, Ordering::Relaxed);
    }
}
