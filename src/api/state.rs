//! Shared application state for the API layer.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;

use crate::ipfs::client::IpfsClient;
use crate::messages::router::MessageRouter;
use crate::notifications::engine::NotificationEngine;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;

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
    /// Connected peer count (updated by the network layer).
    peers: AtomicU32,
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
    ) -> Self {
        let (ws_broadcast, _) = broadcast::channel(1024);
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
    ) -> Self {
        Self {
            storage,
            router,
            node_id,
            started_at: Instant::now(),
            peers: AtomicU32::new(0),
            ws_broadcast,
            klever_network,
            contract_address,
            ipfs,
            identity,
            public_url,
            notification_engine,
        }
    }

    pub fn peer_count(&self) -> u32 {
        self.peers.load(Ordering::Relaxed)
    }

    pub fn set_peer_count(&self, count: u32) {
        self.peers.store(count, Ordering::Relaxed);
    }
}
