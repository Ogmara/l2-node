//! Shared application state for the API layer.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use tokio::sync::broadcast;

use crate::messages::router::MessageRouter;
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
}

impl AppState {
    pub fn new(
        storage: Storage,
        router: MessageRouter,
        node_id: String,
        klever_network: String,
        contract_address: String,
    ) -> Self {
        let (ws_broadcast, _) = broadcast::channel(1024);
        Self {
            storage,
            router,
            node_id,
            started_at: Instant::now(),
            peers: AtomicU32::new(0),
            ws_broadcast,
            klever_network,
            contract_address,
        }
    }

    pub fn peer_count(&self) -> u32 {
        self.peers.load(Ordering::Relaxed)
    }

    pub fn set_peer_count(&self, count: u32) {
        self.peers.store(count, Ordering::Relaxed);
    }
}
