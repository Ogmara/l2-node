//! Peer discovery mechanisms.
//!
//! Three discovery methods (spec 5.3):
//! 1. Bootstrap nodes — well-known nodes from config
//! 2. Kademlia DHT — distributed peer discovery
//! 3. mDNS — local network discovery (for dev and LAN)
//!
//! The actual discovery is handled by the composed behaviour in behaviour.rs.
//! This module provides helper functions for managing the peer directory.

use std::collections::HashMap;
use std::time::Instant;

use libp2p::PeerId;

/// A record of a known peer and its capabilities.
#[derive(Debug, Clone)]
pub struct PeerRecord {
    /// Peer ID.
    pub peer_id: PeerId,
    /// Channels this peer serves.
    pub channels: Vec<u64>,
    /// Approximate user count.
    pub user_count: u32,
    /// Public API endpoint (if exposed).
    pub api_endpoint: Option<String>,
    /// When we last heard from this peer.
    pub last_seen: Instant,
    /// TTL from the node announcement.
    pub ttl_seconds: u32,
}

impl PeerRecord {
    /// Check if this peer's announcement is stale.
    pub fn is_stale(&self) -> bool {
        self.last_seen.elapsed().as_secs() > self.ttl_seconds as u64
    }
}

/// In-memory peer directory mapping peer IDs to their announcements.
///
/// Populated from NodeAnnouncement messages received via GossipSub.
/// Stale entries (older than TTL) are periodically cleaned up.
pub struct PeerDirectory {
    peers: HashMap<PeerId, PeerRecord>,
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Update or insert a peer record from a node announcement.
    pub fn upsert(&mut self, record: PeerRecord) {
        self.peers.insert(record.peer_id, record);
    }

    /// Remove stale peer entries.
    pub fn prune_stale(&mut self) {
        self.peers.retain(|_, record| !record.is_stale());
    }

    /// Find peers that serve a specific channel.
    pub fn peers_for_channel(&self, channel_id: u64) -> Vec<&PeerRecord> {
        self.peers
            .values()
            .filter(|r| !r.is_stale() && r.channels.contains(&channel_id))
            .collect()
    }

    /// Get all known (non-stale) peers.
    pub fn all_peers(&self) -> Vec<&PeerRecord> {
        self.peers
            .values()
            .filter(|r| !r.is_stale())
            .collect()
    }

    /// Get the total number of known peers (including stale).
    pub fn total_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the number of active (non-stale) peers.
    pub fn active_count(&self) -> usize {
        self.peers.values().filter(|r| !r.is_stale()).count()
    }
}
