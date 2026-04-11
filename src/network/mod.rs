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
pub mod sync;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
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
}

impl NetworkService {
    /// Create and start the network service.
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

        info!(
            quic = %quic_addr,
            tcp = %tcp_addr,
            "Network listening"
        );

        // Connect to bootstrap nodes and add them to Kademlia
        let mut bootstrap_addrs = Vec::new();
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

        // Create topic manager and subscribe to default topics
        let mut topics = TopicManager::new();
        topics.subscribe_defaults(&mut swarm);

        // Create message router for P2P message processing (no PoW for gossip)
        let router = MessageRouter::new(storage.clone(), identity, None);

        let public_url = config.api.public_url.clone();

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
        })
    }

    /// Get the local peer ID.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Subscribe to a channel's GossipSub topic.
    pub fn subscribe_channel(&mut self, channel_id: u64) {
        self.topics
            .subscribe_channel(&mut self.swarm, channel_id);
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
    ) {
        info!(
            peer_id = %self.swarm.local_peer_id(),
            "Network event loop started"
        );

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

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
                }
                Some(channel_id) = channel_rx.recv() => {
                    self.topics.subscribe_channel(&mut self.swarm, channel_id);
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
                        Err(e) => warn!(topic = %topic, error = %e, "Failed to publish to GossipSub"),
                    }
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
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                    self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
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
                let is_ogmara = info.protocol_version.starts_with("/ogmara/");
                let agent_ver = info.agent_version.clone();
                info!(
                    peer = %peer_id,
                    protocol_version = %info.protocol_version,
                    agent_version = %agent_ver,
                    listen_addrs = info.listen_addrs.len(),
                    "Identified peer"
                );
                // Add identified peer's addresses to Kademlia and store the
                // first address for reconnection after disconnect.
                let mut first_addr = None;
                for addr in info.listen_addrs.into_iter().take(16) {
                    if first_addr.is_none() {
                        first_addr = Some(addr.clone());
                    }
                    // Only add Ogmara peers to Kademlia (prevent DHT pollution)
                    if is_ogmara {
                        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    }
                }
                // Store address for reconnection
                if let Some(addr) = first_addr {
                    self.known_peer_addrs.insert(peer_id, addr);
                }
                // Remove from reconnect queue if it was pending (successfully connected)
                self.reconnect_queue.retain(|e| e.peer_id != peer_id);

                if is_ogmara {
                    // Sync channel messages from this peer
                    self.sync_channels_with_peer(peer_id);

                    // Track this peer so it appears in /api/v1/network/nodes
                    // even before its NodeAnnouncement arrives via GossipSub
                    if let Ok(ed25519_pk) = info.public_key.try_into_ed25519() {
                        use sha2::{Digest, Sha256};
                        let hash = Sha256::digest(ed25519_pk.to_bytes());
                        let node_id = bs58::encode(&hash[..20]).into_string();
                        self.peer_node_ids.insert(peer_id, node_id.clone());
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
                                    });
                                }
                            }
                            Err(e) => warn!("connected_peers lock poisoned: {e}"),
                        }
                    }
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::RequestResponse(event)) => {
                self.handle_request_response(event);
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
                        debug!(addr = %addr, error = %e, "Bootstrap redial failed");
                    } else {
                        debug!(addr = %addr, "Redialing bootstrap node");
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

            // Max attempts exceeded? Give up.
            if entry.attempts >= MAX_RECONNECT_ATTEMPTS {
                debug!(
                    peer = %entry.peer_id,
                    attempts = entry.attempts,
                    "Giving up on reconnection"
                );
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

    /// Publish a NodeAnnouncement to the /ogmara/v1/network topic.
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

        let topic = libp2p::gossipsub::IdentTopic::new(gossip::TOPIC_NETWORK);
        match self.swarm.behaviour_mut().gossipsub.publish(topic, envelope_bytes) {
            Ok(_) => info!(node_id = %self.node_id, "Published NodeAnnouncement"),
            Err(e) => debug!(error = %e, "Failed to publish NodeAnnouncement (no peers yet?)"),
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
