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

use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::messages::router::{MessageRouter, RouteResult};
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;

use self::behaviour::{OgmaraBehaviour, OgmaraBehaviourEvent};
use self::gossip::TopicManager;

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
}

impl NetworkService {
    /// Create and start the network service.
    pub async fn new(
        config: &Config,
        storage: Storage,
        identity: IdentityResolver,
        keypair: libp2p::identity::Keypair,
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

        // Connect to bootstrap nodes
        for addr_str in &config.network.bootstrap_nodes {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    if let Err(e) = swarm.dial(addr.clone()) {
                        warn!(addr = %addr, error = %e, "Failed to dial bootstrap node");
                    } else {
                        info!(addr = %addr, "Dialing bootstrap node");
                    }
                }
                Err(e) => {
                    warn!(addr = %addr_str, error = %e, "Invalid bootstrap node address");
                }
            }
        }

        // Create topic manager and subscribe to default topics
        let mut topics = TopicManager::new();
        topics.subscribe_defaults(&mut swarm);

        // Create message router with rate limiting and identity resolution
        let router = MessageRouter::new(storage.clone(), identity, config.api.rate_limit_per_ip);

        Ok(Self {
            swarm,
            topics,
            router,
            storage,
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
    /// Processes swarm events and routes messages to storage.
    pub async fn run(
        &mut self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) {
        info!(
            peer_id = %self.swarm.local_peer_id(),
            "Network event loop started"
        );

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
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
                debug!(event = ?event, "Kademlia event");
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, info, .. },
            )) => {
                debug!(
                    peer = %peer_id,
                    protocol_version = %info.protocol_version,
                    agent_version = %info.agent_version,
                    "Identified peer"
                );
                // Add identified peer's addresses to Kademlia
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
            }

            SwarmEvent::Behaviour(OgmaraBehaviourEvent::RequestResponse(event)) => {
                sync::handle_request_response_event(event, &self.storage, &self.router);
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                info!(addr = %address, "Listening on new address");
            }

            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                ..
            } => {
                debug!(
                    peer = %peer_id,
                    connections = %num_established,
                    "Connection established"
                );
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                debug!(
                    peer = %peer_id,
                    remaining = %num_established,
                    "Connection closed"
                );
            }

            _ => {}
        }
    }

    /// Handle a received GossipSub message through the full validation pipeline.
    fn handle_gossip_message(&self, data: &[u8]) -> Result<()> {
        match self.router.process_message(data) {
            RouteResult::Accepted { msg_id, msg_type } => {
                debug!(
                    msg_id = %hex::encode(msg_id),
                    msg_type = ?msg_type,
                    "Message accepted from gossip"
                );
                Ok(())
            }
            RouteResult::Duplicate => {
                debug!("Duplicate message from gossip, skipping");
                Ok(())
            }
            RouteResult::Rejected(reason) => {
                warn!(reason = %reason, "Rejected message from gossip");
                Ok(())
            }
        }
    }
}
