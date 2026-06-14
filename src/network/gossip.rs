//! GossipSub topic management for the Ogmara network.
//!
//! Topic structure (spec 5.2) — includes network_id for cross-network isolation:
//!   /ogmara/{network}/v1/channel/{channel_id}  — chat messages for a channel
//!   /ogmara/{network}/v1/dm/{address}          — direct messages TO this address
//!   /ogmara/{network}/v1/news/global           — all news posts
//!   /ogmara/{network}/v1/news/tag/{tag}        — news posts with specific tag
//!   /ogmara/{network}/v1/profile               — profile updates
//!   /ogmara/{network}/v1/network               — network coordination messages

use std::collections::HashSet;

use libp2p::gossipsub::{IdentTopic, TopicHash};
use libp2p::Swarm;
use tracing::{debug, warn};

use super::behaviour::OgmaraBehaviour;

/// Build well-known topic paths with network prefix.
pub fn topic_news_global(network_id: &str) -> String {
    format!("/ogmara/{}/v1/news/global", network_id)
}
pub fn topic_profile(network_id: &str) -> String {
    format!("/ogmara/{}/v1/profile", network_id)
}
pub fn topic_network(network_id: &str) -> String {
    format!("/ogmara/{}/v1/network", network_id)
}

/// Presence-gossip topic for non-anchoring service-provider discovery
/// (spec 13 §10, l2-node 0.48.0+). The per-network prefix mirrors the
/// existing per-network isolation rule in spec 13 §4.2 so mainnet and
/// testnet nodes do not see each other's presence records.
pub fn topic_presence(network_id: &str) -> String {
    format!("/ogmara/{}/presence/v1", network_id)
}

/// Build a channel topic string.
pub fn channel_topic(network_id: &str, channel_id: u64) -> String {
    format!("/ogmara/{}/v1/channel/{}", network_id, channel_id)
}

/// Build a DM topic string for a given recipient address.
pub fn dm_topic(network_id: &str, address: &str) -> String {
    format!("/ogmara/{}/v1/dm/{}", network_id, address)
}

/// Build a news tag topic string.
pub fn news_tag_topic(network_id: &str, tag: &str) -> String {
    format!("/ogmara/{}/v1/news/tag/{}", network_id, tag)
}

/// Create a TopicHash from a topic string.
pub fn topic_hash(topic: &str) -> TopicHash {
    IdentTopic::new(topic).hash()
}

/// Manages GossipSub topic subscriptions.
pub struct TopicManager {
    /// Network ID for topic prefixing (testnet/mainnet).
    network_id: String,
    /// Currently subscribed channel IDs.
    subscribed_channels: HashSet<u64>,
    /// Currently subscribed DM addresses.
    subscribed_dms: HashSet<String>,
}

impl TopicManager {
    pub fn new(network_id: &str) -> Self {
        Self {
            network_id: network_id.to_string(),
            subscribed_channels: HashSet::new(),
            subscribed_dms: HashSet::new(),
        }
    }

    /// Return the network ID this manager uses for topic prefixes.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Subscribe to default topics that every node should be on.
    ///
    /// - /ogmara/{network}/v1/network — node announcements, coordination
    /// - /ogmara/{network}/v1/profile — profile updates (all nodes sync structure)
    /// - /ogmara/{network}/v1/news/global — global news feed
    pub fn subscribe_defaults(&mut self, swarm: &mut Swarm<OgmaraBehaviour>) {
        let net = topic_network(&self.network_id);
        let prof = topic_profile(&self.network_id);
        let news = topic_news_global(&self.network_id);
        self.subscribe_topic(swarm, &net);
        self.subscribe_topic(swarm, &prof);
        self.subscribe_topic(swarm, &news);
    }

    /// Subscribe to the presence-gossip topic (spec 13 §10, l2-node
    /// 0.48.0+). Called separately from `subscribe_defaults` because
    /// participation is opt-in: only nodes with `[network.presence]
    /// enabled = true` join the topic. Nodes that don't subscribe see
    /// no presence traffic, period.
    pub fn subscribe_presence(&mut self, swarm: &mut Swarm<OgmaraBehaviour>) {
        let topic = topic_presence(&self.network_id);
        self.subscribe_topic(swarm, &topic);
    }

    /// Subscribe to a channel's GossipSub topic.
    pub fn subscribe_channel(
        &mut self,
        swarm: &mut Swarm<OgmaraBehaviour>,
        channel_id: u64,
    ) {
        if self.subscribed_channels.insert(channel_id) {
            let topic = channel_topic(&self.network_id, channel_id);
            self.subscribe_topic(swarm, &topic);
        }
    }

    /// Subscribe to a user's DM topic.
    pub fn subscribe_dm(
        &mut self,
        swarm: &mut Swarm<OgmaraBehaviour>,
        address: &str,
    ) {
        if self.subscribed_dms.insert(address.to_string()) {
            let topic = dm_topic(&self.network_id, address);
            self.subscribe_topic(swarm, &topic);
        }
    }

    /// Unsubscribe from a user's DM topic (LRU eviction of a local DM user,
    /// l2-node 0.69.0+). No-op if not currently subscribed. Returns `true` iff
    /// a subscription was actually removed.
    pub fn unsubscribe_dm(
        &mut self,
        swarm: &mut Swarm<OgmaraBehaviour>,
        address: &str,
    ) -> bool {
        if self.subscribed_dms.remove(address) {
            let topic = IdentTopic::new(dm_topic(&self.network_id, address));
            match swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
                true => debug!(topic = %topic, "Unsubscribed from DM topic"),
                false => debug!(topic = %topic, "Was not subscribed to DM topic"),
            }
            true
        } else {
            false
        }
    }

    /// Get the set of subscribed channel IDs.
    pub fn subscribed_channels(&self) -> &HashSet<u64> {
        &self.subscribed_channels
    }

    fn subscribe_topic(&self, swarm: &mut Swarm<OgmaraBehaviour>, topic_str: &str) {
        let topic = IdentTopic::new(topic_str);
        match swarm.behaviour_mut().gossipsub.subscribe(&topic) {
            Ok(true) => debug!(topic = %topic_str, "Subscribed to topic"),
            Ok(false) => debug!(topic = %topic_str, "Already subscribed"),
            Err(e) => warn!(topic = %topic_str, error = %e, "Failed to subscribe"),
        }
    }

}
