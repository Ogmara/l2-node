//! GossipSub topic management for the Ogmara network.
//!
//! Topic structure (spec 5.2):
//!   /ogmara/v1/channel/{channel_id}  — chat messages for a channel
//!   /ogmara/v1/dm/{address}          — direct messages TO this address
//!   /ogmara/v1/news/global           — all news posts
//!   /ogmara/v1/news/tag/{tag}        — news posts with specific tag
//!   /ogmara/v1/profile               — profile updates
//!   /ogmara/v1/network               — network coordination messages

use std::collections::HashSet;

use libp2p::gossipsub::{IdentTopic, TopicHash};
use libp2p::Swarm;
use tracing::{debug, warn};

use super::behaviour::OgmaraBehaviour;

/// Well-known topic paths.
pub const TOPIC_NEWS_GLOBAL: &str = "/ogmara/v1/news/global";
pub const TOPIC_PROFILE: &str = "/ogmara/v1/profile";
pub const TOPIC_NETWORK: &str = "/ogmara/v1/network";

/// Build a channel topic string.
pub fn channel_topic(channel_id: u64) -> String {
    format!("/ogmara/v1/channel/{}", channel_id)
}

/// Build a DM topic string for a given recipient address.
pub fn dm_topic(address: &str) -> String {
    format!("/ogmara/v1/dm/{}", address)
}

/// Build a news tag topic string.
pub fn news_tag_topic(tag: &str) -> String {
    format!("/ogmara/v1/news/tag/{}", tag)
}

/// Create a TopicHash from a topic string.
pub fn topic_hash(topic: &str) -> TopicHash {
    IdentTopic::new(topic).hash()
}

/// Manages GossipSub topic subscriptions.
pub struct TopicManager {
    /// Currently subscribed channel IDs.
    subscribed_channels: HashSet<u64>,
    /// Currently subscribed DM addresses.
    subscribed_dms: HashSet<String>,
}

impl TopicManager {
    pub fn new() -> Self {
        Self {
            subscribed_channels: HashSet::new(),
            subscribed_dms: HashSet::new(),
        }
    }

    /// Subscribe to default topics that every node should be on.
    ///
    /// - /ogmara/v1/network — node announcements, coordination
    /// - /ogmara/v1/profile — profile updates (all nodes sync structure)
    /// - /ogmara/v1/news/global — global news feed
    pub fn subscribe_defaults(&mut self, swarm: &mut Swarm<OgmaraBehaviour>) {
        self.subscribe_topic(swarm, TOPIC_NETWORK);
        self.subscribe_topic(swarm, TOPIC_PROFILE);
        self.subscribe_topic(swarm, TOPIC_NEWS_GLOBAL);
    }

    /// Subscribe to a channel's GossipSub topic.
    pub fn subscribe_channel(
        &mut self,
        swarm: &mut Swarm<OgmaraBehaviour>,
        channel_id: u64,
    ) {
        if self.subscribed_channels.insert(channel_id) {
            let topic = channel_topic(channel_id);
            self.subscribe_topic(swarm, &topic);
        }
    }

    /// Unsubscribe from a channel's GossipSub topic.
    pub fn unsubscribe_channel(
        &mut self,
        swarm: &mut Swarm<OgmaraBehaviour>,
        channel_id: u64,
    ) {
        if self.subscribed_channels.remove(&channel_id) {
            let topic = channel_topic(channel_id);
            self.unsubscribe_topic(swarm, &topic);
        }
    }

    /// Subscribe to a user's DM topic.
    pub fn subscribe_dm(
        &mut self,
        swarm: &mut Swarm<OgmaraBehaviour>,
        address: &str,
    ) {
        if self.subscribed_dms.insert(address.to_string()) {
            let topic = dm_topic(address);
            self.subscribe_topic(swarm, &topic);
        }
    }

    /// Unsubscribe from a user's DM topic.
    pub fn unsubscribe_dm(
        &mut self,
        swarm: &mut Swarm<OgmaraBehaviour>,
        address: &str,
    ) {
        if self.subscribed_dms.remove(address) {
            let topic = dm_topic(address);
            self.unsubscribe_topic(swarm, &topic);
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

    fn unsubscribe_topic(&self, swarm: &mut Swarm<OgmaraBehaviour>, topic_str: &str) {
        let topic = IdentTopic::new(topic_str);
        if swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
            debug!(topic = %topic_str, "Unsubscribed from topic");
        } else {
            debug!(topic = %topic_str, "Was not subscribed");
        }
    }
}
