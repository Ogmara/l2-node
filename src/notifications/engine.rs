//! Notification engine — mention detection, routing, and push gateway.
//!
//! Parses the `mentions` field in chat messages, matches against locally
//! connected users, and delivers notifications via WebSocket and push gateway.

use std::collections::HashSet;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::messages::envelope::Envelope;
use crate::messages::types::{ChatMessagePayload, MessageType, NewsCommentPayload};

/// A notification to deliver to a user.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    /// Type of notification.
    pub notification_type: NotificationType,
    /// Message ID that triggered the notification.
    pub msg_id: String,
    /// Author of the message.
    pub author: String,
    /// Channel context (if applicable).
    pub channel_id: Option<u64>,
    /// Preview of the content (first 100 chars).
    pub preview: String,
    /// Timestamp of the triggering message.
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    Mention,
    Reply,
    Dm,
}

/// The notification engine processes messages and generates notifications.
pub struct NotificationEngine {
    /// Addresses of locally connected users (for mention matching).
    local_users: HashSet<String>,
    /// Broadcast channel for WebSocket delivery.
    ws_broadcast: broadcast::Sender<String>,
    /// Push gateway URL (if configured).
    push_gateway_url: Option<String>,
    /// Push gateway auth token.
    push_gateway_token: Option<String>,
    /// HTTP client for push gateway.
    http: reqwest::Client,
}

impl NotificationEngine {
    pub fn new(
        ws_broadcast: broadcast::Sender<String>,
        push_gateway_url: Option<String>,
        push_gateway_token: Option<String>,
    ) -> Self {
        Self {
            local_users: HashSet::new(),
            ws_broadcast,
            push_gateway_url,
            push_gateway_token,
            http: reqwest::Client::new(),
        }
    }

    /// Register a locally connected user for mention notifications.
    pub fn add_local_user(&mut self, address: &str) {
        self.local_users.insert(address.to_string());
    }

    /// Remove a locally connected user.
    pub fn remove_local_user(&mut self, address: &str) {
        self.local_users.remove(address);
    }

    /// Process an envelope and generate notifications if applicable.
    pub async fn process(&self, envelope: &Envelope) {
        match envelope.msg_type {
            MessageType::ChatMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChatMessagePayload>(&envelope.payload)
                {
                    let preview = truncate(&payload.content, 100);
                    // Cap mentions to prevent amplification (max 50 per spec)
                    let mentions = &payload.mentions[..payload.mentions.len().min(50)];
                    self.check_mentions(envelope, mentions, Some(payload.channel_id), &preview)
                        .await;
                }
            }
            MessageType::NewsComment => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsCommentPayload>(&envelope.payload)
                {
                    let preview = truncate(&payload.content, 100);
                    let mentions = &payload.mentions[..payload.mentions.len().min(50)];
                    self.check_mentions(envelope, mentions, None, &preview)
                        .await;
                }
            }
            MessageType::DirectMessage => {
                // DM notifications are handled by the DM subscription system
                // The recipient's node gets the message via GossipSub topic
            }
            _ => {}
        }
    }

    /// Check mentions list against local users and deliver notifications.
    async fn check_mentions(
        &self,
        envelope: &Envelope,
        mentions: &[String],
        channel_id: Option<u64>,
        preview: &str,
    ) {
        for mentioned_address in mentions {
            if self.local_users.contains(mentioned_address) {
                let notification = Notification {
                    notification_type: NotificationType::Mention,
                    msg_id: hex::encode(envelope.msg_id),
                    author: envelope.author.clone(),
                    channel_id,
                    preview: preview.to_string(),
                    timestamp: envelope.timestamp,
                };

                self.deliver(notification).await;
            }
        }
    }

    /// Deliver a notification via WebSocket broadcast and push gateway.
    async fn deliver(&self, notification: Notification) {
        debug!(
            to = ?notification.notification_type,
            msg_id = %notification.msg_id,
            "Delivering notification"
        );

        // WebSocket broadcast
        let ws_msg = serde_json::json!({
            "type": "notification",
            "mention": notification,
        });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(json);
        }

        // Push gateway (if configured)
        if let Some(ref url) = self.push_gateway_url {
            self.send_to_push_gateway(url, &notification).await;
        }
    }

    /// Send a notification to the push gateway.
    async fn send_to_push_gateway(&self, url: &str, notification: &Notification) {
        let mut req = self.http.post(url).json(notification);

        if let Some(ref token) = self.push_gateway_token {
            req = req.bearer_auth(token);
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!("Push notification sent successfully");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Push gateway returned error");
            }
            Err(e) => {
                warn!(error = %e, "Failed to send push notification");
            }
        }
    }
}

/// Truncate a string to max_len characters, adding "..." if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if max_len < 4 {
        return s.chars().take(max_len).collect();
    }
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len - 3).collect();
        format!("{}...", truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
        assert_eq!(truncate("", 5), "");
    }
}
