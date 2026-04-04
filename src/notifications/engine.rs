//! Notification engine — mention detection, routing, and push gateway.
//!
//! Parses the `mentions` field in chat messages, matches against locally
//! connected users, and delivers notifications via WebSocket and push gateway.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use crate::messages::envelope::Envelope;
use crate::messages::types::{ChatMessagePayload, MessageType, NewsCommentPayload};
use crate::storage::rocks::Storage;
use crate::storage::schema::cf;

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
    /// Human-readable channel name (for display in push notifications).
    pub channel_name: Option<String>,
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
///
/// Thread-safe: can be shared across tasks via `Arc<NotificationEngine>`.
pub struct NotificationEngine {
    /// Addresses of locally connected users (for mention matching).
    /// Protected by RwLock for concurrent access from WS handlers
    /// and the message processing pipeline.
    local_users: Arc<RwLock<HashSet<String>>>,
    /// Broadcast channel for WebSocket delivery.
    ws_broadcast: broadcast::Sender<String>,
    /// Push gateway base URL (if configured).
    push_gateway_url: Option<String>,
    /// Push gateway auth token.
    push_gateway_token: Option<String>,
    /// HTTP client for push gateway.
    http: reqwest::Client,
    /// Persistent storage for notification history retrieval via API.
    storage: Option<Storage>,
}

impl NotificationEngine {
    pub fn new(
        ws_broadcast: broadcast::Sender<String>,
        push_gateway_url: Option<String>,
        push_gateway_token: Option<String>,
    ) -> Self {
        Self {
            local_users: Arc::new(RwLock::new(HashSet::new())),
            ws_broadcast,
            push_gateway_url,
            push_gateway_token,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            storage: None,
        }
    }

    /// Set the storage backend for persisting notifications.
    ///
    /// When set, every delivered notification is also written to disk so it
    /// can be retrieved later via the `GET /api/v1/notifications` endpoint.
    pub fn set_storage(&mut self, storage: Storage) {
        self.storage = Some(storage);
    }

    /// Register a locally connected user for mention notifications.
    pub async fn add_local_user(&self, address: &str) {
        let mut users = self.local_users.write().await;
        users.insert(address.to_string());
        debug!(address, local_users = users.len(), "Added local user for notifications");
    }

    /// Remove a locally connected user.
    pub async fn remove_local_user(&self, address: &str) {
        let mut users = self.local_users.write().await;
        users.remove(address);
        debug!(address, local_users = users.len(), "Removed local user from notifications");
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
        let users = self.local_users.read().await;

        // Look up channel name once (if applicable)
        let channel_name = channel_id.and_then(|id| self.lookup_channel_name(id));

        for mentioned_address in mentions {
            if users.contains(mentioned_address) {
                let notification = Notification {
                    notification_type: NotificationType::Mention,
                    msg_id: hex::encode(envelope.msg_id),
                    author: envelope.author.clone(),
                    channel_id,
                    channel_name: channel_name.clone(),
                    preview: preview.to_string(),
                    timestamp: envelope.timestamp,
                };

                self.deliver(mentioned_address, &envelope.msg_id, notification)
                    .await;
            }
        }
    }

    /// Look up a channel's display name from storage.
    fn lookup_channel_name(&self, channel_id: u64) -> Option<String> {
        let storage = self.storage.as_ref()?;
        let data = storage
            .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())
            .ok()??;
        let channel: serde_json::Value = serde_json::from_slice(&data).ok()?;
        // Try "name" first, fall back to "slug"
        channel
            .get("name")
            .or_else(|| channel.get("slug"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Deliver a notification via WebSocket broadcast, push gateway, and persistent storage.
    ///
    /// `target_address` is the klv1 address of the notification recipient.
    /// `notification_id` is the 32-byte msg_id used as a unique notification key.
    async fn deliver(
        &self,
        target_address: &str,
        notification_id: &[u8; 32],
        notification: Notification,
    ) {
        debug!(
            to = ?notification.notification_type,
            msg_id = %notification.msg_id,
            target = %target_address,
            "Delivering notification"
        );

        // Persist to storage (if configured) so the GET /api/v1/notifications
        // endpoint can retrieve historical notifications.
        if let Some(ref storage) = self.storage {
            // Field names match the SDK Notification interface:
            // type (not notification_type), from (not author)
            let notification_json = serde_json::json!({
                "type": notification_type_str(&notification.notification_type),
                "msg_id": notification.msg_id,
                "from": notification.author,
                "channel_id": notification.channel_id.map(|id| id.to_string()),
                "channel_name": notification.channel_name,
                "preview": notification.preview,
                "timestamp": notification.timestamp,
            });
            if let Err(e) = storage.store_notification(
                target_address,
                notification_id,
                notification.timestamp,
                &notification_json,
            ) {
                warn!(error = %e, "Failed to persist notification to storage");
            }
        }

        // WebSocket broadcast
        let ws_msg = serde_json::json!({
            "type": "notification",
            "mention": notification,
        });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(json);
        }

        // Push gateway (if configured)
        if let Some(ref base_url) = self.push_gateway_url {
            self.send_to_push_gateway(base_url, target_address, &notification)
                .await;
        }
    }

    /// Send a notification to the push gateway.
    ///
    /// Posts to `{base_url}/push` with the payload format expected by the
    /// push gateway's `PushTrigger` struct.
    async fn send_to_push_gateway(
        &self,
        base_url: &str,
        target_address: &str,
        notification: &Notification,
    ) {
        let url = format!("{}/push", base_url.trim_end_matches('/'));

        let notification_type = match notification.notification_type {
            NotificationType::Mention => "mention",
            NotificationType::Reply => "reply",
            NotificationType::Dm => "dm",
        };

        let body = serde_json::json!({
            "address": target_address,
            "type": notification_type,
            "channel_id": notification.channel_id,
            "channel_name": notification.channel_name,
            "msg_id": notification.msg_id,
            "sender": notification.author,
            "timestamp": notification.timestamp,
        });

        let mut req = self.http.post(&url).json(&body);

        if let Some(ref token) = self.push_gateway_token {
            req = req.bearer_auth(token);
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!(target = %target_address, "Push notification sent to gateway");
            }
            Ok(resp) => {
                warn!(
                    status = %resp.status(),
                    target = %target_address,
                    "Push gateway returned error"
                );
            }
            Err(e) => {
                warn!(error = %e, "Failed to send push notification to gateway");
            }
        }
    }
}

/// Convert NotificationType to the string expected by the SDK Notification interface.
fn notification_type_str(nt: &NotificationType) -> &'static str {
    match nt {
        NotificationType::Mention => "mention",
        NotificationType::Reply => "reply",
        NotificationType::Dm => "dm",
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
