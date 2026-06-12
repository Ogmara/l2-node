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
use crate::messages::types::{
    ChatMessagePayload, DeletePayload, DirectMessagePayload, EditPayload, MessageType,
    NewsCommentPayload, ReactionPayload,
};
use crate::api::state::{WsAudience, WsOutbound};
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
    ws_broadcast: broadcast::Sender<Arc<WsOutbound>>,
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
        ws_broadcast: broadcast::Sender<Arc<WsOutbound>>,
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
                    // Real-time delivery: broadcast the chat message to WS
                    // subscribers. `process()` runs on BOTH the API-post path
                    // AND the gossip-receive path, so this is what makes a
                    // message posted on one node appear live on every node's
                    // connected clients (not just after a poll/reload).
                    self.broadcast_channel_message(envelope, payload.channel_id, &[]);
                }
            }
            // Real-time delivery for reactions/edits/deletes so they appear
            // live cross-node (they already propagate via gossip, but without
            // this only show on poll/reload). `target_msg_id` (hex of the
            // payload's `target_id`) is surfaced top-level so the client can
            // apply the update to the right message.
            MessageType::ChatReaction => {
                if let Ok(p) = rmp_serde::from_slice::<ReactionPayload>(&envelope.payload) {
                    if let Some(cid) = p.channel_id {
                        self.broadcast_channel_message(
                            envelope,
                            cid,
                            &[
                                ("target_msg_id", serde_json::json!(hex::encode(p.target_id))),
                                ("emoji", serde_json::json!(p.emoji)),
                                ("remove", serde_json::json!(p.remove)),
                            ],
                        );
                    }
                }
            }
            MessageType::ChatEdit => {
                if let Ok(p) = rmp_serde::from_slice::<EditPayload>(&envelope.payload) {
                    if let Some(cid) = p.channel_id {
                        self.broadcast_channel_message(
                            envelope,
                            cid,
                            &[("target_msg_id", serde_json::json!(hex::encode(p.target_id)))],
                        );
                    }
                }
            }
            MessageType::ChatDelete => {
                if let Ok(p) = rmp_serde::from_slice::<DeletePayload>(&envelope.payload) {
                    if let Some(cid) = p.channel_id {
                        self.broadcast_channel_message(
                            envelope,
                            cid,
                            &[("target_msg_id", serde_json::json!(hex::encode(p.target_id)))],
                        );
                    }
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
                // Real-time delivery: push the DM to the sender's + recipient's
                // connected clients. The recipient's node receives the DM via the
                // GossipSub DM topic and lands here on the gossip-receive path; the
                // sender's node lands here on the API-post path. Without this,
                // cross-node DMs were stored but never pushed to the live WS (only
                // surfaced on a poll/reload) — the "web→desktop never arrives"
                // bug. Targeted to the two participants only (no all-client leak).
                self.broadcast_direct_message(envelope);
            }
            _ => {}
        }
    }

    /// Broadcast a chat message to WebSocket subscribers as a `{type:"message"}`
    /// event so connected clients render it live. The JSON mirrors the REST
    /// message shape (hex `msg_id`, device→wallet-resolved `author`) and adds a
    /// top-level `channel_id` so clients can filter by the channel they're
    /// viewing. Best-effort — a dropped broadcast just means the client picks
    /// the message up on its next poll/reload.
    /// Whether a channel is PUBLIC (0) or READ-PUBLIC (1) — i.e. its content is
    /// world-readable. Fails CLOSED (returns false) for every other case: the
    /// CHANNELS record is missing (a fresh/lagging node may receive a message
    /// before the channel record), the record fails to parse, the channel is
    /// PRIVATE (2), or the type is unknown. Accepts both numeric and legacy
    /// string `channel_type` encodings. Used to gate anything that fans out to
    /// all WS clients (message + reaction/edit/delete broadcasts, mention
    /// previews).
    fn channel_is_public(&self, channel_id: u64) -> bool {
        self.storage
            .as_ref()
            .and_then(|s| s.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()).ok().flatten())
            .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
            .and_then(|meta| match meta.get("channel_type") {
                Some(serde_json::Value::Number(n)) => n.as_u64(),
                Some(serde_json::Value::String(s)) => match s.as_str() {
                    "Public" => Some(0),
                    "ReadPublic" => Some(1),
                    "Private" => Some(2),
                    _ => None,
                },
                _ => None,
            })
            .map(|ct| ct == 0 || ct == 1)
            .unwrap_or(false)
    }

    fn broadcast_channel_message(
        &self,
        envelope: &Envelope,
        channel_id: u64,
        extra: &[(&str, serde_json::Value)],
    ) {
        // PRIVACY (fail CLOSED): the broadcast fans out to ALL connected WS
        // clients (they filter by channel_id client-side), so ONLY broadcast
        // PUBLIC / READ-PUBLIC channels — never a private channel's content.
        if !self.channel_is_public(channel_id) {
            return;
        }
        let mut val = match serde_json::to_value(envelope) {
            Ok(v) => v,
            Err(_) => return,
        };
        if let serde_json::Value::Object(ref mut map) = val {
            // msg_id: byte array → hex (matches REST `envelope_to_json`).
            if let Some(serde_json::Value::Array(bytes)) = map.get("msg_id") {
                let hex: String = bytes
                    .iter()
                    .filter_map(|b| b.as_u64().map(|n| format!("{:02x}", n as u8)))
                    .collect();
                map.insert("msg_id".into(), serde_json::Value::String(hex));
            }
            // Resolve device key → wallet so the live message's author matches
            // the REST/optimistic one (lets the client dedup the echo).
            if let Some(ref storage) = self.storage {
                if let Ok(Some(wallet)) = storage.resolve_wallet(&envelope.author) {
                    map.insert("author".into(), serde_json::Value::String(wallet));
                }
            }
            // The bare envelope has no top-level channel_id (it's in the
            // payload); clients filter on it, so surface it here.
            map.insert("channel_id".into(), serde_json::json!(channel_id));
            // Per-type routing fields (e.g. target_msg_id/emoji/remove for
            // reactions/edits/deletes) the client needs to apply the update.
            for (k, v) in extra {
                map.insert((*k).to_string(), v.clone());
            }
        }
        let ws_msg = serde_json::json!({ "type": "message", "envelope": val });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            // Public-channel content → every connected client (the guard above
            // already returned for private channels).
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Everyone,
                json,
            }));
        }
    }

    /// Real-time WS delivery of a `DirectMessage` to its two participants only.
    ///
    /// Runs on BOTH the API-post and gossip-receive paths (see [`Self::process`]),
    /// so a DM sent on one node appears live on the recipient's connected client
    /// on ANY node — previously the `DirectMessage` arm was empty, so cross-node
    /// DMs were stored but never pushed (they only showed on a poll/reload), and
    /// a recipient whose client doesn't poll saw nothing at all.
    ///
    /// PRIVACY: a DM envelope (ciphertext + sender/recipient metadata) is
    /// delivered ONLY to the sender's and recipient's wallets via a `Wallets`
    /// audience — never broadcast to all clients like public-channel messages.
    fn broadcast_direct_message(&self, envelope: &Envelope) {
        let payload: DirectMessagePayload = match rmp_serde::from_slice(&envelope.payload) {
            Ok(p) => p,
            Err(_) => return,
        };
        // Resolve the sender's device key → wallet so the client's
        // `author === peerAddress` match (and its own-echo filter) works, exactly
        // like the channel-message path.
        let sender_wallet = self
            .storage
            .as_ref()
            .and_then(|s| s.resolve_wallet(&envelope.author).ok().flatten())
            .unwrap_or_else(|| envelope.author.clone());

        let mut val = match serde_json::to_value(envelope) {
            Ok(v) => v,
            Err(_) => return,
        };
        if let serde_json::Value::Object(ref mut map) = val {
            // msg_id: byte array → hex (matches REST `envelope_to_json` + the
            // channel path, so the client dedups against the polled copy).
            if let Some(serde_json::Value::Array(bytes)) = map.get("msg_id") {
                let hex: String = bytes
                    .iter()
                    .filter_map(|b| b.as_u64().map(|n| format!("{:02x}", n as u8)))
                    .collect();
                map.insert("msg_id".into(), serde_json::Value::String(hex));
            }
            map.insert(
                "author".into(),
                serde_json::Value::String(sender_wallet.clone()),
            );
        }
        let ws_msg = serde_json::json!({ "type": "dm", "envelope": val });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Wallets(vec![sender_wallet, payload.recipient]),
                json,
            }));
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

        // audit 2026-06-07 (W20): dedup mentions so a message that names the
        // same wallet multiple times only fires one notification / stores one
        // mention row, instead of one per repeat.
        let mut seen: HashSet<&str> = HashSet::new();

        for mentioned_address in mentions {
            if !seen.insert(mentioned_address.as_str()) {
                continue;
            }
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

        // WebSocket broadcast. This fans out to ALL connected WS clients (they
        // filter by recipient client-side), so for PRIVATE channels redact the
        // preview — otherwise a private channel's plaintext would leak to every
        // client. The full preview is still delivered privately to the recipient
        // via the per-recipient persisted notification above (authenticated
        // GET /api/v1/notifications). Public-channel previews are world-readable.
        // (Follow-up: per-recipient WS delivery would also hide the mention
        // metadata — author/channel — not just the preview.)
        let broadcast_notification = match notification.channel_id {
            Some(cid) if !self.channel_is_public(cid) => {
                let mut redacted = notification.clone();
                redacted.preview = String::new();
                redacted
            }
            _ => notification.clone(),
        };
        let ws_msg = serde_json::json!({
            "type": "notification",
            "mention": broadcast_notification,
        });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            // Mention notifications keep the legacy all-clients fan-out (clients
            // filter to the mentioned wallet; private-channel previews are
            // redacted above). See the follow-up note re: per-recipient delivery.
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Everyone,
                json,
            }));
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
