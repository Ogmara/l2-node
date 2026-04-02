//! Message routing pipeline (spec 3.4).
//!
//! Processing steps for every incoming message:
//! 1. Deserialize (MessagePack)
//! 2. Validate envelope (version, msg_type, msg_id, signature length)
//! 3. Check duplicate (msg_id lookup in storage)
//! 4. Verify signature (Ed25519, check delegation if needed)
//! 5. Verify timestamp (±5 min drift)
//! 6. Check rate limits (per-user counters)
//! 7. Validate payload (type-specific rules)
//! 8. Store message (RocksDB)
//! 9. Forward to GossipSub (relay to peers)
//! 10. Notify local clients (WebSocket push)
//! 11. Check mention notifications

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tracing::{debug, warn};

use crate::crypto;
use crate::crypto::signing;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;
use crate::storage::schema;
use ed25519_dalek;

use super::envelope::{Envelope, MAX_TIMESTAMP_DRIFT_MS};
use super::types::*;
use super::validation;

/// Per-user, per-category rate limit counters.
struct RateLimitEntry {
    /// Message count in the current window.
    count: u32,
    /// Window start (Unix ms).
    window_start: u64,
}

/// Rate limit categories with per-spec limits (spec Part 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateCategory {
    ChatMessages,      // 30 per minute
    NewsPost,          // 5 per hour
    Reaction,          // 60 per minute (chat + news reactions)
    Repost,            // 10 per hour
    ChannelAdmin,      // 30 per hour (kick/ban/mute)
    ModeratorChange,   // 10 per day
    ChannelInvite,     // 20 per hour
    PinUnpin,          // 20 per hour
    Other,             // fallback: 100 per minute
}

impl RateCategory {
    /// (max_count, window_ms) per category.
    fn limits(self) -> (u32, u64) {
        match self {
            Self::ChatMessages => (30, 60_000),
            Self::NewsPost => (5, 3_600_000),
            Self::Reaction => (60, 60_000),
            Self::Repost => (10, 3_600_000),
            Self::ChannelAdmin => (30, 3_600_000),
            Self::ModeratorChange => (10, 86_400_000),
            Self::ChannelInvite => (20, 3_600_000),
            Self::PinUnpin => (20, 3_600_000),
            Self::Other => (100, 60_000),
        }
    }

    fn from_msg_type(msg_type: MessageType) -> Self {
        match msg_type {
            MessageType::ChatMessage | MessageType::ChatEdit | MessageType::ChatDelete
            | MessageType::DirectMessage | MessageType::DirectMessageEdit
            | MessageType::DirectMessageDelete => Self::ChatMessages,
            MessageType::NewsPost | MessageType::NewsEdit | MessageType::NewsDelete
            | MessageType::NewsComment => Self::NewsPost,
            MessageType::ChatReaction | MessageType::DirectMessageReaction
            | MessageType::NewsReaction => Self::Reaction,
            MessageType::NewsRepost => Self::Repost,
            MessageType::ChannelKick | MessageType::ChannelBan
            | MessageType::ChannelUnban | MessageType::ChannelMute => Self::ChannelAdmin,
            MessageType::ChannelAddModerator | MessageType::ChannelRemoveModerator => Self::ModeratorChange,
            MessageType::ChannelInvite => Self::ChannelInvite,
            MessageType::ChannelPinMessage | MessageType::ChannelUnpinMessage => Self::PinUnpin,
            _ => Self::Other,
        }
    }
}

/// The message router processes incoming messages through the full pipeline.
pub struct MessageRouter {
    storage: Storage,
    /// Device-to-wallet identity resolver.
    identity: IdentityResolver,
    /// Per-user, per-category rate limit counters: "(address:category)" → entry.
    rate_limits: DashMap<String, RateLimitEntry>,
}

/// Result of processing a message through the router.
#[derive(Debug)]
pub enum RouteResult {
    /// Message accepted, stored, and should be relayed.
    Accepted {
        msg_id: [u8; 32],
        msg_type: MessageType,
    },
    /// Message is a duplicate (already stored).
    Duplicate,
    /// Message rejected with reason.
    Rejected(String),
}

impl MessageRouter {
    pub fn new(storage: Storage, identity: IdentityResolver, _rate_limit_per_minute: u32) -> Self {
        Self {
            storage,
            identity,
            rate_limits: DashMap::new(),
        }
    }

    /// Process a raw message through the full pipeline.
    ///
    /// Returns the routing result indicating whether the message was
    /// accepted, is a duplicate, or was rejected.
    pub fn process_message(&self, raw_bytes: &[u8]) -> RouteResult {
        // Step 1: Deserialize
        let envelope: Envelope = match rmp_serde::from_slice(raw_bytes) {
            Ok(env) => env,
            Err(e) => return RouteResult::Rejected(format!("deserialization failed: {}", e)),
        };

        // Step 2: Validate envelope structure
        if let Err(e) = envelope.validate_structure() {
            return RouteResult::Rejected(format!("invalid envelope: {}", e));
        }

        // Step 3: Check duplicate
        match self.storage.message_exists(&envelope.msg_id) {
            Ok(true) => return RouteResult::Duplicate,
            Ok(false) => {}
            Err(e) => return RouteResult::Rejected(format!("storage error: {}", e)),
        }

        // Step 4a: Verify msg_id computation
        if let Err(e) = self.verify_msg_id(&envelope) {
            return RouteResult::Rejected(format!("invalid msg_id: {}", e));
        }

        // Step 4b: Verify Ed25519 signature (against device/signing key)
        if let Err(e) = self.verify_signature(&envelope) {
            return RouteResult::Rejected(format!("signature verification failed: {}", e));
        }

        // Step 4c: Resolve device key → wallet address for all subsequent operations.
        // Signature verification used envelope.author (device key) directly.
        // From here on, `resolved_author` is the wallet identity used for
        // storage, indexing, rate limiting, and authorization.
        let resolved_author = match self.identity.resolve(&envelope.author) {
            Ok(addr) => addr,
            Err(e) => return RouteResult::Rejected(format!("identity resolution failed: {}", e)),
        };

        // Step 5: Verify timestamp (±5 min drift)
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if !envelope.is_timestamp_valid(now_ms) {
            return RouteResult::Rejected(format!(
                "timestamp drift too large: {} vs now {}",
                envelope.timestamp, now_ms
            ));
        }

        // Step 6: Rate limit by wallet address (not device key)
        if envelope.msg_type.requires_registration() {
            let category = RateCategory::from_msg_type(envelope.msg_type);
            if self.is_rate_limited(&resolved_author, category, now_ms) {
                return RouteResult::Rejected(format!("rate limited ({:?})", category));
            }
        }

        // Step 7: Validate payload (type-specific rules — uses resolved author)
        if let Err(e) = self.validate_payload(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("payload validation failed: {}", e));
        }

        // Step 7b: Check ban enforcement — banned users cannot post to channels
        if let Err(e) = self.check_channel_ban(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("banned: {}", e));
        }

        // Step 7c: Authorize channel admin operations
        if let Err(e) = self.authorize_channel_action(&envelope, &resolved_author) {
            return RouteResult::Rejected(format!("unauthorized: {}", e));
        }

        // Step 8: Store message (atomically increments total_messages counter)
        if let Err(e) = self.storage.store_message(&envelope.msg_id, raw_bytes) {
            return RouteResult::Rejected(format!("storage error: {}", e));
        }

        // Step 8b: Update indexes using resolved wallet address
        if let Err(e) = self.update_indexes(&envelope, &resolved_author) {
            warn!(error = %e, "Failed to update indexes (message still stored)");
        }

        debug!(
            msg_id = %hex::encode(envelope.msg_id),
            msg_type = ?envelope.msg_type,
            signing_key = %envelope.author,
            author = %resolved_author,
            "Message routed successfully"
        );

        // Steps 9-11 (relay, WS push, notifications) are handled by the caller
        RouteResult::Accepted {
            msg_id: envelope.msg_id,
            msg_type: envelope.msg_type,
        }
    }

    /// Verify the Ed25519 signature on the envelope.
    ///
    /// Supports both Ogmara protocol signing (delegated/device keys) and
    /// Klever message signing (wallet keys). Tries Ogmara format first.
    fn verify_signature(&self, envelope: &Envelope) -> Result<()> {
        let verifying_key = crypto::address_to_verifying_key(&envelope.author)
            .map_err(|e| anyhow::anyhow!("invalid author key: {}", e))?;

        let signature = ed25519_dalek::Signature::from_slice(&envelope.signature)
            .map_err(|e| anyhow::anyhow!("invalid signature bytes: {}", e))?;

        // Try Ogmara protocol format first (most common for L2 messages)
        let ogmara_result = signing::verify_ogmara_message(
            &verifying_key,
            envelope.version,
            envelope.msg_type_u8(),
            &envelope.msg_id,
            envelope.timestamp,
            &envelope.payload,
            &signature,
        );

        if ogmara_result.is_ok() {
            return Ok(());
        }

        // Fall back to Klever message format (for wallet-signed messages)
        let signed_bytes = signing::ogmara_signed_bytes(
            envelope.version,
            envelope.msg_type_u8(),
            &envelope.msg_id,
            envelope.timestamp,
            &envelope.payload,
        );
        let klever_result = signing::verify_klever_message(
            &verifying_key,
            &signed_bytes,
            &signature,
        );

        klever_result.map_err(|_| anyhow::anyhow!("signature verification failed for both formats"))
    }

    /// Verify that the msg_id matches Keccak-256(author + payload + timestamp).
    fn verify_msg_id(&self, envelope: &Envelope) -> Result<()> {
        let author_bytes = crypto::address_to_pubkey_bytes(&envelope.author)
            .map_err(|e| anyhow::anyhow!("invalid author address: {}", e))?;

        let computed = crypto::compute_msg_id(
            &author_bytes,
            &envelope.payload,
            envelope.timestamp,
        );

        if computed != envelope.msg_id {
            anyhow::bail!(
                "msg_id mismatch: expected {}, got {}",
                hex::encode(computed),
                hex::encode(envelope.msg_id)
            );
        }
        Ok(())
    }

    /// Check if a user is rate-limited for a specific action category.
    fn is_rate_limited(&self, author: &str, category: RateCategory, now_ms: u64) -> bool {
        let (max_count, window_ms) = category.limits();
        let key = format!("{}:{:?}", author, category);

        let mut entry = self
            .rate_limits
            .entry(key)
            .or_insert(RateLimitEntry {
                count: 0,
                window_start: now_ms,
            });

        // Reset window if expired
        if now_ms.saturating_sub(entry.window_start) > window_ms {
            entry.count = 0;
            entry.window_start = now_ms;
        }

        entry.count = entry.count.saturating_add(1);
        entry.count > max_count
    }

    /// Evict expired rate limit entries to prevent unbounded memory growth.
    /// Should be called periodically (e.g., every few minutes).
    pub fn cleanup_rate_limits(&self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Use the largest window (86_400_000ms = 1 day) as the eviction threshold
        self.rate_limits.retain(|_, entry| {
            now_ms.saturating_sub(entry.window_start) < 86_400_000
        });
    }

    /// Validate the payload based on message type.
    fn validate_payload(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), validation::ValidationError> {
        match deserialize_payload(envelope.msg_type, &envelope.payload) {
            Ok(payload) => match payload {
                DeserializedPayload::ChatMessage(ref p) => validation::validate_chat_message(p),
                DeserializedPayload::NewsPost(ref p) => validation::validate_news_post(p),
                DeserializedPayload::NewsComment(ref p) => validation::validate_news_comment(p),
                DeserializedPayload::ChannelCreate(ref p) => validation::validate_channel_create(p),
                DeserializedPayload::ChannelUpdate(ref p) => validation::validate_channel_update(p),
                DeserializedPayload::ProfileUpdate(ref p) => validation::validate_profile_update(p),
                DeserializedPayload::Edit(ref p) => validation::validate_edit(p),
                DeserializedPayload::Reaction(ref p) => validation::validate_reaction(p),
                DeserializedPayload::Report(ref p) => validation::validate_report(p),
                DeserializedPayload::DeviceDelegation(ref p) => {
                    validation::validate_device_delegation(p)
                }
                DeserializedPayload::Follow(ref p) => {
                    validation::validate_follow(resolved_author, p)
                }
                DeserializedPayload::Unfollow(ref p) => {
                    validation::validate_unfollow(resolved_author, p)
                }
                DeserializedPayload::ChannelAddModerator(ref p) => {
                    validation::validate_channel_add_moderator(p)
                }
                DeserializedPayload::ChannelRemoveModerator(ref p) => {
                    validation::validate_channel_remove_moderator(p)
                }
                DeserializedPayload::ChannelKick(ref p) => {
                    validation::validate_channel_kick(p)
                }
                DeserializedPayload::ChannelBan(ref p) => {
                    validation::validate_channel_ban(p)
                }
                DeserializedPayload::ChannelUnban(ref p) => {
                    validation::validate_channel_unban(p)
                }
                DeserializedPayload::ChannelPinMessage(ref p) => {
                    validation::validate_channel_pin(p)
                }
                DeserializedPayload::ChannelUnpinMessage(ref p) => {
                    validation::validate_channel_unpin(p)
                }
                DeserializedPayload::ChannelInvite(ref p) => {
                    validation::validate_channel_invite(p)
                }
                DeserializedPayload::NewsRepost(ref p) => {
                    validation::validate_news_repost(resolved_author, p)
                }
                DeserializedPayload::ContentRequest(ref p) => {
                    validation::validate_content_request(p)
                }
                DeserializedPayload::DirectMessage(ref p) => {
                    validation::validate_direct_message(resolved_author, p)
                }
                // Types with no specific validation rules (NewsReaction uses existing validate_reaction)
                _ => Ok(()),
            },
            Err(e) => Err(validation::ValidationError(format!(
                "payload deserialization failed: {}",
                e
            ))),
        }
    }

    /// Check if the author is banned from the target channel.
    /// Rejects channel-scoped messages from banned users.
    /// Also enforces ban expiration: expired bans are cleaned up on read.
    fn check_channel_ban(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), String> {
        let channel_id = match self.extract_channel_id(envelope) {
            Some(id) => id,
            None => return Ok(()), // not a channel-scoped message
        };

        let ban_key = schema::encode_channel_ban_key(channel_id, resolved_author);
        match self.storage.get_cf(schema::cf::CHANNEL_BANS, &ban_key) {
            Ok(Some(data)) => {
                // Check if ban has expired
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
                    let duration = record.get("duration_secs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if duration > 0 {
                        let banned_at = record.get("banned_at")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let elapsed_secs = (now_ms.saturating_sub(banned_at)) / 1000;
                        if elapsed_secs >= duration {
                            // Ban expired — clean up and allow
                            let _ = self.storage.delete_cf(schema::cf::CHANNEL_BANS, &ban_key);
                            return Ok(());
                        }
                    }
                }
                Err(format!("user is banned from channel {}", channel_id))
            }
            _ => Ok(()),
        }
    }

    /// Authorize channel admin operations per spec section 2.6.
    /// Verifies the sender has the required role/permissions.
    /// Uses `resolved_author` (wallet address) for all permission checks.
    fn authorize_channel_action(&self, envelope: &Envelope, resolved_author: &str) -> Result<(), String> {
        match envelope.msg_type {
            // Creator-only actions
            MessageType::ChannelAddModerator | MessageType::ChannelRemoveModerator => {
                let channel_id = self.extract_channel_id(envelope).unwrap_or(0);
                if !self.is_channel_creator(channel_id, resolved_author)? {
                    return Err("only the channel creator can manage moderators".into());
                }
                // Cannot remove self (creator)
                if envelope.msg_type == MessageType::ChannelRemoveModerator {
                    if let Ok(p) = rmp_serde::from_slice::<ChannelRemoveModeratorPayload>(&envelope.payload) {
                        if p.target_user == resolved_author {
                            return Err("cannot remove yourself as moderator".into());
                        }
                    }
                }
                Ok(())
            }
            // Creator + mods with can_kick
            MessageType::ChannelKick => {
                let channel_id = self.extract_channel_id(envelope).unwrap_or(0);
                if let Ok(p) = rmp_serde::from_slice::<ChannelKickPayload>(&envelope.payload) {
                    // Cannot kick the creator
                    if self.is_channel_creator(channel_id, &p.target_user)? {
                        return Err("cannot kick the channel creator".into());
                    }
                }
                self.require_mod_permission(channel_id, resolved_author, "can_kick")
            }
            // Creator + mods with can_ban
            MessageType::ChannelBan => {
                let channel_id = self.extract_channel_id(envelope).unwrap_or(0);
                if let Ok(p) = rmp_serde::from_slice::<ChannelBanPayload>(&envelope.payload) {
                    if self.is_channel_creator(channel_id, &p.target_user)? {
                        return Err("cannot ban the channel creator".into());
                    }
                }
                self.require_mod_permission(channel_id, resolved_author, "can_ban")
            }
            MessageType::ChannelUnban => {
                let channel_id = self.extract_channel_id(envelope).unwrap_or(0);
                self.require_mod_permission(channel_id, resolved_author, "can_ban")
            }
            // Creator + mods with can_pin
            MessageType::ChannelPinMessage | MessageType::ChannelUnpinMessage => {
                let channel_id = self.extract_channel_id(envelope).unwrap_or(0);
                self.require_mod_permission(channel_id, resolved_author, "can_pin")
            }
            // Creator + any moderator
            MessageType::ChannelInvite => {
                let channel_id = self.extract_channel_id(envelope).unwrap_or(0);
                if self.is_channel_creator(channel_id, resolved_author)? {
                    return Ok(());
                }
                if self.storage.is_channel_moderator(channel_id, resolved_author)
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                Err("only creator or moderators can invite users".into())
            }
            _ => Ok(()),
        }
    }

    /// Extract the channel_id from channel-scoped message payloads.
    fn extract_channel_id(&self, envelope: &Envelope) -> Option<u64> {
        match envelope.msg_type {
            MessageType::ChatMessage => {
                rmp_serde::from_slice::<ChatMessagePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChatReaction => {
                rmp_serde::from_slice::<ReactionPayload>(&envelope.payload)
                    .ok().and_then(|p| p.channel_id)
            }
            MessageType::ChannelAddModerator => {
                rmp_serde::from_slice::<ChannelAddModeratorPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelRemoveModerator => {
                rmp_serde::from_slice::<ChannelRemoveModeratorPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelKick => {
                rmp_serde::from_slice::<ChannelKickPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelBan => {
                rmp_serde::from_slice::<ChannelBanPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelUnban => {
                rmp_serde::from_slice::<ChannelUnbanPayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelPinMessage => {
                rmp_serde::from_slice::<ChannelPinMessagePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelUnpinMessage => {
                rmp_serde::from_slice::<ChannelUnpinMessagePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelInvite => {
                rmp_serde::from_slice::<ChannelInvitePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            MessageType::ChannelUpdate => {
                rmp_serde::from_slice::<ChannelUpdatePayload>(&envelope.payload)
                    .ok().map(|p| p.channel_id)
            }
            _ => None,
        }
    }

    /// Check if address is the channel creator by looking up channel metadata.
    fn is_channel_creator(&self, channel_id: u64, address: &str) -> Result<bool, String> {
        match self.storage.get_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes()) {
            Ok(Some(data)) => {
                if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                    Ok(meta.get("creator").and_then(|v| v.as_str()) == Some(address))
                } else {
                    Ok(false)
                }
            }
            Ok(None) => Err(format!("channel {} not found", channel_id)),
            Err(e) => Err(format!("storage error: {}", e)),
        }
    }

    /// Check if the user is the creator or a moderator with the required permission.
    fn require_mod_permission(
        &self,
        channel_id: u64,
        author: &str,
        permission: &str,
    ) -> Result<(), String> {
        // Creator has all permissions
        if self.is_channel_creator(channel_id, author)? {
            return Ok(());
        }

        // Check moderator permissions
        let mod_key = schema::encode_channel_moderator_key(channel_id, author);
        match self.storage.get_cf(schema::cf::CHANNEL_MODERATORS, &mod_key) {
            Ok(Some(data)) => {
                if let Ok(perms) = serde_json::from_slice::<serde_json::Value>(&data) {
                    let has_perm = perms.get(permission)
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if has_perm {
                        Ok(())
                    } else {
                        Err(format!("moderator lacks '{}' permission", permission))
                    }
                } else {
                    Err("corrupt moderator permissions".into())
                }
            }
            Ok(None) => Err("not a moderator of this channel".into()),
            Err(e) => Err(format!("storage error: {}", e)),
        }
    }

    /// Add a member to a channel (idempotent — skips if already member).
    /// Updates the member_count in channel metadata.
    fn add_channel_member(&self, channel_id: u64, address: &str, timestamp: u64, role: &str) -> Result<bool> {
        // Check channel exists
        let channel_key = channel_id.to_be_bytes();
        let channel_data = self.storage.get_cf(schema::cf::CHANNELS, &channel_key)?;
        if channel_data.is_none() {
            return Ok(false); // channel doesn't exist
        }

        let member_key = schema::encode_channel_member_key(channel_id, address);
        if self.storage.get_cf(schema::cf::CHANNEL_MEMBERS, &member_key)?.is_some() {
            return Ok(false); // already a member
        }

        let record = serde_json::json!({
            "joined_at": timestamp,
            "role": role,
        });
        let record_bytes = serde_json::to_vec(&record)
            .context("serializing member record")?;
        self.storage.put_cf(schema::cf::CHANNEL_MEMBERS, &member_key, &record_bytes)?;

        // Update member_count in channel metadata
        if let Some(data) = channel_data {
            if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                let count = meta.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0);
                meta["member_count"] = serde_json::json!(count + 1);
                if let Ok(bytes) = serde_json::to_vec(&meta) {
                    let _ = self.storage.put_cf(schema::cf::CHANNELS, &channel_key, &bytes);
                }
            }
        }

        Ok(true)
    }

    /// Remove a member from a channel. Updates member_count.
    fn remove_channel_member(&self, channel_id: u64, address: &str) -> Result<()> {
        let member_key = schema::encode_channel_member_key(channel_id, address);
        self.storage.delete_cf(schema::cf::CHANNEL_MEMBERS, &member_key)?;

        // Decrement member_count in channel metadata
        let channel_key = channel_id.to_be_bytes();
        if let Some(data) = self.storage.get_cf(schema::cf::CHANNELS, &channel_key)? {
            if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                let count = meta.get("member_count").and_then(|v| v.as_u64()).unwrap_or(1);
                meta["member_count"] = serde_json::json!(count.saturating_sub(1));
                if let Ok(bytes) = serde_json::to_vec(&meta) {
                    let _ = self.storage.put_cf(schema::cf::CHANNELS, &channel_key, &bytes);
                }
            }
        }

        Ok(())
    }

    /// Update storage indexes based on message type.
    fn update_indexes(&self, envelope: &Envelope, resolved_author: &str) -> Result<()> {
        match envelope.msg_type {
            MessageType::ChatMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChatMessagePayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_msg_key(
                        payload.channel_id,
                        envelope.lamport_ts,
                        &envelope.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::CHANNEL_MSGS, &key, &[])?;
                    self.storage
                        .increment_stat(schema::state_keys::TOTAL_CHANNEL_MESSAGES)?;

                    // Auto-add author as channel member on first message
                    let _ = self.add_channel_member(
                        payload.channel_id,
                        resolved_author,
                        envelope.timestamp,
                        "member",
                    );
                }
            }
            MessageType::DirectMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<DirectMessagePayload>(&envelope.payload)
                {
                    // 1. Index the message by conversation
                    let msg_key = schema::encode_dm_msg_key(
                        &payload.conversation_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::DM_MESSAGES, &msg_key, &[])?;

                    // 2. Update conversation index for BOTH participants
                    // Sender's entry: value = recipient address (the peer)
                    let sender_conv_key = schema::encode_dm_conversation_key(
                        resolved_author.as_bytes(),
                        envelope.timestamp,
                        &payload.conversation_id,
                    );
                    self.storage.put_cf(
                        schema::cf::DM_CONVERSATIONS,
                        &sender_conv_key,
                        payload.recipient.as_bytes(),
                    )?;

                    // Recipient's entry: value = sender address (the peer)
                    let recipient_conv_key = schema::encode_dm_conversation_key(
                        payload.recipient.as_bytes(),
                        envelope.timestamp,
                        &payload.conversation_id,
                    );
                    self.storage.put_cf(
                        schema::cf::DM_CONVERSATIONS,
                        &recipient_conv_key,
                        resolved_author.as_bytes(),
                    )?;
                }
            }
            MessageType::NewsPost => {
                let key =
                    schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                self.storage
                    .put_cf(schema::cf::NEWS_FEED, &key, &[])?;
                self.storage
                    .increment_stat(schema::state_keys::TOTAL_NEWS_MESSAGES)?;

                // Index by author (resolved wallet address)
                let author_key = schema::encode_news_by_author_key(
                    resolved_author,
                    envelope.timestamp,
                    &envelope.msg_id,
                );
                self.storage
                    .put_cf(schema::cf::NEWS_BY_AUTHOR, &author_key, &[])?;

                // Index by tags
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsPostPayload>(&envelope.payload)
                {
                    for tag in &payload.tags {
                        let tag_key = schema::encode_news_by_tag_key(
                            tag,
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.storage
                            .put_cf(schema::cf::NEWS_BY_TAG, &tag_key, &[])?;
                    }
                }
            }
            MessageType::Follow => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<FollowPayload>(&envelope.payload)
                {
                    self.storage.follow(resolved_author, &payload.target)?;
                }
            }
            MessageType::Unfollow => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<UnfollowPayload>(&envelope.payload)
                {
                    self.storage.unfollow(resolved_author, &payload.target)?;
                }
            }
            MessageType::ChannelCreate => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelCreatePayload>(&envelope.payload)
                {
                    // Store channel metadata (member_count starts at 0, add_channel_member increments)
                    let meta = serde_json::json!({
                        "channel_id": payload.channel_id,
                        "slug": payload.slug,
                        "channel_type": payload.channel_type,
                        "creator": resolved_author,
                        "created_at": envelope.timestamp,
                        "display_name": payload.display_name,
                        "description": payload.description,
                        "member_count": 0,
                    });
                    let meta_bytes = serde_json::to_vec(&meta)
                        .context("serializing channel metadata")?;
                    self.storage.put_cf(
                        schema::cf::CHANNELS,
                        &payload.channel_id.to_be_bytes(),
                        &meta_bytes,
                    )?;
                    self.storage
                        .increment_stat(schema::state_keys::TOTAL_CHANNELS)?;

                    // Add creator as first member (increments member_count to 1)
                    let _ = self.add_channel_member(
                        payload.channel_id,
                        resolved_author,
                        envelope.timestamp,
                        "creator",
                    );
                }
            }
            MessageType::ChannelJoin => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelJoinPayload>(&envelope.payload)
                {
                    // Validates channel exists and is idempotent (skips if already member)
                    let _ = self.add_channel_member(
                        payload.channel_id,
                        resolved_author,
                        envelope.timestamp,
                        "member",
                    );
                }
            }
            // TODO: Add ChannelDelete support — when creator deletes a channel:
            // 1. Remove all members from CHANNEL_MEMBERS
            // 2. Remove channel metadata from CHANNELS
            // 3. Decrement TOTAL_CHANNELS
            // 4. Optionally: remove all channel messages from CHANNEL_MSGS
            // Requires adding MessageType::ChannelDelete (or use ChannelUpdate with deleted flag)
            MessageType::ChannelLeave => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelLeavePayload>(&envelope.payload)
                {
                    self.remove_channel_member(payload.channel_id, resolved_author)?;
                }
            }
            MessageType::NewsComment => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsCommentPayload>(&envelope.payload)
                {
                    // Index under parent post for threaded retrieval
                    let comment_key = schema::encode_news_comment_key(
                        &payload.post_id,
                        envelope.timestamp,
                        &envelope.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::NEWS_COMMENTS, &comment_key, &[])?;

                    // Also index in NEWS_FEED so comments appear in the timeline
                    let feed_key =
                        schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                    self.storage
                        .put_cf(schema::cf::NEWS_FEED, &feed_key, &[])?;
                }
            }
            MessageType::NewsReaction => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ReactionPayload>(&envelope.payload)
                {
                    self.storage.toggle_news_reaction(
                        &payload.target_id,
                        &payload.emoji,
                        resolved_author,
                        payload.remove,
                    )?;
                }
            }
            MessageType::NewsRepost => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<NewsRepostPayload>(&envelope.payload)
                {
                    self.storage.add_repost(
                        &payload.original_id,
                        resolved_author,
                        &envelope.msg_id,
                    )?;
                    // Also index the repost in the global news feed
                    let key =
                        schema::encode_news_key(envelope.timestamp, &envelope.msg_id);
                    self.storage
                        .put_cf(schema::cf::NEWS_FEED, &key, &[])?;
                    self.storage
                        .increment_stat(schema::state_keys::TOTAL_NEWS_MESSAGES)?;
                }
            }
            MessageType::ChannelAddModerator => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelAddModeratorPayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_moderator_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    let perms = serde_json::to_vec(&payload.permissions)
                        .context("serializing moderator permissions")?;
                    self.storage
                        .put_cf(schema::cf::CHANNEL_MODERATORS, &key, &perms)?;
                }
            }
            MessageType::ChannelRemoveModerator => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelRemoveModeratorPayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_moderator_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    self.storage
                        .delete_cf(schema::cf::CHANNEL_MODERATORS, &key)?;
                }
            }
            MessageType::ChannelKick => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelKickPayload>(&envelope.payload)
                {
                    self.remove_channel_member(payload.channel_id, &payload.target_user)?;
                }
            }
            MessageType::ChannelBan => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelBanPayload>(&envelope.payload)
                {
                    // Remove from members (updates member_count)
                    self.remove_channel_member(payload.channel_id, &payload.target_user)?;

                    // Add to bans
                    let ban_key = schema::encode_channel_ban_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    let record = serde_json::json!({
                        "reason": payload.reason,
                        "duration_secs": payload.duration_secs,
                        "banned_at": envelope.timestamp,
                        "banned_by": resolved_author,
                    });
                    let record_bytes = serde_json::to_vec(&record)
                        .context("serializing ban record")?;
                    self.storage.put_cf(
                        schema::cf::CHANNEL_BANS,
                        &ban_key,
                        &record_bytes,
                    )?;
                }
            }
            MessageType::ChannelUnban => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelUnbanPayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_ban_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    self.storage
                        .delete_cf(schema::cf::CHANNEL_BANS, &key)?;
                }
            }
            MessageType::ChannelPinMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelPinMessagePayload>(&envelope.payload)
                {
                    let pin_count = self.storage.get_pin_count(payload.channel_id)?;
                    // If max 10 pins, FIFO — remove oldest if at limit
                    if pin_count >= 10 {
                        let prefix = payload.channel_id.to_be_bytes();
                        if let Ok(entries) = self.storage.prefix_iter_cf(
                            schema::cf::CHANNEL_PINS,
                            &prefix,
                            1,
                        ) {
                            if let Some((oldest_key, _)) = entries.first() {
                                self.storage
                                    .delete_cf(schema::cf::CHANNEL_PINS, oldest_key)?;
                            }
                        }
                    }
                    // Use monotonically increasing sequence to avoid pin_order collisions
                    let seq_key = format!("pin_seq:{}", payload.channel_id);
                    let next_seq = match self.storage.get_cf(schema::cf::NODE_STATE, seq_key.as_bytes())? {
                        Some(bytes) if bytes.len() == 4 => {
                            u32::from_be_bytes(bytes.try_into().unwrap_or([0; 4])) + 1
                        }
                        _ => 0,
                    };
                    self.storage.put_cf(schema::cf::NODE_STATE, seq_key.as_bytes(), &next_seq.to_be_bytes())?;
                    let key = schema::encode_channel_pin_key(
                        payload.channel_id,
                        next_seq,
                        &payload.msg_id,
                    );
                    self.storage
                        .put_cf(schema::cf::CHANNEL_PINS, &key, &[])?;
                }
            }
            MessageType::ChannelUnpinMessage => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelUnpinMessagePayload>(&envelope.payload)
                {
                    // Scan for the pinned msg_id and remove it
                    let prefix = payload.channel_id.to_be_bytes();
                    if let Ok(entries) = self.storage.prefix_iter_cf(
                        schema::cf::CHANNEL_PINS,
                        &prefix,
                        10,
                    ) {
                        for (key, _) in entries {
                            if key.len() >= 44 {
                                let stored_id: [u8; 32] =
                                    key[12..44].try_into().unwrap_or([0u8; 32]);
                                if stored_id == payload.msg_id {
                                    self.storage
                                        .delete_cf(schema::cf::CHANNEL_PINS, &key)?;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            MessageType::ChannelInvite => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelInvitePayload>(&envelope.payload)
                {
                    let key = schema::encode_channel_invite_key(
                        payload.channel_id,
                        &payload.target_user,
                    );
                    let record = serde_json::json!({
                        "invited_by": resolved_author,
                        "timestamp": envelope.timestamp,
                    });
                    let record_bytes = serde_json::to_vec(&record)
                        .context("serializing invite record")?;
                    self.storage.put_cf(
                        schema::cf::CHANNEL_INVITES,
                        &key,
                        &record_bytes,
                    )?;
                }
            }
            MessageType::ProfileUpdate => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ProfileUpdatePayload>(&envelope.payload)
                {
                    let is_new = !self
                        .storage
                        .exists_cf(schema::cf::USERS, resolved_author.as_bytes())?;

                    // Load existing user record or create a new one
                    let mut record = match self
                        .storage
                        .get_cf(schema::cf::USERS, resolved_author.as_bytes())?
                    {
                        Some(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                            .unwrap_or_else(|_| serde_json::json!({})),
                        None => serde_json::json!({
                            "address": resolved_author,
                            "public_key": "",
                            "registered_at": envelope.timestamp,
                        }),
                    };

                    // Merge profile fields
                    if let serde_json::Value::Object(ref mut map) = record {
                        if let Some(name) = &payload.display_name {
                            map.insert("display_name".into(), serde_json::json!(name));
                        }
                        if let Some(avatar) = &payload.avatar_cid {
                            map.insert("avatar_cid".into(), serde_json::json!(avatar));
                        }
                        if let Some(bio) = &payload.bio {
                            map.insert("bio".into(), serde_json::json!(bio));
                        }
                    }

                    let bytes = serde_json::to_vec(&record)
                        .context("serializing user record")?;
                    self.storage.put_cf(
                        schema::cf::USERS,
                        resolved_author.as_bytes(),
                        &bytes,
                    )?;

                    if is_new {
                        self.storage
                            .increment_stat(schema::state_keys::TOTAL_USERS)?;
                    }

                    tracing::info!(address = %resolved_author, "Profile updated");
                }
            }
            _ => {}
        }

        Ok(())
    }
}
