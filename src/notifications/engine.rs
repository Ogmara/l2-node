//! Notification engine — mention detection, routing, and push gateway.
//!
//! Parses the `mentions` field in chat messages, matches against locally
//! connected users, and delivers notifications via WebSocket and push gateway.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use crate::messages::envelope::Envelope;
use crate::messages::types::{
    ChannelInvitePayload, ChatMessagePayload, DeletePayload, DirectMessagePayload, EditPayload,
    MessageType, NewsCommentPayload, ReactionPayload, SettingsSyncPayload,
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
    /// Anchor node API endpoint (`channel_invite` only) — tells the
    /// recipient's client where a private channel it doesn't know locally
    /// is hosted, so it can `federate_channel` before joining.
    pub anchor_node: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    Mention,
    Reply,
    Dm,
    /// Someone (channel creator or moderator) invited this wallet to a
    /// channel. The only notification type NOT gated on the recipient being
    /// currently connected — see the `ChannelInvite` arm in `process()`.
    ChannelInvite,
}

/// The notification engine processes messages and generates notifications.
///
/// Thread-safe: can be shared across tasks via `Arc<NotificationEngine>`.
/// Upper bound on how many followers receive the live WS push for a
/// `Visibility::Followers` news post. The audience list is materialised into a
/// single broadcast frame, so an uncapped follower count would let one popular
/// author build an arbitrarily large one. Followers beyond the cap still see the
/// post on their next refetch — the same guarantee they had before live news
/// delivery existed.
const FOLLOWER_FANOUT_CAP: usize = 512;

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
    /// Max stored notifications per target address, enforced at write
    /// time by evicting the oldest (audit final pre-mainnet W31 —
    /// Security Audit follow-up). See
    /// `Storage::store_notification_capped`'s doc comment for the full
    /// rationale. `0` = unlimited.
    max_stored_per_address: u64,
    /// Per-wallet coalescing for `bot_commands_changed` (spec 3 §4.3):
    /// `wallet -> last broadcast instant`.
    ///
    /// SIZE-BOUNDED at [`BOT_COALESCE_MAX_ENTRIES`] and pruned on insert — an
    /// unbounded per-address map is a memory-exhaustion vector, and this one is
    /// keyed by attacker-suppliable input.
    bot_broadcast_seen: Arc<RwLock<HashMap<String, Instant>>>,
    /// Which members of a channel are bots, for
    /// `GET /api/v1/channels/{channel_id}/bots` (spec 3 §4.1):
    /// `channel_id -> (computed_at, bot addresses)`.
    ///
    /// Caches only the ADDRESS LIST, never the rendered response. That choice
    /// does most of the work in this feature's cost model:
    ///
    /// - **Memory.** A rendered response is up to 50 bots x 32 commands x ~224 B;
    ///   held as `serde_json::Value` that is ~1 MB per channel, so a 1000-entry
    ///   cache would be ~1 GB of RSS. An address list is ~50 x 62 B, so the same
    ///   cache is a few MB.
    /// - **Freshness.** Commands are re-read from `USERS` on every request, so a
    ///   descriptor change is visible IMMEDIATELY without invalidating anything.
    ///   That is why a descriptor change does not flush this cache: it does not
    ///   need to, and a global flush would be a remotely-triggerable off-switch
    ///   for the only defense this endpoint has.
    /// - **Moderation.** Ban and mute are re-applied on every read, so a mute or
    ///   an unban takes effect at once rather than after the TTL.
    ///
    /// What it still saves is the expensive part: the up-to-5000-row
    /// `CHANNEL_MEMBERS` scan. Only a MEMBERSHIP change invalidates an entry, and
    /// that trigger is already keyed by channel.
    ///
    /// Lives on the engine rather than on `AppState` because invalidation must
    /// happen on BOTH ingestion paths — the API post path holds `AppState`, but
    /// the gossip receive path does not, and the engine is the one component
    /// both already share. Node-local derived state: never persisted, and so
    /// excluded from snapshot `DOMAIN_CFS` by construction.
    /// `channel_id -> (computed_at, scan_was_capped, bot addresses)`.
    ///
    /// `scan_was_capped` rides WITH the entry: it is a property of the scan that
    /// produced this list, so serving the list without it would report a
    /// truncated channel as complete for the whole TTL — the one thing the flag
    /// exists to prevent.
    channel_bots_cache: Arc<RwLock<HashMap<u64, (Instant, bool, Arc<Vec<String>>)>>>,
}

/// Minimum gap between two `bot_commands_changed` broadcasts for the SAME
/// wallet. The descriptor is public and the event carries no payload, so the
/// cost of a broadcast is fan-out, not disclosure — this bounds the fan-out.
const BOT_COALESCE_WINDOW: Duration = Duration::from_secs(10);
/// Hard cap on the coalescing map. On overflow the least-recently-broadcast
/// entries are dropped; losing one only means the next broadcast for that
/// wallet is not coalesced, which is safe.
const BOT_COALESCE_MAX_ENTRIES: usize = 10_000;

impl NotificationEngine {
    pub fn new(
        ws_broadcast: broadcast::Sender<Arc<WsOutbound>>,
        push_gateway_url: Option<String>,
        push_gateway_token: Option<String>,
        max_stored_per_address: u64,
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
            max_stored_per_address,
            bot_broadcast_seen: Arc::new(RwLock::new(HashMap::new())),
            channel_bots_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Storage-less engine for unit tests: exercises the pure audience/routing
    /// logic without a RocksDB fixture. `storage: None` is also the fail-closed
    /// path the visibility tests assert on.
    #[cfg(test)]
    pub fn new_for_test() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self::new(tx, None, None, 0)
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
            // Real-time delivery for the global news feed. None of the news
            // types had an arm here before 0.119.0, so the node never pushed a
            // news envelope over the WS at all: every client (web, desktop and
            // mobile alike) only picked up a new post when something forced a
            // REST refetch, which in practice meant navigating away from the
            // feed and back. Audience/visibility handling lives in
            // `broadcast_news`.
            MessageType::NewsPost => {
                self.broadcast_news(envelope, &[]);
            }
            MessageType::NewsEdit | MessageType::NewsDelete | MessageType::NewsRepost => {
                if let Some(target) = Self::news_target_id(envelope) {
                    self.broadcast_news(
                        envelope,
                        &[("target_msg_id", serde_json::json!(hex::encode(target)))],
                    );
                }
            }
            MessageType::NewsReaction => {
                if let Ok(p) = rmp_serde::from_slice::<ReactionPayload>(&envelope.payload) {
                    self.broadcast_news(
                        envelope,
                        &[
                            ("target_msg_id", serde_json::json!(hex::encode(p.target_id))),
                            ("emoji", serde_json::json!(p.emoji)),
                            ("remove", serde_json::json!(p.remove)),
                        ],
                    );
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
                    self.broadcast_news(
                        envelope,
                        &[(
                            "target_msg_id",
                            serde_json::json!(hex::encode(payload.post_id)),
                        )],
                    );
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
            MessageType::DirectMessageEdit | MessageType::DirectMessageDelete => {
                // Real-time delivery of DM edits/deletes to both participants so
                // they appear live (they also propagate via gossip + storage, but
                // without this only show on the recipient's next poll/reload).
                self.broadcast_dm_update(envelope);
            }
            MessageType::ChannelInvite => {
                if let Ok(payload) =
                    rmp_serde::from_slice::<ChannelInvitePayload>(&envelope.payload)
                {
                    let notification = Notification {
                        notification_type: NotificationType::ChannelInvite,
                        msg_id: hex::encode(envelope.msg_id),
                        author: envelope.author.clone(),
                        channel_id: Some(payload.channel_id),
                        channel_name: self.lookup_channel_name(payload.channel_id),
                        preview: String::new(),
                        timestamp: envelope.timestamp,
                        anchor_node: payload.anchor_node.clone(),
                    };
                    // Deliberately NOT gated on `local_users` (unlike
                    // check_mentions): the whole point is that the invited
                    // wallet discovers this LATER, via GET
                    // /api/v1/notifications, after being offline at invite
                    // time — a bot in particular is typically only
                    // intermittently running. Gating on "connected right now"
                    // would silently drop exactly the case this exists for.
                    // Rate-limited to 20/hour (RateLimits::flat(20, ...) for
                    // ChannelInvite), so unconditional persistence here adds
                    // no meaningful storage/DoS surface.
                    self.deliver(&payload.target_user, &envelope.msg_id, notification)
                        .await;
                }
            }
            MessageType::ChannelJoin | MessageType::ChannelLeave => {
                #[derive(serde::Deserialize)]
                struct E {
                    channel_id: u64,
                }
                if let Ok(p) = rmp_serde::from_slice::<E>(&envelope.payload) {
                    let member = self.resolve_member_wallet(&envelope.author);
                    let action = if envelope.msg_type == MessageType::ChannelJoin {
                        "join"
                    } else {
                        "leave"
                    };
                    // Membership decides who appears in this channel's bot list,
                    // so a join/leave invalidates it. Unlike a descriptor change
                    // this trigger IS keyed by channel, so it can be a point
                    // eviction rather than a full flush.
                    self.channel_bots_invalidate(p.channel_id).await;
                    self.broadcast_channel_membership_change(p.channel_id, action, &member);
                }
            }
            MessageType::ChannelKick | MessageType::ChannelBan => {
                #[derive(serde::Deserialize)]
                struct E {
                    channel_id: u64,
                    target_user: String,
                }
                if let Ok(p) = rmp_serde::from_slice::<E>(&envelope.payload) {
                    let action = if envelope.msg_type == MessageType::ChannelKick {
                        "kick"
                    } else {
                        "ban"
                    };
                    // A kicked or banned bot must drop out of this channel's
                    // picker immediately — the endpoint filters banned/muted bots,
                    // but a cached response predates the ban.
                    self.channel_bots_invalidate(p.channel_id).await;
                    self.broadcast_channel_membership_change(p.channel_id, action, &p.target_user);
                }
            }
            MessageType::ChannelDelete => {
                #[derive(serde::Deserialize)]
                struct E {
                    channel_id: u64,
                }
                if let Ok(p) = rmp_serde::from_slice::<E>(&envelope.payload) {
                    self.broadcast_channel_deleted(p.channel_id);
                }
            }
            MessageType::SettingsSync => {
                // Nudge the wallet's OTHER connected sessions to re-pull
                // `GET /api/v1/settings` and re-apply their synced objects
                // (`channelOrg`, `hiddenDms`, `topicGroups`). Runs on BOTH the
                // home node's API-post path AND the `topic_profile` gossip
                // receive path (0.125.0 — SettingsSync now replicates), so a
                // device on a DIFFERENT node than the writer is nudged too, not
                // just on its next login (the "one-shot sync = permanent
                // divergence" failure mode). Spec 3 §4.3.
                //
                // Skip the nudge when this copy is not actually newer than what
                // this node already holds — an out-of-order gossip relay of an
                // already-superseded blob shouldn't wake every local session.
                let wallet = self.resolve_member_wallet(&envelope.author);
                let incoming_ts = rmp_serde::from_slice::<SettingsSyncPayload>(&envelope.payload)
                    .ok()
                    .map(|p| if p.updated_at > 0 { p.updated_at } else { envelope.timestamp })
                    .unwrap_or(envelope.timestamp);
                let stored_ts = self
                    .storage
                    .as_ref()
                    .and_then(|s| s.get_settings_ts(&wallet).ok())
                    .unwrap_or(0);
                if incoming_ts >= stored_ts {
                    self.broadcast_settings_changed(&wallet);
                }
            }
            _ => {}
        }
    }

    /// Resolve a device key → wallet (fallback to the address itself).
    fn resolve_member_wallet(&self, author: &str) -> String {
        self.storage
            .as_ref()
            .and_then(|s| s.resolve_wallet(author).ok().flatten())
            .unwrap_or_else(|| author.to_string())
    }

    /// Notify a channel's members that membership changed, so their clients react
    /// live: on `join` an existing member's client wraps the channel epoch key to
    /// the new member (reliable key delivery — no longer depends on a member
    /// actively viewing the channel); on `kick`/`ban`/`leave` clients drop the member
    /// (and the removed member learns it lost access). Members-only `Wallets` audience.
    /// Runs on BOTH the API-post and gossip-receive paths, so it reaches members on
    /// every node. Skipped for channels that need no key cover — i.e. PRIVATE (2)
    /// or `encryption_enabled` PUBLIC/READ-PUBLIC (P4) channels both need it;
    /// plain unencrypted public channels don't.
    fn broadcast_channel_membership_change(&self, channel_id: u64, action: &str, member: &str) {
        // Gate on KNOWN-needs-cover (not "not known public") so a channel learned
        // via gossip before its CHANNELS metadata arrives doesn't get a spurious
        // member-targeted push.
        if !self.channel_needs_key_cover(channel_id) {
            return;
        }
        let mut audience = self.channel_member_addresses(channel_id);
        // On removal the member is already out of CHANNEL_MEMBERS — include them so
        // their own client learns it was removed.
        if matches!(action, "kick" | "ban" | "leave") && !audience.iter().any(|a| a == member) {
            audience.push(member.to_string());
        }
        if audience.is_empty() {
            return;
        }
        // Current key-epoch floor (P2d): bumped in update_indexes BEFORE this runs, so
        // it reflects the removal. Clients use it to re-key (mods) / refuse sending
        // under a below-floor epoch (all members) without an extra channel fetch.
        let key_epoch_floor = self.channel_key_epoch_floor(channel_id);
        let ws_msg = serde_json::json!({
            "type": "channel_members_changed",
            "channel_id": channel_id,
            "action": action,
            "member": member,
            "key_epoch_floor": key_epoch_floor,
        });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Wallets(audience),
                json,
            }));
        }
    }

    /// Notify a channel's members that it was deleted, so their clients drop it
    /// from their local "joined channels" list and bounce out of its view if
    /// currently open — the deletion counterpart to kick/ban
    /// (`broadcast_channel_membership_change`). Reads the member list
    /// `tombstone_channel` captured just before wiping `CHANNEL_MEMBERS`: by the
    /// time this runs, that CF (and the `CHANNELS` record itself) are already
    /// gone, so there is nothing left here to derive the audience from directly.
    /// Runs on BOTH the API-post and gossip-receive paths, so it reaches members
    /// on every node — including federated nodes, whose only signal that the
    /// channel is gone is this broadcast plus their own local tombstone (applied
    /// moments earlier by the same `ChannelDelete` envelope).
    fn broadcast_channel_deleted(&self, channel_id: u64) {
        let Some(storage) = self.storage.as_ref() else { return };
        let members = storage.deleted_channel_members(channel_id).unwrap_or_default();
        if members.is_empty() {
            return;
        }
        let ws_msg = serde_json::json!({
            "type": "channel_deleted",
            "channel_id": channel_id,
        });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Wallets(members),
                json,
            }));
        }
    }

    /// Read a channel's cached bot addresses, if present and within `ttl`.
    pub async fn channel_bots_cached(
        &self,
        channel_id: u64,
        ttl: Duration,
    ) -> Option<(bool, Arc<Vec<String>>)> {
        let cache = self.channel_bots_cache.read().await;
        cache
            .get(&channel_id)
            .filter(|(at, _, _)| at.elapsed() < ttl)
            .map(|(_, capped, v)| (*capped, Arc::clone(v)))
    }

    /// Store a channel's bot addresses, evicting the oldest entries if the cache
    /// is at `max_entries`.
    pub async fn channel_bots_store(
        &self,
        channel_id: u64,
        scan_capped: bool,
        value: Arc<Vec<String>>,
        max_entries: usize,
    ) {
        let mut cache = self.channel_bots_cache.write().await;
        if cache.len() >= max_entries && !cache.contains_key(&channel_id) {
            // Drop the oldest half rather than one entry, so a hot node does not
            // pay an eviction scan on every single insert once it is full.
            let mut by_age: Vec<(u64, Instant)> =
                cache.iter().map(|(k, (at, _, _))| (*k, *at)).collect();
            by_age.sort_by_key(|(_, at)| *at);
            for (k, _) in by_age.into_iter().take(max_entries / 2 + 1) {
                cache.remove(&k);
            }
        }
        cache.insert(channel_id, (Instant::now(), scan_capped, value));
    }

    /// Drop one channel's cached bot list — used when that channel's membership
    /// changes, which is a trigger already keyed by channel.
    pub async fn channel_bots_invalidate(&self, channel_id: u64) {
        self.channel_bots_cache.write().await.remove(&channel_id);
    }

    /// Tell every connected client that `wallet`'s bot descriptor changed, so
    /// clients viewing a channel that bot is in re-fetch
    /// `GET /api/v1/channels/{channel_id}/bots` and refresh their `/`-picker.
    ///
    /// Audience is `Everyone`, deliberately: the descriptor is public, and
    /// `WsAudience` has no "all authenticated sessions" variant — do not add one
    /// for this.
    ///
    /// The caller is responsible for only invoking this when the descriptor
    /// ACTUALLY changed (the router's content comparison) and never from
    /// identity-sync. This method adds the second half of that defense:
    /// per-wallet coalescing, so a wallet that legitimately edits its commands
    /// in a burst still only wakes every client once per window.
    pub async fn broadcast_bot_commands_changed(&self, wallet: &str) {
        // NOTE: this deliberately does NOT touch `channel_bots_cache`.
        //
        // An earlier revision flushed the whole cache here, on the reasoning that
        // there is no wallet -> channels reverse index so selective eviction is
        // not computable. That was true but the wrong conclusion: a global flush
        // reachable from any wallet on any node — the trigger arrives over gossip
        // — is a remotely-triggerable off-switch for the only thing standing in
        // front of an unauthenticated 5000-row scan, and coalescing bounds client
        // fan-out without bounding the flush at all.
        //
        // The cache now holds only the channel's bot ADDRESSES; commands are
        // re-read from `USERS` on every request. So a descriptor change is
        // already visible immediately and there is nothing stale to evict.
        {
            let now = Instant::now();
            let mut seen = self.bot_broadcast_seen.write().await;
            if let Some(last) = seen.get(wallet) {
                if now.duration_since(*last) < BOT_COALESCE_WINDOW {
                    return;
                }
            }
            // Prune before inserting so the map cannot grow past its cap.
            if seen.len() >= BOT_COALESCE_MAX_ENTRIES && !seen.contains_key(wallet) {
                let cutoff = now.checked_sub(BOT_COALESCE_WINDOW).unwrap_or(now);
                seen.retain(|_, t| *t > cutoff);
                // Still full even after dropping everything stale: refuse to
                // grow. Skipping the bookkeeping (not the broadcast) degrades
                // coalescing, never correctness.
                if seen.len() >= BOT_COALESCE_MAX_ENTRIES {
                    seen.clear();
                }
            }
            seen.insert(wallet.to_string(), now);
        }

        let ws_msg = serde_json::json!({
            "type": "bot_commands_changed",
            "address": wallet,
        });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Everyone,
                json,
            }));
        }
    }

    /// Notify a wallet's authenticated WebSocket sessions that its cross-device
    /// settings blob was overwritten (`SettingsSync` / 0x33). Payload-free — the
    /// blob is E2E-encrypted and the node can't read it; the client reacts by
    /// re-fetching `GET /api/v1/settings` and re-applying its synced objects
    /// under their normal last-writer-wins merge. Targeted to `Wallets([wallet])`
    /// — the WS layer delivers to every session authenticated as that wallet,
    /// including (harmlessly) the one that just wrote, which dedups on its own
    /// `updatedAt`. Spec 3 §4.3.
    fn broadcast_settings_changed(&self, wallet: &str) {
        let ws_msg = serde_json::json!({ "type": "settings_changed" });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Wallets(vec![wallet.to_string()]),
                json,
            }));
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

    /// True only when the channel's stored metadata is present, parseable, and the
    /// channel needs join/leave key cover — either explicitly PRIVATE (2), or
    /// explicitly `encryption_enabled: true` (P4 encrypted PUBLIC/READ-PUBLIC
    /// channels use the same epoch-key-wrap-on-join mechanism as private ones).
    /// Unlike `!channel_is_public`, a missing/unparseable record returns `false`
    /// here — so membership-change pushes fire only for channels we KNOW need
    /// cover, never for not-yet-synced metadata.
    fn channel_needs_key_cover(&self, channel_id: u64) -> bool {
        self.storage
            .as_ref()
            .and_then(|s| s.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()).ok().flatten())
            .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
            .map(|meta| {
                let is_private = match meta.get("channel_type") {
                    Some(serde_json::Value::Number(n)) => n.as_u64() == Some(2),
                    Some(serde_json::Value::String(s)) => s == "Private",
                    _ => false,
                };
                let encrypted = meta
                    .get("encryption_enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                is_private || encrypted
            })
            .unwrap_or(false)
    }

    /// Current key-epoch floor for a channel (0 if unset / metadata absent).
    fn channel_key_epoch_floor(&self, channel_id: u64) -> u64 {
        self.storage
            .as_ref()
            .and_then(|s| s.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()).ok().flatten())
            .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
            .and_then(|meta| meta.get("key_epoch_floor").and_then(|v| v.as_u64()))
            .unwrap_or(0)
    }

    /// Member wallet addresses of a channel (from `CHANNEL_MEMBERS`). Bounded scan.
    fn channel_member_addresses(&self, channel_id: u64) -> Vec<String> {
        let Some(storage) = self.storage.as_ref() else {
            return Vec::new();
        };
        storage
            .prefix_iter_cf(cf::CHANNEL_MEMBERS, &channel_id.to_be_bytes(), 4096)
            .map(|entries| {
                entries
                    .into_iter()
                    .filter_map(|(k, _)| {
                        // key = channel_id_be8 ++ address
                        if k.len() > 8 {
                            String::from_utf8(k[8..].to_vec()).ok()
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn broadcast_channel_message(
        &self,
        envelope: &Envelope,
        channel_id: u64,
        extra: &[(&str, serde_json::Value)],
    ) {
        // PRIVACY: a PUBLIC / READ-PUBLIC channel's content fans out to ALL
        // connected clients (they filter by channel_id). A PRIVATE channel must
        // NEVER hit that all-client broadcast — instead it's delivered ONLY to its
        // members (targeted `Wallets` audience), which is privacy-safe (members are
        // authorized, content is encrypted) and gives them LIVE updates. Without
        // this, private-channel messages only appeared on a manual refetch.
        let public = self.channel_is_public(channel_id);
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
            let audience = if public {
                WsAudience::Everyone
            } else {
                // Private channel → members only. No members reachable (e.g. record
                // missing) → nothing to deliver.
                let members = self.channel_member_addresses(channel_id);
                if members.is_empty() {
                    return;
                }
                WsAudience::Wallets(members)
            };
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound { audience, json }));
        }
    }

    /// Real-time WS delivery of a global-news envelope.
    ///
    /// Runs on BOTH the API-post and gossip-receive paths (see [`Self::process`]),
    /// so a post made on one node appears live on every node's connected clients.
    /// Before 0.119.0 no news message type had a `process()` arm at all, so the
    /// node never pushed news over the WS: web, desktop and mobile alike only
    /// showed a new post after navigating away from the feed and back, because
    /// that forced a REST refetch. This is the news counterpart of
    /// [`Self::broadcast_channel_message`].
    ///
    /// PRIVACY: a `NewsPost` marked `Visibility::Followers` must not reach every
    /// connected client. Those are delivered to the author plus the author's
    /// followers via a targeted `Wallets` audience, mirroring what
    /// `Storage::news_followers_post_visible_to` enforces on the REST path
    /// (audit W37). Anything whose visibility can't be determined — a payload
    /// that won't decode — is treated as restricted and dropped rather than
    /// broadcast, so a decode failure can never become a disclosure.
    fn broadcast_news(&self, envelope: &Envelope, extra: &[(&str, serde_json::Value)]) {
        use crate::messages::types::{MessageType, NewsPostPayload, Visibility};

        // Only a NewsPost carries a visibility field. Edits, deletes, reactions,
        // comments and reposts reference a post by id; their audience is that of
        // the post they target, so resolve it rather than assuming public.
        let audience = if envelope.msg_type == MessageType::NewsPost {
            match rmp_serde::from_slice::<NewsPostPayload>(&envelope.payload) {
                Ok(p) if p.visibility == Visibility::Followers => {
                    match self.news_followers_audience(&envelope.author) {
                        Some(a) => a,
                        None => return,
                    }
                }
                Ok(_) => WsAudience::Everyone,
                // Undecodable payload — fail closed.
                Err(_) => return,
            }
        } else {
            match self.news_target_audience(envelope) {
                Some(a) => a,
                None => return,
            }
        };

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
            // Resolve device key → wallet so the live post's author matches the
            // REST/optimistic one and the client can dedup its own echo.
            if let Some(ref storage) = self.storage {
                if let Ok(Some(wallet)) = storage.resolve_wallet(&envelope.author) {
                    map.insert("author".into(), serde_json::Value::String(wallet));
                }
            }
            for (k, v) in extra {
                map.insert((*k).to_string(), v.clone());
            }
        }
        let ws_msg = serde_json::json!({ "type": "message", "envelope": val });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound { audience, json }));
        }
    }

    /// Audience for a `Followers`-only post: the author plus their followers.
    /// `None` when storage is unavailable or the follower list can't be read —
    /// callers must drop the frame rather than fall back to `Everyone`.
    fn news_followers_audience(&self, author: &str) -> Option<WsAudience> {
        let storage = self.storage.as_ref()?;
        // The author is addressed by wallet, not by the device key that signed.
        let author_wallet = storage
            .resolve_wallet(author)
            .ok()
            .flatten()
            .unwrap_or_else(|| author.to_string());
        // Bounded: an unbounded follower list would build an arbitrarily large
        // frame. FOLLOWER_FANOUT_CAP followers get the live push; anyone beyond
        // it still sees the post on their next refetch, which is the same
        // guarantee they had before this existed.
        let mut wallets = storage
            .get_followers(&author_wallet, FOLLOWER_FANOUT_CAP)
            .ok()?;
        wallets.push(author_wallet);
        Some(WsAudience::Wallets(wallets))
    }

    /// The msg_id of the `NewsPost` a news envelope refers to.
    ///
    /// The field name differs per payload — `EditPayload`/`DeletePayload`/
    /// `ReactionPayload` use `target_id`, `NewsCommentPayload` uses `post_id`,
    /// and `NewsRepostPayload` uses `original_id` — so this cannot be one
    /// generic struct. Getting it wrong fails silently (the payload just
    /// doesn't decode), which is exactly how the reference would go missing.
    fn news_target_id(envelope: &Envelope) -> Option<[u8; 32]> {
        use crate::messages::types::{
            DeletePayload, EditPayload, MessageType, NewsCommentPayload, NewsRepostPayload,
            ReactionPayload,
        };
        match envelope.msg_type {
            MessageType::NewsEdit => rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                .ok()
                .map(|p| p.target_id),
            MessageType::NewsDelete => rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                .ok()
                .map(|p| p.target_id),
            MessageType::NewsReaction => {
                rmp_serde::from_slice::<ReactionPayload>(&envelope.payload)
                    .ok()
                    .map(|p| p.target_id)
            }
            MessageType::NewsComment => {
                rmp_serde::from_slice::<NewsCommentPayload>(&envelope.payload)
                    .ok()
                    .map(|p| p.post_id)
            }
            MessageType::NewsRepost => {
                rmp_serde::from_slice::<NewsRepostPayload>(&envelope.payload)
                    .ok()
                    .map(|p| p.original_id)
            }
            _ => None,
        }
    }

    /// Audience for a news envelope that targets another post (edit, delete,
    /// reaction, comment, repost): whatever the targeted post's audience is.
    /// `None` when the target can't be resolved — fail closed.
    fn news_target_audience(&self, envelope: &Envelope) -> Option<WsAudience> {
        use crate::messages::types::{MessageType, NewsPostPayload, Visibility};

        let storage = self.storage.as_ref()?;
        let target_id = Self::news_target_id(envelope)?;
        let raw = storage.get_message(&target_id).ok()??;
        let target_env: Envelope = rmp_serde::from_slice(&raw).ok()?;
        if target_env.msg_type != MessageType::NewsPost {
            return None;
        }
        let p: NewsPostPayload = rmp_serde::from_slice(&target_env.payload).ok()?;
        if p.visibility == Visibility::Followers {
            self.news_followers_audience(&target_env.author)
        } else {
            Some(WsAudience::Everyone)
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

    /// Real-time WS delivery of a DM **edit/delete** to its two participants.
    ///
    /// Mirrors [`Self::broadcast_direct_message`] but surfaces `target_msg_id`
    /// (hex of the edited/deleted message) top-level so the client can refetch the
    /// authoritative, projected conversation instead of appending a phantom
    /// message. Runs on BOTH the API-post and gossip-receive paths, so an edit
    /// applied on one node reaches the recipient's connected client on any node.
    /// Targeted to the two wallets only — never a global broadcast.
    fn broadcast_dm_update(&self, envelope: &Envelope) {
        #[derive(serde::Deserialize)]
        struct DmUpdateExtract {
            recipient: String,
            target_id: [u8; 32],
        }
        let p: DmUpdateExtract = match rmp_serde::from_slice(&envelope.payload) {
            Ok(p) => p,
            Err(_) => return,
        };
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
            if let Some(serde_json::Value::Array(bytes)) = map.get("msg_id") {
                let hex: String = bytes
                    .iter()
                    .filter_map(|b| b.as_u64().map(|n| format!("{:02x}", n as u8)))
                    .collect();
                map.insert("msg_id".into(), serde_json::Value::String(hex));
            }
            map.insert("author".into(), serde_json::Value::String(sender_wallet.clone()));
            // Which message changed — the client keys its refetch/update on this.
            map.insert(
                "target_msg_id".into(),
                serde_json::json!(hex::encode(p.target_id)),
            );
        }
        let ws_msg = serde_json::json!({ "type": "dm", "envelope": val });
        if let Ok(json) = serde_json::to_string(&ws_msg) {
            let _ = self.ws_broadcast.send(Arc::new(WsOutbound {
                audience: WsAudience::Wallets(vec![sender_wallet, p.recipient]),
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
                    anchor_node: None,
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
                "anchor_node": notification.anchor_node,
            });
            if let Err(e) = storage.store_notification_capped(
                target_address,
                notification_id,
                notification.timestamp,
                &notification_json,
                self.max_stored_per_address,
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
        //
        // A ChannelInvite to a non-public channel skips this broadcast
        // entirely rather than redacting just the preview, unlike a mention:
        // preview-only redaction still leaves channel_id/channel_name/author
        // in the Everyone-audience frame, which for a mention just says "an
        // already-visible channel had activity" but for an invite says "wallet
        // X was just invited to private channel Y" — a fact about someone
        // else's private-channel membership with no legitimate audience
        // beyond the invitee, who already gets it in full via the persisted,
        // per-recipient GET /api/v1/notifications path above. This only skips
        // the ALL-CLIENTS broadcast below — the per-recipient push-gateway
        // delivery further down still fires, since that one is not public.
        let suppress_broadcast = matches!(notification.notification_type, NotificationType::ChannelInvite)
            && notification.channel_id.is_some_and(|cid| !self.channel_is_public(cid));
        if !suppress_broadcast {
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
            NotificationType::ChannelInvite => "channel_invite",
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
        NotificationType::ChannelInvite => "channel_invite",
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

    // --- news_target_id ---
    //
    // Every news payload names its reference to the parent post differently:
    // `target_id` on edit/delete/reaction, `post_id` on a comment, `original_id`
    // on a repost. Decoding one with another's struct fails silently — the
    // payload simply doesn't parse and the reference goes missing — so pin each
    // mapping. Getting this wrong drops the live WS update for that type.

    use crate::messages::envelope::Envelope;
    use crate::messages::types::{
        Attachment, ContentRating, DeletePayload, EditPayload, MessageType, NewsCommentPayload,
        NewsPostPayload, NewsRepostPayload, ReactionPayload, Visibility,
    };

    const TARGET: [u8; 32] = [7u8; 32];

    fn env(msg_type: MessageType, payload: Vec<u8>) -> Envelope {
        Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id: [0u8; 32],
            author: "klv1author".into(),
            timestamp: 1,
            lamport_ts: 0,
            payload,
            signature: vec![0u8; 64],
            relay_path: Vec::new(),
        }
    }

    #[test]
    fn news_target_id_reads_edit_and_delete_target_id() {
        let edit = EditPayload {
            target_id: TARGET,
            channel_id: None,
            content: "x".into(),
            edited_at: 1,
            title: None,
            tags: None,
            attachments: None,
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        };
        let e = env(MessageType::NewsEdit, rmp_serde::to_vec_named(&edit).unwrap());
        assert_eq!(NotificationEngine::news_target_id(&e), Some(TARGET));

        let del = DeletePayload { target_id: TARGET, channel_id: None };
        let e = env(MessageType::NewsDelete, rmp_serde::to_vec_named(&del).unwrap());
        assert_eq!(NotificationEngine::news_target_id(&e), Some(TARGET));
    }

    #[test]
    fn news_target_id_reads_reaction_target_id() {
        let r = ReactionPayload {
            target_id: TARGET,
            channel_id: None,
            emoji: "👍".into(),
            remove: false,
        };
        let e = env(MessageType::NewsReaction, rmp_serde::to_vec_named(&r).unwrap());
        assert_eq!(NotificationEngine::news_target_id(&e), Some(TARGET));
    }

    #[test]
    fn news_target_id_reads_comment_post_id_not_target_id() {
        let c = NewsCommentPayload {
            post_id: TARGET,
            content: "hi".into(),
            reply_to: None,
            mentions: Vec::new(),
            attachments: Vec::<Attachment>::new(),
        };
        let e = env(MessageType::NewsComment, rmp_serde::to_vec_named(&c).unwrap());
        assert_eq!(NotificationEngine::news_target_id(&e), Some(TARGET));
    }

    #[test]
    fn news_target_id_reads_repost_original_id_not_target_id() {
        let r = NewsRepostPayload {
            original_id: TARGET,
            original_author: "klv1orig".into(),
            comment: None,
        };
        let e = env(MessageType::NewsRepost, rmp_serde::to_vec_named(&r).unwrap());
        assert_eq!(NotificationEngine::news_target_id(&e), Some(TARGET));
    }

    #[test]
    fn news_target_id_is_none_for_a_post_or_unrelated_type() {
        // A NewsPost is the target, it doesn't reference one.
        let p = NewsPostPayload {
            title: "t".into(),
            content: "c".into(),
            content_rating: ContentRating::General,
            tags: Vec::new(),
            attachments: Vec::new(),
            visibility: Visibility::Public,
        };
        let e = env(MessageType::NewsPost, rmp_serde::to_vec_named(&p).unwrap());
        assert_eq!(NotificationEngine::news_target_id(&e), None);

        let e = env(MessageType::ChatMessage, Vec::new());
        assert_eq!(NotificationEngine::news_target_id(&e), None);
    }

    // --- Visibility gating ---
    //
    // A Followers-only post must never reach the all-clients `Everyone`
    // audience. `broadcast_news` resolves that through `news_followers_audience`,
    // which returns None without storage — and the caller must then DROP the
    // frame rather than fall back to a broadcast. This pins the fail-closed
    // direction: with no storage, a Followers post produces no frame at all,
    // while a Public one still would.
    #[test]
    fn followers_only_post_never_broadcasts_to_everyone() {
        let engine = NotificationEngine::new_for_test();

        let followers = NewsPostPayload {
            title: "t".into(),
            content: "c".into(),
            content_rating: ContentRating::General,
            tags: Vec::new(),
            attachments: Vec::new(),
            visibility: Visibility::Followers,
        };
        let e = env(
            MessageType::NewsPost,
            rmp_serde::to_vec_named(&followers).unwrap(),
        );
        let mut rx = engine.ws_broadcast.subscribe();
        engine.broadcast_news(&e, &[]);
        assert!(
            rx.try_recv().is_err(),
            "a Followers-only post must not produce a broadcast frame when the \
             audience cannot be resolved — silence is correct, Everyone is not"
        );

        let public = NewsPostPayload {
            visibility: Visibility::Public,
            ..followers
        };
        let e = env(
            MessageType::NewsPost,
            rmp_serde::to_vec_named(&public).unwrap(),
        );
        engine.broadcast_news(&e, &[]);
        let frame = rx.try_recv().expect("a Public post must be delivered");
        assert!(matches!(frame.audience, WsAudience::Everyone));
    }

    // --- ChannelInvite notification ---

    use crate::messages::types::ChannelInvitePayload;
    use tempfile::TempDir;

    fn engine_with_storage() -> (NotificationEngine, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut engine = NotificationEngine::new_for_test();
        engine.set_storage(storage);
        (engine, dir)
    }

    #[tokio::test]
    async fn channel_invite_is_persisted_even_when_the_invitee_is_offline() {
        // REGRESSION GUARD. `check_mentions` only delivers to an address
        // present in `local_users` — populated solely by a live WS connection
        // (api/websocket.rs) — because a mention that arrives while you're
        // reading the channel anyway doesn't need durable delivery. An invite
        // is the opposite case: the whole point is that the invitee (very
        // often a bot, which is only intermittently running) discovers it
        // LATER by polling GET /api/v1/notifications. Gating this on
        // `local_users` the same way mentions are gated would silently drop
        // every invite sent while the invitee happens to be offline — which
        // is the normal case, not the exception.
        let (engine, _dir) = engine_with_storage();
        // Deliberately NOT calling engine.add_local_user() — the invitee is
        // offline for this whole test.
        let payload = ChannelInvitePayload {
            channel_id: 42,
            target_user: "klv1invitee".into(),
            anchor_node: None,
        };
        let e = env(
            MessageType::ChannelInvite,
            rmp_serde::to_vec_named(&payload).unwrap(),
        );
        engine.process(&e).await;

        let stored = engine
            .storage
            .as_ref()
            .unwrap()
            .get_notifications("klv1invitee", None, 50, None)
            .unwrap();
        assert_eq!(stored.len(), 1, "the invite must be persisted regardless of connection state");
        assert_eq!(stored[0]["type"], "channel_invite");
        assert_eq!(stored[0]["channel_id"], "42");
        assert_eq!(stored[0]["from"], "klv1author");

        // Nobody else's notifications are touched.
        assert!(engine
            .storage
            .as_ref()
            .unwrap()
            .get_notifications("klv1author", None, 50, None)
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn channel_invite_broadcasts_over_ws_for_a_public_channel() {
        // The bot's own WS subscription is one path it could react to an
        // invite in real time through (in addition to polling on reconnect),
        // so the broadcast side must fire too, not just storage — but only
        // when the channel is public, since a public channel's existence is
        // not itself sensitive information.
        let (engine, _dir) = engine_with_storage();
        engine
            .storage
            .as_ref()
            .unwrap()
            .put_cf(
                cf::CHANNELS,
                &7u64.to_be_bytes(),
                &serde_json::to_vec(&serde_json::json!({"channel_type": 0, "name": "Public Chan"}))
                    .unwrap(),
            )
            .unwrap();
        let mut rx = engine.ws_broadcast.subscribe();
        let payload = ChannelInvitePayload {
            channel_id: 7,
            target_user: "klv1invitee".into(),
            anchor_node: None,
        };
        let e = env(
            MessageType::ChannelInvite,
            rmp_serde::to_vec_named(&payload).unwrap(),
        );
        engine.process(&e).await;

        let frame = rx.try_recv().expect("an invite to a PUBLIC channel must produce a WS frame");
        assert!(matches!(frame.audience, WsAudience::Everyone));
        assert!(frame.json.contains("channel_invite"));
    }

    #[tokio::test]
    async fn channel_invite_never_broadcasts_over_ws_for_a_private_channel() {
        // REGRESSION GUARD. Unlike a mention (where redacting just the
        // preview is enough, since the channel itself is already visible to
        // whoever is in it), an invite's channel_id/channel_name/author would
        // otherwise leak "wallet X was just invited to private channel Y" to
        // every connected client, not only the invitee — a fact about
        // someone else's private-channel membership with no legitimate
        // audience beyond the invitee. The invitee still gets it in full via
        // the persisted, per-recipient GET /api/v1/notifications path
        // (proven by the sibling offline-delivery test), so this test only
        // has to prove the PUBLIC, all-clients broadcast is suppressed.
        let (engine, _dir) = engine_with_storage();
        engine
            .storage
            .as_ref()
            .unwrap()
            .put_cf(
                cf::CHANNELS,
                &9u64.to_be_bytes(),
                &serde_json::to_vec(&serde_json::json!({"channel_type": 2, "name": "Secret Chan"}))
                    .unwrap(),
            )
            .unwrap();
        let mut rx = engine.ws_broadcast.subscribe();
        let payload = ChannelInvitePayload {
            channel_id: 9,
            target_user: "klv1invitee".into(),
            anchor_node: None,
        };
        let e = env(
            MessageType::ChannelInvite,
            rmp_serde::to_vec_named(&payload).unwrap(),
        );
        engine.process(&e).await;

        assert!(
            rx.try_recv().is_err(),
            "an invite to a PRIVATE channel must never broadcast to Everyone"
        );
        // Still persisted for the invitee's own private, authenticated poll.
        let stored = engine
            .storage
            .as_ref()
            .unwrap()
            .get_notifications("klv1invitee", None, 50, None)
            .unwrap();
        assert_eq!(stored.len(), 1);
    }
}

// --- channel bot discovery cache (spec 3 §4.1) ---

#[cfg(test)]
mod channel_bots_cache_tests {
    use super::*;

    fn addrs(n: usize) -> Arc<Vec<String>> {
        Arc::new((0..n).map(|i| format!("klv1bot{i}")).collect())
    }

    #[tokio::test]
    async fn scan_capped_survives_a_cache_hit() {
        // REGRESSION: the cache originally stored only the address list, so
        // `scan_capped` was recomputed as `false` on every hit — meaning a
        // channel whose member scan WAS truncated reported itself complete for
        // the whole TTL. The flag describes the scan that produced the list, so
        // it has to travel with it.
        let e = NotificationEngine::new_for_test();
        e.channel_bots_store(42, true, addrs(3), 10).await;
        let (capped, list) = e
            .channel_bots_cached(42, Duration::from_secs(60))
            .await
            .expect("entry should be cached");
        assert!(capped, "scan_capped must survive a cache hit");
        assert_eq!(list.len(), 3);

        e.channel_bots_store(7, false, addrs(1), 10).await;
        let (capped, _) = e
            .channel_bots_cached(7, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!capped, "an uncapped scan must not report capped");
    }

    #[tokio::test]
    async fn entry_expires_with_ttl() {
        let e = NotificationEngine::new_for_test();
        e.channel_bots_store(1, false, addrs(1), 10).await;
        assert!(e.channel_bots_cached(1, Duration::from_secs(60)).await.is_some());
        // A zero TTL makes every entry already stale.
        assert!(e.channel_bots_cached(1, Duration::ZERO).await.is_none());
    }

    #[tokio::test]
    async fn membership_invalidation_drops_only_that_channel() {
        let e = NotificationEngine::new_for_test();
        e.channel_bots_store(1, false, addrs(1), 10).await;
        e.channel_bots_store(2, false, addrs(1), 10).await;
        e.channel_bots_invalidate(1).await;
        assert!(e.channel_bots_cached(1, Duration::from_secs(60)).await.is_none());
        assert!(e.channel_bots_cached(2, Duration::from_secs(60)).await.is_some());
    }

    #[tokio::test]
    async fn a_descriptor_change_does_NOT_flush_the_cache() {
        // Deliberate: the cache holds addresses, not commands, so a descriptor
        // change needs no eviction — and a flush reachable over gossip from any
        // wallet on any node would be a remotely-triggerable off-switch for the
        // endpoint's only DoS bound. If someone reintroduces the flush, this
        // fails.
        let e = NotificationEngine::new_for_test();
        e.channel_bots_store(1, false, addrs(2), 10).await;
        e.broadcast_bot_commands_changed("klv1somebot").await;
        assert!(
            e.channel_bots_cached(1, Duration::from_secs(60)).await.is_some(),
            "a descriptor change must not evict channel bot lists"
        );
    }

    #[tokio::test]
    async fn cache_stays_bounded_at_max_entries() {
        let e = NotificationEngine::new_for_test();
        for ch in 0..50u64 {
            e.channel_bots_store(ch, false, addrs(1), 8).await;
        }
        let len = e.channel_bots_cache.read().await.len();
        assert!(len <= 8, "cache grew past max_entries: {len}");
    }

    #[tokio::test]
    async fn coalescing_suppresses_a_second_broadcast_in_the_window() {
        let e = NotificationEngine::new_for_test();
        let mut rx = e.ws_broadcast.subscribe();
        e.broadcast_bot_commands_changed("klv1a").await;
        e.broadcast_bot_commands_changed("klv1a").await;
        let first = rx.try_recv().expect("first broadcast should be sent");
        assert!(first.json.contains("bot_commands_changed"));
        assert!(
            rx.try_recv().is_err(),
            "second broadcast for the same wallet within the window must be suppressed"
        );
        // A different wallet is not coalesced against the first.
        e.broadcast_bot_commands_changed("klv1b").await;
        assert!(rx.try_recv().is_ok(), "a different wallet must still broadcast");
    }
}
