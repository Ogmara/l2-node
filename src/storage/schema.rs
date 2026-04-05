//! Column family definitions and key encoding for RocksDB.
//!
//! Each column family is a separate key-value namespace (spec 3.5).

/// Column family names for RocksDB (spec 3.5).
pub mod cf {
    /// msg_id → Envelope (serialized MessagePack)
    pub const MESSAGES: &str = "messages";
    /// (channel_id, lamport_ts, msg_id) → () — ordered channel message index
    pub const CHANNEL_MSGS: &str = "channel_msgs";
    /// (conversation_id, timestamp, msg_id) → () — DM index per conversation
    pub const DM_MESSAGES: &str = "dm_messages";
    /// (user_address, last_activity_ts, conversation_id) → () — user's DM list
    pub const DM_CONVERSATIONS: &str = "dm_conversations";
    /// (timestamp, msg_id) → () — global news feed index
    pub const NEWS_FEED: &str = "news_feed";
    /// (tag, timestamp, msg_id) → () — tag-based news index
    pub const NEWS_BY_TAG: &str = "news_by_tag";
    /// (author, timestamp, msg_id) → () — author's posts
    pub const NEWS_BY_AUTHOR: &str = "news_by_author";
    /// klever_address → UserProfile (serialized)
    pub const USERS: &str = "users";
    /// channel_id → ChannelMetadata (serialized)
    pub const CHANNELS: &str = "channels";
    /// (user_address, device_pub_key) → Delegation (serialized)
    pub const DELEGATIONS: &str = "delegations";
    /// block_height → StateAnchor (serialized)
    pub const STATE_ANCHORS: &str = "state_anchors";
    /// node_id → NodeAnnouncement (serialized)
    pub const PEER_DIRECTORY: &str = "peer_directory";
    /// (source, id, timestamp) → Envelope — LRU cache of fetched content
    pub const CONTENT_CACHE: &str = "content_cache";
    /// key → value — cursor positions, node config, etc.
    pub const NODE_STATE: &str = "node_state";

    /// (follower_address, followed_address) → () — who you follow
    pub const FOLLOWS: &str = "follows";
    /// (followed_address, follower_address) → () — who follows you (reverse index)
    pub const FOLLOWERS: &str = "followers";
    /// address → (following_count: u64, follower_count: u64) — cached counts
    pub const FOLLOWER_COUNTS: &str = "follower_counts";

    // --- News Engagement ---

    /// (msg_id, emoji, author) → () — individual reactions on news posts
    pub const NEWS_REACTIONS: &str = "news_reactions";
    /// (msg_id, emoji) → u64 — cached reaction counts per post per emoji
    pub const REACTION_COUNTS: &str = "reaction_counts";
    /// (original_id, reposter_address) → repost_msg_id — who reposted what
    pub const REPOSTS: &str = "reposts";
    /// msg_id → u64 — cached repost count per post
    pub const REPOST_COUNTS: &str = "repost_counts";
    /// (user_address, timestamp, msg_id) → () — user's saved posts, ordered by save time
    pub const BOOKMARKS: &str = "bookmarks";

    // --- Channel Administration ---

    /// (channel_id, address) → ModeratorPermissions (serialized)
    pub const CHANNEL_MODERATORS: &str = "channel_moderators";
    /// (channel_id, address) → BanRecord (serialized: reason, duration, banned_at, banned_by)
    pub const CHANNEL_BANS: &str = "channel_bans";
    /// (channel_id, pin_order, msg_id) → () — max 10 pins per channel
    pub const CHANNEL_PINS: &str = "channel_pins";
    /// (channel_id, address) → MemberRecord (serialized: joined_at, role)
    pub const CHANNEL_MEMBERS: &str = "channel_members";
    /// (channel_id, address) → InviteRecord (serialized: invited_by, timestamp)
    pub const CHANNEL_INVITES: &str = "channel_invites";

    /// (node_id, timestamp) → block_height — anchors indexed by submitting node
    pub const ANCHOR_BY_NODE: &str = "anchor_by_node";

    /// (post_id, timestamp, msg_id) → () — comments indexed by parent news post
    pub const NEWS_COMMENTS: &str = "news_comments";

    // --- Device-to-Wallet Identity Mapping ---

    /// device_address → wallet_address — resolves device key to owning wallet
    pub const DEVICE_WALLET_MAP: &str = "device_wallet_map";
    /// (wallet_address, 0xFF, device_address) → DeviceClaim (serialized) — wallet's registered devices
    pub const WALLET_DEVICES: &str = "wallet_devices";

    /// (wallet_address, 0xFF, channel_id_be8) → last_read_ts (u64 BE) — per-user per-channel read cursor
    pub const CHANNEL_READ_STATE: &str = "channel_read_state";

    /// (wallet_address, 0xFF, conversation_id) → last_read_ts (u64 BE) — per-user per-DM read cursor
    pub const DM_READ_STATE: &str = "dm_read_state";

    /// channel_id (8 bytes BE) → deletion timestamp (u64 BE) — tombstone for deleted channels.
    /// Prevents chain scanner from re-creating channels that were intentionally deleted.
    pub const DELETED_CHANNELS: &str = "deleted_channels";

    // --- Edit/Delete Tracking ---

    /// msg_id (32 bytes) → DeletionRecord JSON (deleted_by, deleted_at, msg_type)
    /// Soft-delete markers — content persists in storage but is hidden in API responses.
    pub const DELETION_MARKERS: &str = "deletion_markers";
    /// (original_msg_id:32, edit_timestamp:8) → edit_msg_id (32 bytes)
    /// Edit chain: tracks successive edits to a message.
    pub const EDIT_HISTORY: &str = "edit_history";

    // --- Chat Reactions ---

    /// (msg_id:32, emoji_len:2, emoji, 0xFF, author) → () — individual reactions on channel messages
    pub const CHAT_REACTIONS: &str = "chat_reactions";
    /// (msg_id:32, emoji) → u64 — cached reaction counts per channel message
    pub const CHAT_REACTION_COUNTS: &str = "chat_reaction_counts";

    // --- Moderation ---

    /// (target_id:32, reporter_address) → ReportRecord JSON (reason, details, timestamp)
    pub const REPORTS: &str = "reports";
    /// (target_id:32, voter_address) → timestamp (u64 BE) — counter-votes on reports
    pub const COUNTER_VOTES: &str = "counter_votes";
    /// (channel_id:8, target_address) → MuteRecord JSON (muted_by, duration_secs, muted_at, reason)
    pub const CHANNEL_MUTES: &str = "channel_mutes";

    // --- Private Channel Anchor Node ---

    /// (channel_id:8, epoch:8) → KeyDistribution JSON (member_keys map)
    /// Encrypted group key material per epoch, stored on the anchor node.
    pub const PRIVATE_CHANNEL_KEYS: &str = "private_channel_keys";
    /// channel_id:8 → AnchorRecord JSON (anchor_url, channel_id, creator)
    /// Maps private channels to their anchor node URL (for remote private channels).
    pub const PRIVATE_CHANNEL_ANCHORS: &str = "private_channel_anchors";

    // --- Cross-Device Sync ---

    /// wallet_address bytes → encrypted settings blob (SettingsSyncPayload serialized)
    pub const SETTINGS_SYNC: &str = "settings_sync";
    /// (target_address, !timestamp:8, notification_id:32) → Notification JSON
    /// Reverse-chronological order. 30-day retention.
    pub const NOTIFICATIONS: &str = "notifications";

    /// All column family names for database initialization.
    pub const ALL: &[&str] = &[
        MESSAGES,
        CHANNEL_MSGS,
        DM_MESSAGES,
        DM_CONVERSATIONS,
        NEWS_FEED,
        NEWS_BY_TAG,
        NEWS_BY_AUTHOR,
        USERS,
        CHANNELS,
        DELEGATIONS,
        STATE_ANCHORS,
        PEER_DIRECTORY,
        CONTENT_CACHE,
        NODE_STATE,
        FOLLOWS,
        FOLLOWERS,
        FOLLOWER_COUNTS,
        NEWS_REACTIONS,
        REACTION_COUNTS,
        REPOSTS,
        REPOST_COUNTS,
        BOOKMARKS,
        CHANNEL_MODERATORS,
        CHANNEL_BANS,
        CHANNEL_PINS,
        CHANNEL_MEMBERS,
        CHANNEL_INVITES,
        ANCHOR_BY_NODE,
        NEWS_COMMENTS,
        DEVICE_WALLET_MAP,
        WALLET_DEVICES,
        CHANNEL_READ_STATE,
        DM_READ_STATE,
        DELETED_CHANNELS,
        DELETION_MARKERS,
        EDIT_HISTORY,
        CHAT_REACTIONS,
        CHAT_REACTION_COUNTS,
        REPORTS,
        COUNTER_VOTES,
        CHANNEL_MUTES,
        SETTINGS_SYNC,
        NOTIFICATIONS,
        PRIVATE_CHANNEL_KEYS,
        PRIVATE_CHANNEL_ANCHORS,
    ];
}

/// Well-known keys in the NODE_STATE column family.
pub mod state_keys {
    /// Last processed Klever block height (u64 big-endian).
    pub const CHAIN_CURSOR: &[u8] = b"chain_cursor";
    /// Node's Ed25519 signing key (32 bytes).
    pub const NODE_PRIVATE_KEY: &[u8] = b"node_private_key";
    /// Local Lamport clock counter (u64 big-endian).
    pub const LAMPORT_COUNTER: &[u8] = b"lamport_counter";
    /// Total stored messages counter (u64 big-endian).
    pub const TOTAL_MESSAGES: &[u8] = b"stat_total_messages";
    /// Total news feed messages counter (u64 big-endian).
    pub const TOTAL_NEWS_MESSAGES: &[u8] = b"stat_total_news_messages";
    /// Total channel chat messages counter (u64 big-endian).
    pub const TOTAL_CHANNEL_MESSAGES: &[u8] = b"stat_total_channel_messages";
    /// Total registered users counter (u64 big-endian).
    pub const TOTAL_USERS: &[u8] = b"stat_total_users";
    /// Total channels counter (u64 big-endian).
    pub const TOTAL_CHANNELS: &[u8] = b"stat_total_channels";
    /// Sentinel: set to 1 after split counters are rebuilt (prevents repeated rebuilds).
    pub const COUNTERS_V2: &[u8] = b"stat_counters_v2";
    /// Sentinel: set to 1 after channel_type values are normalized from strings to u8.
    pub const CHANNEL_TYPE_NORMALIZED: &[u8] = b"migration_channel_type_normalized";
    /// Sentinel: set to 1 after DELEGATIONS are backfilled into DEVICE_WALLET_MAP.
    pub const DELEGATION_MAP_BACKFILLED: &[u8] = b"migration_delegation_map_backfilled";
    /// Sentinel: set to 1 after device addresses are re-derived from klv1 → ogd1.
    pub const DEVICE_HRP_MIGRATED: &[u8] = b"migration_device_hrp_migrated";
}

/// Encode a channel message index key: (channel_id, lamport_ts, msg_id).
///
/// Uses big-endian encoding for natural sort order.
pub fn encode_channel_msg_key(channel_id: u64, lamport_ts: u64, msg_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + 8 + 32);
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(&lamport_ts.to_be_bytes());
    key.extend_from_slice(msg_id);
    key
}

/// Encode a DM message index key: (conversation_id, timestamp, msg_id).
pub fn encode_dm_msg_key(conversation_id: &[u8; 32], timestamp: u64, msg_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 8 + 32);
    key.extend_from_slice(conversation_id);
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(msg_id);
    key
}

/// Encode a DM conversation list key: (user_address_bytes, last_activity_ts, conversation_id).
pub fn encode_dm_conversation_key(
    user_address: &[u8],
    last_activity_ts: u64,
    conversation_id: &[u8; 32],
) -> Vec<u8> {
    let mut key = Vec::with_capacity(user_address.len() + 8 + 32);
    key.extend_from_slice(user_address);
    // Negate timestamp for reverse-chronological order (most recent first)
    key.extend_from_slice(&(!last_activity_ts).to_be_bytes());
    key.extend_from_slice(conversation_id);
    key
}

/// Encode a news feed index key: (timestamp, msg_id).
pub fn encode_news_key(timestamp: u64, msg_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + 32);
    // Negate timestamp for reverse-chronological order
    key.extend_from_slice(&(!timestamp).to_be_bytes());
    key.extend_from_slice(msg_id);
    key
}

/// Encode a news-by-tag index key: (tag, timestamp, msg_id).
pub fn encode_news_by_tag_key(tag: &str, timestamp: u64, msg_id: &[u8; 32]) -> Vec<u8> {
    let tag_bytes = tag.as_bytes();
    let mut key = Vec::with_capacity(2 + tag_bytes.len() + 8 + 32);
    // Length-prefix the tag for clean key boundaries
    key.extend_from_slice(&(tag_bytes.len() as u16).to_be_bytes());
    key.extend_from_slice(tag_bytes);
    key.extend_from_slice(&(!timestamp).to_be_bytes());
    key.extend_from_slice(msg_id);
    key
}

/// Encode a news-by-author index key: (author_address, timestamp, msg_id).
pub fn encode_news_by_author_key(author: &str, timestamp: u64, msg_id: &[u8; 32]) -> Vec<u8> {
    let author_bytes = author.as_bytes();
    let mut key = Vec::with_capacity(author_bytes.len() + 1 + 8 + 32);
    key.extend_from_slice(author_bytes);
    key.push(0xFF); // separator
    key.extend_from_slice(&(!timestamp).to_be_bytes());
    key.extend_from_slice(msg_id);
    key
}

/// Encode a delegation key: (user_address, device_pub_key_hex).
pub fn encode_delegation_key(user_address: &str, device_pub_key: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(user_address.len() + 1 + device_pub_key.len());
    key.extend_from_slice(user_address.as_bytes());
    key.push(0xFF); // separator
    key.extend_from_slice(device_pub_key.as_bytes());
    key
}

/// Encode a follow key: (follower, followed) separated by 0xFF.
pub fn encode_follow_key(follower: &str, followed: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(follower.len() + 1 + followed.len());
    key.extend_from_slice(follower.as_bytes());
    key.push(0xFF);
    key.extend_from_slice(followed.as_bytes());
    key
}

// --- News Engagement key encoding ---

/// Encode a news reaction key: (msg_id, emoji, author).
pub fn encode_news_reaction_key(msg_id: &[u8; 32], emoji: &str, author: &str) -> Vec<u8> {
    let emoji_bytes = emoji.as_bytes();
    let author_bytes = author.as_bytes();
    let mut key = Vec::with_capacity(32 + 2 + emoji_bytes.len() + 1 + author_bytes.len());
    key.extend_from_slice(msg_id);
    key.extend_from_slice(&(emoji_bytes.len() as u16).to_be_bytes());
    key.extend_from_slice(emoji_bytes);
    key.push(0xFF);
    key.extend_from_slice(author_bytes);
    key
}

/// Encode a reaction count key: (msg_id, emoji).
pub fn encode_reaction_count_key(msg_id: &[u8; 32], emoji: &str) -> Vec<u8> {
    let emoji_bytes = emoji.as_bytes();
    let mut key = Vec::with_capacity(32 + emoji_bytes.len());
    key.extend_from_slice(msg_id);
    key.extend_from_slice(emoji_bytes);
    key
}

/// Encode a repost key: (original_id, reposter_address).
pub fn encode_repost_key(original_id: &[u8; 32], reposter: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + reposter.len());
    key.extend_from_slice(original_id);
    key.extend_from_slice(reposter.as_bytes());
    key
}

/// Encode a bookmark key: (user_address, timestamp, msg_id).
pub fn encode_bookmark_key(user_address: &str, timestamp: u64, msg_id: &[u8; 32]) -> Vec<u8> {
    let addr_bytes = user_address.as_bytes();
    let mut key = Vec::with_capacity(addr_bytes.len() + 1 + 8 + 32);
    key.extend_from_slice(addr_bytes);
    key.push(0xFF);
    key.extend_from_slice(&(!timestamp).to_be_bytes()); // newest first
    key.extend_from_slice(msg_id);
    key
}

// --- Channel Administration key encoding ---

/// Encode a channel moderator key: (channel_id, address).
pub fn encode_channel_moderator_key(channel_id: u64, address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + address.len());
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(address.as_bytes());
    key
}

/// Encode a channel ban key: (channel_id, address).
pub fn encode_channel_ban_key(channel_id: u64, address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + address.len());
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(address.as_bytes());
    key
}

/// Encode a channel pin key: (channel_id, pin_order).
pub fn encode_channel_pin_key(channel_id: u64, pin_order: u32, msg_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + 4 + 32);
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(&pin_order.to_be_bytes());
    key.extend_from_slice(msg_id);
    key
}

/// Encode a channel member key: (channel_id, address).
pub fn encode_channel_member_key(channel_id: u64, address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + address.len());
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(address.as_bytes());
    key
}

/// Encode a channel invite key: (channel_id, address).
pub fn encode_channel_invite_key(channel_id: u64, address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + address.len());
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(address.as_bytes());
    key
}

/// Encode an anchor-by-node key: (node_id, timestamp).
pub fn encode_anchor_by_node_key(node_id: &str, timestamp: u64) -> Vec<u8> {
    let id_bytes = node_id.as_bytes();
    let mut key = Vec::with_capacity(id_bytes.len() + 1 + 8);
    key.extend_from_slice(id_bytes);
    key.push(0xFF); // separator
    key.extend_from_slice(&timestamp.to_be_bytes());
    key
}

/// Encode a news comment index key: (post_id, timestamp, msg_id).
pub fn encode_news_comment_key(post_id: &[u8; 32], timestamp: u64, msg_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 8 + 32);
    key.extend_from_slice(post_id);
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(msg_id);
    key
}

// --- Device-to-Wallet Identity Mapping key encoding ---

/// Encode a wallet devices key: (wallet_address, 0xFF, device_address).
///
/// Prefix iteration on wallet_address bytes returns all devices for that wallet.
pub fn encode_wallet_device_key(wallet_address: &str, device_address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(wallet_address.len() + 1 + device_address.len());
    key.extend_from_slice(wallet_address.as_bytes());
    key.push(0xFF); // separator
    key.extend_from_slice(device_address.as_bytes());
    key
}

// --- Channel Read State key encoding ---

/// Encode a channel read state key: (wallet_address, 0xFF, channel_id_be8).
pub fn encode_channel_read_key(wallet_address: &str, channel_id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(wallet_address.len() + 1 + 8);
    key.extend_from_slice(wallet_address.as_bytes());
    key.push(0xFF);
    key.extend_from_slice(&channel_id.to_be_bytes());
    key
}

// --- DM Read State key encoding ---

/// Encode a DM read state key: (wallet_address, 0xFF, conversation_id).
pub fn encode_dm_read_key(wallet_address: &str, conversation_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(wallet_address.len() + 1 + 32);
    key.extend_from_slice(wallet_address.as_bytes());
    key.push(0xFF);
    key.extend_from_slice(conversation_id);
    key
}

// --- Edit/Delete key encoding ---

/// Encode an edit history key: (original_msg_id, edit_timestamp).
pub fn encode_edit_history_key(original_msg_id: &[u8; 32], edit_timestamp: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + 8);
    key.extend_from_slice(original_msg_id);
    key.extend_from_slice(&edit_timestamp.to_be_bytes());
    key
}

// --- Chat Reaction key encoding ---

/// Encode a chat reaction key: (msg_id, emoji, author). Mirrors news reaction format.
pub fn encode_chat_reaction_key(msg_id: &[u8; 32], emoji: &str, author: &str) -> Vec<u8> {
    let emoji_bytes = emoji.as_bytes();
    let author_bytes = author.as_bytes();
    let mut key = Vec::with_capacity(32 + 2 + emoji_bytes.len() + 1 + author_bytes.len());
    key.extend_from_slice(msg_id);
    key.extend_from_slice(&(emoji_bytes.len() as u16).to_be_bytes());
    key.extend_from_slice(emoji_bytes);
    key.push(0xFF);
    key.extend_from_slice(author_bytes);
    key
}

/// Encode a chat reaction count key: (msg_id, emoji).
pub fn encode_chat_reaction_count_key(msg_id: &[u8; 32], emoji: &str) -> Vec<u8> {
    let emoji_bytes = emoji.as_bytes();
    let mut key = Vec::with_capacity(32 + emoji_bytes.len());
    key.extend_from_slice(msg_id);
    key.extend_from_slice(emoji_bytes);
    key
}

// --- Moderation key encoding ---

/// Encode a report key: (target_id, reporter_address).
pub fn encode_report_key(target_id: &[u8; 32], reporter: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + reporter.len());
    key.extend_from_slice(target_id);
    key.extend_from_slice(reporter.as_bytes());
    key
}

/// Encode a counter-vote key: (target_id, voter_address).
pub fn encode_counter_vote_key(target_id: &[u8; 32], voter: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + voter.len());
    key.extend_from_slice(target_id);
    key.extend_from_slice(voter.as_bytes());
    key
}

/// Encode a channel mute key: (channel_id, target_address).
pub fn encode_channel_mute_key(channel_id: u64, address: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + address.len());
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(address.as_bytes());
    key
}

// --- Notification key encoding ---

/// Encode a notification key: (target_address, !timestamp, notification_id).
/// Negated timestamp for reverse-chronological order (newest first).
pub fn encode_notification_key(target_address: &str, timestamp: u64, notification_id: &[u8; 32]) -> Vec<u8> {
    let addr_bytes = target_address.as_bytes();
    let mut key = Vec::with_capacity(addr_bytes.len() + 1 + 8 + 32);
    key.extend_from_slice(addr_bytes);
    key.push(0xFF);
    key.extend_from_slice(&(!timestamp).to_be_bytes()); // newest first
    key.extend_from_slice(notification_id);
    key
}

// --- Private Channel key encoding ---

/// Encode a private channel key distribution key: (channel_id, epoch).
///
/// Prefix iteration on channel_id returns all epochs for that channel.
pub fn encode_private_channel_key(channel_id: u64, epoch: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&channel_id.to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// Encode a private channel anchor key: channel_id (8 bytes BE).
pub fn encode_private_channel_anchor_key(channel_id: u64) -> Vec<u8> {
    channel_id.to_be_bytes().to_vec()
}
