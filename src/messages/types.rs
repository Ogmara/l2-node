//! All Ogmara protocol message types and payload definitions.
//!
//! Defines the 25+ MessageType enum and all payload structs per protocol spec 3.2–3.12.
//! All payloads are serialized with MessagePack (rmp-serde).

use serde::{Deserialize, Serialize};

/// Protocol message type identifiers (spec 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    // Chat (channels)
    ChatMessage = 0x01,
    ChatEdit = 0x02,
    ChatDelete = 0x03,
    ChatReaction = 0x04,

    // Direct Messages
    DirectMessage = 0x05,
    DirectMessageEdit = 0x06,
    DirectMessageDelete = 0x07,
    DirectMessageReaction = 0x08,

    // Channels
    ChannelCreate = 0x10,
    ChannelUpdate = 0x11,
    ChannelJoin = 0x12,
    ChannelLeave = 0x13,

    // Channel Administration
    ChannelAddModerator = 0x14,
    ChannelRemoveModerator = 0x15,
    ChannelKick = 0x16,
    ChannelBan = 0x17,
    ChannelUnban = 0x18,
    ChannelPinMessage = 0x19,
    ChannelUnpinMessage = 0x1A,
    ChannelInvite = 0x1B,

    // News / Posts
    NewsPost = 0x20,
    NewsEdit = 0x21,
    NewsDelete = 0x22,
    NewsComment = 0x23,

    // News Engagement
    NewsReaction = 0x24,
    NewsRepost = 0x25,

    // Profile & Identity
    ProfileUpdate = 0x30,
    DeviceDelegation = 0x31,
    DeviceRevocation = 0x32,
    SettingsSync = 0x33,
    Follow = 0x34,
    Unfollow = 0x35,

    // Moderation
    Report = 0x40,
    CounterVote = 0x41,
    ChannelMute = 0x42,

    // Account Management
    DeletionRequest = 0x50,

    // Network
    NodeAnnouncement = 0xE0,
    Ping = 0xF0,
    Pong = 0xF1,
    StateRoot = 0xF2,
    SyncRequest = 0xF3,
    SyncResponse = 0xF4,
}

impl MessageType {
    /// Convert a u8 to a MessageType.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::ChatMessage),
            0x02 => Some(Self::ChatEdit),
            0x03 => Some(Self::ChatDelete),
            0x04 => Some(Self::ChatReaction),
            0x05 => Some(Self::DirectMessage),
            0x06 => Some(Self::DirectMessageEdit),
            0x07 => Some(Self::DirectMessageDelete),
            0x08 => Some(Self::DirectMessageReaction),
            0x10 => Some(Self::ChannelCreate),
            0x11 => Some(Self::ChannelUpdate),
            0x12 => Some(Self::ChannelJoin),
            0x13 => Some(Self::ChannelLeave),
            0x14 => Some(Self::ChannelAddModerator),
            0x15 => Some(Self::ChannelRemoveModerator),
            0x16 => Some(Self::ChannelKick),
            0x17 => Some(Self::ChannelBan),
            0x18 => Some(Self::ChannelUnban),
            0x19 => Some(Self::ChannelPinMessage),
            0x1A => Some(Self::ChannelUnpinMessage),
            0x1B => Some(Self::ChannelInvite),
            0x20 => Some(Self::NewsPost),
            0x21 => Some(Self::NewsEdit),
            0x22 => Some(Self::NewsDelete),
            0x23 => Some(Self::NewsComment),
            0x24 => Some(Self::NewsReaction),
            0x25 => Some(Self::NewsRepost),
            0x30 => Some(Self::ProfileUpdate),
            0x31 => Some(Self::DeviceDelegation),
            0x32 => Some(Self::DeviceRevocation),
            0x33 => Some(Self::SettingsSync),
            0x34 => Some(Self::Follow),
            0x35 => Some(Self::Unfollow),
            0x40 => Some(Self::Report),
            0x41 => Some(Self::CounterVote),
            0x42 => Some(Self::ChannelMute),
            0x50 => Some(Self::DeletionRequest),
            0xE0 => Some(Self::NodeAnnouncement),
            0xF0 => Some(Self::Ping),
            0xF1 => Some(Self::Pong),
            0xF2 => Some(Self::StateRoot),
            0xF3 => Some(Self::SyncRequest),
            0xF4 => Some(Self::SyncResponse),
            _ => None,
        }
    }

    /// Whether this message type is a network-level message (not user content).
    pub fn is_network(&self) -> bool {
        (*self as u8) >= 0xE0
    }

    /// Whether this message type requires the sender to be registered.
    pub fn requires_registration(&self) -> bool {
        !self.is_network()
    }
}

// --- Content Rating (spec 3.3) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentRating {
    General = 0x00,
    Teen = 0x01,
    Mature = 0x02,
    Explicit = 0x03,
}

impl Default for ContentRating {
    fn default() -> Self {
        Self::General
    }
}

// --- Attachment (spec 3.3) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// IPFS content identifier (CIDv1, base32).
    pub cid: String,
    /// MIME type (e.g., "image/png").
    pub mime_type: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Original filename.
    pub filename: Option<String>,
    /// Thumbnail CID for images/videos.
    pub thumbnail_cid: Option<String>,
}

// --- Encrypted Attachment (spec 3.4) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAttachment {
    /// CID of encrypted content on IPFS.
    pub cid: String,
    /// AES-GCM encrypted metadata (mime_type, size, filename, thumbnail_cid).
    pub encrypted_meta: Vec<u8>,
    /// AES-GCM nonce for metadata.
    pub nonce: [u8; 12],
}

// --- Chat Message Payload (spec 3.3) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessagePayload {
    /// Target channel (SC-assigned sequential u64 ID).
    pub channel_id: u64,
    /// UTF-8 text content, max 4096 chars.
    pub content: String,
    /// Voluntary content rating.
    #[serde(default)]
    pub content_rating: ContentRating,
    /// msg_id of parent message (for replies).
    pub reply_to: Option<[u8; 32]>,
    /// Mentioned user addresses (for notifications).
    #[serde(default)]
    pub mentions: Vec<String>,
    /// Media references.
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

// --- Direct Message Payload (spec 3.4) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessagePayload {
    /// The other party's Klever address.
    pub recipient: String,
    /// Deterministic: Keccak-256(sorted(sender, recipient)).
    pub conversation_id: [u8; 32],
    /// Encrypted ciphertext (AES-256-GCM).
    pub content: Vec<u8>,
    /// AES-GCM nonce (unique per message).
    pub nonce: [u8; 12],
    /// Which DH-derived key epoch was used.
    pub key_epoch: u64,
    /// msg_id of parent message.
    pub reply_to: Option<[u8; 32]>,
    /// Encrypted media references.
    #[serde(default)]
    pub attachments: Vec<EncryptedAttachment>,
}

// --- News Post Payload (spec 3.5) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Visibility {
    Public = 0x00,
    Followers = 0x01,
}

impl Default for Visibility {
    fn default() -> Self {
        Self::Public
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsPostPayload {
    /// Post title, max 256 chars.
    pub title: String,
    /// Markdown content, max 65536 chars.
    pub content: String,
    /// Content rating.
    #[serde(default)]
    pub content_rating: ContentRating,
    /// Topic tags, max 10.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Media references.
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// Public or followers-only.
    #[serde(default)]
    pub visibility: Visibility,
}

// --- Channel Payloads (spec 3.6) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChannelType {
    /// Anyone can read and write.
    Public = 0x00,
    /// Anyone can read, members can write.
    ReadPublic = 0x01,
    /// Invite-only, encrypted (L2 only, not on SC).
    Private = 0x02,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationPolicy {
    /// Addresses with mod powers.
    pub admins: Vec<String>,
    /// Human-readable rules, max 1024 chars.
    pub rules: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCreatePayload {
    /// SC-assigned sequential ID (from channelCreated event).
    pub channel_id: u64,
    /// Unique slug (matches SC), max 64 chars.
    pub slug: String,
    /// Channel type.
    pub channel_type: ChannelType,
    /// Human-readable name, max 64 chars (L2 only).
    pub display_name: Option<String>,
    /// Max 256 chars (L2 only).
    pub description: Option<String>,
    /// Default content rating for messages.
    #[serde(default)]
    pub content_rating: ContentRating,
    /// Moderation policy.
    pub moderation: ModerationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelUpdatePayload {
    /// Must be channel admin/creator or mod with can_edit_info.
    pub channel_id: u64,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub content_rating: Option<ContentRating>,
    pub moderation: Option<ModerationPolicy>,
    /// Channel avatar/logo IPFS CID.
    pub logo_cid: Option<String>,
    /// Channel banner image IPFS CID.
    pub banner_cid: Option<String>,
    /// External website URL, max 256 chars.
    pub website_url: Option<String>,
    /// Channel topic tags, max 5.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelJoinPayload {
    pub channel_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLeavePayload {
    pub channel_id: u64,
}

// --- Channel Administration Payloads (spec 3.9) ---

/// Permissions granted to a channel moderator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeratorPermissions {
    pub can_mute: bool,
    pub can_kick: bool,
    pub can_ban: bool,
    pub can_pin: bool,
    pub can_edit_info: bool,
    pub can_delete_msgs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelAddModeratorPayload {
    pub channel_id: u64,
    /// User to promote.
    pub target_user: String,
    pub permissions: ModeratorPermissions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRemoveModeratorPayload {
    pub channel_id: u64,
    /// User to demote.
    pub target_user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelKickPayload {
    pub channel_id: u64,
    pub target_user: String,
    /// Max 256 chars.
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBanPayload {
    pub channel_id: u64,
    pub target_user: String,
    /// Max 256 chars.
    pub reason: Option<String>,
    /// 0 = permanent.
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelUnbanPayload {
    pub channel_id: u64,
    pub target_user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPinMessagePayload {
    pub channel_id: u64,
    pub msg_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelUnpinMessagePayload {
    pub channel_id: u64,
    pub msg_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInvitePayload {
    pub channel_id: u64,
    /// User to invite.
    pub target_user: String,
}

// --- News Engagement Payloads ---

/// Repost of a news post (with optional quote comment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsRepostPayload {
    /// msg_id of the original news post.
    pub original_id: [u8; 32],
    /// Author of the original post.
    pub original_author: String,
    /// Optional "quote repost" comment, max 512 chars.
    pub comment: Option<String>,
}

// --- Edit, Delete, Reaction Payloads (spec 3.7) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditPayload {
    /// msg_id of the message to edit.
    pub target_id: [u8; 32],
    /// Channel context (None for DMs/news).
    pub channel_id: Option<u64>,
    /// New content (full replacement).
    pub content: String,
    /// Timestamp of the edit.
    pub edited_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePayload {
    /// msg_id of the message to delete.
    pub target_id: [u8; 32],
    /// Channel context (None for DMs/news).
    pub channel_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionPayload {
    /// msg_id of the message to react to.
    pub target_id: [u8; 32],
    /// Channel context (None for DMs).
    pub channel_id: Option<u64>,
    /// Unicode emoji, max 32 bytes.
    pub emoji: String,
    /// true = remove reaction, false = add.
    pub remove: bool,
}

// --- News Comment Payload (spec 3.8) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsCommentPayload {
    /// msg_id of the parent NewsPost.
    pub post_id: [u8; 32],
    /// UTF-8 text, max 4096 chars.
    pub content: String,
    /// msg_id of parent comment (for threading).
    pub reply_to: Option<[u8; 32]>,
    /// Mentioned users.
    #[serde(default)]
    pub mentions: Vec<String>,
    /// Media references.
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

// --- Profile and Identity Payloads (spec 3.9) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileUpdatePayload {
    /// Max 64 UTF-8 chars.
    pub display_name: Option<String>,
    /// IPFS CID for avatar image.
    pub avatar_cid: Option<String>,
    /// Max 256 UTF-8 chars.
    pub bio: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDelegationPayload {
    /// 32-byte Ed25519 public key (hex-encoded).
    pub device_pub_key: String,
    /// Permission flags.
    pub permissions: DelegationPermissions,
    /// Optional expiry timestamp.
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationPermissions {
    pub can_send_messages: bool,
    pub can_create_channels: bool,
    pub can_update_profile: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRevocationPayload {
    /// 32-byte Ed25519 public key (hex-encoded).
    pub device_pub_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsSyncPayload {
    /// AES-256-GCM ciphertext.
    pub encrypted_settings: Vec<u8>,
    /// AES-GCM nonce.
    pub nonce: [u8; 12],
    /// Encryption key epoch.
    pub key_epoch: u64,
}

// --- Social Payloads (Follow/Unfollow) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowPayload {
    /// Klever address of the user to follow.
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnfollowPayload {
    /// Klever address of the user to unfollow.
    pub target: String,
}

// --- Moderation Payloads (spec 3.10) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReportTarget {
    Message = 0x01,
    User = 0x02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReportReason {
    Spam = 0x01,
    Scam = 0x02,
    Harassment = 0x03,
    IllegalContent = 0x04,
    Impersonation = 0x05,
    MisratedContent = 0x06,
    Other = 0xFF,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPayload {
    pub target_type: ReportTarget,
    /// msg_id or Keccak-256(user_address).
    pub target_id: [u8; 32],
    pub reason: ReportReason,
    /// Max 256 chars.
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterVotePayload {
    /// msg_id being counter-voted.
    pub target_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMutePayload {
    pub channel_id: u64,
    pub target_user: String,
    /// 0 = permanent.
    pub duration_secs: u64,
    pub reason: Option<String>,
}

// --- Account Management (spec 3.11) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeletionType {
    SingleMessage = 0x01,
    AllUserContent = 0x02,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRequestPayload {
    pub delete_type: DeletionType,
    /// msg_id for single message, None for account deletion.
    pub target_id: Option<[u8; 32]>,
}

// --- Node Announcement (spec 3.12) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Capability {
    Chat = 0x01,
    News = 0x02,
    Sync = 0x03,
    StateRoot = 0x04,
    PushGateway = 0x05,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAnnouncementPayload {
    /// Base58(SHA-256(public_key)[:20]).
    pub node_id: String,
    /// Channel IDs this node serves.
    pub channels: Vec<u64>,
    /// Approximate local users.
    pub user_count: u32,
    /// Node capabilities.
    pub capabilities: Vec<Capability>,
    /// Public REST API URL (if exposed).
    pub api_endpoint: Option<String>,
    /// Announcement validity in seconds (default: 600 = 10 min).
    pub ttl_seconds: u32,
}

// --- Content Request/Response (spec 5.5.2) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentRequestType {
    ChannelMessages = 0x01,
    DirectMessages = 0x02,
    NewsPosts = 0x03,
    NewsPostsByTag = 0x04,
    UserPosts = 0x05,
    PersonalFeed = 0x06,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentRequest {
    pub request_type: ContentRequestType,
    pub channel_id: Option<u64>,
    pub conversation_id: Option<[u8; 32]>,
    pub before_id: Option<[u8; 32]>,
    pub after_id: Option<[u8; 32]>,
    pub after_timestamp: Option<u64>,
    /// Max messages (max 500).
    pub limit: u32,
}

/// Deserialize a payload from MessagePack bytes based on the message type.
///
/// The `msg_type` field from the Envelope determines which payload struct
/// to deserialize into. This avoids the ambiguity problems of serde's
/// `#[serde(untagged)]` enum when payload structs share similar shapes.
pub fn deserialize_payload(
    msg_type: MessageType,
    payload_bytes: &[u8],
) -> Result<DeserializedPayload, rmp_serde::decode::Error> {
    match msg_type {
        MessageType::ChatMessage => Ok(DeserializedPayload::ChatMessage(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChatEdit | MessageType::DirectMessageEdit | MessageType::NewsEdit => {
            Ok(DeserializedPayload::Edit(rmp_serde::from_slice(payload_bytes)?))
        }
        MessageType::ChatDelete | MessageType::DirectMessageDelete | MessageType::NewsDelete => {
            Ok(DeserializedPayload::Delete(rmp_serde::from_slice(payload_bytes)?))
        }
        MessageType::ChatReaction | MessageType::DirectMessageReaction | MessageType::NewsReaction => {
            Ok(DeserializedPayload::Reaction(rmp_serde::from_slice(payload_bytes)?))
        }
        MessageType::DirectMessage => Ok(DeserializedPayload::DirectMessage(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelCreate => Ok(DeserializedPayload::ChannelCreate(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelUpdate => Ok(DeserializedPayload::ChannelUpdate(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelJoin => Ok(DeserializedPayload::ChannelJoin(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelLeave => Ok(DeserializedPayload::ChannelLeave(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelAddModerator => Ok(DeserializedPayload::ChannelAddModerator(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelRemoveModerator => Ok(DeserializedPayload::ChannelRemoveModerator(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelKick => Ok(DeserializedPayload::ChannelKick(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelBan => Ok(DeserializedPayload::ChannelBan(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelUnban => Ok(DeserializedPayload::ChannelUnban(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelPinMessage => Ok(DeserializedPayload::ChannelPinMessage(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelUnpinMessage => Ok(DeserializedPayload::ChannelUnpinMessage(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelInvite => Ok(DeserializedPayload::ChannelInvite(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::NewsRepost => Ok(DeserializedPayload::NewsRepost(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::NewsPost => Ok(DeserializedPayload::NewsPost(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::NewsComment => Ok(DeserializedPayload::NewsComment(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ProfileUpdate => Ok(DeserializedPayload::ProfileUpdate(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::DeviceDelegation => Ok(DeserializedPayload::DeviceDelegation(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::DeviceRevocation => Ok(DeserializedPayload::DeviceRevocation(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::SettingsSync => Ok(DeserializedPayload::SettingsSync(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::Follow => Ok(DeserializedPayload::Follow(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::Unfollow => Ok(DeserializedPayload::Unfollow(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::Report => Ok(DeserializedPayload::Report(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::CounterVote => Ok(DeserializedPayload::CounterVote(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::ChannelMute => Ok(DeserializedPayload::ChannelMute(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::DeletionRequest => Ok(DeserializedPayload::DeletionRequest(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::NodeAnnouncement => Ok(DeserializedPayload::NodeAnnouncement(rmp_serde::from_slice(payload_bytes)?)),
        MessageType::SyncRequest => Ok(DeserializedPayload::ContentRequest(rmp_serde::from_slice(payload_bytes)?)),
        // Ping, Pong, StateRoot, SyncResponse carry opaque bytes
        _ => Ok(DeserializedPayload::Raw(payload_bytes.to_vec())),
    }
}

/// Typed payload after msg_type-driven deserialization.
#[derive(Debug, Clone)]
pub enum DeserializedPayload {
    ChatMessage(ChatMessagePayload),
    DirectMessage(DirectMessagePayload),
    NewsPost(NewsPostPayload),
    NewsComment(NewsCommentPayload),
    NewsRepost(NewsRepostPayload),
    ChannelCreate(ChannelCreatePayload),
    ChannelUpdate(ChannelUpdatePayload),
    ChannelJoin(ChannelJoinPayload),
    ChannelLeave(ChannelLeavePayload),
    ChannelAddModerator(ChannelAddModeratorPayload),
    ChannelRemoveModerator(ChannelRemoveModeratorPayload),
    ChannelKick(ChannelKickPayload),
    ChannelBan(ChannelBanPayload),
    ChannelUnban(ChannelUnbanPayload),
    ChannelPinMessage(ChannelPinMessagePayload),
    ChannelUnpinMessage(ChannelUnpinMessagePayload),
    ChannelInvite(ChannelInvitePayload),
    Edit(EditPayload),
    Delete(DeletePayload),
    Reaction(ReactionPayload),
    ProfileUpdate(ProfileUpdatePayload),
    DeviceDelegation(DeviceDelegationPayload),
    DeviceRevocation(DeviceRevocationPayload),
    SettingsSync(SettingsSyncPayload),
    Follow(FollowPayload),
    Unfollow(UnfollowPayload),
    Report(ReportPayload),
    CounterVote(CounterVotePayload),
    ChannelMute(ChannelMutePayload),
    DeletionRequest(DeletionRequestPayload),
    NodeAnnouncement(NodeAnnouncementPayload),
    ContentRequest(ContentRequest),
    Raw(Vec<u8>),
}
