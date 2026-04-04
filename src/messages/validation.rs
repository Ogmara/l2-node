//! Payload validation rules for each message type.
//!
//! Enforces field constraints per the protocol spec (section 3).

use super::types::*;

/// Maximum content length for chat messages (4096 chars).
pub const MAX_CHAT_CONTENT: usize = 4096;
/// Maximum title length for news posts (256 chars).
pub const MAX_NEWS_TITLE: usize = 256;
/// Maximum content length for news posts (65536 chars).
pub const MAX_NEWS_CONTENT: usize = 65536;
/// Maximum tags per news post.
pub const MAX_NEWS_TAGS: usize = 10;
/// Maximum display name length (64 chars).
pub const MAX_DISPLAY_NAME: usize = 64;
/// Maximum bio length (256 chars).
pub const MAX_BIO: usize = 256;
/// Maximum channel slug length (64 chars).
pub const MAX_SLUG: usize = 64;
/// Maximum channel description length (256 chars).
pub const MAX_DESCRIPTION: usize = 256;
/// Maximum moderation rules length (1024 chars).
pub const MAX_RULES: usize = 1024;
/// Maximum report details length (256 chars).
pub const MAX_REPORT_DETAILS: usize = 256;
/// Maximum emoji length (32 bytes).
pub const MAX_EMOJI_BYTES: usize = 32;
/// Maximum tag length (64 chars).
pub const MAX_TAG_LENGTH: usize = 64;
/// Maximum mentions per message.
pub const MAX_MENTIONS: usize = 50;
/// Maximum attachments per message.
pub const MAX_ATTACHMENTS: usize = 20;
/// Maximum reason length for kicks/bans (256 chars).
pub const MAX_REASON: usize = 256;
/// Maximum repost comment length (512 chars).
pub const MAX_REPOST_COMMENT: usize = 512;
/// Maximum website URL length (256 chars).
pub const MAX_WEBSITE_URL: usize = 256;
/// Maximum content request limit (per spec 5.5.2).
pub const MAX_CONTENT_REQUEST_LIMIT: u32 = 500;
/// Maximum channel tags.
pub const MAX_CHANNEL_TAGS: usize = 5;
/// Maximum pinned messages per channel.
pub const MAX_PINS_PER_CHANNEL: usize = 10;

/// Validation error with a human-readable message.
#[derive(Debug, Clone)]
pub struct ValidationError(pub String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "validation error: {}", self.0)
    }
}

impl std::error::Error for ValidationError {}

/// Validate a chat message payload.
pub fn validate_chat_message(p: &ChatMessagePayload) -> Result<(), ValidationError> {
    if p.content.is_empty() && p.attachments.is_empty() {
        return Err(ValidationError("content or attachments required".into()));
    }
    if p.content.len() > MAX_CHAT_CONTENT {
        return Err(ValidationError(format!(
            "content too long: {} > {}",
            p.content.len(),
            MAX_CHAT_CONTENT
        )));
    }
    if p.mentions.len() > MAX_MENTIONS {
        return Err(ValidationError("too many mentions".into()));
    }
    if p.attachments.len() > MAX_ATTACHMENTS {
        return Err(ValidationError("too many attachments".into()));
    }
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    Ok(())
}

/// Validate a news post payload.
pub fn validate_news_post(p: &NewsPostPayload) -> Result<(), ValidationError> {
    if p.title.len() > MAX_NEWS_TITLE {
        return Err(ValidationError("title too long".into()));
    }
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_NEWS_CONTENT {
        return Err(ValidationError("content too long".into()));
    }
    if p.tags.len() > MAX_NEWS_TAGS {
        return Err(ValidationError("too many tags".into()));
    }
    for tag in &p.tags {
        if tag.len() > MAX_TAG_LENGTH {
            return Err(ValidationError("tag too long".into()));
        }
    }
    if p.attachments.len() > MAX_ATTACHMENTS {
        return Err(ValidationError("too many attachments".into()));
    }
    Ok(())
}

/// Validate a news comment payload.
pub fn validate_news_comment(p: &NewsCommentPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() && p.attachments.is_empty() {
        return Err(ValidationError("content or attachments required".into()));
    }
    if p.content.len() > MAX_CHAT_CONTENT {
        return Err(ValidationError("content too long".into()));
    }
    if p.mentions.len() > MAX_MENTIONS {
        return Err(ValidationError("too many mentions".into()));
    }
    if p.attachments.len() > MAX_ATTACHMENTS {
        return Err(ValidationError("too many attachments".into()));
    }
    Ok(())
}

/// Validate a channel create payload.
pub fn validate_channel_create(p: &ChannelCreatePayload) -> Result<(), ValidationError> {
    if p.slug.is_empty() || p.slug.len() > MAX_SLUG {
        return Err(ValidationError("invalid slug length".into()));
    }
    // Validate slug format: lowercase alphanumeric + hyphens
    for ch in p.slug.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '-' {
            return Err(ValidationError(
                "slug must be lowercase alphanumeric and hyphens only".into(),
            ));
        }
    }
    if p.slug.starts_with('-') || p.slug.ends_with('-') {
        return Err(ValidationError("slug cannot start or end with hyphen".into()));
    }
    if let Some(ref name) = p.display_name {
        if name.len() > MAX_DISPLAY_NAME {
            return Err(ValidationError("display_name too long".into()));
        }
    }
    if let Some(ref desc) = p.description {
        if desc.len() > MAX_DESCRIPTION {
            return Err(ValidationError("description too long".into()));
        }
    }
    if let Some(ref rules) = p.moderation.rules {
        if rules.len() > MAX_RULES {
            return Err(ValidationError("moderation rules too long".into()));
        }
    }
    Ok(())
}

/// Validate a channel update payload.
pub fn validate_channel_update(p: &ChannelUpdatePayload) -> Result<(), ValidationError> {
    if let Some(ref name) = p.display_name {
        if name.len() > MAX_DISPLAY_NAME {
            return Err(ValidationError("display_name too long".into()));
        }
    }
    if let Some(ref desc) = p.description {
        if desc.len() > MAX_DESCRIPTION {
            return Err(ValidationError("description too long".into()));
        }
    }
    if let Some(ref url) = p.website_url {
        if url.len() > MAX_WEBSITE_URL {
            return Err(ValidationError("website_url too long".into()));
        }
    }
    if let Some(ref tags) = p.tags {
        if tags.len() > MAX_CHANNEL_TAGS {
            return Err(ValidationError("too many channel tags (max 5)".into()));
        }
        for tag in tags {
            if tag.len() > MAX_TAG_LENGTH {
                return Err(ValidationError("channel tag too long".into()));
            }
        }
    }
    Ok(())
}

/// Validate a profile update payload.
pub fn validate_profile_update(p: &ProfileUpdatePayload) -> Result<(), ValidationError> {
    if let Some(ref name) = p.display_name {
        if name.len() > MAX_DISPLAY_NAME {
            return Err(ValidationError("display_name too long".into()));
        }
    }
    if let Some(ref bio) = p.bio {
        if bio.len() > MAX_BIO {
            return Err(ValidationError("bio too long".into()));
        }
    }
    Ok(())
}

/// Validate an edit payload (generic — applies to all edit types).
pub fn validate_edit(p: &EditPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_NEWS_CONTENT {
        return Err(ValidationError("content too long".into()));
    }
    Ok(())
}

/// Validate a chat edit payload — content not empty, within chat length limits.
pub fn validate_chat_edit(p: &EditPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_CHAT_CONTENT {
        return Err(ValidationError(format!(
            "content too long: {} > {}",
            p.content.len(),
            MAX_CHAT_CONTENT
        )));
    }
    Ok(())
}

/// Validate a chat delete payload — target_id must not be zero.
pub fn validate_chat_delete(p: &DeletePayload) -> Result<(), ValidationError> {
    if p.target_id == [0u8; 32] {
        return Err(ValidationError("target_id must not be zero".into()));
    }
    Ok(())
}

/// Validate a DM edit payload — content not empty, within chat length limits.
pub fn validate_dm_edit(p: &EditPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_CHAT_CONTENT {
        return Err(ValidationError(format!(
            "content too long: {} > {}",
            p.content.len(),
            MAX_CHAT_CONTENT
        )));
    }
    Ok(())
}

/// Validate a DM delete payload — target_id must not be zero.
pub fn validate_dm_delete(p: &DeletePayload) -> Result<(), ValidationError> {
    if p.target_id == [0u8; 32] {
        return Err(ValidationError("target_id must not be zero".into()));
    }
    Ok(())
}

/// Validate a news edit payload — content not empty, within news length limits.
pub fn validate_news_edit(p: &EditPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_NEWS_CONTENT {
        return Err(ValidationError("content too long".into()));
    }
    Ok(())
}

/// Validate a news delete payload — target_id must not be zero.
pub fn validate_news_delete(p: &DeletePayload) -> Result<(), ValidationError> {
    if p.target_id == [0u8; 32] {
        return Err(ValidationError("target_id must not be zero".into()));
    }
    Ok(())
}

/// Validate a reaction payload.
pub fn validate_reaction(p: &ReactionPayload) -> Result<(), ValidationError> {
    if p.emoji.is_empty() {
        return Err(ValidationError("emoji must not be empty".into()));
    }
    if p.emoji.len() > MAX_EMOJI_BYTES {
        return Err(ValidationError("emoji too long".into()));
    }
    Ok(())
}

/// Validate a report payload.
pub fn validate_report(p: &ReportPayload) -> Result<(), ValidationError> {
    if let Some(ref details) = p.details {
        if details.len() > MAX_REPORT_DETAILS {
            return Err(ValidationError("report details too long".into()));
        }
    }
    Ok(())
}

/// Validate a device delegation payload.
pub fn validate_device_delegation(p: &DeviceDelegationPayload) -> Result<(), ValidationError> {
    // 32-byte Ed25519 public key, hex-encoded = 64 chars
    if p.device_pub_key.len() != 64 {
        return Err(ValidationError("device_pub_key must be 64 hex chars".into()));
    }
    if hex::decode(&p.device_pub_key).is_err() {
        return Err(ValidationError("device_pub_key must be valid hex".into()));
    }
    if !p.permissions.can_send_messages
        && !p.permissions.can_create_channels
        && !p.permissions.can_update_profile
    {
        return Err(ValidationError("at least one permission must be granted".into()));
    }
    Ok(())
}

/// Validate a follow payload.
pub fn validate_follow(author: &str, p: &FollowPayload) -> Result<(), ValidationError> {
    if p.target.is_empty() {
        return Err(ValidationError("target must not be empty".into()));
    }
    if author == p.target {
        return Err(ValidationError("cannot follow yourself".into()));
    }
    if !p.target.starts_with("klv1") {
        return Err(ValidationError("target must be a valid Klever address".into()));
    }
    Ok(())
}

/// Validate an unfollow payload.
pub fn validate_unfollow(author: &str, p: &UnfollowPayload) -> Result<(), ValidationError> {
    if p.target.is_empty() {
        return Err(ValidationError("target must not be empty".into()));
    }
    if author == p.target {
        return Err(ValidationError("cannot unfollow yourself".into()));
    }
    if !p.target.starts_with("klv1") {
        return Err(ValidationError("target must be a valid Klever address".into()));
    }
    Ok(())
}

// --- Channel Administration validation ---

/// Validate a channel add moderator payload.
pub fn validate_channel_add_moderator(p: &ChannelAddModeratorPayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError("target_user must be a valid Klever address".into()));
    }
    Ok(())
}

/// Validate a channel remove moderator payload.
pub fn validate_channel_remove_moderator(p: &ChannelRemoveModeratorPayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError("target_user must be a valid Klever address".into()));
    }
    Ok(())
}

/// Validate a channel kick payload.
pub fn validate_channel_kick(p: &ChannelKickPayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError("target_user must be a valid Klever address".into()));
    }
    if let Some(ref reason) = p.reason {
        if reason.len() > MAX_REASON {
            return Err(ValidationError("reason too long".into()));
        }
    }
    Ok(())
}

/// Validate a channel ban payload.
pub fn validate_channel_ban(p: &ChannelBanPayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError("target_user must be a valid Klever address".into()));
    }
    // Ban reason is required per spec section 2.6
    match p.reason {
        None => return Err(ValidationError("ban reason is required".into())),
        Some(ref reason) if reason.is_empty() => {
            return Err(ValidationError("ban reason must not be empty".into()));
        }
        Some(ref reason) if reason.len() > MAX_REASON => {
            return Err(ValidationError("reason too long".into()));
        }
        _ => {}
    }
    Ok(())
}

/// Validate a channel unban payload.
pub fn validate_channel_unban(p: &ChannelUnbanPayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError("target_user must be a valid Klever address".into()));
    }
    Ok(())
}

/// Validate a channel pin message payload.
pub fn validate_channel_pin(p: &ChannelPinMessagePayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    Ok(())
}

/// Validate a channel unpin message payload.
pub fn validate_channel_unpin(p: &ChannelUnpinMessagePayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    Ok(())
}

/// Maximum anchor_node URL length.
pub const MAX_ANCHOR_NODE_URL: usize = 256;

/// Validate a channel invite payload.
pub fn validate_channel_invite(p: &ChannelInvitePayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError("target_user must be a valid Klever address".into()));
    }
    // Validate anchor_node URL if present (mandatory for private channels,
    // validated in router; here we just check format safety)
    if let Some(ref url) = p.anchor_node {
        if url.len() > MAX_ANCHOR_NODE_URL {
            return Err(ValidationError("anchor_node URL too long".into()));
        }
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(ValidationError(
                "anchor_node must be a valid HTTP(S) URL".into(),
            ));
        }
        // Reject private/internal IP ranges to prevent SSRF
        let host_part = url.trim_start_matches("https://").trim_start_matches("http://");
        let host = host_part.split('/').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or(""); // strip port
        if host == "localhost"
            || host == "127.0.0.1"
            || host == "0.0.0.0"
            || host == "[::1]"
            || host.starts_with("10.")
            || host.starts_with("172.16.")
            || host.starts_with("172.17.")
            || host.starts_with("172.18.")
            || host.starts_with("172.19.")
            || host.starts_with("172.20.")
            || host.starts_with("172.21.")
            || host.starts_with("172.22.")
            || host.starts_with("172.23.")
            || host.starts_with("172.24.")
            || host.starts_with("172.25.")
            || host.starts_with("172.26.")
            || host.starts_with("172.27.")
            || host.starts_with("172.28.")
            || host.starts_with("172.29.")
            || host.starts_with("172.30.")
            || host.starts_with("172.31.")
            || host.starts_with("192.168.")
            || host.starts_with("169.254.")
        {
            return Err(ValidationError(
                "anchor_node must not point to private/internal addresses".into(),
            ));
        }
    }
    Ok(())
}

/// Validate a content request payload.
pub fn validate_content_request(p: &ContentRequest) -> Result<(), ValidationError> {
    if p.limit > MAX_CONTENT_REQUEST_LIMIT {
        return Err(ValidationError(format!(
            "content request limit too large: {} > {}",
            p.limit, MAX_CONTENT_REQUEST_LIMIT
        )));
    }
    if p.limit == 0 {
        return Err(ValidationError("content request limit must be > 0".into()));
    }
    Ok(())
}

// --- Moderation validation ---

/// Maximum mute duration: 1 year in seconds.
pub const MAX_MUTE_DURATION_SECS: u64 = 365 * 24 * 3600;

/// Validate a counter-vote payload.
pub fn validate_counter_vote(p: &CounterVotePayload) -> Result<(), ValidationError> {
    if p.target_id == [0u8; 32] {
        return Err(ValidationError("target_id must not be zero".into()));
    }
    Ok(())
}

/// Validate a channel mute payload.
pub fn validate_channel_mute(p: &ChannelMutePayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError(
            "target_user must be a valid Klever address".into(),
        ));
    }
    // duration_secs == 0 means permanent, otherwise cap at 1 year
    if p.duration_secs > MAX_MUTE_DURATION_SECS {
        return Err(ValidationError(format!(
            "mute duration too long: {} > {} seconds",
            p.duration_secs, MAX_MUTE_DURATION_SECS
        )));
    }
    if let Some(ref reason) = p.reason {
        if reason.len() > MAX_REASON {
            return Err(ValidationError("reason too long".into()));
        }
    }
    Ok(())
}

// --- Account/Device Message validation ---

/// Maximum encrypted settings size: 1 MB.
pub const MAX_SETTINGS_SIZE: usize = 1_048_576;

/// Validate a settings sync payload.
pub fn validate_settings_sync(p: &SettingsSyncPayload) -> Result<(), ValidationError> {
    if p.encrypted_settings.is_empty() {
        return Err(ValidationError("encrypted_settings must not be empty".into()));
    }
    if p.encrypted_settings.len() > MAX_SETTINGS_SIZE {
        return Err(ValidationError(format!(
            "encrypted_settings too large: {} > {} bytes",
            p.encrypted_settings.len(),
            MAX_SETTINGS_SIZE
        )));
    }
    Ok(())
}

/// Validate a device revocation payload.
pub fn validate_device_revocation(p: &DeviceRevocationPayload) -> Result<(), ValidationError> {
    // 32-byte Ed25519 public key, hex-encoded = 64 chars
    if p.device_pub_key.len() != 64 {
        return Err(ValidationError("device_pub_key must be 64 hex chars".into()));
    }
    if hex::decode(&p.device_pub_key).is_err() {
        return Err(ValidationError("device_pub_key must be valid hex".into()));
    }
    Ok(())
}

/// Validate a deletion request payload.
pub fn validate_deletion_request(p: &DeletionRequestPayload) -> Result<(), ValidationError> {
    match p.delete_type {
        DeletionType::SingleMessage => {
            match p.target_id {
                None => return Err(ValidationError(
                    "target_id is required for SingleMessage deletion".into(),
                )),
                Some(id) if id == [0u8; 32] => return Err(ValidationError(
                    "target_id must not be zero".into(),
                )),
                _ => {}
            }
        }
        DeletionType::AllUserContent => {
            if p.target_id.is_some() {
                return Err(ValidationError(
                    "target_id must be None for AllUserContent deletion".into(),
                ));
            }
        }
    }
    Ok(())
}

// --- Direct Message validation ---

/// Maximum DM content length (10,000 bytes).
pub const MAX_DM_CONTENT: usize = 10_000;

/// Validate a direct message payload.
pub fn validate_direct_message(
    author: &str,
    p: &DirectMessagePayload,
) -> Result<(), ValidationError> {
    if p.recipient.is_empty() || !p.recipient.starts_with("klv1") {
        return Err(ValidationError(
            "recipient must be a valid Klever address".into(),
        ));
    }
    if author == p.recipient {
        return Err(ValidationError("cannot send a DM to yourself".into()));
    }
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_DM_CONTENT {
        return Err(ValidationError(format!(
            "content too long: {} > {}",
            p.content.len(),
            MAX_DM_CONTENT
        )));
    }
    // Verify conversation_id matches the expected value
    let expected = crate::crypto::compute_conversation_id(author, &p.recipient);
    if p.conversation_id != expected {
        return Err(ValidationError(
            "conversation_id does not match sender/recipient".into(),
        ));
    }
    Ok(())
}

// --- News Engagement validation ---

/// Maximum members in a single key distribution (per spec: private channels are small groups).
pub const MAX_KEY_DISTRIBUTION_MEMBERS: usize = 500;
/// Maximum encrypted key blob size per member (nonce + ciphertext).
pub const MAX_ENCRYPTED_KEY_SIZE: usize = 256;

/// Validate a private channel key distribution payload.
pub fn validate_private_channel_key_distribution(
    p: &PrivateChannelKeyDistributionPayload,
) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.member_keys.is_empty() {
        return Err(ValidationError("member_keys must not be empty".into()));
    }
    if p.member_keys.len() > MAX_KEY_DISTRIBUTION_MEMBERS {
        return Err(ValidationError(format!(
            "too many members: {} > {}",
            p.member_keys.len(),
            MAX_KEY_DISTRIBUTION_MEMBERS
        )));
    }
    for (address, key_blob) in &p.member_keys {
        if !address.starts_with("klv1") {
            return Err(ValidationError(format!(
                "invalid member address: {}",
                address
            )));
        }
        if key_blob.is_empty() {
            return Err(ValidationError("encrypted key blob must not be empty".into()));
        }
        if key_blob.len() > MAX_ENCRYPTED_KEY_SIZE {
            return Err(ValidationError("encrypted key blob too large".into()));
        }
    }
    Ok(())
}

/// Validate a news repost payload.
pub fn validate_news_repost(author: &str, p: &NewsRepostPayload) -> Result<(), ValidationError> {
    if p.original_author.is_empty() || !p.original_author.starts_with("klv1") {
        return Err(ValidationError("original_author must be a valid Klever address".into()));
    }
    if author == p.original_author {
        return Err(ValidationError("cannot repost your own post".into()));
    }
    if let Some(ref comment) = p.comment {
        if comment.len() > MAX_REPOST_COMMENT {
            return Err(ValidationError("repost comment too long (max 512)".into()));
        }
    }
    Ok(())
}
