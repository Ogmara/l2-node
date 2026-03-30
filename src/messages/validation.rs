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
    if p.title.is_empty() {
        return Err(ValidationError("title must not be empty".into()));
    }
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
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
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

/// Validate an edit payload.
pub fn validate_edit(p: &EditPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_NEWS_CONTENT {
        return Err(ValidationError("content too long".into()));
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

/// Validate a channel invite payload.
pub fn validate_channel_invite(p: &ChannelInvitePayload) -> Result<(), ValidationError> {
    if p.channel_id == 0 {
        return Err(ValidationError("channel_id must be > 0".into()));
    }
    if p.target_user.is_empty() || !p.target_user.starts_with("klv1") {
        return Err(ValidationError("target_user must be a valid Klever address".into()));
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

// --- News Engagement validation ---

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
