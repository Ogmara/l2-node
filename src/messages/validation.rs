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
