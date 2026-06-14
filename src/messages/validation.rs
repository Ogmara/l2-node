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
    // Reject the whole envelope when the runtime channel_type flip targets
    // Private. Switching to or from Private is not supported post-creation
    // (different storage, discovery, and key-distribution model). Failing the
    // entire payload here gives atomic semantics: clients see a clear
    // rejection instead of "some fields applied, the type flip didn't".
    // See protocol spec §3.6 — L2-mutable channel_type only flips Public ⇄ ReadPublic.
    if let Some(new_type) = p.channel_type {
        if new_type == ChannelType::Private {
            return Err(ValidationError(
                "channel_type cannot be flipped to Private post-creation".into(),
            ));
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
///
/// Only the router's per-type validators (`validate_chat_edit`,
/// `validate_dm_edit`, `validate_news_edit`) are reached during normal
/// dispatch; this remains as a defensive fallback for unforeseen msg_types.
/// Treats title/tags/attachments under the **news** caps, since that is the
/// most permissive of the three (chat/dm forbid them entirely).
pub fn validate_edit(p: &EditPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_NEWS_CONTENT {
        return Err(ValidationError("content too long".into()));
    }
    if let Some(ref title) = p.title {
        if title.len() > MAX_NEWS_TITLE {
            return Err(ValidationError("title too long".into()));
        }
    }
    if let Some(ref tags) = p.tags {
        if tags.len() > MAX_NEWS_TAGS {
            return Err(ValidationError("too many tags".into()));
        }
        for tag in tags {
            if tag.len() > MAX_TAG_LENGTH {
                return Err(ValidationError("tag too long".into()));
            }
        }
    }
    if let Some(ref atts) = p.attachments {
        if atts.len() > MAX_ATTACHMENTS {
            return Err(ValidationError("too many attachments".into()));
        }
    }
    Ok(())
}

/// Validate a chat edit payload — within chat length limits, with create-path parity.
///
/// `validate_chat_message` permits an empty content string when the
/// message carries at least one attachment ("photo with no caption"). The
/// edit validator must mirror that asymmetry, otherwise the user can
/// upload an attach-only chat but then can't edit the text away without
/// also removing the file. Empty content is rejected only when no
/// non-empty attachment list is supplied.
pub fn validate_chat_edit(p: &EditPayload) -> Result<(), ValidationError> {
    let has_attachments = matches!(p.attachments, Some(ref a) if !a.is_empty());
    if p.content.is_empty() && !has_attachments {
        return Err(ValidationError("content or attachments required".into()));
    }
    if p.content.len() > MAX_CHAT_CONTENT {
        return Err(ValidationError(format!(
            "content too long: {} > {}",
            p.content.len(),
            MAX_CHAT_CONTENT
        )));
    }
    // Chat edits cannot change title/tags (those fields don't exist on
    // ChatMessagePayload). Reject explicit attempts so the client can't
    // silently set values that the projection will ignore — easier debugging.
    if p.title.is_some() {
        return Err(ValidationError("title not allowed on chat edit".into()));
    }
    if p.tags.is_some() {
        return Err(ValidationError("tags not allowed on chat edit".into()));
    }
    if let Some(ref atts) = p.attachments {
        if atts.len() > MAX_ATTACHMENTS {
            return Err(ValidationError("too many attachments".into()));
        }
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
    // DMs are end-to-end encrypted: the new content rides as ciphertext in
    // `enc_content` (sealed under the conv_key), never as the plaintext
    // `content` String — which is an unused placeholder for DM edits.
    let ct = p.enc_content.as_ref().ok_or_else(|| {
        ValidationError("DM edit requires encrypted content (enc_content)".into())
    })?;
    if ct.is_empty() {
        return Err(ValidationError("enc_content must not be empty".into()));
    }
    if ct.len() > MAX_DM_CONTENT {
        return Err(ValidationError(format!(
            "enc_content too long: {} > {}",
            ct.len(),
            MAX_DM_CONTENT
        )));
    }
    if p.enc_nonce.is_none() {
        return Err(ValidationError("DM edit requires enc_nonce".into()));
    }
    // Encrypted conversations start at epoch 1; epoch 0 is the legacy plaintext
    // MVP and must never be used for an encrypted edit.
    match p.key_epoch {
        Some(e) if e >= 1 => {}
        _ => return Err(ValidationError("DM edit requires key_epoch >= 1".into())),
    }
    // The plaintext `content` String is an unused placeholder for DM edits — it
    // must be empty so a future code path that ever surfaces the raw edit envelope
    // can never leak plaintext the user intended to encrypt.
    if !p.content.is_empty() {
        return Err(ValidationError(
            "DM edit must not carry plaintext content".into(),
        ));
    }
    // Field-level overrides have no meaning for an encrypted DM. Reject attempts.
    if p.title.is_some() || p.tags.is_some() || p.attachments.is_some() {
        return Err(ValidationError(
            "field overrides not allowed on DM edit".into(),
        ));
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
///
/// Field-level overrides (title/tags/attachments) — when present — must
/// satisfy the same caps as `validate_news_post`. When absent the original
/// post's value is preserved at read-time projection.
pub fn validate_news_edit(p: &EditPayload) -> Result<(), ValidationError> {
    if p.content.is_empty() {
        return Err(ValidationError("content must not be empty".into()));
    }
    if p.content.len() > MAX_NEWS_CONTENT {
        return Err(ValidationError("content too long".into()));
    }
    if let Some(ref title) = p.title {
        if title.len() > MAX_NEWS_TITLE {
            return Err(ValidationError("title too long".into()));
        }
    }
    if let Some(ref tags) = p.tags {
        if tags.len() > MAX_NEWS_TAGS {
            return Err(ValidationError("too many tags".into()));
        }
        for tag in tags {
            if tag.len() > MAX_TAG_LENGTH {
                return Err(ValidationError("tag too long".into()));
            }
        }
    }
    if let Some(ref atts) = p.attachments {
        if atts.len() > MAX_ATTACHMENTS {
            return Err(ValidationError("too many attachments".into()));
        }
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

/// Maximum number of code points in a reaction emoji. A single emoji grapheme —
/// including ZWJ family sequences (👨‍👩‍👧‍👦 = 7), skin-tone modifiers, and flags —
/// is well under this; the cap rejects a long run of combining marks
/// masquerading as one "emoji". (The 32-byte cap already bounds this, but the
/// explicit code-point cap documents intent.)
pub const MAX_EMOJI_CHARS: usize = 12;

/// Validate a reaction emoji (audit 2026-06-07 C3). Must be non-empty, within
/// the byte + code-point caps, and free of control / bidi / separator / BOM
/// format characters — these have no place in an emoji, can spoof how the
/// (signed) reaction is rendered, and would otherwise be persisted verbatim in
/// the reaction-count key suffix. ZWJ (U+200D) and variation selectors are
/// allowed since they legitimately compose emoji sequences.
pub fn validate_emoji(emoji: &str) -> Result<(), ValidationError> {
    if emoji.is_empty() {
        return Err(ValidationError("emoji must not be empty".into()));
    }
    if emoji.len() > MAX_EMOJI_BYTES {
        return Err(ValidationError("emoji too long".into()));
    }
    if emoji.chars().count() > MAX_EMOJI_CHARS {
        return Err(ValidationError("emoji has too many code points".into()));
    }
    for c in emoji.chars() {
        let cp = c as u32;
        let disallowed = c.is_control()                  // C0/C1 incl. \n \t \r
            || matches!(cp, 0x2028 | 0x2029)             // line / paragraph separator
            || matches!(cp, 0x202A..=0x202E)             // bidi embeddings/overrides
            || matches!(cp, 0x2066..=0x2069)             // bidi isolates
            || cp == 0xFEFF; // zero-width no-break space / BOM
        if disallowed {
            return Err(ValidationError(
                "emoji contains a disallowed control/format character".into(),
            ));
        }
    }
    Ok(())
}

/// Validate a reaction payload.
pub fn validate_reaction(p: &ReactionPayload) -> Result<(), ValidationError> {
    validate_emoji(&p.emoji)
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

/// Exact wrapped-key length: 32-byte key + 16-byte Poly1305 tag (spec §8.1).
pub const WRAPPED_KEY_LEN: usize = 48;

/// Upper bound on a Klever bech32 address length (`klv1…` is 62 chars). Caps the
/// `target`/`peer` fields that flow into `channel_keys` RocksDB keys, closing a
/// storage-amplification path (audit 2026-06-11 Code-W1).
pub const MAX_KLEVER_ADDRESS_LEN: usize = 70;

/// Whether `s` is a syntactically plausible, length-bounded Klever address.
fn is_bounded_klever_address(s: &str) -> bool {
    s.starts_with("klv1") && s.len() <= MAX_KLEVER_ADDRESS_LEN
}

/// Validate a per-device channel key envelope (spec 8.1.1 / 8.2). Structural only —
/// participant-binding (DM) / membership (channel) authorization is enforced in the
/// router's `authorize_channel_action`.
pub fn validate_channel_key_envelope(
    p: &super::types::ChannelKeyEnvelopePayload,
) -> Result<(), ValidationError> {
    use super::types::key_scope_kind;
    if p.scope_kind != key_scope_kind::DM && p.scope_kind != key_scope_kind::CHANNEL {
        return Err(ValidationError(format!("invalid scope_kind: {}", p.scope_kind)));
    }
    if !is_bounded_klever_address(&p.target) {
        return Err(ValidationError("target must be a valid Klever address".into()));
    }
    // device_id is the hex of an Ed25519 signing pubkey: 64 lowercase hex chars.
    if p.device_id.len() != 64 || !p.device_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ValidationError("device_id must be 64 hex chars".into()));
    }
    if p.eph_pub.iter().all(|&b| b == 0) {
        return Err(ValidationError("eph_pub must not be all-zero".into()));
    }
    if p.wrapped.len() != WRAPPED_KEY_LEN {
        return Err(ValidationError(format!(
            "wrapped key must be {} bytes, got {}",
            WRAPPED_KEY_LEN,
            p.wrapped.len()
        )));
    }
    match p.scope_kind {
        key_scope_kind::DM => {
            // DM scope: a peer (the other participant) is required for the router's
            // `key_scope == conversation_id(author, peer)` authorization check.
            match &p.peer {
                Some(peer) if is_bounded_klever_address(peer) => {}
                _ => return Err(ValidationError("DM key envelope requires a valid peer".into())),
            }
        }
        key_scope_kind::CHANNEL => {
            if p.channel_id.unwrap_or(0) == 0 {
                return Err(ValidationError("channel key envelope requires channel_id > 0".into()));
            }
        }
        _ => unreachable!(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    fn dm_key_envelope() -> super::super::types::ChannelKeyEnvelopePayload {
        super::super::types::ChannelKeyEnvelopePayload {
            key_scope: [1u8; 32],
            scope_kind: super::super::types::key_scope_kind::DM,
            epoch: 1,
            target: "klv1target".into(),
            device_id: "ab".repeat(32),
            peer: Some("klv1peer".into()),
            channel_id: None,
            eph_pub: [2u8; 32],
            nonce: [3u8; 24],
            wrapped: vec![0u8; WRAPPED_KEY_LEN],
        }
    }

    #[test]
    fn validate_channel_key_envelope_accepts_good_dm() {
        assert!(validate_channel_key_envelope(&dm_key_envelope()).is_ok());
    }

    #[test]
    fn validate_channel_key_envelope_rejects_bad() {
        // wrong wrapped length
        let mut p = dm_key_envelope();
        p.wrapped = vec![0u8; 32];
        assert!(validate_channel_key_envelope(&p).is_err());
        // all-zero eph_pub
        let mut p = dm_key_envelope();
        p.eph_pub = [0u8; 32];
        assert!(validate_channel_key_envelope(&p).is_err());
        // bad device_id (not 64 hex)
        let mut p = dm_key_envelope();
        p.device_id = "zz".into();
        assert!(validate_channel_key_envelope(&p).is_err());
        // DM scope without a peer
        let mut p = dm_key_envelope();
        p.peer = None;
        assert!(validate_channel_key_envelope(&p).is_err());
        // unknown scope_kind
        let mut p = dm_key_envelope();
        p.scope_kind = 9;
        assert!(validate_channel_key_envelope(&p).is_err());
        // over-long target (storage-key amplification guard, Code-W1)
        let mut p = dm_key_envelope();
        p.target = format!("klv1{}", "a".repeat(MAX_KLEVER_ADDRESS_LEN));
        assert!(validate_channel_key_envelope(&p).is_err());
        // over-long peer
        let mut p = dm_key_envelope();
        p.peer = Some(format!("klv1{}", "a".repeat(MAX_KLEVER_ADDRESS_LEN)));
        assert!(validate_channel_key_envelope(&p).is_err());
    }

    #[test]
    fn validate_emoji_accepts_real_emoji_incl_zwj_sequences() {
        assert!(validate_emoji("👍").is_ok());
        assert!(validate_emoji("❤️").is_ok()); // emoji + variation selector
        assert!(validate_emoji("👨‍👩‍👧‍👦").is_ok()); // ZWJ family sequence (7 code points)
        assert!(validate_emoji("🇬🇧").is_ok()); // regional-indicator flag
    }

    #[test]
    fn validate_emoji_rejects_empty_and_oversize() {
        assert!(validate_emoji("").is_err());
        assert!(validate_emoji(&"a".repeat(MAX_EMOJI_BYTES + 1)).is_err());
    }

    #[test]
    fn validate_emoji_rejects_control_and_format_chars() {
        // audit C3: control / bidi / separator / BOM must be rejected so they
        // can't be persisted in the signed reaction-count key suffix.
        assert!(validate_emoji("👍\n").is_err()); // newline (control)
        assert!(validate_emoji("a\tb").is_err()); // tab (control)
        assert!(validate_emoji("\u{202E}x").is_err()); // RLO bidi override
        assert!(validate_emoji("\u{2066}x").is_err()); // LRI bidi isolate
        assert!(validate_emoji("\u{2028}").is_err()); // line separator
        assert!(validate_emoji("\u{FEFF}").is_err()); // BOM / ZWNBSP
    }

    fn empty_update(channel_id: u64) -> ChannelUpdatePayload {
        ChannelUpdatePayload {
            channel_id,
            display_name: None,
            description: None,
            content_rating: None,
            moderation: None,
            logo_cid: None,
            banner_cid: None,
            website_url: None,
            tags: None,
            channel_type: None,
            threads_enabled: None,
        }
    }

    #[test]
    fn channel_update_accepts_no_type_change() {
        let p = empty_update(1);
        assert!(validate_channel_update(&p).is_ok());
    }

    #[test]
    fn channel_update_accepts_flip_to_public() {
        let mut p = empty_update(1);
        p.channel_type = Some(ChannelType::Public);
        assert!(validate_channel_update(&p).is_ok());
    }

    #[test]
    fn channel_update_accepts_flip_to_readpublic() {
        let mut p = empty_update(1);
        p.channel_type = Some(ChannelType::ReadPublic);
        assert!(validate_channel_update(&p).is_ok());
    }

    #[test]
    fn channel_update_rejects_flip_to_private() {
        let mut p = empty_update(1);
        p.channel_type = Some(ChannelType::Private);
        let err = validate_channel_update(&p)
            .expect_err("flip to Private must be rejected at validation");
        assert!(
            err.0.contains("Private"),
            "error message should mention Private, got: {}",
            err.0
        );
    }

    #[test]
    fn channel_update_rejects_private_flip_atomically() {
        // The whole envelope is rejected — sibling fields don't get partial-applied
        // because the validation step short-circuits the entire payload.
        let mut p = empty_update(1);
        p.display_name = Some("New Name".into());
        p.description = Some("New Description".into());
        p.channel_type = Some(ChannelType::Private);
        assert!(
            validate_channel_update(&p).is_err(),
            "Private flip in any combination must reject the whole payload"
        );
    }

    #[test]
    fn channel_update_accepts_threads_enabled_toggle() {
        let mut p = empty_update(1);
        p.threads_enabled = Some(true);
        assert!(validate_channel_update(&p).is_ok());
        p.threads_enabled = Some(false);
        assert!(validate_channel_update(&p).is_ok());
    }

    // --- Edit-payload field-override tests (spec 3.7 extension) ---

    fn base_edit() -> EditPayload {
        EditPayload {
            target_id: [1u8; 32],
            channel_id: None,
            content: "updated".into(),
            edited_at: 1_700_000_000_000,
            title: None,
            tags: None,
            attachments: None,
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        }
    }

    #[test]
    fn news_edit_accepts_optional_overrides() {
        let mut p = base_edit();
        p.title = Some("New Title".into());
        p.tags = Some(vec!["a".into(), "b".into()]);
        p.attachments = Some(vec![]);
        assert!(validate_news_edit(&p).is_ok());
    }

    #[test]
    fn news_edit_rejects_oversize_title() {
        let mut p = base_edit();
        p.title = Some("x".repeat(MAX_NEWS_TITLE + 1));
        assert!(validate_news_edit(&p).is_err());
    }

    #[test]
    fn news_edit_rejects_too_many_tags() {
        let mut p = base_edit();
        p.tags = Some(vec!["t".into(); MAX_NEWS_TAGS + 1]);
        assert!(validate_news_edit(&p).is_err());
    }

    #[test]
    fn news_edit_rejects_oversize_tag() {
        let mut p = base_edit();
        p.tags = Some(vec!["x".repeat(MAX_TAG_LENGTH + 1)]);
        assert!(validate_news_edit(&p).is_err());
    }

    #[test]
    fn news_edit_rejects_too_many_attachments() {
        let mut p = base_edit();
        p.attachments = Some(vec![
            Attachment {
                cid: "Qm".into(),
                mime_type: "image/png".into(),
                size_bytes: 0,
                filename: None,
                thumbnail_cid: None,
            };
            MAX_ATTACHMENTS + 1
        ]);
        assert!(validate_news_edit(&p).is_err());
    }

    #[test]
    fn chat_edit_rejects_title_or_tags() {
        let mut p = base_edit();
        p.content = "c".into();
        p.title = Some("nope".into());
        assert!(validate_chat_edit(&p).is_err());
        p.title = None;
        p.tags = Some(vec!["nope".into()]);
        assert!(validate_chat_edit(&p).is_err());
    }

    #[test]
    fn chat_edit_accepts_attachments_within_cap() {
        let mut p = base_edit();
        p.content = "c".into();
        p.attachments = Some(vec![]);
        assert!(validate_chat_edit(&p).is_ok());
    }

    #[test]
    fn chat_edit_accepts_empty_content_with_attachments() {
        // Parity with `validate_chat_message`: attach-only messages are
        // legal at create time, so the same must hold at edit time.
        let mut p = base_edit();
        p.content = "".into();
        p.attachments = Some(vec![Attachment {
            cid: "Qm".into(),
            mime_type: "image/png".into(),
            size_bytes: 100,
            filename: None,
            thumbnail_cid: None,
        }]);
        assert!(validate_chat_edit(&p).is_ok());
    }

    #[test]
    fn chat_edit_rejects_empty_content_and_no_attachments() {
        let mut p = base_edit();
        p.content = "".into();
        p.attachments = None;
        assert!(validate_chat_edit(&p).is_err());
        p.attachments = Some(vec![]);
        assert!(validate_chat_edit(&p).is_err());
    }

    /// A well-formed encrypted DM edit: ciphertext + 24-byte nonce + epoch ≥ 1.
    fn encrypted_dm_edit() -> EditPayload {
        let mut p = base_edit();
        p.content = String::new(); // unused placeholder for DM edits
        p.enc_content = Some(vec![0xAB; 48]);
        p.enc_nonce = Some([0u8; 24]);
        p.key_epoch = Some(1);
        p
    }

    #[test]
    fn dm_edit_accepts_encrypted_content() {
        assert!(validate_dm_edit(&encrypted_dm_edit()).is_ok());
    }

    #[test]
    fn dm_edit_rejects_missing_enc_content() {
        // The legacy plaintext shape (no enc_content) must be rejected outright.
        let p = base_edit();
        assert!(validate_dm_edit(&p).is_err());
    }

    #[test]
    fn dm_edit_rejects_epoch_zero() {
        let mut p = encrypted_dm_edit();
        p.key_epoch = Some(0);
        assert!(validate_dm_edit(&p).is_err());
    }

    #[test]
    fn dm_edit_rejects_missing_nonce() {
        let mut p = encrypted_dm_edit();
        p.enc_nonce = None;
        assert!(validate_dm_edit(&p).is_err());
    }

    #[test]
    fn dm_edit_rejects_any_override() {
        let mut p = encrypted_dm_edit();
        p.attachments = Some(vec![]);
        assert!(validate_dm_edit(&p).is_err());
    }

    /// Wire-format compatibility: an old 4-element edit envelope must still
    /// decode after the struct gains optional fields. This guards against an
    /// accidental field reordering or removal of `#[serde(default)]`.
    #[test]
    fn edit_payload_decodes_legacy_four_field_msgpack() {
        // Manually craft a 4-element msgpack array matching the pre-extension
        // wire format: [target_id, channel_id, content, edited_at].
        let legacy = EditPayloadLegacy {
            target_id: [7u8; 32],
            channel_id: Some(42),
            content: "legacy".into(),
            edited_at: 1_000,
        };
        let bytes = rmp_serde::to_vec(&legacy).expect("encode legacy");
        let decoded: EditPayload = rmp_serde::from_slice(&bytes).expect("decode new struct");
        assert_eq!(decoded.target_id, [7u8; 32]);
        assert_eq!(decoded.channel_id, Some(42));
        assert_eq!(decoded.content, "legacy");
        assert_eq!(decoded.edited_at, 1_000);
        assert!(decoded.title.is_none());
        assert!(decoded.tags.is_none());
        assert!(decoded.attachments.is_none());
    }

    // Replica of the pre-extension struct shape — used only by the test above
    // to produce a wire-format we no longer write from production code.
    #[derive(Serialize)]
    struct EditPayloadLegacy {
        target_id: [u8; 32],
        channel_id: Option<u64>,
        content: String,
        edited_at: u64,
    }
}
