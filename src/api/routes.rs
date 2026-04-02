//! Public and authenticated REST endpoint handlers.
//!
//! Public endpoints (spec 4.1): health, stats, channels, news, users.
//! Authenticated endpoints (spec 4.2): messages, profile, DMs, notifications.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Multipart, Path, Query};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::storage::schema::cf;

use super::auth::AuthUser;
use super::state::AppState;

/// Convert an Envelope's byte-array fields (msg_id, payload, signature) to hex strings
/// in the JSON representation. serde serializes [u8; 32] and Vec<u8> as number arrays,
/// but the API should return hex strings for client consumption.
/// Convert an envelope to JSON, resolving the author to the wallet address.
///
/// The envelope stores the signing key (device key) as `author`, but clients
/// should always see the wallet address. The identity resolver maps device keys
/// to wallet addresses; for built-in wallets the address is unchanged.
fn envelope_to_json(
    envelope: &crate::messages::envelope::Envelope,
    identity: &crate::storage::identity::IdentityResolver,
) -> serde_json::Value {
    let mut val = serde_json::to_value(envelope).unwrap_or_default();
    if let serde_json::Value::Object(ref mut map) = val {
        // Convert msg_id from byte array to hex string
        if let Some(serde_json::Value::Array(bytes)) = map.get("msg_id") {
            let hex: String = bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|n| format!("{:02x}", n as u8)))
                .collect();
            map.insert("msg_id".into(), serde_json::Value::String(hex));
        }
        // Resolve device key → wallet address
        match identity.resolve(&envelope.author) {
            Ok(wallet) => { map.insert("author".into(), serde_json::Value::String(wallet)); }
            Err(e) => { tracing::warn!(author = %envelope.author, error = %e, "Identity resolution failed in API response"); }
        }
    }
    val
}

// --- Query parameters ---

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct MessageParams {
    pub before: Option<String>,
    pub limit: Option<u32>,
}

// --- Response types ---

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub peers: u32,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub node_id: String,
    pub network: String,
    pub contract_address: String,
    pub peers: u32,
    pub total_messages: u64,
    pub total_news_messages: u64,
    pub total_channel_messages: u64,
    pub total_channels: u64,
    pub total_users: u64,
    pub uptime_seconds: u64,
    pub protocol_version: u8,
    pub anchor_status: crate::storage::rocks::SelfAnchorStatus,
}

#[derive(Serialize)]
struct NodeEntry {
    node_id: String,
    api_endpoint: Option<String>,
    channels: Vec<u64>,
    user_count: u32,
    last_seen: u64,
    anchor_status: crate::storage::rocks::AnchorStatus,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub msg_id: String,
}

#[derive(Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

// --- Public endpoint handlers ---

/// GET /api/v1/health
pub async fn health(Extension(state): Extension<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        peers: state.peer_count(),
    })
}

/// GET /api/v1/network/stats
pub async fn network_stats(Extension(state): Extension<Arc<AppState>>) -> Json<StatsResponse> {
    let uptime = state.started_at.elapsed().as_secs();
    let anchor_status = state.storage.get_self_anchor_status(&state.node_id).unwrap_or_else(|_| {
        crate::storage::rocks::SelfAnchorStatus {
            is_anchorer: false,
            last_anchor_height: None,
            last_anchor_age_seconds: None,
            total_anchors: 0,
            anchoring_since: None,
        }
    });
    use crate::storage::schema::state_keys;
    let total_messages = state.storage.get_stat(state_keys::TOTAL_MESSAGES).unwrap_or(0);
    let total_news_messages = state.storage.get_stat(state_keys::TOTAL_NEWS_MESSAGES).unwrap_or(0);
    let total_channel_messages = state.storage.get_stat(state_keys::TOTAL_CHANNEL_MESSAGES).unwrap_or(0);
    let total_users = state.storage.get_stat(state_keys::TOTAL_USERS).unwrap_or(0);
    let total_channels = state.storage.get_stat(state_keys::TOTAL_CHANNELS).unwrap_or(0);

    Json(StatsResponse {
        node_id: state.node_id.clone(),
        network: state.klever_network.clone(),
        contract_address: state.contract_address.clone(),
        peers: state.peer_count(),
        total_messages,
        total_news_messages,
        total_channel_messages,
        total_channels,
        total_users,
        uptime_seconds: uptime,
        protocol_version: crate::messages::envelope::PROTOCOL_VERSION,
        anchor_status,
    })
}

/// GET /api/v1/network/nodes
pub async fn network_nodes(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(500) as usize;

    match state.storage.prefix_iter_cf(cf::PEER_DIRECTORY, &[], limit) {
        Ok(entries) => {
            let nodes: Vec<NodeEntry> = entries
                .into_iter()
                .filter_map(|(_, v)| {
                    let ann: serde_json::Value = serde_json::from_slice(&v).ok()?;
                    let node_id = ann.get("node_id")?.as_str()?.to_string();
                    let api_endpoint = ann.get("api_endpoint").and_then(|v| v.as_str()).map(String::from);
                    let channels: Vec<u64> = ann.get("channels")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
                        .unwrap_or_default();
                    let user_count = ann.get("user_count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    let last_seen = ann.get("last_seen").and_then(|v| v.as_u64()).unwrap_or(0);

                    let anchor_status = state.storage.compute_anchor_status(&node_id).unwrap_or_else(|_| {
                        crate::storage::rocks::AnchorStatus {
                            verified: false,
                            level: "none".to_string(),
                            last_anchor_age_seconds: None,
                            anchoring_since: None,
                            total_anchors: 0,
                        }
                    });

                    Some(NodeEntry {
                        node_id,
                        api_endpoint,
                        channels,
                        user_count,
                        last_seen,
                        anchor_status,
                    })
                })
                .collect();
            let total = nodes.len();
            Json(serde_json::json!({
                "nodes": nodes,
                "total": total,
                "page": params.page.unwrap_or(1),
            })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error listing nodes");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// GET /api/v1/channels
pub async fn list_channels(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100) as usize;

    match state
        .storage
        .prefix_iter_cf(cf::CHANNELS, &[], limit)
    {
        Ok(entries) => {
            let channels: Vec<serde_json::Value> = entries
                .iter()
                .filter_map(|(_, v)| serde_json::from_slice(v).ok())
                .collect();
            let total = channels.len();
            Json(serde_json::json!({
                "channels": channels,
                "total": total,
                "page": params.page.unwrap_or(1),
            }))
            .into_response()
        }
        Err(e) => {
            {
                tracing::error!(error = %e, "Storage error in API handler");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// GET /api/v1/channels/:channel_id — extended response with moderators, pins, member_count
pub async fn get_channel(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    match state
        .storage
        .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())
    {
        Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(channel) => {
                // Fetch moderator list
                let prefix = channel_id.to_be_bytes();
                let moderators: Vec<String> = state.storage
                    .prefix_iter_cf(cf::CHANNEL_MODERATORS, &prefix, 100)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|(key, _)| {
                        if key.len() > 8 {
                            String::from_utf8(key[8..].to_vec()).ok()
                        } else {
                            None
                        }
                    })
                    .collect();

                // Fetch pinned messages
                let pinned: Vec<serde_json::Value> = state.storage
                    .prefix_iter_cf(cf::CHANNEL_PINS, &prefix, 10)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|(key, _)| {
                        if key.len() >= 44 {
                            let msg_id: [u8; 32] = key[12..44].try_into().ok()?;
                            let bytes = state.storage.get_message(&msg_id).ok()??;
                            let env = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&bytes).ok()?;
                            serde_json::to_value(&env).ok()
                        } else {
                            None
                        }
                    })
                    .collect();

                // Fetch member count
                let member_count = state.storage
                    .prefix_iter_cf(cf::CHANNEL_MEMBERS, &prefix, 10000)
                    .map(|e| e.len() as u64)
                    .unwrap_or(0);

                Json(serde_json::json!({
                    "channel": channel,
                    "moderators": moderators,
                    "pinned_messages": pinned,
                    "member_count": member_count,
                    "moderator_count": moderators.len(),
                })).into_response()
            }
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "corrupt channel data").into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "channel not found").into_response(),
        Err(e) => {
            {
                tracing::error!(error = %e, "Storage error in API handler");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// GET /api/v1/channels/:channel_id/messages
pub async fn get_channel_messages(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<u64>,
    Query(params): Query<MessageParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(500) as usize;
    let prefix = channel_id.to_be_bytes();

    match state
        .storage
        .prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, limit)
    {
        Ok(entries) => {
            let mut messages = Vec::with_capacity(entries.len());
            for (key, _) in &entries {
                if key.len() >= 48 {
                    let msg_id: [u8; 32] = key[16..48].try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(envelope_bytes)) = state.storage.get_message(&msg_id) {
                        if let Ok(envelope) = rmp_serde::from_slice::<
                            crate::messages::envelope::Envelope,
                        >(&envelope_bytes)
                        {
                            messages.push(envelope_to_json(&envelope, &state.identity));
                        }
                    }
                }
            }
            let has_more = entries.len() == limit;
            Json(serde_json::json!({
                "messages": messages,
                "has_more": has_more,
            }))
            .into_response()
        }
        Err(e) => {
            {
                tracing::error!(error = %e, "Storage error in API handler");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// GET /api/v1/users/:address
pub async fn get_user(
    Extension(state): Extension<Arc<AppState>>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    // Resolve device key → wallet address so lookups by device key find the right profile
    let resolved = state.identity.resolve(&address).unwrap_or_else(|_| address.clone());
    match state.storage.get_cf(cf::USERS, resolved.as_bytes()) {
        Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(user) => Json(serde_json::json!({ "user": user })).into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "corrupt user data").into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            {
                tracing::error!(error = %e, "Storage error in API handler");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// GET /api/v1/news
pub async fn list_news(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100) as usize;

    match state
        .storage
        .prefix_iter_cf(cf::NEWS_FEED, &[], limit)
    {
        Ok(entries) => {
            let mut posts = Vec::with_capacity(entries.len());
            for (key, _) in &entries {
                // Key: (!timestamp:8, msg_id:32)
                if key.len() >= 40 {
                    let msg_id: [u8; 32] = key[8..40].try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(envelope_bytes)) = state.storage.get_message(&msg_id) {
                        if let Ok(envelope) = rmp_serde::from_slice::<
                            crate::messages::envelope::Envelope,
                        >(&envelope_bytes)
                        {
                            let mut post = envelope_to_json(&envelope, &state.identity);
                            if let serde_json::Value::Object(ref mut map) = post {
                                // Check if this is a comment (msg_type == "NewsComment")
                                let is_comment = map.get("msg_type")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s == "NewsComment")
                                    .unwrap_or(false);

                                // Enrich all feed items with engagement counts
                                let reactions = state.storage.get_news_reactions(&msg_id).unwrap_or_default();
                                let reaction_counts: serde_json::Map<String, serde_json::Value> = reactions
                                    .into_iter()
                                    .map(|(e, c)| (e, serde_json::json!(c)))
                                    .collect();
                                map.insert("reaction_counts".into(), serde_json::json!(reaction_counts));
                                map.insert("repost_count".into(),
                                    serde_json::json!(state.storage.get_repost_count(&msg_id).unwrap_or(0)));
                                map.insert("comment_count".into(),
                                    serde_json::json!(state.storage.get_comment_count(&msg_id).unwrap_or(0)));

                                if is_comment {
                                    // Enrich with parent post context
                                    if let Ok(payload) = rmp_serde::from_slice::<
                                        crate::messages::types::NewsCommentPayload,
                                    >(&envelope.payload) {
                                        map.insert("parent_post_id".into(),
                                            serde_json::json!(hex::encode(payload.post_id)));
                                        // Fetch parent post for author + title preview
                                        if let Ok(Some(parent_bytes)) = state.storage.get_message(&payload.post_id) {
                                            if let Ok(parent_env) = rmp_serde::from_slice::<
                                                crate::messages::envelope::Envelope,
                                            >(&parent_bytes) {
                                                let parent_author = state.identity.resolve(&parent_env.author)
                                                    .unwrap_or_else(|_| parent_env.author.clone());
                                                map.insert("parent_author".into(),
                                                    serde_json::json!(parent_author));
                                                // Try to extract parent title
                                                if let Ok(parent_payload) = rmp_serde::from_slice::<
                                                    crate::messages::types::NewsPostPayload,
                                                >(&parent_env.payload) {
                                                    if !parent_payload.title.is_empty() {
                                                        map.insert("parent_title".into(),
                                                            serde_json::json!(parent_payload.title));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            posts.push(post);
                        }
                    }
                }
            }
            let total = posts.len();
            Json(serde_json::json!({
                "posts": posts,
                "total": total,
                "page": params.page.unwrap_or(1),
            }))
            .into_response()
        }
        Err(e) => {
            {
                tracing::error!(error = %e, "Storage error in API handler");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// GET /api/v1/news/{msg_id} — single news post with comments.
pub async fn get_news_post(
    Extension(state): Extension<Arc<AppState>>,
    Path(msg_id_hex): Path<String>,
) -> impl IntoResponse {
    let msg_id = match hex::decode(&msg_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid msg_id").into_response(),
    };

    // Fetch the post envelope
    let envelope_bytes = match state.storage.get_message(&msg_id) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return (StatusCode::NOT_FOUND, "post not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Storage error fetching news post");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    let envelope = match rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&envelope_bytes) {
        Ok(env) => env,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "corrupt envelope").into_response(),
    };

    let mut post = envelope_to_json(&envelope, &state.identity);

    // Enrich with engagement counts
    if let serde_json::Value::Object(ref mut map) = post {
        let reactions = state.storage.get_news_reactions(&msg_id).unwrap_or_default();
        let reaction_counts: serde_json::Map<String, serde_json::Value> = reactions
            .into_iter()
            .map(|(e, c)| (e, serde_json::json!(c)))
            .collect();
        map.insert("reaction_counts".into(), serde_json::json!(reaction_counts));
        map.insert(
            "repost_count".into(),
            serde_json::json!(state.storage.get_repost_count(&msg_id).unwrap_or(0)),
        );
        map.insert(
            "comment_count".into(),
            serde_json::json!(state.storage.get_comment_count(&msg_id).unwrap_or(0)),
        );
    }

    // Fetch comments (prefix scan NEWS_COMMENTS by post_id)
    let comments = match state.storage.prefix_iter_cf(cf::NEWS_COMMENTS, &msg_id, 200) {
        Ok(entries) => {
            let mut result = Vec::with_capacity(entries.len());
            for (key, _) in &entries {
                // Key: (post_id[32], timestamp[8], msg_id[32])
                if key.len() >= 72 {
                    let comment_id: [u8; 32] = key[40..72].try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(comment_bytes)) = state.storage.get_message(&comment_id) {
                        if let Ok(comment_env) = rmp_serde::from_slice::<
                            crate::messages::envelope::Envelope,
                        >(&comment_bytes)
                        {
                            result.push(envelope_to_json(&comment_env, &state.identity));
                        }
                    }
                }
            }
            result
        }
        Err(_) => Vec::new(),
    };

    Json(serde_json::json!({
        "post": post,
        "comments": comments,
    }))
    .into_response()
}

// --- Social endpoints (public) ---

/// GET /api/v1/users/:address/followers
pub async fn get_followers(
    Extension(state): Extension<Arc<AppState>>,
    Path(address): Path<String>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(200) as usize;
    match state.storage.get_followers(&address, limit) {
        Ok(followers) => {
            let (_, follower_count) = state.storage.get_follower_counts(&address).unwrap_or((0, 0));
            Json(serde_json::json!({
                "followers": followers,
                "total": follower_count,
                "page": params.page.unwrap_or(1),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in API handler");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// GET /api/v1/users/:address/following
pub async fn get_following(
    Extension(state): Extension<Arc<AppState>>,
    Path(address): Path<String>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(200) as usize;
    match state.storage.get_following(&address, limit) {
        Ok(following) => {
            let (following_count, _) = state.storage.get_follower_counts(&address).unwrap_or((0, 0));
            Json(serde_json::json!({
                "following": following,
                "total": following_count,
                "page": params.page.unwrap_or(1),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in API handler");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// --- Authenticated endpoint handlers ---

/// POST /api/v1/messages — submit a signed message envelope
pub async fn post_message(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { msg_id, .. } => {
            Json(MessageResponse {
                msg_id: hex::encode(msg_id),
            })
            .into_response()
        }
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "message already exists").into_response()
        }
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// PUT /api/v1/profile — submit a signed profile update
pub async fn update_profile(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "already processed").into_response()
        }
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// POST /api/v1/dm/:address — send an encrypted DM
pub async fn send_dm(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(_address): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { msg_id, .. } => {
            Json(MessageResponse {
                msg_id: hex::encode(msg_id),
            })
            .into_response()
        }
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "message already exists").into_response()
        }
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// GET /api/v1/dm/conversations — list DM conversations for the authenticated user.
pub async fn get_dm_conversations(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(1).max(1) as usize;
    let limit = params.limit.unwrap_or(20).min(100) as usize;
    let offset = (page - 1) * limit;

    let prefix = auth_user.address.as_bytes().to_vec();
    // Fetch enough entries to cover duplicates (each message creates a new entry per conversation).
    // We fetch a generous amount and deduplicate before paginating.
    let max_raw_entries = 2000;

    match state
        .storage
        .prefix_iter_cf(cf::DM_CONVERSATIONS, &prefix, max_raw_entries)
    {
        Ok(entries) => {
            // Deduplicate first: keep only the newest entry per conversation_id
            // (entries are in reverse-chronological order due to !timestamp, so first seen = newest)
            let mut seen_conversations = std::collections::HashSet::new();
            let mut unique_entries = Vec::new();
            let addr_len = auth_user.address.len();

            for (key, value) in entries {
                if key.len() < addr_len + 8 + 32 {
                    continue;
                }
                let conversation_id: [u8; 32] =
                    key[addr_len + 8..addr_len + 40].try_into().unwrap_or([0u8; 32]);
                if seen_conversations.insert(conversation_id) {
                    unique_entries.push((key, value));
                }
            }

            let total = unique_entries.len();
            let page_entries: Vec<_> = unique_entries.into_iter().skip(offset).take(limit).collect();

            let mut conversations = Vec::with_capacity(page_entries.len());

            for (key, value) in &page_entries {
                // Key layout: (wallet_address:44, !timestamp:8, conversation_id:32)
                if key.len() < addr_len + 8 + 32 {
                    continue;
                }
                let negated_ts_bytes: [u8; 8] =
                    key[addr_len..addr_len + 8].try_into().unwrap_or([0u8; 8]);
                let last_activity_ts = !u64::from_be_bytes(negated_ts_bytes);
                let conversation_id: [u8; 32] =
                    key[addr_len + 8..addr_len + 40].try_into().unwrap_or([0u8; 32]);

                // Value stores the peer address
                let peer = String::from_utf8_lossy(value).to_string();

                // Fetch last message preview from DM_MESSAGES
                let mut last_message_preview = String::new();
                // Fetch enough messages to find the newest (prefix_iter returns ascending order)
                if let Ok(msgs) = state
                    .storage
                    .prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, 500)
                {
                    if let Some((msg_key, _)) = msgs.last() {
                        if msg_key.len() >= 72 {
                            let msg_id: [u8; 32] =
                                msg_key[40..72].try_into().unwrap_or([0u8; 32]);
                            if let Ok(Some(env_bytes)) = state.storage.get_message(&msg_id) {
                                if let Ok(env) = rmp_serde::from_slice::<
                                    crate::messages::envelope::Envelope,
                                >(&env_bytes)
                                {
                                    // Try to extract content preview from payload
                                    if let Ok(payload) = rmp_serde::from_slice::<
                                        crate::messages::types::DirectMessagePayload,
                                    >(&env.payload)
                                    {
                                        let text =
                                            String::from_utf8_lossy(&payload.content);
                                        // Truncate to 100 chars for preview (char-safe boundary)
                                        last_message_preview = if text.chars().count() > 100 {
                                            let truncated: String = text.chars().take(97).collect();
                                            format!("{truncated}...")
                                        } else {
                                            text.to_string()
                                        };
                                    }
                                }
                            }
                        }
                    }
                }

                // Get unread count from DM_READ_STATE
                let read_key = crate::storage::schema::encode_dm_read_key(
                    &auth_user.address,
                    &conversation_id,
                );
                let last_read_ts =
                    match state.storage.get_cf(cf::DM_READ_STATE, &read_key) {
                        Ok(Some(bytes)) if bytes.len() == 8 => {
                            u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8]))
                        }
                        _ => 0,
                    };

                let mut unread_count = 0u64;
                if let Ok(msgs) =
                    state
                        .storage
                        .prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, 100)
                {
                    for (msg_key, _) in &msgs {
                        if msg_key.len() >= 40 {
                            let ts_bytes: [u8; 8] =
                                msg_key[32..40].try_into().unwrap_or([0u8; 8]);
                            let msg_ts = u64::from_be_bytes(ts_bytes);
                            if msg_ts > last_read_ts {
                                unread_count += 1;
                            }
                        }
                    }
                }

                conversations.push(serde_json::json!({
                    "conversation_id": hex::encode(conversation_id),
                    "peer": peer,
                    "last_message_at": last_activity_ts,
                    "last_message_preview": last_message_preview,
                    "unread_count": unread_count.min(99),
                }));
            }

            Json(serde_json::json!({
                "conversations": conversations,
                "total": total,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list DM conversations");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /api/v1/dm/:address/messages — retrieve DM messages with a specific user.
pub async fn get_dm_messages(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(address): Path<String>,
    Query(params): Query<MessageParams>,
) -> impl IntoResponse {
    if !address.starts_with("klv1") || address.len() != 44 {
        return (StatusCode::BAD_REQUEST, "invalid Klever address").into_response();
    }
    let limit = params.limit.unwrap_or(50).min(500) as usize;

    // Compute conversation_id from auth user + path address
    let conversation_id =
        crate::crypto::compute_conversation_id(&auth_user.address, &address);

    match state
        .storage
        .prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, limit)
    {
        Ok(entries) => {
            let mut messages = Vec::with_capacity(entries.len());
            for (key, _) in &entries {
                // Key: (conversation_id:32, timestamp:8, msg_id:32)
                if key.len() >= 72 {
                    let msg_id: [u8; 32] = key[40..72].try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(envelope_bytes)) = state.storage.get_message(&msg_id) {
                        if let Ok(envelope) = rmp_serde::from_slice::<
                            crate::messages::envelope::Envelope,
                        >(&envelope_bytes)
                        {
                            messages.push(envelope_to_json(&envelope, &state.identity));
                        }
                    }
                }
            }
            let has_more = entries.len() == limit;
            Json(serde_json::json!({
                "messages": messages,
                "has_more": has_more,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get DM messages");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// POST /api/v1/dm/:address/read — mark a DM conversation as read.
pub async fn mark_dm_read(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    if !address.starts_with("klv1") || address.len() != 44 {
        return (StatusCode::BAD_REQUEST, "invalid Klever address").into_response();
    }
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let conversation_id =
        crate::crypto::compute_conversation_id(&auth_user.address, &address);
    let key = crate::storage::schema::encode_dm_read_key(
        &auth_user.address,
        &conversation_id,
    );

    match state
        .storage
        .put_cf(cf::DM_READ_STATE, &key, &now_ms.to_be_bytes())
    {
        Ok(()) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to mark DM read");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /api/v1/dm/unread — get unread DM counts per conversation.
pub async fn get_dm_unread_counts(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Get all conversations for this user
    let prefix = auth_user.address.as_bytes().to_vec();
    let conversations = match state
        .storage
        .prefix_iter_cf(cf::DM_CONVERSATIONS, &prefix, 200)
    {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list DM conversations for unread");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let mut unread: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut seen_conversations = std::collections::HashSet::new();
    let addr_len = auth_user.address.len();

    for (key, _) in &conversations {
        if key.len() < addr_len + 8 + 32 {
            continue;
        }
        let conversation_id: [u8; 32] =
            key[addr_len + 8..addr_len + 40].try_into().unwrap_or([0u8; 32]);

        if !seen_conversations.insert(conversation_id) {
            continue;
        }

        // Get read cursor
        let read_key = crate::storage::schema::encode_dm_read_key(
            &auth_user.address,
            &conversation_id,
        );
        let last_read_ts = match state.storage.get_cf(cf::DM_READ_STATE, &read_key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8]))
            }
            _ => 0,
        };

        // Count unread messages
        if let Ok(msgs) = state
            .storage
            .prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, 100)
        {
            let mut count = 0u64;
            for (msg_key, _) in &msgs {
                if msg_key.len() >= 40 {
                    let ts_bytes: [u8; 8] =
                        msg_key[32..40].try_into().unwrap_or([0u8; 8]);
                    let msg_ts = u64::from_be_bytes(ts_bytes);
                    if msg_ts > last_read_ts {
                        count += 1;
                    }
                }
            }
            if count > 0 {
                unread.insert(
                    hex::encode(conversation_id),
                    serde_json::json!(count.min(99)),
                );
            }
        }
    }

    Json(serde_json::json!({ "unread": unread })).into_response()
}

/// POST /api/v1/users/:address/follow — follow a user (signed envelope)
pub async fn follow_user(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(_address): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// DELETE /api/v1/users/:address/follow — unfollow a user (signed envelope)
pub async fn unfollow_user(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(_address): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

// --- News Engagement endpoints ---

/// GET /api/v1/news/:msg_id/reactions
/// Supports optional auth header to include `user_reacted` per spec.
pub async fn get_news_reactions(
    Extension(state): Extension<Arc<AppState>>,
    auth_user: Option<Extension<AuthUser>>,
    Path(msg_id_hex): Path<String>,
) -> impl IntoResponse {
    let msg_id = match hex::decode(&msg_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid msg_id").into_response(),
    };

    let caller_address = auth_user.map(|a| a.0.address.clone());

    match state.storage.get_news_reactions(&msg_id) {
        Ok(reactions) => {
            let map: serde_json::Map<String, serde_json::Value> = reactions
                .into_iter()
                .map(|(emoji, count)| {
                    let mut entry = serde_json::json!({ "count": count });
                    if let Some(ref addr) = caller_address {
                        let reacted = state.storage
                            .has_user_reacted(&msg_id, &emoji, addr)
                            .unwrap_or(false);
                        entry["user_reacted"] = serde_json::json!(reacted);
                    }
                    (emoji, entry)
                })
                .collect();
            Json(serde_json::json!({ "reactions": map })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_news_reactions");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// POST /api/v1/news/:msg_id/react — react to a news post (authenticated)
pub async fn react_to_news(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(_msg_id_hex): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// POST /api/v1/news/:msg_id/repost — repost a news post (authenticated)
pub async fn repost_news(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(_msg_id_hex): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { msg_id, .. } => {
            Json(MessageResponse {
                msg_id: hex::encode(msg_id),
            })
            .into_response()
        }
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "already reposted").into_response()
        }
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// GET /api/v1/news/:msg_id/reposts
pub async fn get_news_reposts(
    Extension(state): Extension<Arc<AppState>>,
    Path(msg_id_hex): Path<String>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let msg_id = match hex::decode(&msg_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid msg_id").into_response(),
    };

    let limit = params.limit.unwrap_or(20).min(100) as usize;
    let prefix = msg_id.to_vec();

    match state
        .storage
        .prefix_iter_cf(cf::REPOSTS, &prefix, limit)
    {
        Ok(entries) => {
            let reposters: Vec<String> = entries
                .into_iter()
                .filter_map(|(key, _)| {
                    if key.len() > 32 {
                        String::from_utf8(key[32..].to_vec()).ok()
                    } else {
                        None
                    }
                })
                .collect();
            let total = state.storage.get_repost_count(&msg_id).unwrap_or(0);
            Json(serde_json::json!({
                "reposters": reposters,
                "total": total,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_news_reposts");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// --- Bookmark endpoints ---

/// GET /api/v1/bookmarks — list bookmarked posts (authenticated)
pub async fn list_bookmarks(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100) as usize;

    match state.storage.list_bookmarks(&auth_user.address, limit) {
        Ok(msg_ids) => {
            let mut bookmarks = Vec::with_capacity(msg_ids.len());
            for msg_id in &msg_ids {
                if let Ok(Some(envelope_bytes)) = state.storage.get_message(msg_id) {
                    if let Ok(envelope) = rmp_serde::from_slice::<
                        crate::messages::envelope::Envelope,
                    >(&envelope_bytes)
                    {
                        bookmarks.push(envelope_to_json(&envelope, &state.identity));
                    }
                }
            }
            let total = bookmarks.len();
            Json(serde_json::json!({
                "bookmarks": bookmarks,
                "total": total,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in list_bookmarks");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// POST /api/v1/bookmarks/:msg_id — save a post (authenticated)
pub async fn save_bookmark(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(msg_id_hex): Path<String>,
) -> impl IntoResponse {
    let msg_id = match hex::decode(&msg_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid msg_id").into_response(),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    match state.storage.add_bookmark(&auth_user.address, &msg_id, now) {
        Ok(()) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Storage error in save_bookmark");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// DELETE /api/v1/bookmarks/:msg_id — unsave a post (authenticated)
pub async fn remove_bookmark(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(msg_id_hex): Path<String>,
) -> impl IntoResponse {
    let msg_id = match hex::decode(&msg_id_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid msg_id").into_response(),
    };

    match state.storage.remove_bookmark(&auth_user.address, &msg_id) {
        Ok(_) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Storage error in remove_bookmark");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

// --- Channel Administration endpoints ---

/// GET /api/v1/channels/:channel_id/members
pub async fn get_channel_members(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<u64>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(200) as usize;
    let prefix = channel_id.to_be_bytes();

    match state
        .storage
        .prefix_iter_cf(cf::CHANNEL_MEMBERS, &prefix, limit)
    {
        Ok(entries) => {
            let members: Vec<serde_json::Value> = entries
                .into_iter()
                .filter_map(|(key, value)| {
                    if key.len() > 8 {
                        let address = String::from_utf8(key[8..].to_vec()).ok()?;
                        let record: serde_json::Value =
                            serde_json::from_slice(&value).unwrap_or_default();
                        Some(serde_json::json!({
                            "address": address,
                            "role": record.get("role").unwrap_or(&serde_json::json!("member")),
                            "joined_at": record.get("joined_at").unwrap_or(&serde_json::json!(0)),
                        }))
                    } else {
                        None
                    }
                })
                .collect();
            let total = members.len();
            Json(serde_json::json!({
                "members": members,
                "total": total,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_channel_members");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// GET /api/v1/channels/:channel_id/pins
pub async fn get_channel_pins(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    let prefix = channel_id.to_be_bytes();

    match state
        .storage
        .prefix_iter_cf(cf::CHANNEL_PINS, &prefix, 10)
    {
        Ok(entries) => {
            let mut pinned_messages = Vec::with_capacity(entries.len());
            for (key, _) in &entries {
                // Key: channel_id(8) + pin_order(4) + msg_id(32)
                if key.len() >= 44 {
                    let msg_id: [u8; 32] = key[12..44].try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(envelope_bytes)) = state.storage.get_message(&msg_id) {
                        if let Ok(envelope) = rmp_serde::from_slice::<
                            crate::messages::envelope::Envelope,
                        >(&envelope_bytes)
                        {
                            pinned_messages
                                .push(envelope_to_json(&envelope, &state.identity));
                        }
                    }
                }
            }
            Json(serde_json::json!({
                "pinned_messages": pinned_messages,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_channel_pins");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// GET /api/v1/channels/:channel_id/bans
pub async fn get_channel_bans(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    let prefix = channel_id.to_be_bytes();

    match state
        .storage
        .prefix_iter_cf(cf::CHANNEL_BANS, &prefix, 200)
    {
        Ok(entries) => {
            let bans: Vec<serde_json::Value> = entries
                .into_iter()
                .filter_map(|(key, value)| {
                    if key.len() > 8 {
                        let address = String::from_utf8(key[8..].to_vec()).ok()?;
                        let record: serde_json::Value =
                            serde_json::from_slice(&value).unwrap_or_default();
                        Some(serde_json::json!({
                            "address": address,
                            "reason": record.get("reason"),
                            "duration_secs": record.get("duration_secs"),
                            "banned_at": record.get("banned_at"),
                            "banned_by": record.get("banned_by"),
                        }))
                    } else {
                        None
                    }
                })
                .collect();
            Json(serde_json::json!({ "bans": bans })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_channel_bans");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// POST /api/v1/channels/:channel_id/moderators — add moderator (authenticated, creator only)
pub async fn add_moderator(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path(_channel_id): Path<u64>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// DELETE /api/v1/channels/:channel_id/moderators/:address — remove moderator (authenticated)
pub async fn remove_moderator(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path((_channel_id, _address)): Path<(u64, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// POST /api/v1/channels/:channel_id/kick/:address — kick user (authenticated)
pub async fn kick_user(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path((_channel_id, _address)): Path<(u64, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
    }
}

/// POST /api/v1/channels/:channel_id/ban/:address — ban user (authenticated)
pub async fn ban_user(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path((_channel_id, _address)): Path<(u64, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
    }
}

/// DELETE /api/v1/channels/:channel_id/ban/:address — unban user (authenticated)
pub async fn unban_user(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path((_channel_id, _address)): Path<(u64, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
    }
}

/// POST /api/v1/channels/:channel_id/pin/:msg_id — pin message (authenticated)
pub async fn pin_message(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path((_channel_id, _msg_id)): Path<(u64, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
    }
}

/// DELETE /api/v1/channels/:channel_id/pin/:msg_id — unpin message (authenticated)
pub async fn unpin_message(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path((_channel_id, _msg_id)): Path<(u64, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
    }
}

/// POST /api/v1/channels/:channel_id/invite/:address — invite user (authenticated)
pub async fn invite_user(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    Path((_channel_id, _address)): Path<(u64, String)>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;

    match state.router.process_message(&body) {
        RouteResult::Accepted { .. } => Json(OkResponse { ok: true }).into_response(),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
    }
}

/// GET /api/v1/feed — personal news feed (posts from followed users)
pub async fn personal_feed(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100) as usize;

    // Cap following fan-out to 200 to prevent O(N*M) DDoS (audit W1/W6)
    let following = match state.storage.get_following(&auth_user.address, 200) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "Storage error in feed handler");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    if following.is_empty() {
        return Json(serde_json::json!({
            "posts": [],
            "total": 0,
            "page": params.page.unwrap_or(1),
        }))
        .into_response();
    }

    // Collect posts from each followed user
    let mut all_posts: Vec<(u64, Vec<u8>)> = Vec::new();
    for author in &following {
        let mut author_prefix = Vec::with_capacity(author.len() + 1);
        author_prefix.extend_from_slice(author.as_bytes());
        author_prefix.push(0xFF);

        if let Ok(entries) = state.storage.prefix_iter_cf(
            crate::storage::schema::cf::NEWS_BY_AUTHOR,
            &author_prefix,
            limit,
        ) {
            for (key, _) in entries {
                let suffix_start = author.len() + 1;
                if key.len() >= suffix_start + 40 {
                    let msg_id: [u8; 32] =
                        key[suffix_start + 8..suffix_start + 40].try_into().unwrap_or([0u8; 32]);
                    let neg_ts: [u8; 8] =
                        key[suffix_start..suffix_start + 8].try_into().unwrap_or([0u8; 8]);
                    let timestamp = !u64::from_be_bytes(neg_ts);
                    if let Ok(Some(env_bytes)) = state.storage.get_message(&msg_id) {
                        all_posts.push((timestamp, env_bytes));
                    }
                }
            }
        }
    }

    // Sort newest first, apply limit
    all_posts.sort_by(|a, b| b.0.cmp(&a.0));
    all_posts.truncate(limit);

    let posts: Vec<serde_json::Value> = all_posts
        .iter()
        .filter_map(|(_, bytes)| {
            rmp_serde::from_slice::<crate::messages::envelope::Envelope>(bytes)
                .ok()
                .and_then(|env| serde_json::to_value(&env).ok())
        })
        .collect();

    Json(serde_json::json!({
        "posts": posts,
        "total": posts.len(),
        "page": params.page.unwrap_or(1),
    }))
    .into_response()
}

// --- Media endpoints ---

/// POST /api/v1/media/upload — upload a file to IPFS (authenticated).
pub async fn upload_media(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let ipfs = match &state.ipfs {
        Some(c) => c,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "IPFS not configured").into_response(),
    };

    // Extract the first file field from the multipart form
    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => return (StatusCode::BAD_REQUEST, "no file in request").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "multipart parse error");
            return (StatusCode::BAD_REQUEST, "invalid multipart data").into_response();
        }
    };

    let filename = field.file_name().map(|s| s.to_string());
    let content_type = field.content_type().unwrap_or("application/octet-stream").to_string();

    let data = match field.bytes().await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read upload body");
            return (StatusCode::BAD_REQUEST, "failed to read file data").into_response();
        }
    };

    match ipfs.upload(data, filename, &content_type).await {
        Ok(result) => {
            tracing::info!(cid = %result.cid, user = %auth_user.address, size = result.size, "Media uploaded");
            Json(serde_json::json!({
                "cid": result.cid,
                "size": result.size,
                "mime_type": result.mime_type,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(user = %auth_user.address, error = %e, "IPFS upload failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "upload failed").into_response()
        }
    }
}

/// GET /api/v1/media/:cid — retrieve media from IPFS (public).
pub async fn get_media(
    Extension(state): Extension<Arc<AppState>>,
    Path(cid): Path<String>,
) -> impl IntoResponse {
    let ipfs = match &state.ipfs {
        Some(c) => c,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "IPFS not configured").into_response(),
    };

    match ipfs.get(&cid).await {
        Ok(data) => {
            // Detect content type from first bytes (basic magic number detection)
            let content_type = detect_content_type(&data);
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable".to_string()),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                ],
                data,
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(cid = %cid, error = %e, "IPFS retrieval failed");
            (StatusCode::NOT_FOUND, "media not found").into_response()
        }
    }
}

// --- Device Registration Endpoints ---

/// Maximum allowed clock skew for device claim timestamps (5 minutes).
const MAX_CLAIM_AGE_MS: u64 = 300_000;

/// Maximum devices per wallet (prevents abuse).
const MAX_DEVICES_PER_WALLET: usize = 10;

/// Request body for device registration.
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    /// Hex-encoded device Ed25519 public key (64 hex chars = 32 bytes).
    pub device_pubkey_hex: String,
    /// Wallet address that authorized this device (klv1...).
    pub wallet_address: String,
    /// Wallet signature over the claim string (hex-encoded, 128 hex chars = 64 bytes).
    pub wallet_signature: String,
    /// Unix timestamp (ms) from the claim string.
    pub timestamp: u64,
}

/// POST /api/v1/devices/register — register a device key under a wallet.
///
/// Verifies the wallet-signed claim:
///   claim = "ogmara-device-claim:{device_pubkey_hex}:{wallet_address}:{timestamp}"
///   signed by wallet key using Klever message signing format.
pub async fn register_device(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Json(body): Json<RegisterDeviceRequest>,
) -> impl IntoResponse {
    // Normalize hex to lowercase for canonical storage
    let device_pubkey_hex = body.device_pubkey_hex.to_ascii_lowercase();

    // Validate device pubkey hex format (must be 64 hex chars = 32 bytes)
    if device_pubkey_hex.len() != 64 {
        return (StatusCode::BAD_REQUEST, "device_pubkey_hex must be 64 hex characters").into_response();
    }
    let device_pubkey_bytes = match hex::decode(&device_pubkey_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid device_pubkey_hex").into_response(),
    };

    // Derive the device's klv1... address from the public key
    let device_verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&device_pubkey_bytes) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid Ed25519 public key").into_response(),
    };
    let device_address = match crate::crypto::pubkey_to_address(&device_verifying_key) {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "failed to derive device address").into_response(),
    };

    // Validate wallet address format
    if crate::crypto::address_to_verifying_key(&body.wallet_address).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid wallet_address").into_response();
    }

    // Caller must be either the device being registered or the owning wallet.
    // This prevents relaying intercepted signed claims.
    if auth_user.signing_address != device_address && auth_user.address != body.wallet_address {
        return (StatusCode::FORBIDDEN, "caller must be the device or owning wallet").into_response();
    }

    // Check timestamp freshness
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let age = now_ms.abs_diff(body.timestamp);
    if age > MAX_CLAIM_AGE_MS {
        return (StatusCode::BAD_REQUEST, "claim timestamp expired or too far in future").into_response();
    }

    // Build the claim string and verify the wallet signature.
    // Uses the original (non-normalized) hex from the request, since the wallet
    // signed this exact string. Signature verification must match what was signed.
    let claim_string = format!(
        "ogmara-device-claim:{}:{}:{}",
        body.device_pubkey_hex, body.wallet_address, body.timestamp
    );

    let sig_bytes = match hex::decode(&body.wallet_signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, "invalid wallet_signature hex").into_response(),
    };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid signature bytes").into_response(),
    };

    let wallet_verifying_key = match crate::crypto::address_to_verifying_key(&body.wallet_address) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid wallet_address").into_response(),
    };

    // Verify using Klever message signing format (same as wallet UIs use)
    if let Err(_) = crate::crypto::signing::verify_klever_message(
        &wallet_verifying_key,
        claim_string.as_bytes(),
        &signature,
    ) {
        return (StatusCode::UNAUTHORIZED, "wallet signature verification failed").into_response();
    }

    // Check device limit per wallet
    match state.identity.list_devices(&body.wallet_address) {
        Ok(existing) => {
            let is_update = existing.iter().any(|c| c.device_address == device_address);
            if !is_update && existing.len() >= MAX_DEVICES_PER_WALLET {
                return (
                    StatusCode::CONFLICT,
                    "maximum devices per wallet reached",
                ).into_response();
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list devices");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }

    // Store the claim (with normalized lowercase hex for consistency)
    let claim = crate::storage::rocks::DeviceClaim {
        device_address: device_address.clone(),
        wallet_address: body.wallet_address.clone(),
        device_pubkey_hex,
        wallet_signature: body.wallet_signature,
        registered_at: body.timestamp,
    };

    match state.identity.register_device(&claim) {
        Ok(()) => {
            // Migrate read state from device address to wallet address.
            // If the user was using a device key before registering, their
            // channel/DM read cursors are stored under the device address.
            if device_address != body.wallet_address {
                let device_prefix = device_address.as_bytes();
                // Channel read state
                if let Ok(entries) = state.storage.prefix_iter_cf(cf::CHANNEL_READ_STATE, device_prefix, 500) {
                    for (old_key, value) in &entries {
                        // Extract channel_id from old key: (device_addr, 0xFF, channel_id:8)
                        let sep_pos = device_address.len();
                        if old_key.len() >= sep_pos + 1 + 8 && old_key[sep_pos] == 0xFF {
                            let channel_id_bytes: [u8; 8] = old_key[sep_pos + 1..sep_pos + 9].try_into().unwrap_or([0u8; 8]);
                            let channel_id = u64::from_be_bytes(channel_id_bytes);
                            let new_key = crate::storage::schema::encode_channel_read_key(&body.wallet_address, channel_id);
                            // Only migrate if wallet doesn't already have a cursor for this channel
                            if let Ok(None) = state.storage.get_cf(cf::CHANNEL_READ_STATE, &new_key) {
                                let _ = state.storage.put_cf(cf::CHANNEL_READ_STATE, &new_key, value);
                            }
                        }
                    }
                }
                // DM read state
                if let Ok(entries) = state.storage.prefix_iter_cf(cf::DM_READ_STATE, device_prefix, 500) {
                    for (old_key, value) in &entries {
                        let sep_pos = device_address.len();
                        if old_key.len() >= sep_pos + 1 + 32 && old_key[sep_pos] == 0xFF {
                            let mut conv_id = [0u8; 32];
                            conv_id.copy_from_slice(&old_key[sep_pos + 1..sep_pos + 33]);
                            let new_key = crate::storage::schema::encode_dm_read_key(&body.wallet_address, &conv_id);
                            if let Ok(None) = state.storage.get_cf(cf::DM_READ_STATE, &new_key) {
                                let _ = state.storage.put_cf(cf::DM_READ_STATE, &new_key, value);
                            }
                        }
                    }
                }
            }

            tracing::info!(
                device = %device_address,
                wallet = %body.wallet_address,
                registered_by = %auth_user.signing_address,
                "Device registered"
            );
            Json(serde_json::json!({
                "ok": true,
                "device_address": device_address,
                "wallet_address": body.wallet_address,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to register device");
            (StatusCode::INTERNAL_SERVER_ERROR, "registration failed").into_response()
        }
    }
}

/// DELETE /api/v1/devices/{device_address} — revoke a device registration.
///
/// Only the owning wallet can revoke a device. The authenticated user's
/// resolved wallet address must match the device's registered wallet.
///
/// By design, any device registered to the wallet can revoke sibling devices
/// (since auth resolves device → wallet). This enables device management from
/// any active device without requiring the wallet key directly.
pub async fn revoke_device(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(device_address): Path<String>,
) -> impl IntoResponse {
    // Validate device address format
    if crate::crypto::address_to_verifying_key(&device_address).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid device address").into_response();
    }

    // The authenticated wallet must own this device
    match state.identity.revoke_device(&device_address, &auth_user.address) {
        Ok(true) => {
            tracing::info!(
                device = %device_address,
                wallet = %auth_user.address,
                "Device revoked"
            );
            Json(serde_json::json!({ "ok": true, "device_address": device_address })).into_response()
        }
        Ok(false) => {
            (StatusCode::NOT_FOUND, "device not registered to this wallet").into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to revoke device");
            (StatusCode::INTERNAL_SERVER_ERROR, "revocation failed").into_response()
        }
    }
}

/// GET /api/v1/devices — list devices registered to the authenticated wallet.
pub async fn list_devices(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    match state.identity.list_devices(&auth_user.address) {
        Ok(devices) => {
            let device_list: Vec<serde_json::Value> = devices
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "device_address": d.device_address,
                        "device_pubkey_hex": d.device_pubkey_hex,
                        "registered_at": d.registered_at,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "wallet_address": auth_user.address,
                "devices": device_list,
                "total": device_list.len(),
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list devices");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

// --- Channel Read State ---

/// POST /api/v1/channels/{channel_id}/read — mark a channel as read.
///
/// Stores the current wall-clock timestamp as the read cursor.
/// The unread counter compares message lamport_ts (which mirrors wall clock)
/// against this cursor.
pub async fn mark_channel_read(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let key = crate::storage::schema::encode_channel_read_key(&auth_user.address, channel_id);
    match state.storage.put_cf(cf::CHANNEL_READ_STATE, &key, &now_ms.to_be_bytes()) {
        Ok(()) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to mark channel read");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /api/v1/channels/unread — get unread message counts for all channels.
///
/// For each channel, compares the user's read cursor (last_read_ts) against
/// the latest messages in that channel.
pub async fn get_unread_counts(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    // Get all channels
    let channels = match state.storage.prefix_iter_cf(cf::CHANNELS, &[], 100) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list channels for unread");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let mut unread: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    for (key, _) in &channels {
        // Channel keys are channel_id as u64 BE bytes
        if key.len() < 8 { continue; }
        let channel_id = u64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));

        // Get the user's read cursor for this channel
        let read_key = crate::storage::schema::encode_channel_read_key(&auth_user.address, channel_id);
        let last_read_ts = match state.storage.get_cf(cf::CHANNEL_READ_STATE, &read_key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8]))
            }
            _ => 0, // Never read — everything is unread
        };

        // Count messages newer than last_read_ts by checking envelope timestamps
        let prefix = channel_id.to_be_bytes();
        if let Ok(msgs) = state.storage.prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, 100) {
            let mut count = 0u64;
            for (msg_key, _) in &msgs {
                // Key: (channel_id:8, lamport_ts:8, msg_id:32)
                if msg_key.len() >= 48 {
                    let msg_id: [u8; 32] = msg_key[16..48].try_into().unwrap_or([0u8; 32]);
                    if let Ok(Some(env_bytes)) = state.storage.get_message(&msg_id) {
                        if let Ok(env) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&env_bytes) {
                            if env.timestamp > last_read_ts {
                                count += 1;
                            }
                        }
                    }
                }
            }
            if count > 0 {
                unread.insert(channel_id.to_string(), serde_json::json!(count.min(99)));
            }
        }
    }

    Json(serde_json::json!({ "unread": unread })).into_response()
}

/// Basic content type detection from file magic bytes.
fn detect_content_type(data: &[u8]) -> String {
    if data.starts_with(b"\x89PNG") {
        "image/png".to_string()
    } else if data.starts_with(b"\xFF\xD8\xFF") {
        "image/jpeg".to_string()
    } else if data.starts_with(b"GIF8") {
        "image/gif".to_string()
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        "image/webp".to_string()
    } else if data.starts_with(b"%PDF") {
        "application/pdf".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}
