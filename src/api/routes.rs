//! Public and authenticated REST endpoint handlers.
//!
//! Public endpoints (spec 4.1): health, stats, channels, news, users.
//! Authenticated endpoints (spec 4.2): messages, profile, DMs, notifications.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::storage::schema::cf;

use super::auth::AuthUser;
use super::state::AppState;

/// Convert an Envelope's byte-array fields (msg_id, payload, signature) to hex strings
/// in the JSON representation. serde serializes [u8; 32] and Vec<u8> as number arrays,
/// but the API should return hex strings for client consumption.
fn envelope_to_json(envelope: &crate::messages::envelope::Envelope) -> serde_json::Value {
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
                            messages.push(envelope_to_json(&envelope));
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
    match state.storage.get_cf(cf::USERS, address.as_bytes()) {
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
                            let mut post = envelope_to_json(&envelope);
                            // Enrich with engagement counts per spec
                            if let serde_json::Value::Object(ref mut map) = post {
                                let reactions = state.storage.get_news_reactions(&msg_id).unwrap_or_default();
                                let reaction_counts: serde_json::Map<String, serde_json::Value> = reactions
                                    .into_iter()
                                    .map(|(e, c)| (e, serde_json::json!(c)))
                                    .collect();
                                map.insert("reaction_counts".into(), serde_json::json!(reaction_counts));
                                map.insert("repost_count".into(),
                                    serde_json::json!(state.storage.get_repost_count(&msg_id).unwrap_or(0)));
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
                        bookmarks.push(envelope_to_json(&envelope));
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
                                .push(envelope_to_json(&envelope));
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
