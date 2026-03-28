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

use crate::storage::rocks::Storage;
use crate::storage::schema::cf;

use super::auth::AuthUser;
use super::state::AppState;

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
    pub peers: u32,
    pub total_messages: u64,
    pub total_channels: u64,
    pub total_users: u64,
    pub uptime_seconds: u64,
    pub protocol_version: u8,
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
    Json(StatsResponse {
        node_id: state.node_id.clone(),
        peers: state.peer_count(),
        total_messages: 0, // TODO: track in storage
        total_channels: 0,
        total_users: 0,
        uptime_seconds: uptime,
        protocol_version: 1,
    })
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

/// GET /api/v1/channels/:channel_id
pub async fn get_channel(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    match state
        .storage
        .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())
    {
        Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(channel) => Json(serde_json::json!({ "channel": channel })).into_response(),
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
                            messages.push(serde_json::to_value(&envelope).unwrap_or_default());
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
                            posts.push(serde_json::to_value(&envelope).unwrap_or_default());
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
