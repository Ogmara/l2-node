//! Admin-only endpoints (spec 4.4).
//!
//! Only accessible from localhost. Provides node operator controls
//! for peer management, storage stats, and state anchoring.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use super::state::AppState;

/// Middleware that restricts access to localhost only.
pub async fn localhost_only(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if addr.ip().is_loopback() {
        next.run(req).await
    } else {
        (StatusCode::FORBIDDEN, "admin endpoints are localhost-only").into_response()
    }
}

// --- Admin handlers ---

/// GET /admin/peers — list connected peers.
pub async fn list_peers(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "peers": [],
        "total": state.peer_count(),
    }))
}

/// GET /admin/storage/stats — disk usage and message counts.
pub async fn storage_stats(
    Extension(_state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // Storage stats will be populated when we have counters
    Json(serde_json::json!({
        "status": "ok",
        "column_families": [
            "messages", "channel_msgs", "dm_messages", "dm_conversations",
            "news_feed", "news_by_tag", "news_by_author", "users",
            "channels", "delegations", "state_anchors", "peer_directory",
            "content_cache", "node_state"
        ],
    }))
}

/// POST /admin/peers/ban — ban a misbehaving peer.
#[derive(Deserialize)]
pub struct BanPeerRequest {
    pub node_id: String,
}

pub async fn ban_peer(
    Extension(_state): Extension<Arc<AppState>>,
    Json(req): Json<BanPeerRequest>,
) -> impl IntoResponse {
    tracing::info!(node_id = %req.node_id, "Peer banned (admin)");
    Json(serde_json::json!({ "ok": true, "banned": req.node_id }))
}

/// POST /admin/channels/pin — pin a channel for permanent storage.
#[derive(Deserialize)]
pub struct PinChannelRequest {
    pub channel_id: u64,
}

pub async fn pin_channel(
    Extension(_state): Extension<Arc<AppState>>,
    Json(req): Json<PinChannelRequest>,
) -> impl IntoResponse {
    tracing::info!(channel_id = req.channel_id, "Channel pinned (admin)");
    Json(serde_json::json!({ "ok": true, "pinned": req.channel_id }))
}

/// GET /admin/state/latest — current Merkle root and stats.
pub async fn state_latest(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let storage = state.storage.clone();
    match tokio::task::spawn_blocking(move || storage.compute_current_state_root()).await {
        Ok(Ok((root, msg_count, chan_count, user_count))) => {
            let anchor_height = state.storage.get_chain_cursor().unwrap_or(0);
            let last_anchor_ts = state
                .storage
                .get_stat(crate::storage::schema::state_keys::LAST_ANCHOR_TS)
                .unwrap_or(0);
            Json(serde_json::json!({
                "state_root": hex::encode(root),
                "message_count": msg_count,
                "channel_count": chan_count,
                "user_count": user_count,
                "latest_anchor_height": anchor_height,
                "last_anchor_ts": if last_anchor_ts > 0 { Some(last_anchor_ts) } else { None },
            }))
            .into_response()
        }
        Ok(Err(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("error: {}", e)).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("task failed: {}", e)).into_response()
        }
    }
}

/// POST /admin/state/anchor — trigger immediate state anchoring.
pub async fn trigger_anchor(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let trigger = match &state.anchor_trigger {
        Some(tx) => tx.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "state anchoring not enabled" })),
            )
                .into_response();
        }
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if trigger.send(reply_tx).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "anchoring task not running" })),
        )
            .into_response();
    }

    match reply_rx.await {
        Ok(Ok(tx_hash)) => Json(serde_json::json!({
            "ok": true,
            "tx_hash": tx_hash,
        }))
        .into_response(),
        Ok(Err(err)) => {
            tracing::error!(error = %err, "State anchor failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": err })),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "anchoring task dropped reply channel" })),
        )
            .into_response(),
    }
}
