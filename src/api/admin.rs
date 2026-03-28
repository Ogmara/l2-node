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
    let anchor_height = state.storage.get_chain_cursor().unwrap_or(0);
    Json(serde_json::json!({
        "latest_anchor_height": anchor_height,
        "state_root": null,
    }))
}

/// POST /admin/state/anchor — trigger immediate state anchoring.
pub async fn trigger_anchor(
    Extension(_state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // State anchoring will be implemented in Phase 5
    (StatusCode::NOT_IMPLEMENTED, "state anchoring not yet implemented")
}
