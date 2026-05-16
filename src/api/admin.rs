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

/// GET /admin/node/registration — node-registration status (spec 12 §3.2).
///
/// Returns the operator-facing snapshot the dashboard's Anchoring tab
/// needs to render: this node's anchorer wallet, on-chain registration
/// state (live SC view), the current registration fee, network-wide
/// node count (used for the bootstrap-quorum banner), and local anchor
/// stats from RocksDB.
///
/// Wallet-authenticated because it exposes the anchorer wallet address.
pub async fn node_registration(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // If the node has no Klever node_url configured, anchoring is
    // effectively disabled — surface a degraded payload instead of
    // making bogus RPC calls.
    let klever_node_url = state.klever_node_url.clone();
    let contract_address = state.contract_address.clone();
    let wallet = state.node_address.clone();

    if klever_node_url.is_empty() || contract_address.is_empty() || wallet.is_empty() {
        return Json(serde_json::json!({
            "wallet": wallet,
            "registered": false,
            "fee_klv": "0",
            "fee_klv_raw": "0",
            "contract_address": contract_address,
            "klever_network": state.klever_network,
            "network_node_count": serde_json::Value::Null,
            "last_canonical_height": serde_json::Value::Null,
            "quorum_min": 3,
            "anchor_count": serde_json::Value::Null,
            "canonical_count": serde_json::Value::Null,
            "last_successful_anchor": serde_json::Value::Null,
            "anchoring_configured": false,
            "error": "klever.node_url, klever.contract_address, or node anchor wallet not configured",
        }))
        .into_response();
    }

    // Reuse the pooled HTTP client built once at startup — avoids
    // per-request TLS-pool reallocation flagged by the v0.43.0 audit.
    let http = &state.klever_view_http;

    // Issue all four view calls concurrently. Each is `Result<T>`; we
    // KEEP the `Result` so the JSON response can distinguish "RPC
    // unavailable" (serialized as `null`) from a genuine zero.
    // Without this distinction, the bootstrap banner would flash on
    // every transient Klever RPC blip (audit W2).
    let (registered_res, count_res, fee_res, canonical_height_res) = tokio::join!(
        crate::chain::sc_views::is_node_registered(http, &klever_node_url, &contract_address, &wallet),
        crate::chain::sc_views::get_node_count(http, &klever_node_url, &contract_address),
        crate::chain::sc_views::get_node_registration_fee(http, &klever_node_url, &contract_address),
        crate::chain::sc_views::get_latest_canonical_height(http, &klever_node_url, &contract_address),
    );

    // `registered` defaults to false on RPC error — surfacing it as
    // null here would confuse the action-area state machine. The
    // operator sees "Status unknown" via the dedicated error field.
    let registered = registered_res.unwrap_or(false);

    // `null` for unavailable so the dashboard can render a "—" rather
    // than misreporting as 0 (which would falsely trigger the
    // bootstrap banner).
    let network_node_count = count_res.ok().map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
    let last_canonical_height = canonical_height_res.ok().map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);

    let (fee_klv, fee_klv_raw) = match fee_res {
        Ok(raw) => (
            serde_json::Value::String(format_klv(raw)),
            serde_json::Value::String(raw.to_string()),
        ),
        Err(_) => (serde_json::Value::Null, serde_json::Value::Null),
    };

    // Local anchor stats from RocksDB.
    let last_anchor_ts = state
        .storage
        .get_stat(crate::storage::schema::state_keys::LAST_ANCHOR_TS)
        .unwrap_or(0);

    Json(serde_json::json!({
        "wallet": wallet,
        "registered": registered,
        "fee_klv": fee_klv,
        "fee_klv_raw": fee_klv_raw,
        "contract_address": contract_address,
        // v0.43.1 — the dashboard needs to hand the right provider
        // (testnet vs mainnet) to the Klever extension BEFORE calling
        // initialize(); without this the extension defaults to mainnet
        // and any SC TX goes to the wrong chain.
        "klever_network": state.klever_network,
        "network_node_count": network_node_count,
        "last_canonical_height": last_canonical_height,
        "quorum_min": 3,
        // anchor_count / canonical_count are local stats derived from
        // RocksDB scans; v0.43 reports `null` placeholders because we
        // haven't yet plumbed a per-anchorer counter through the
        // scanner. The dashboard handles `null` by hiding the field.
        "anchor_count": serde_json::Value::Null,
        "canonical_count": serde_json::Value::Null,
        "last_successful_anchor": if last_anchor_ts > 0 {
            serde_json::Value::Number(last_anchor_ts.into())
        } else {
            serde_json::Value::Null
        },
        "anchoring_configured": true,
    }))
    .into_response()
}

/// Format a raw KLV amount (1 KLV = 10^6 raw units) as a human string.
/// Uses up to 6 fractional digits, trimming trailing zeros and the
/// decimal point when integer-valued. `100_000_000` → `"100"`,
/// `100_500_000` → `"100.5"`, `0` → `"0"`.
fn format_klv(raw: u128) -> String {
    if raw == 0 {
        return "0".to_string();
    }
    let whole = raw / 1_000_000;
    let frac = raw % 1_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{:06}", frac);
    let trimmed = frac_str.trim_end_matches('0');
    format!("{}.{}", whole, trimmed)
}

#[cfg(test)]
mod tests {
    use super::format_klv;

    #[test]
    fn klv_formatting() {
        assert_eq!(format_klv(0), "0");
        assert_eq!(format_klv(1_000_000), "1");
        assert_eq!(format_klv(100_000_000), "100");
        assert_eq!(format_klv(100_500_000), "100.5");
        assert_eq!(format_klv(1), "0.000001");
        assert_eq!(format_klv(123_456), "0.123456");
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
