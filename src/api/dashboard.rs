//! Embedded admin dashboard — serves a multi-section SPA and provides
//! REST endpoints and WebSocket for real-time metrics updates.
//!
//! Spec 10-dashboard.md: bundled into the binary via `include_str!`,
//! no external CDN dependencies, works fully offline/air-gapped.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Query};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::metrics::MetricsSnapshot;

use super::state::AppState;

/// Maximum concurrent dashboard WebSocket connections (prevents local DoS).
const MAX_DASHBOARD_WS: usize = 10;

// ── Dashboard page ──────────────────────────────────────────────────

/// GET /admin/dashboard — serve the embedded HTML dashboard.
pub async fn dashboard_page() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

// ── WebSocket ───────────────────────────────────────────────────────

/// Active WebSocket connection counter.
static WS_CONNECTIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// GET /admin/dashboard/ws — WebSocket for real-time metric updates (2s push).
pub async fn dashboard_ws(
    ws: WebSocketUpgrade,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // Atomically increment if under limit (prevents race between check and increment)
    let acquired = WS_CONNECTIONS.fetch_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |current| if current < MAX_DASHBOARD_WS { Some(current + 1) } else { None },
    );
    if acquired.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many dashboard connections")
            .into_response();
    }
    ws.on_upgrade(move |socket| handle_dashboard_ws(socket, state))
        .into_response()
}

async fn handle_dashboard_ws(socket: WebSocket, state: Arc<AppState>) {
    use futures::{SinkExt, StreamExt};

    // Connection already counted by the atomic fetch_update in dashboard_ws()
    debug!("Dashboard WebSocket connected");

    let (mut sender, mut receiver) = socket.split();
    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let snapshot = state
                    .metrics_latest
                    .read()
                    .map(|s| *s)
                    .unwrap_or_default();

                let msg = build_ws_payload(&state, &snapshot);
                match serde_json::to_string(&msg) {
                    Ok(json) => {
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {} // ignore pings, pongs, text from client
                }
            }
        }
    }

    WS_CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    debug!("Dashboard WebSocket disconnected");
}

/// Build the WebSocket payload from a metrics snapshot and live state.
fn build_ws_payload(state: &AppState, snap: &MetricsSnapshot) -> serde_json::Value {
    let uptime = state.started_at.elapsed().as_secs();

    serde_json::json!({
        "type": "metrics",
        "version": 2,
        "timestamp": chrono::Utc::now().timestamp(),
        "data": {
            "node": {
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": crate::messages::envelope::PROTOCOL_VERSION,
                "uptime_seconds": uptime,
                "network": &state.klever_network,
                "node_id": &state.node_id,
            },
            "system": {
                "cpu_percent": snap.cpu_percent,
                "memory_used_bytes": snap.memory_used_bytes,
                "memory_total_bytes": snap.memory_total_bytes,
                "disk_used_bytes": snap.disk_used_bytes,
                "disk_total_bytes": snap.disk_total_bytes,
            },
            "network": {
                "peers_connected": snap.peers_connected,
                "bandwidth_in_bytes_sec": snap.bandwidth_in_bytes_sec,
                "bandwidth_out_bytes_sec": snap.bandwidth_out_bytes_sec,
                "messages_received_sec": snap.messages_received_sec,
                "messages_relayed_sec": snap.messages_relayed_sec,
                "messages_received_total": snap.messages_received_total,
                "messages_relayed_total": snap.messages_relayed_total,
                "messages_stored_total": snap.messages_stored_total,
                "failed_validations_total": snap.failed_validations_total,
                "rate_limited_total": snap.rate_limited_total,
                "pow_required_total": snap.pow_required_total,
            },
            "storage": {
                "db_size_bytes": snap.db_size_bytes,
                "messages_total": snap.messages_total,
                "channel_messages_total": snap.channel_messages_total,
                "news_messages_total": snap.news_messages_total,
                "users_total": snap.users_total,
                "channels_total": snap.channels_total,
            },
            "ipfs": {
                "connected": snap.ipfs_connected,
                "pinned_count": snap.ipfs_pinned_count,
                "repo_size_bytes": snap.ipfs_repo_size_bytes,
            },
            "chain": {
                "contract_address": &state.contract_address,
                "last_indexed_block": snap.klever_last_block,
                "sync_lag_blocks": snap.klever_sync_lag_blocks,
            },
            "anchoring": {
                "last_anchor_age_seconds": snap.last_anchor_age_seconds,
                "total_anchors": snap.total_anchors,
            },
            "wallet": {
                "address": &state.node_address,
                "balance_klv": snap.wallet_balance_klv,
            },
        }
    })
}

// ── REST Endpoints ──────────────────────────────────────────────────

/// GET /admin/metrics/snapshot — current-instant full metrics.
pub async fn metrics_snapshot(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let snap = state
        .metrics_latest
        .read()
        .map(|s| *s)
        .unwrap_or_default();

    Json(build_ws_payload(&state, &snap))
}

/// Query parameters for history endpoint.
#[derive(Deserialize)]
pub struct HistoryQuery {
    /// Metric name to retrieve.
    pub metric: String,
    /// Time period: "1h", "6h", "24h".
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_period() -> String {
    "1h".to_string()
}

/// GET /admin/metrics/history — time-series data from ring buffer.
pub async fn metrics_history(
    Extension(state): Extension<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> impl IntoResponse {
    let minutes = match query.period.as_str() {
        "1h" => 60,
        "6h" => 360,
        "24h" => 1440,
        _ => 60,
    };

    let points = if let Ok(history) = state.metrics_history.read() {
        let snapshots = history.last_n(minutes);
        snapshots
            .iter()
            .map(|s| {
                let v: f64 = match query.metric.as_str() {
                    "cpu_percent" => s.cpu_percent as f64,
                    "memory_used_bytes" => s.memory_used_bytes as f64,
                    "disk_used_bytes" => s.disk_used_bytes as f64,
                    "peers_connected" => s.peers_connected as f64,
                    "messages_per_minute" => s.messages_received_sec * 60.0,
                    "bandwidth_in" => s.bandwidth_in_bytes_sec as f64,
                    "bandwidth_out" => s.bandwidth_out_bytes_sec as f64,
                    "ipfs_pinned_count" => s.ipfs_pinned_count as f64,
                    "ipfs_repo_size_bytes" => s.ipfs_repo_size_bytes as f64,
                    _ => 0.0,
                };
                serde_json::json!({ "t": s.timestamp_ms / 1000, "v": v })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    Json(serde_json::json!({
        "metric": query.metric,
        "period": query.period,
        "points": points,
    }))
}

/// GET /admin/metrics/peers — detailed connected peers table.
pub async fn metrics_peers(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let peers = if let Ok(map) = state.connected_peers.read() {
        map.iter()
            .map(|(node_id, info)| {
                serde_json::json!({
                    "node_id": node_id,
                    "agent_version": info.agent_version,
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    Json(serde_json::json!({
        "peers": peers,
        "total": state.peer_count(),
    }))
}

/// GET /admin/metrics/storage — storage breakdown by column family.
pub async fn metrics_storage(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let storage = state.storage.clone();
    let cf_stats = match tokio::task::spawn_blocking(move || storage.cf_stats()).await {
        Ok(stats) => stats,
        Err(e) => {
            warn!(error = %e, "Failed to collect CF stats");
            Vec::new()
        }
    };

    let db_size = state
        .metrics_latest
        .read()
        .map(|s| s.db_size_bytes)
        .unwrap_or(0);

    let snap = state
        .metrics_latest
        .read()
        .map(|s| *s)
        .unwrap_or_default();

    let families: Vec<serde_json::Value> = cf_stats
        .iter()
        .map(|(name, keys, size)| {
            serde_json::json!({
                "name": name,
                "estimated_keys": keys,
                "estimated_size_bytes": size,
            })
        })
        .collect();

    Json(serde_json::json!({
        "db_size_bytes": db_size,
        "column_families": families,
        "ipfs": {
            "connected": snap.ipfs_connected,
            "pinned_count": snap.ipfs_pinned_count,
            "repo_size_bytes": snap.ipfs_repo_size_bytes,
        }
    }))
}

/// GET /admin/metrics/rejections — recent message rejections for troubleshooting.
pub async fn metrics_rejections(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let rejections = state.counters.get_recent_rejections();
    Json(serde_json::json!({ "rejections": rejections }))
}

/// GET /admin/alerts/history — alert history from the AlertEngine.
pub async fn alerts_history(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let alerts = if let Ok(history) = state.alert_history.read() {
        history
            .iter()
            .rev()
            .take(100)
            .map(|a| {
                serde_json::json!({
                    "severity": a.severity,
                    "condition": a.condition,
                    "message": a.message,
                    "triggered_at": a.triggered_at,
                    "resolved": a.resolved,
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    Json(serde_json::json!({ "alerts": alerts }))
}

// ── Embedded HTML ───────────────────────────────────────────────────

/// The embedded dashboard HTML — self-contained multi-section SPA.
/// Vanilla HTML/CSS/JS, inline SVG charts, no external dependencies.
/// Dark theme default with light theme toggle.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");
