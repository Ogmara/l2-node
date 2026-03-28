//! Embedded admin dashboard — serves a self-contained HTML page and
//! provides a WebSocket endpoint for real-time metrics updates.
//!
//! Spec 4.5: bundled into the binary via `include_str!`, no external
//! CDN dependencies, works fully offline/air-gapped.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Extension;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use futures::SinkExt;
use serde::Serialize;
use tracing::debug;

use super::state::AppState;

/// Metrics payload pushed to the dashboard WebSocket every 2 seconds (spec 4.5.2).
#[derive(Debug, Serialize)]
pub struct DashboardMetrics {
    pub uptime_seconds: u64,
    pub peers_connected: u32,
    pub messages_total: u64,
    pub messages_per_second: f64,
    pub users_total: u64,
    pub channels_total: u64,
    pub disk_used_bytes: u64,
    pub memory_used_bytes: u64,
    pub bandwidth_in_bytes_sec: u64,
    pub bandwidth_out_bytes_sec: u64,
    pub klever_last_block: u64,
    pub klever_sync_lag_blocks: u64,
    pub ipfs_connected: bool,
    pub ipfs_pinned_count: u64,
    pub last_anchor_height: u64,
    pub last_anchor_age_seconds: u64,
}

/// GET /admin/dashboard — serve the embedded HTML dashboard.
pub async fn dashboard_page() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

/// GET /admin/dashboard/ws — WebSocket for real-time metric updates.
pub async fn dashboard_ws(
    ws: WebSocketUpgrade,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_dashboard_ws(socket, state))
}

async fn handle_dashboard_ws(mut socket: WebSocket, state: Arc<AppState>) {
    debug!("Dashboard WebSocket connected");

    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        interval.tick().await;

        let metrics = collect_metrics(&state);
        let msg = serde_json::json!({
            "type": "metrics",
            "timestamp": chrono::Utc::now().timestamp(),
            "data": metrics,
        });

        match serde_json::to_string(&msg) {
            Ok(json) => {
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    debug!("Dashboard WebSocket disconnected");
}

/// Collect current metrics from the application state.
fn collect_metrics(state: &AppState) -> DashboardMetrics {
    let uptime = state.started_at.elapsed().as_secs();
    let last_block = state.storage.get_chain_cursor().unwrap_or(0);

    DashboardMetrics {
        uptime_seconds: uptime,
        peers_connected: state.peer_count(),
        messages_total: 0,  // TODO: track in storage counter
        messages_per_second: 0.0,
        users_total: 0,
        channels_total: 0,
        disk_used_bytes: 0,
        memory_used_bytes: 0,
        bandwidth_in_bytes_sec: 0,
        bandwidth_out_bytes_sec: 0,
        klever_last_block: last_block,
        klever_sync_lag_blocks: 0,
        ipfs_connected: false, // TODO: periodic health check
        ipfs_pinned_count: 0,
        last_anchor_height: 0,
        last_anchor_age_seconds: 0,
    }
}

/// The embedded dashboard HTML — self-contained, no external dependencies.
/// Respects prefers-color-scheme for dark/light theme.
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ogmara Node Dashboard</title>
<style>
:root { --bg: #f5f5f5; --fg: #1a1a1a; --card: #fff; --border: #e0e0e0; --accent: #6c5ce7; --green: #00b894; --yellow: #fdcb6e; --red: #d63031; }
@media (prefers-color-scheme: dark) { :root { --bg: #1a1a2e; --fg: #e0e0e0; --card: #16213e; --border: #0f3460; --accent: #a29bfe; --green: #55efc4; --yellow: #ffeaa7; --red: #ff7675; } }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--fg); padding: 20px; }
h1 { font-size: 1.5em; margin-bottom: 20px; color: var(--accent); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.card h2 { font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.7; margin-bottom: 8px; }
.metric { font-size: 2em; font-weight: 700; }
.metric.green { color: var(--green); }
.metric.yellow { color: var(--yellow); }
.metric.red { color: var(--red); }
.label { font-size: 0.85em; opacity: 0.6; margin-top: 4px; }
.status { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.status.ok { background: var(--green); }
.status.warn { background: var(--yellow); }
.status.err { background: var(--red); }
#conn-status { position: fixed; top: 10px; right: 20px; font-size: 0.8em; }
</style>
</head>
<body>
<div id="conn-status"><span class="status err" id="ws-dot"></span><span id="ws-text">Connecting...</span></div>
<h1>Ogmara Node Dashboard</h1>
<div class="grid">
  <div class="card"><h2>Uptime</h2><div class="metric green" id="uptime">--</div></div>
  <div class="card"><h2>Peers</h2><div class="metric" id="peers">--</div></div>
  <div class="card"><h2>Messages</h2><div class="metric" id="messages">--</div><div class="label" id="msg-rate">-- msg/s</div></div>
  <div class="card"><h2>Users</h2><div class="metric" id="users">--</div></div>
  <div class="card"><h2>Channels</h2><div class="metric" id="channels">--</div></div>
  <div class="card"><h2>Klever Sync</h2><div class="metric" id="klever-block">--</div><div class="label" id="klever-lag">lag: --</div></div>
  <div class="card"><h2>IPFS</h2><div class="metric" id="ipfs-status">--</div><div class="label" id="ipfs-pins">-- pinned</div></div>
  <div class="card"><h2>State Anchor</h2><div class="metric" id="anchor-height">--</div><div class="label" id="anchor-age">-- ago</div></div>
  <div class="card"><h2>Disk</h2><div class="metric" id="disk">--</div></div>
  <div class="card"><h2>Memory</h2><div class="metric" id="memory">--</div></div>
</div>
<script>
function fmt(n) { if (n >= 1e9) return (n/1e9).toFixed(1)+'G'; if (n >= 1e6) return (n/1e6).toFixed(1)+'M'; if (n >= 1e3) return (n/1e3).toFixed(1)+'K'; return n.toString(); }
function fmtBytes(b) { if (b >= 1073741824) return (b/1073741824).toFixed(1)+' GB'; if (b >= 1048576) return (b/1048576).toFixed(1)+' MB'; return (b/1024).toFixed(0)+' KB'; }
function fmtTime(s) { if (s >= 86400) return Math.floor(s/86400)+'d '+Math.floor((s%86400)/3600)+'h'; if (s >= 3600) return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m'; if (s >= 60) return Math.floor(s/60)+'m '+s%60+'s'; return s+'s'; }
function connect() {
  const ws = new WebSocket('ws://'+location.host+'/admin/dashboard/ws');
  ws.onopen = () => { document.getElementById('ws-dot').className='status ok'; document.getElementById('ws-text').textContent='Connected'; };
  ws.onclose = () => { document.getElementById('ws-dot').className='status err'; document.getElementById('ws-text').textContent='Disconnected'; setTimeout(connect, 3000); };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data); if (msg.type !== 'metrics') return; const d = msg.data;
    document.getElementById('uptime').textContent = fmtTime(d.uptime_seconds);
    document.getElementById('peers').textContent = d.peers_connected;
    document.getElementById('messages').textContent = fmt(d.messages_total);
    document.getElementById('msg-rate').textContent = d.messages_per_second.toFixed(1)+' msg/s';
    document.getElementById('users').textContent = fmt(d.users_total);
    document.getElementById('channels').textContent = fmt(d.channels_total);
    document.getElementById('klever-block').textContent = '#'+fmt(d.klever_last_block);
    document.getElementById('klever-lag').textContent = 'lag: '+d.klever_sync_lag_blocks+' blocks';
    document.getElementById('ipfs-status').textContent = d.ipfs_connected ? 'Connected' : 'Offline';
    document.getElementById('ipfs-status').className = 'metric '+(d.ipfs_connected?'green':'red');
    document.getElementById('ipfs-pins').textContent = fmt(d.ipfs_pinned_count)+' pinned';
    document.getElementById('anchor-height').textContent = '#'+fmt(d.last_anchor_height);
    document.getElementById('anchor-age').textContent = fmtTime(d.last_anchor_age_seconds)+' ago';
    document.getElementById('disk').textContent = fmtBytes(d.disk_used_bytes);
    document.getElementById('memory').textContent = fmtBytes(d.memory_used_bytes);
  };
}
connect();
</script>
</body>
</html>"#;
