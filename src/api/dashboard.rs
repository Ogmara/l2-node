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
///
/// v0.45.0: emits each peer's `source` (spec 13 §4.1 discovery tier
/// breakdown — `book` / `config` / `sc` / `runtime`) so the Network
/// tab can render the new peer-source column + per-tier counts.
pub async fn metrics_peers(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // Aggregated per-tier counters for a small at-a-glance summary
    // (rendered above the peers table). Same data the per-row column
    // shows, but pre-aggregated so the dashboard doesn't need to
    // recount on every render.
    let mut count_book = 0u32;
    let mut count_config = 0u32;
    let mut count_sc = 0u32;
    let mut count_runtime = 0u32;
    let peers = if let Ok(map) = state.connected_peers.read() {
        use crate::api::state::DiscoverySource;
        let v: Vec<_> = map
            .iter()
            .map(|(node_id, info)| {
                match info.source {
                    DiscoverySource::Book => count_book += 1,
                    DiscoverySource::Config => count_config += 1,
                    DiscoverySource::Sc => count_sc += 1,
                    DiscoverySource::Runtime => count_runtime += 1,
                }
                serde_json::json!({
                    "node_id": node_id,
                    "agent_version": info.agent_version,
                    "source": info.source,
                })
            })
            .collect();
        v
    } else {
        Vec::new()
    };

    Json(serde_json::json!({
        "peers": peers,
        "total": state.peer_count(),
        "by_source": {
            "book": count_book,
            "config": count_config,
            "sc": count_sc,
            "runtime": count_runtime,
        },
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

/// GET /admin/alerts/config — current `[alerts]` configuration
/// (governance-dashboard-plan.md Phase 8).
///
/// Serializes `AlertsConfig` directly rather than hand-building a
/// JSON object field-by-field: every secret field on the underlying
/// config structs (`telegram.bot_token`, `discord.webhook_url`,
/// `ogmara_channel.signing_key_path`) already carries
/// `#[serde(skip_serializing)]`, so this is compiler-enforced-safe —
/// a hand-rolled reshape would risk silently including a secret if a
/// future field is added without the attribute, or silently DROPPING
/// a legitimately-public field the dashboard needs. `webhook.url` and
/// `ogmara_channel.{wallet_address,channel_id}` are intentionally NOT
/// redacted (established policy elsewhere in this codebase — see
/// `config.rs`'s `WebhookAlertConfig` doc), so they appear as-is.
pub async fn alerts_config(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    Json(state.alerts_config.clone())
}

/// POST /admin/alerts/test — dispatch a one-off test alert to every
/// ENABLED channel (governance-dashboard-plan.md Phase 8). Routes
/// into the running `AlertEngine` via the same
/// channel+oneshot-reply+shared-timeout-budget idiom as
/// `admin::submit_signed_call` — see that function's doc comment
/// for why the deadline must cover both the channel send AND the
/// reply wait, not just the latter.
pub async fn alerts_test(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    let Some(tx) = &state.alert_test_tx else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "alerts are not enabled on this node" })),
        )
            .into_response();
    };
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    match tokio::time::timeout_at(
        deadline,
        tx.send(crate::notifications::alerts::TestAlertRequest { reply: reply_tx }),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "alert engine not running" })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                Json(serde_json::json!({ "error": "timed out waiting to queue test-alert request (alert engine busy)" })),
            )
                .into_response();
        }
    }
    match tokio::time::timeout_at(deadline, reply_rx).await {
        Ok(Ok(result)) => Json(serde_json::json!({ "sent_to": result.sent_to, "failed": result.failed })).into_response(),
        Ok(Err(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "alert engine dropped reply" })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({ "error": "timed out waiting for alert engine to dispatch test alert" })),
        )
            .into_response(),
    }
}

/// GET /admin/snapshot/status — current snapshot cache state.
///
/// Returns the most recent successfully built snapshot's metadata so
/// operators can confirm Phase 1 serving is healthy (spec 11-snapshot-sync.md).
/// Returns `{ "available": false }` if no cache has been built yet.
pub async fn snapshot_status(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    use crate::storage::schema;

    let last_served_height = state
        .storage
        .get_stat(schema::state_keys::SNAPSHOT_LAST_SERVED_HEIGHT)
        .unwrap_or(0);

    match state.snapshot_cache.read() {
        Ok(guard) => match guard.as_ref() {
            Some(cache) => {
                let manifest = &cache.manifest;
                let cf_summaries: Vec<serde_json::Value> = manifest
                    .cfs
                    .iter()
                    .map(|cf| {
                        serde_json::json!({
                            "cf_name": cf.cf_name,
                            "num_entries": cf.num_entries,
                            "total_bytes": cf.total_bytes,
                            "chunks": cf.chunks.len(),
                            "cf_root": hex::encode(cf.cf_root),
                        })
                    })
                    .collect();
                Json(serde_json::json!({
                    "available": true,
                    "version": manifest.version,
                    "network_id": manifest.network_id,
                    "block_height": manifest.block_height,
                    "snapshot_root": hex::encode(manifest.snapshot_root),
                    "total_users": manifest.total_users,
                    "total_channels": manifest.total_channels,
                    "created_at": manifest.created_at,
                    "producer_node_id": manifest.producer_node_id,
                    "compressed_total_bytes": cache.compressed_total_bytes,
                    "chunk_count": cache.chunks.len(),
                    "column_families": cf_summaries,
                    "last_served_height": last_served_height,
                }))
            }
            None => Json(serde_json::json!({
                "available": false,
                "reason": "cache not yet built (warming up after startup)",
                "last_served_height": last_served_height,
            })),
        },
        Err(_) => Json(serde_json::json!({
            "available": false,
            "reason": "cache lock poisoned",
        })),
    }
}

// ── Embedded HTML ───────────────────────────────────────────────────

/// The embedded dashboard HTML — self-contained multi-section SPA.
/// Vanilla HTML/CSS/JS, inline SVG charts, no external dependencies.
/// Dark theme default with light theme toggle.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[cfg(test)]
mod dashboard_js_tests {
    use super::DASHBOARD_HTML;
    use std::collections::HashSet;

    /// Everything between the inline `<script>` tags.
    fn script_body() -> String {
        let mut out = String::new();
        let mut rest = DASHBOARD_HTML;
        while let Some(open) = rest.find("<script") {
            let after = &rest[open..];
            let Some(gt) = after.find('>') else { break };
            let body_start = open + gt + 1;
            let Some(close) = rest[body_start..].find("</script>") else { break };
            out.push_str(&rest[body_start..body_start + close]);
            out.push('\n');
            rest = &rest[body_start + close..];
        }
        out
    }

    /// Strip `//` and `/* */` comments, preserving line structure.
    ///
    /// Essential, not cosmetic: the declaration scanner keys off the words
    /// `for `, `catch `, `function ` and `let `, all of which occur constantly
    /// in ENGLISH PROSE in this file's comments ("for the operator", "catch a
    /// failure"). Scanning them made the analyser run away over the following
    /// code and mark every identifier in it as declared, silently disabling
    /// the check. It also means commenting out a declaration no longer counts
    /// as declaring it.
    ///
    /// String contents are tracked so a `//` inside a URL literal is not
    /// mistaken for a comment.
    fn strip_comments(js: &str) -> String {
        let mut out = String::with_capacity(js.len());
        let mut chars = js.chars().peekable();
        let mut quote: Option<char> = None;
        let mut escaped = false;
        while let Some(c) = chars.next() {
            if let Some(q) = quote {
                out.push(c);
                if escaped { escaped = false; }
                else if c == '\\' { escaped = true; }
                else if c == q { quote = None; }
                continue;
            }
            match c {
                '\'' | '"' | '`' => { quote = Some(c); out.push(c); }
                '/' if chars.peek() == Some(&'/') => {
                    for n in chars.by_ref() {
                        if n == '\n' { out.push('\n'); break; }
                    }
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    let mut prev = '\0';
                    for n in chars.by_ref() {
                        if n == '\n' { out.push('\n'); }
                        if prev == '*' && n == '/' { break; }
                        prev = n;
                    }
                }
                _ => out.push(c),
            }
        }
        out
    }

    /// Names bound by a `let` / `const` / `var` / `function` declaration.
    ///
    /// Captures EVERY declarator, not just the first: `let a = 1, b = 2;` and
    /// destructuring (`const { x, y } = o`, `const [p, q] = arr`) all bind
    /// names that later assignments legitimately target. An earlier version
    /// took only the first identifier, which left real declarations such as
    /// `let min = Infinity, max = -Infinity;` unseen — a latent false positive
    /// that would have failed the build on a purely cosmetic reformat.
    ///
    /// Also collects function/arrow parameters and `catch (e)` bindings, since
    /// all of those are assignable.
    fn declared_names(js: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        let bytes = js.as_bytes();
        let is_ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';

        let push_idents = |seg: &str, names: &mut HashSet<String>| {
            let mut cur = String::new();
            for c in seg.chars() {
                if is_ident(c) {
                    cur.push(c);
                } else if !cur.is_empty() && !cur.starts_with(|d: char| d.is_ascii_digit()) {
                    names.insert(std::mem::take(&mut cur));
                } else {
                    cur.clear();
                }
            }
            if !cur.is_empty() && !cur.starts_with(|d: char| d.is_ascii_digit()) {
                names.insert(cur);
            }
        };

        // Declaration keywords whose binding region is a plain declarator
        // list, and `catch`/`for`, whose bindings live inside parentheses.
        for kw in ["let ", "const ", "var ", "function ", "catch ", "for "] {
            // `function`, `catch` and `for` bind only a name and/or a
            // parenthesised list — their region must END at the closing paren.
            // Letting `function` run to the next `;` would swallow the whole
            // body and mark every identifier in it as declared, silently
            // defeating the check.
            let paren_scoped = kw == "catch " || kw == "for " || kw == "function ";
            let mut from = 0usize;
            while let Some(i) = js[from..].find(kw) {
                let at = from + i;
                let prev_ok = at == 0 || !js[..at].chars().next_back().is_some_and(is_ident);
                if prev_ok {
                    let rest = &js[at + kw.len()..];
                    // Hard cap so a malformed or unusual construct can never let
                    // the scan run away and swallow unrelated code — which would
                    // silently mark real undeclared names as declared and defeat
                    // the whole check.
                    // Char-safe cap: slicing at a raw byte index would panic
                    // mid-codepoint (this file contains box-drawing comments).
                    let cap = rest
                        .char_indices()
                        .nth(300)
                        .map(|(bi, _)| bi)
                        .unwrap_or(rest.len());
                    let window = &rest[..cap];
                    let mut depth = 0i32;
                    let mut end = window.len();
                    for (bi, ch) in window.char_indices() {
                        match ch {
                            '(' | '[' | '{' => depth += 1,
                            ')' | ']' | '}' => {
                                depth -= 1;
                                // catch/for bindings end with their paren.
                                if depth <= 0 && paren_scoped { end = bi; break; }
                            }
                            // A declarator list ends at the statement end. We do
                            // NOT stop at the first `=`: that would drop every
                            // later declarator in `let a = 1, b = 2;`, leaving
                            // real declarations unseen — the exact false
                            // positive that would fail the build on a reformat.
                            ';' if depth == 0 && !paren_scoped => { end = bi; break; }
                            _ => {}
                        }
                    }
                    let region = &window[..end];
                    // Split on depth-0 commas into declarators, then take each
                    // one's binding side (before its own `=`). Handles
                    // `let a = 1, b = 2` and `const { x, y } = o` alike.
                    let mut depth2 = 0i32;
                    let mut seg_start = 0usize;
                    let mut segments: Vec<&str> = Vec::new();
                    for (bi, ch) in region.char_indices() {
                        match ch {
                            '(' | '[' | '{' => depth2 += 1,
                            ')' | ']' | '}' => depth2 -= 1,
                            ',' if depth2 == 0 => {
                                segments.push(&region[seg_start..bi]);
                                seg_start = bi + 1;
                            }
                            _ => {}
                        }
                    }
                    segments.push(&region[seg_start..]);
                    for seg in segments {
                        let mut d3 = 0i32;
                        let mut cut = seg.len();
                        for (bi, ch) in seg.char_indices() {
                            match ch {
                                '(' | '[' | '{' => d3 += 1,
                                ')' | ']' | '}' => d3 -= 1,
                                '=' if d3 == 0 => { cut = bi; break; }
                                _ => {}
                            }
                        }
                        push_idents(&seg[..cut], &mut names);
                    }

                }
                from = at + kw.len();
            }
        }
        let _ = bytes;
        names
    }

    /// Catches assignment to a name that was never declared.
    ///
    /// This exists because of a real 0.126.1 regression: an edit deleted
    /// `let earnStatusSticky = false;` while leaving four assignments to it
    /// behind. `node --check` reported the file as valid — a missing
    /// declaration is a RUNTIME `ReferenceError`, not a syntax error — so the
    /// dashboard shipped and every earnings refresh died with "earnStatusSticky
    /// is not defined", blanking the card. Only a browser (or an executing
    /// harness) would have caught it, and neither runs in this test suite.
    ///
    /// Deliberately narrow to avoid false positives: it only inspects
    /// statement-leading `name = ...` assignments, so property writes
    /// (`el.textContent = x`), declarations, and comparisons are all ignored.
    #[test]
    fn no_assignment_to_an_undeclared_variable() {
        let js = strip_comments(&script_body());
        assert!(!js.is_empty(), "dashboard.html should contain inline script");
        let declared = declared_names(&js);
        // Assigned via a `for (x of ...)`/`catch (e)` binding or the DOM globals.
        let known_globals: HashSet<&str> = ["window", "document", "location"].into_iter().collect();

        let mut offenders = Vec::new();
        for (lineno, raw) in js.lines().enumerate() {
            let line = raw.trim();
            if line.starts_with("//") || line.starts_with('*') || line.starts_with("/*") {
                continue;
            }
            // `name = ...` but not `==`, `===`, `>=`, `<=`, `!=`, `+=`, etc.
            let Some(eq) = line.find('=') else { continue };
            if eq == 0 || eq + 1 >= line.len() {
                continue;
            }
            let before = &line[..eq];
            let after_ch = line.as_bytes()[eq + 1];
            let prev_ch = line.as_bytes()[eq - 1];
            if after_ch == b'=' || matches!(prev_ch, b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'&' | b'|') {
                continue;
            }
            let name = before.trim();
            if name.is_empty()
                || !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$')
                || name.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                continue;
            }
            if !declared.contains(name) && !known_globals.contains(name) {
                offenders.push(format!("line {}: `{}`", lineno + 1, name));
            }
        }
        assert!(
            offenders.is_empty(),
            "assignment to undeclared variable(s) in dashboard.html — a runtime \
             ReferenceError that no syntax check catches:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// `callValue` must be a JSON number, never a string.
    ///
    /// The Klever node refuses a string at JSON decode ("cannot unmarshal
    /// string into Go struct field SmartContractRequest.callValue of type
    /// int64"), verified against live testnet on both signing paths. A
    /// long-standing comment in `dashboard.html` asserted the opposite, and
    /// `registerNodeOnChain` followed it — so node registration returned a 400
    /// for any non-zero `node_registration_fee`, which has defaulted to 100 KLV
    /// since SC 0.5.0. It went unnoticed because an empty `{}` IS correct when
    /// no value is attached, so the path worked while the fee was zero.
    #[test]
    fn call_value_is_never_a_string() {
        let js = strip_comments(&script_body());
        let mut offenders = Vec::new();
        for (i, line) in js.lines().enumerate() {
            // Comments are already stripped, so this file can document the
            // very shape it forbids without tripping its own guard.
            if !line.contains("KLV:") {
                continue;
            }
            // A string amount is the bug: `KLV: "..."`, `KLV: x.toString()`,
            // or `KLV: String(x)`.
            let after = line.split("KLV:").nth(1).unwrap_or("").trim_start();
            if after.starts_with('"')
                || after.starts_with('\'')
                || after.starts_with("String(")
                || after.split(&[',', '}'][..]).next().is_some_and(|v| v.contains(".toString()"))
            {
                offenders.push(format!("line {}: {}", i + 1, line.trim()));
            }
        }
        assert!(
            offenders.is_empty(),
            "callValue amounts must be JSON numbers — the Klever node rejects              strings at JSON decode:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The dashboard must stay inside the `/admin/*` namespace.
    ///
    /// Also a real 0.126.0 regression: the earnings card fetched the public
    /// `/api/v1/registration/info`, which returned a correct 200 when queried
    /// directly but silently failed from the dashboard on a deployment whose
    /// reverse proxy scopes only `/admin` to the node. Every other fetch in
    /// this file targets `/admin/*`, and that is load-bearing.
    #[test]
    fn dashboard_never_fetches_the_public_api() {
        let js = strip_comments(&script_body());
        assert!(
            !js.contains("fetch('/api/")
                && !js.contains("fetch(\"/api/")
                // Template-literal fetches are already the house style in this
                // file, so the exact regression can recur in that form.
                && !js.contains("fetch(`/api/"),
            "dashboard.html must fetch only /admin/* — a public-API fetch fails \
             silently behind an admin-scoped reverse proxy"
        );
    }
}
