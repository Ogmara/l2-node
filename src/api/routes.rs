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
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use rocksdb::WriteBatch;

use crate::storage::schema::{cf, decode_users_by_name_key, encode_channel_msg_key, encode_dm_msg_key, state_keys};

use super::auth::AuthUser;
use super::state::{AppState, CachedMedia};

/// Build a 429 response with a PoW challenge for the given wallet address.
///
/// Called when the router returns `RouteResult::PowRequired`. The client
/// must solve the challenge and submit it to `/api/v1/pow/verify` before
/// retrying the original request.
fn pow_required_response(state: &AppState, address: &str) -> axum::response::Response {
    if let Some(ref pow) = state.pow {
        match pow.generate_challenge(address) {
            Some(challenge) => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "pow_required",
                    "message": "Proof-of-work required for new wallets",
                    "challenge": challenge,
                    "address": address,
                })),
            )
                .into_response(),
            None => (
                StatusCode::SERVICE_UNAVAILABLE,
                "too many pending challenges, try again later",
            )
                .into_response(),
        }
    } else {
        // PoW disabled but router returned PowRequired — shouldn't happen, treat as internal error
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    }
}

// --- PoW anti-spam endpoints (public, no auth required) ---

/// POST /api/v1/pow/challenge — request a PoW challenge for a wallet address.
///
/// Body: `{ "address": "klv1..." }` or `{ "address": "ogd1..." }`
pub async fn pow_challenge(
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<PowChallengeRequest>,
) -> impl IntoResponse {
    // Validate address format
    if (!body.address.starts_with("klv1") && !body.address.starts_with("ogd1"))
        || body.address.len() < 10
        || body.address.len() > 100
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid address format" })),
        )
            .into_response();
    }

    match &state.pow {
        Some(pow) => {
            if pow.is_wallet_known(&body.address) {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "known": true,
                        "message": "Wallet already verified"
                    })),
                )
                    .into_response();
            }
            match pow.generate_challenge(&body.address) {
                Some(challenge) => {
                    (StatusCode::OK, Json(serde_json::json!({ "challenge": challenge }))).into_response()
                }
                None => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "too many pending challenges, try again later"
                    })),
                )
                    .into_response(),
            }
        }
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "known": true,
                "message": "PoW not required on this node"
            })),
        )
            .into_response(),
    }
}

/// POST /api/v1/pow/verify — submit a PoW solution.
///
/// Body: `{ "challenge_id": "...", "address": "klv1...", "nonce": 123456 }`
pub async fn pow_verify(
    Extension(state): Extension<Arc<AppState>>,
    Json(solution): Json<crate::pow::PowSolution>,
) -> impl IntoResponse {
    match &state.pow {
        Some(pow) => match pow.verify_solution(&solution) {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "message": "Wallet verified" })),
            )
                .into_response(),
            Err(reason) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": reason })),
            )
                .into_response(),
        },
        None => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "message": "PoW not required" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct PowChallengeRequest {
    pub address: String,
}

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

/// Apply the latest edit envelope on top of the original message's payload
/// and return the merged payload as fresh msgpack bytes. Returns `None` on
/// any decode failure, when the original message is missing, or when the
/// `msg_type` is one without a defined edit-merge rule — the caller treats
/// `None` as "unrecoverable edit" and blanks the response's `payload` to
/// avoid leaking pre-edit content (privacy fail-safe).
///
/// Per-type merge semantics (spec §3.7):
///   - `NewsPost`     — content always; title/tags/attachments when `Some(_)`.
///   - `ChatMessage`  — content always; attachments when `Some(_)`. mentions
///                      stay untouched by edits (re-triggering @-notifications
///                      from an edit would invite spam).
///   - `DirectMessage`— rejected at validation (encrypted ciphertext blobs
///                      have no field-level shape from the server's view);
///                      returns `None` if it ever gets here.
///   - Anything else  — including hypothetical comment-edits, returns `None`
///                      until a corresponding `MessageType` variant and
///                      router dispatch exist.
fn project_edited_payload(
    original_msg_id: &[u8; 32],
    edit_msg_id: &[u8; 32],
    storage: &crate::storage::rocks::Storage,
) -> Option<Vec<u8>> {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{ChatMessagePayload, EditPayload, MessageType, NewsPostPayload};

    // Helper: turn each decode/IO failure into a tracing warn so storage
    // corruption is observable instead of presenting as "the edit just
    // didn't apply". Using a closure for the trace tag avoids repeating
    // the msg_ids in every log call.
    let warn_decode = |stage: &'static str, err: &dyn std::fmt::Display| {
        tracing::warn!(
            stage = stage,
            original = %hex::encode(original_msg_id),
            edit = %hex::encode(edit_msg_id),
            error = %err,
            "edit projection failed",
        );
    };

    // Pull both envelopes from storage. A failure at any step bails out —
    // the caller treats `None` as "unrecoverable edit" and blanks the
    // payload (so a redacting edit never reveals the pre-edit content).
    let orig_bytes = match storage.get_message(original_msg_id) {
        Ok(Some(b)) => b,
        Ok(None) => { warn_decode("original_missing", &"not in storage"); return None; }
        Err(e) => { warn_decode("original_read", &e); return None; }
    };
    let orig_env = match Envelope::from_bytes(&orig_bytes) {
        Ok(e) => e,
        Err(e) => { warn_decode("original_envelope_decode", &e); return None; }
    };

    let edit_bytes = match storage.get_message(edit_msg_id) {
        Ok(Some(b)) => b,
        Ok(None) => { warn_decode("edit_missing", &"not in storage"); return None; }
        Err(e) => { warn_decode("edit_read", &e); return None; }
    };
    let edit_env = match Envelope::from_bytes(&edit_bytes) {
        Ok(e) => e,
        Err(e) => { warn_decode("edit_envelope_decode", &e); return None; }
    };
    let edit: EditPayload = match rmp_serde::from_slice(&edit_env.payload) {
        Ok(e) => e,
        Err(e) => { warn_decode("edit_payload_decode", &e); return None; }
    };

    // Only message types whose Rust struct EditPayload can target are
    // handled. There is no `NewsCommentEdit` message type today (router
    // dispatches only ChatEdit / DirectMessageEdit / NewsEdit), and DMs
    // are encrypted ciphertext blobs whose validator forbids field
    // overrides — so comments and DMs return None and the caller blanks
    // the payload (consistent privacy fail-safe).
    // Re-encode with `to_vec_named` (struct → msgpack MAP), not `to_vec`
    // (struct → msgpack ARRAY). JS clients (`@msgpack/msgpack`) decode the
    // payload by field name — an array-encoded merge result deserializes as
    // a positional JS array, so `.title`, `.content`, `.tags`, `.attachments`
    // all read `undefined` and every edited post renders blank. The original
    // posts arrive map-encoded because they're authored by the SDK, which
    // emits maps; for parity we must re-emit maps here too. (Rust clients
    // accept both forms, so existing rmp_serde::from_slice callers stay
    // happy.) Same fix applies to ChatMessage edits below.
    match orig_env.msg_type {
        MessageType::NewsPost => {
            let mut p: NewsPostPayload = match rmp_serde::from_slice(&orig_env.payload) {
                Ok(v) => v,
                Err(e) => { warn_decode("news_post_decode", &e); return None; }
            };
            p.content = edit.content;
            if let Some(t) = edit.title { p.title = t; }
            if let Some(t) = edit.tags { p.tags = t; }
            if let Some(a) = edit.attachments { p.attachments = a; }
            rmp_serde::to_vec_named(&p)
                .map_err(|e| warn_decode("news_post_reencode", &e))
                .ok()
        }
        MessageType::ChatMessage => {
            let mut p: ChatMessagePayload = match rmp_serde::from_slice(&orig_env.payload) {
                Ok(v) => v,
                Err(e) => { warn_decode("chat_decode", &e); return None; }
            };
            p.content = edit.content;
            if let Some(a) = edit.attachments { p.attachments = a; }
            rmp_serde::to_vec_named(&p)
                .map_err(|e| warn_decode("chat_reencode", &e))
                .ok()
        }
        _ => None,
    }
}

/// Enrich a message JSON value with deletion and edit status from storage.
///
/// Checks the storage layer for soft-deletion markers and edit history,
/// adding `deleted`, `deleted_at`, `edited`, and `last_edited_at` fields
/// as appropriate. Deleted messages have their `payload` field blanked.
fn enrich_message_json(msg: &mut serde_json::Value, storage: &crate::storage::rocks::Storage) {
    let msg_id_bytes: Option<[u8; 32]> = msg
        .get("msg_id")
        .and_then(|v| v.as_str())
        .and_then(|hex_str| {
            let bytes = hex::decode(hex_str).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                None
            }
        });

    let msg_id = match msg_id_bytes {
        Some(id) => id,
        None => return,
    };

    // Check deletion status
    if let Ok(true) = storage.is_deleted(&msg_id) {
        if let serde_json::Value::Object(ref mut map) = msg {
            map.insert("deleted".into(), serde_json::json!(true));
            // Try to extract deleted_at timestamp from the marker
            if let Ok(Some(marker_bytes)) = storage.get_cf(cf::DELETION_MARKERS, &msg_id) {
                if let Ok(marker) = serde_json::from_slice::<serde_json::Value>(&marker_bytes) {
                    if let Some(ts) = marker.get("deleted_at").and_then(|v| v.as_u64()) {
                        map.insert("deleted_at".into(), serde_json::json!(ts));
                    }
                }
            }
            // Blank the payload — content is hidden but metadata remains
            map.insert("payload".into(), serde_json::Value::Null);
        }
    }

    // Check edit status and apply the latest edit on top of the original
    // payload. Pre-0.37 this branch overwrote `payload` with just the edit's
    // content string, which destroyed title/tags/attachments/mentions and
    // forced every client to handle two payload shapes. The new behavior
    // keeps `payload` as msgpack bytes (a JSON array of u8 in transit) and
    // merges field-level overrides — see `project_edited_payload`.
    //
    // CRITICAL: must SKIP this branch entirely when the message is soft-
    // deleted. The deletion branch above explicitly blanks `payload` to
    // hide content. Without this guard, an edited-then-deleted message
    // would have its payload re-populated here with the merged edit
    // contents — exposing data the user intended to redact.
    let is_deleted = storage.is_deleted(&msg_id).unwrap_or(false);
    if !is_deleted {
        if let Ok(true) = storage.is_edited(&msg_id) {
            if let serde_json::Value::Object(ref mut map) = msg {
                map.insert("edited".into(), serde_json::json!(true));
                if let Ok(edits) = storage.get_edit_history(&msg_id) {
                    if let Some((last_ts, edit_msg_id)) = edits.last() {
                        map.insert("last_edited_at".into(), serde_json::json!(last_ts));
                        match project_edited_payload(&msg_id, edit_msg_id, storage) {
                            Some(merged) => {
                                // Bytes form keeps the wire contract identical to a
                                // never-edited message — clients msgpack-decode the
                                // payload exactly the same way in both cases.
                                map.insert("payload".into(), serde_json::json!(merged));
                            }
                            None => {
                                // Privacy guard: an `edited` marker without a
                                // recoverable edit envelope (orphaned index row,
                                // corrupted bytes, etc.) would otherwise display
                                // the PRE-edit content as if it were current. A
                                // user who edited to redact ("never mind, here's
                                // the correct statement") would see the original.
                                // Blank the payload like the deletion path so
                                // unrecoverable edits fail safe.
                                tracing::warn!(
                                    msg_id = %hex::encode(msg_id),
                                    edit_msg_id = %hex::encode(edit_msg_id),
                                    "edit projection returned None — blanking payload to avoid pre-edit leak",
                                );
                                map.insert("payload".into(), serde_json::Value::Null);
                            }
                        }
                    }
                }
            }
        }
    }

    // Enrich with chat reaction counts
    if let Ok(reactions) = storage.get_chat_reactions(&msg_id) {
        if !reactions.is_empty() {
            let reaction_map: serde_json::Map<String, serde_json::Value> = reactions
                .into_iter()
                .map(|(emoji, count)| (emoji, serde_json::json!(count)))
                .collect();
            if let serde_json::Value::Object(ref mut map) = msg {
                map.insert("reactions".into(), serde_json::json!(reaction_map));
            }
        }
    }
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
    /// Hex-encoded msg_id cursor: return messages strictly after this message.
    /// Mutually exclusive with `before`; if both provided, `after` takes precedence.
    pub after: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct NotificationParams {
    pub since: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ModerationReportParams {
    pub target: String,
}

// --- Response types ---

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub peers: u32,
    /// Whether this node can currently accept media uploads and serve
    /// media — i.e., an IPFS backend is configured AND reachable. A node
    /// can be configured-but-offline (the Kubo daemon isn't running), so
    /// this is a live capability signal, not a static config flag.
    /// Clients use it to disable the attach/upload UI and tell the user
    /// to switch to a media-capable node instead of failing on upload or
    /// rendering broken image placeholders. Older nodes omit this field;
    /// clients should treat its absence as "unknown" → assume available
    /// (preserves prior behavior).
    pub media_uploads: bool,
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
    /// libp2p PeerId (`12D3KooW...`) in base58. Populated for the
    /// local node (always) and for currently-connected discovered
    /// peers (from `ConnectedPeerInfo.peer_id`, set at Identify
    /// time). `None` for peers known only via cached PEER_DIRECTORY
    /// announcements where the libp2p binding isn't currently held.
    /// Consumers (website, SDK) use this to dedup against gossip
    /// records that key by libp2p PeerId rather than Ogmara node_id.
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    api_endpoint: Option<String>,
    channels: Vec<u64>,
    user_count: u32,
    last_seen: u64,
    anchor_status: crate::storage::rocks::AnchorStatus,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub msg_id: String,
    /// Real-time GossipSub delivery outcome for endpoints that publish
    /// (B4 fix proper, l2-node 0.48.4). `"propagated"` = handed to the
    /// mesh; `"degraded"` = no mesh peer right now (message is stored
    /// and will reach peers via backfill/reconciliation); `"pending"` =
    /// outcome unknown (network task slow or unavailable). Omitted
    /// entirely for endpoints that don't gossip, so existing clients
    /// see no change. Advisory only — the message is always persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<&'static str>,
}

#[derive(Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

// --- Public endpoint handlers ---

/// GET /api/v1/health
pub async fn health(Extension(state): Extension<Arc<AppState>>) -> Json<HealthResponse> {
    // Live media capability: configured AND the Kubo daemon answers.
    // `is_available()` is cached (15s TTL) so polling /health stays cheap.
    let media_uploads = match &state.ipfs {
        Some(c) => c.is_available().await,
        None => false,
    };
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        peers: state.peer_count(),
        media_uploads,
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

    // Build self entry — this node always appears first
    let self_user_count = state.storage.get_stat(state_keys::TOTAL_USERS).unwrap_or(0) as u32;
    let self_channels: Vec<u64> = state
        .storage
        .prefix_iter_cf(cf::CHANNELS, &[], 10_000)
        .unwrap_or_default()
        .iter()
        .filter_map(|(key, _)| {
            if key.len() >= 8 {
                Some(u64::from_be_bytes(key[..8].try_into().ok()?))
            } else {
                None
            }
        })
        .collect();
    let self_anchor_status = state.storage.compute_anchor_status(&state.node_id).unwrap_or_else(|_| {
        crate::storage::rocks::AnchorStatus {
            verified: false,
            level: "none".to_string(),
            last_anchor_age_seconds: None,
            anchoring_since: None,
            total_anchors: 0,
        }
    });
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Build a node_id → libp2p peer_id lookup from the currently-
    // connected peers map. This binding is known at Identify time
    // (see network/mod.rs); we use it to attach a `peer_id` to each
    // NodeEntry so consumers can dedup against presence-gossip rows
    // (which key by libp2p PeerId). PEER_DIRECTORY entries whose
    // peer is not currently connected get `peer_id: None`.
    let peer_id_by_node_id: std::collections::HashMap<String, String> =
        state.connected_peers.read()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.peer_id.clone())).collect())
            .unwrap_or_default();

    let self_entry = NodeEntry {
        node_id: state.node_id.clone(),
        peer_id: Some(state.network_peer_id.clone()),
        api_endpoint: state.public_url.clone(),
        channels: self_channels,
        user_count: self_user_count,
        last_seen: now_ms,
        anchor_status: self_anchor_status,
    };

    match state.storage.prefix_iter_cf(cf::PEER_DIRECTORY, &[], limit) {
        Ok(entries) => {
            let mut nodes: Vec<NodeEntry> = Vec::with_capacity(entries.len() + 1);
            nodes.push(self_entry);

            for (_, v) in entries {
                let entry = (|| {
                    let ann: serde_json::Value = serde_json::from_slice(&v).ok()?;
                    let node_id = ann.get("node_id")?.as_str()?.to_string();
                    // Skip if this is our own node (avoid duplicate)
                    if node_id == state.node_id {
                        return None;
                    }
                    let last_seen = ann.get("last_seen").and_then(|v| v.as_u64()).unwrap_or(0);
                    let ttl_seconds = ann.get("ttl_seconds").and_then(|v| v.as_u64()).unwrap_or(600);
                    // Filter stale entries (last_seen + TTL exceeded)
                    if now_ms > last_seen + ttl_seconds * 1000 {
                        return None;
                    }
                    let api_endpoint = ann.get("api_endpoint").and_then(|v| v.as_str()).map(String::from);
                    let channels: Vec<u64> = ann.get("channels")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
                        .unwrap_or_default();
                    let user_count = ann.get("user_count").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

                    let anchor_status = state.storage.compute_anchor_status(&node_id).unwrap_or_else(|_| {
                        crate::storage::rocks::AnchorStatus {
                            verified: false,
                            level: "none".to_string(),
                            last_anchor_age_seconds: None,
                            anchoring_since: None,
                            total_anchors: 0,
                        }
                    });

                    let peer_id = peer_id_by_node_id.get(&node_id).cloned();

                    Some(NodeEntry {
                        node_id,
                        peer_id,
                        api_endpoint,
                        channels,
                        user_count,
                        last_seen,
                        anchor_status,
                    })
                })();
                if let Some(entry) = entry {
                    nodes.push(entry);
                }
            }

            // Include connected Ogmara peers that aren't in the PEER_DIRECTORY yet
            // (e.g. peers whose NodeAnnouncement hasn't arrived via GossipSub)
            // Note: do not hold this lock across .await points
            if let Ok(connected) = state.connected_peers.read() {
                let known_ids: std::collections::HashSet<String> =
                    nodes.iter().map(|n| n.node_id.clone()).collect();
                for (node_id, info) in connected.iter() {
                    if known_ids.contains(node_id) {
                        continue;
                    }
                    nodes.push(NodeEntry {
                        node_id: node_id.clone(),
                        peer_id: Some(info.peer_id.clone()),
                        api_endpoint: None,
                        channels: vec![],
                        user_count: 0,
                        last_seen: now_ms,
                        anchor_status: state.storage.compute_anchor_status(node_id).unwrap_or_else(|_| {
                            crate::storage::rocks::AnchorStatus {
                                verified: false,
                                level: "none".to_string(),
                                last_anchor_age_seconds: None,
                                anchoring_since: None,
                                total_anchors: 0,
                            }
                        }),
                    });
                }
            }

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

/// GET /api/v1/network/discovery/bootstrap-candidates
///
/// Public, no auth (spec 13 §4.5). Returns the node's union of known
/// bootstrap candidates across three tiers:
///   - **tier 1 — peer book** (`PEER_DIRECTORY` CF, persisted peers
///     dialed in prior sessions). `last_anchor_at` is null — the book
///     doesn't track anchor recency.
///   - **tier 2 — config** (`[network] bootstrap_nodes`). Same null
///     `last_anchor_at` semantics.
///   - **tier 3 — SC registry** (`getActiveNodes` + `getNodeMetadata`).
///     `last_anchor_at` is the on-chain timestamp.
///
/// Dedupes by exact multiaddr string. Collisions across tiers resolved
/// by: highest `last_anchor_at` wins (null treated as 0); on tie,
/// SC > book > config (locked v0.46.0 plan OPEN 4 resolution,
/// 2026-05-17). The winning entry's source label is reported.
/// Different multiaddrs sharing the same peer_id (TCP + QUIC variants)
/// are intentionally preserved as separate entries — SDK consumers
/// want both transports to dial.
///
/// Response cached for 5 minutes (spec 13 §4.5). Concurrent
/// regenerations serialized via async Mutex so a thundering herd
/// doesn't trigger N parallel SC RPC bursts.
///
/// Filters per spec 13 §7 (tier 3 only):
///   - Skip entries whose `last_anchor_at` is older than
///     `[network.discovery] max_peer_staleness_days`.
///   - Skip the node's own anchorer address (the caller already knows
///     about us).
///   - Skip entries whose `getNodeMetadata` is empty (privacy profile
///     — operator opted out of publication; spec 13 §6).
///
/// Sort: entries with non-null `last_anchor_at` first (desc); then
/// null entries by source order [book, config]. Capped at 256 total.
///
/// When SC is unconfigured or the RPC fan-out fails / times out, tier
/// 1+2 entries are still emitted with a `source_note` describing the
/// SC condition; cache TTL drops to 60s for fast recovery.
pub async fn network_bootstrap_candidates(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // 5-minute positive TTL per spec 13 §4.5. Constant rather than
    // configurable because the spec ties it to client behaviour
    // (clients are told 300s in the response body); changing it
    // without a coordinated client update would just produce
    // stale-cache mismatches.
    const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
    // Shorter negative TTL — when the upstream is unhealthy and we
    // serve an empty body, we want to recover quickly after the RPC
    // comes back online (Security Audit N3 / Code Audit W1 follow-up).
    const NEGATIVE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
    // Outer timeout around the whole refresh — a pathological Klever
    // RPC can otherwise keep the refresh task running for ~64 min
    // (256 metadata calls × 15s each). Surfaces as the negative-TTL
    // empty payload.
    const REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let max_age_header = format!("public, max-age={}", CACHE_TTL.as_secs());

    // Fast path: cache hit under a read lock. Concurrent hits never
    // serialize (Code Audit W1 + Security Audit W2 fix).
    {
        let read = state.bootstrap_candidates_cache.read().await;
        if let Some(cached) = read.as_ref() {
            if cached.generated_at.elapsed() < CACHE_TTL {
                return (
                    [(header::CACHE_CONTROL, max_age_header.clone())],
                    Json(cached.payload.clone()),
                )
                    .into_response();
            }
        }
    }

    // Cache miss / stale — try to win the refresh slot. Single-flight
    // gate: many readers can wait here, but only one actually runs
    // the SC RPC fan-out.
    let _refresh_guard = state.bootstrap_candidates_refresh.lock().await;
    // Re-check the cache after acquiring — a sibling refresh may
    // have just populated it. (This is the standard double-checked
    // locking pattern for async caches and the reason we serialize
    // only refreshers, never readers.)
    {
        let read = state.bootstrap_candidates_cache.read().await;
        if let Some(cached) = read.as_ref() {
            if cached.generated_at.elapsed() < CACHE_TTL {
                return (
                    [(header::CACHE_CONTROL, max_age_header.clone())],
                    Json(cached.payload.clone()),
                )
                    .into_response();
            }
        }
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Helper closure to record a payload into the cache and return
    // the response — used by every termination branch below.
    async fn cache_and_respond(
        state: &Arc<AppState>,
        payload: serde_json::Value,
        now_unix: u64,
        ttl_for_freshness: std::time::Duration,
        max_age_header: String,
    ) -> axum::response::Response {
        // The "freshness duration" is used to set the Instant such
        // that elapsed-since-write < TTL behaves correctly for both
        // the positive (5min) and negative (60s) cache cases. We
        // backdate `generated_at` by (CACHE_TTL - ttl_for_freshness)
        // to achieve the effective shorter TTL while keeping a
        // single comparison on the read side.
        let backdate = CACHE_TTL.checked_sub(ttl_for_freshness).unwrap_or_default();
        let mut write = state.bootstrap_candidates_cache.write().await;
        *write = Some(crate::api::state::CachedBootstrapCandidates {
            payload: payload.clone(),
            generated_at: std::time::Instant::now()
                .checked_sub(backdate)
                .unwrap_or_else(std::time::Instant::now),
            generated_at_unix: now_unix,
        });
        drop(write);
        (
            [(header::CACHE_CONTROL, max_age_header)],
            Json(payload),
        )
            .into_response()
    }

    // Gather tier 1 (peer book) and tier 2 (config) synchronously —
    // both are local reads (RocksDB prefix iter, in-memory Vec) and
    // never need a network RPC. Doing this OUTSIDE the SC timeout
    // means we always have a useful response even when the on-chain
    // registry is unreachable (spec 13 §4.5 union requirement).
    let book = gather_book_candidates(&state);
    let config = gather_config_candidates(&state);

    // Tier 3 (SC) — wrapped in an outer timeout so a wedged Klever
    // RPC can't pin the refresh slot for the worst-case ~64 minutes
    // (256 metadata calls × 15s each; Code Audit W1 + Security Audit
    // W2 fix). On unconfigured / failure / timeout we still serve
    // tier 1+2 with a `source_note` describing the SC condition.
    //
    // Isolated-subnet mode (l2-node 0.46.5+, spec 13 §4.2): when
    // `[network.sc_discovery] enabled = false`, skip the SC call
    // path entirely so this handler does not generate any Klever
    // RPC traffic from the discovery surface. Audit invariant for
    // operators in regions where Klever endpoints must not be
    // queried.
    let (sc, sc_failure_note) = if !state.sc_discovery_enabled {
        (
            Vec::new(),
            Some(
                "sc_discovery disabled (isolated-subnet mode — the on-chain \
                 registry is not queried by this node)"
                    .to_string(),
            ),
        )
    } else if state.klever_node_url.is_empty() || state.contract_address.is_empty() {
        (
            Vec::new(),
            Some("this node is not configured to query the on-chain registry".to_string()),
        )
    } else {
        match tokio::time::timeout(REFRESH_TIMEOUT, gather_sc_candidates(&state)).await {
            Ok(Ok(entries)) => (entries, None),
            Ok(Err(reason)) => {
                tracing::debug!(reason = %reason, "bootstrap-candidates: SC fan-out failed");
                (Vec::new(), Some(reason))
            }
            Err(_elapsed) => {
                tracing::warn!(
                    timeout_secs = REFRESH_TIMEOUT.as_secs(),
                    "bootstrap-candidates: SC fan-out timed out"
                );
                (Vec::new(), Some("refresh budget exceeded".to_string()))
            }
        }
    };

    let candidates = merge_candidates(book, config, sc);

    // Positive TTL when SC contributed; negative TTL when SC was
    // unavailable so we re-poll soon. Tier 1+2 are stable within
    // either window — the shorter TTL just speeds SC recovery.
    let ttl = if sc_failure_note.is_some() {
        NEGATIVE_CACHE_TTL
    } else {
        CACHE_TTL
    };
    let mut payload = serde_json::json!({
        "candidates": candidates,
        "generated_at": now_unix,
        "cache_ttl_seconds": ttl.as_secs(),
    });
    if let Some(note) = sc_failure_note {
        payload["source_note"] = serde_json::Value::String(note);
    }
    cache_and_respond(&state, payload, now_unix, ttl, max_age_header).await
}

/// Internal candidate type carried through the merge pipeline. Built
/// per-tier by the `gather_*_candidates` helpers and turned into JSON
/// by `merge_candidates` after dedupe + sort + cap.
#[derive(Debug, Clone)]
struct CandidateEntry {
    multiaddr: String,
    peer_id: Option<String>,
    last_anchor_at: Option<u64>,
    /// Tier label — `"book"`, `"config"`, or `"sc"`.
    source: &'static str,
    paused: bool,
    /// Set only for SC-tier entries (the on-chain wallet that
    /// published the multiaddr). `None` for book/config — those
    /// tiers carry no wallet binding.
    owner_address: Option<String>,
    /// Coarse transport tag derived from the multiaddr's protocol
    /// stack (spec 13 §4.5, l2-node 0.46.5+). One of `"clearnet"`,
    /// `"onion"`, `"i2p"`, `"unknown"`. SDK consumers use this to
    /// filter peer candidates by reachability profile without
    /// re-parsing the multiaddr; dashboards surface a "high-
    /// resilience mode available" indicator when at least one peer
    /// reports `"onion"`.
    transport: &'static str,
}

impl CandidateEntry {
    fn into_json(self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "multiaddr": self.multiaddr,
            "peer_id": self.peer_id,
            "last_anchor_at": self.last_anchor_at,
            "source": self.source,
            "paused": self.paused,
            "transport": self.transport,
        });
        if let Some(owner) = self.owner_address {
            v["owner_address"] = serde_json::Value::String(owner);
        }
        v
    }
}

/// Reject multiaddr strings that exceed 256 bytes or contain any
/// non-printable-ASCII byte. Applied uniformly across all three tiers
/// — defense against a future SC bug or hostile chain returning
/// oversized payloads, AND against operator-config typos that smuggle
/// control characters into the response.
///
/// The full byte filter (`0x20..=0x7e` only) is intentionally narrower
/// than just stripping ASCII controls: real libp2p multiaddrs are
/// ASCII per spec (DNS names use Punycode for IDN, /p2p/ payloads
/// are base58, /onion3/ is lowercase base32). Permitting bytes ≥ 0x80
/// would let a hostile SC publish multiaddrs containing bidi-override
/// / zero-width / RTL marks that render deceptively in operator
/// dashboards or terminals (Phase A Security Audit N2 v0.46.0).
fn sanitize_multiaddr_str(s: &str) -> bool {
    const MAX_MULTIADDR_LEN: usize = 256;
    s.len() <= MAX_MULTIADDR_LEN && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Extract the `/p2p/<peer_id>` suffix from a multiaddr string, if
/// parseable. Returns `None` for malformed multiaddrs or those without
/// a `/p2p/` component (legal but unhelpful for the dedupe key).
fn extract_peer_id(multiaddr_str: &str) -> Option<String> {
    multiaddr_str
        .parse::<libp2p::Multiaddr>()
        .ok()
        .and_then(|m| {
            m.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::P2p(id) = p {
                    Some(id.to_string())
                } else {
                    None
                }
            })
        })
}

/// Tier 1 — read `PEER_DIRECTORY` (key `pa:<peer_id>` → multiaddr).
/// Capped at the same 256 as the persistence cap (`network/mod.rs`
/// `persist_peer_addr`). `last_anchor_at` is always `None` — the book
/// does not track anchor recency.
fn gather_book_candidates(state: &Arc<AppState>) -> Vec<CandidateEntry> {
    const PEER_ADDR_PREFIX: &[u8] = b"pa:";
    const MAX_BOOK_ENTRIES: usize = 256;
    let rows = match state.storage.prefix_iter_cf(
        crate::storage::schema::cf::PEER_DIRECTORY,
        PEER_ADDR_PREFIX,
        MAX_BOOK_ENTRIES,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "bootstrap-candidates: peer-book read failed");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(rows.len());
    for (key, value) in rows {
        // Key shape: `pa:<peer_id_str>`. Strip prefix AND require
        // the suffix decodes as UTF-8 — both are guaranteed by the
        // writer (`network/mod.rs::persist_peer_addr`), so a failure
        // means a corrupt row. Skip entirely rather than emit with
        // `peer_id: None`, which would silently break the dedupe
        // contract that callers rely on (Phase A Code Audit W2).
        let Some(peer_id) = key
            .strip_prefix(PEER_ADDR_PREFIX)
            .and_then(|suffix| std::str::from_utf8(suffix).ok())
            .map(|s| s.to_string())
        else {
            continue;
        };
        let multiaddr_str = match std::str::from_utf8(&value) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };
        if !sanitize_multiaddr_str(&multiaddr_str) {
            continue;
        }
        let transport =
            crate::chain::sc_views::classify_transport(&multiaddr_str).as_str();
        out.push(CandidateEntry {
            multiaddr: multiaddr_str,
            peer_id: Some(peer_id),
            last_anchor_at: None,
            source: "book",
            paused: false,
            owner_address: None,
            transport,
        });
    }
    out
}

/// Tier 2 — convert `[network] bootstrap_nodes` (snapshotted into
/// `AppState` at startup) to candidate entries. Multiaddrs without
/// a parseable `/p2p/` are still emitted so libp2p clients can dial
/// them; `peer_id` is then `None` (which also disables cross-tier
/// dedupe for that entry — acceptable because dedupe is by multiaddr
/// string, not by peer_id).
///
/// Capped at 256 entries to mirror the tier-1 cap. Defense against an
/// operator-misconfig that pastes a 100k-entry list, which would
/// otherwise push 100k allocations through `merge_candidates` before
/// the final 256-truncate (Phase A Security Audit W1).
fn gather_config_candidates(state: &Arc<AppState>) -> Vec<CandidateEntry> {
    const MAX_CONFIG_ENTRIES: usize = 256;
    let take = state.bootstrap_nodes.len().min(MAX_CONFIG_ENTRIES);
    let mut out = Vec::with_capacity(take);
    for raw in state.bootstrap_nodes.iter().take(MAX_CONFIG_ENTRIES) {
        if !sanitize_multiaddr_str(raw) {
            continue;
        }
        let transport = crate::chain::sc_views::classify_transport(raw).as_str();
        out.push(CandidateEntry {
            multiaddr: raw.clone(),
            peer_id: extract_peer_id(raw),
            last_anchor_at: None,
            source: "config",
            paused: false,
            owner_address: None,
            transport,
        });
    }
    out
}

/// Tier 3 — page `getActiveNodes`, fetch metadata per candidate,
/// build entries. Returns `Err(reason)` on hard SC failure so the
/// handler can surface it as `source_note` while still serving tier
/// 1+2.
async fn gather_sc_candidates(
    state: &Arc<AppState>,
) -> Result<Vec<CandidateEntry>, String> {
    // Same pagination + cap as sc_discovery::fan_out_once.
    const PAGE_SIZE: u32 = 64;
    const MAX_CANDIDATES: usize = 256;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let staleness_cutoff = now_unix.saturating_sub(state.max_peer_staleness_secs);

    let mut collected: Vec<crate::chain::sc_views::ActiveNode> = Vec::new();
    let mut offset: u32 = 0;
    let http = &state.klever_view_http;
    loop {
        match crate::chain::sc_views::get_active_nodes(
            http,
            &state.klever_node_url,
            &state.contract_address,
            offset,
            PAGE_SIZE,
        )
        .await
        {
            Ok(page) => {
                let page_len = page.len();
                if page_len == 0 {
                    break;
                }
                collected.extend(page);
                if collected.len() >= MAX_CANDIDATES {
                    collected.truncate(MAX_CANDIDATES);
                    break;
                }
                if (page_len as u32) < PAGE_SIZE {
                    break;
                }
                offset = offset.saturating_add(PAGE_SIZE);
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "bootstrap-candidates: getActiveNodes failed"
                );
                return Err("on-chain registry temporarily unavailable".to_string());
            }
        }
    }

    // Filter staleness + self before the metadata fan-out so we don't
    // burn one SC view call per skipped candidate.
    let self_addr = state.node_address.clone();
    let candidates: Vec<crate::chain::sc_views::ActiveNode> = collected
        .into_iter()
        .filter(|n| n.address != self_addr)
        .filter(|n| n.last_anchor_at > 0 && n.last_anchor_at >= staleness_cutoff)
        .collect();

    let mut entries: Vec<CandidateEntry> = Vec::with_capacity(candidates.len());
    for cand in &candidates {
        let multiaddrs = match crate::chain::sc_views::get_node_metadata(
            http,
            &state.klever_node_url,
            &state.contract_address,
            &cand.address,
        )
        .await
        {
            Ok(addrs) => addrs,
            Err(_) => continue,
        };
        if multiaddrs.is_empty() {
            // Privacy profile — operator chose not to publish (§6).
            continue;
        }
        for raw_addr in multiaddrs {
            if !sanitize_multiaddr_str(&raw_addr) {
                continue;
            }
            let transport =
                crate::chain::sc_views::classify_transport(&raw_addr).as_str();
            entries.push(CandidateEntry {
                peer_id: extract_peer_id(&raw_addr),
                multiaddr: raw_addr,
                last_anchor_at: Some(cand.last_anchor_at),
                source: "sc",
                // getActiveNodes excludes paused entries server-side
                // (spec 12 §2.10), so we surface a hard false rather
                // than recheck isNodePaused per candidate.
                paused: false,
                owner_address: Some(cand.address.clone()),
                transport,
            });
        }
    }

    Ok(entries)
}

/// Source ranking for tie-break when two entries share an identical
/// multiaddr AND identical `last_anchor_at` (including both being
/// `None`/0). Higher rank wins. Locked v0.46.0 plan OPEN 4 resolution
/// (2026-05-17): SC > book > config.
fn source_rank(s: &str) -> u8 {
    match s {
        "sc" => 2,
        "book" => 1,
        "config" => 0,
        _ => 0,
    }
}

/// Merge tier 1/2/3 candidate vectors into the final JSON list.
///
/// Dedupe key is the **exact multiaddr string** — a stronger key than
/// the spec 13 §4.5 model wording "by `(peer_id, transport)`". The
/// multiaddr embeds both the peer_id (`/p2p/<id>`) and the transport
/// (`/tcp/<port>` vs `/udp/<port>/quic-v1`), so the full-string key
/// entails the `(peer_id, transport)` model: TCP+QUIC variants of the
/// same peer have distinct multiaddrs and survive dedupe, while two
/// identical multiaddrs collapse. Collisions across tiers resolved
/// by: higher `last_anchor_at` wins (`None` treated as 0); on tie,
/// `source_rank` decides (SC > book > config).
///
/// Sort: entries with non-null `last_anchor_at` first, descending;
/// then null entries by `source_rank` descending (book before config)
/// for a stable, predictable dial order. Capped at 256.
fn merge_candidates(
    book: Vec<CandidateEntry>,
    config: Vec<CandidateEntry>,
    sc: Vec<CandidateEntry>,
) -> Vec<serde_json::Value> {
    const MAX_TOTAL_ENTRIES: usize = 256;
    use std::collections::HashMap;
    let mut by_multiaddr: HashMap<String, CandidateEntry> = HashMap::new();
    for entry in sc.into_iter().chain(book.into_iter()).chain(config.into_iter()) {
        match by_multiaddr.get(&entry.multiaddr) {
            None => {
                by_multiaddr.insert(entry.multiaddr.clone(), entry);
            }
            Some(existing) => {
                let existing_anchor = existing.last_anchor_at.unwrap_or(0);
                let new_anchor = entry.last_anchor_at.unwrap_or(0);
                let new_wins = new_anchor > existing_anchor
                    || (new_anchor == existing_anchor
                        && source_rank(entry.source) > source_rank(existing.source));
                if new_wins {
                    by_multiaddr.insert(entry.multiaddr.clone(), entry);
                }
            }
        }
    }

    let mut merged: Vec<CandidateEntry> = by_multiaddr.into_values().collect();
    merged.sort_by(|a, b| match (a.last_anchor_at, b.last_anchor_at) {
        (Some(ta), Some(tb)) => tb.cmp(&ta),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => source_rank(b.source).cmp(&source_rank(a.source)),
    });
    merged.truncate(MAX_TOTAL_ENTRIES);
    merged.into_iter().map(CandidateEntry::into_json).collect()
}

/// GET /api/v1/channels
///
/// Returns public/read-public channels for everyone. Private channels (type 2)
/// are only included for authenticated users who are a member of that channel.
pub async fn list_channels(
    Extension(state): Extension<Arc<AppState>>,
    auth_user: Option<Extension<AuthUser>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(20).min(100) as usize;

    match state
        .storage
        .prefix_iter_cf(cf::CHANNELS, &[], limit)
    {
        Ok(entries) => {
            let caller = auth_user.as_ref().map(|u| u.address.as_str());

            let channels: Vec<serde_json::Value> = entries
                .iter()
                .filter_map(|(_, v)| serde_json::from_slice::<serde_json::Value>(v).ok())
                .filter(|ch| {
                    if !is_private_channel(ch) {
                        return true;
                    }
                    // Private: only show if caller is a member
                    let Some(addr) = caller else { return false };
                    let Some(id) = ch.get("channel_id").and_then(|v| v.as_u64()) else { return false };
                    let member_key = crate::storage::schema::encode_channel_member_key(id, addr);
                    state.storage.exists_cf(cf::CHANNEL_MEMBERS, &member_key).unwrap_or(false)
                })
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

/// Check if a channel's metadata indicates it is private (type 2).
/// Handles both integer and legacy string representations.
/// Determine the GossipSub topic for a message envelope based on its type and payload.
///
/// Returns None if the message type doesn't map to a GossipSub topic.
fn gossip_topic_for_envelope(
    envelope: &crate::messages::envelope::Envelope,
    network_id: &str,
) -> Option<String> {
    use crate::messages::types::MessageType;
    use crate::network::gossip;

    match envelope.msg_type {
        MessageType::ChatMessage | MessageType::ChatEdit | MessageType::ChatDelete
        | MessageType::ChatReaction | MessageType::ChannelPinMessage
        | MessageType::ChannelUnpinMessage | MessageType::ChannelJoin
        | MessageType::ChannelLeave
        // ChannelUpdate carries channel metadata (display_name, description,
        // logo_cid, banner_cid, …). It was previously NOT gossiped, so a
        // channel's logo/metadata only ever existed on the node where it was
        // set — other nodes (which discover the channel via the chain scanner,
        // which does NOT carry these L2-only fields) showed no logo. Gossiping
        // it to the channel topic propagates metadata to subscribed nodes.
        // Safe: `authorize_channel_action` (process_message_inner step 302)
        // runs on every ingest path and rejects a ChannelUpdate whose author
        // isn't the channel creator or a mod with `can_edit_info`, so a relayed
        // update can't be forged. The creator is known on every node (set by
        // the chain scanner).
        | MessageType::ChannelUpdate => {
            // Extract channel_id from payload
            let payload: serde_json::Value = rmp_serde::from_slice(&envelope.payload).ok()?;
            let channel_id = payload.get("channel_id")?.as_u64()?;
            Some(gossip::channel_topic(network_id, channel_id))
        }
        MessageType::NewsPost => {
            Some(gossip::topic_news_global(network_id))
        }
        MessageType::ProfileUpdate => {
            Some(gossip::topic_profile(network_id))
        }
        MessageType::DirectMessage => {
            // DMs go to the recipient's topic
            let payload: serde_json::Value = rmp_serde::from_slice(&envelope.payload).ok()?;
            let recipient = payload.get("recipient")?.as_str()?;
            Some(gossip::dm_topic(network_id, recipient))
        }
        MessageType::NodeAnnouncement | MessageType::DeviceDelegation => {
            Some(gossip::topic_network(network_id))
        }
        _ => None,
    }
}

fn is_private_channel(channel_meta: &serde_json::Value) -> bool {
    match channel_meta.get("channel_type") {
        Some(serde_json::Value::Number(n)) => n.as_u64() == Some(2),
        Some(serde_json::Value::String(s)) => s == "Private",
        _ => false,
    }
}

/// Check if the caller has access to a private channel.
/// Returns true if the channel is public/read-public, or if the caller is a member.
fn check_channel_access(
    state: &AppState,
    channel_meta: &serde_json::Value,
    channel_id: u64,
    caller: Option<&str>,
) -> bool {
    if !is_private_channel(channel_meta) {
        return true; // public or read-public
    }
    let Some(addr) = caller else { return false };
    let member_key = crate::storage::schema::encode_channel_member_key(channel_id, addr);
    state.storage.exists_cf(cf::CHANNEL_MEMBERS, &member_key).unwrap_or(false)
}

/// Fetch channel metadata and check private channel access in one step.
/// Returns Ok(()) if access is allowed, Err(Response) if denied or not found.
fn require_channel_access(
    state: &AppState,
    channel_id: u64,
    caller: Option<&str>,
) -> Result<(), axum::response::Response> {
    match state.storage.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()) {
        Ok(Some(data)) => {
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                if !check_channel_access(state, &meta, channel_id, caller) {
                    return Err((StatusCode::NOT_FOUND, "channel not found").into_response());
                }
            }
            Ok(())
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "channel not found").into_response()),
        Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()),
    }
}

/// GET /api/v1/channels/:channel_id — extended response with moderators, pins, member_count
pub async fn get_channel(
    Extension(state): Extension<Arc<AppState>>,
    auth_user: Option<Extension<AuthUser>>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    match state
        .storage
        .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())
    {
        Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(channel) => {
                let caller = auth_user.as_ref().map(|u| u.address.as_str());
                if !check_channel_access(&state, &channel, channel_id, caller) {
                    // Private channel, caller not a member — return limited info
                    // so join/invite pages can display the channel name and type.
                    let prefix = channel_id.to_be_bytes();
                    let member_count = state.storage
                        .prefix_iter_cf(cf::CHANNEL_MEMBERS, &prefix, 10000)
                        .map(|e| e.len() as u64)
                        .unwrap_or(0);
                    let mut limited = serde_json::json!({
                        "channel_type": channel.get("channel_type").cloned().unwrap_or(serde_json::json!(2)),
                        "channel_id": channel_id,
                    });
                    // Include safe display fields
                    for key in ["display_name", "slug", "description"] {
                        if let Some(v) = channel.get(key) {
                            limited[key] = v.clone();
                        }
                    }
                    return Json(serde_json::json!({
                        "channel": limited,
                        "member_count": member_count,
                        "restricted": true,
                    })).into_response();
                }
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
    auth_user: Option<Extension<AuthUser>>,
    Path(channel_id): Path<u64>,
    Query(params): Query<MessageParams>,
) -> impl IntoResponse {
    // Block access to private channel messages for non-members
    if let Ok(Some(data)) = state.storage.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()) {
        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&data) {
            let caller = auth_user.as_ref().map(|u| u.address.as_str());
            if !check_channel_access(&state, &meta, channel_id, caller) {
                return (StatusCode::NOT_FOUND, "channel not found").into_response();
            }
        }
    }

    let limit = params.limit.unwrap_or(50).min(500) as usize;
    let prefix = channel_id.to_be_bytes();

    // Look up the authenticated user's read cursor for unread divider support
    let last_read_ts: Option<u64> = auth_user.as_ref().and_then(|u| {
        let read_key = crate::storage::schema::encode_channel_read_key(&u.address, channel_id);
        match state.storage.get_cf(cf::CHANNEL_READ_STATE, &read_key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                Some(u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8])))
            }
            _ => None,
        }
    });

    // Resolve `after` cursor to a seek key for incremental fetching
    let entries_result = if let Some(after_hex) = &params.after {
        // Parse the hex msg_id, look up the message to get its lamport_ts,
        // then verify the message belongs to this channel (prevents cross-channel oracle)
        let after_key = (|| -> Option<Vec<u8>> {
            let msg_id_bytes = hex::decode(after_hex).ok()?;
            let msg_id: [u8; 32] = msg_id_bytes.try_into().ok()?;
            let envelope_bytes = state.storage.get_message(&msg_id).ok()??;
            let envelope = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(
                &envelope_bytes,
            ).ok()?;
            let key = encode_channel_msg_key(channel_id, envelope.lamport_ts, &msg_id);
            // Verify this msg_id is indexed under this channel (not a foreign channel)
            if !state.storage.exists_cf(cf::CHANNEL_MSGS, &key).unwrap_or(false) {
                return None;
            }
            Some(key)
        })();
        match after_key {
            Some(seek_key) => state.storage.prefix_iter_cf_after(
                cf::CHANNEL_MSGS, &seek_key, &prefix, limit,
            ),
            // Cursor not found or not in this channel — fall back to full fetch
            None => state.storage.prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, limit),
        }
    } else {
        state.storage.prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, limit)
    };

    match entries_result {
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
                            let mut msg = envelope_to_json(&envelope, &state.identity);
                            enrich_message_json(&mut msg, &state.storage);
                            // Check if the message author is muted in this channel
                            if let Some(author) = msg.get("author").and_then(|v| v.as_str()) {
                                if state.storage.is_channel_muted(channel_id, author).unwrap_or(false) {
                                    if let serde_json::Value::Object(ref mut map) = msg {
                                        map.insert("muted".into(), serde_json::json!(true));
                                    }
                                }
                            }
                            messages.push(msg);
                        }
                    }
                }
            }
            let has_more = entries.len() == limit;
            let mut resp = serde_json::json!({
                "messages": messages,
                "has_more": has_more,
            });
            // Include the read cursor so clients can render an unread divider
            if let Some(ts) = last_read_ts {
                resp["last_read_ts"] = serde_json::json!(ts);
            }
            Json(resp).into_response()
        }
        Err(e) => {
            {
                tracing::error!(error = %e, "Storage error in API handler");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
        }
    }
}

/// Query parameters for `GET /api/v1/users/search`.
#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    /// Prefix to match against display_name (case-insensitive). Required, 1..=64 chars.
    pub q: String,
    /// Max results, clamped to 1..=50. Default 20.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// GET /api/v1/users/search
///
/// Case-insensitive prefix search on `display_name` for client-side
/// `@`-mention autocomplete. Backed by the USERS_BY_NAME prefix index
/// (maintained on every ProfileUpdate, backfilled from USERS on first
/// startup after v0.32.0).
///
/// Address-prefix matches: if `q` looks like a klv1-style prefix
/// (`klv1...`), results also include exact/prefix matches against the
/// USERS column family by address.
///
/// No authentication required — display names are public profile
/// information already exposed via `GET /users/{address}`.
///
/// Spec: 03-l2-node §4.1, 06-frontend §6.1.1.
pub async fn search_users(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<UserSearchQuery>,
) -> impl IntoResponse {
    // Validate query
    let q_trimmed = params.q.trim();
    if q_trimmed.is_empty() {
        return (StatusCode::BAD_REQUEST, "query parameter `q` is required").into_response();
    }
    if q_trimmed.len() > 64 {
        return (StatusCode::BAD_REQUEST, "query too long (max 64 chars)").into_response();
    }
    let limit = params.limit.unwrap_or(20).clamp(1, 50) as usize;

    let q_lower = q_trimmed.to_lowercase();
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut seen_addresses: std::collections::HashSet<String> = std::collections::HashSet::new();

    // 1. Prefix scan on USERS_BY_NAME for display-name matches.
    //    The index key is `lowercase(name) + 0x00 + address` so a prefix
    //    scan with the lowercased query bytes returns every row whose name
    //    starts with that query.
    if let Ok(entries) = state
        .storage
        .prefix_iter_cf(cf::USERS_BY_NAME, q_lower.as_bytes(), limit * 4)
    {
        for (key, _) in &entries {
            if results.len() >= limit {
                break;
            }
            let (_name_lower, address) = match decode_users_by_name_key(key) {
                Some(parts) => parts,
                None => continue,
            };
            if seen_addresses.contains(address) {
                continue;
            }
            if let Some(entry) = build_search_result(&state, address) {
                seen_addresses.insert(address.to_string());
                results.push(entry);
            }
        }
    }

    // 2. Address-prefix matches: if the query looks like a klv1 prefix,
    //    fall through to USERS to find any address starting with that
    //    prefix. This lets users complete `@klv1abc` even when no display
    //    name is set.
    if results.len() < limit && q_trimmed.starts_with("klv1") {
        if let Ok(entries) = state
            .storage
            .prefix_iter_cf(cf::USERS, q_trimmed.as_bytes(), limit * 2)
        {
            for (key, _) in &entries {
                if results.len() >= limit {
                    break;
                }
                let address = match std::str::from_utf8(key) {
                    Ok(s) if s.starts_with("klv1") => s,
                    _ => continue,
                };
                if seen_addresses.contains(address) {
                    continue;
                }
                if let Some(entry) = build_search_result(&state, address) {
                    seen_addresses.insert(address.to_string());
                    results.push(entry);
                }
            }
        }
    }

    Json(serde_json::json!({ "users": results })).into_response()
}

/// Build a single search-result entry for `address` from the USERS row.
/// Returns `None` if the user record is missing or unparseable.
fn build_search_result(state: &Arc<AppState>, address: &str) -> Option<serde_json::Value> {
    let bytes = state
        .storage
        .get_cf(cf::USERS, address.as_bytes())
        .ok()
        .flatten()?;
    let user: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let display_name = user.get("display_name").and_then(|v| v.as_str()).map(String::from);
    let avatar_cid = user.get("avatar_cid").and_then(|v| v.as_str()).map(String::from);
    // `verified` reflects on-chain registration: definition is
    // "USERS record exists AND `registered_at` is present AND > 0". The
    // chain scanner sets a real timestamp on UserRegistered events; L2-only
    // ProfileUpdate creates records with `registered_at: 0` (router.rs).
    // Missing field falls through to `false` — defensive against malformed
    // records but should never happen in normal flow because the
    // ProfileUpdate / UserRegistered handlers always populate the field.
    let verified = user
        .get("registered_at")
        .and_then(|v| v.as_u64())
        .map(|ts| ts > 0)
        .unwrap_or(false);
    Some(serde_json::json!({
        "address": address,
        "display_name": display_name,
        "avatar_cid": avatar_cid,
        "verified": verified,
    }))
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
            Ok(mut user) => {
                // Enrich with follower/following counts
                let (following_count, follower_count) = state
                    .storage
                    .get_follower_counts(&resolved)
                    .unwrap_or((0, 0));
                if let serde_json::Value::Object(ref mut map) = user {
                    map.insert("follower_count".into(), serde_json::json!(follower_count));
                    map.insert("following_count".into(), serde_json::json!(following_count));
                }
                Json(serde_json::json!({ "user": user })).into_response()
            }
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "corrupt user data").into_response(),
        },
        Ok(None) => {
            // Return an empty profile instead of 404 — the address is valid,
            // the user just hasn't set a profile yet. This avoids noisy 404s
            // in the browser console for users who have posted but never
            // configured a display name or avatar.
            let (following_count, follower_count) = state
                .storage
                .get_follower_counts(&resolved)
                .unwrap_or((0, 0));
            Json(serde_json::json!({
                "user": {
                    "address": resolved,
                    "follower_count": follower_count,
                    "following_count": following_count,
                }
            })).into_response()
        }
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
                            enrich_message_json(&mut post, &state.storage);
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
    enrich_message_json(&mut post, &state.storage);

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
                            let mut comment = envelope_to_json(&comment_env, &state.identity);
                            enrich_message_json(&mut comment, &state.storage);
                            result.push(comment);
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

    // Track incoming bytes for dashboard metrics
    state.counters.add_bytes_in(body.len() as u64);
    state.counters.inc_messages_received();

    match state.router.process_message(&body) {
        RouteResult::Accepted {
            msg_id,
            raw_bytes,
            msg_type,
        } => {
            state.counters.inc_messages_stored();

            // Real-time GossipSub delivery outcome (B4 fix proper,
            // 0.48.4). `None` for messages with no gossip topic; set to
            // the publish outcome otherwise. The message is already
            // persisted above, so this is purely an advisory hint.
            let mut delivery: Option<&'static str> = None;

            // Publish to GossipSub so other nodes receive the message
            if let Ok(envelope) =
                rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&raw_bytes)
            {
                if let Some(topic) = gossip_topic_for_envelope(&envelope, &state.klever_network) {
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let sent = state
                        .gossip_tx
                        .send(crate::network::GossipPublish {
                            topic,
                            data: raw_bytes.clone(),
                            respond_to: Some(tx),
                        })
                        .is_ok();
                    delivery = if !sent {
                        // Network task gone — message is stored, will
                        // propagate via backfill once a node serves it.
                        Some("pending")
                    } else {
                        // Bounded wait: the network task answers in
                        // microseconds in steady state. A timeout means
                        // it's busy, not that the publish failed — the
                        // message is stored regardless.
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(1500),
                            rx,
                        )
                        .await
                        {
                            Ok(Ok(crate::network::PublishOutcome::Propagated)) => {
                                Some("propagated")
                            }
                            Ok(Ok(crate::network::PublishOutcome::Degraded)) => {
                                Some("degraded")
                            }
                            Ok(Err(_)) | Err(_) => Some("pending"),
                        }
                    };
                }

                // Feed to notification engine for mention detection
                if let Some(ref engine) = state.notification_engine {
                    let engine = engine.clone();
                    tokio::spawn(async move {
                        engine.process(&envelope).await;
                    });
                }
            }

            Json(MessageResponse {
                msg_id: hex::encode(msg_id),
                delivery,
            })
            .into_response()
        }
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "message already exists").into_response()
        }
        RouteResult::PowRequired { address } => {
            state.counters.inc_pow_required();
            state.counters.record_rejection("PoW required", &address);
            pow_required_response(&state, &address)
        }
        RouteResult::Rejected(reason) => {
            state.counters.inc_failed_validations();
            state.counters.record_rejection(&reason, &_auth_user.address);
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// POST /api/v1/channels — create a channel via a ChannelCreate envelope.
///
/// Processes the message like `post_message` but also extracts the
/// `channel_id` from the `ChannelCreatePayload` so the response includes
/// it alongside the `msg_id`.
pub async fn create_channel(
    Extension(state): Extension<Arc<AppState>>,
    Extension(_auth_user): Extension<AuthUser>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::envelope::Envelope;
    use crate::messages::router::RouteResult;
    use crate::messages::types::ChannelCreatePayload;

    match state.router.process_message(&body) {
        RouteResult::Accepted { msg_id, .. } => {
            // Try to extract channel_id from the envelope payload
            let channel_id = rmp_serde::from_slice::<Envelope>(&body)
                .ok()
                .and_then(|env| {
                    rmp_serde::from_slice::<ChannelCreatePayload>(&env.payload)
                        .ok()
                        .map(|p| p.channel_id)
                });

            Json(serde_json::json!({
                "ok": true,
                "msg_id": hex::encode(msg_id),
                "channel_id": channel_id,
            }))
            .into_response()
        }
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "message already exists").into_response()
        }
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
    }
}

/// DELETE /api/v1/channels/:channel_id — delete a channel (creator only).
///
/// Removes channel metadata, all members, bans, pins, and invites.
/// Messages remain in storage but the channel is no longer discoverable.
pub async fn delete_channel(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    // Verify the requester is the channel creator
    let channel_key = channel_id.to_be_bytes();
    match state.storage.get_cf(cf::CHANNELS, &channel_key) {
        Ok(Some(data)) => {
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                let creator = meta.get("creator").and_then(|v| v.as_str()).unwrap_or("");
                if creator != auth_user.address {
                    return (StatusCode::FORBIDDEN, "only the channel creator can delete").into_response();
                }
            } else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "corrupt channel data").into_response();
            }
        }
        Ok(None) => return (StatusCode::NOT_FOUND, "channel not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Storage error deleting channel");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }

    // Atomically write tombstone + delete channel metadata
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut batch = WriteBatch::default();
    match (
        state.storage.cf_handle(cf::DELETED_CHANNELS),
        state.storage.cf_handle(cf::CHANNELS),
    ) {
        (Ok(tombstone_cf), Ok(channels_cf)) => {
            batch.put_cf(&tombstone_cf, &channel_key, &now.to_be_bytes());
            batch.delete_cf(&channels_cf, &channel_key);
            if let Err(e) = state.storage.write_batch(batch) {
                tracing::error!(channel_id, error = %e, "Failed to write channel deletion batch");
                return (StatusCode::INTERNAL_SERVER_ERROR, "deletion failed").into_response();
            }
        }
        _ => {
            tracing::error!(channel_id, "Missing column families for channel deletion");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }

    // Bulk cleanup — tombstone already prevents resurrection, so partial failure is safe
    let cleanup_cfs: &[(&str, usize)] = &[
        (cf::CHANNEL_MEMBERS, 10_000),
        (cf::CHANNEL_MODERATORS, 10_000),
        (cf::CHANNEL_BANS, 10_000),
        (cf::CHANNEL_PINS, 100),
        (cf::CHANNEL_INVITES, 10_000),
    ];
    for &(cf_name, limit) in cleanup_cfs {
        match state.storage.prefix_iter_cf(cf_name, &channel_key, limit) {
            Ok(entries) => {
                for (key, _) in &entries {
                    if let Err(e) = state.storage.delete_cf(cf_name, key) {
                        tracing::warn!(channel_id, cf = cf_name, error = %e, "Failed to delete entry during channel cleanup");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(channel_id, cf = cf_name, error = %e, "Failed to iterate during channel cleanup");
            }
        }
    }

    // Decrement total channels counter
    if let Err(e) = state.storage.decrement_stat(
        crate::storage::schema::state_keys::TOTAL_CHANNELS,
    ) {
        tracing::warn!(channel_id, error = %e, "Failed to decrement TOTAL_CHANNELS");
    }

    tracing::info!(channel_id, creator = %auth_user.address, "Channel deleted");
    Json(OkResponse { ok: true }).into_response()
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
            // DMs don't gossip via this path, so no delivery hint.
            Json(MessageResponse {
                msg_id: hex::encode(msg_id),
                delivery: None,
            })
            .into_response()
        }
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "message already exists").into_response()
        }
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
    if !address.starts_with("klv1") || address.len() < 44 {
        return (StatusCode::BAD_REQUEST, "invalid Klever address").into_response();
    }
    let limit = params.limit.unwrap_or(50).min(500) as usize;

    // Compute conversation_id from auth user + path address
    let conversation_id =
        crate::crypto::compute_conversation_id(&auth_user.address, &address);

    // Resolve `after` cursor for incremental DM fetching
    // Verify the cursor message belongs to this conversation (prevents cross-conversation oracle)
    let entries_result = if let Some(after_hex) = &params.after {
        let after_key = (|| -> Option<Vec<u8>> {
            let msg_id_bytes = hex::decode(after_hex).ok()?;
            let msg_id: [u8; 32] = msg_id_bytes.try_into().ok()?;
            let envelope_bytes = state.storage.get_message(&msg_id).ok()??;
            let envelope = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(
                &envelope_bytes,
            ).ok()?;
            let key = encode_dm_msg_key(&conversation_id, envelope.timestamp, &msg_id);
            // Verify this msg_id is indexed under this conversation
            if !state.storage.exists_cf(cf::DM_MESSAGES, &key).unwrap_or(false) {
                return None;
            }
            Some(key)
        })();
        match after_key {
            Some(seek_key) => state.storage.prefix_iter_cf_after(
                cf::DM_MESSAGES, &seek_key, &conversation_id, limit,
            ),
            // Cursor not found or not in this conversation — fall back to full fetch
            None => state.storage.prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, limit),
        }
    } else {
        state.storage.prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, limit)
    };

    match entries_result {
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
                            let mut msg = envelope_to_json(&envelope, &state.identity);
                            enrich_message_json(&mut msg, &state.storage);
                            messages.push(msg);
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
    if !address.starts_with("klv1") || address.len() < 44 {
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

        // Count unread messages, excluding own
        if let Ok(msgs) = state
            .storage
            .prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, 100)
        {
            let mut count = 0u64;
            for (msg_key, _) in &msgs {
                if msg_key.len() >= 72 {
                    let ts_bytes: [u8; 8] =
                        msg_key[32..40].try_into().unwrap_or([0u8; 8]);
                    let msg_ts = u64::from_be_bytes(ts_bytes);
                    if msg_ts > last_read_ts {
                        // Fetch envelope to check author
                        let msg_id: [u8; 32] = msg_key[40..72].try_into().unwrap_or([0u8; 32]);
                        if let Ok(Some(env_bytes)) = state.storage.get_message(&msg_id) {
                            if let Ok(env) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&env_bytes) {
                                let resolved = state.identity.resolve(&env.author)
                                    .unwrap_or_else(|_| env.author.clone());
                                if resolved != auth_user.address {
                                    count += 1;
                                }
                            }
                        }
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
                delivery: None,
            })
            .into_response()
        }
        RouteResult::Duplicate => {
            (StatusCode::CONFLICT, "already reposted").into_response()
        }
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
                        let mut bm = envelope_to_json(&envelope, &state.identity);
                        enrich_message_json(&mut bm, &state.storage);
                        bookmarks.push(bm);
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
    auth_user: Option<Extension<AuthUser>>,
    Path(channel_id): Path<u64>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let caller = auth_user.as_ref().map(|u| u.address.as_str());
    if let Err(resp) = require_channel_access(&state, channel_id, caller) {
        return resp;
    }

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
    auth_user: Option<Extension<AuthUser>>,
    Path(channel_id): Path<u64>,
) -> impl IntoResponse {
    let caller = auth_user.as_ref().map(|u| u.address.as_str());
    if let Err(resp) = require_channel_access(&state, channel_id, caller) {
        return resp;
    }

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
                            let mut pin = envelope_to_json(&envelope, &state.identity);
                            enrich_message_json(&mut pin, &state.storage);
                            pinned_messages.push(pin);
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
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
                .map(|env| {
                    let mut post = envelope_to_json(&env, &state.identity);
                    enrich_message_json(&mut post, &state.storage);
                    post
                })
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
            // Distinguish "storage backend offline" (Kubo not running /
            // unreachable — the node is configured for media but the
            // daemon is down, e.g. a text-only deployment) from a genuine
            // upload error. The former gets a 503 + actionable message so
            // the client tells the user to switch nodes rather than
            // surfacing a confusing generic 500.
            //
            // Uses the CACHED `is_available()` (≤15s stale), not a fresh
            // probe: `upload_media` has no per-IP limiter (only the global
            // governor), so a fresh probe on every failed upload would let
            // an authenticated client amplify uncapped 5s outbound probes
            // against a slow/blackholed Kubo. A 15s-stale liveness signal
            // is more than adequate to pick an error message. (Security
            // audit, v0.48.7.)
            if !ipfs.is_available().await {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "media uploads unavailable on this node (storage backend offline) — switch to a node with media support",
                )
                    .into_response();
            }
            (StatusCode::INTERNAL_SERVER_ERROR, "upload failed").into_response()
        }
    }
}

/// GET / HEAD `/api/v1/media/:cid` — retrieve media from IPFS (public).
///
/// Same handler serves both methods; HEAD elides the body but emits
/// identical headers (RFC 9110 §9.3.2). Architecture (v0.39, audit-revised):
///
///   1. **`If-None-Match` 304 short-circuit runs BEFORE semaphore
///      acquisition.** Cache lookup is free; for cache misses,
///      existence is probed via `exists_local` (Kubo `files/stat?
///      offline=true`) so an attacker can't weaponize the existence
///      oracle into a DHT-walk amplification vector.
///   2. **Body-fetch path bounded by `media_semaphore`** (32 permits),
///      preventing memory-amplification DoS.
///   3. **`media_cache` (moka LRU) stores `(bytes, content_type)`
///      tuples.** Cache hits skip both the IPFS fetch AND the
///      content-type re-sniff. Coalesced fills via `try_get_with`
///      prevent thundering-herd on cold cache.
///   4. **Range requests on uncached large files** use
///      `IpfsClient::get_range`; only the requested bytes leave IPFS.
///   5. **`Content-Disposition` policy: `inline` for an explicit
///      allowlist of media MIME prefixes; everything else is
///      `attachment`.** Inverts the pre-audit blacklist that would
///      auto-inline any new MIME type a future detector might add.
///   6. **HEAD responses use the (status, headers) IntoResponse form**
///      (no body in tuple), so the user-set `Content-Length` is the
///      only one emitted — no double-header / smuggling risk.
pub async fn get_media(
    Extension(state): Extension<Arc<AppState>>,
    axum::extract::ConnectInfo(peer_addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(cid): Path<String>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let is_head = method == axum::http::Method::HEAD;
    let ipfs = match &state.ipfs {
        Some(c) => c,
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, "IPFS not configured")
                .into_response();
        }
    };

    let etag = format!("\"{}\"", cid);
    let cache_control = "public, max-age=31536000, immutable";

    // ----- If-None-Match short-circuit (NO permit yet) --------------
    // Audit warning W-1 (code) + W-3 (security): both held the permit
    // through a `get_size` call that could hit the DHT for unknown
    // CIDs. We now check the cache (free) and then `exists_local`
    // (offline-only) before paying the permit cost. The 304 path
    // is also the busiest in CDN-fronted deployments — every
    // periodic revalidator hits it.
    if let Some(if_none_match) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
    {
        if if_none_match == "*" || if_none_match == etag {
            let cache_hit = state.media_cache.get(&cid).await.is_some();
            let exists = cache_hit
                || ipfs.exists_local(&cid).await.unwrap_or(false);
            if exists {
                return build_304(etag, cache_control);
            }
            return (StatusCode::NOT_FOUND, "media not found").into_response();
        }
    }

    // ----- Per-IP + global limiter (v0.41, v0.42 trust model) ------
    // Resolve the real client IP, then acquire one per-IP slot AND
    // one global slot. Per-IP cap exhaustion returns 429 fast (no
    // global queue cost paid); global exhaustion queues FIFO;
    // tracked-IP-map overflow returns 503 (v0.42).
    //
    // IP resolution rules (v0.42 — see `crate::trusted_proxies`):
    //   * TCP peer is loopback OR in `api.trusted_proxies` →
    //     consult `Forwarded` / `X-Forwarded-For` headers, walking
    //     the forwarding chain right-to-left and skipping trusted
    //     entries. The first untrusted address is the real client.
    //   * Otherwise → use the peer directly; headers are
    //     attacker-controlled and ignored.
    let client_ip = resolve_client_ip(peer_addr, &headers, &state.trusted_proxies);
    let _permit = match state.media_limiter.acquire(client_ip).await {
        Ok(p) => p,
        Err(crate::api::media_limiter::RejectReason::PerIpExceeded) => {
            // 429 + Retry-After. The retry value is a best-effort
            // hint — there's no way to know exactly when a permit
            // will free; 5 seconds is "long enough that an honest
            // burst client backs off, short enough that a real
            // browser tab regains responsiveness quickly".
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [
                    (header::RETRY_AFTER, "5".to_string()),
                    (
                        header::CONTENT_TYPE,
                        "text/plain; charset=utf-8".to_string(),
                    ),
                ],
                "too many concurrent media requests from this client; retry shortly",
            )
                .into_response();
        }
        Err(crate::api::media_limiter::RejectReason::Shutdown) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "shutting down")
                .into_response();
        }
        Err(crate::api::media_limiter::RejectReason::CapacityExceeded) => {
            // v0.42: the per-IP tracking map hit its hard cap and the
            // inline sweep couldn't free a slot. Tell the client to
            // back off — Retry-After is set to the background sweep
            // interval (5 min) so an honest client polling on this
            // CID resumes after the next cleanup. The 503 also tells
            // CDNs not to cache this response. Operationally this
            // path only fires under an adversarial /24-rotation flood.
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [
                    (header::RETRY_AFTER, "300".to_string()),
                    (
                        header::CONTENT_TYPE,
                        "text/plain; charset=utf-8".to_string(),
                    ),
                ],
                "media subsystem at capacity; retry shortly",
            )
                .into_response();
        }
    };

    // ----- Cache hit fast path --------------------------------------
    if let Some(cached) = state.media_cache.get(&cid).await {
        return serve_from_cached(
            is_head,
            cached,
            etag,
            cache_control,
            &cid,
            &headers,
        );
    }

    // ----- Cache miss: actual size first ----------------------------
    // `get_size` (v0.39.0) now uses `files/stat?offline=true` and
    // returns the ACTUAL file size (not `CumulativeSize`), so the
    // `total` we report in Content-Range matches what `get_range`
    // can deliver. Audit warning W-2 (security) / #3 (code).
    //
    // Local-miss: try cross-node peer fallback BEFORE 404-ing (spec
    // 3 §media-fetch, l2-node 0.46.7+). The fallback may pin a
    // verified copy into the local Kubo, so we re-stat after success
    // to pick up the now-present blob via the normal path. Disabled
    // cleanly if [media] peer_fallback_enabled = false or Klever is
    // unconfigured — `state.media_fallback` is None in that case.
    let total = match ipfs.get_size(&cid).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(cid = %cid, error = %e, "IPFS stat failed (local miss)");
            // Peer fallback attempt. Returns `Some(bytes)` only when
            // a peer returned 200 AND the IPFS add+verify succeeded.
            // Bytes are already pinned locally as a side effect.
            let fallback_bytes = match state.media_fallback.as_ref() {
                Some(fb) => {
                    crate::api::media_fallback::fetch_via_peers(
                        fb,
                        &state.storage,
                        ipfs,
                        &cid,
                        ipfs.max_upload_bytes(),
                    )
                    .await
                }
                None => None,
            };
            match fallback_bytes {
                Some(bytes) => {
                    // Bytes are now pinned locally. Build a cached
                    // response directly instead of round-tripping
                    // back through Kubo for size: we already have
                    // the bytes in hand.
                    let content_type = detect_content_type(&bytes).to_string();
                    let cached = CachedMedia {
                        bytes,
                        content_type,
                        last_modified: std::time::SystemTime::now(),
                    };
                    // Insert into the LRU for subsequent requests
                    // (small files only — large files stream from
                    // the now-pinned local copy on the next request).
                    if (cached.bytes.len() as u64) <= state.media_cache_item_bytes as u64 {
                        state.media_cache.insert(cid.clone(), cached.clone()).await;
                    }
                    return serve_from_cached(
                        is_head,
                        cached,
                        etag,
                        cache_control,
                        &cid,
                        &headers,
                    );
                }
                None => {
                    tracing::warn!(
                        cid = %cid,
                        "media not found locally and peer fallback declined or failed"
                    );
                    return (StatusCode::NOT_FOUND, "media not found").into_response();
                }
            }
        }
    };

    // Stream-range path: large file + Range. No full buffer. The
    // streamed path has no stored `last_modified` (we don't store
    // anything for uncached blobs), so `If-Range` is matched by
    // ETag only — an `If-Range: <date>` against the streamed path
    // never matches and the Range is dropped, which then falls
    // through to the full-fetch cacheable path below (or the file
    // is too large to cache and we serve a 200 of the whole thing).
    let range_value = determine_range(&headers, &etag, None);
    if let Some(ref range_str) = range_value {
        if total > state.media_cache_item_bytes as u64 {
            return serve_range_streamed(
                is_head, ipfs, &cid, range_str, total, etag, cache_control,
            )
            .await;
        }
    }

    // Cacheable path (small file, any request) OR large file + no
    // Range. For cacheable files we use `try_get_with` so concurrent
    // requests for the same cold CID coalesce into a single IPFS
    // fetch (audit note N-4 security). For large files we go direct
    // — caching them would evict 16× more useful small items.
    let cached: CachedMedia = if total <= state.media_cache_item_bytes as u64 {
        // Closure captures `ipfs` and `cid` by reference. The future
        // is constructed each time but only the FIRST waiter's
        // future runs; subsequent waiters skip the IPFS round-trip.
        let cid_for_fetch = cid.clone();
        let init = async {
            let bytes = ipfs.get(&cid_for_fetch).await?;
            let content_type = detect_content_type(&bytes).to_string();
            Ok::<_, anyhow::Error>(CachedMedia {
                bytes,
                content_type,
                last_modified: std::time::SystemTime::now(),
            })
        };
        match state
            .media_cache
            .try_get_with(cid.clone(), init)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(cid = %cid, error = %*e, "IPFS retrieval failed");
                return (StatusCode::NOT_FOUND, "media not found").into_response();
            }
        }
    } else {
        // Too large to cache. Direct fetch — no coalesce, no insert.
        match ipfs.get(&cid).await {
            Ok(bytes) => {
                let content_type = detect_content_type(&bytes).to_string();
                CachedMedia {
                    bytes,
                    content_type,
                    last_modified: std::time::SystemTime::now(),
                }
            }
            Err(e) => {
                tracing::warn!(cid = %cid, error = %e, "IPFS retrieval failed");
                return (StatusCode::NOT_FOUND, "media not found").into_response();
            }
        }
    };

    serve_from_cached(
        is_head,
        cached,
        etag,
        cache_control,
        &cid,
        &headers,
    )
}

/// Build the `Content-Disposition` header value for a media response.
///
/// **Inline allowlist** (post-audit revision): only the EXACT MIME
/// types below are rendered inline; everything else is downloaded as
/// an attachment. Audit warning W-4 (security).
///
/// The list is an EXACT enumeration (not a prefix match) so that
/// dangerous subtypes are excluded by default. Notably:
///
///   - **`image/svg+xml` is NOT inline.** SVG can contain `<script>`
///     elements and is a stored-XSS vector at the media origin. A
///     prefix-match on `image/` would have admitted SVG; the exact
///     enumeration excludes it.
///   - **`text/*` is never inline.** Even `text/plain` can be sniffed
///     by old browsers into `text/html` under some legacy paths;
///     forcing `attachment` removes the entire XSS class.
///   - **`application/*` is inline only for `application/pdf`**, where
///     modern browsers sandbox the renderer heavily.
///
/// Any future detector addition (e.g. `image/heic`) requires an
/// explicit code change here, with the security review that comes
/// with it.
fn media_content_disposition(content_type: &str, cid: &str) -> String {
    // Keep this list in lockstep with `detect_content_type`. Sniffable
    // types that ARE safe to render inline live here; everything else
    // is forced to `attachment`.
    const INLINE_ALLOWED: &[&str] = &[
        // Raster images — no script execution.
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        // Video containers — `<video>` decoder, no JS surface.
        "video/mp4",
        "video/webm",
        "video/ogg",
        "video/x-msvideo",
        // Audio — `<audio>` decoder.
        "audio/mpeg",
        "audio/wav",
        "audio/flac",
        // PDF — modern browsers sandbox the renderer.
        "application/pdf",
    ];
    let inline = INLINE_ALLOWED.iter().any(|t| *t == content_type);
    if inline {
        format!("inline; filename=\"{}\"", cid)
    } else {
        format!("attachment; filename=\"{}\"", cid)
    }
}

/// Resolve the real client IP for the per-IP media limiter.
///
/// v0.41 introduced loopback-only XFF trust; v0.42 generalizes this
/// to configurable trusted_proxies + RFC 7239 Forwarded support +
/// rightmost-untrusted-walk for chain resolution. See
/// `crate::trusted_proxies` for the security rationale.
fn resolve_client_ip(
    peer: std::net::SocketAddr,
    headers: &axum::http::HeaderMap,
    trusted_proxies: &crate::trusted_proxies::TrustedProxies,
) -> std::net::IpAddr {
    let forwarded = headers
        .get("forwarded")
        .and_then(|v| v.to_str().ok());
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    crate::trusted_proxies::resolve_client_ip(peer, forwarded, xff, trusted_proxies)
}

/// 304 Not Modified response. Used by the If-None-Match short-circuit.
fn build_304(etag: String, cache_control: &'static str) -> axum::response::Response {
    (
        StatusCode::NOT_MODIFIED,
        [
            (header::ETAG, etag),
            (header::ACCEPT_RANGES, "bytes".to_string()),
            (header::CACHE_CONTROL, cache_control.to_string()),
        ],
    )
        .into_response()
}

/// 416 Range Not Satisfiable response.
fn build_416(total: u64) -> axum::response::Response {
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        [
            (header::ACCEPT_RANGES, "bytes".to_string()),
            (header::CONTENT_RANGE, format!("bytes */{}", total)),
        ],
    )
        .into_response()
}

/// Serve a media body from a fully-buffered `CachedMedia` (cache hit
/// OR just-fetched small file). Handles 200 / 206 / 416 selection
/// based on the Range header; elides the body for HEAD requests.
///
/// `If-Range` matching is performed here (v0.42) because the cache
/// owns `last_modified`, which the HTTP-date form of `If-Range`
/// needs to compare against.
fn serve_from_cached(
    is_head: bool,
    cached: CachedMedia,
    etag: String,
    cache_control: &'static str,
    cid: &str,
    headers_in: &axum::http::HeaderMap,
) -> axum::response::Response {
    let CachedMedia { bytes, content_type, last_modified } = cached;
    let total = bytes.len() as u64;
    let disposition = media_content_disposition(&content_type, cid);
    // RFC 7231 §7.1.1.2: Last-Modified is HTTP-date format.
    let last_modified_str = httpdate::fmt_http_date(last_modified);

    // If-Range matching uses the cached `last_modified` so the
    // HTTP-date form is honored — see `match_if_range` for the
    // ETag-first, date-fallback semantics.
    let range_value = determine_range(headers_in, &etag, Some(last_modified));
    let range_str = match range_value {
        None => {
            // 200 OK. HEAD uses the `(status, headers)` tuple form
            // (NO body) — that's the only way to guarantee axum
            // doesn't emit a body-derived `Content-Length: 0`
            // alongside our user-set `Content-Length: <total>`
            // (audit warning W-5 security).
            let headers = [
                (header::CONTENT_TYPE, content_type),
                (header::ACCEPT_RANGES, "bytes".to_string()),
                (header::VARY, "Range".to_string()),
                (header::ETAG, etag),
                (header::LAST_MODIFIED, last_modified_str),
                (header::CACHE_CONTROL, cache_control.to_string()),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                (header::CONTENT_DISPOSITION, disposition),
                (header::CONTENT_LENGTH, total.to_string()),
            ];
            return if is_head {
                (StatusCode::OK, headers).into_response()
            } else {
                (StatusCode::OK, headers, bytes).into_response()
            };
        }
        Some(s) => s,
    };

    let (start, end) = match parse_byte_range(&range_str, total) {
        Some(r) => r,
        None => return build_416(total),
    };
    let start_usize = match usize::try_from(start) {
        Ok(v) => v,
        Err(_) => return build_416(total),
    };
    let end_usize = match usize::try_from(end) {
        Ok(v) => v,
        Err(_) => return build_416(total),
    };
    // Zero-copy slice — Bytes holds a refcount + view, doesn't copy
    // the underlying buffer.
    let slice: Bytes = bytes.slice(start_usize..=end_usize);
    let content_length = slice.len() as u64;
    let headers = [
        (header::CONTENT_TYPE, content_type),
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (header::VARY, "Range".to_string()),
        (header::ETAG, etag),
        (header::LAST_MODIFIED, last_modified_str),
        (header::CACHE_CONTROL, cache_control.to_string()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        (header::CONTENT_DISPOSITION, disposition),
        (
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end, total),
        ),
        (header::CONTENT_LENGTH, content_length.to_string()),
    ];
    if is_head {
        (StatusCode::PARTIAL_CONTENT, headers).into_response()
    } else {
        (StatusCode::PARTIAL_CONTENT, headers, slice).into_response()
    }
}

/// Check whether a request's `If-Range` header (if any) authorizes
/// serving a 206 partial response. Per RFC 7233 §3.2:
///
///   * **No `If-Range`** → unconditionally honor any `Range`.
///   * **`If-Range: "<etag>"`** → match against the resource ETag;
///     on match honor Range, otherwise serve full 200.
///   * **`If-Range: <HTTP-date>`** → match against the resource's
///     `Last-Modified` (if any) with second-level resolution; same
///     on/off semantics.
///
/// `last_modified` is `None` when the caller is on a path that has
/// no stored timestamp (the stream-range path for uncached large
/// files). In that case the date form is treated as "no match" —
/// safe default, the client just won't get a 206 from a date-form
/// `If-Range` for uncached streams. They WILL still get a 206 from
/// an ETag-form `If-Range` because CIDs are immutable.
fn match_if_range(
    headers: &axum::http::HeaderMap,
    etag: &str,
    last_modified: Option<std::time::SystemTime>,
) -> bool {
    let value = match headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) {
        Some(v) if !v.is_empty() => v,
        _ => return true, // No If-Range → Range honored unconditionally.
    };
    // ETag form: literal comparison against our ETag. RFC 7233
    // §3.2 requires *strong* comparison for If-Range; our ETag is
    // always strong (no `W/` prefix — see `etag` construction in
    // `get_media`), so bitwise equality IS the strong form. A
    // client that sends `If-Range: W/"<cid>"` (e.g. a CDN that
    // rewrites strong to weak) will correctly fail to match here
    // and fall back to a full 200 — RFC-compliant.
    if value == etag {
        return true;
    }
    // HTTP-date form: parse and compare against last_modified at
    // second resolution. RFC 7233 requires an *exact* validator
    // match (no "newer-than" semantics here).
    if let Some(lm) = last_modified {
        if let Ok(parsed) = httpdate::parse_http_date(value) {
            let lm_secs = lm.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs());
            let in_secs = parsed.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs());
            return lm_secs.is_some() && lm_secs == in_secs;
        }
    }
    false
}

/// Determine the effective `Range` header value after applying any
/// `If-Range` precondition. Returns `Some(range)` when the Range
/// should be honored, `None` when it should be ignored (either
/// because no Range was sent, or because If-Range invalidated it).
fn determine_range(
    headers: &axum::http::HeaderMap,
    etag: &str,
    last_modified: Option<std::time::SystemTime>,
) -> Option<String> {
    if !match_if_range(headers, etag, last_modified) {
        return None;
    }
    headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

/// Stream-range path: large uncached file + Range request. Fetches
/// only the requested bytes from IPFS + a 16-byte prefix for
/// content-type sniffing. Never buffers the full blob.
async fn serve_range_streamed(
    is_head: bool,
    ipfs: &crate::ipfs::client::IpfsClient,
    cid: &str,
    range_str: &str,
    total: u64,
    etag: String,
    cache_control: &'static str,
) -> axum::response::Response {
    let (start, end) = match parse_byte_range(range_str, total) {
        Some(r) => r,
        None => return build_416(total),
    };
    let length = end - start + 1;

    // Fetch just the requested range from IPFS.
    let slice = match ipfs.get_range(cid, start, length).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(cid = %cid, error = %e, "IPFS range fetch failed");
            return (StatusCode::BAD_GATEWAY, "range fetch failed").into_response();
        }
    };

    // Defense against a malicious / misbehaving Kubo that reports an
    // inflated size but truncates the actual response. Without this
    // check we'd emit `Content-Range: bytes start-end/total` where
    // `end - start + 1` doesn't equal the body length we're sending.
    // Audit critical C-1 (security).
    if slice.len() as u64 != length {
        tracing::warn!(
            cid = %cid,
            expected = length,
            actual = slice.len(),
            "IPFS range returned wrong length"
        );
        return (StatusCode::BAD_GATEWAY, "range length mismatch").into_response();
    }

    // For content-type sniffing we need bytes from the start of the
    // file, not the requested range. If we're already serving the
    // start, reuse those bytes; otherwise do a 16-byte prefix fetch.
    // Surface a sniff-fetch failure as 502 rather than silently
    // flipping the disposition to `attachment` (audit warning W-2).
    let content_type = if start == 0 {
        detect_content_type(&slice)
    } else {
        match ipfs.get_range(cid, 0, 16).await {
            Ok(head) => detect_content_type(&head),
            Err(e) => {
                tracing::warn!(cid = %cid, error = %e, "sniff prefix fetch failed");
                return (StatusCode::BAD_GATEWAY, "sniff fetch failed").into_response();
            }
        }
    };
    let disposition = media_content_disposition(&content_type, cid);
    let content_length = slice.len() as u64;
    let headers = [
        (header::CONTENT_TYPE, content_type),
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (header::VARY, "Range".to_string()),
        (header::ETAG, etag),
        (header::CACHE_CONTROL, cache_control.to_string()),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        (header::CONTENT_DISPOSITION, disposition),
        (
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end, total),
        ),
        (header::CONTENT_LENGTH, content_length.to_string()),
    ];
    if is_head {
        (StatusCode::PARTIAL_CONTENT, headers).into_response()
    } else {
        (StatusCode::PARTIAL_CONTENT, headers, slice).into_response()
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
    /// **OPTIONAL** (l2-node 0.49.0+, P-0 dual-signed delegation):
    /// hex-encoded Ed25519 signature by the DEVICE key over the SAME
    /// canonical claim string the wallet signed
    /// (`ogmara-device-claim:{device_pubkey_hex}:{wallet_address}:{timestamp}`,
    /// Klever message format). This is the device's **proof-of-possession**.
    ///
    /// When BOTH the wallet signature (`wallet_signature`) and this device
    /// signature are present and valid, the node constructs a dual-signed
    /// `DeviceDelegation` envelope and gossips it to peers, so every node
    /// learns the device→wallet mapping for **free** (no on-chain TX). Peers
    /// re-verify both signatures (see `router::verify_device_delegation_claim`),
    /// so a relaying node is never trusted: impersonating a wallet needs the
    /// wallet key, hijacking a device needs the device key.
    ///
    /// Without this field the registration is **local-only** (back-compat with
    /// pre-0.49 clients and the K5 device-signed-claim flow) — peers learn the
    /// mapping later via identity-sync backfill (P-1) or never.
    #[serde(default)]
    pub device_signature: Option<String>,
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

    // Derive the device's ogd1... address from the public key
    let device_verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&device_pubkey_bytes) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid Ed25519 public key").into_response(),
    };
    let device_address = match crate::crypto::device_pubkey_to_address(&device_verifying_key) {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "failed to derive device address").into_response(),
    };

    // Validate wallet address format — must be a klv1 wallet address, not a device address
    if !body.wallet_address.starts_with("klv1") {
        return (StatusCode::BAD_REQUEST, "wallet_address must be a klv1 wallet address").into_response();
    }
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

    // Build the claim string for signature verification.
    // Uses the original (non-normalized) hex from the request, since the signer
    // signed this exact string.
    // Canonical claim uses the LOWERCASE device pubkey (matches the SDK's
    // buildDeviceClaim and the gossip-side verify in
    // router::verify_device_delegation_claim). Using the lowercased local var
    // here keeps local-verify, gossip-build, and gossip-verify byte-identical,
    // so a non-lowercase client fails consistently (closed) instead of
    // registering locally but silently failing to propagate.
    let claim_string = format!(
        "ogmara-device-claim:{}:{}:{}",
        device_pubkey_hex, body.wallet_address, body.timestamp
    );

    let sig_bytes = match hex::decode(&body.wallet_signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return (StatusCode::BAD_REQUEST, "invalid wallet_signature hex").into_response(),
    };
    let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid signature bytes").into_response(),
    };

    // Try wallet signature first (desktop Klever Extension flow)
    let wallet_verifying_key = match crate::crypto::address_to_verifying_key(&body.wallet_address) {
        Ok(k) => k,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid wallet_address").into_response(),
    };

    let wallet_sig_valid = crate::crypto::signing::verify_klever_message(
        &wallet_verifying_key,
        claim_string.as_bytes(),
        &signature,
    ).is_ok();

    if !wallet_sig_valid {
        // Fallback: accept device-signed claim (K5 mobile browser flow).
        // The device signs the claim instead of the wallet. Security:
        // caller must be the device itself (proven by auth headers).
        let device_sig_valid = crate::crypto::signing::verify_klever_message(
            &device_verifying_key,
            claim_string.as_bytes(),
            &signature,
        ).is_ok();

        if !device_sig_valid {
            tracing::warn!(
                device = %device_address,
                wallet = %body.wallet_address,
                "Device registration failed: neither wallet nor device signature valid"
            );
            return (StatusCode::UNAUTHORIZED, "signature verification failed").into_response();
        }

        // Device-signed: caller MUST be the device itself (not a relay)
        if auth_user.signing_address != device_address {
            return (StatusCode::FORBIDDEN, "device-signed claims must come from the device itself").into_response();
        }

        tracing::info!(
            device = %device_address,
            wallet = %body.wallet_address,
            "Device registered via device-signed claim (K5 fallback)"
        );
    }

    // Check device limit per wallet.
    // If list_devices fails (e.g. corrupted entry from pre-v0.15 migration),
    // log a warning and proceed — the new registration will overwrite the
    // corrupted data. Better to recover than to permanently block the wallet.
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
            tracing::warn!(
                error = %e,
                wallet = %body.wallet_address,
                "Failed to list devices (corrupted entry?), proceeding with registration"
            );
            // Continue — the new device claim will be written regardless
        }
    }

    // Store the claim (with normalized lowercase hex for consistency)
    let claim = crate::storage::rocks::DeviceClaim {
        device_address: device_address.clone(),
        wallet_address: body.wallet_address.clone(),
        device_pubkey_hex: device_pubkey_hex.clone(),
        wallet_signature: body.wallet_signature.clone(),
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

            // B2 propagation (spec 1 §device-delegation, l2-node
            // 0.46.8+): if the client supplied a wallet-signed
            // DeviceDelegation envelope, route it through the message
            // router and publish on the network gossip topic so peer
            // nodes update their device→wallet maps. The router-side
            // apply arm is what makes the propagated envelope durable
            // on receivers (`messages/router.rs::update_indexes`).
            //
            // Failures here DO NOT fail the request — local registration
            // already succeeded, and a malformed envelope from a buggy
            // client should not undo that. We log loudly so operator
            // metrics surface the drift.
            // P-0 (0.49.0): free, dual-signed delegation gossip. Propagate
            // ONLY when the wallet authorized the claim (verified above) AND a
            // device_signature is supplied. The device proof-of-possession is
            // verified by the router during gossip-build below
            // (verify_device_delegation_claim), which is the authoritative gate
            // — an invalid device_signature yields propagated=false, never a
            // bad envelope. The node constructs the dual-signed envelope from
            // the two claim signatures it holds; peers re-verify both, so no
            // relaying node is trusted and no on-chain TX is needed.
            let mut propagated = false;
            if wallet_sig_valid {
                if let Some(device_sig_hex) = body.device_signature.as_deref() {
                    propagated = build_and_gossip_dual_delegation(
                        &state,
                        &device_pubkey_hex,
                        &body.wallet_address,
                        body.timestamp,
                        &body.wallet_signature,
                        device_sig_hex,
                    )
                    .await;
                }
            }

            tracing::info!(
                device = %device_address,
                wallet = %body.wallet_address,
                registered_by = %auth_user.signing_address,
                propagated,
                "Device registered"
            );
            Json(serde_json::json!({
                "ok": true,
                "device_address": device_address,
                "wallet_address": body.wallet_address,
                "propagated": propagated,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to register device");
            (StatusCode::INTERNAL_SERVER_ERROR, "registration failed").into_response()
        }
    }
}

/// Construct a **dual-signed** `DeviceDelegation` envelope from the two claim
/// signatures collected at registration, route it through the standard router
/// pipeline (which re-verifies both signatures), and publish it on the
/// network-coordination gossip topic. Returns `true` iff the router accepted
/// the envelope AND a gossip publish was queued (P-0, l2-node 0.49.0+).
///
/// The propagated artifact is the wallet-signed claim plus the device's
/// proof-of-possession over the SAME claim — so any receiving node verifies
/// the binding itself (see `router::verify_device_delegation_claim`) and never
/// trusts this node. This is the FREE, permissionless delegation path: no
/// on-chain transaction, just two signatures the clients already produce.
///
/// Local registration is intentionally NOT undone on any failure here —
/// operators see `propagated = false` on the response plus a structured log.
/// `device_pubkey_hex` MUST already be lowercase (canonical claim form).
async fn build_and_gossip_dual_delegation(
    state: &Arc<AppState>,
    device_pubkey_hex: &str,
    wallet_address: &str,
    timestamp: u64,
    wallet_signature_hex: &str,
    device_signature_hex: &str,
) -> bool {
    use crate::messages::envelope::Envelope;
    use crate::messages::router::RouteResult;
    use crate::messages::types::{DelegationPermissions, DeviceDelegationPayload, MessageType};

    // Decode the wallet's claim signature → becomes the envelope signature.
    let wallet_sig = match hex::decode(wallet_signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            tracing::info!(wallet = %wallet_address,
                "wallet_signature is not 64-byte hex; skipping delegation gossip");
            return false;
        }
    };

    // The device proof-of-possession travels in the payload; the router
    // re-verifies it against `device_pub_key` over the canonical claim.
    let payload = DeviceDelegationPayload {
        device_pub_key: device_pubkey_hex.to_string(),
        permissions: DelegationPermissions {
            can_send_messages: true,
            can_create_channels: true,
            can_update_profile: true,
        },
        expires_at: None,
        device_signature: device_signature_hex.to_string(),
    };
    let payload_bytes = match rmp_serde::to_vec_named(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, wallet = %wallet_address,
                "Failed to serialize DeviceDelegation payload; skipping gossip");
            return false;
        }
    };

    // msg_id = Keccak-256(wallet_pubkey + payload + timestamp) — matches
    // `verify_msg_id` on every receiver.
    let wallet_pubkey = match crate::crypto::address_to_pubkey_bytes(wallet_address) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let msg_id = crate::crypto::compute_msg_id(&wallet_pubkey, &payload_bytes, timestamp);

    let envelope = Envelope {
        version: 1,
        msg_type: MessageType::DeviceDelegation,
        msg_id,
        author: wallet_address.to_string(),
        timestamp,
        // Delegations are ordered by claim timestamp (registered_at), not by
        // the Lamport clock, so 0 is correct and avoids minting clock values
        // for a wallet-authored envelope the node merely relays.
        lamport_ts: 0,
        payload: payload_bytes,
        signature: wallet_sig,
        relay_path: Vec::new(),
    };
    let envelope_bytes = match envelope.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, wallet = %wallet_address,
                "Failed to serialize DeviceDelegation envelope; skipping gossip");
            return false;
        }
    };

    // Route through the full pipeline (re-verifies BOTH signatures via
    // verify_device_delegation_claim, stores, applies). On Accepted/Duplicate
    // the mapping is durable network-wide; publish to gossip.
    match state.router.process_message(&envelope_bytes) {
        RouteResult::Accepted { raw_bytes, .. } => {
            let topic = crate::network::gossip::topic_network(&state.klever_network);
            if let Err(e) = state.gossip_tx.send(crate::network::GossipPublish {
                topic,
                data: raw_bytes,
                respond_to: None,
            }) {
                tracing::warn!(error = %e, wallet = %wallet_address,
                    "Failed to enqueue DeviceDelegation envelope for gossip publish");
                return false;
            }
            true
        }
        RouteResult::Duplicate => {
            tracing::debug!(wallet = %wallet_address,
                "DeviceDelegation already known; treating as propagated");
            true
        }
        RouteResult::Rejected(reason) => {
            tracing::warn!(reason = %reason, wallet = %wallet_address,
                "Router rejected constructed DeviceDelegation; not propagating");
            false
        }
        RouteResult::PowRequired { .. } => {
            tracing::warn!(wallet = %wallet_address,
                "DeviceDelegation unexpectedly required PoW; not propagating");
            false
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

    // The authenticated wallet must own this device. Tombstone with the
    // current time (P-2) so a later stale delegation can't resurrect it.
    let revoked_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    match state.identity.revoke_device(&device_address, &auth_user.address, revoked_at) {
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
/// the latest messages in that channel. Also reports a per-channel count of
/// unread messages where the viewer was @-mentioned (capped at 99).
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
    let mut mentions: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    for (key, value) in &channels {
        // Channel keys are channel_id as u64 BE bytes
        if key.len() < 8 { continue; }
        let channel_id = u64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));

        // Skip private channels the user isn't a member of
        if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(value) {
            if !check_channel_access(&state, &meta, channel_id, Some(&auth_user.address)) {
                continue;
            }
        }

        // Get the user's read cursor for this channel
        let read_key = crate::storage::schema::encode_channel_read_key(&auth_user.address, channel_id);
        let last_read_ts = match state.storage.get_cf(cf::CHANNEL_READ_STATE, &read_key) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                u64::from_be_bytes(bytes.try_into().unwrap_or([0u8; 8]))
            }
            _ => 0, // Never read — everything is unread
        };

        // Count messages newer than last_read_ts, excluding the user's own messages.
        // Within those, count how many @-mention the viewer (after device→wallet resolution).
        //
        // Hot-path optimization: the channel-message index key embeds the lamport
        // timestamp at bytes 8..16. Decode that first and skip the RocksDB point
        // lookup + envelope decode + payload decode entirely when the message is
        // already-read. Also short-circuit once both counters hit 99 — that's the
        // display cap, so any further decoding is wasted work.
        let prefix = channel_id.to_be_bytes();
        if let Ok(msgs) = state.storage.prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, 100) {
            let mut count = 0u64;
            let mut mention_count = 0u64;
            for (msg_key, _) in &msgs {
                if count >= 99 && mention_count >= 99 { break; }
                // Key: (channel_id:8, lamport_ts:8, msg_id:32)
                if msg_key.len() < 48 { continue; }
                let key_ts = u64::from_be_bytes(msg_key[8..16].try_into().unwrap_or([0u8; 8]));
                // Fast skip: if the index timestamp is already <= read cursor,
                // the message is read; no need to fetch the envelope at all.
                if key_ts <= last_read_ts { continue; }
                let msg_id: [u8; 32] = msg_key[16..48].try_into().unwrap_or([0u8; 32]);
                let env_bytes = match state.storage.get_message(&msg_id) {
                    Ok(Some(b)) => b,
                    _ => continue,
                };
                let env = match rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&env_bytes) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                // Envelope timestamp is the authoritative wall-clock check.
                // Index lamport_ts can lag wall-clock under heavy fan-in.
                if env.timestamp <= last_read_ts { continue; }
                let resolved = state.identity.resolve(&env.author)
                    .unwrap_or_else(|_| env.author.clone());
                if resolved == auth_user.address { continue; }
                count += 1;
                // Only decode the payload if we still need mention info.
                if mention_count < 99 {
                    if let Ok(payload) = rmp_serde::from_slice::<crate::messages::types::ChatMessagePayload>(&env.payload) {
                        let mentioned = payload.mentions.iter().any(|m| {
                            let resolved_m = state.identity.resolve(m)
                                .unwrap_or_else(|_| m.clone());
                            resolved_m == auth_user.address
                        });
                        if mentioned {
                            mention_count += 1;
                        }
                    }
                }
            }
            if count > 0 {
                unread.insert(channel_id.to_string(), serde_json::json!(count.min(99)));
            }
            if mention_count > 0 {
                mentions.insert(channel_id.to_string(), serde_json::json!(mention_count.min(99)));
            }
        }
    }

    Json(serde_json::json!({ "unread": unread, "mentions": mentions })).into_response()
}

/// GET /api/v1/settings — retrieve synced settings (authenticated)
pub async fn get_settings(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    match state.storage.get_settings(&auth_user.address) {
        Ok(Some(data)) => {
            // Data is stored as JSON string by the SettingsSync handler
            match serde_json::from_slice::<serde_json::Value>(&data) {
                Ok(json) => Json(json).into_response(),
                Err(_) => {
                    // Legacy format (raw bytes) — return hex-encoded for backwards compat
                    Json(serde_json::json!({
                        "encrypted_settings": data,
                        "nonce": [],
                        "key_epoch": 0,
                    })).into_response()
                }
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no settings found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get settings");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// GET /api/v1/account/export — download all user data as a text file (authenticated)
pub async fn export_account(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
) -> impl IntoResponse {
    let address = &auth_user.address;
    let now = {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = ts.as_secs();
        let days_since_epoch = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;
        let (year, month, day) = days_to_ymd(days_since_epoch as i64);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        )
    };
    let date_short = &now[..10]; // YYYY-MM-DD

    let mut out = String::with_capacity(64 * 1024);
    out.push_str("=== OGMARA ACCOUNT EXPORT ===\n");
    out.push_str(&format!("Date: {}\n", now));
    out.push_str(&format!("Wallet: {}\n", address));

    // --- Profile ---
    out.push_str("\n=== PROFILE ===\n");
    match state.storage.get_cf(cf::USERS, address.as_bytes()) {
        Ok(Some(data)) => match serde_json::from_slice::<serde_json::Value>(&data) {
            Ok(profile) => {
                out.push_str(&serde_json::to_string_pretty(&profile).unwrap_or_default());
                out.push('\n');
            }
            Err(_) => out.push_str("[corrupt data]\n"),
        },
        Ok(None) => out.push_str("[no profile]\n"),
        Err(e) => out.push_str(&format!("[error: {}]\n", e)),
    }

    // --- News Posts ---
    let news_limit = 10_000;
    let mut news_prefix = Vec::with_capacity(address.len() + 1);
    news_prefix.extend_from_slice(address.as_bytes());
    news_prefix.push(0xFF);

    let news_entries = state
        .storage
        .prefix_iter_cf(cf::NEWS_BY_AUTHOR, &news_prefix, news_limit)
        .unwrap_or_default();
    out.push_str(&format!("\n=== NEWS POSTS ({}) ===\n", news_entries.len()));
    for (key, _) in &news_entries {
        // Key: (author, 0xFF, !timestamp:8, msg_id:32)
        if key.len() >= news_prefix.len() + 8 + 32 {
            let msg_id: [u8; 32] = match key[key.len() - 32..].try_into() {
                Ok(id) => id,
                Err(_) => continue,
            };
            if let Ok(Some(envelope_bytes)) = state.storage.get_message(&msg_id) {
                if let Ok(envelope) = rmp_serde::from_slice::<
                    crate::messages::envelope::Envelope,
                >(&envelope_bytes)
                {
                    let json = envelope_to_json(&envelope, &state.identity);
                    out.push_str(&serde_json::to_string(&json).unwrap_or_default());
                    out.push('\n');
                }
            }
        }
    }

    // --- Channel Memberships ---
    let channels = state
        .storage
        .prefix_iter_cf(cf::CHANNELS, &[], 10_000)
        .unwrap_or_default();
    let mut memberships = Vec::new();
    for (key, value) in &channels {
        if key.len() < 8 {
            continue;
        }
        let channel_id = u64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
        let member_key =
            crate::storage::schema::encode_channel_member_key(channel_id, address);
        if state
            .storage
            .exists_cf(cf::CHANNEL_MEMBERS, &member_key)
            .unwrap_or(false)
        {
            let slug = serde_json::from_slice::<serde_json::Value>(value)
                .ok()
                .and_then(|v| v.get("slug").and_then(|s| s.as_str()).map(String::from))
                .unwrap_or_default();

            let (role, joined_at) = state
                .storage
                .get_cf(cf::CHANNEL_MEMBERS, &member_key)
                .ok()
                .flatten()
                .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
                .map(|v| {
                    let role = v
                        .get("role")
                        .and_then(|r| r.as_str())
                        .unwrap_or("member")
                        .to_string();
                    let joined = v
                        .get("joined_at")
                        .and_then(|j| j.as_u64())
                        .unwrap_or(0);
                    (role, joined)
                })
                .unwrap_or_else(|| ("member".to_string(), 0));

            memberships.push(format!(
                "channel_id={}, slug={}, role={}, joined_at={}",
                channel_id, slug, role, joined_at
            ));
        }
    }
    out.push_str(&format!(
        "\n=== CHANNEL MEMBERSHIPS ({}) ===\n",
        memberships.len()
    ));
    for m in &memberships {
        out.push_str(m);
        out.push('\n');
    }

    // --- Bookmarks ---
    let bookmarks = state
        .storage
        .list_bookmarks(address, 10_000)
        .unwrap_or_default();
    out.push_str(&format!("\n=== BOOKMARKS ({}) ===\n", bookmarks.len()));
    for msg_id in &bookmarks {
        out.push_str(&hex::encode(msg_id));
        out.push('\n');
    }

    // --- DM Conversations ---
    let dm_prefix = address.as_bytes().to_vec();
    let dm_entries = state
        .storage
        .prefix_iter_cf(cf::DM_CONVERSATIONS, &dm_prefix, 2000)
        .unwrap_or_default();

    let addr_len = address.len();
    let mut seen_convos = std::collections::HashSet::new();
    let mut dm_lines = Vec::new();

    for (key, value) in &dm_entries {
        if key.len() < addr_len + 8 + 32 {
            continue;
        }
        let conversation_id: [u8; 32] =
            match key[addr_len + 8..addr_len + 40].try_into() {
                Ok(id) => id,
                Err(_) => continue,
            };
        if !seen_convos.insert(conversation_id) {
            continue;
        }

        let conv_id_hex = hex::encode(conversation_id);
        let peer = serde_json::from_slice::<serde_json::Value>(value)
            .ok()
            .and_then(|v| v.get("peer").and_then(|p| p.as_str()).map(String::from))
            .unwrap_or_else(|| "unknown".to_string());

        let msg_count = state
            .storage
            .prefix_iter_cf(cf::DM_MESSAGES, &conversation_id, 1000)
            .map(|entries| entries.len())
            .unwrap_or(0);

        dm_lines.push(format!(
            "conversation_id={}, peer={}, message_count={}",
            conv_id_hex, peer, msg_count
        ));
    }

    out.push_str(&format!(
        "\n=== DM CONVERSATIONS ({}) ===\n",
        dm_lines.len()
    ));
    for line in &dm_lines {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("Note: DM content is encrypted and exported as ciphertext.\n");

    // --- Following ---
    let following = state
        .storage
        .get_following(address, 10_000)
        .unwrap_or_default();
    out.push_str(&format!("\n=== FOLLOWING ({}) ===\n", following.len()));
    for addr in &following {
        out.push_str(addr);
        out.push('\n');
    }

    // --- Followers ---
    let followers = state
        .storage
        .get_followers(address, 10_000)
        .unwrap_or_default();
    out.push_str(&format!("\n=== FOLLOWERS ({}) ===\n", followers.len()));
    for addr in &followers {
        out.push_str(addr);
        out.push('\n');
    }

    // --- Settings (encrypted) ---
    out.push_str("\n=== SETTINGS (encrypted) ===\n");
    match state.storage.get_settings(address) {
        Ok(Some(blob)) => {
            out.push_str(&hex::encode(&blob));
            out.push('\n');
        }
        Ok(None) => out.push_str("[no settings]\n"),
        Err(e) => out.push_str(&format!("[error: {}]\n", e)),
    }

    out.push_str("\n=== END OF EXPORT ===\n");

    // Build address short form for filename (first 10 chars + last 4)
    let addr_short = if address.len() > 14 {
        format!(
            "{}..{}",
            &address[..10],
            &address[address.len() - 4..]
        )
    } else {
        address.clone()
    };

    let filename = format!("ogmara-export-{}-{}.txt", addr_short, date_short);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        out,
    )
        .into_response()
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Basic content type detection from file magic bytes.
fn detect_content_type(data: &[u8]) -> String {
    // Images
    if data.starts_with(b"\x89PNG") {
        "image/png".to_string()
    } else if data.starts_with(b"\xFF\xD8\xFF") {
        "image/jpeg".to_string()
    } else if data.starts_with(b"GIF8") {
        "image/gif".to_string()
    } else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        "image/webp".to_string()
    }
    // Documents
    else if data.starts_with(b"%PDF") {
        "application/pdf".to_string()
    }
    // Video / audio containers — these are the critical adds for inline
    // playback. WebKit's `<video>` codec dispatch reads Content-Type
    // before it touches the bitstream; an `application/octet-stream`
    // response makes it bail with "format not supported" even when the
    // file is perfectly playable MP4.
    //
    // MP4 / MOV / 3GP / M4V — all `ftyp`-prefixed ISO Base Media files.
    // We return `video/mp4` uniformly: the spec-correct alternatives
    // (`audio/mp4` for M4A, `video/quicktime` for MOV) are mostly
    // distinguished by major_brand bytes 8-11, but browsers accept
    // `video/mp4` for all of them inside `<video>` and `<audio>`, and
    // splitting would just create more failure paths for callers that
    // hardcode the MIME type.
    else if data.len() >= 8 && &data[4..8] == b"ftyp" {
        "video/mp4".to_string()
    }
    // WebM (and MKV — same EBML signature). Browsers play WebM inline
    // in `<video>`; MKV is an out-of-scope edge case but the MIME is
    // still useful for download dispatch.
    else if data.starts_with(b"\x1A\x45\xDF\xA3") {
        "video/webm".to_string()
    }
    // Ogg container (Theora video, Vorbis/Opus audio). Returning
    // `video/ogg` works for both — `<audio>` accepts it as well.
    else if data.starts_with(b"OggS") {
        "video/ogg".to_string()
    }
    // AVI (RIFF AVI ).
    else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"AVI " {
        "video/x-msvideo".to_string()
    }
    // MP3 — either ID3v2-tagged or raw frames with MPEG audio sync
    // word (0xFFE0+). The latter check matches the first 11 bits of an
    // MPEG-1/2/2.5 frame header, which is the universal "this is mp3"
    // signal in untagged files.
    else if data.starts_with(b"ID3")
        || (data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0)
    {
        "audio/mpeg".to_string()
    }
    // WAV (RIFF WAVE).
    else if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        "audio/wav".to_string()
    }
    // FLAC.
    else if data.starts_with(b"fLaC") {
        "audio/flac".to_string()
    }
    // Fallback: opaque blob. Browsers will offer a download instead of
    // attempting to render.
    else {
        "application/octet-stream".to_string()
    }
}

/// Parse the value of a `Range:` request header into an inclusive
/// `(start, end)` byte tuple given the total resource size.
///
/// Supported forms:
///   - `bytes=START-END`  — explicit range
///   - `bytes=START-`     — open-ended ("from START to EOF")
///   - `bytes=-SUFFIX`    — suffix length ("last SUFFIX bytes")
///
/// Multi-range (`bytes=0-99,200-299`) and any malformed input return
/// `None`; the caller falls back to a full-body response.
///
/// Returns `Some((start, end))` only when the range is fully inside
/// the resource: `start <= end < total`. Out-of-range, zero-size, or
/// inverted ranges return `None` — caller can choose 416 vs 200.
fn parse_byte_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let s = value.trim().strip_prefix("bytes=")?;
    if s.contains(',') {
        // Multi-range — we don't emit multipart/byteranges responses;
        // ignore and let caller decide on full body or 416.
        return None;
    }
    let (start_str, end_str) = s.split_once('-')?;
    if total == 0 {
        return None;
    }
    let (start, end) = if start_str.is_empty() {
        // Suffix-length form: `bytes=-N` means "last N bytes".
        let suffix: u64 = end_str.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        let clamped = suffix.min(total);
        (total - clamped, total - 1)
    } else if end_str.is_empty() {
        // Open-ended form: `bytes=N-` means "from N to EOF".
        let start: u64 = start_str.parse().ok()?;
        (start, total - 1)
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end: u64 = end_str.parse().ok()?;
        (start, end)
    };
    if start > end || end >= total {
        return None;
    }
    Some((start, end))
}

// ---------------------------------------------------------------------------
// User posts, notifications, and moderation endpoints
// ---------------------------------------------------------------------------

/// GET /api/v1/users/{address}/posts — list news posts by a specific author.
///
/// Public endpoint. Returns paginated posts in reverse-chronological order,
/// enriched with reaction counts, comment count, repost count, and
/// edit/deletion status — mirroring the `list_news` enrichment pattern.
pub async fn get_user_posts(
    Extension(state): Extension<Arc<AppState>>,
    Path(address): Path<String>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    // Validate klv1 address format
    if !address.starts_with("klv1") || address.len() < 44 {
        return (StatusCode::BAD_REQUEST, "invalid klv1 address").into_response();
    }

    let limit = params.limit.unwrap_or(20).min(100) as usize;
    let page = params.page.unwrap_or(1);

    // Resolve to wallet address for consistent lookup
    let resolved = state.identity.resolve(&address).unwrap_or_else(|_| address.clone());

    // Prefix scan NEWS_BY_AUTHOR: key = author + 0xFF + !timestamp + msg_id
    let mut prefix = Vec::with_capacity(resolved.len() + 1);
    prefix.extend_from_slice(resolved.as_bytes());
    prefix.push(0xFF);

    // Skip entries for pagination (page-based offset)
    let skip = ((page.saturating_sub(1)) as usize) * limit;
    let fetch_limit = skip + limit;

    match state.storage.prefix_iter_cf(cf::NEWS_BY_AUTHOR, &prefix, fetch_limit) {
        Ok(entries) => {
            let mut posts = Vec::with_capacity(limit);
            for (key, _) in entries.into_iter().skip(skip) {
                // Key layout: author_bytes + 0xFF + !timestamp(8) + msg_id(32)
                if key.len() < prefix.len() + 8 + 32 {
                    continue;
                }
                let msg_id_start = key.len() - 32;
                let msg_id: [u8; 32] = match key[msg_id_start..].try_into() {
                    Ok(id) => id,
                    Err(_) => continue,
                };

                // Fetch envelope
                let envelope_bytes = match state.storage.get_message(&msg_id) {
                    Ok(Some(bytes)) => bytes,
                    _ => continue,
                };
                let envelope = match rmp_serde::from_slice::<
                    crate::messages::envelope::Envelope,
                >(&envelope_bytes) {
                    Ok(env) => env,
                    Err(_) => continue,
                };

                let mut post = envelope_to_json(&envelope, &state.identity);
                enrich_message_json(&mut post, &state.storage);
                if let serde_json::Value::Object(ref mut map) = post {
                    // Enrich with engagement counts
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
                posts.push(post);
            }

            let total = posts.len();
            Json(serde_json::json!({
                "posts": posts,
                "total": total,
                "page": page,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_user_posts");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// GET /api/v1/notifications — list notifications for the authenticated user.
///
/// Authenticated endpoint. Returns notifications in reverse-chronological
/// order, optionally filtered by a `since` timestamp.
pub async fn get_notifications(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Query(params): Query<NotificationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(200) as usize;
    let since = params.since;

    match state.storage.get_notifications(&auth_user.address, since, limit) {
        Ok(notifications) => {
            let total = notifications.len();
            Json(serde_json::json!({
                "notifications": notifications,
                "total": total,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_notifications");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// GET /api/v1/moderation/reports — view reports and counter-votes for a target.
///
/// Public endpoint for transparency. Requires `?target=<msg_id_hex>`.
/// Returns reports, counter-vote count, and a simplified moderation score.
pub async fn get_moderation_reports(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<ModerationReportParams>,
) -> impl IntoResponse {
    // Decode the target msg_id from hex
    let target_id = match hex::decode(&params.target) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, "invalid target msg_id hex").into_response(),
    };

    // Fetch reports
    let reports = match state.storage.get_reports(&target_id) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Storage error in get_moderation_reports");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };

    // Fetch counter-vote count
    let counter_votes = state.storage.get_counter_vote_count(&target_id).unwrap_or(0);

    // Compute simplified moderation score:
    // reports weigh negative, counter-votes weigh positive
    let report_count = reports.len() as i64;
    let score = report_count * -1 + counter_votes as i64;

    Json(serde_json::json!({
        "target": params.target,
        "reports": reports,
        "counter_votes": counter_votes,
        "score": score,
    }))
    .into_response()
}

/// GET /api/v1/moderation/user/{address} — user moderation reputation summary.
///
/// Public endpoint. Returns a reputation profile including report counts,
/// counter-vote counts, account age, and a computed trust score.
pub async fn get_user_moderation(
    Extension(state): Extension<Arc<AppState>>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    // Validate klv1 address format
    if !address.starts_with("klv1") || address.len() < 44 {
        return (StatusCode::BAD_REQUEST, "invalid klv1 address").into_response();
    }

    let resolved = state.identity.resolve(&address).unwrap_or_else(|_| address.clone());

    // Account age: look up user profile for registration timestamp
    let account_age_days = match state.storage.get_cf(cf::USERS, resolved.as_bytes()) {
        Ok(Some(data)) => {
            if let Ok(profile) = serde_json::from_slice::<serde_json::Value>(&data) {
                let registered_at = profile
                    .get("registered_at")
                    .and_then(|v| v.as_u64())
                    .or_else(|| profile.get("created_at").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                if registered_at > 0 {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    // registered_at is in milliseconds
                    now_ms.saturating_sub(registered_at) / (1000 * 60 * 60 * 24)
                } else {
                    0
                }
            } else {
                0
            }
        }
        _ => 0,
    };

    // Scan REPORTS to count reports filed BY this user and AGAINST this user's content.
    // REPORTS key: (target_id:32, reporter_address) → ReportRecord JSON
    // We need to scan all reports — this is expensive but bounded by total report count.
    let all_reports = state.storage.prefix_iter_cf(cf::REPORTS, &[], 10_000).unwrap_or_default();

    let mut total_reports_filed: u64 = 0;
    let mut total_reports_received: u64 = 0;
    let mut targets_with_reports: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    for (key, value) in &all_reports {
        if key.len() <= 32 {
            continue;
        }
        let target_id: [u8; 32] = match key[..32].try_into() {
            Ok(id) => id,
            Err(_) => continue,
        };
        let reporter_address = String::from_utf8_lossy(&key[32..]);

        // Count reports filed by this user
        if reporter_address == resolved {
            total_reports_filed += 1;
        }

        // Check if the report target is authored by this user
        if let Ok(record) = serde_json::from_slice::<serde_json::Value>(value) {
            // The report record may contain the target author, but more reliably
            // we check the target message's envelope
            if !targets_with_reports.contains(&target_id) {
                if let Ok(Some(env_bytes)) = state.storage.get_message(&target_id) {
                    if let Ok(env) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&env_bytes) {
                        let msg_author = state.identity.resolve(&env.author).unwrap_or_else(|_| env.author.clone());
                        if msg_author == resolved {
                            targets_with_reports.insert(target_id);
                        }
                    }
                }
            }
            // If we already know this target belongs to the user, count this report
            if targets_with_reports.contains(&target_id) {
                total_reports_received += 1;
                let _ = record; // suppress unused warning
            }
        }
    }

    // Count counter-votes on reports targeting this user's content
    let mut counter_votes_received: u64 = 0;
    for target_id in &targets_with_reports {
        counter_votes_received += state.storage.get_counter_vote_count(target_id).unwrap_or(0);
    }

    // Compute trust score:
    // - account_age component: min(1.0, age_days / 365) * 0.3
    // - report ratio component: (1.0 - reports_received_ratio) * 0.4
    //   where ratio = reports_received / max(1, total content by user) — approximate with reports_received / max(1, reports_received + 10)
    // - counter-vote component: counter_votes / max(1, reports_received) capped at 1.0, * 0.3
    let age_component = (account_age_days as f64 / 365.0).min(1.0) * 0.3;
    let reports_ratio = total_reports_received as f64 / (total_reports_received as f64 + 10.0).max(1.0);
    let report_component = (1.0 - reports_ratio) * 0.4;
    let cv_ratio = if total_reports_received > 0 {
        (counter_votes_received as f64 / total_reports_received as f64).min(1.0)
    } else {
        1.0 // no reports = full counter-vote score
    };
    let cv_component = cv_ratio * 0.3;
    let trust_score = (age_component + report_component + cv_component).min(1.0);

    Json(serde_json::json!({
        "address": resolved,
        "reputation": {
            "account_age_days": account_age_days,
            "trust_score": (trust_score * 1000.0).round() / 1000.0,
            "total_reports_filed": total_reports_filed,
            "total_reports_received": total_reports_received,
            "counter_votes_received": counter_votes_received,
        },
    }))
    .into_response()
}

// --- Private Channel Key Distribution Endpoints ---

/// GET /api/v1/channels/:channel_id/keys — get encrypted group key material (authenticated)
///
/// Returns the latest (or specified epoch) key distribution for a private channel.
/// Only accessible to channel members. Returns 404 for non-members (no channel existence leakage).
pub async fn get_channel_keys(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(channel_id): Path<u64>,
    Query(params): Query<KeyParams>,
) -> impl IntoResponse {
    // Verify the channel exists and is private
    let channel_key = channel_id.to_be_bytes();
    let meta = match state.storage.get_cf(cf::CHANNELS, &channel_key) {
        Ok(Some(bytes)) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(m) => m,
            Err(_) => return (StatusCode::NOT_FOUND, "not found").into_response(),
        },
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };

    let channel_type = meta.get("channel_type").and_then(|v| v.as_u64()).unwrap_or(0);
    if channel_type != 2 {
        // Return 404 to avoid leaking whether the channel exists or its type
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    // Verify the user is a member
    let member_key = crate::storage::schema::encode_channel_member_key(channel_id, &auth_user.address);
    match state.storage.exists_cf(cf::CHANNEL_MEMBERS, &member_key) {
        Ok(true) => {}
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    }

    // Fetch key material
    let result = if let Some(epoch) = params.epoch {
        state.storage.get_private_channel_keys(channel_id, epoch)
            .map(|opt| opt.map(|data| (epoch, data)))
    } else {
        state.storage.get_private_channel_keys_latest(channel_id)
    };

    match result {
        Ok(Some((epoch, key_data))) => {
            // key_data is JSON: { epoch, member_keys, distributed_by, timestamp }
            // Only return the requesting member's encrypted key blob — not the full
            // member_keys map — to avoid leaking the membership list to individual members.
            match serde_json::from_slice::<serde_json::Value>(&key_data) {
                Ok(data) => {
                    let my_key = data.get("member_keys")
                        .and_then(|m| m.get(&auth_user.address));
                    Json(serde_json::json!({
                        "channel_id": channel_id,
                        "epoch": epoch,
                        "encrypted_key": my_key,
                        "timestamp": data.get("timestamp"),
                    })).into_response()
                }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "corrupt key data").into_response(),
            }
        }
        Ok(None) => Json(serde_json::json!({
            "channel_id": channel_id,
            "epoch": null,
            "encrypted_key": null,
        })).into_response(),
        Err(e) => {
            tracing::error!(error = %e, channel_id, "Failed to fetch channel keys");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

/// POST /api/v1/channels/:channel_id/keys — distribute group keys (authenticated)
///
/// Only the channel creator or admins can publish key distributions.
/// The node stores the encrypted key material but cannot decrypt it.
pub async fn distribute_channel_keys(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(channel_id): Path<u64>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    use crate::messages::router::RouteResult;
    use crate::messages::types::PrivateChannelKeyDistributionPayload;

    // Defense-in-depth: verify the envelope's channel_id and author match expectations
    if let Ok(envelope) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&body) {
        // Resolve envelope author to wallet address for comparison
        let envelope_wallet = state.identity
            .resolve(&envelope.author)
            .unwrap_or_else(|_| envelope.author.clone());
        if envelope_wallet != auth_user.address {
            return (
                StatusCode::BAD_REQUEST,
                "envelope author does not match authenticated user",
            )
                .into_response();
        }
        if let Ok(payload) =
            rmp_serde::from_slice::<PrivateChannelKeyDistributionPayload>(&envelope.payload)
        {
            if payload.channel_id != channel_id {
                return (
                    StatusCode::BAD_REQUEST,
                    "payload channel_id does not match URL path",
                )
                    .into_response();
            }
        }
    }

    match state.router.process_message(&body) {
        RouteResult::Accepted { msg_id, .. } => {
            // Fetch the latest epoch to confirm which epoch was accepted (per spec §4.2)
            let epoch = state.storage.get_private_channel_keys_latest(channel_id)
                .ok().flatten().map(|(e, _)| e);
            Json(serde_json::json!({
                "ok": true,
                "msg_id": hex::encode(msg_id),
                "epoch": epoch,
            })).into_response()
        }
        RouteResult::PowRequired { address } => pow_required_response(&state, &address),
        RouteResult::Rejected(reason) => {
            (StatusCode::BAD_REQUEST, reason).into_response()
        }
        RouteResult::Duplicate => Json(OkResponse { ok: true }).into_response(),
    }
}

/// Query params for key distribution endpoint.
#[derive(Debug, Deserialize)]
pub struct KeyParams {
    /// Specific epoch to fetch. If omitted, returns the latest.
    pub epoch: Option<u64>,
}

// --- Presence-gossip REST surface (spec 03 §4.1, spec 13 §10.6) -----
//
// All three endpoints are public + read-only. Handlers consult
// `AppState.presence_manager`:
//   - `None`         → presence disabled — `/network/presence` returns
//                      an empty body (per spec 03 §4.1), the per-peer
//                      lookup returns 404, `/network/identity` reports
//                      `presence_broadcasting: false`.
//   - `Some(mgr)`    → serve cache snapshots, enriched with the
//                      SC-source `verified_on_chain` flag from the
//                      bootstrap-candidates cache when populated.

/// JSON row for `/network/presence` and `/network/presence/{peer_id}`.
#[derive(Serialize)]
struct PresenceRecordJson {
    peer_id: String,
    public_url: Option<String>,
    version: String,
    timestamp: u64,
    ttl_secs: u32,
    first_heard: u64,
    last_heard: u64,
    expires_at: u64,
    verified_on_chain: bool,
    anchored: bool,
    last_anchor_at: Option<u64>,
}

/// Build a single response row from a cached record. The SC-enrichment
/// fields (`verified_on_chain`, `anchored`, `last_anchor_at`) are
/// computed at response time by consulting the SC-set produced by the
/// bootstrap-candidates handler. The set is a snapshot of PeerIds that
/// the local node has observed on-chain in the last bootstrap-
/// candidates refresh; richer per-anchor data (`anchored`,
/// `last_anchor_at`) is currently not surfaced and reports `false /
/// None` — Phase 2 will wire a per-PeerId index once the
/// `network/nodes` consolidation lands.
fn presence_row_from_cached(
    cached: &crate::network::presence::CachedPresenceRecord,
    now_unix: u64,
    sc_known_peer_ids: &std::collections::HashSet<String>,
) -> PresenceRecordJson {
    // Approximate `first_heard` / `last_heard` wall-clock unix by
    // computing the deltas from `Instant::now` — the cache stores
    // `Instant`s (monotonic, can't be wall-clock-converted directly),
    // so we map `Instant -> SystemTime` by computing the elapsed
    // duration and subtracting from `now_unix`. Worst-case skew is the
    // function-call latency (microseconds); the response timestamp
    // resolution is seconds, so the skew rounds out.
    let now_inst = std::time::Instant::now();
    let first_secs_ago = now_inst.duration_since(cached.first_heard).as_secs();
    let last_secs_ago = now_inst.duration_since(cached.last_heard).as_secs();
    let first_heard = now_unix.saturating_sub(first_secs_ago);
    let last_heard = now_unix.saturating_sub(last_secs_ago);
    let verified_on_chain = sc_known_peer_ids.contains(&cached.record.peer_id);
    PresenceRecordJson {
        peer_id: cached.record.peer_id.clone(),
        public_url: cached.record.public_url.clone(),
        version: cached.record.version.clone(),
        timestamp: cached.record.timestamp,
        ttl_secs: cached.record.ttl_secs,
        first_heard,
        last_heard,
        expires_at: cached.record.expires_at(),
        verified_on_chain,
        anchored: false,        // Phase 2 — see fn doc above.
        last_anchor_at: None,   // Phase 2 — see fn doc above.
    }
}

/// Snapshot of PeerIds that appear in the local `bootstrap_candidates_cache`.
/// Used to mark presence rows as `verified_on_chain: true` when the
/// gossip-discovered PeerId also appears in the SC-derived discovery
/// view (spec 03 §4.1). Returns an empty set if the cache is empty,
/// disabled (isolated-subnet mode), or hasn't refreshed yet.
async fn collect_sc_peer_ids(
    state: &std::sync::Arc<AppState>,
) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let read = state.bootstrap_candidates_cache.read().await;
    let Some(cached) = read.as_ref() else {
        return out;
    };
    if let Some(arr) = cached.payload.get("candidates").and_then(|v| v.as_array()) {
        for c in arr {
            if let Some(pid) = c.get("peer_id").and_then(|v| v.as_str()) {
                out.insert(pid.to_string());
            }
        }
    }
    out
}

/// GET /api/v1/network/identity
///
/// Lightweight self-description for consumer-side reachability probes
/// (spec 13 §10.9). The public Network page and SDK fetch this to
/// verify that a `public_url` advertised via presence gossip resolves
/// to the same `peer_id` that signed the gossip record.
pub async fn network_identity(
    Extension(state): Extension<std::sync::Arc<AppState>>,
) -> Json<serde_json::Value> {
    let broadcasting = state
        .presence_manager
        .as_ref()
        .map(|m| m.broadcasting())
        .unwrap_or(false);
    // Spec 03 §4.1 / spec 13 §10.6: `peer_id` is the libp2p PeerId
    // (12D3KooW...), NOT the L2 anchorer `node_id` (sha256-truncated
    // Klever pubkey hash). Use the manager's view when broadcasting
    // (cheaper — it's already cached as a string), otherwise fall back
    // to `state.network_peer_id`, which the network layer wrote at
    // startup from `swarm.local_peer_id()`. The two are equal by
    // construction; the manager-first path keeps the hot path free of
    // an extra `.clone()` when presence is enabled.
    let peer_id = state
        .presence_manager
        .as_ref()
        .map(|m| m.self_peer_id().to_string())
        .unwrap_or_else(|| state.network_peer_id.clone());
    Json(serde_json::json!({
        "peer_id": peer_id,
        "network_id": state.network_id,
        "version": env!("CARGO_PKG_VERSION"),
        "public_url": state.public_url,
        "presence_broadcasting": broadcasting,
    }))
}

/// GET /api/v1/network/presence
///
/// Returns all cached presence records ranked by `last_heard` desc,
/// with SC-source enrichment. When presence is disabled returns an
/// empty `records` array (spec 03 §4.1).
pub async fn network_presence(
    Extension(state): Extension<std::sync::Arc<AppState>>,
) -> Json<serde_json::Value> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let Some(mgr) = state.presence_manager.clone() else {
        // Disabled-presence response shape per spec 03 §4.1. The
        // `self_peer_id` is the local libp2p PeerId — NOT the L2
        // anchorer `node_id`. See `network_identity` for the same
        // taxonomy fix.
        return Json(serde_json::json!({
            "self_peer_id": state.network_peer_id,
            "broadcasting": false,
            "cache_size": 0,
            "cache_cap": crate::network::presence::PRESENCE_CACHE_CAP,
            "records": Vec::<serde_json::Value>::new(),
        }));
    };
    let sc_peer_ids = collect_sc_peer_ids(&state).await;
    let cache = mgr.cache();
    let mut rows: Vec<crate::network::presence::CachedPresenceRecord> = cache.snapshot().await;
    // Rank by `last_heard` descending.
    rows.sort_by_key(|c| std::cmp::Reverse(c.last_heard));
    let records: Vec<PresenceRecordJson> = rows
        .iter()
        .map(|c| presence_row_from_cached(c, now_unix, &sc_peer_ids))
        .collect();
    Json(serde_json::json!({
        "self_peer_id": mgr.self_peer_id(),
        "broadcasting": mgr.broadcasting(),
        "cache_size": records.len(),
        "cache_cap": crate::network::presence::PRESENCE_CACHE_CAP,
        "records": records,
    }))
}

/// GET /api/v1/network/presence/:peer_id
///
/// Single presence record by libp2p PeerId. 404 if not in cache or
/// presence is disabled.
pub async fn network_presence_by_peer(
    Extension(state): Extension<std::sync::Arc<AppState>>,
    Path(peer_id_str): Path<String>,
) -> axum::response::Response {
    let Some(mgr) = state.presence_manager.clone() else {
        return (StatusCode::NOT_FOUND, "presence not enabled").into_response();
    };
    let peer_id: libp2p::PeerId = match peer_id_str.parse() {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid peer_id").into_response();
        }
    };
    let cache = mgr.cache();
    let Some(row) = cache.get(&peer_id).await else {
        return (StatusCode::NOT_FOUND, "peer_id not in presence cache").into_response();
    };
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sc_peer_ids = collect_sc_peer_ids(&state).await;
    let json = presence_row_from_cached(&row, now_unix, &sc_peer_ids);
    Json(json).into_response()
}

#[cfg(test)]
mod media_tests {
    use super::{detect_content_type, parse_byte_range};

    // --- detect_content_type ---

    #[test]
    fn detects_png() {
        assert_eq!(detect_content_type(b"\x89PNG\r\n\x1a\n..."), "image/png");
    }

    #[test]
    fn detects_jpeg() {
        assert_eq!(detect_content_type(b"\xFF\xD8\xFF\xE0..."), "image/jpeg");
    }

    #[test]
    fn detects_mp4_via_ftyp_box() {
        // Real MP4 starts with size(4) + "ftyp" + brand(4) + minor(4).
        // The leading 4 bytes are the box size — opaque to our matcher.
        let data = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00";
        assert_eq!(detect_content_type(data), "video/mp4");
    }

    #[test]
    fn detects_mp4_with_quicktime_brand() {
        // Different major_brand, same `ftyp` prefix → still video/mp4.
        let data = b"\x00\x00\x00\x14ftypqt  \x00\x00\x02\x00";
        assert_eq!(detect_content_type(data), "video/mp4");
    }

    #[test]
    fn detects_webm() {
        assert_eq!(
            detect_content_type(b"\x1A\x45\xDF\xA3..."),
            "video/webm"
        );
    }

    #[test]
    fn detects_ogg() {
        assert_eq!(detect_content_type(b"OggS\x00\x02..."), "video/ogg");
    }

    #[test]
    fn detects_mp3_id3v2() {
        assert_eq!(detect_content_type(b"ID3\x03..."), "audio/mpeg");
    }

    #[test]
    fn detects_mp3_raw_frame() {
        // 0xFF 0xFB = MPEG-1 Layer 3 frame sync.
        assert_eq!(detect_content_type(b"\xFF\xFB..."), "audio/mpeg");
    }

    #[test]
    fn detects_wav() {
        assert_eq!(
            detect_content_type(b"RIFF\x00\x00\x00\x00WAVEfmt "),
            "audio/wav"
        );
    }

    #[test]
    fn unknown_falls_back_to_octet_stream() {
        assert_eq!(
            detect_content_type(b"random garbage"),
            "application/octet-stream"
        );
    }

    #[test]
    fn riff_without_recognized_form_is_opaque() {
        // RIFF prefix with unknown form (e.g., "XYZ ") should NOT be
        // misclassified. Guards against false positives.
        assert_eq!(
            detect_content_type(b"RIFF\x00\x00\x00\x00XYZ \x00\x00\x00\x00"),
            "application/octet-stream"
        );
    }

    // --- parse_byte_range ---

    #[test]
    fn explicit_range() {
        assert_eq!(parse_byte_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_byte_range("bytes=100-199", 1000), Some((100, 199)));
        assert_eq!(parse_byte_range("bytes=500-999", 1000), Some((500, 999)));
    }

    #[test]
    fn open_ended_range() {
        // `bytes=500-` means "from 500 to EOF".
        assert_eq!(parse_byte_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(parse_byte_range("bytes=0-", 1000), Some((0, 999)));
    }

    #[test]
    fn suffix_length_range() {
        // `bytes=-N` means "last N bytes".
        assert_eq!(parse_byte_range("bytes=-100", 1000), Some((900, 999)));
        assert_eq!(parse_byte_range("bytes=-1", 1000), Some((999, 999)));
    }

    #[test]
    fn suffix_length_clamps_to_total() {
        // Suffix larger than file = "give me the whole thing".
        assert_eq!(parse_byte_range("bytes=-99999", 1000), Some((0, 999)));
    }

    #[test]
    fn whitespace_tolerant() {
        assert_eq!(parse_byte_range(" bytes=0-99 ", 1000), Some((0, 99)));
    }

    #[test]
    fn rejects_missing_bytes_prefix() {
        assert_eq!(parse_byte_range("0-99", 1000), None);
    }

    #[test]
    fn rejects_multi_range() {
        // RFC 7233 allows multi-range responses (multipart/byteranges)
        // but we deliberately don't emit them — return None so caller
        // falls back to 416 or full body.
        assert_eq!(parse_byte_range("bytes=0-99,200-299", 1000), None);
    }

    #[test]
    fn rejects_inverted_range() {
        assert_eq!(parse_byte_range("bytes=500-100", 1000), None);
    }

    #[test]
    fn rejects_out_of_bounds_end() {
        assert_eq!(parse_byte_range("bytes=0-1000", 1000), None);
        assert_eq!(parse_byte_range("bytes=500-99999", 1000), None);
    }

    #[test]
    fn rejects_zero_total() {
        assert_eq!(parse_byte_range("bytes=0-0", 0), None);
    }

    #[test]
    fn rejects_zero_suffix() {
        assert_eq!(parse_byte_range("bytes=-0", 1000), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_byte_range("bytes=abc-def", 1000), None);
        assert_eq!(parse_byte_range("bytes=", 1000), None);
        assert_eq!(parse_byte_range("", 1000), None);
    }

    // --- Audit-derived edge cases ---

    #[test]
    fn rejects_open_ended_on_empty_resource() {
        // `bytes=0-` on a zero-byte file must not underflow `total-1`.
        // The `total == 0` short-circuit catches this — locked here.
        assert_eq!(parse_byte_range("bytes=0-", 0), None);
    }

    #[test]
    fn rejects_open_ended_at_eof() {
        // `bytes=1000-` on a 1000-byte file: start == total → no bytes
        // available. Caller would compute (1000, 999) and the
        // `start > end` guard returns None.
        assert_eq!(parse_byte_range("bytes=1000-", 1000), None);
        assert_eq!(parse_byte_range("bytes=1001-", 1000), None);
    }

    #[test]
    fn rejects_dash_only() {
        // `bytes=-` is neither suffix-length nor explicit; parse fails.
        assert_eq!(parse_byte_range("bytes=-", 1000), None);
    }

    // --- Additional detector parity ---

    #[test]
    fn detects_gif() {
        assert_eq!(detect_content_type(b"GIF89a..."), "image/gif");
        assert_eq!(detect_content_type(b"GIF87a..."), "image/gif");
    }

    #[test]
    fn detects_webp() {
        assert_eq!(
            detect_content_type(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            "image/webp"
        );
    }

    #[test]
    fn detects_pdf() {
        assert_eq!(detect_content_type(b"%PDF-1.4..."), "application/pdf");
    }

    #[test]
    fn detects_avi() {
        assert_eq!(
            detect_content_type(b"RIFF\x00\x00\x00\x00AVI LIST"),
            "video/x-msvideo"
        );
    }

    #[test]
    fn detects_flac() {
        assert_eq!(detect_content_type(b"fLaC\x00\x00..."), "audio/flac");
    }

    #[test]
    fn empty_input_does_not_panic() {
        // Edge case: a deleted-but-still-pinned IPFS object could return
        // empty bytes. Detector must return octet-stream and not panic.
        assert_eq!(detect_content_type(b""), "application/octet-stream");
    }

    #[test]
    fn ftyp_at_exact_8_byte_boundary() {
        // Smallest possible ftyp prefix: 8 bytes total. The matcher
        // checks `data[4..8] == "ftyp"` which requires `len >= 8`.
        let data: &[u8] = b"\x00\x00\x00\x08ftyp";
        assert_eq!(detect_content_type(data), "video/mp4");
    }

    #[test]
    fn short_inputs_do_not_panic() {
        // None of the matchers should panic on a 1, 2, or 3-byte input.
        assert_eq!(detect_content_type(b"\x89"), "application/octet-stream");
        assert_eq!(detect_content_type(b"\xFF\xD8"), "application/octet-stream");
        assert_eq!(detect_content_type(b"GIF"), "application/octet-stream");
    }

    // --- media_content_disposition (v0.39 allowlist) ---
    //
    // The pre-audit policy was a BLACKLIST: anything not
    // `application/octet-stream` was returned `inline`. Audit warning
    // W-4 (security) — if a future detector added `text/html`,
    // `image/svg+xml`, or similar to the recognized list, the policy
    // would auto-flip them to `inline` and create stored-XSS surface
    // at the media origin. The v0.39 policy is an ALLOWLIST: only the
    // explicit media-rendering prefixes are inline; everything else
    // (including hypothetical future text/html, svg, xml) is forced
    // to `attachment`. These tests lock the allowlist.

    use super::media_content_disposition;

    #[test]
    fn disposition_image_is_inline() {
        let d = media_content_disposition("image/png", "bafy123");
        assert_eq!(d, "inline; filename=\"bafy123\"");
        let d = media_content_disposition("image/jpeg", "bafy123");
        assert!(d.starts_with("inline;"));
        let d = media_content_disposition("image/webp", "bafy123");
        assert!(d.starts_with("inline;"));
    }

    #[test]
    fn disposition_video_is_inline() {
        assert!(media_content_disposition("video/mp4", "bafy123").starts_with("inline;"));
        assert!(media_content_disposition("video/webm", "bafy123").starts_with("inline;"));
        assert!(media_content_disposition("video/ogg", "bafy123").starts_with("inline;"));
        assert!(
            media_content_disposition("video/x-msvideo", "bafy123").starts_with("inline;")
        );
    }

    #[test]
    fn disposition_audio_is_inline() {
        assert!(media_content_disposition("audio/mpeg", "bafy123").starts_with("inline;"));
        assert!(media_content_disposition("audio/wav", "bafy123").starts_with("inline;"));
        assert!(media_content_disposition("audio/flac", "bafy123").starts_with("inline;"));
    }

    #[test]
    fn disposition_pdf_is_inline() {
        assert!(
            media_content_disposition("application/pdf", "bafy123").starts_with("inline;")
        );
    }

    #[test]
    fn disposition_octet_stream_is_attachment() {
        let d = media_content_disposition("application/octet-stream", "bafy123");
        assert_eq!(d, "attachment; filename=\"bafy123\"");
    }

    #[test]
    fn disposition_unrecognized_is_attachment() {
        // The CORE security guarantee of the allowlist: any future
        // detector addition that isn't an explicit media type gets
        // `attachment` automatically. These all SHOULD be `attachment`,
        // not `inline`.
        assert!(
            media_content_disposition("text/html", "bafy123").starts_with("attachment;")
        );
        assert!(
            media_content_disposition("text/plain", "bafy123").starts_with("attachment;")
        );
        assert!(
            media_content_disposition("image/svg+xml", "bafy123").starts_with("attachment;")
        );
        assert!(
            media_content_disposition("application/xml", "bafy123").starts_with("attachment;")
        );
        assert!(
            media_content_disposition("application/javascript", "bafy123")
                .starts_with("attachment;")
        );
        assert!(
            media_content_disposition("application/zip", "bafy123").starts_with("attachment;")
        );
    }

    #[test]
    fn disposition_uses_cid_as_filename() {
        // The CID-as-filename is intentional — original upload
        // filenames are not stored at the IPFS layer. CIDs are
        // base32-alphanumeric per `validate_cid`, so embedding them
        // in a quoted-string is safe without escaping.
        let d = media_content_disposition("image/png", "bafkrei123abc");
        assert!(d.contains("filename=\"bafkrei123abc\""));
    }

    // --- HEAD tuple-form regression (v0.40) -------------------------
    //
    // Auditor v0.39 followup #5: lock the guarantee that HEAD
    // responses use the `(status, headers)` IntoResponse form (no
    // body in tuple). Without this guard a future contributor could
    // re-introduce the double-Content-Length bug by adding an empty
    // body to the HEAD branch. The test goes through `serve_from_cached`
    // with `is_head=true` and asserts:
    //   - exactly ONE `Content-Length` header is emitted
    //   - that header's value matches what we explicitly set
    //   - the response body is empty
    //
    // Same pattern applies to the Partial Content branch (Range +
    // HEAD) — locked separately below.

    use super::{match_if_range, serve_from_cached, CachedMedia};
    use axum::body::to_bytes;
    use bytes::Bytes;

    fn make_cached(payload: &[u8], ct: &str) -> CachedMedia {
        CachedMedia {
            bytes: Bytes::copy_from_slice(payload),
            content_type: ct.to_string(),
            // Use a fixed historical timestamp so the
            // httpdate-formatted Last-Modified is deterministic in
            // assertions (no flakes from `SystemTime::now`).
            last_modified: std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    fn empty_headers() -> axum::http::HeaderMap {
        axum::http::HeaderMap::new()
    }

    fn headers_with_range(value: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert("range", value.parse().unwrap());
        h
    }

    #[tokio::test]
    async fn head_200_emits_single_content_length_and_no_body() {
        let cached = make_cached(b"hello world", "image/png");
        let resp = serve_from_cached(
            /* is_head */ true,
            cached,
            "\"cid123\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid123",
            &empty_headers(),
        );
        assert_eq!(resp.status(), 200);
        let cl_count = resp
            .headers()
            .get_all(axum::http::header::CONTENT_LENGTH)
            .iter()
            .count();
        assert_eq!(cl_count, 1, "HEAD must emit exactly one Content-Length");
        let cl = resp
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cl, "11", "CL must reflect would-be GET body size");
        // v0.42: Last-Modified must be present.
        assert!(
            resp.headers().get(axum::http::header::LAST_MODIFIED).is_some(),
            "Last-Modified must be emitted on cached 200 responses",
        );
        // Body must be empty for HEAD.
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(body_bytes.is_empty(), "HEAD response body must be empty");
    }

    #[tokio::test]
    async fn head_206_partial_emits_single_content_length_and_no_body() {
        let cached = make_cached(b"hello world", "image/png");
        let resp = serve_from_cached(
            /* is_head */ true,
            cached,
            "\"cid123\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid123",
            &headers_with_range("bytes=0-4"),
        );
        assert_eq!(resp.status(), 206);
        let cl_count = resp
            .headers()
            .get_all(axum::http::header::CONTENT_LENGTH)
            .iter()
            .count();
        assert_eq!(
            cl_count, 1,
            "HEAD 206 must emit exactly one Content-Length"
        );
        let cl = resp
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cl, "5", "CL on HEAD 206 must reflect would-be slice size");
        // Content-Range must still be present even though body isn't —
        // that's the whole point of HEAD-vs-GET parity on metadata.
        let cr = resp
            .headers()
            .get(axum::http::header::CONTENT_RANGE)
            .expect("Content-Range required on HEAD 206")
            .to_str()
            .unwrap();
        assert_eq!(cr, "bytes 0-4/11");
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(body_bytes.is_empty());
    }

    #[tokio::test]
    async fn get_200_includes_body_with_content_length() {
        let cached = make_cached(b"abcdef", "image/png");
        let resp = serve_from_cached(
            /* is_head */ false,
            cached,
            "\"cid\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid",
            &empty_headers(),
        );
        assert_eq!(resp.status(), 200);
        let cl = resp
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cl, "6");
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body_bytes[..], b"abcdef");
    }

    #[tokio::test]
    async fn get_206_range_returns_slice() {
        let cached = make_cached(b"hello world", "image/png");
        let resp = serve_from_cached(
            false,
            cached,
            "\"cid\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid",
            &headers_with_range("bytes=6-10"),
        );
        assert_eq!(resp.status(), 206);
        let cr = resp
            .headers()
            .get(axum::http::header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cr, "bytes 6-10/11");
        let body_bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body_bytes[..], b"world");
    }

    // --- v0.42: Last-Modified + If-Range HTTP-date -------------------

    #[tokio::test]
    async fn cached_200_emits_last_modified_in_http_date_format() {
        // The deterministic fixture timestamp is 2023-11-14 22:13:20 UTC.
        let cached = make_cached(b"hello", "image/png");
        let resp = serve_from_cached(
            false,
            cached,
            "\"cid\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid",
            &empty_headers(),
        );
        let lm = resp
            .headers()
            .get(axum::http::header::LAST_MODIFIED)
            .expect("Last-Modified emitted on cached 200")
            .to_str()
            .unwrap();
        // RFC 7231 format: "Tue, 14 Nov 2023 22:13:20 GMT".
        assert!(lm.ends_with("GMT"), "HTTP-date format ends with GMT: {}", lm);
        assert!(lm.contains("2023"), "year present in fixture: {}", lm);
    }

    #[tokio::test]
    async fn if_range_matching_etag_honors_range() {
        let cached = make_cached(b"hello world", "image/png");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("range", "bytes=0-4".parse().unwrap());
        headers.insert("if-range", "\"cid\"".parse().unwrap());
        let resp = serve_from_cached(
            false,
            cached,
            "\"cid\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid",
            &headers,
        );
        // ETag matches → 206.
        assert_eq!(resp.status(), 206);
    }

    #[tokio::test]
    async fn if_range_mismatching_etag_drops_range_and_serves_full() {
        let cached = make_cached(b"hello world", "image/png");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("range", "bytes=0-4".parse().unwrap());
        headers.insert("if-range", "\"different-cid\"".parse().unwrap());
        let resp = serve_from_cached(
            false,
            cached,
            "\"cid\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid",
            &headers,
        );
        // ETag doesn't match → fall back to 200 full body.
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn if_range_matching_http_date_honors_range() {
        // Fixture last_modified = epoch + 1_700_000_000 secs.
        let cached = make_cached(b"hello world", "image/png");
        let date_str = httpdate::fmt_http_date(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("range", "bytes=0-4".parse().unwrap());
        headers.insert("if-range", date_str.parse().unwrap());
        let resp = serve_from_cached(
            false,
            cached,
            "\"cid\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid",
            &headers,
        );
        assert_eq!(resp.status(), 206, "matching If-Range date honors Range");
    }

    #[tokio::test]
    async fn if_range_mismatching_http_date_drops_range() {
        let cached = make_cached(b"hello world", "image/png");
        // Date one hour earlier than the fixture's last_modified.
        let date_str = httpdate::fmt_http_date(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 - 3600),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("range", "bytes=0-4".parse().unwrap());
        headers.insert("if-range", date_str.parse().unwrap());
        let resp = serve_from_cached(
            false,
            cached,
            "\"cid\"".to_string(),
            "public, max-age=31536000, immutable",
            "cid",
            &headers,
        );
        assert_eq!(resp.status(), 200, "stale date drops Range, serves full body");
    }

    #[test]
    fn match_if_range_no_header_returns_true() {
        // Baseline: absent If-Range means Range is unconditionally honored.
        let headers = axum::http::HeaderMap::new();
        assert!(match_if_range(&headers, "\"cid\"", None));
    }

    #[test]
    fn match_if_range_etag_succeeds_without_last_modified() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("if-range", "\"cid\"".parse().unwrap());
        // Streamed path: no last_modified available; ETag-form still works.
        assert!(match_if_range(&headers, "\"cid\"", None));
    }

    #[test]
    fn match_if_range_http_date_returns_false_without_last_modified() {
        // Streamed path: no last_modified → date-form If-Range can't match.
        let mut headers = axum::http::HeaderMap::new();
        let date_str = httpdate::fmt_http_date(std::time::UNIX_EPOCH);
        headers.insert("if-range", date_str.parse().unwrap());
        assert!(!match_if_range(&headers, "\"cid\"", None));
    }

    #[test]
    fn match_if_range_garbage_value_returns_false() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("if-range", "not-an-etag-or-date".parse().unwrap());
        // Neither matches our ETag nor parses as a date → fail closed.
        let lm = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert!(!match_if_range(&headers, "\"cid\"", Some(lm)));
    }

    // --- resolve_client_ip (v0.42 trusted_proxies integration) ------
    //
    // Smoke tests at the routes.rs wrapper level — the underlying
    // algorithm has exhaustive coverage in
    // `crate::trusted_proxies::tests`. Tests here verify the wrapper
    // correctly extracts the `Forwarded` + `X-Forwarded-For` headers
    // and forwards them to the resolver with the right argument
    // shape.

    use super::resolve_client_ip;
    use crate::trusted_proxies::TrustedProxies;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sock(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    fn headers_with_xff(value: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    fn empty_proxies() -> TrustedProxies {
        TrustedProxies::default()
    }

    #[test]
    fn resolve_ip_uses_xff_when_peer_is_loopback() {
        let peer = sock("127.0.0.1", 50000);
        let headers = headers_with_xff("203.0.113.5");
        assert_eq!(
            resolve_client_ip(peer, &headers, &empty_proxies()),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
        );
    }

    #[test]
    fn resolve_ip_multi_hop_returns_rightmost_untrusted() {
        // v0.42 behaviour change: with no extra trusted_proxies, the
        // walk stops at the rightmost untrusted entry (10.0.0.1 is
        // NOT in the trust set by default — only loopback is). The
        // earlier leftmost-trust behavior was unsafe in multi-proxy
        // setups where intermediates could forge the leftmost entry.
        // To recover the leftmost-original-client behavior, the
        // operator adds the intermediate proxies to trusted_proxies.
        let peer = sock("127.0.0.1", 50000);
        let headers = headers_with_xff("198.51.100.7, 203.0.113.1, 10.0.0.1");
        assert_eq!(
            resolve_client_ip(peer, &headers, &empty_proxies()),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "without trusted_proxies, the closest hop is the safest answer",
        );
    }

    #[test]
    fn resolve_ip_multi_hop_with_trusted_intermediates_returns_client() {
        // With every intermediate proxy in trusted_proxies, the walk
        // converges on the original leftmost client.
        let peer = sock("127.0.0.1", 50000);
        let headers = headers_with_xff("198.51.100.7, 203.0.113.1, 10.0.0.1");
        let trusted = TrustedProxies::from_strings(&[
            "10.0.0.0/8".to_string(),
            "203.0.113.0/24".to_string(),
        ])
        .unwrap();
        assert_eq!(
            resolve_client_ip(peer, &headers, &trusted),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
        );
    }

    #[test]
    fn resolve_ip_ignores_xff_when_peer_is_remote() {
        // CRITICAL SECURITY: a non-loopback, non-trusted peer's XFF
        // header is attacker-controlled and must be ignored.
        let peer = sock("203.0.113.99", 50000);
        let headers = headers_with_xff("1.2.3.4");
        assert_eq!(
            resolve_client_ip(peer, &headers, &empty_proxies()),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)),
            "XFF from non-loopback, non-trusted peer must be ignored",
        );
    }

    #[test]
    fn resolve_ip_falls_back_to_peer_when_no_xff() {
        let peer = sock("127.0.0.1", 50000);
        let headers = axum::http::HeaderMap::new();
        assert_eq!(resolve_client_ip(peer, &headers, &empty_proxies()), peer.ip());
    }

    #[test]
    fn resolve_ip_falls_back_to_peer_on_unparseable_xff() {
        let peer = sock("127.0.0.1", 50000);
        let headers = headers_with_xff("not-an-ip");
        assert_eq!(resolve_client_ip(peer, &headers, &empty_proxies()), peer.ip());
    }

    #[test]
    fn resolve_ip_handles_ipv4_mapped_ipv6_loopback() {
        // Dual-stack Linux listener delivers loopback as
        // `::ffff:127.0.0.1`. The wrapper must still trust XFF.
        let peer: SocketAddr = "[::ffff:127.0.0.1]:50000".parse().unwrap();
        let headers = headers_with_xff("203.0.113.5");
        assert_eq!(
            resolve_client_ip(peer, &headers, &empty_proxies()),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        );
    }

    #[test]
    fn resolve_ip_prefers_forwarded_over_xff() {
        // v0.42: RFC 7239 Forwarded wins over X-Forwarded-For when
        // both headers are present.
        let peer = sock("127.0.0.1", 50000);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("forwarded", "for=4.4.4.4".parse().unwrap());
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        assert_eq!(
            resolve_client_ip(peer, &headers, &empty_proxies()),
            IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4))
        );
    }
}

#[cfg(test)]
mod edit_projection_tests {
    //! Regression guards for the read-time edit projection in
    //! `project_edited_payload`. The bug they catch: re-emitting the merged
    //! payload with `rmp_serde::to_vec` (struct → msgpack ARRAY) instead of
    //! `rmp_serde::to_vec_named` (struct → msgpack MAP). JS clients decode
    //! by field name; the array form makes every field on an edited post
    //! read `undefined` and the post renders blank in the UI.
    use crate::messages::types::{
        Attachment, ChatMessagePayload, ContentRating, NewsPostPayload, Visibility,
    };

    fn sample_news() -> NewsPostPayload {
        NewsPostPayload {
            title: "T".into(),
            content: "C".into(),
            content_rating: ContentRating::General,
            tags: vec!["a".into()],
            attachments: vec![Attachment {
                cid: "Qm".into(),
                mime_type: "image/png".into(),
                size_bytes: 1,
                filename: Some("p.png".into()),
                thumbnail_cid: None,
            }],
            visibility: Visibility::default(),
        }
    }

    fn sample_chat() -> ChatMessagePayload {
        ChatMessagePayload {
            channel_id: 1,
            content: "C".into(),
            content_rating: ContentRating::General,
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
        }
    }

    #[test]
    fn news_post_reencodes_as_msgpack_map_not_array() {
        let bytes = rmp_serde::to_vec_named(&sample_news()).expect("encode named");
        // 0x80-0x8f = fixmap, 0xde = map16, 0xdf = map32. NewsPostPayload
        // has ≤15 fields so fixmap is the expected prefix. Array would be
        // 0x90-0x9f and trigger the bug this test guards.
        assert!(
            (0x80..=0x8f).contains(&bytes[0]),
            "expected msgpack map (0x80..=0x8f), got 0x{:02x} (array would be 0x90..=0x9f)",
            bytes[0]
        );
    }

    #[test]
    fn news_post_named_roundtrip_preserves_every_field() {
        let p = sample_news();
        let bytes = rmp_serde::to_vec_named(&p).expect("encode named");
        let decoded: NewsPostPayload = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(decoded.title, p.title);
        assert_eq!(decoded.content, p.content);
        assert_eq!(decoded.tags, p.tags);
        assert_eq!(decoded.attachments.len(), p.attachments.len());
    }

    #[test]
    fn attachments_inner_struct_is_also_map_encoded() {
        // `to_vec_named` is recursive; the nested Attachment must serialize
        // with named fields too. A partial fix that only swapped the outer
        // call but kept arrays for nested values would still render blank
        // attachments client-side.
        let bytes = rmp_serde::to_vec_named(&sample_news()).expect("encode named");
        for needle in ["cid", "mime_type", "size_bytes", "filename", "thumbnail_cid"] {
            assert!(
                bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "attachment field name {:?} missing from named encoding",
                needle
            );
        }
    }

    #[test]
    fn chat_message_reencodes_as_msgpack_map_not_array() {
        // ChatMessagePayload is reached via the same projection branch in
        // `project_edited_payload`; same fix applies.
        let bytes = rmp_serde::to_vec_named(&sample_chat()).expect("encode named");
        assert!(
            (0x80..=0x8f).contains(&bytes[0]) || bytes[0] == 0xde || bytes[0] == 0xdf,
            "expected msgpack map, got 0x{:02x}",
            bytes[0]
        );
    }
}

#[cfg(test)]
mod bootstrap_candidates_tests {
    use super::{
        extract_peer_id, merge_candidates, sanitize_multiaddr_str, source_rank, CandidateEntry,
    };

    // Real-shaped peer_id (the production default in `default_bootstrap_nodes()`).
    const REAL_PEER_ID: &str = "12D3KooWNx9TnsmVQux3fMm6sUUe5tFdeXjECUSyDqYtYfsbt3Mo";

    fn entry(multiaddr: &str, last: Option<u64>, source: &'static str) -> CandidateEntry {
        let transport = crate::chain::sc_views::classify_transport(multiaddr).as_str();
        CandidateEntry {
            multiaddr: multiaddr.to_string(),
            peer_id: extract_peer_id(multiaddr),
            last_anchor_at: last,
            source,
            paused: false,
            owner_address: if source == "sc" {
                Some("klv1testowner".to_string())
            } else {
                None
            },
            transport,
        }
    }

    #[test]
    fn merge_unions_book_config_sc() {
        let book = vec![entry(
            &format!("/dns4/a.org/tcp/41720/p2p/{}", REAL_PEER_ID),
            None,
            "book",
        )];
        let config = vec![entry(
            &format!("/dns4/b.org/tcp/41720/p2p/{}", REAL_PEER_ID),
            None,
            "config",
        )];
        let sc = vec![entry(
            &format!("/dns4/c.org/tcp/41720/p2p/{}", REAL_PEER_ID),
            Some(1000),
            "sc",
        )];
        let out = merge_candidates(book, config, sc);
        assert_eq!(out.len(), 3);
        // SC has the only non-null last_anchor_at; appears first.
        assert_eq!(out[0]["source"], "sc");
    }

    #[test]
    fn merge_dedupes_by_peer_id_prefers_freshest() {
        // Same multiaddr in book and SC — collapses to one entry.
        // SC has the higher `last_anchor_at` so it wins.
        let addr = format!("/dns4/x.org/tcp/41720/p2p/{}", REAL_PEER_ID);
        let book = vec![entry(&addr, None, "book")];
        let sc = vec![entry(&addr, Some(2000), "sc")];
        let out = merge_candidates(book, Vec::new(), sc);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["source"], "sc");
        assert_eq!(out[0]["last_anchor_at"], 2000);
    }

    #[test]
    fn merge_tie_breaks_on_source_rank_sc_over_book() {
        // Same multiaddr, both with last_anchor_at = 0 (book is None,
        // SC has Some(0) which normalises to 0). SC wins by source rank.
        let addr = format!("/dns4/y.org/tcp/41720/p2p/{}", REAL_PEER_ID);
        let book = vec![entry(&addr, None, "book")];
        let sc = vec![entry(&addr, Some(0), "sc")];
        let out = merge_candidates(book, Vec::new(), sc);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["source"], "sc");
    }

    #[test]
    fn merge_preserves_tcp_and_quic_for_same_peer_id() {
        // Same peer_id, different transports — both retained because
        // SDK consumers want to dial either.
        let tcp = format!("/dns4/z.org/tcp/41720/p2p/{}", REAL_PEER_ID);
        let quic = format!("/dns4/z.org/udp/41720/quic-v1/p2p/{}", REAL_PEER_ID);
        let sc = vec![entry(&tcp, Some(1000), "sc"), entry(&quic, Some(1000), "sc")];
        let out = merge_candidates(Vec::new(), Vec::new(), sc);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn merge_caps_at_256() {
        let sc: Vec<CandidateEntry> = (0..300)
            .map(|i| CandidateEntry {
                // Multiaddrs are distinct strings — peer_id parsing
                // can fail (test fixture); dedupe is by multiaddr
                // string so distinctness is what matters.
                multiaddr: format!("/dns4/host{}.org/tcp/41720", i),
                peer_id: None,
                last_anchor_at: Some(1000 + i as u64),
                source: "sc",
                paused: false,
                owner_address: Some("klv1testowner".to_string()),
                transport: "clearnet",
            })
            .collect();
        let out = merge_candidates(Vec::new(), Vec::new(), sc);
        assert_eq!(out.len(), 256);
        // After sort, the highest last_anchor_at (1299) is first.
        assert_eq!(out[0]["last_anchor_at"], 1299);
    }

    #[test]
    fn merge_orders_nulls_after_timestamps_book_before_config() {
        let book = vec![CandidateEntry {
            multiaddr: "/dns4/book.org/tcp/41720".to_string(),
            peer_id: None,
            last_anchor_at: None,
            source: "book",
            paused: false,
            owner_address: None,
            transport: "clearnet",
        }];
        let config = vec![CandidateEntry {
            multiaddr: "/dns4/cfg.org/tcp/41720".to_string(),
            peer_id: None,
            last_anchor_at: None,
            source: "config",
            paused: false,
            owner_address: None,
            transport: "clearnet",
        }];
        let sc = vec![CandidateEntry {
            multiaddr: "/dns4/sc.org/tcp/41720".to_string(),
            peer_id: None,
            last_anchor_at: Some(1000),
            source: "sc",
            paused: false,
            owner_address: Some("klv1testowner".to_string()),
            transport: "clearnet",
        }];
        let out = merge_candidates(book, config, sc);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["source"], "sc"); // non-null timestamp first
        assert_eq!(out[1]["source"], "book"); // then book (rank 1)
        assert_eq!(out[2]["source"], "config"); // then config (rank 0)
    }

    #[test]
    fn merge_emits_owner_address_only_for_sc_entries() {
        let book = vec![CandidateEntry {
            multiaddr: "/dns4/book.org/tcp/41720".to_string(),
            peer_id: None,
            last_anchor_at: None,
            source: "book",
            paused: false,
            owner_address: None,
            transport: "clearnet",
        }];
        let sc = vec![CandidateEntry {
            multiaddr: "/dns4/sc.org/tcp/41720".to_string(),
            peer_id: None,
            last_anchor_at: Some(1000),
            source: "sc",
            paused: false,
            owner_address: Some("klv1ownerxyz".to_string()),
            transport: "clearnet",
        }];
        let out = merge_candidates(book, Vec::new(), sc);
        // SC entry is first (non-null last_anchor_at).
        assert_eq!(out[0]["owner_address"], "klv1ownerxyz");
        // Book entry must NOT carry owner_address (absent, not null).
        assert!(out[1].get("owner_address").is_none());
    }

    #[test]
    fn sanitize_rejects_oversized_multiaddr() {
        let big = "x".repeat(257);
        assert!(!sanitize_multiaddr_str(&big));
    }

    #[test]
    fn sanitize_rejects_control_chars() {
        assert!(!sanitize_multiaddr_str("/dns4/x.org\n/tcp/41720"));
        assert!(!sanitize_multiaddr_str("/dns4/x.org\x00/tcp/41720"));
        assert!(!sanitize_multiaddr_str("/dns4/x.org\x7f/tcp/41720"));
    }

    #[test]
    fn sanitize_accepts_normal_multiaddr() {
        let addr = format!("/dns4/x.org/tcp/41720/p2p/{}", REAL_PEER_ID);
        assert!(sanitize_multiaddr_str(&addr));
    }

    #[test]
    fn extract_peer_id_returns_p2p_suffix() {
        let addr = format!("/dns4/x.org/tcp/41720/p2p/{}", REAL_PEER_ID);
        assert_eq!(extract_peer_id(&addr), Some(REAL_PEER_ID.to_string()));
    }

    #[test]
    fn extract_peer_id_returns_none_without_p2p() {
        assert_eq!(extract_peer_id("/dns4/x.org/tcp/41720"), None);
    }

    #[test]
    fn extract_peer_id_returns_none_for_malformed() {
        assert_eq!(extract_peer_id("not a multiaddr"), None);
    }

    #[test]
    fn source_rank_orders_sc_over_book_over_config() {
        assert!(source_rank("sc") > source_rank("book"));
        assert!(source_rank("book") > source_rank("config"));
    }
}
