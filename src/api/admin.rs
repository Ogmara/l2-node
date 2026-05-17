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
            "registration_source": "none",
            "registered_at": serde_json::Value::Null,
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

    // Issue five view calls concurrently. Each is `Result<T>`; we
    // KEEP the `Result` so the JSON response can distinguish "RPC
    // unavailable" (serialized as `null`) from a genuine zero.
    // Without this distinction, the bootstrap banner would flash on
    // every transient Klever RPC blip (v0.43.0 audit W2).
    //
    // The fifth call (`get_node_registered_at`) is historically what
    // let the dashboard distinguish "in v0.3+ permissionless registry"
    // (timestamp > 0) from "only in the legacy authorized_anchorer
    // allowlist" (timestamp == 0 but isNodeRegistered == true). With
    // SC v0.4.0+ that legacy state is no longer reachable — the SC
    // collapsed `isNodeRegistered` to only consult `registered_node`,
    // and `register_node` always writes the timestamp. We keep the
    // call because it still drives the State C/D / "registered since"
    // dashboard display; the "legacy" classification branch below is
    // retained as defensive scaffolding but cannot fire against an
    // SC ≥ 0.4.0. Dashboard State B′ (v0.43.3) is correspondingly
    // unreachable post-upgrade; full removal scheduled for v0.45.0.
    let (registered_res, count_res, fee_res, canonical_height_res, registered_at_res) = tokio::join!(
        crate::chain::sc_views::is_node_registered(http, &klever_node_url, &contract_address, &wallet),
        crate::chain::sc_views::get_node_count(http, &klever_node_url, &contract_address),
        crate::chain::sc_views::get_node_registration_fee(http, &klever_node_url, &contract_address),
        crate::chain::sc_views::get_latest_canonical_height(http, &klever_node_url, &contract_address),
        crate::chain::sc_views::get_node_registered_at(http, &klever_node_url, &contract_address, &wallet),
    );

    // `registered` defaults to false on RPC error — surfacing it as
    // null here would confuse the action-area state machine. The
    // operator sees "Status unknown" via the dedicated error field.
    let registered = registered_res.unwrap_or(false);
    let registered_at = registered_at_res.unwrap_or(0);

    // Source classification — drives the dashboard's action-area branch:
    //   "v3"     → in the permissionless registry; unregister works.
    //   "legacy" → only in the deprecated `authorized_anchorer` allowlist;
    //              unregister would fail with "Not registered" because
    //              the SC's unregister_node only manages the v0.3+ map.
    //              Dashboard offers a "Migrate to v0.3 registry" path instead.
    //              **Unreachable against SC ≥ 0.4.0** — SC no longer
    //              ORs in authorized_anchorer for isNodeRegistered, and
    //              register_node always sets the timestamp. Kept as a
    //              defensive arm so a downgraded SC would still classify
    //              correctly; remove in v0.45.0 alongside the dashboard
    //              State B′ cleanup.
    //   "none"   → not registered anywhere; show the register CTA.
    let registration_source = match (registered, registered_at) {
        (true, n) if n > 0 => "v3",
        (true, _)          => "legacy",
        (false, _)         => "none",
    };

    // `null` for unavailable so the dashboard can render a "—" rather
    // than misreporting as 0 (which would falsely trigger the
    // bootstrap banner).
    let network_node_count = count_res.ok().map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
    let canonical_height_u64 = canonical_height_res.as_ref().ok().copied();
    let last_canonical_height = canonical_height_u64
        .map(serde_json::Value::from)
        .unwrap_or(serde_json::Value::Null);

    // v0.45.0 — spec 12 §2.8 escalated-divergence visibility for the
    // Anchoring tab divergence panel. Looks up the latest canonical
    // height (when known) to surface whether the SC has entered
    // escalated mode + the dynamically-set threshold. Null when the
    // height itself was unavailable or when the view call failed —
    // dashboard renders "—" instead of misreporting either way.
    let (divergence_escalated_json, divergence_escalated_threshold_json) =
        if let Some(h) = canonical_height_u64 {
            let (esc, thresh) = tokio::join!(
                crate::chain::sc_views::is_divergence_escalated(http, &klever_node_url, &contract_address, h),
                crate::chain::sc_views::get_escalated_threshold(http, &klever_node_url, &contract_address, h),
            );
            (
                esc.ok().map(serde_json::Value::from).unwrap_or(serde_json::Value::Null),
                // `getEscalatedThreshold` returns 0 when not escalated; surface
                // null for either "RPC down" OR "not escalated" so the
                // dashboard renders just the bool half.
                thresh.ok().and_then(|t| if t == 0 { None } else { Some(serde_json::Value::from(t)) }).unwrap_or(serde_json::Value::Null),
            )
        } else {
            (serde_json::Value::Null, serde_json::Value::Null)
        };

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
    // v0.43.4: anchor_count is the count of submissions this node has
    // made (from the chain scanner's index by our node_id). Falls back
    // to null on storage error rather than 0 so the dashboard doesn't
    // misreport "0 anchors" when the lookup failed.
    let anchor_count = state
        .storage
        .get_self_anchor_status(&state.node_id)
        .ok()
        .map(|s| serde_json::Value::from(s.total_anchors))
        .unwrap_or(serde_json::Value::Null);
    // v0.43.4: canonical_count is the process-local count of our
    // submissions that reached canonical (quorum-confirmed) status,
    // written by the divergence watcher (StateAnchorer::check_divergence).
    // Resets across restarts — that's intentional and documented.
    let canonical_count = state
        .anchor_canonical_counter
        .load(std::sync::atomic::Ordering::Relaxed);
    // v0.45.0 — consecutive-divergence counter (spec 12 §6.1). Drives
    // the divergence panel on the Anchoring tab. Resets to 0 on any
    // canonical match, so a steady value > 0 indicates the local root
    // disagrees with the chain across multiple heights in a row.
    let divergence_consecutive = state
        .anchor_divergence_counter
        .load(std::sync::atomic::Ordering::Relaxed);

    Json(serde_json::json!({
        "wallet": wallet,
        "registered": registered,
        "registration_source": registration_source,
        "registered_at": if registered_at > 0 {
            serde_json::Value::Number(registered_at.into())
        } else {
            serde_json::Value::Null
        },
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
        // v0.43.4+: live local stats.
        // anchor_count: total submissions this node has made (from the
        // chain scanner's per-node index). null on storage error.
        // canonical_count: process-local count of our submissions that
        // reached canonical (quorum-confirmed) status. Resets across
        // node restarts; documented in spec 12 §3.2.
        "anchor_count": anchor_count,
        "canonical_count": canonical_count,
        "last_successful_anchor": if last_anchor_ts > 0 {
            serde_json::Value::Number(last_anchor_ts.into())
        } else {
            serde_json::Value::Null
        },
        "anchoring_configured": true,
        // v0.45.0 — divergence-panel inputs (spec 12 §2.8 + §6.1).
        // `consecutive` is the local counter; `escalated` + threshold
        // are live SC views for last_canonical_height (null when the
        // height itself was unavailable).
        "divergence_consecutive": divergence_consecutive,
        "divergence_escalated": divergence_escalated_json,
        "divergence_escalated_threshold": divergence_escalated_threshold_json,
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
    use super::{
        build_set_metadata_calldata, compute_effective_multiaddrs, extract_host_from_url,
        format_klv,
    };
    use crate::config::AnchorMetadataConfig;

    #[test]
    fn klv_formatting() {
        assert_eq!(format_klv(0), "0");
        assert_eq!(format_klv(1_000_000), "1");
        assert_eq!(format_klv(100_000_000), "100");
        assert_eq!(format_klv(100_500_000), "100.5");
        assert_eq!(format_klv(1), "0.000001");
        assert_eq!(format_klv(123_456), "0.123456");
    }

    #[test]
    fn host_extraction_basic() {
        assert_eq!(
            extract_host_from_url("https://node.ogmara.org:1234/path"),
            Some("node.ogmara.org".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://node.ogmara.org"),
            Some("node.ogmara.org".to_string())
        );
        assert_eq!(
            extract_host_from_url("https://1.2.3.4:8080"),
            Some("1.2.3.4".to_string())
        );
        // IPv6 bracketed form rejected — operator must set multiaddrs explicitly.
        assert_eq!(extract_host_from_url("http://[::1]:8080"), None);
        // Unbracketed IPv6 — the previous trailing-port rsplit would
        // have leaked through; now rejected (Code Audit W7).
        assert_eq!(extract_host_from_url("http://::1:8080"), None);
        // Control characters anywhere in the host (newline injection
        // defense, Security Audit N4).
        assert_eq!(extract_host_from_url("https://host\n.attacker.com"), None);
        // No scheme — treat the whole thing as authority.
        assert_eq!(
            extract_host_from_url("node.ogmara.org:9000"),
            Some("node.ogmara.org".to_string())
        );
        // Userinfo stripped.
        assert_eq!(
            extract_host_from_url("https://user:pass@node.ogmara.org:8443/x"),
            Some("node.ogmara.org".to_string())
        );
    }

    // Stable test peer-id — base58 of an arbitrary 32-byte key.
    // Real values look like this; tests don't need cryptographic
    // significance, just shape.
    const TEST_PEER_ID: &str = "12D3KooWNx9TnsmVQux3fMm6sUUe5tFdeXjECUSyDqYtYfsbt3Mo";

    #[test]
    fn effective_multiaddrs_publish_off() {
        let cfg = AnchorMetadataConfig {
            publish: false,
            multiaddrs: vec!["/dns4/x/tcp/1".into()],
        };
        let (eff, derived) = compute_effective_multiaddrs(
            &cfg,
            41720,
            Some("https://node.ogmara.org"),
            TEST_PEER_ID,
        );
        assert!(eff.is_empty());
        assert!(!derived);
    }

    #[test]
    fn effective_multiaddrs_explicit_pass_through() {
        // Explicit multiaddrs are returned VERBATIM — the operator
        // is responsible for including /p2p/ when explicit (we don't
        // mutate their input).
        let cfg = AnchorMetadataConfig {
            publish: true,
            multiaddrs: vec!["/dns4/x/tcp/1".into(), "/ip4/1.2.3.4/tcp/2".into()],
        };
        let (eff, derived) = compute_effective_multiaddrs(&cfg, 41720, None, TEST_PEER_ID);
        assert_eq!(eff.len(), 2);
        assert_eq!(eff[0], "/dns4/x/tcp/1");
        assert!(!derived);
    }

    #[test]
    fn effective_multiaddrs_auto_derive_dns() {
        let cfg = AnchorMetadataConfig {
            publish: true,
            multiaddrs: vec![],
        };
        let (eff, derived) = compute_effective_multiaddrs(
            &cfg,
            41720,
            Some("https://node.ogmara.org:8443/x"),
            TEST_PEER_ID,
        );
        assert!(derived);
        // Spec 13 §6.1 — auto-derive emits TCP + QUIC variants WITH
        // `/p2p/<peer_id>` so consumers (sc_discovery) can persist
        // them as complete dial targets (v0.45.1 fix).
        assert_eq!(
            eff,
            vec![
                format!("/dns4/node.ogmara.org/tcp/41720/p2p/{}", TEST_PEER_ID),
                format!("/dns4/node.ogmara.org/udp/41720/quic-v1/p2p/{}", TEST_PEER_ID),
            ]
        );
    }

    #[test]
    fn effective_multiaddrs_auto_derive_ipv4() {
        let cfg = AnchorMetadataConfig {
            publish: true,
            multiaddrs: vec![],
        };
        let (eff, derived) = compute_effective_multiaddrs(
            &cfg,
            9000,
            Some("http://203.0.113.7:1234"),
            TEST_PEER_ID,
        );
        assert!(derived);
        assert_eq!(
            eff,
            vec![
                format!("/ip4/203.0.113.7/tcp/9000/p2p/{}", TEST_PEER_ID),
                format!("/ip4/203.0.113.7/udp/9000/quic-v1/p2p/{}", TEST_PEER_ID),
            ]
        );
    }

    #[test]
    fn effective_multiaddrs_auto_derive_missing_url() {
        let cfg = AnchorMetadataConfig {
            publish: true,
            multiaddrs: vec![],
        };
        let (eff, derived) = compute_effective_multiaddrs(&cfg, 41720, None, TEST_PEER_ID);
        // auto_derived flagged true so the dashboard can surface
        // "publish enabled but no public_url" diagnostic, but the
        // effective list stays empty so we don't push junk on-chain.
        assert!(derived);
        assert!(eff.is_empty());
    }

    #[test]
    fn effective_multiaddrs_auto_derive_missing_peer_id() {
        // v0.45.1 hotfix path: peer_id empty (e.g. test constructor)
        // ⇒ auto-derive returns empty with derived=true so the
        // dashboard surfaces "publish enabled but peer_id missing"
        // rather than pushing a /p2p-less multiaddr that sc_discovery
        // would silently reject downstream.
        let cfg = AnchorMetadataConfig {
            publish: true,
            multiaddrs: vec![],
        };
        let (eff, derived) =
            compute_effective_multiaddrs(&cfg, 41720, Some("https://node.ogmara.org"), "");
        assert!(derived);
        assert!(eff.is_empty());
    }

    #[test]
    fn set_metadata_calldata_encoding() {
        // Empty — should NOT be invoked in production (caller short-
        // circuits on empty effective). Still exercise the trivial
        // case: just the function name, no args.
        assert_eq!(build_set_metadata_calldata(&[]), "setNodeMetadata");
        // Single multiaddr — hex of "/dns4/x/tcp/1" is its UTF-8 bytes.
        let one = build_set_metadata_calldata(&["/dns4/x/tcp/1".to_string()]);
        assert_eq!(one, "setNodeMetadata@2f646e73342f782f7463702f31");
        // Multiple multiaddrs — `@`-separated hex chunks.
        let two = build_set_metadata_calldata(&[
            "/dns4/x/tcp/1".to_string(),
            "/ip4/1.2.3.4/tcp/2".to_string(),
        ]);
        let expected = format!(
            "setNodeMetadata@{}@{}",
            hex::encode("/dns4/x/tcp/1"),
            hex::encode("/ip4/1.2.3.4/tcp/2")
        );
        assert_eq!(two, expected);
    }
}

// ─── v0.45.0: metadata + pause/resume admin endpoints (spec 12 §2.10 + §2.11) ───
//
// All four endpoints return Klever-extension calldata, never sign or
// broadcast a TX themselves — the dashboard does that via
// `kleverWeb.buildTransaction` / `signTransaction` / `broadcastTransactions`,
// matching the established `registerNode` / `unregisterNode` pattern
// (dashboard.html § registerNodeOnChain). The only node-side SC-signing
// path in v0.45.0 is the SIGTERM `pauseNode` handler.
//
// `calldata` strings follow the Klever VM ABI: `funcName@hex1@hex2@…`,
// where each `hex` is the lowercase-hex of the argument bytes. The
// dashboard `btoa`s this string and passes it as the second argument
// to `kleverWeb.buildTransaction([{type:63,payload:{scType:0,…}}], [btoa(callData)])`.
// Empty args (e.g. `pauseNode`) emit just the function name with no `@`.

/// Compute the effective multiaddr list — what the node WOULD publish.
///
/// Returns `(effective, auto_derived)`. `auto_derived = true` iff
/// `publish=true` and `configured.multiaddrs` is empty, in which case
/// we synthesize a single multiaddr from the API public_url host + the
/// libp2p listen_port. Returns empty when `publish=false` or when
/// auto-derive is requested but the host can't be parsed out of
/// `public_url`.
fn compute_effective_multiaddrs(
    cfg: &crate::config::AnchorMetadataConfig,
    network_listen_port: u16,
    api_public_url: Option<&str>,
    network_peer_id: &str,
) -> (Vec<String>, bool) {
    if !cfg.publish {
        return (Vec::new(), false);
    }
    if !cfg.multiaddrs.is_empty() {
        return (cfg.multiaddrs.clone(), false);
    }
    // Spec 13 §6.1 requires `/p2p/<peer_id>` in the auto-derived
    // multiaddr — without it, `sc_discovery::persist_multiaddr` can't
    // extract the storage key and silently drops the entry, defeating
    // the whole tier 3 discovery path (v0.45.0 → 0.45.1 hotfix).
    // Empty peer_id ⇒ auto-derive returns empty with the flag set so
    // the dashboard can surface "publish enabled but peer_id missing".
    if network_peer_id.is_empty() {
        return (Vec::new(), true);
    }
    // Auto-derive. Pull the hostname from `[api] public_url`, pair it
    // with the libp2p `[network] listen_port`, and suffix `/p2p/<peer_id>`
    // (spec 13 §6.1). The peer_id is required by `sc_discovery::persist_multiaddr`
    // which uses it as the PEER_DIRECTORY storage key — without it, the
    // consumer silently drops the entry (v0.45.1 fix). Operators with
    // non-trivial topology (NAT, anonymizer front, onion) set
    // `multiaddrs` explicitly instead.
    let host = api_public_url.and_then(extract_host_from_url);
    let Some(host) = host else {
        // `publish=true` but we can't infer a host — return empty
        // rather than emit an invalid multiaddr that would fail the
        // SC's `Invalid multiaddr length` / parse check later.
        return (Vec::new(), true);
    };
    // Prefer /dns4 for hostnames; /ip4 for literal IPv4. We don't
    // attempt to detect IPv6 here — operators who run on a v6-only
    // host must set `multiaddrs` explicitly.
    let proto = if host.parse::<std::net::Ipv4Addr>().is_ok() {
        "ip4"
    } else {
        "dns4"
    };
    // Spec 13 §6.1: emit BOTH TCP and QUIC variants so dual-transport
    // dialers can choose. The libp2p listener binds both transports
    // on the same port (see NetworkService::new), so this is correct
    // even though `listen_port` is single-valued in config. Each
    // variant carries `/p2p/<self_peer_id>` so consumers can use the
    // multiaddr as a complete dial target (v0.45.1 fix — without
    // /p2p/, sc_discovery::persist_multiaddr rejects the entry).
    let tcp = format!(
        "/{}/{}/tcp/{}/p2p/{}",
        proto, host, network_listen_port, network_peer_id
    );
    let quic = format!(
        "/{}/{}/udp/{}/quic-v1/p2p/{}",
        proto, host, network_listen_port, network_peer_id
    );
    (vec![tcp, quic], true)
}

/// Extract the host portion of a URL like `https://node.ogmara.org:1234/path`.
/// Returns `None` if no host can be found. Strips the userinfo (`user@`),
/// the port (`:1234`), and the path. Bracketed IPv6 hosts (`[::1]`) are
/// rejected — operators with an IPv6 endpoint must set `multiaddrs`
/// explicitly because the libp2p multiaddr form differs.
fn extract_host_from_url(url: &str) -> Option<String> {
    // Skip the scheme (everything up to "://").
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // Stop at the first '/', '?', or '#' — those start the path / query / fragment.
    let authority = after_scheme
        .split(|c: char| matches!(c, '/' | '?' | '#'))
        .next()
        .unwrap_or("");
    // Strip userinfo if present.
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // Reject bracketed IPv6 — see fn-doc.
    if host_port.starts_with('[') {
        return None;
    }
    // Strip the port. rsplit_once on ':' so an IPv6 literal without
    // brackets (already rejected above) wouldn't mis-truncate.
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    if host.is_empty() {
        return None;
    }
    // Reject any residual colon — unbracketed IPv6 like `http://::1:8080`
    // would otherwise leak through and produce an invalid multiaddr
    // the SC rejects at publish time (Code Audit W7).
    if host.contains(':') {
        return None;
    }
    // Reject control characters / non-printable bytes — defense
    // against a hostile operator config or a clipboard accident
    // (Security Audit N4). Standard DNS / IPv4 hostnames never
    // contain anything outside [0x21, 0x7e].
    if host.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
        return None;
    }
    Some(host.to_string())
}

/// Build the Klever-VM calldata string for `setNodeMetadata(multiaddrs)`.
/// Each multiaddr becomes its own hex-encoded arg. Empty arg list ⇒
/// just the function name (which the SC would reject — caller should
/// short-circuit before calling this).
fn build_set_metadata_calldata(multiaddrs: &[String]) -> String {
    let mut s = String::from("setNodeMetadata");
    for m in multiaddrs {
        s.push('@');
        s.push_str(&hex::encode(m.as_bytes()));
    }
    s
}

/// GET /admin/node/metadata — operator metadata snapshot + publish calldata.
///
/// Returns the operator's current `[anchoring.metadata]` config
/// (publish flag + configured multiaddrs), the effective list the node
/// WOULD publish (post auto-derive), the on-chain list currently
/// registered for the anchorer wallet (via the `getNodeMetadata` SC
/// view), and pre-built calldata strings for the dashboard's Publish /
/// Clear buttons. The dashboard renders an "in sync" indicator by
/// comparing `effective_multiaddrs` to `on_chain_multiaddrs`.
///
/// Wallet-authenticated. No node-side signing; the calldata is meant
/// to be passed straight to `kleverWeb.buildTransaction` after
/// `btoa(...)`.
pub async fn node_metadata(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let klever_node_url = state.klever_node_url.clone();
    let contract_address = state.contract_address.clone();
    let wallet = state.node_address.clone();

    if klever_node_url.is_empty() || contract_address.is_empty() || wallet.is_empty() {
        return Json(serde_json::json!({
            "wallet": wallet,
            "klever_network": state.klever_network,
            "contract_address": contract_address,
            "anchoring_configured": false,
            "error": "klever.node_url, klever.contract_address, or node anchor wallet not configured",
        }))
        .into_response();
    }

    let (effective, auto_derived) = compute_effective_multiaddrs(
        &state.anchor_metadata_config,
        state.network_listen_port,
        state.public_url.as_deref(),
        &state.network_peer_id,
    );

    let on_chain_res = crate::chain::sc_views::get_node_metadata(
        &state.klever_view_http,
        &klever_node_url,
        &contract_address,
        &wallet,
    )
    .await;

    // null on RPC failure so the dashboard can render "—" rather than
    // misreport "empty" and prompt the operator to re-publish (same
    // pattern as the v0.43.0 audit W2 fix on registration view).
    let (on_chain_value, on_chain_for_diff) = match on_chain_res {
        Ok(v) => (serde_json::Value::from(v.clone()), Some(v)),
        Err(_) => (serde_json::Value::Null, None),
    };

    // in_sync is null when we couldn't read the on-chain state — don't
    // claim diff status against an unknown.
    let in_sync = on_chain_for_diff.as_ref().map(|on_chain| {
        on_chain.len() == effective.len()
            && on_chain.iter().zip(effective.iter()).all(|(a, b)| a == b)
    });

    // set_calldata is null when publish is off or effective is empty
    // (would result in a no-op or SC reject). clear_calldata is null
    // when the on-chain list is already empty (no-op) or we couldn't
    // read it (avoid prompting a destructive action against unknown
    // state).
    let set_calldata = if state.anchor_metadata_config.publish && !effective.is_empty() {
        serde_json::Value::String(build_set_metadata_calldata(&effective))
    } else {
        serde_json::Value::Null
    };
    let clear_calldata = match on_chain_for_diff.as_ref() {
        Some(v) if !v.is_empty() => serde_json::Value::String("unsetNodeMetadata".to_string()),
        _ => serde_json::Value::Null,
    };

    Json(serde_json::json!({
        "wallet": wallet,
        "klever_network": state.klever_network,
        "contract_address": contract_address,
        "anchoring_configured": true,
        "publish_enabled": state.anchor_metadata_config.publish,
        "configured_multiaddrs": state.anchor_metadata_config.multiaddrs,
        "effective_multiaddrs": effective,
        "auto_derived": auto_derived,
        "on_chain_multiaddrs": on_chain_value,
        "in_sync": in_sync,
        "set_calldata": set_calldata,
        "clear_calldata": clear_calldata,
    }))
    .into_response()
}

/// Build the Klever-VM calldata string for `pauseNode(reason)`.
/// `reason` is hex-encoded; spec 12 §2.11 caps it at 256 bytes — we
/// truncate locally so a slip-past doesn't waste the operator's TX gas.
fn build_pause_calldata(reason: &str) -> String {
    const MAX_REASON_BYTES: usize = 256;
    let bytes = reason.as_bytes();
    let trimmed = if bytes.len() > MAX_REASON_BYTES {
        // Truncate at a UTF-8 boundary so the hex-decoded string the
        // SC sees is still valid (the SC stores it as ManagedBuffer
        // bytes — UTF-8 validity isn't required, but it keeps the
        // event log readable).
        let mut cut = MAX_REASON_BYTES;
        while cut > 0 && (bytes[cut] & 0xC0) == 0x80 {
            cut -= 1;
        }
        &bytes[..cut]
    } else {
        bytes
    };
    format!("pauseNode@{}", hex::encode(trimmed))
}

/// GET /admin/node/pause-status — pause state + resume calldata.
///
/// Returns the live `isNodePaused` SC view for the anchorer wallet
/// plus the local `pause_on_shutdown` config flag and whether a
/// wallet_key is configured (which determines if SIGTERM-pause can
/// actually fire). Bundles resume calldata; pause calldata requires
/// an operator-supplied reason (spec 12 §2.11 + spec 13 §6.3) so the
/// dashboard POSTs `/admin/node/pause` with the reason after
/// prompting the operator.
pub async fn node_pause_status(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let klever_node_url = state.klever_node_url.clone();
    let contract_address = state.contract_address.clone();
    let wallet = state.node_address.clone();

    if klever_node_url.is_empty() || contract_address.is_empty() || wallet.is_empty() {
        return Json(serde_json::json!({
            "wallet": wallet,
            "klever_network": state.klever_network,
            "contract_address": contract_address,
            "anchoring_configured": false,
            "paused": serde_json::Value::Null,
            "pause_on_shutdown": state.anchor_pause_on_shutdown,
            "wallet_key_configured": state.anchor_wallet_key_configured,
            "error": "klever.node_url, klever.contract_address, or node anchor wallet not configured",
        }))
        .into_response();
    }

    // null on RPC failure — operator sees "Pause status unknown" in
    // the dashboard rather than a falsely confident "Active".
    let paused = crate::chain::sc_views::is_node_paused(
        &state.klever_view_http,
        &klever_node_url,
        &contract_address,
        &wallet,
    )
    .await
    .ok()
    .map(serde_json::Value::from)
    .unwrap_or(serde_json::Value::Null);

    Json(serde_json::json!({
        "wallet": wallet,
        "klever_network": state.klever_network,
        "contract_address": contract_address,
        "anchoring_configured": true,
        "paused": paused,
        "pause_on_shutdown": state.anchor_pause_on_shutdown,
        "wallet_key_configured": state.anchor_wallet_key_configured,
        // No pre-built pause calldata — pauseNode requires a reason
        // arg (spec 12 §2.11). The dashboard POSTs to /admin/node/pause
        // with {reason} and gets the assembled calldata back. Resume
        // takes no args so we surface it directly.
        "resume_calldata": "resumeNode",
    }))
    .into_response()
}

/// POST /admin/node/pause — returns the `pauseNode(reason)` calldata.
///
/// Request body (JSON): `{ "reason": "Upgrading to l2-node 0.45.0" }`.
/// The reason becomes the `pause_node(reason: ManagedBuffer)` argument
/// (spec 12 §2.11) and is also emitted on the `nodePaused` event log
/// so consumers (other operators, the dashboard "recent activity"
/// feed) can see why a node went offline. The SC caps reason at 256
/// bytes; we mirror the cap locally so an oversized field doesn't
/// waste the operator's TX gas on a guaranteed `require!` failure.
///
/// Empty / missing reason is accepted — the SC `require!(reason.len() <= 256)`
/// trivially passes — but the dashboard always prompts.
#[derive(Deserialize, Default)]
pub struct PauseRequest {
    #[serde(default)]
    pub reason: String,
}

pub async fn node_pause(
    Extension(state): Extension<Arc<AppState>>,
    body: Option<Json<PauseRequest>>,
) -> impl IntoResponse {
    let wallet = state.node_address.clone();
    let contract_address = state.contract_address.clone();
    if contract_address.is_empty() || wallet.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "anchoring not configured (missing klever.contract_address or anchor wallet)"
            })),
        )
            .into_response();
    }
    let reason = body.map(|Json(b)| b.reason).unwrap_or_default();
    Json(serde_json::json!({
        "wallet": wallet,
        "klever_network": state.klever_network,
        "contract_address": contract_address,
        "calldata": build_pause_calldata(&reason),
        "reason": reason,
    }))
    .into_response()
}

/// POST /admin/node/resume — returns the `resumeNode` calldata.
///
/// `resumeNode` takes no SC args (spec 12 §2.11) so no body is read.
pub async fn node_resume(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let wallet = state.node_address.clone();
    let contract_address = state.contract_address.clone();
    if contract_address.is_empty() || wallet.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "anchoring not configured (missing klever.contract_address or anchor wallet)"
            })),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "wallet": wallet,
        "klever_network": state.klever_network,
        "contract_address": contract_address,
        "calldata": "resumeNode",
    }))
    .into_response()
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
