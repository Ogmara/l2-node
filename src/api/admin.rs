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

/// GET /admin/network/mesh-stats — GossipSub mesh-state instrumentation
/// (spec 10 §9.2, l2-node 0.46.6+).
///
/// Returns a snapshot of per-topic mesh size + subscriber count plus
/// the cumulative publish-failure counters partitioned by
/// `PublishError` variant. Used to diagnose B4 (asymmetric GossipSub
/// propagation, `docs/planning/mainnet-blockers-fix-plan.md` step 2)
/// and gate the proper fix that ships in v0.46.10.
///
/// The snapshot is refreshed by the network task every 30s
/// ([`crate::network::MESH_STATS_REFRESH_INTERVAL`]); poll less
/// frequently than that to avoid serving stale-but-changing data.
/// Publish-failure counters are read live from `Arc<AtomicU64>` so
/// they're always current, separately from the 30s topic snapshot.
///
/// Operator runbook for full diagnosis:
///
/// ```text
/// # Capture 30 minutes of mesh control messages alongside polled snapshots.
/// RUST_LOG="info,libp2p_gossipsub=trace" ogmara-node --config ogmara.toml
/// watch -n5 'curl -s http://127.0.0.1:41721/admin/network/mesh-stats | jq'
/// ```
///
/// Response shape:
/// ```json
/// {
///   "generated_at_unix": 1748707200,
///   "topics": [
///     { "topic": "...", "mesh_size": 2, "subscribers": 3 }
///   ],
///   "total_mesh_slots": 4,
///   "publish_failures": {
///     "total": 12,
///     "no_peers_subscribed": 7,
///     "all_queues_full": 1,
///     "other": 4
///   }
/// }
/// ```
pub async fn mesh_stats(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // Live counter read — these are atomics so the response always
    // reflects the latest increment, even between the 30s topic-
    // snapshot refresh ticks.
    let (total, no_peers, all_queues_full, other) =
        state.publish_failure_counters.snapshot();

    // Topic snapshot under a brief read lock. If poisoned (shouldn't
    // happen — the writer never panics inside the critical section),
    // serve an empty topic list with `generated_at_unix = 0` to
    // signal "no fresh data" rather than 500ing the diagnostic
    // endpoint (it's most-needed when something is wrong).
    let topic_payload = match state.mesh_stats.read() {
        Ok(snap) => serde_json::json!({
            "generated_at_unix": snap.generated_at_unix,
            "topics": snap.topics,
            "total_mesh_slots": snap.total_mesh_slots,
        }),
        Err(_) => serde_json::json!({
            "generated_at_unix": 0,
            "topics": [],
            "total_mesh_slots": 0,
            "note": "mesh_stats lock poisoned — serving live counters only"
        }),
    };

    let mut body = topic_payload;
    body["publish_failures"] = serde_json::json!({
        "total": total,
        "no_peers_subscribed": no_peers,
        "all_queues_full": all_queues_full,
        "other": other,
    });
    Json(body)
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
        format_klv, is_ipv6_non_routable, HostKind,
    };
    use crate::config::AnchorMetadataConfig;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
    fn host_extraction_dns() {
        assert_eq!(
            extract_host_from_url("https://node.ogmara.org:1234/path"),
            Some(HostKind::Dns("node.ogmara.org".to_string()))
        );
        assert_eq!(
            extract_host_from_url("http://node.ogmara.org"),
            Some(HostKind::Dns("node.ogmara.org".to_string()))
        );
        // No scheme — treat the whole thing as authority.
        assert_eq!(
            extract_host_from_url("node.ogmara.org:9000"),
            Some(HostKind::Dns("node.ogmara.org".to_string()))
        );
        // Userinfo stripped.
        assert_eq!(
            extract_host_from_url("https://user:pass@node.ogmara.org:8443/x"),
            Some(HostKind::Dns("node.ogmara.org".to_string()))
        );
    }

    #[test]
    fn host_extraction_ipv4() {
        assert_eq!(
            extract_host_from_url("https://1.2.3.4:8080"),
            Some(HostKind::Ipv4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(
            extract_host_from_url("http://203.0.113.7"),
            Some(HostKind::Ipv4(Ipv4Addr::new(203, 0, 113, 7)))
        );
    }

    #[test]
    fn host_extraction_ipv6_bracketed() {
        // v0.46.0 Phase D — bracketed IPv6 with port is now accepted.
        assert_eq!(
            extract_host_from_url("http://[::1]:8080"),
            Some(HostKind::Ipv6(Ipv6Addr::LOCALHOST))
        );
        // Bracketed IPv6 without port.
        assert_eq!(
            extract_host_from_url("http://[2001:db8::1]"),
            Some(HostKind::Ipv6("2001:db8::1".parse().unwrap()))
        );
        // Bracketed with path.
        assert_eq!(
            extract_host_from_url("http://[2001:db8::1]:9000/admin"),
            Some(HostKind::Ipv6("2001:db8::1".parse().unwrap()))
        );
    }

    #[test]
    fn host_extraction_ipv6_malformed_rejected() {
        // Missing closing bracket.
        assert_eq!(extract_host_from_url("http://[::1:8080"), None);
        // Garbage after closing bracket.
        assert_eq!(extract_host_from_url("http://[::1]garbage"), None);
        // Non-numeric port after closing bracket.
        assert_eq!(extract_host_from_url("http://[::1]:abc"), None);
        // Invalid IPv6 inside brackets.
        assert_eq!(extract_host_from_url("http://[not-an-ipv6]:80"), None);
    }

    #[test]
    fn host_extraction_unbracketed_ipv6_still_rejected() {
        // Unbracketed IPv6 — the rsplit-on-colon port-strip would
        // mis-truncate, so we reject. Operators must use bracketed form.
        assert_eq!(extract_host_from_url("http://::1:8080"), None);
    }

    #[test]
    fn host_extraction_control_chars_rejected() {
        // Control characters anywhere in the host (newline injection
        // defense, Security Audit N4).
        assert_eq!(extract_host_from_url("https://host\n.attacker.com"), None);
    }

    #[test]
    fn ipv6_routable_classification() {
        // Routable — must pass.
        assert!(!is_ipv6_non_routable(&"2001:db8::1".parse().unwrap()));
        assert!(!is_ipv6_non_routable(&"fc00::1".parse().unwrap())); // ULA — allowed
        assert!(!is_ipv6_non_routable(&"2620:0:2d0:200::7".parse().unwrap()));

        // Non-routable — must reject.
        assert!(is_ipv6_non_routable(&Ipv6Addr::LOCALHOST)); // ::1
        assert!(is_ipv6_non_routable(&Ipv6Addr::UNSPECIFIED)); // ::
        assert!(is_ipv6_non_routable(&"fe80::1".parse().unwrap())); // link-local
        assert!(is_ipv6_non_routable(&"ff02::1".parse().unwrap())); // multicast
        assert!(is_ipv6_non_routable(&"::ffff:1.2.3.4".parse().unwrap())); // IPv4-mapped
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
    fn effective_multiaddrs_auto_derive_ipv6() {
        // v0.46.0 Phase D — v6-only operator can now use auto-derive
        // (was: forced to set `multiaddrs` explicitly).
        let cfg = AnchorMetadataConfig {
            publish: true,
            multiaddrs: vec![],
        };
        let (eff, derived) = compute_effective_multiaddrs(
            &cfg,
            41720,
            Some("http://[2001:db8::1]:8443"),
            TEST_PEER_ID,
        );
        assert!(derived);
        assert_eq!(
            eff,
            vec![
                format!("/ip6/2001:db8::1/tcp/41720/p2p/{}", TEST_PEER_ID),
                format!("/ip6/2001:db8::1/udp/41720/quic-v1/p2p/{}", TEST_PEER_ID),
            ]
        );
    }

    #[test]
    fn effective_multiaddrs_auto_derive_ipv6_non_routable_rejected() {
        // Non-routable IPv6 returns empty + auto_derived=true so the
        // dashboard can surface the same diagnostic shape as the
        // missing-peer_id branch — emitting a link-local multiaddr on
        // chain would waste consumer dial cycles (Phase A R5).
        let cfg = AnchorMetadataConfig {
            publish: true,
            multiaddrs: vec![],
        };
        for unreachable in &[
            "[::1]:8080",            // loopback
            "[fe80::1]:8080",        // link-local
            "[ff02::1]:8080",        // multicast
            "[::]:8080",             // unspecified
            "[::ffff:1.2.3.4]:8080", // IPv4-mapped — libp2p routes via v4 anyway
        ] {
            let url = format!("http://{}", unreachable);
            let (eff, derived) =
                compute_effective_multiaddrs(&cfg, 41720, Some(&url), TEST_PEER_ID);
            assert!(derived, "auto_derived should stay true for {}", unreachable);
            assert!(
                eff.is_empty(),
                "non-routable IPv6 {} must not emit a multiaddr",
                unreachable
            );
        }
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
pub(crate) fn compute_effective_multiaddrs(
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
    // Auto-derive. Pull the host from `[api] public_url`, pair it
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
    // Branch by host kind. `/dns4` for hostnames, `/ip4` for IPv4
    // literals, `/ip6` for routable IPv6 literals (v0.46.0 Phase D).
    // Non-routable IPv6 (loopback, link-local, multicast, unspecified,
    // IPv4-mapped) returns empty with auto_derived=true so the
    // dashboard surfaces the diagnostic (matches the missing-peer_id
    // branch shape) — emitting `/ip6/fe80::1/...` on chain would burn
    // operator gas and waste consumers' dial cycles on an unreachable
    // address (Phase A Risk R5 from the v0.46.0 plan).
    let (proto, host_str) = match host {
        HostKind::Dns(s) => ("dns4", s),
        HostKind::Ipv4(ip) => ("ip4", ip.to_string()),
        HostKind::Ipv6(ip) => {
            if is_ipv6_non_routable(&ip) {
                tracing::debug!(
                    address = %ip,
                    "compute_effective_multiaddrs: auto-derive skipped non-routable IPv6"
                );
                return (Vec::new(), true);
            }
            ("ip6", ip.to_string())
        }
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
        proto, host_str, network_listen_port, network_peer_id
    );
    let quic = format!(
        "/{}/{}/udp/{}/quic-v1/p2p/{}",
        proto, host_str, network_listen_port, network_peer_id
    );
    (vec![tcp, quic], true)
}

/// Compute the onion multiaddr to append to the desired metadata
/// list when `[network.tor] advertise_onion_in_metadata = true` and a
/// hidden-service hostname + port are configured. Returns `None` when
/// onion advertisement is off, when Tor is not enabled, or when the
/// hostname/port are missing.
///
/// Multiaddr format: `/onion3/<stem>:<port>/p2p/<peer_id>` where
/// `<stem>` is the 56-char base32 portion of the v3 onion address
/// (the part before `.onion`). The `/p2p/<peer_id>` suffix is
/// required by the v0.46.5 SC-driven bootstrap rules (spec 13 §4.2)
/// — without it, consumers reject the entry as undialable.
///
/// Spec 13 §6.4 (l2-node 0.46.9+).
pub(crate) fn compute_onion_advertisement(
    tor: &crate::config::TorConfig,
    network_peer_id: &str,
) -> Option<String> {
    if !tor.enabled || !tor.advertise_onion_in_metadata {
        return None;
    }
    if tor.listen_onion_port == 0 {
        return None;
    }
    if network_peer_id.is_empty() {
        // Same rule as `compute_effective_multiaddrs`: an empty
        // peer_id means we couldn't produce a dialable multiaddr, so
        // omit the entry rather than emit something the consumer will
        // reject.
        return None;
    }
    let host = tor.listen_onion_hostname.trim();
    let stem = host.strip_suffix(".onion")?;
    if stem.len() != 56 {
        // Defensive — `validate` already enforced this, but the
        // helper is called from contexts that may have skipped
        // validation (unit tests constructing config by hand).
        return None;
    }
    Some(format!(
        "/onion3/{}:{}/p2p/{}",
        stem, tor.listen_onion_port, network_peer_id
    ))
}

/// Tagged host kind returned by [`extract_host_from_url`]. Drives the
/// `/dns4` vs `/ip4` vs `/ip6` multiaddr-protocol selection in
/// [`compute_effective_multiaddrs`]. Added in v0.46.0 Phase D so v6-only
/// operators can run with `[anchoring.metadata] publish = true,
/// multiaddrs = []` instead of being forced to set `multiaddrs`
/// explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostKind {
    /// Hostname (parsed as DNS — could be Punycode-encoded IDN).
    Dns(String),
    /// IPv4 literal.
    Ipv4(std::net::Ipv4Addr),
    /// IPv6 literal. Routability check (loopback / link-local /
    /// multicast / unspecified / IPv4-mapped rejection) is the
    /// consumer's responsibility — `extract_host_from_url` returns
    /// every well-formed parse.
    Ipv6(std::net::Ipv6Addr),
}

/// True iff the IPv6 address is in a non-routable range that would
/// be useless to publish on-chain as a dial target. Rejects:
/// - `::1/128` loopback
/// - `::/128` unspecified
/// - `ff00::/8` multicast
/// - `fe80::/10` link-local
/// - `::ffff:0:0/96` IPv4-mapped (libp2p dials those via IPv4 anyway)
///
/// Does NOT reject ULA (`fc00::/7`) or documentation (`2001:db8::/32`)
/// — operators on private networks legitimately publish ULA, and
/// documentation ranges are technically dialable on lab nets. Phase D
/// design: false-positives (rejecting a valid addr) hurt operators;
/// false-negatives (passing a bogus addr) only waste consumer dial
/// cycles, which is recoverable.
fn is_ipv6_non_routable(addr: &std::net::Ipv6Addr) -> bool {
    addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        // Link-local fe80::/10 — first 10 bits are 1111111010.
        || (addr.segments()[0] & 0xffc0 == 0xfe80)
        // IPv4-mapped ::ffff:0:0/96 — libp2p would route via IPv4 anyway,
        // so an operator publishing /ip6/::ffff:1.2.3.4 is misconfigured.
        || addr.to_ipv4_mapped().is_some()
}

/// Extract the host portion of a URL like `https://node.ogmara.org:1234/path`.
/// Returns `None` if no host can be found. Strips the userinfo (`user@`),
/// the port (`:1234`), and the path.
///
/// Three host kinds recognised:
///   - **DNS name** — any non-empty ASCII-printable string without `:`
///     or `[`. Punycode-encoded IDN works (it's ASCII).
///   - **IPv4 literal** — auto-detected via `Ipv4Addr` parse on the
///     extracted host.
///   - **IPv6 literal** — bracketed form REQUIRED (`[::1]:8080`,
///     `[2001:db8::1]/path`, etc.). Unbracketed forms are rejected
///     because the rsplit-on-colon port-strip would mis-truncate them
///     (and unbracketed IPv6 is non-standard in URLs anyway). Routability
///     filtering is left to the caller (`compute_effective_multiaddrs`
///     rejects loopback / link-local / multicast / unspecified /
///     IPv4-mapped before emitting an on-chain multiaddr).
fn extract_host_from_url(url: &str) -> Option<HostKind> {
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

    // Bracketed IPv6: `[<addr>]` or `[<addr>]:<port>`. Find the
    // matching `]` and parse what's inside as an Ipv6Addr.
    if let Some(stripped) = host_port.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            // `[` without matching `]` — malformed.
            return None;
        };
        let inner = &stripped[..end];
        // Self-documenting guard: `[]` has empty inner and `parse`
        // would also reject, but the early return makes the intent
        // explicit (Phase D Security Audit N1).
        if inner.is_empty() {
            return None;
        }
        // Anything after `]` must be empty or `:<port>` — reject
        // garbage like `[::1]xyz`. Port digit count is intentionally
        // unbounded: the port from `public_url` is NEVER extracted
        // here (the multiaddr port comes from `[network] listen_port`
        // config), so an oversized or zero-padded port string is just
        // ignored after the syntax check (Phase D Security Audit N2).
        let trailing = &stripped[end + 1..];
        if !(trailing.is_empty()
            || (trailing.starts_with(':') && trailing[1..].chars().all(|c| c.is_ascii_digit())))
        {
            return None;
        }
        return inner.parse::<std::net::Ipv6Addr>().ok().map(HostKind::Ipv6);
    }

    // Non-bracketed: strip the trailing `:<port>` if present.
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    if host.is_empty() {
        return None;
    }
    // Reject any residual colon — unbracketed IPv6 like `http://::1:8080`
    // would otherwise leak through and produce an invalid multiaddr
    // the SC rejects at publish time (Code Audit W7 carried forward).
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
    // IPv4 literal vs DNS name — try parsing as Ipv4Addr first.
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some(HostKind::Ipv4(ip));
    }
    Some(HostKind::Dns(host.to_string()))
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

    let (mut effective, auto_derived) = compute_effective_multiaddrs(
        &state.anchor_metadata_config,
        state.network_listen_port,
        state.public_url.as_deref(),
        &state.network_peer_id,
    );
    // Spec 13 §6.4 (l2-node 0.46.9+) — append the onion multiaddr
    // when the operator has opted into advertising it. This runs
    // regardless of whether the clearnet multiaddrs were configured
    // explicitly or auto-derived, so onion-only operators see the
    // entry too.
    if let Some(onion) = compute_onion_advertisement(
        &state.tor_config,
        &state.network_peer_id,
    ) {
        effective.push(onion);
    }

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

    // Background reconciler's most-recent observation (spec 13 §6.1).
    // `drift_detected` lets the dashboard render a yellow "On-chain
    // metadata is out of sync — click Publish to update" banner even
    // between operator-driven page loads; `drift_detected_at` lets
    // the operator see how long the divergence has persisted.
    let (drift_detected, drift_detected_at) = {
        let snap = state.metadata_drift.read().await;
        match snap.as_ref() {
            Some(s) => (true, Some(s.detected_at)),
            None => (false, None),
        }
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
        "drift_detected": drift_detected,
        "drift_detected_at": drift_detected_at,
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
