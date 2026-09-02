//! Admin-only endpoints (spec 4.4).
//!
//! Only accessible from localhost. Provides node operator controls
//! for peer management, storage stats, and state anchoring.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use super::state::AppState;

// NOTE: the old `localhost_only` middleware was removed (audit 2026-06-07 N5) —
// it was dead code (admin routes are gated by `admin_auth::admin_auth_middleware`,
// which does the resolved-client-IP loopback check; see B1.1).

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
/// propagation, `docs/planning/mainnet-blockers-fix-plan.md` step 2);
/// the proper fix shipped in l2-node 0.48.4 (`mesh_outbound_min = 0`
/// plus the `/admin/network/peer-telemetry` direction view below).
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

/// GET /admin/network/peer-telemetry — per-peer connection-direction
/// view (B4 fix proper, l2-node 0.48.4).
///
/// B4 (asymmetric GossipSub propagation, `mainnet-blockers-fix-plan.md`
/// step 6) is rooted in connection *direction*: a node holding only
/// inbound connections cannot fill an outbound mesh slot. The 0.48.4
/// release sets `mesh_outbound_min = 0` so such a node publishes
/// anyway; this endpoint lets operators *see* the balance so a NATed
/// or dial-failing node is still diagnosable.
///
/// `inbound_only_peers > 0` while `outbound_peers == 0` is the danger
/// zone the config change tolerates — worth alerting on operationally.
///
/// **GossipSub peer-scoring is intentionally disabled.** libp2p's
/// score-based mesh maintenance prunes low-scored peers; on Ogmara's
/// small meshes (often 1–3 peers) that would evict the only peer a
/// node has and make B4 worse, not better. Connection-direction
/// telemetry is the actionable signal at this scale, so `gossipsub_
/// scoring` is reported as `"disabled"` to make the decision explicit.
///
/// Reads the same `MeshStatsSnapshot` the network task refreshes every
/// 30s ([`crate::network::MESH_STATS_REFRESH_INTERVAL`]); the per-peer
/// rows reflect that snapshot, not live swarm state.
///
/// Response shape:
/// ```json
/// {
///   "generated_at_unix": 1748707200,
///   "total_peers": 4,
///   "outbound_peers": 1,
///   "inbound_only_peers": 3,
///   "gossipsub_scoring": "disabled",
///   "peers": [
///     { "peer_id": "12D3KooW...", "outbound_conns": 1, "inbound_conns": 0, "mesh_topics": 2 }
///   ]
/// }
/// ```
pub async fn peer_telemetry(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // Brief read lock; the writer never panics inside its critical
    // section, but if poisoned we serve an empty view with
    // `generated_at_unix = 0` ("no fresh data") rather than 500ing a
    // diagnostic endpoint that's most-needed when something is wrong.
    match state.mesh_stats.read() {
        Ok(snap) => Json(serde_json::json!({
            "generated_at_unix": snap.generated_at_unix,
            "total_peers": snap.total_peers,
            "outbound_peers": snap.outbound_peers,
            "inbound_only_peers": snap.inbound_only_peers,
            "gossipsub_scoring": "disabled",
            "peers": snap.peers,
        })),
        Err(_) => Json(serde_json::json!({
            "generated_at_unix": 0,
            "total_peers": 0,
            "outbound_peers": 0,
            "inbound_only_peers": 0,
            "gossipsub_scoring": "disabled",
            "peers": [],
            "note": "mesh_stats lock poisoned — no fresh peer telemetry",
        })),
    }
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
            "news_feed", "news_by_tag", "news_by_author",
            "hot_topics_local", "hot_topics_merged", "users",
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
    // Honest 501 (audit 2026-06-07 N5): peer-banning is NOT wired. Returning
    // `{ok:true}` gave operators/dashboards a false sense of control. Surface
    // it as unimplemented until the peer-ban enforcement path exists.
    tracing::warn!(node_id = %req.node_id, "ban_peer called but peer-banning is not implemented");
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "ok": false,
            "error": "peer banning is not implemented",
        })),
    )
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
    // Honest 501 (audit 2026-06-07 N5): channel pinning is NOT wired — see
    // ban_peer. Don't claim success for a no-op control.
    tracing::warn!(channel_id = req.channel_id, "pin_channel called but channel pinning is not implemented");
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "ok": false,
            "error": "channel pinning is not implemented",
        })),
    )
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
            "network_active_node_count": serde_json::Value::Null,
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
    let (
        registered_res,
        count_res,
        active_count_res,
        fee_res,
        canonical_height_res,
        registered_at_res,
    ) = tokio::join!(
        crate::chain::sc_views::is_node_registered(http, &klever_node_url, &contract_address, &wallet),
        crate::chain::sc_views::get_node_count(http, &klever_node_url, &contract_address),
        // v0.109.0 (SC 0.5.0+): active (non-paused) count is the actual
        // denominator behind the hybrid-quorum escalation threshold — a
        // registered-but-paused node doesn't count toward it. Surfaced
        // alongside the paused-inclusive count so the dashboard doesn't
        // conflate "registered" with "can anchor right now" (spec 12 §2.8).
        crate::chain::sc_views::get_active_node_count(http, &klever_node_url, &contract_address),
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
    // v0.109.0: same null-on-unavailable convention as `network_node_count`.
    let network_active_node_count = active_count_res.ok().map(serde_json::Value::from).unwrap_or(serde_json::Value::Null);
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
        "network_active_node_count": network_active_node_count,
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
/// Thin alias over the shared formatter in `util`, which the public
/// `registration/info` endpoint also uses — one implementation, so the
/// dashboard and the API can never disagree about how an amount renders.
fn format_klv(raw: u128) -> String {
    crate::util::format_klv_amount(raw)
}

#[cfg(test)]
mod tests {
    use super::{
        build_set_metadata_calldata, compute_effective_multiaddrs, encode_bool_calldata_arg,
        encode_biguint_calldata_arg, encode_u64_calldata_arg, extract_host_from_url, format_klv,
        is_ipv6_non_routable, node_voting_period_in_range, proposal_status, HostKind,
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

    // --- Governance calldata encoders (governance-dashboard-plan.md Phase 6) ---

    #[test]
    fn bool_calldata_arg_false_is_empty_not_zero() {
        // THE landmine (see the function's doc comment): false must be
        // "", never "00" — a stored/encoded bool false top-encodes to
        // empty bytes in klever-sc-codec, not a zero byte.
        assert_eq!(encode_bool_calldata_arg(false), "");
        assert_eq!(encode_bool_calldata_arg(true), "01");
    }

    #[test]
    fn u64_calldata_arg_zero_is_empty_not_00() {
        // Different rule from sc_views.rs's view-call encoder, which
        // encodes 0 as "00" — TX calldata's 0 is empty bytes.
        assert_eq!(encode_u64_calldata_arg(0), "");
        assert_eq!(encode_u64_calldata_arg(1), "01");
        assert_eq!(encode_u64_calldata_arg(256), "0100");
        assert_eq!(encode_u64_calldata_arg(0xff), "ff");
        assert_eq!(encode_u64_calldata_arg(u64::MAX), "ffffffffffffffff");
    }

    #[test]
    fn biguint_calldata_arg_encodes_and_rejects() {
        assert_eq!(encode_biguint_calldata_arg("0").unwrap(), "");
        assert_eq!(encode_biguint_calldata_arg("500").unwrap(), "01f4");
        // Exceeds u64::MAX — proves this doesn't route through a
        // fixed-width integer type anywhere.
        assert_eq!(
            encode_biguint_calldata_arg("18446744073709551616").unwrap(),
            "010000000000000000"
        );
        assert!(encode_biguint_calldata_arg("-1").is_err());
        assert!(encode_biguint_calldata_arg("not a number").is_err());
    }

    #[test]
    fn proposal_status_labels() {
        // executed always wins, regardless of tally.
        assert_eq!(proposal_status(true, 1000, 2000, false, false), "executed");
        // still open: quorum/supermajority irrelevant.
        assert_eq!(proposal_status(false, 2000, 1000, true, true), "open");
        // voting ended (now >= expires_at) — quorum+supermajority both met -> closed (awaiting execute).
        assert_eq!(proposal_status(false, 1000, 2000, true, true), "closed");
        // boundary: now == expires_at is already "ended".
        assert_eq!(proposal_status(false, 1000, 1000, true, true), "closed");
        // voting ended, quorum not met -> failed.
        assert_eq!(proposal_status(false, 1000, 2000, false, true), "failed");
        // voting ended, quorum met but supermajority not -> failed.
        assert_eq!(proposal_status(false, 1000, 2000, true, false), "failed");
        // voting ended, neither met -> failed.
        assert_eq!(proposal_status(false, 1000, 2000, false, false), "failed");
    }

    #[test]
    fn node_voting_period_bounds_match_sc_not_user_track() {
        // Regression test: an earlier version of this handler validated
        // against the USER track's bounds (86400..=604800, 1-7 days) by
        // mistake instead of the NODE track's (604800..=2592000, 7-30
        // days) — the two tracks have deliberately different limits.
        assert!(!node_voting_period_in_range(604799)); // just under 7 days
        assert!(node_voting_period_in_range(604800)); // exactly 7 days (min)
        assert!(node_voting_period_in_range(2592000)); // exactly 30 days (max)
        assert!(!node_voting_period_in_range(2592001)); // just over 30 days
        // Values valid on the USER track but NOT the node track must be
        // rejected here — this is exactly the bug that shipped.
        assert!(!node_voting_period_in_range(86400)); // 1 day — user-track min
        assert!(!node_voting_period_in_range(172800)); // 2 days
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

// ─── Governance (governance-dashboard-plan.md Phase 6) ──────────────
//
// Two tracks: the existing user-gated one (read-only from this
// dashboard — see the plan's design rationale) and the new node-gated
// one (full read+write). Node-track writes are signed SERVER-SIDE by
// the anchoring task's own wallet (`state.governance_submit`) — there
// is no "return calldata for the browser to sign" step here, unlike
// the `node_metadata`/`node_pause`/`node_resume` handlers above. This
// is a deliberate departure: the operator never connects a browser
// wallet for governance, they just click a button on an authenticated
// dashboard session.

/// Current unix time. Used to compute each proposal's `status` label
/// (open/closed/executed) client-side per the plan's design note —
/// the SC's list views intentionally don't do this filtering.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `open` = not executed, voting still open. `closed` = not executed,
/// voting ended, AND the tally would pass (quorum + supermajority met)
/// — awaiting someone to click Execute. `failed` = not executed, voting
/// ended, and the tally would NOT pass — will never be executable, the
/// SC's own `require!`s in `executeNodeProposal`/`executeProposal`
/// would reject it. `executed` = the SC applied the proposal. Quorum/
/// supermajority are only meaningful once voting has actually ended —
/// checking them earlier would misreport an `open` proposal that just
/// hasn't finished accumulating votes yet as `failed`.
fn proposal_status(
    executed: bool,
    expires_at: u64,
    now: u64,
    quorum_met: bool,
    supermajority_met: bool,
) -> &'static str {
    if executed {
        "executed"
    } else if now < expires_at {
        "open"
    } else if quorum_met && supermajority_met {
        "closed"
    } else {
        "failed"
    }
}

/// Render one [`crate::chain::sc_views::ProposalSummary`] as the JSON
/// shape both the list and single-item endpoints share — single
/// source of truth so the two response shapes can't drift apart.
fn proposal_summary_json(p: &crate::chain::sc_views::ProposalSummary, now: u64) -> serde_json::Value {
    serde_json::json!({
        "id": p.id,
        "proposer": p.proposer,
        "description": p.description,
        "param_key": p.param_key,
        "param_value": p.param_value,
        "created_at": p.created_at,
        "expires_at": p.expires_at,
        "executed": p.executed,
        "vote_count": p.vote_count,
        "oppose_count": p.oppose_count,
        "quorum": p.quorum,
        "quorum_met": p.quorum_met,
        "supermajority_met": p.supermajority_met,
        "status": proposal_status(p.executed, p.expires_at, now, p.quorum_met, p.supermajority_met),
    })
}

#[derive(Deserialize)]
pub struct GovernanceListQuery {
    #[serde(default)]
    pub offset: Option<u32>,
    #[serde(default)]
    pub limit: Option<u32>,
    /// `open` | `closed` | `failed` | `executed` | `all` (default
    /// `all`) — see [`proposal_status`] for exactly what distinguishes
    /// `closed` (voting ended, tally would pass, awaiting execute) from
    /// `failed` (voting ended, tally would NOT pass, never executable).
    /// Filtered
    /// AFTER fetching the requested page from the SC — per the plan's
    /// design note, the SC's list views intentionally don't do this
    /// filtering, so a filtered response page can be shorter than
    /// `limit` even when more matching rows exist beyond this page.
    /// Acceptable for this low-traffic admin surface.
    #[serde(default)]
    pub status: Option<String>,
}

/// Shared list+decode+filter path for `GET .../user/proposals` and
/// `GET .../node/proposals` — `node_track` is the only thing that
/// differs between the two callers (same DRY reasoning as Phase 5's
/// `sc_views` generic helpers).
async fn governance_list_response(
    state: &AppState,
    node_track: bool,
    offset: u32,
    limit: u32,
    status_filter: Option<String>,
) -> axum::response::Response {
    let http = &state.klever_view_http;
    let url = &state.klever_node_url;
    let addr = &state.contract_address;

    let (count_result, list_result) = if node_track {
        tokio::join!(
            crate::chain::sc_views::get_node_proposal_count(http, url, addr),
            crate::chain::sc_views::list_node_proposals(http, url, addr, offset, limit),
        )
    } else {
        tokio::join!(
            crate::chain::sc_views::get_proposal_count(http, url, addr),
            crate::chain::sc_views::list_proposals(http, url, addr, offset, limit),
        )
    };

    let rows = match list_result {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, node_track, "governance list-proposals view call failed");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "failed to query governance proposals" })),
            )
                .into_response();
        }
    };
    // Total count is a courtesy for pagination UI — if the count view
    // fails independently of the list view (unlikely, same RPC), fall
    // back to the page length rather than failing the whole request.
    let total = count_result.unwrap_or(rows.len() as u64);

    let now = now_unix();
    let proposals: Vec<serde_json::Value> = rows
        .iter()
        .map(|p| proposal_summary_json(p, now))
        .filter(|v| match status_filter.as_deref() {
            None | Some("all") | Some("") => true,
            Some(want) => v["status"] == want,
        })
        .collect();

    Json(serde_json::json!({ "proposals": proposals, "total": total })).into_response()
}

/// GET /admin/governance/user/proposals?offset=&limit=&status=
pub async fn governance_user_proposals(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<GovernanceListQuery>,
) -> impl IntoResponse {
    governance_list_response(
        &state,
        false,
        params.offset.unwrap_or(0),
        params.limit.unwrap_or(20).clamp(1, 20),
        params.status,
    )
    .await
}

/// GET /admin/governance/node/proposals?offset=&limit=&status=
pub async fn governance_node_proposals(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<GovernanceListQuery>,
) -> impl IntoResponse {
    governance_list_response(
        &state,
        true,
        params.offset.unwrap_or(0),
        params.limit.unwrap_or(20).clamp(1, 20),
        params.status,
    )
    .await
}

/// Shared single-item fetch — reuses the paginated list view with
/// `offset = id - 1, limit = 1` rather than adding a new `sc_views`
/// function: the SC's `listProposals`/`listNodeProposals` index
/// sequentially by ID (`for id in offset+1..=offset+limit`), so this
/// deterministically returns exactly the row for `id` (or empty if it
/// doesn't exist) — a low-traffic admin surface, not worth a dedicated
/// single-proposal view.
async fn governance_by_id_response(state: &AppState, node_track: bool, id: u64) -> axum::response::Response {
    if id == 0 || id > u32::MAX as u64 {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "proposal not found" })),
        )
            .into_response();
    }
    let offset = (id - 1) as u32;
    let http = &state.klever_view_http;
    let url = &state.klever_node_url;
    let addr = &state.contract_address;

    let rows_result = if node_track {
        crate::chain::sc_views::list_node_proposals(http, url, addr, offset, 1).await
    } else {
        crate::chain::sc_views::list_proposals(http, url, addr, offset, 1).await
    };
    let rows = match rows_result {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, node_track, id, "governance proposal-by-id view call failed");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": "failed to query proposal" })),
            )
                .into_response();
        }
    };
    let Some(p) = rows.first() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "proposal not found" })),
        )
            .into_response();
    };
    Json(proposal_summary_json(p, now_unix())).into_response()
}

/// GET /admin/governance/user/proposals/{id}
pub async fn governance_user_proposal_by_id(
    Extension(state): Extension<Arc<AppState>>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    governance_by_id_response(&state, false, id).await
}

/// GET /admin/governance/node/proposals/{id}
pub async fn governance_node_proposal_by_id(
    Extension(state): Extension<Arc<AppState>>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    governance_by_id_response(&state, true, id).await
}

#[derive(Deserialize, Default)]
pub struct WalletStatusQuery {
    /// Comma-separated proposal IDs to report this wallet's vote on,
    /// e.g. `1,2,3`. Empty/absent ⇒ `votes: {}`.
    #[serde(default)]
    pub proposal_ids: String,
}

/// GET /admin/governance/node/wallet-status?proposal_ids=1,2,3
///
/// The only wallet that matters here is the node's OWN
/// `state.anchor_wallet_address` — there is no `?address=` param,
/// unlike the superseded draft's design, because server-side signing
/// (decision 1) means no other wallet could ever act on this
/// dashboard's behalf.
pub async fn governance_node_wallet_status(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<WalletStatusQuery>,
) -> impl IntoResponse {
    let Some(wallet) = state.anchor_wallet_address.clone() else {
        return Json(serde_json::json!({
            "wallet_address": null,
            "is_registered_node": null,
            "is_active": null,
            "votes": {},
            "error": "anchoring not enabled — no signing wallet available for governance actions",
        }))
        .into_response();
    };
    let http = &state.klever_view_http;
    let url = &state.klever_node_url;
    let addr = &state.contract_address;

    // Reuses the SAME is_node_registered/is_node_paused wrappers
    // already used for the anchoring-registration/pause-status
    // handlers above — "is this wallet a registered, active node" is
    // one concept, not a governance-specific reimplementation. `Err`
    // (transport failure) degrades to "not active" rather than
    // failing the whole response — the dashboard shows a disabled
    // vote button with the RPC error still surfaced via the fields
    // above being present-but-false, matching this file's existing
    // "null/false on RPC failure, never a falsely-confident answer to
    // the wrong side" convention used elsewhere (e.g. `node_metadata`).
    let is_registered = crate::chain::sc_views::is_node_registered(http, url, addr, &wallet)
        .await
        .unwrap_or(false);
    let is_paused = crate::chain::sc_views::is_node_paused(http, url, addr, &wallet)
        .await
        .unwrap_or(false);
    let is_active = is_registered && !is_paused;

    // Defensive cap mirrors this file's other bounded-input-list
    // conventions (e.g. `get_node_metadata`'s MAX_RETURNED_ENTRIES) —
    // an operator's dashboard only ever asks about one visible page
    // of proposals at a time, so 64 is generous headroom, not a real
    // limit in practice.
    const MAX_WALLET_STATUS_IDS: usize = 64;
    let ids: Vec<u64> = params
        .proposal_ids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<u64>().ok())
        .take(MAX_WALLET_STATUS_IDS)
        .collect();

    // Fan out concurrently — sequential awaits here would let up to
    // MAX_WALLET_STATUS_IDS (64) RPC round-trips serialize behind one
    // another (worst case, at this file's per-call transport timeout,
    // minutes for one dashboard request).
    let vote_results = futures::future::join_all(ids.iter().map(|&id| {
        crate::chain::sc_views::get_node_vote(http, url, addr, id, &wallet)
    }))
    .await;
    let mut votes = serde_json::Map::with_capacity(ids.len());
    for (id, result) in ids.iter().zip(vote_results) {
        votes.insert(id.to_string(), serde_json::Value::from(result.unwrap_or(0)));
    }

    Json(serde_json::json!({
        "wallet_address": wallet,
        "is_registered_node": is_registered,
        "is_active": is_active,
        "votes": votes,
    }))
    .into_response()
}

/// TX-calldata encoding for a `bool` argument. **Different rule from
/// any view-call bool encoding** (see the module doc + the plan's
/// "argument encoding" section): klever-sc-codec top-encodes `true` as
/// a single `0x01` byte and `false` as EMPTY bytes (verified directly
/// against `klever-sc-codec` 0.19.0 source,
/// `impl_for_types/impl_bool.rs`) — the SAME landmine class as the
/// SC's `VOTE_OPPOSE` u8 marker (a stored `bool false` top-encodes to
/// empty, which is exactly why votes are stored as u8 there, not
/// bool). **DO NOT "fix" `false` to `"00"`** — that is wrong and will
/// desync from what the SC actually decodes, silently breaking "vote
/// against."
fn encode_bool_calldata_arg(support: bool) -> &'static str {
    if support {
        "01"
    } else {
        ""
    }
}

/// TX-calldata encoding for a `u64` argument: minimal big-endian
/// bytes, `0` → EMPTY string. **A DIFFERENT rule from
/// `sc_views.rs`'s `encode_u64_minimal_hex`**, which encodes `0` as
/// `"00"` for VIEW-call arguments specifically (`/vm/query`/`/vm/hex`)
/// — a different RPC context from TX calldata (`/transaction/send`'s
/// `Data` field, `@`-separated). Do not merge these two encoders.
fn encode_u64_calldata_arg(v: u64) -> String {
    if v == 0 {
        return String::new();
    }
    let trimmed = format!("{:016x}", v).trim_start_matches('0').to_string();
    if trimmed.len() % 2 != 0 {
        format!("0{trimmed}")
    } else {
        trimmed
    }
}

/// TX-calldata encoding for a `BigUint` argument, given as a decimal
/// string (arbitrary precision — a governance fee value can exceed
/// u64). Parses via the SAME `sc_views::decimal_string_to_bytes_be`
/// conversion used for the reverse (view-decode) direction in Phase 5
/// — one tested BigUint⇄bytes conversion in this codebase, not two.
/// `"0"` correctly round-trips to an empty hex string (minimal-BE
/// encoding of zero), matching the TX-calldata zero rule.
fn encode_biguint_calldata_arg(decimal: &str) -> Result<String, String> {
    crate::chain::sc_views::decimal_string_to_bytes_be(decimal)
        .map(hex::encode)
        .map_err(|e| format!("invalid param_value: {e}"))
}

/// Shared submit path for all 3 node-track write endpoints. Mirrors
/// `trigger_anchor`'s channel-send/reply-await shape, but ADDS an
/// explicit timeout — `trigger_anchor`'s own await has none (an
/// accepted, pre-existing risk on that endpoint, not retroactively
/// fixed here), but these are user-facing form submissions where an
/// indefinite hang is a materially worse UX than a clear timeout
/// error, so the two endpoints are allowed to diverge on this point
/// deliberately.
/// Sign and broadcast an arbitrary SC call from this node's ANCHOR wallet.
///
/// Named `submit_governance_call` until v0.126.0; renamed because
/// `claimNodeEarnings` is not a governance action. The duplicate-broadcast
/// guard below is keyed on the exact `call_data`, which matters more for
/// no-argument calls — see `node_claim_earnings`.
async fn submit_signed_call(state: &AppState, call_data: String) -> Result<String, (StatusCode, String)> {
    let Some(tx) = &state.governance_submit else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "anchoring not enabled — governance actions require a signing wallet".into(),
        ));
    };
    // Duplicate-broadcast guard (audit follow-up): an entry present
    // for this EXACT call_data means an identical submission was
    // already successfully enqueued within the last 60s — reject the
    // retry rather than risk broadcasting the same TX intent twice.
    // `entry().or_insert()` is atomic, so two concurrent identical
    // requests can't both observe "not present" and both proceed.
    let entry = state
        .governance_inflight
        .entry(call_data.clone())
        .or_insert(())
        .await;
    if !entry.is_fresh() {
        return Err((
            StatusCode::CONFLICT,
            "an identical governance submission was already sent — wait before retrying".into(),
        ));
    }
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    // Single shared deadline covering BOTH the enqueue and the reply
    // wait — the channel is bounded (capacity 4, see node.rs) and each
    // queued request can itself take tens of seconds, so a `send()`
    // that only starts timing out AFTER it completes would let queued-
    // up concurrent callers block well past the 30s budget this
    // function advertises.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    match tokio::time::timeout_at(
        deadline,
        tx.send(crate::chain::anchoring::GovernanceSubmitRequest {
            call_data: call_data.clone(),
            reply: reply_tx,
        }),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            // Enqueue itself failed — this was never actually queued,
            // so release the guard rather than block a legitimate
            // immediate retry for 60s.
            state.governance_inflight.invalidate(&call_data).await;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "anchoring task not running".into(),
            ));
        }
        Err(_) => {
            state.governance_inflight.invalidate(&call_data).await;
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                "timed out waiting to queue governance submission (anchoring task busy)".into(),
            ));
        }
    }
    // From here on the submission WAS successfully enqueued — the
    // guard stays in place (TTL-bounded) even on a reply timeout,
    // since the anchoring task may still broadcast it.
    match tokio::time::timeout_at(deadline, reply_rx).await {
        Ok(Ok(Ok(tx_hash))) => Ok(tx_hash),
        Ok(Ok(Err(e))) => Err((StatusCode::BAD_GATEWAY, e)),
        Ok(Err(_)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "anchoring task dropped reply".into(),
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            "timed out waiting for anchoring task to sign+broadcast".into(),
        )),
    }
}

/// v1 node-track votable-param set. **KEEP IN SYNC** with
/// `smart-contract/src/node_governance.rs`'s `valid_keys` — the SC is
/// the actual enforcement point (a mismatch here just means an
/// operator sees a late `require!` failure instead of an early 400),
/// but a stale list here is still a real UX bug worth avoiding.
/// Mirrors the contract's node-track `valid_keys` in
/// `smart-contract/src/node_governance.rs`. **These two lists must be updated
/// together** — nothing in either repo's build or audit pipeline catches the
/// drift, and a stale list here rejects a valid proposal with a 400 before it
/// ever reaches the chain. Asserted by `node_governance_param_keys_match_sc`
/// below.
const NODE_GOVERNANCE_VALID_PARAM_KEYS: &[&str] = &[
    "node_registration_fee",
    // Added in SC 0.10.0: user registration economics moved to the node track.
    "registration_fee",
    "node_fee_share_bps",
];

/// Upper bounds mirroring the contract's hard caps
/// (`registry::MAX_REGISTRATION_FEE`, `registry::MAX_NODE_FEE_SHARE_BPS`).
/// Checked here purely so the operator gets an immediate, readable 400 rather
/// than a `require!` failure after signing and broadcasting — the CONTRACT is
/// the authority, and it re-checks at both proposal creation and execution.
const MAX_REGISTRATION_FEE_RAW: u128 = 10_000_000_000;
const MAX_NODE_FEE_SHARE_BPS: u128 = 8_000;

/// Mirrors `smart-contract::node_governance::MIN_VOTING_PERIOD_SECONDS`
/// / `MAX_VOTING_PERIOD_SECONDS` (604800..=2592000, 7-30 days). Kept in
/// sync manually like `NODE_GOVERNANCE_VALID_PARAM_KEYS` above — the SC
/// is the real enforcement point, this just gives an operator an early
/// 400 instead of a late `require!` failure. **Do not copy the user
/// track's bounds here** (86400..=604800, 1-7 days, see
/// `governance.rs`) — an earlier version of this handler did exactly
/// that by mistake, which would have silently accepted periods the SC
/// rejects and rejected periods the SC allows.
fn node_voting_period_in_range(secs: u64) -> bool {
    const MIN: u64 = 604800;
    const MAX: u64 = 2592000;
    (MIN..=MAX).contains(&secs)
}

#[derive(Deserialize)]
pub struct CreateNodeProposalRequest {
    pub description: String,
    pub param_key: String,
    /// Decimal string — arbitrary precision, never parsed to a fixed
    /// integer type before hitting `encode_biguint_calldata_arg`.
    pub param_value: String,
    pub voting_period_seconds: u64,
}

/// Advisory bounds check mirroring the contract's caps for the node-track
/// parameters that have them. Returns `Some(message)` when the value is out
/// of range and `None` when it is acceptable.
///
/// `node_registration_fee` is deliberately absent: it is uncapped on chain.
///
/// A value that does not parse as `u128` is treated as OUT OF BOUNDS for any
/// capped key, not waved through. `decimal_string_to_bytes_be` is
/// arbitrary-precision and happily encodes a 60-digit decimal, so "let the
/// calldata encoder reject it" is false for exactly the values this check
/// exists to catch — they would be signed and broadcast at real gas cost only
/// to hit the contract's `require!`. Non-numeric input still falls through to
/// the encoder, which reports it better than a bounds message would.
fn node_param_value_out_of_bounds(key: &str, value: &str) -> Option<String> {
    let trimmed = value.trim();
    let has_cap = matches!(key, "registration_fee" | "node_fee_share_bps");
    let parsed: u128 = match trimmed.parse() {
        Ok(v) => v,
        // All-digits but too large for u128 — far beyond any cap.
        Err(_) if has_cap && !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_digit()) => {
            return Some(format!("{} value is far above the contract maximum", key));
        }
        Err(_) => return None,
    };
    match key {
        "registration_fee" if parsed > MAX_REGISTRATION_FEE_RAW => Some(format!(
            "registration_fee exceeds the contract maximum of {} raw KLV ({} KLV)",
            MAX_REGISTRATION_FEE_RAW,
            crate::util::format_klv_amount(MAX_REGISTRATION_FEE_RAW)
        )),
        "node_fee_share_bps" if parsed > MAX_NODE_FEE_SHARE_BPS => Some(format!(
            "node_fee_share_bps exceeds the contract maximum of {} ({}%)",
            MAX_NODE_FEE_SHARE_BPS,
            MAX_NODE_FEE_SHARE_BPS / 100
        )),
        _ => None,
    }
}

#[cfg(test)]
mod node_governance_param_tests {
    use super::*;

    /// Pins this crate's allowlist against the CONTRACT's node-track
    /// `valid_keys`. Cross-repo drift is invisible to both repos' build and
    /// audit pipelines, and a stale list here silently rejects valid
    /// proposals — so assert the expected set explicitly. If the contract
    /// gains a votable key, this test must be updated in the same change.
    #[test]
    fn node_governance_param_keys_match_sc() {
        assert_eq!(
            NODE_GOVERNANCE_VALID_PARAM_KEYS,
            &[
                "node_registration_fee",
                "registration_fee",
                "node_fee_share_bps"
            ],
            "allowlist drifted from smart-contract/src/node_governance.rs valid_keys"
        );
    }

    #[test]
    fn bounds_check_matches_contract_caps() {
        // At the cap is fine; one over is not.
        assert!(node_param_value_out_of_bounds("registration_fee", "10000000000").is_none());
        assert!(node_param_value_out_of_bounds("registration_fee", "10000000001").is_some());
        assert!(node_param_value_out_of_bounds("node_fee_share_bps", "8000").is_none());
        assert!(node_param_value_out_of_bounds("node_fee_share_bps", "8001").is_some());
        // Uncapped on chain — must not be rejected here.
        assert!(
            node_param_value_out_of_bounds("node_registration_fee", "999999999999").is_none()
        );
        // Non-numeric falls through to the calldata encoder's own error.
        assert!(node_param_value_out_of_bounds("registration_fee", "abc").is_none());
        // All-digits but beyond u128 must be REJECTED, not waved through:
        // `decimal_string_to_bytes_be` is arbitrary-precision and would
        // happily encode this, so it would otherwise be signed and broadcast
        // at real gas cost only to hit the contract's `require!`.
        let huge = "9".repeat(60);
        assert!(node_param_value_out_of_bounds("registration_fee", &huge).is_some());
        assert!(node_param_value_out_of_bounds("node_fee_share_bps", &huge).is_some());
        // But an uncapped key still passes — the contract has no bound there.
        assert!(node_param_value_out_of_bounds("node_registration_fee", &huge).is_none());
    }

    /// The anchoring-disabled branch must report `null` balances, not `0`.
    /// "not applicable" and "earned nothing" render identically otherwise,
    /// and a concrete 0 beside "anchoring is not enabled" is actively wrong.
    #[test]
    fn earnings_disabled_branch_reports_null_not_zero() {
        let p = earnings_disabled_payload();
        assert!(p["unclaimed_raw"].is_null(), "unclaimed_raw must be null");
        assert!(p["unclaimed_klv"].is_null(), "unclaimed_klv must be null");
        assert!(p["wallet"].is_null());
        assert_eq!(p["claimable"], serde_json::json!(false));
        // The reason must be present and non-empty, so a disabled Claim
        // button is never unexplained in the dashboard.
        assert!(p["reason"].as_str().is_some_and(|r| !r.is_empty()));
        // Explicitly NOT the numeric zero these fields could plausibly carry.
        assert_ne!(p["unclaimed_raw"], serde_json::json!("0"));
        assert_ne!(p["unclaimed_klv"], serde_json::json!("0"));
    }
}

/// The `node_earnings` response for a node with anchoring disabled.
///
/// Extracted so the null-vs-zero contract can be asserted directly rather than
/// by scraping source text: balances here are `null`, NOT `0`. The truthful
/// answer is "not applicable" — this node has no wallet that could ever earn —
/// and a concrete `0` sitting next to "anchoring is not enabled" reads as
/// "you have earned nothing", which is a different and misleading claim. The
/// dashboard renders `null` as "--".
fn earnings_disabled_payload() -> serde_json::Value {
    serde_json::json!({
        "wallet": serde_json::Value::Null,
        "claimable": false,
        "reason": "anchoring is not enabled — this node has no signing wallet to earn or claim with",
        "unclaimed_raw": serde_json::Value::Null,
        "unclaimed_klv": serde_json::Value::Null,
    })
}

/// GET /admin/node/earnings
///
/// This operator's unclaimed share of user registration fees (SC 0.10.0),
/// plus the network-wide total for context.
///
/// Returns HTTP 200 with `claimable: false` and a `reason` when anchoring is
/// disabled, rather than an error status: the dashboard should EXPLAIN the
/// state, not render a failure. Mirrors `node_pause_status`, which reports a
/// null status the same way.
pub async fn node_earnings(Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    let klever_node_url = state.klever_node_url.clone();
    let contract_address = state.contract_address.clone();
    // The ANCHOR wallet is what signs `registerNode`, so it is the address the
    // contract credits — NOT `node_address`.
    let wallet = state.anchor_wallet_address.clone().unwrap_or_default();

    if klever_node_url.is_empty() || contract_address.is_empty() || wallet.is_empty() {
        return Json(earnings_disabled_payload()).into_response();
    }

    let http = &state.klever_view_http;
    let (mine_res, total_res) = tokio::join!(
        crate::chain::sc_views::get_node_earnings(http, &klever_node_url, &contract_address, &wallet),
        crate::chain::sc_views::get_total_unclaimed_node_earnings(http, &klever_node_url, &contract_address),
    );

    // On an RPC error report null rather than 0 — "we could not read it" and
    // "you have earned nothing" must not look identical to the operator.
    let (unclaimed, claimable, reason) = match mine_res {
        Ok(v) if v > 0 => (Some(v), true, serde_json::Value::Null),
        Ok(v) => (
            Some(v),
            false,
            serde_json::Value::from("nothing to claim yet"),
        ),
        Err(e) => (
            None,
            false,
            serde_json::Value::from(format!("could not read earnings from the contract: {}", e)),
        ),
    };

    Json(serde_json::json!({
        "wallet": wallet,
        "klever_network": state.klever_network,
        "contract_address": contract_address,
        "claimable": claimable,
        "reason": reason,
        "unclaimed_raw": unclaimed.map(|v| v.to_string()),
        "unclaimed_klv": unclaimed.map(format_klv),
        "network_unclaimed_raw": total_res.as_ref().ok().map(|v| v.to_string()),
        "network_unclaimed_klv": total_res.as_ref().ok().map(|v| format_klv(*v)),
    }))
    .into_response()
}

/// POST /admin/node/claim-earnings
///
/// Claims this operator's accrued registration-fee share. Takes no body —
/// `claimNodeEarnings` takes no SC arguments and pays only its caller, so
/// there is nothing to parameterise and nothing to authorise beyond holding
/// the anchor wallet key.
///
/// **One claim per 60 seconds.** `submit_signed_call`'s duplicate-broadcast
/// guard is keyed on the exact `call_data`. Every other signed call varies by
/// argument (`proposal_id`, vote direction), so the guard only ever catches
/// genuine double-submits — but `claimNodeEarnings` has NO arguments, so its
/// calldata is a constant for the life of the node and the guard therefore
/// rate-limits legitimate repeat claims too. That is acceptable (a second
/// claim inside the window would hit "No earnings to claim" anyway), but it
/// is surfaced with a specific message below rather than the generic
/// governance wording, so nobody debugs it as a mystery 409.
pub async fn node_claim_earnings(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    // Check the balance BEFORE broadcasting. `claimNodeEarnings` reverts with
    // "No earnings to claim" on a zero balance, and a reverted TX still costs
    // the anchor wallet its fee — the same wallet that funds anchoring. The
    // dashboard disables the button, but that is client-side only, so anything
    // that reaches this endpoint (a stale tab, a script, a CSRF-triggered POST
    // from a page the operator has open on the node host) could otherwise burn
    // fee on a guaranteed-revert call. `getNodeEarnings` is a free view.
    let wallet = state.anchor_wallet_address.clone().unwrap_or_default();
    if !wallet.is_empty()
        && !state.klever_node_url.is_empty()
        && !state.contract_address.is_empty()
    {
        if let Ok(0) = crate::chain::sc_views::get_node_earnings(
            &state.klever_view_http,
            &state.klever_node_url,
            &state.contract_address,
            &wallet,
        )
        .await
        {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "nothing to claim — no earnings have accrued to this node yet",
                })),
            )
                .into_response();
        }
        // An RPC error here is deliberately NOT fatal: the contract is the
        // authority on the balance, and refusing to claim because a view call
        // failed would be worse than letting the operator try.
    }

    match submit_signed_call(&state, "claimNodeEarnings".to_string()).await {
        Ok(tx_hash) => Json(serde_json::json!({ "ok": true, "tx_hash": tx_hash })).into_response(),
        Err((StatusCode::CONFLICT, _)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "a claim was just submitted — wait a minute before retrying",
            })),
        )
            .into_response(),
        // `submit_signed_call`'s message is worded for governance actions;
        // an operator clicking Claim should not be told about proposals.
        Err((StatusCode::SERVICE_UNAVAILABLE, _)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "error": "anchoring is not enabled — this node has no signing wallet to claim with",
            })),
        )
            .into_response(),
        Err((status, err)) => (
            status,
            Json(serde_json::json!({ "ok": false, "error": err })),
        )
            .into_response(),
    }
}

/// POST /admin/governance/node/create-proposal
pub async fn governance_node_create_proposal(
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<CreateNodeProposalRequest>,
) -> impl IntoResponse {
    if body.description.len() > 512 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "description too long (max 512 bytes)" })),
        )
            .into_response();
    }
    if !NODE_GOVERNANCE_VALID_PARAM_KEYS.contains(&body.param_key.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unsupported parameter key" })),
        )
            .into_response();
    }
    // Early bounds check so an out-of-range value fails HERE with a readable
    // message, instead of after the operator has signed and broadcast and the
    // contract's `require!` rejects it. Advisory only — the contract enforces
    // the real caps at both creation and execution.
    if let Some(err) = node_param_value_out_of_bounds(&body.param_key, &body.param_value) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": err })),
        )
            .into_response();
    }
    // `encode_biguint_calldata_arg` → `decimal_string_to_bytes_be` is
    // O(n^2) in digit count (repeated-division algorithm). 100 digits
    // is already far beyond any realistic KLV-denominated governance
    // parameter — this bounds worst-case cost to a few microseconds
    // while leaving no legitimate value unreachable.
    if body.param_value.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "param_value too long (max 100 digits)" })),
        )
            .into_response();
    }
    // Node track's bounds (604800..=2592000, 7-30 days) are WIDER than
    // the user track's (86400..=604800, 1-7 days, see governance.rs) —
    // this is `create_node_proposal`, so it must validate against
    // `node_governance::MIN/MAX_VOTING_PERIOD_SECONDS`, not the user
    // track's. Mismatching these lets a client submit a period this
    // handler accepts but `smart-contract`'s SC rejects (any value in
    // 86400..604800), OR conversely reject periods the SC would have
    // allowed (604800..2592000) with a wrong client-facing message.
    if !node_voting_period_in_range(body.voting_period_seconds) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "voting_period_seconds must be between 604800 (7 days) and 2592000 (30 days)"
            })),
        )
            .into_response();
    }
    let param_value_hex = match encode_biguint_calldata_arg(&body.param_value) {
        Ok(h) => h,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e }))).into_response()
        }
    };
    let call_data = format!(
        "createNodeProposal@{}@{}@{}@{}",
        hex::encode(body.description.as_bytes()),
        hex::encode(body.param_key.as_bytes()),
        param_value_hex,
        encode_u64_calldata_arg(body.voting_period_seconds),
    );
    match submit_signed_call(&state, call_data).await {
        Ok(tx_hash) => Json(serde_json::json!({ "ok": true, "tx_hash": tx_hash })).into_response(),
        Err((status, err)) => (status, Json(serde_json::json!({ "ok": false, "error": err }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct NodeVoteRequest {
    pub proposal_id: u64,
    pub support: bool,
}

/// POST /admin/governance/node/vote
///
/// `proposal_id` existence is NOT re-checked locally — the SC's own
/// `require!` already covers it, and the TX cost of a doomed vote is
/// the operator's own click, not a security issue (mirrors the plan's
/// explicit reasoning for skipping this pre-check).
pub async fn governance_node_vote(
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<NodeVoteRequest>,
) -> impl IntoResponse {
    if body.proposal_id == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "proposal_id must be > 0" })),
        )
            .into_response();
    }
    let call_data = format!(
        "nodeVote@{}@{}",
        encode_u64_calldata_arg(body.proposal_id),
        encode_bool_calldata_arg(body.support),
    );
    match submit_signed_call(&state, call_data).await {
        Ok(tx_hash) => Json(serde_json::json!({ "ok": true, "tx_hash": tx_hash })).into_response(),
        Err((status, err)) => (status, Json(serde_json::json!({ "ok": false, "error": err }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct ExecuteNodeProposalRequest {
    pub proposal_id: u64,
}

/// POST /admin/governance/node/execute-proposal
///
/// No client-side "did this proposal really pass" pre-check — the SC
/// enforces quorum/supermajority/expiry and will just revert if not
/// met. The dashboard (Phase 7) disables the Execute button client-side
/// using the already-fetched tally as a UX nicety; this handler mainly
/// exists to be hit when that button IS enabled.
pub async fn governance_node_execute_proposal(
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<ExecuteNodeProposalRequest>,
) -> impl IntoResponse {
    if body.proposal_id == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "proposal_id must be > 0" })),
        )
            .into_response();
    }
    let call_data = format!(
        "executeNodeProposal@{}",
        encode_u64_calldata_arg(body.proposal_id)
    );
    match submit_signed_call(&state, call_data).await {
        Ok(tx_hash) => Json(serde_json::json!({ "ok": true, "tx_hash": tx_hash })).into_response(),
        Err((status, err)) => (status, Json(serde_json::json!({ "ok": false, "error": err }))).into_response(),
    }
}

/// Query for [`debug_e2e`].
#[derive(Deserialize)]
pub struct E2eDebugParams {
    /// Wallet (or device) address whose enc-key directory to dump.
    pub wallet: String,
    /// Optional conversation_id (64-hex) for its key envelopes + DM messages.
    #[serde(default)]
    pub scope: Option<String>,
    /// Optional DM peer — if given (and `scope` is not), the scope is computed as
    /// `compute_conversation_id(wallet, peer)` so callers needn't hash.
    #[serde(default)]
    pub peer: Option<String>,
}

/// GET /admin/debug/e2e?wallet=<addr>&peer=<addr> — loopback-only E2E key +
/// DM-storage dump, for diagnosing "can't decrypt" / vanishing DMs.
///
/// Returns, for `wallet`: `enc_keys` (its device enc-key directory — **two
/// entries sharing a `device_id` is the wrap-collision signature**: a sender
/// wraps to both, the `channel_keys` envelopes collide on
/// `(scope,target,author,device_id,epoch)` first-write-wins, and the stale one
/// can win so the recipient's current device can't unwrap → "can't decrypt").
/// With a scope: `channel_keys` (decoded `target/author/device_id/epoch`) and
/// `dm_messages` (the conversation's stored messages; `has_envelope=false` means
/// indexed-but-body-missing, i.e. it vanishes from history on reload).
///
/// Loopback-only (same guard as the other `/admin` routes). Public key material
/// + ciphertext metadata only — no private keys, no plaintext.
pub async fn debug_e2e(
    Extension(state): Extension<Arc<AppState>>,
    Query(params): Query<E2eDebugParams>,
) -> impl IntoResponse {
    use crate::storage::schema::cf;

    let wallet = state
        .identity
        .resolve(&params.wallet)
        .unwrap_or_else(|_| params.wallet.clone());

    // Device enc-key directory for the wallet.
    let mut enc_prefix = wallet.as_bytes().to_vec();
    enc_prefix.push(0xFF);
    let enc_keys: Vec<serde_json::Value> = state
        .storage
        .prefix_iter_cf(cf::DEVICE_ENC_KEYS, &enc_prefix, 256)
        .map(|entries| {
            entries
                .into_iter()
                .filter_map(|(_, v)| serde_json::from_slice::<serde_json::Value>(&v).ok())
                .collect()
        })
        .unwrap_or_default();

    // Resolve the conversation scope: explicit `scope` hex wins; else derive from `peer`.
    let scope_bytes: Option<Vec<u8>> = match (&params.scope, &params.peer) {
        (Some(hex_s), _) => hex::decode(hex_s).ok().filter(|b| b.len() == 32),
        (None, Some(peer)) => {
            let peer_wallet = state.identity.resolve(peer).unwrap_or_else(|_| peer.clone());
            Some(crate::crypto::compute_conversation_id(&wallet, &peer_wallet).to_vec())
        }
        _ => None,
    };
    let scope_hex_resolved = scope_bytes.as_ref().map(hex::encode);

    let mut channel_keys: Vec<serde_json::Value> = Vec::new();
    let mut dm_messages: Vec<serde_json::Value> = Vec::new();

    if let Some(scope_bytes) = scope_bytes.as_ref() {
        // Wrapped-key envelopes stored for this scope.
        if let Ok(entries) = state.storage.prefix_iter_cf(cf::CHANNEL_KEYS, scope_bytes, 512) {
            // key = scope(32) ++ target ++ 0xFF ++ author ++ 0xFF ++ device_id ++ epoch_be8
            let split_ff = |b: &[u8]| -> (String, usize) {
                match b.iter().position(|x| *x == 0xFF) {
                    Some(i) => (String::from_utf8_lossy(&b[..i]).into_owned(), i + 1),
                    None => (String::from_utf8_lossy(b).into_owned(), b.len()),
                }
            };
            for (k, v) in entries {
                if k.len() <= 32 {
                    continue;
                }
                let rest = &k[32..];
                let (target, o1) = split_ff(rest);
                let (author, o2) = split_ff(&rest[o1..]);
                let tail = &rest[o1 + o2..];
                let (device_id, epoch) = if tail.len() >= 8 {
                    let mut e = [0u8; 8];
                    e.copy_from_slice(&tail[tail.len() - 8..]);
                    (
                        String::from_utf8_lossy(&tail[..tail.len() - 8]).into_owned(),
                        u64::from_be_bytes(e),
                    )
                } else {
                    (String::from_utf8_lossy(tail).into_owned(), 0)
                };
                channel_keys.push(serde_json::json!({
                    "target": target,
                    "author": author,
                    "device_id": device_id,
                    "epoch": epoch,
                    "value_len": v.len(),
                }));
            }
        }

        // Stored DM messages for this conversation.
        if let Ok(entries) = state.storage.prefix_iter_cf(cf::DM_MESSAGES, scope_bytes, 256) {
            for (k, _) in entries {
                // key = conversation_id(32) ++ timestamp_be8 ++ msg_id(32)
                if k.len() < 72 {
                    continue;
                }
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&k[32..40]);
                let mut mid = [0u8; 32];
                mid.copy_from_slice(&k[40..72]);
                // Is the body retrievable? false ⇒ indexed but missing ⇒ vanishes on reload.
                let (has_envelope, author, key_epoch) = match state.storage.get_message(&mid) {
                    Ok(Some(bytes)) => {
                        rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&bytes)
                            .ok()
                            .map(|env| {
                                let ep = rmp_serde::from_slice::<
                                    crate::messages::types::DirectMessagePayload,
                                >(&env.payload)
                                .ok()
                                .map(|p| p.key_epoch);
                                (true, Some(env.author), ep)
                            })
                            .unwrap_or((true, None, None))
                    }
                    _ => (false, None, None),
                };
                dm_messages.push(serde_json::json!({
                    "timestamp": u64::from_be_bytes(ts),
                    "msg_id": hex::encode(mid),
                    "has_envelope": has_envelope,
                    "author": author,
                    "key_epoch": key_epoch,
                }));
            }
        }
    }

    Json(serde_json::json!({
        "wallet": wallet,
        "enc_key_count": enc_keys.len(),
        "enc_keys": enc_keys,
        "scope": scope_hex_resolved,
        "channel_key_count": channel_keys.len(),
        "channel_keys": channel_keys,
        "dm_message_count": dm_messages.len(),
        "dm_messages": dm_messages,
    }))
}
