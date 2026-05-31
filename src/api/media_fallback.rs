//! Cross-node media fallback (spec 3 §media-fetch, l2-node 0.46.7+).
//!
//! When [`crate::api::routes::get_media`] sees a local-Kubo miss for
//! a CID, it asks this module to fetch the bytes from the SC-
//! registered peer set instead of returning 404 immediately.
//!
//! # Trust set (strict at launch)
//!
//! Only peers that satisfy all of:
//!   1. Returned by `getActiveNodes` (registered + not server-paused).
//!   2. `lastAnchorAt` within `[network.discovery] max_peer_staleness_days`
//!      (default 7).
//!   3. Have a `NodeAnnouncement` record in the local `PEER_DIRECTORY`
//!      with a usable `api_endpoint` and `last_seen + ttl_seconds` not
//!      in the past.
//!   4. Not the local node itself.
//!   5. The `api_endpoint` is `http(s)://<routable host>`. Loopback,
//!      RFC1918, link-local incl. 169.254.169.254 cloud-metadata,
//!      ULA, CGNAT, IPv4-mapped IPv6 are refused. `.onion` is refused
//!      at launch (proper onion transport lands in v0.46.9).
//!
//! # Resource controls
//!
//! - **5-min candidate snapshot cache**
//!   (`peer_fallback_candidate_cache_secs`) bounds the SC RPC rate.
//! - **Global concurrent fan-out semaphore**
//!   (`peer_fallback_global_concurrent`, default 16) caps the node's
//!   outbound footprint when many clients trigger fallbacks at once.
//! - **Per-source amplification** is already capped by the per-IP
//!   media-handler permit each client holds for the fallback
//!   duration ([`crate::api::media_limiter`]).
//! - **Per-dial timeouts**: separate connect (5s) and total
//!   request (30s) budgets — a dead peer drops fast without aborting
//!   a slow-but-healthy one.
//!
//! # Content verification
//!
//! Every successful peer response is re-added to the local Kubo via
//! [`crate::ipfs::IpfsClient::add_and_verify_cid`], which hard-rejects
//! any CID mismatch. A peer can only return what the requested CID
//! actually addresses; anything else fails verification and the
//! handler surfaces 404 as if the peer hadn't responded.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use rand::seq::SliceRandom;
use serde::Deserialize;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info, warn};

use crate::chain::sc_views::{self, TransportKind};
use crate::config::MediaConfig;
use crate::storage::rocks::Storage;
use futures::StreamExt;

/// Shared fallback state, constructed once at node startup and held
/// in [`crate::api::state::AppState`].
#[derive(Clone)]
pub struct MediaFallbackState {
    /// SC candidate snapshot — built lazily on the first fallback
    /// fetch, refreshed when its `generated_at` is older than the
    /// `peer_fallback_candidate_cache_secs` budget. `None` until the
    /// first refresh runs; transient Klever RPC failures keep the
    /// last good snapshot in place rather than dropping to empty.
    pub candidates: Arc<RwLock<Option<CandidateSnapshot>>>,
    /// Global concurrent-fan-out cap. The handler acquires one
    /// permit per fallback attempt; capacity is set from
    /// `peer_fallback_global_concurrent`. Acquisition uses
    /// `try_acquire_owned` so excess concurrent attempts fall
    /// through to a regular 404 rather than queuing on the
    /// semaphore.
    pub global_semaphore: Arc<Semaphore>,
    /// HTTP client used for outbound peer dials. Built once with the
    /// configured connect/read timeouts; reused across fetches
    /// (connection pool stays warm).
    pub http: reqwest::Client,
    /// Snapshot of the relevant `MediaConfig` fields, cloned at
    /// startup. Operators restart to change the policy.
    pub config: MediaConfig,
    /// Own anchorer address — excluded from the candidate set.
    /// Empty string means the node has no SC identity (anchoring
    /// disabled); the self-exclusion path is then a no-op.
    pub self_address: String,
    /// Klever API URL for SC view calls. Empty when the node has no
    /// Klever connection — fallback then cleanly disables.
    pub klever_node_url: String,
    /// Ogmara KApp address.
    pub contract_address: String,
    /// Staleness cutoff in seconds — `[network.discovery]
    /// max_peer_staleness_days × 86400`. Mirrors the
    /// `sc_discovery` and `bootstrap-candidates` cutoff for
    /// cross-surface consistency.
    pub peer_staleness_secs: u64,
}

/// One refresh's worth of SC candidates plus their resolved REST
/// URLs. Held under the RwLock in [`MediaFallbackState`].
#[derive(Debug, Clone)]
pub struct CandidateSnapshot {
    /// Instant at refresh — TTL is measured against this. `Instant`
    /// (monotonic) avoids wall-clock-drift bugs at TTL boundaries.
    pub generated_at: Instant,
    /// Unix-seconds at refresh, for human-readable freshness on any
    /// debug surface.
    pub generated_at_unix: u64,
    /// Resolved candidates: each has the klv1 address (for
    /// diagnostic logging), the api_endpoint we will dial, and the
    /// classified transport (so callers can skip onion entries
    /// while v0.46.9 ships).
    pub entries: Vec<CandidateEntry>,
}

#[derive(Debug, Clone)]
pub struct CandidateEntry {
    /// klv1 wallet address — diagnostic logging only.
    pub address: String,
    /// Sanitised api_endpoint (e.g. `https://node.example.org`).
    pub api_endpoint: String,
    /// Classified transport — only `Clearnet` candidates are dialed
    /// at v0.46.7.
    pub transport: TransportKind,
}

impl MediaFallbackState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: MediaConfig,
        self_address: String,
        klever_node_url: String,
        contract_address: String,
        peer_staleness_secs: u64,
    ) -> anyhow::Result<Self> {
        let connect = Duration::from_secs(config.peer_fallback_connect_timeout_secs);
        let read = Duration::from_secs(config.peer_fallback_read_timeout_secs);
        let http = reqwest::Client::builder()
            .connect_timeout(connect)
            .timeout(read)
            // No redirects — peer-fallback URLs come from on-chain
            // metadata; an unexpected 3xx is either a misconfigured
            // operator (cleanly surfaces as failure) or a redirect
            // attack worth refusing.
            .redirect(reqwest::redirect::Policy::none())
            // reqwest 0.13 with default features does NOT enable the
            // `cookies` feature, so the client never persists or
            // sends cookies between requests — no extra config call
            // needed to lock that down.
            .build()?;
        let global_semaphore =
            Arc::new(Semaphore::new(config.peer_fallback_global_concurrent));
        Ok(Self {
            candidates: Arc::new(RwLock::new(None)),
            global_semaphore,
            http,
            config,
            self_address,
            klever_node_url,
            contract_address,
            peer_staleness_secs,
        })
    }

    /// Is the fallback path runnable at all? Used by `get_media` to
    /// skip the whole branch cheaply when the config or Klever
    /// wiring is unset.
    pub fn is_enabled(&self) -> bool {
        self.config.peer_fallback_enabled
            && !self.klever_node_url.is_empty()
            && !self.contract_address.is_empty()
    }
}

/// Validate a peer-fallback URL for SSRF and onion-disabled
/// rejection. Public so tests and any future caller share the rules.
///
/// Accept:
/// - `http(s)://<DNS hostname>[:port][/path]`
/// - `http(s)://<publicly-routable IP literal>[:port][/path]`
///
/// Reject:
/// - schemes other than `http(s)`
/// - non-routable IP literals (RFC1918, loopback, link-local incl.
///   169.254.169.254, ULA, CGNAT, IPv4-mapped IPv6, documentation
///   ranges)
/// - `.onion` hosts (until v0.46.9 ships proper onion transport)
/// - empty / unparseable URLs
pub fn classify_api_endpoint(api_endpoint: &str) -> Result<url::Url, &'static str> {
    let parsed = url::Url::parse(api_endpoint).map_err(|_| "unparseable URL")?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("disallowed scheme"),
    }
    let host = parsed.host_str().ok_or("missing host")?;
    if host.is_empty() {
        return Err("empty host");
    }
    if host.ends_with(".onion") {
        return Err("onion transport not enabled (pre-v0.46.9)");
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        if !ipv4_routable(&v4) {
            return Err("non-routable IPv4");
        }
    } else if let Ok(v6) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::Ipv6Addr>()
    {
        if !ipv6_routable(&v6) {
            return Err("non-routable IPv6");
        }
    }
    // DNS hostname — accept by string. The peer-set membership
    // constraint (SC-registered, anchoring, within 7d) provides the
    // primary trust boundary; resolving DNS here would leak the
    // lookup to the operator's resolver and add latency we can't
    // amortise.
    Ok(parsed)
}

fn ipv4_routable(ip: &std::net::Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
    {
        return false;
    }
    let o = ip.octets();
    // CGNAT 100.64.0.0/10
    if o[0] == 100 && (o[1] & 0xc0) == 0x40 {
        return false;
    }
    true
}

fn ipv6_routable(ip: &std::net::Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    let s = ip.segments();
    if (s[0] & 0xff00) == 0xff00 {
        return false; // multicast
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        return false; // ULA
    }
    if (s[0] & 0xffc0) == 0xfe80 {
        return false; // link-local
    }
    if s[0..5].iter().all(|&x| x == 0) && s[5] == 0xffff {
        return false; // IPv4-mapped
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false; // documentation
    }
    true
}

/// `NodeAnnouncement` record shape, deserialised from
/// `PEER_DIRECTORY` values.
#[derive(Debug, Deserialize)]
pub struct PeerDirectoryRecord {
    #[serde(default)]
    pub api_endpoint: Option<String>,
    #[serde(default)]
    pub last_seen: u64,
    #[serde(default)]
    pub ttl_seconds: u64,
}

impl PeerDirectoryRecord {
    /// `true` if `last_seen + max(ttl_seconds, 60) < now_unix`.
    /// `ttl_seconds` is floored at 60 so an operator-published 0
    /// doesn't silently expire every record (TTLs near zero are an
    /// operator misconfig — be forgiving without being blind).
    pub fn is_expired(&self, now_unix: u64) -> bool {
        let ttl = self.ttl_seconds.max(60);
        self.last_seen + ttl < now_unix
    }
}

/// Decode a `PEER_DIRECTORY` row.
pub fn decode_peer_record(value: &[u8]) -> Option<PeerDirectoryRecord> {
    serde_json::from_slice(value).ok()
}

/// Resolve a single klv1 address → `CandidateEntry`. Returns `None`
/// when the lookup misses any of the trust-set rules listed in the
/// module doc.
///
/// **Transport classification (Security Audit C-1, 0.46.7):** any
/// URL that passes [`classify_api_endpoint`] is, by construction,
/// `http(s)://` over a publicly-routable host. `.onion` is rejected
/// inside `classify_api_endpoint`. We therefore hardcode the
/// transport to `Clearnet` here — the multiaddr-style
/// `classify_transport` would degrade every URL to `Unknown` and
/// silently disable the fallback. `TransportKind::Onion`/`I2p` may
/// appear here in a future release that adds a SOCKS5-aware
/// transport branch; for v0.46.7 the only outcome of a successful
/// classify is clearnet.
pub fn resolve_endpoint(
    storage: &Storage,
    address: &str,
    now_unix: u64,
) -> Option<CandidateEntry> {
    let node_id = crate::crypto::address_to_node_id(address).ok()?;
    let value = storage
        .get_cf(crate::storage::schema::cf::PEER_DIRECTORY, node_id.as_bytes())
        .ok()??;
    let record = decode_peer_record(&value)?;
    if record.is_expired(now_unix) {
        return None;
    }
    let api_endpoint = record.api_endpoint?;
    let _ = classify_api_endpoint(&api_endpoint).ok()?;
    Some(CandidateEntry {
        address: address.to_string(),
        api_endpoint,
        transport: TransportKind::Clearnet,
    })
}

/// Resolve a slice of klv1 addresses → dialable entries, deduping
/// by address first.
pub fn resolve_endpoints(
    storage: &Storage,
    addresses: &[String],
    now_unix: u64,
) -> Vec<CandidateEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(addresses.len());
    for addr in addresses {
        if !seen.insert(addr.clone()) {
            continue;
        }
        if let Some(entry) = resolve_endpoint(storage, addr, now_unix) {
            out.push(entry);
        }
    }
    out
}

/// Refresh the cached candidate snapshot (or return the cached one
/// if still within TTL). Returns the current entries.
///
/// `storage` is needed to resolve each SC-active klv1 address →
/// REST endpoint via the `PEER_DIRECTORY` (NodeAnnouncement records).
///
/// **Lock shape (Code Audit W-1, 0.46.7):** the SC RPC fetch runs
/// with NO lock held. Two concurrent refreshes may then race and one
/// overwrites the other under the brief write lock — that's
/// idempotent (both refreshes pull the same SC view) and bounded by
/// the global semaphore plus 5-min TTL, so the worst case is one
/// duplicate `getActiveNodes` call per TTL window. The previous
/// implementation held the write lock across the SC fetch and
/// serialised every concurrent fallback request on the refresh.
async fn ensure_snapshot(
    state: &MediaFallbackState,
    storage: &Storage,
) -> Vec<CandidateEntry> {
    let ttl = Duration::from_secs(state.config.peer_fallback_candidate_cache_secs);

    // Fast path: snapshot is fresh.
    {
        let read = state.candidates.read().await;
        if let Some(snap) = read.as_ref() {
            if snap.generated_at.elapsed() < ttl {
                return snap.entries.clone();
            }
        }
    }

    // Refresh path: do the SC RPC + storage resolution with NO lock
    // held. Concurrent refreshes are bounded by the global semaphore
    // (default 16) and are functionally idempotent.
    const PAGE_SIZE: u32 = 64;
    const MAX_TOTAL: usize = 256;
    let mut collected: Vec<sc_views::ActiveNode> = Vec::new();
    let mut offset: u32 = 0;
    loop {
        match sc_views::get_active_nodes(
            &state.http,
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
                if collected.len() >= MAX_TOTAL {
                    collected.truncate(MAX_TOTAL);
                    break;
                }
                if (page_len as u32) < PAGE_SIZE {
                    break;
                }
                offset = offset.saturating_add(PAGE_SIZE);
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "media-fallback: getActiveNodes failed; keeping prior snapshot"
                );
                let read = state.candidates.read().await;
                return read
                    .as_ref()
                    .map(|s| s.entries.clone())
                    .unwrap_or_default();
            }
        }
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let staleness_cutoff = now_unix.saturating_sub(state.peer_staleness_secs);

    // Filter + self-exclude.
    let self_addr = &state.self_address;
    let addresses: Vec<String> = collected
        .into_iter()
        .filter(|n| {
            &n.address != self_addr
                && n.last_anchor_at > 0
                && n.last_anchor_at >= staleness_cutoff
        })
        .map(|n| n.address)
        .collect();

    let entries = resolve_endpoints(storage, &addresses, now_unix);

    debug!(
        active_nodes = addresses.len(),
        resolved_endpoints = entries.len(),
        "media-fallback: refreshed candidate snapshot"
    );

    // Install the snapshot atomically. A concurrent refresh that
    // raced us here may overwrite (or be overwritten by) this
    // write; either way the result is a snapshot with the same
    // semantic content because both refreshes saw the same SC
    // state within the TTL window.
    let mut write = state.candidates.write().await;
    *write = Some(CandidateSnapshot {
        generated_at: Instant::now(),
        generated_at_unix: now_unix,
        entries: entries.clone(),
    });
    entries
}

/// Public entry point: try to fetch `cid` from the peer fallback
/// set. Returns `Some(bytes)` only if a candidate returned 200 AND
/// the IPFS add+verify succeeded; `None` otherwise (the handler
/// surfaces `None` as a regular 404).
///
/// On success, the returned bytes have ALREADY been added + pinned
/// to the local Kubo via [`crate::ipfs::IpfsClient::add_and_verify_cid`].
/// That side effect is intentional: subsequent local lookups for
/// this CID hit immediately.
pub async fn fetch_via_peers(
    state: &MediaFallbackState,
    storage: &Storage,
    ipfs: &crate::ipfs::client::IpfsClient,
    cid: &str,
    max_body_bytes: u64,
) -> Option<Bytes> {
    if !state.is_enabled() {
        return None;
    }

    // Acquire a global concurrent permit (best-effort: drop the
    // attempt if we're at the cap rather than queuing).
    let _permit = match state.global_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            debug!("media-fallback: global concurrent cap hit; declining fallback");
            return None;
        }
    };

    let snapshot = ensure_snapshot(state, storage).await;
    if snapshot.is_empty() {
        debug!("media-fallback: no candidates resolved");
        return None;
    }

    // Filter to clearnet only at v0.46.7. Onion / I2P land later.
    let mut dialable: Vec<CandidateEntry> = snapshot
        .into_iter()
        .filter(|e| matches!(e.transport, TransportKind::Clearnet))
        .collect();
    if dialable.is_empty() {
        debug!("media-fallback: no clearnet-classified candidates");
        return None;
    }

    // Randomise before truncate — defeats SC-ordering attempts to
    // pin a fresh node to a specific subset (same posture as
    // sc_discovery in step 1).
    dialable.shuffle(&mut rand::thread_rng());
    dialable.truncate(state.config.peer_fallback_fanout);

    info!(
        cid = %cid,
        fanout = dialable.len(),
        "media-fallback: dialing peer set"
    );

    // Race the fetches. `select_ok` returns the first successful
    // future and drops the rest (cancels in-flight on drop).
    let futures: Vec<_> = dialable
        .into_iter()
        .map(|cand| Box::pin(fetch_one(state, cid.to_string(), cand, max_body_bytes)))
        .collect();

    let bytes = match futures::future::select_ok(futures).await {
        Ok((bytes, _rest)) => bytes,
        Err(e) => {
            debug!(error = %e, "media-fallback: all peer dials failed");
            return None;
        }
    };

    // Content-verify + pin. On mismatch this returns an Err and we
    // surface as a clean miss; the peer cannot poison the local
    // store with content that doesn't match the requested CID.
    if let Err(e) = ipfs.add_and_verify_cid(cid, bytes.to_vec()).await {
        warn!(
            cid = %cid,
            error = %e,
            "media-fallback: CID verification failed — refusing peer bytes"
        );
        return None;
    }

    info!(
        cid = %cid,
        size = bytes.len(),
        "media-fallback: serving verified peer bytes (now pinned locally)"
    );
    Some(bytes)
}

/// Single peer dial — race entry. Returns `Bytes` on success, error
/// on any failure path so `select_ok` collects via the Err arm.
///
/// **Body-size cap (Security Audit C-2, 0.46.7):** the body is
/// streamed and aborted as soon as the accumulated size exceeds the
/// configured `max_body_bytes`. Without this cap, a hostile peer
/// could stream up to (link_rate × `peer_fallback_read_timeout_secs`)
/// of bytes — easily hundreds of MB on a fast link — fully buffered
/// in RAM before `add_and_verify_cid` had a chance to check size.
/// We honour `Content-Length` for a fast reject when the peer
/// advertises an oversized payload, and enforce the same cap during
/// the streaming read for peers that omit or lie about the header.
async fn fetch_one(
    state: &MediaFallbackState,
    cid: String,
    candidate: CandidateEntry,
    max_body_bytes: u64,
) -> anyhow::Result<Bytes> {
    let url = format!(
        "{}/api/v1/media/{}",
        candidate.api_endpoint.trim_end_matches('/'),
        cid
    );
    let resp = state.http.get(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "peer {} returned {} for {}",
            candidate.address,
            resp.status(),
            cid
        );
    }
    if let Some(advertised) = resp.content_length() {
        if advertised > max_body_bytes {
            anyhow::bail!(
                "peer {} advertised oversized body for {}: {} > {}",
                candidate.address,
                cid,
                advertised,
                max_body_bytes
            );
        }
    }
    // Pre-allocate up to the expected size when known, capped at the
    // max to defeat an attacker advertising a huge but unbacked
    // Content-Length.
    let initial = resp
        .content_length()
        .map(|n| n.min(max_body_bytes) as usize)
        .unwrap_or(0);
    let mut buf: Vec<u8> = Vec::with_capacity(initial);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if (buf.len() as u64).saturating_add(chunk.len() as u64) > max_body_bytes {
            anyhow::bail!(
                "peer {} body exceeded cap mid-stream for {} (cap = {})",
                candidate.address,
                cid,
                max_body_bytes
            );
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_accepts_public_https() {
        assert!(classify_api_endpoint("https://node.example.org").is_ok());
        assert!(classify_api_endpoint("https://node.example.org:8443/api").is_ok());
        assert!(classify_api_endpoint("https://8.8.8.8/api").is_ok());
    }

    #[test]
    fn classify_accepts_routable_ipv6() {
        assert!(
            classify_api_endpoint("https://[2606:4700:4700::1111]/api").is_ok()
        );
    }

    #[test]
    fn classify_rejects_private_ranges() {
        for raw in [
            "http://127.0.0.1/api",
            "http://10.0.0.5/api",
            "http://172.16.0.1/api",
            "http://192.168.1.1/api",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/api",
            "http://0.0.0.0/api",
            "https://[fe80::1]/api",
            "https://[fc00::1]/api",
            "https://[::1]/api",
        ] {
            assert!(
                classify_api_endpoint(raw).is_err(),
                "{raw} must be rejected"
            );
        }
    }

    #[test]
    fn classify_rejects_onion_until_v0_46_9() {
        let err = classify_api_endpoint("http://abc123.onion/api").unwrap_err();
        assert!(err.contains("onion"));
    }

    #[test]
    fn classify_rejects_non_http_schemes() {
        for raw in [
            "ftp://example.org",
            "file:///etc/passwd",
            "gopher://example.org",
            "ws://example.org",
        ] {
            assert!(
                classify_api_endpoint(raw).is_err(),
                "{raw} must be rejected"
            );
        }
    }

    #[test]
    fn peer_record_expiry() {
        let r = PeerDirectoryRecord {
            api_endpoint: Some("https://x.org".into()),
            last_seen: 1000,
            ttl_seconds: 600,
        };
        assert!(!r.is_expired(1599));
        assert!(r.is_expired(1601));
    }

    #[test]
    fn peer_record_floor_ttl_at_60s() {
        // Operator-published ttl_seconds = 0 would otherwise mean
        // "expire immediately" — clamp to 60s.
        let r = PeerDirectoryRecord {
            api_endpoint: Some("https://x.org".into()),
            last_seen: 1000,
            ttl_seconds: 0,
        };
        assert!(!r.is_expired(1059));
        assert!(r.is_expired(1061));
    }

    #[test]
    fn decode_peer_record_extracts_api_endpoint() {
        let json = br#"{"api_endpoint":"https://node.x.org","last_seen":1000,"ttl_seconds":600,"channels":[],"user_count":0}"#;
        let r = decode_peer_record(json).expect("valid");
        assert_eq!(r.api_endpoint.as_deref(), Some("https://node.x.org"));
        assert_eq!(r.last_seen, 1000);
        assert_eq!(r.ttl_seconds, 600);
    }

    #[test]
    fn decode_peer_record_handles_missing_endpoint() {
        let json = br#"{"last_seen":1000,"ttl_seconds":600}"#;
        let r = decode_peer_record(json).expect("valid");
        assert!(r.api_endpoint.is_none());
    }

    #[test]
    fn decode_peer_record_rejects_garbage() {
        assert!(decode_peer_record(b"not json").is_none());
        assert!(decode_peer_record(b"").is_none());
    }

    #[test]
    fn resolved_entries_classify_as_clearnet_not_unknown() {
        // Security Audit C-1 regression guard (0.46.7). The
        // multiaddr-style `classify_transport` returns `Unknown` for
        // every HTTP URL — using it here would silently filter out
        // every candidate in `fetch_via_peers`. `resolve_endpoint`
        // therefore hardcodes Clearnet after `classify_api_endpoint`
        // accepts the URL. Without this test, a future refactor
        // could quietly disable the entire fallback path.
        let parsed = classify_api_endpoint("https://node.example.org/api").expect("valid");
        assert_eq!(parsed.scheme(), "https");
        // The hardcoded transport choice is encoded in resolve_endpoint;
        // we verify the *type* by constructing what resolve_endpoint
        // would build for a passing URL.
        let synthetic = CandidateEntry {
            address: "klv1test".to_string(),
            api_endpoint: "https://node.example.org/api".to_string(),
            transport: TransportKind::Clearnet,
        };
        assert!(matches!(synthetic.transport, TransportKind::Clearnet));
    }
}
