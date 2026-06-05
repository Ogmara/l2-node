//! News-sync — bounded backfill of the GLOBAL news feed (P-3, l2-node 0.52.0+).
//!
//! NewsPosts gossip once and are never backfilled, so a fresh node (or one that
//! wiped) shows an empty news feed. News-sync fixes that — but it is **bounded
//! by design**: it pulls only the last `news_max_age_days` of news (default 7),
//! capped + paged, racing a few peers. It is NOT a full-history transfer — a
//! node with years of news never serves more than the recent window to any one
//! peer. Triggered lazily, ONCE, only when the local NEWS_FEED is empty.
//!
//! Mirrors `network/reconcile.rs`/`identity_sync.rs`: libp2p request/response,
//! cursor paging, capped + rate-limited responses; the responder re-serves the
//! ORIGINAL signed envelopes and the requester re-validates each through
//! `router::process_synced_message`, so a relaying peer is never trusted.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::storage::rocks::Storage;
use crate::storage::schema;

/// libp2p CBOR request/response codec for news-sync.
pub type NewsSyncCodec =
    libp2p::request_response::cbor::Behaviour<NewsSyncRequest, NewsSyncResponse>;

/// Protocol string. Versioned independently.
pub fn protocol_string(network_id: &str) -> String {
    format!("/ogmara/{}/news-sync/1.0.0", network_id)
}

// --- Tuning (window comes from config; these bound it further) ---

/// Max envelopes a responder returns per page.
pub const MAX_ENVELOPES_PER_RESPONSE: usize = 200;
/// Hard ceiling on cumulative envelopes one peer may pull per process lifetime.
pub const TOTAL_ENVELOPES_CAP: u64 = 2_000;
/// Max concurrent inbound news-sync requests served to one peer.
pub const SERVER_MAX_CONCURRENT_PER_PEER: usize = 4;
/// How many peers an outbound backfill races (first non-empty wins).
pub const FANOUT: usize = 3;

/// Returns true iff `msg_type` is a news-feed message type (`0x20`–`0x25`) —
/// what the NEWS_FEED index holds. Used as the receiver's type-smuggling
/// defense so a responder can't inject a non-news type through this path.
pub fn is_news_type(msg_type: u8) -> bool {
    use crate::messages::types::MessageType;
    matches!(
        MessageType::from_u8(msg_type),
        Some(
            MessageType::NewsPost
                | MessageType::NewsEdit
                | MessageType::NewsDelete
                | MessageType::NewsComment
                | MessageType::NewsRepost
        )
    )
}

// --- Wire types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsSyncRequest {
    /// Only serve news newer than `now - max_age_secs`. `u64::MAX` = unlimited
    /// (archive). Bounded by the responder's own config window regardless.
    pub max_age_secs: u64,
    /// Opaque paging cursor (continue with OLDER news after this point).
    pub cursor: Option<NewsCursor>,
    /// RESERVED — future set-reconciliation. Always empty.
    #[serde(default)]
    pub overlap_digest: Vec<u8>,
    /// RESERVED. Always 0.
    #[serde(default)]
    pub round: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsSyncResponse {
    /// Original signed news envelopes (MessagePack). Receiver re-validates.
    pub envelopes: Vec<Vec<u8>>,
    pub has_more: bool,
    pub next_cursor: Option<NewsCursor>,
    pub server_capped: bool,
    #[serde(default)]
    pub completeness_root: Option<[u8; 32]>,
}

/// Cursor over the reverse-chronological NEWS_FEED. `after_timestamp` is the
/// real (un-negated) ms timestamp of the last served item; paging continues
/// with strictly OLDER items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsCursor {
    pub after_timestamp: u64,
    pub after_msg_id: [u8; 32],
}

/// A `server_capped` response carrying nothing — sent when rate-limited.
pub fn capped_response() -> NewsSyncResponse {
    NewsSyncResponse {
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: true,
        completeness_root: None,
    }
}

/// Build a response: walk NEWS_FEED newest-first from the cursor, stop at the
/// window cutoff, re-serve the original signed envelopes from MESSAGES. Caps at
/// `max_envelopes`. `window_max_age_secs` is the RESPONDER's configured window
/// (we serve the tighter of it and the request's `max_age_secs`).
pub fn build_response(
    storage: &Storage,
    request: &NewsSyncRequest,
    max_envelopes: usize,
    now_ms: u64,
    window_max_age_secs: u64,
) -> NewsSyncResponse {
    // Honour the tighter of the requester's ask and our own configured window,
    // so a peer can't ask us to scan further back than we allow.
    let effective_age = request.max_age_secs.min(window_max_age_secs);
    let min_ts = if effective_age == u64::MAX {
        0
    } else {
        now_ms.saturating_sub(effective_age.saturating_mul(1000))
    };

    let probe_limit = max_envelopes.saturating_add(1);
    // NEWS_FEED is keyed (!timestamp, msg_id): newest first. No cursor = start
    // at the newest; cursor = continue strictly after the last served key
    // (i.e. older).
    let rows = if let Some(c) = request.cursor.as_ref() {
        let start_key = schema::encode_news_key(c.after_timestamp, &c.after_msg_id);
        storage.prefix_iter_cf_after(schema::cf::NEWS_FEED, &start_key, &[], probe_limit)
    } else {
        storage.prefix_iter_cf(schema::cf::NEWS_FEED, &[], probe_limit)
    };

    let rows = match rows {
        Ok(r) => r,
        Err(_) => {
            return NewsSyncResponse {
                envelopes: Vec::new(),
                has_more: false,
                next_cursor: None,
                server_capped: false,
                completeness_root: None,
            }
        }
    };

    // If the storage batch came back full, there may be rows beyond it.
    let truncated = rows.len() >= probe_limit;
    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    let mut next_cursor: Option<NewsCursor> = None;
    let mut hit_cap = false;
    let mut hit_window_end = false;

    for (key, _) in rows {
        if key.len() < 8 + 32 {
            continue; // malformed — our keys are always 40 bytes
        }
        // Un-negate the timestamp (keys store !timestamp for reverse order).
        let neg = u64::from_be_bytes(match key[0..8].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        });
        let ts = !neg;
        // Reverse-chrono + descending ts → once we pass the cutoff, everything
        // after is older. Monotonic with the sort, so we can stop definitively.
        if ts < min_ts {
            hit_window_end = true;
            break;
        }
        // Page full — stop before consuming this row; next page resumes at it.
        if envelopes.len() >= max_envelopes {
            hit_cap = true;
            break;
        }
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&key[8..40]);

        // Advance the cursor over EVERY in-window row we examine (even if its
        // MESSAGES entry is missing) so a sparse page can't strand older
        // in-window rows by ending with `envelopes.len() < max`.
        next_cursor = Some(NewsCursor {
            after_timestamp: ts,
            after_msg_id: msg_id,
        });
        if let Ok(Some(raw)) = storage.get_cf(schema::cf::MESSAGES, &msg_id) {
            envelopes.push(raw);
        }
    }

    // More pages exist if we stopped at the page cap, or the batch was
    // truncated and we did NOT reach the window's older edge.
    let has_more = hit_cap || (truncated && !hit_window_end);
    if !has_more {
        next_cursor = None;
    }

    NewsSyncResponse {
        envelopes,
        has_more,
        next_cursor,
        server_capped: false,
        completeness_root: None,
    }
}

// --- Responder rate limiting (per peer; the feed is global) ---

/// Bounds how much one peer can pull, mirroring `reconcile::ResponderLimits`
/// but global (keyed by `PeerId` only — no channel/wallet).
#[derive(Debug, Default)]
pub struct NewsResponderLimits {
    inner: Mutex<NewsLimitsInner>,
}

#[derive(Debug, Default)]
struct NewsLimitsInner {
    per_peer: HashMap<libp2p::PeerId, usize>,
    served: HashMap<libp2p::PeerId, u64>,
}

impl NewsResponderLimits {
    /// Admit one inbound request, or `None` if over a cap (→ `capped_response`).
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: libp2p::PeerId,
        max_concurrent_per_peer: usize,
        total_envelopes_cap: u64,
    ) -> Option<NewsResponderGuard> {
        /// Soft ceiling on distinct per-peer cumulative-served entries; cleared
        /// on overflow (abuse limiter, not a security invariant). Bounds growth
        /// from an adversary cycling peer identities.
        const MAX_TRACKED: usize = 100_000;
        let mut inner = self.inner.lock().ok()?;
        if inner.served.len() >= MAX_TRACKED {
            inner.served.clear();
        }
        let in_flight = inner.per_peer.get(&peer).copied().unwrap_or(0);
        if in_flight >= max_concurrent_per_peer {
            return None;
        }
        if inner.served.get(&peer).copied().unwrap_or(0) >= total_envelopes_cap {
            return None;
        }
        inner.per_peer.insert(peer, in_flight + 1);
        Some(NewsResponderGuard {
            limits: Arc::clone(self),
            peer,
        })
    }

    pub fn add_served(&self, peer: libp2p::PeerId, count: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            *inner.served.entry(peer).or_insert(0) += count;
        }
    }
}

/// RAII guard releasing a peer's in-flight slot on drop.
pub struct NewsResponderGuard {
    limits: Arc<NewsResponderLimits>,
    peer: libp2p::PeerId,
}

impl Drop for NewsResponderGuard {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.limits.inner.lock() {
            if let Some(n) = inner.per_peer.get_mut(&self.peer) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    inner.per_peer.remove(&self.peer);
                }
            }
        }
    }
}
