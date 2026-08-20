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
use tracing::warn;

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
                // Audit final pre-mainnet W28: NewsReaction was excluded here
                // (and had no gossip bridge arm), so reaction counts on other
                // nodes stayed permanently 0 — a node catching up via backfill
                // never got a chance to see them either.
                | MessageType::NewsReaction
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

/// Whether a raw envelope may be re-served to a backfilling peer over this
/// unauthenticated P2P protocol (audit W37). This responder has no concept
/// of "requester identity" — unlike the REST `/api/v1/news` endpoints (which
/// can check `Storage::news_followers_post_visible_to` against an
/// authenticated caller), a news-sync peer is just another node, not a
/// wallet. A `Followers`-only `NewsPost` is therefore never backfillable
/// here; it only ever reaches a fresh/cold-joined node via live gossip
/// (already-subscribed nodes keep whatever they received that way — this
/// only affects catch-up for a node that missed the original broadcast).
/// Anything else (comments, reactions, reposts, or an undecodable payload)
/// is unaffected — only the post's OWN `visibility` field gates it.
fn is_backfillable(raw: &[u8]) -> bool {
    let Ok(envelope) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(raw) else {
        return true; // corrupt — not this check's job to hide it
    };
    if envelope.msg_type != crate::messages::types::MessageType::NewsPost {
        return true;
    }
    let Ok(payload) =
        rmp_serde::from_slice::<crate::messages::types::NewsPostPayload>(&envelope.payload)
    else {
        return true;
    };
    payload.visibility != crate::messages::types::Visibility::Followers
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
            if is_backfillable(&raw) {
                envelopes.push(raw);
            }
        }
    }

    // More pages exist if we stopped at the page cap, or the batch was
    // truncated and we did NOT reach the window's older edge.
    let has_more = hit_cap || (truncated && !hit_window_end);
    if !has_more {
        next_cursor = None;
    }

    // Audit final pre-mainnet W6: ride edit/delete envelopes along on the
    // session's LAST (oldest) page only. News-sync walks newest→oldest, but
    // pages are still requested/applied strictly in order against a single
    // peer, so by the last page every post the session could have
    // delivered has already been applied — which `authorize_edit_delete`
    // requires before an edit/delete can be accepted.
    if !has_more {
        envelopes.extend(news_edit_delete_envelopes(storage, min_ts));
    }

    NewsSyncResponse {
        envelopes,
        has_more,
        next_cursor,
        server_capped: false,
        completeness_root: None,
    }
}

/// Gather `NewsEdit`/`NewsDelete` envelopes within the window (audit final
/// pre-mainnet W6 — News shares the identical gap Chat/DM had, not
/// originally named in the finding). Without this, edit/delete envelopes
/// never reach a backfilling node at all — the primary `NEWS_FEED` scan
/// above only ever contains original `NewsPost`/`NewsComment` rows — so
/// "deleted for everyone" content is re-served forever. Bounded +
/// best-effort, same tradeoff already accepted elsewhere in this file.
fn news_edit_delete_envelopes(storage: &Storage, min_ts: u64) -> Vec<Vec<u8>> {
    const NEWS_EDIT_DELETE_CAP: usize = 2_000;
    let rows = match storage.prefix_iter_cf(
        schema::cf::NEWS_EDIT_DELETE,
        &[],
        NEWS_EDIT_DELETE_CAP.saturating_add(1),
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    if rows.len() > NEWS_EDIT_DELETE_CAP {
        warn!(
            cap = NEWS_EDIT_DELETE_CAP,
            "news-sync: more edit/delete markers than the ride-along cap; \
             oldest excess markers were not shipped this session"
        );
    }
    let mut out = Vec::with_capacity(rows.len().min(NEWS_EDIT_DELETE_CAP));
    for (key, _) in rows.into_iter().take(NEWS_EDIT_DELETE_CAP) {
        // Key shape matches NEWS_FEED: !timestamp:8 ++ msg_id:32.
        if key.len() < 8 + 32 {
            continue;
        }
        let neg = u64::from_be_bytes(match key[0..8].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        });
        let ts = !neg;
        if ts < min_ts {
            continue;
        }
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&key[8..40]);
        if let Ok(Some(raw)) = storage.get_cf(schema::cf::MESSAGES, &msg_id) {
            if edit_is_backfillable(storage, &raw) {
                out.push(raw);
            }
        }
    }
    out
}

/// Whether a `NewsEdit`/`NewsDelete` envelope may ride along to a
/// backfilling peer (audit W37 follow-up, found while closing the main
/// finding). `NewsDelete` never carries content, so it's always safe.
/// `NewsEdit`'s `EditPayload.content`/`title` carry the post's FULL NEW
/// plaintext — even though `is_backfillable` above already excludes the
/// original `Followers`-only `NewsPost` envelope from this same response,
/// an edit ride-along on that post's `target_id` would otherwise leak its
/// edited content through this side channel to a peer who never received
/// the original. Looks up the target post to check its CURRENT visibility
/// (an edit can't itself change `visibility` — that's immutable per
/// `channel_encryption_defaults`-style write-time enforcement elsewhere —
/// so the original post's stored visibility is authoritative).
fn edit_is_backfillable(storage: &Storage, raw: &[u8]) -> bool {
    let Ok(envelope) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(raw) else {
        return true;
    };
    if envelope.msg_type != crate::messages::types::MessageType::NewsEdit {
        return true;
    }
    let Ok(edit) = rmp_serde::from_slice::<crate::messages::types::EditPayload>(&envelope.payload)
    else {
        return true;
    };
    let Ok(Some(original_raw)) = storage.get_cf(schema::cf::MESSAGES, &edit.target_id) else {
        return true; // original gone/unknown — nothing more restrictive to check
    };
    is_backfillable(&original_raw)
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

#[cfg(test)]
mod tests {
    use super::is_news_type;
    use crate::messages::types::MessageType;

    #[test]
    fn is_news_type_covers_news_reaction() {
        // Regression (audit final pre-mainnet W28): NewsReaction was
        // excluded here, so a node catching up via backfill never got a
        // chance to see reaction counts either (on top of the missing
        // gossip bridge arm).
        assert!(is_news_type(MessageType::NewsReaction as u8));
    }

    #[test]
    fn is_news_type_covers_the_other_news_variants() {
        for t in [
            MessageType::NewsPost,
            MessageType::NewsEdit,
            MessageType::NewsDelete,
            MessageType::NewsComment,
            MessageType::NewsRepost,
        ] {
            assert!(is_news_type(t as u8), "{:?} should be a news type", t);
        }
    }

    #[test]
    fn is_news_type_excludes_unrelated_types() {
        assert!(!is_news_type(MessageType::ChatMessage as u8));
        assert!(!is_news_type(MessageType::Follow as u8));
    }
}

#[cfg(test)]
mod edit_delete_ride_along_tests {
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{DeletePayload, MessageType, NewsPostPayload};
    use tempfile::TempDir;

    fn put_news_post(storage: &Storage, author: &str, msg_id: [u8; 32], ts: u64) {
        let payload = NewsPostPayload {
            title: "headline".to_string(),
            content: "body".to_string(),
            content_rating: Default::default(),
            tags: vec![],
            attachments: vec![],
            visibility: Default::default(),
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::NewsPost,
            msg_id,
            author: author.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::NEWS_FEED, &schema::encode_news_key(ts, &msg_id), &[])
            .unwrap();
        storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn put_news_delete(storage: &Storage, author: &str, target_id: [u8; 32], msg_id: [u8; 32], ts: u64) {
        let payload = DeletePayload { target_id, channel_id: None };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::NewsDelete,
            msg_id,
            author: author.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::NEWS_EDIT_DELETE, &schema::encode_news_key(ts, &msg_id), &[])
            .unwrap();
        storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn contains_type(envelopes: &[Vec<u8>], msg_type: MessageType) -> bool {
        envelopes.iter().any(|e| {
            rmp_serde::from_slice::<Envelope>(e)
                .map(|env| env.msg_type == msg_type)
                .unwrap_or(false)
        })
    }

    /// Regression for audit final pre-mainnet W6 (News shares the identical
    /// gap Chat/DM had, not originally named in the finding). News-sync
    /// walks newest→oldest, so "final page" means the OLDEST page — this
    /// proves the ride-along still fires there (not on an earlier, newer
    /// page) since pages are applied strictly in order regardless of scan
    /// direction.
    #[test]
    fn ride_along_only_appears_on_the_final_oldest_page() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let base_ts = 1_700_000_000_000u64;
        let mut ids = Vec::new();
        for n in 0u8..3 {
            let mut mid = [0u8; 32];
            mid[0] = n + 1;
            put_news_post(&storage, author, mid, base_ts + n as u64);
            ids.push(mid);
        }
        // Delete the OLDEST post (ids[0], ts = base_ts) — its marker has a
        // LATER timestamp than the post itself, same as real usage.
        put_news_delete(&storage, author, ids[0], [9u8; 32], base_ts + 100);

        // Page 1 (newest-first): cap=2 (< 3 total) → has_more → no ride-along.
        let req1 = NewsSyncRequest { max_age_secs: u64::MAX, cursor: None, overlap_digest: vec![], round: 0 };
        let resp1 = build_response(&storage, &req1, 2, base_ts + 1000, u64::MAX);
        assert!(resp1.has_more, "page 1 should be capped (2 of 3 posts)");
        assert!(
            !contains_type(&resp1.envelopes, MessageType::NewsDelete),
            "delete must not ride along on a non-final page"
        );

        // Page 2 (final/oldest): remaining post, under cap → ride-along present.
        let req2 = NewsSyncRequest {
            max_age_secs: u64::MAX,
            cursor: resp1.next_cursor,
            overlap_digest: vec![],
            round: 0,
        };
        let resp2 = build_response(&storage, &req2, 2, base_ts + 1000, u64::MAX);
        assert!(!resp2.has_more, "page 2 should be the final page");
        assert!(
            contains_type(&resp2.envelopes, MessageType::NewsDelete),
            "delete must ride along on the final page"
        );
    }
}

#[cfg(test)]
mod w37_followers_visibility_tests {
    //! Audit W37: news-sync has no requester identity (unlike the REST
    //! `/api/v1/news` endpoints), so a `Followers`-only post can never be
    //! backfilled through this protocol — only excluded, not conditionally
    //! shown. Also covers the edit-payload side channel found while fixing
    //! this: an edit ride-along on a Followers-only post must not leak its
    //! new content to a peer who never received the original post.
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{EditPayload, MessageType, NewsPostPayload, Visibility};
    use tempfile::TempDir;

    fn contains_type(envelopes: &[Vec<u8>], msg_type: MessageType) -> bool {
        envelopes.iter().any(|e| {
            rmp_serde::from_slice::<Envelope>(e)
                .map(|env| env.msg_type == msg_type)
                .unwrap_or(false)
        })
    }

    fn put_news_post_vis(
        storage: &Storage,
        author: &str,
        msg_id: [u8; 32],
        ts: u64,
        visibility: Visibility,
    ) {
        let payload = NewsPostPayload {
            title: "headline".to_string(),
            content: "body".to_string(),
            content_rating: Default::default(),
            tags: vec![],
            attachments: vec![],
            visibility,
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::NewsPost,
            msg_id,
            author: author.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::NEWS_FEED, &schema::encode_news_key(ts, &msg_id), &[])
            .unwrap();
        storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn put_news_edit(storage: &Storage, author: &str, target_id: [u8; 32], msg_id: [u8; 32], ts: u64) {
        let payload = EditPayload {
            target_id,
            channel_id: None,
            content: "leaked new content".to_string(),
            edited_at: ts,
            title: Some("leaked new title".to_string()),
            tags: None,
            attachments: None,
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::NewsEdit,
            msg_id,
            author: author.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::NEWS_EDIT_DELETE, &schema::encode_news_key(ts, &msg_id), &[])
            .unwrap();
        storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    #[test]
    fn followers_only_post_is_never_backfilled() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let ts = 1_700_000_000_000u64;
        put_news_post_vis(&storage, author, [1u8; 32], ts, Visibility::Followers);

        let req = NewsSyncRequest { max_age_secs: u64::MAX, cursor: None, overlap_digest: vec![], round: 0 };
        let resp = build_response(&storage, &req, 10, ts + 1000, u64::MAX);
        assert!(
            resp.envelopes.is_empty(),
            "a Followers-only post must never ride the news-sync backfill response"
        );
    }

    #[test]
    fn public_post_is_still_backfilled() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let ts = 1_700_000_000_000u64;
        put_news_post_vis(&storage, author, [1u8; 32], ts, Visibility::Public);

        let req = NewsSyncRequest { max_age_secs: u64::MAX, cursor: None, overlap_digest: vec![], round: 0 };
        let resp = build_response(&storage, &req, 10, ts + 1000, u64::MAX);
        assert_eq!(resp.envelopes.len(), 1, "a Public post must still backfill normally");
    }

    #[test]
    fn edit_of_a_followers_only_post_does_not_leak_via_ride_along() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let ts = 1_700_000_000_000u64;
        let post_id = [1u8; 32];
        put_news_post_vis(&storage, author, post_id, ts, Visibility::Followers);
        put_news_edit(&storage, author, post_id, [2u8; 32], ts + 100);

        // cap=1 forces has_more on a first page with only the (excluded)
        // post row present, but the edit lives in NEWS_EDIT_DELETE and only
        // rides along on the FINAL page — use a cap large enough that this
        // one post's absence still yields the final page immediately.
        let req = NewsSyncRequest { max_age_secs: u64::MAX, cursor: None, overlap_digest: vec![], round: 0 };
        let resp = build_response(&storage, &req, 10, ts + 1000, u64::MAX);
        assert!(
            resp.envelopes.is_empty(),
            "an edit whose target post is Followers-only must not leak the edited content \
             via the ride-along side channel, even though the original post is already excluded"
        );
    }

    #[test]
    fn edit_of_a_public_post_still_rides_along() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let ts = 1_700_000_000_000u64;
        let post_id = [1u8; 32];
        put_news_post_vis(&storage, author, post_id, ts, Visibility::Public);
        put_news_edit(&storage, author, post_id, [2u8; 32], ts + 100);

        let req = NewsSyncRequest { max_age_secs: u64::MAX, cursor: None, overlap_digest: vec![], round: 0 };
        let resp = build_response(&storage, &req, 10, ts + 1000, u64::MAX);
        assert!(
            contains_type(&resp.envelopes, MessageType::NewsEdit),
            "an edit on a Public post must still ride along normally"
        );
    }
}
