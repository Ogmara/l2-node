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
use tracing::warn;

use crate::network::reconcile::{append_within_byte_budget, envelope_wire_cost, MAX_RESPONSE_ENVELOPE_BYTES};

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

/// Max envelopes a responder returns per page — the primary `NEWS_FEED`
/// scan only. The LAST page also carries the edit/delete and reaction
/// ride-alongs on top (see [`MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS`]).
pub const MAX_ENVELOPES_PER_RESPONSE: usize = 200;
/// Max edit/delete (and, since l2-node 0.151.0, GDPR `DeletionRequest`)
/// envelopes one last-page ride-along carries.
pub const NEWS_EDIT_DELETE_CAP: usize = 2_000;
/// Max `NewsReaction` envelopes one last-page ride-along carries.
pub const NEWS_REACTION_CAP: usize = 4_000;
/// The largest page an honest responder sends: a full primary page plus both
/// full ride-alongs. The requester refuses (does not verify) anything larger.
/// Before l2-node 0.151.0 the requester compared against
/// `MAX_ENVELOPES_PER_RESPONSE` alone, so any last page whose ride-alongs
/// pushed it past 200 envelopes was discarded whole — edits, deletes and
/// reactions included.
pub const MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS: usize =
    MAX_ENVELOPES_PER_RESPONSE + NEWS_EDIT_DELETE_CAP + NEWS_REACTION_CAP;
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
                // GDPR DeletionRequest (l2-node 0.151.0, G5): indexed into
                // NEWS_EDIT_DELETE when its target is news, so the last-page
                // ride-along carries it. The receiver also checks the target
                // (`network::deletion_request_fit`).
                | MessageType::DeletionRequest
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
///
/// (Test convenience wrapper — production calls the `_metered` variant.)
#[cfg(test)]
pub fn build_response(
    storage: &Storage,
    request: &NewsSyncRequest,
    max_envelopes: usize,
    now_ms: u64,
    window_max_age_secs: u64,
) -> NewsSyncResponse {
    build_response_metered(storage, request, max_envelopes, now_ms, window_max_age_secs).0
}

/// `build_response` plus the storage work it did — one unit per seek and per
/// index row examined (ride-along rows included), for the responder's
/// rolling budget (`reconcile::budget_charge`, l2-node 0.151.0).
///
/// A post or comment erased by a GDPR `DeletionRequest` (decision D4) is
/// never re-served, nor is an edit/delete/reaction of one; the request
/// itself rides along on the last page.
pub fn build_response_metered(
    storage: &Storage,
    request: &NewsSyncRequest,
    max_envelopes: usize,
    now_ms: u64,
    window_max_age_secs: u64,
) -> (NewsSyncResponse, u64) {
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
            return (
                NewsSyncResponse {
                    envelopes: Vec::new(),
                    has_more: false,
                    next_cursor: None,
                    server_capped: false,
                    completeness_root: None,
                },
                1,
            )
        }
    };
    let mut work: u64 = 1 + rows.len() as u64;

    // If the storage batch came back full, there may be rows beyond it.
    let truncated = rows.len() >= probe_limit;
    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    let mut next_cursor: Option<NewsCursor> = None;
    let mut hit_cap = false;
    let mut hit_window_end = false;
    // Wire bytes of the page so far (W5).
    let mut bytes: usize = 0;

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

        // D4 (l2-node 0.151.0): never re-serve a GDPR-erased post/comment.
        let raw = if storage.is_gdpr_erased(&msg_id) {
            None
        } else {
            storage
                .get_cf(schema::cf::MESSAGES, &msg_id)
                .ok()
                .flatten()
                .filter(|raw| is_backfillable(raw))
        };
        // W5 (l2-node 0.151.0): page full by BYTES — stop before consuming
        // this row; the next page resumes at it.
        if let Some(r) = raw.as_ref() {
            if !envelopes.is_empty() && bytes.saturating_add(envelope_wire_cost(r)) > MAX_RESPONSE_ENVELOPE_BYTES {
                hit_cap = true;
                break;
            }
        }

        // Advance the cursor over EVERY in-window row we examine (even if its
        // MESSAGES entry is missing) so a sparse page can't strand older
        // in-window rows by ending with `envelopes.len() < max`.
        next_cursor = Some(NewsCursor {
            after_timestamp: ts,
            after_msg_id: msg_id,
        });
        if let Some(r) = raw {
            bytes = bytes.saturating_add(envelope_wire_cost(&r));
            envelopes.push(r);
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
        let (ed, ed_work) = news_edit_delete_envelopes(storage, min_ts);
        let (re, re_work) = news_reaction_envelopes(storage, min_ts);
        work += ed_work + re_work;
        // W5: edits/deletes (incl. DeletionRequests) first, then reactions,
        // each newest-first, within the response byte budget.
        let bytes = append_within_byte_budget(&mut envelopes, ed, bytes);
        append_within_byte_budget(&mut envelopes, re, bytes);
    }

    (
        NewsSyncResponse {
            envelopes,
            has_more,
            next_cursor,
            server_capped: false,
            completeness_root: None,
        },
        work,
    )
}

/// Gather `NewsReaction` envelopes within the window.
///
/// Reactions are the one news type that appears in NO index the primary scan
/// walks: `NewsComment` and `NewsRepost` are written into `NEWS_FEED` (they are
/// timeline content), but a reaction is not, so before `NEWS_REACTION_MSGS`
/// existed a reaction reached a backfilling peer by no mechanism whatsoever. A
/// reaction missed while a node was down or unmeshed was lost permanently, and
/// two nodes could hold the same post with different counts forever — observed
/// in the field as one node showing two reactions and its peer none.
///
/// Bounded + best-effort, the same tradeoff already accepted for edits/deletes.
/// Rides along on the last page for the same ordering reason: `toggle_news_reaction`
/// keys off the target post, so the post wants to be applied first.
fn news_reaction_envelopes(storage: &Storage, min_ts: u64) -> (Vec<Vec<u8>>, u64) {
    let rows = match storage.prefix_iter_cf(
        schema::cf::NEWS_REACTION_MSGS,
        &[],
        NEWS_REACTION_CAP.saturating_add(1),
    ) {
        Ok(r) => r,
        Err(_) => return (Vec::new(), 1),
    };
    let work = 1 + rows.len() as u64;
    if rows.len() > NEWS_REACTION_CAP {
        warn!(
            cap = NEWS_REACTION_CAP,
            "news-sync: more reaction envelopes than the ride-along cap; \
             oldest excess reactions were not shipped this session"
        );
    }
    let mut out = Vec::with_capacity(rows.len().min(NEWS_REACTION_CAP));
    for (key, _) in rows.into_iter().take(NEWS_REACTION_CAP) {
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
            if reaction_is_backfillable(storage, &raw)
                && !crate::network::reconcile::ride_along_target_erased(storage, &raw)
            {
                out.push(raw);
            }
        }
    }
    (out, work)
}

/// Whether a `NewsReaction` may ride along to a backfilling peer.
///
/// A reaction carries no post content, but it does reveal that a given post
/// EXISTS and who engaged with it. `is_backfillable` already withholds a
/// `Followers`-only `NewsPost` from this same response, so shipping a reaction
/// on that post would leak its `msg_id` — and a reactor's address — to a peer
/// that never received the post. Mirrors `edit_is_backfillable`.
fn reaction_is_backfillable(storage: &Storage, raw: &[u8]) -> bool {
    let Ok(envelope) = rmp_serde::from_slice::<crate::messages::envelope::Envelope>(raw) else {
        return true;
    };
    if envelope.msg_type != crate::messages::types::MessageType::NewsReaction {
        return true;
    }
    let Ok(reaction) =
        rmp_serde::from_slice::<crate::messages::types::ReactionPayload>(&envelope.payload)
    else {
        return true;
    };
    let Ok(Some(target_raw)) = storage.get_cf(schema::cf::MESSAGES, &reaction.target_id) else {
        return true; // target gone/unknown — nothing more restrictive to check
    };
    is_backfillable(&target_raw)
}

/// Gather `NewsEdit`/`NewsDelete` envelopes within the window (audit final
/// pre-mainnet W6 — News shares the identical gap Chat/DM had, not
/// originally named in the finding). Without this, edit/delete envelopes
/// never reach a backfilling node at all — the primary `NEWS_FEED` scan
/// above only ever contains original `NewsPost`/`NewsComment` rows — so
/// "deleted for everyone" content is re-served forever. Bounded +
/// best-effort, same tradeoff already accepted elsewhere in this file.
fn news_edit_delete_envelopes(storage: &Storage, min_ts: u64) -> (Vec<Vec<u8>>, u64) {
    let rows = match storage.prefix_iter_cf(
        schema::cf::NEWS_EDIT_DELETE,
        &[],
        NEWS_EDIT_DELETE_CAP.saturating_add(1),
    ) {
        Ok(r) => r,
        Err(_) => return (Vec::new(), 1),
    };
    let work = 1 + rows.len() as u64;
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
            if edit_is_backfillable(storage, &raw)
                && !crate::network::reconcile::ride_along_target_erased(storage, &raw)
            {
                out.push(raw);
            }
        }
    }
    (out, work)
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

/// Responder admission for news-sync (l2-node 0.151.0): per-peer concurrency
/// (`SERVER_MAX_CONCURRENT_PER_PEER`) plus a rolling budget per peer —
/// `[backfill] news_responder_budget_burst` units (default 2,000) refilled at
/// `news_responder_budget_refill_per_hour` (default 2,000/h), charged with
/// `reconcile::budget_charge`. Before 0.151.0 this was a LIFETIME counter of
/// envelopes served (`TOTAL_ENVELOPES_CAP = 2,000`, ride-alongs included)
/// that never refilled until the responder restarted, so a long-lived peer
/// was refused every 6-hourly catch-up after one busy session.
pub type NewsResponderLimits = crate::network::budget::PeerBudgetLimits<libp2p::PeerId>;

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

    /// D4 + G5 (l2-node 0.151.0): an erased post is never served, nor is a
    /// delete of it; its DeletionRequest (indexed into NEWS_EDIT_DELETE)
    /// rides along on the last page. Work is metered for the budget.
    #[test]
    fn erased_post_is_withheld_and_its_request_rides_along() {
        use crate::messages::types::{DeletionRequestPayload, DeletionType};
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let base_ts = 1_700_000_000_000u64;
        let (keep, erase, del, req_id) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        put_news_post(&storage, author, keep, base_ts);
        put_news_post(&storage, author, erase, base_ts + 1);
        put_news_delete(&storage, author, erase, del, base_ts + 2);
        let payload = DeletionRequestPayload { delete_type: DeletionType::SingleMessage, target_id: Some(erase) };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DeletionRequest,
            msg_id: req_id,
            author: author.to_string(),
            timestamp: base_ts + 3,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage.put_cf(schema::cf::MESSAGES, &req_id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
        storage.put_verified_deletion_request(&erase, &req_id, author, base_ts + 3).unwrap();
        assert!(storage.index_deletion_request(&erase, &req_id, base_ts + 3).unwrap());

        let req = NewsSyncRequest { max_age_secs: u64::MAX, cursor: None, overlap_digest: vec![], round: 0 };
        let (resp, work) = build_response_metered(&storage, &req, 10, base_ts + 1000, u64::MAX);
        let ids: Vec<[u8; 32]> = resp
            .envelopes
            .iter()
            .map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_id)
            .collect();
        assert_eq!(ids, vec![keep, req_id], "only the kept post and the request");
        assert!(work >= 2 + 1 + 2, "feed rows plus ride-along rows are metered: {work}");
        assert!(is_news_type(MessageType::DeletionRequest as u8));
    }

    /// W5 (audit, l2-node 0.151.0): a maximal page — big posts plus a full
    /// set of large ride-alongs — is cut by BYTES so it always fits the
    /// libp2p CBOR response cap (10 MiB); the rest continues on later pages.
    /// Encoded and decoded with the real codec.
    #[test]
    fn maximal_page_encodes_under_the_transport_cap() {
        use futures::executor::block_on;
        use libp2p::request_response::Codec;
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let base_ts = 1_700_000_000_000u64;
        let big = "x".repeat(60_000);
        for n in 0..200u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_be_bytes());
            id[31] = 1;
            let payload = NewsPostPayload {
                title: "t".into(),
                content: big.clone(),
                content_rating: Default::default(),
                tags: vec![],
                attachments: vec![],
                visibility: Default::default(),
            };
            let env = Envelope {
                version: crate::messages::envelope::PROTOCOL_VERSION,
                msg_type: MessageType::NewsPost,
                msg_id: id,
                author: author.to_string(),
                timestamp: base_ts + n as u64,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&payload).unwrap(),
                signature: vec![],
                relay_path: vec![],
            };
            storage.put_cf(schema::cf::NEWS_FEED, &schema::encode_news_key(base_ts + n as u64, &id), &[]).unwrap();
            storage.put_cf(schema::cf::MESSAGES, &id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
        }
        let codec_check = |resp: NewsSyncResponse| {
            let mut codec = libp2p::request_response::cbor::codec::Codec::<NewsSyncRequest, NewsSyncResponse>::default();
            let proto = libp2p::StreamProtocol::new("/test");
            let mut buf = Vec::new();
            block_on(codec.write_response(&proto, &mut futures::io::Cursor::new(&mut buf), resp)).unwrap();
            assert!(buf.len() < 10 * 1024 * 1024, "encoded page {} bytes", buf.len());
            block_on(codec.read_response(&proto, &mut futures::io::Cursor::new(&buf))).expect("decodes under the default cap")
        };
        let mut cursor = None;
        let mut total = 0usize;
        for _ in 0..10 {
            let req = NewsSyncRequest { max_age_secs: u64::MAX, cursor: cursor.clone(), overlap_digest: vec![], round: 0 };
            let resp = build_response(&storage, &req, MAX_ENVELOPES_PER_RESPONSE, base_ts + 10_000, u64::MAX);
            let bytes: usize = resp.envelopes.iter().map(|e| envelope_wire_cost(e)).sum();
            assert!(bytes <= MAX_RESPONSE_ENVELOPE_BYTES);
            total += resp.envelopes.len();
            let more = resp.has_more;
            cursor = resp.next_cursor.clone();
            let back = codec_check(resp);
            assert_eq!(back.has_more, more);
            if !more {
                break;
            }
        }
        assert_eq!(total, 200, "every post delivered across byte-bounded pages");
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
            buttons: None,
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

    fn put_news_reaction(
        storage: &Storage,
        reactor: &str,
        target_id: [u8; 32],
        msg_id: [u8; 32],
        ts: u64,
    ) {
        let payload = crate::messages::types::ReactionPayload {
            target_id,
            channel_id: None,
            emoji: "🔥".to_string(),
            remove: false,
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::NewsReaction,
            msg_id,
            author: reactor.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::NEWS_REACTION_MSGS, &schema::encode_news_key(ts, &msg_id), &[])
            .unwrap();
        storage
            .put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    /// The whole point of the reaction index: a reaction on a PUBLIC post must
    /// actually reach a backfilling peer. Reactions live in no index the primary
    /// NEWS_FEED scan walks, so if the ride-along regresses they silently stop
    /// propagating and nothing else catches it.
    #[test]
    fn reaction_on_a_public_post_rides_along() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let ts = 1_700_000_000_000u64;
        let post_id = [1u8; 32];
        put_news_post_vis(&storage, author, post_id, ts, Visibility::Public);
        put_news_reaction(&storage, "klv1reactor", post_id, [3u8; 32], ts + 50);

        let req = NewsSyncRequest {
            max_age_secs: u64::MAX,
            cursor: None,
            overlap_digest: vec![],
            round: 0,
        };
        let resp = build_response(&storage, &req, 10, ts + 1000, u64::MAX);
        assert_eq!(
            resp.envelopes.len(),
            2,
            "the public post AND its reaction must both be served"
        );
    }

    /// Mirror of the edit side channel: a reaction reveals that a post exists and
    /// who engaged with it. Since the Followers-only post itself is withheld from
    /// this response, shipping a reaction on it would leak the post's msg_id and
    /// the reactor's address to a peer that never received the post.
    #[test]
    fn reaction_on_a_followers_only_post_does_not_leak_via_ride_along() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let author = "klv1author";
        let ts = 1_700_000_000_000u64;
        let post_id = [1u8; 32];
        put_news_post_vis(&storage, author, post_id, ts, Visibility::Followers);
        put_news_reaction(&storage, "klv1reactor", post_id, [3u8; 32], ts + 50);

        let req = NewsSyncRequest {
            max_age_secs: u64::MAX,
            cursor: None,
            overlap_digest: vec![],
            round: 0,
        };
        let resp = build_response(&storage, &req, 10, ts + 1000, u64::MAX);
        assert!(
            resp.envelopes.is_empty(),
            "a reaction on a Followers-only post must not leak its existence via the \
             ride-along, even though the post itself is already excluded"
        );
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
