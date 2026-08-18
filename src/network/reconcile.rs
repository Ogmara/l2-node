//! Channel-history reconciliation protocol (spec 1, l2-node 0.47.0+).
//!
//! Closes B1 in `docs/planning/mainnet-blockers-fix-plan.md`: fresh
//! nodes joining an existing channel were left with empty
//! `CHANNEL_MSGS` indexes — gossip catches future messages but never
//! backfills history. This module implements the cold-join backfill:
//! on the first `subscribe_channel(channel_id)` where the local
//! `CHANNEL_MSGS` prefix-iter for that channel returns zero rows, the
//! node requests the missing history from up to `fanout` peers in
//! parallel, races for the first non-empty response, and pages
//! through cursor-based batches until the responding peer signals
//! `has_more = false`.
//!
//! # Wire protocol
//!
//! - Protocol string: `/ogmara/{network_id}/channel-reconcile/1.0.0`
//! - Codec: `libp2p::request_response::cbor::Behaviour<ReconcileRequest,
//!   ReconcileResponse>` — third request-response behaviour in
//!   [`crate::network::behaviour::OgmaraBehaviour`] alongside the
//!   existing sync + snapshot codecs.
//!
//! ## Forward compatibility
//!
//! The `fingerprint` field on [`ReconcileRequest`] is reserved for a
//! future range-based set-reconciliation handshake (the steady-state
//! overlap case). In v0.47.0 the field is always `Vec::new()`, which
//! responders interpret as "client has no data — bulk-send everything
//! in the configured window". The same applies to the
//! `epoch_root_known` request field and the `epoch_root` response
//! field — both reserved for the spec 14 post-mainnet completeness-
//! proof work and currently `None`. Adding fingerprint computation
//! and epoch_root anchoring is a forward-compatible change: same
//! wire protocol, new field semantics.
//!
//! # Trust model
//!
//! **Backfilled envelopes go through the standard router pipeline.**
//! There is NO fast-path bypass. A malicious responder can return
//! any bytes they want; the receiver routes them through
//! `MessageRouter::process_synced_message` which verifies signatures,
//! validates payloads, deduplicates by `msg_id`, and refuses anything
//! that fails. The worst a malicious responder can do is waste the
//! receiver's CPU; they cannot poison the local store with bogus
//! data.
//!
//! # Server-side rate limiting
//!
//! Two semaphore-style guards (default values from
//! `[backfill] server_max_concurrent_per_peer` /
//! `server_max_concurrent_per_channel`):
//!   - Per `(peer, channel)`: max 1 active request — a single peer
//!     cannot pipeline requests for the same channel.
//!   - Per peer: max 4 concurrent requests across all channels —
//!     stops a single peer from monopolising the responder.
//!
//! Excess requests get a response with `server_capped = true` and
//! empty envelopes; the client backs off and retries. We never
//! queue or block — busy responder = clean back-pressure signal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::messages::envelope::Envelope;
use crate::storage::rocks::Storage;
use crate::storage::schema;

/// Codec type alias for the reconcile protocol.
pub type ReconcileCodec =
    libp2p::request_response::cbor::Behaviour<ReconcileRequest, ReconcileResponse>;

/// Protocol-string builder. Mirrors the existing pattern from
/// [`crate::network::sync`] and [`crate::network::snapshot`].
pub fn protocol_string(network_id: &str) -> String {
    format!("/ogmara/{}/channel-reconcile/1.0.0", network_id)
}

/// Reconciliation request sent from a cold-joining requester to a
/// responder peer holding history for the target channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileRequest {
    /// Target channel.
    pub channel_id: u64,
    /// How far back to fetch, in seconds from now. `u64::MAX` means
    /// "no time-window filter".
    pub max_age_secs: u64,
    /// Cursor for the next batch. `None` on the first request; on
    /// subsequent requests echoes back the responder's
    /// `next_cursor`. Cursor is opaque to the wire — currently
    /// the `(lamport_ts, msg_id_first_byte)` of the last delivered
    /// envelope + 1 so the next scan resumes cleanly.
    pub cursor: Option<ReconcileCursor>,
    /// **Reserved** for future range-based set-reconciliation
    /// fingerprint (spec 14 / steady-state overlap case). v0.47.0
    /// always sends `Vec::new()`; responders interpret empty as
    /// "client has no data — bulk-send everything in window".
    #[serde(default)]
    pub fingerprint: Vec<u8>,
    /// **Reserved** for spec 14 completeness-proof comparison.
    /// `None` until spec 14 ships.
    #[serde(default)]
    pub epoch_root_known: Option<[u8; 32]>,
    /// Multi-round handshake counter — `0` on the first request,
    /// incremented per round. Reserved for the spec 14 multi-round
    /// fingerprint exchange; v0.47.0 always 0.
    #[serde(default)]
    pub round: u8,
}

/// Reconciliation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileResponse {
    /// Echoes the request's channel_id so the receiver can route
    /// without retaining per-request state when racing.
    pub channel_id: u64,
    /// Serialised MessagePack envelopes, sorted by `lamport_ts`
    /// ascending. Total size bounded by
    /// `[backfill] max_envelopes_per_response`.
    pub envelopes: Vec<Vec<u8>>,
    /// `true` when the responder hit the per-response cap before
    /// running out of envelopes in window. Client requests again
    /// with `next_cursor`.
    pub has_more: bool,
    /// Cursor for the next batch. `None` when `has_more = false`.
    pub next_cursor: Option<ReconcileCursor>,
    /// `true` when the responder hit its per-peer or per-channel
    /// rate limit. The `envelopes` field will be empty in this
    /// case; the client should back off ~30s and retry.
    pub server_capped: bool,
    /// **Reserved** for the spec 14 (channel, epoch) anchor root.
    /// `None` until spec 14 ships. Forward-compat: receivers that
    /// know the epoch root can hash the received envelope set into
    /// the same Merkle structure and compare for completeness.
    #[serde(default)]
    pub epoch_root: Option<[u8; 32]>,
}

/// Opaque-to-the-wire cursor for paging within a single
/// reconciliation. Encodes the last-delivered `(lamport_ts, msg_id)`
/// so the next scan resumes immediately after.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileCursor {
    pub after_lamport_ts: u64,
    pub after_msg_id: [u8; 32],
}

/// Server-side rate-limit state. One instance per `NetworkService`,
/// keyed internally by `(peer_id, channel_id)` and `peer_id`.
///
/// Uses `std::sync::Mutex` not tokio's because the critical section
/// is sub-microsecond (increment / decrement counters) and the
/// handler is on the swarm task — no `.await` while holding.
#[derive(Debug, Default)]
pub struct ResponderLimits {
    inner: Mutex<ResponderLimitsInner>,
}

#[derive(Debug, Default)]
struct ResponderLimitsInner {
    /// `peer_id` → number of active requests across all channels.
    per_peer: HashMap<libp2p::PeerId, usize>,
    /// `(peer_id, channel_id)` → number of active requests on that
    /// specific channel.
    per_pair: HashMap<(libp2p::PeerId, u64), usize>,
    /// `(peer_id, channel_id)` → cumulative envelopes served across
    /// all paginated requests in this process's lifetime. Used to
    /// enforce `[backfill] total_envelopes_cap` per session
    /// (Security Audit C2, 0.47.0). Per-process state — resets on
    /// restart. A legitimate peer that genuinely needs to
    /// re-backfill (e.g. after operator wiped the local db)
    /// regains access after we restart, which is acceptable
    /// behaviour for the threat surface.
    served: HashMap<(libp2p::PeerId, u64), u64>,
}

impl ResponderLimits {
    /// Try to reserve a slot. Returns the `Guard` on success;
    /// returns `None` when either cap is exhausted — caller should
    /// respond with `server_capped = true` and empty envelopes.
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: libp2p::PeerId,
        channel: u64,
        max_per_peer: usize,
        max_per_channel: usize,
        total_envelopes_cap: u64,
    ) -> Option<ResponderGuard> {
        let mut inner = self.inner.lock().ok()?;
        // Security Audit C2 (0.47.0): refuse if this (peer, channel)
        // session has already received `total_envelopes_cap`
        // envelopes — stops a malicious requester from inducing an
        // unbounded scan via repeated cursor paging.
        let served = inner.served.get(&(peer, channel)).copied().unwrap_or(0);
        if served >= total_envelopes_cap {
            return None;
        }
        // Read both counts without holding entry()-mutable borrows,
        // so we can release the per_peer borrow before reaching for
        // per_pair (borrow checker — both maps live in `inner`).
        let pp_current = inner.per_peer.get(&peer).copied().unwrap_or(0);
        if pp_current >= max_per_peer {
            return None;
        }
        let pc_current = inner
            .per_pair
            .get(&(peer, channel))
            .copied()
            .unwrap_or(0);
        if pc_current >= max_per_channel {
            return None;
        }
        inner.per_peer.insert(peer, pp_current + 1);
        inner.per_pair.insert((peer, channel), pc_current + 1);
        Some(ResponderGuard {
            limits: Arc::clone(self),
            peer,
            channel,
        })
    }

    /// Record envelopes served toward the (peer, channel) session
    /// cap. Called after a successful `build_response` produced
    /// `count` envelopes.
    pub fn add_served(&self, peer: libp2p::PeerId, channel: u64, count: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            let e = inner.served.entry((peer, channel)).or_insert(0);
            *e = e.saturating_add(count);
        }
    }
}

/// RAII guard — decrements the per-peer and per-(peer, channel)
/// counters on drop.
pub struct ResponderGuard {
    limits: Arc<ResponderLimits>,
    peer: libp2p::PeerId,
    channel: u64,
}

impl Drop for ResponderGuard {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.limits.inner.lock() {
            if let Some(v) = inner.per_peer.get_mut(&self.peer) {
                *v = v.saturating_sub(1);
                if *v == 0 {
                    inner.per_peer.remove(&self.peer);
                }
            }
            if let Some(v) = inner.per_pair.get_mut(&(self.peer, self.channel)) {
                *v = v.saturating_sub(1);
                if *v == 0 {
                    inner.per_pair.remove(&(self.peer, self.channel));
                }
            }
        }
    }
}

/// Cap on response payload size — enforces the
/// `[backfill] max_envelopes_per_response` operator knob plus a hard
/// ceiling so a misconfigured `usize::MAX` cannot OOM the responder.
pub const MAX_ENVELOPES_PER_RESPONSE_CEILING: usize = 50_000;

/// Build a [`ReconcileResponse`] for an inbound request by scanning
/// the local `CHANNEL_MSGS` index forward from the cursor.
///
/// The cap (`max_envelopes`) is the smaller of the operator-configured
/// `[backfill] max_envelopes_per_response` and
/// [`MAX_ENVELOPES_PER_RESPONSE_CEILING`].
pub fn build_response(
    storage: &Storage,
    request: &ReconcileRequest,
    max_envelopes: usize,
    now_unix: u64,
) -> ReconcileResponse {
    // Security Audit C1 (0.47.0): private channels are not served
    // via the reconcile protocol — the wire types don't carry the
    // signed `requester`/`proof` fields the existing
    // `network::sync::verify_private_channel_access` requires.
    // Until v0.47.x adds those auth fields, private-channel
    // history backfill MUST happen over the authenticated
    // `sync.rs::PrivateChannelMessages` path. Refuse with an
    // empty response so a malicious peer cannot pull ciphertext +
    // metadata for a channel they were never a member of.
    if is_private_channel(storage, request.channel_id) {
        debug!(
            channel_id = request.channel_id,
            "reconcile: private channel — refusing (use authenticated sync)"
        );
        return ReconcileResponse {
            channel_id: request.channel_id,
            envelopes: Vec::new(),
            has_more: false,
            next_cursor: None,
            // Use server_capped to signal "go away" without
            // disclosing whether the channel exists or not.
            server_capped: true,
            epoch_root: None,
        };
    }

    let cap = max_envelopes.min(MAX_ENVELOPES_PER_RESPONSE_CEILING);

    // Window-filter cutoff in unix seconds. `u64::MAX` request value
    // means "archive mode — no filter"; we represent that by setting
    // the cutoff to 0 so every envelope passes.
    let min_timestamp = if request.max_age_secs == u64::MAX {
        0
    } else {
        now_unix.saturating_sub(request.max_age_secs)
    };

    // Build the prefix from channel_id. CHANNEL_MSGS keys are
    // `(channel_id:8, lamport_ts:8, msg_id:32)`. Forward iteration is
    // sorted ascending by `(lamport_ts, msg_id)` — which is the
    // natural delivery order.
    let prefix = request.channel_id.to_be_bytes();

    // Read with a small over-fetch so we can detect "iteration hit
    // the cap" vs "iteration ran out of channel rows".
    let probe_limit = cap.saturating_add(1);

    // Code Audit C1 (0.47.0): paging requires a seek-from-cursor
    // iterator. The earlier implementation used `prefix_iter_cf`
    // (which always starts at the channel prefix) plus a post-skip
    // of the cursor — that returned the SAME first 1000 rows on
    // every page and the cursor filter dropped them all, leaving
    // the responder stuck on page 1 forever. Use the existing
    // `prefix_iter_cf_after` helper which RocksDB-seeks to the
    // start key, so paging is O(cap) per request regardless of
    // depth instead of O(N) post-skip.
    let rows = if let Some(c) = request.cursor.as_ref() {
        let start_key = schema::encode_channel_msg_key(
            request.channel_id,
            c.after_lamport_ts,
            &c.after_msg_id,
        );
        storage.prefix_iter_cf_after(
            schema::cf::CHANNEL_MSGS,
            &start_key,
            &prefix,
            probe_limit,
        )
    } else {
        storage.prefix_iter_cf(schema::cf::CHANNEL_MSGS, &prefix, probe_limit)
    };
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            warn!(
                channel_id = request.channel_id,
                error = %e,
                "reconcile: CHANNEL_MSGS iteration failed"
            );
            return ReconcileResponse {
                channel_id: request.channel_id,
                envelopes: Vec::new(),
                has_more: false,
                next_cursor: None,
                server_capped: false,
                epoch_root: None,
            };
        }
    };

    let mut envelopes: Vec<Vec<u8>> = Vec::with_capacity(cap);

    // P-3b: on the FIRST page, ride the channel's L2 metadata + membership
    // envelopes (ChannelCreate/Update/Join/Leave) along with the chat history.
    // The chain scanner only writes a skeleton (slug/creator), so this is how a
    // node that chain-discovered a public channel gets its name/logo/members.
    // These are re-validated + applied by the requester like any synced
    // envelope (ChannelCreate apply is now merge-safe). Counted separately so
    // the chat `cap` below is unaffected.
    if request.cursor.is_none() {
        envelopes.extend(channel_meta_envelopes(storage, request.channel_id));
    }

    let mut last_cursor: Option<ReconcileCursor> = None;
    let mut hit_cap = false;
    let mut chat_count = 0usize;

    for (key, _val) in rows {
        // Key layout from `encode_channel_msg_key`:
        // [0..8] channel_id, [8..16] lamport_ts, [16..48] msg_id.
        if key.len() != 48 {
            // Corrupt index row — skip silently. The matching
            // MESSAGES read below would also fail.
            continue;
        }
        let lamport_ts = u64::from_be_bytes(key[8..16].try_into().unwrap_or([0; 8]));
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&key[16..48]);

        // Fetch the envelope, deserialise enough to check the
        // wall-clock timestamp for the window filter.
        let raw = match storage.get_message(&msg_id) {
            Ok(Some(b)) => b,
            Ok(None) => continue, // Index row without matching message — skip.
            Err(e) => {
                warn!(
                    msg_id = %hex::encode(msg_id),
                    error = %e,
                    "reconcile: get_message failed"
                );
                continue;
            }
        };
        let env: Envelope = match rmp_serde::from_slice(&raw) {
            Ok(e) => e,
            Err(_) => continue, // Stored bytes don't decode — skip.
        };

        // `envelope.timestamp` is millis-since-epoch in the existing
        // protocol — divide by 1000 to compare against the
        // unix-seconds cutoff.
        let env_secs = env.timestamp / 1000;
        if env_secs < min_timestamp {
            continue;
        }

        envelopes.push(raw);
        chat_count += 1;
        last_cursor = Some(ReconcileCursor {
            after_lamport_ts: lamport_ts,
            after_msg_id: msg_id,
        });

        if chat_count >= cap {
            hit_cap = true;
            break;
        }
    }

    // Audit final pre-mainnet W6: ride edit/delete envelopes along on the
    // session's LAST chat page only (`!hit_cap`). All pages of one reconcile
    // session are requested/applied strictly in order against a single
    // peer, so by the time this is the last page every original message the
    // session could have delivered has already been applied — which
    // `authorize_edit_delete` requires before an edit/delete can be accepted.
    if !hit_cap {
        envelopes.extend(channel_edit_delete_envelopes(
            storage,
            request.channel_id,
            min_timestamp,
        ));
    }

    ReconcileResponse {
        channel_id: request.channel_id,
        envelopes,
        has_more: hit_cap,
        next_cursor: if hit_cap { last_cursor } else { None },
        server_capped: false,
        epoch_root: None,
    }
}

/// Gather a channel's L2 metadata + membership envelopes (P-3b) to ride along
/// with the first reconcile page. ChannelCreate (0x10) / ChannelUpdate (0x11)
/// — which carry display_name/logo_cid/description — sort before
/// ChannelJoin/Leave in the `CHANNEL_META_MSGS` key (msg_type is the second
/// key field), so the name/logo are always included even if a large membership
/// list is truncated at the cap. Bounded; the requester re-validates each
/// envelope through `process_synced_message`.
fn channel_meta_envelopes(storage: &Storage, channel_id: u64) -> Vec<Vec<u8>> {
    const CHANNEL_META_CAP: usize = 256;
    let prefix = channel_id.to_be_bytes();
    let rows = match storage.prefix_iter_cf(
        schema::cf::CHANNEL_META_MSGS,
        &prefix,
        CHANNEL_META_CAP,
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (key, _) in rows {
        // key: channel_id:8 ++ msg_type:1 ++ ts:8 ++ msg_id:32 = 49 bytes.
        if key.len() != 8 + 1 + 8 + 32 {
            continue;
        }
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&key[17..49]);
        if let Ok(Some(raw)) = storage.get_message(&msg_id) {
            out.push(raw);
        }
    }
    out
}

/// Gather a channel's `ChatEdit`/`ChatDelete` envelopes (audit final
/// pre-mainnet W6) to ride along on the LAST page of a reconcile session.
/// Without this, edit/delete envelopes never reach a backfilling node at
/// all — the primary `CHANNEL_MSGS` scan above only ever contains original
/// `ChatMessage` rows — so "deleted for everyone" content is re-served
/// forever by any fresh/cold-joining node. Unlike `channel_meta_envelopes`
/// (which rides the FIRST page), this rides the LAST page (`build_response`
/// only calls it when `!hit_cap`): all pages of one reconcile session are
/// requested/applied strictly in order against a single peer, so by the
/// last page every original message the session could have delivered has
/// already been applied — which `authorize_edit_delete` requires before an
/// edit/delete can be accepted (it looks up the target by `target_id` and
/// hard-rejects if missing). Bounded + best-effort, same tradeoff already
/// accepted for `channel_meta_envelopes`: a channel with more markers than
/// the cap just doesn't get its oldest excess markers this session (they'll
/// still arrive via live gossip for anything edited/deleted going forward).
fn channel_edit_delete_envelopes(
    storage: &Storage,
    channel_id: u64,
    min_timestamp: u64,
) -> Vec<Vec<u8>> {
    const CHANNEL_EDIT_DELETE_CAP: usize = 2_000;
    let prefix = channel_id.to_be_bytes();
    // Security-audit follow-up (2026-08-18): `CHANNEL_EDIT_DELETE_MSGS` keys
    // use a forward (non-negated) timestamp, so a FORWARD prefix scan is
    // oldest-first — `.take(cap)` on that would silently drop the NEWEST
    // excess markers under overflow, exactly backwards from the intent (and
    // from what the warning below claims). Reverse-scan from the upper
    // bound instead so overflow drops the OLDEST markers, matching
    // `news_edit_delete_envelopes` (whose `!timestamp`-negated keys make a
    // forward scan newest-first there).
    let rows = match storage.reverse_iter_cf(
        schema::cf::CHANNEL_EDIT_DELETE_MSGS,
        &schema::message_key_upper_bound(&prefix),
        &prefix,
        CHANNEL_EDIT_DELETE_CAP.saturating_add(1),
    ) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    if rows.len() > CHANNEL_EDIT_DELETE_CAP {
        warn!(
            channel_id,
            cap = CHANNEL_EDIT_DELETE_CAP,
            "reconcile: channel has more edit/delete markers than the ride-along cap; \
             oldest excess markers were not shipped this session"
        );
    }
    let mut out = Vec::new();
    for (key, _) in rows.into_iter().take(CHANNEL_EDIT_DELETE_CAP) {
        // Key shape matches CHANNEL_MSGS: channel_id:8 ++ timestamp:8 ++ msg_id:32.
        if key.len() != 48 {
            continue;
        }
        let ts_ms = u64::from_be_bytes(match key[8..16].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        });
        if ts_ms / 1000 < min_timestamp {
            continue;
        }
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&key[16..48]);
        if let Ok(Some(raw)) = storage.get_message(&msg_id) {
            out.push(raw);
        }
    }
    out
}

/// Inspect the `CHANNELS` metadata row for `channel_id` and return
/// `true` if it is marked `channel_type = 2` (private). Used by
/// [`build_response`] to refuse private-channel history over the
/// unauthenticated reconcile path. Returns `false` for unknown
/// channels (we don't have metadata yet) — those go through the
/// normal scan, but `CHANNEL_MSGS` will be empty for them anyway so
/// the response is empty regardless.
///
/// Mirrors `crate::messages::router::is_private_channel_meta` and
/// the inline check at `crate::storage::rocks::Storage::is_local_anchor`.
fn is_private_channel(storage: &Storage, channel_id: u64) -> bool {
    let key = channel_id.to_be_bytes();
    let bytes = match storage.get_cf(schema::cf::CHANNELS, &key) {
        Ok(Some(b)) => b,
        _ => return false,
    };
    let meta: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    matches!(
        meta.get("channel_type").and_then(|v| v.as_u64()),
        Some(2)
    )
}

/// Construct a `server_capped` response (no envelopes) — used when the
/// per-peer or per-channel rate limit denies the request.
pub fn capped_response(request: &ReconcileRequest) -> ReconcileResponse {
    ReconcileResponse {
        channel_id: request.channel_id,
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: true,
        epoch_root: None,
    }
}

#[cfg(test)]
mod edit_delete_ride_along_tests {
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{ChatMessagePayload, DeletePayload, MessageType};
    use crate::storage::rocks::Storage;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn put_chat_message(s: &Storage, channel_id: u64, msg_id: [u8; 32], ts: u64) {
        let payload = ChatMessagePayload {
            channel_id,
            content: "hi".to_string(),
            content_rating: Default::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: None,
            enc_nonce: None,
            key_epoch: None,
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id,
            author: "klv1author".to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(
            schema::cf::CHANNEL_MSGS,
            &schema::encode_channel_msg_key(channel_id, ts, &msg_id),
            &[],
        )
        .unwrap();
        s.put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn put_chat_delete(s: &Storage, channel_id: u64, target_id: [u8; 32], msg_id: [u8; 32], ts: u64) {
        let payload = DeletePayload {
            target_id,
            channel_id: Some(channel_id),
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatDelete,
            msg_id,
            author: "klv1author".to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(
            schema::cf::CHANNEL_EDIT_DELETE_MSGS,
            &schema::encode_channel_msg_key(channel_id, ts, &msg_id),
            &[],
        )
        .unwrap();
        s.put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn contains_type(envelopes: &[Vec<u8>], msg_type: MessageType) -> bool {
        envelopes.iter().any(|e| {
            rmp_serde::from_slice::<Envelope>(e)
                .map(|env| env.msg_type == msg_type)
                .unwrap_or(false)
        })
    }

    /// Regression for audit final pre-mainnet W6: without the ride-along,
    /// a fresh node backfilling via reconcile would receive the 3 original
    /// ChatMessages but never learn `[1u8;32]` was deleted — "deleted for
    /// everyone" content resurfaces on every cold-joining node. Also proves
    /// the ordering constraint: the ride-along must NOT appear on a
    /// non-final (capped) page, since the target might not have been
    /// delivered yet.
    #[test]
    fn ride_along_only_appears_on_the_final_page() {
        let (s, _d) = db();
        let channel_id = 77u64;
        for i in 0..3u64 {
            put_chat_message(&s, channel_id, [i as u8 + 1; 32], 1_000 + i);
        }
        put_chat_delete(&s, channel_id, [1u8; 32], [9u8; 32], 2_000);

        // Page 1: cap=2 chat messages (< 3 total) → hits cap → no ride-along.
        let req1 = ReconcileRequest {
            channel_id,
            max_age_secs: u64::MAX,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };
        let resp1 = build_response(&s, &req1, 2, 5_000);
        assert!(resp1.has_more, "page 1 should be capped (2 of 3 messages)");
        assert!(
            !contains_type(&resp1.envelopes, MessageType::ChatDelete),
            "delete must not ride along on a non-final page"
        );

        // Page 2 (final): remaining 1 chat message, under cap → ride-along present.
        let req2 = ReconcileRequest {
            channel_id,
            max_age_secs: u64::MAX,
            cursor: resp1.next_cursor,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };
        let resp2 = build_response(&s, &req2, 2, 5_000);
        assert!(!resp2.has_more, "page 2 should be the final page");
        assert!(
            contains_type(&resp2.envelopes, MessageType::ChatDelete),
            "delete must ride along on the final page"
        );
    }

    /// A small channel that fits entirely on page 1 (never hits the cap)
    /// gets the ride-along immediately — the gate is `!hit_cap`, not "page
    /// 2 specifically".
    #[test]
    fn ride_along_present_on_a_single_page_session() {
        let (s, _d) = db();
        let channel_id = 78u64;
        put_chat_message(&s, channel_id, [1u8; 32], 1_000);
        put_chat_delete(&s, channel_id, [1u8; 32], [9u8; 32], 2_000);

        let req = ReconcileRequest {
            channel_id,
            max_age_secs: u64::MAX,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };
        let resp = build_response(&s, &req, 500, 5_000);
        assert!(!resp.has_more);
        assert!(contains_type(&resp.envelopes, MessageType::ChatDelete));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    fn fake_peer() -> PeerId {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        kp.public().to_peer_id()
    }

    #[test]
    fn protocol_string_includes_network_id() {
        assert_eq!(
            protocol_string("mainnet"),
            "/ogmara/mainnet/channel-reconcile/1.0.0"
        );
    }

    #[test]
    fn responder_limits_enforce_per_pair_cap() {
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        let g1 = limits
            .try_acquire(peer, 42, 4, 1, u64::MAX)
            .expect("first acquire must succeed");
        let g2 = limits.try_acquire(peer, 42, 4, 1, u64::MAX);
        assert!(
            g2.is_none(),
            "per-pair cap = 1 must reject second concurrent request"
        );
        drop(g1);
        let g3 = limits
            .try_acquire(peer, 42, 4, 1, u64::MAX)
            .expect("after drop, slot is free again");
        drop(g3);
    }

    #[test]
    fn responder_limits_enforce_per_peer_cap() {
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        // Four distinct channels under a per_peer cap of 4 + per_pair
        // cap of 1 — all four succeed.
        let _g1 = limits.try_acquire(peer, 1, 4, 1, u64::MAX).expect("ch1");
        let _g2 = limits.try_acquire(peer, 2, 4, 1, u64::MAX).expect("ch2");
        let _g3 = limits.try_acquire(peer, 3, 4, 1, u64::MAX).expect("ch3");
        let _g4 = limits.try_acquire(peer, 4, 4, 1, u64::MAX).expect("ch4");
        // Fifth channel is denied by the per-peer cap.
        let g5 = limits.try_acquire(peer, 5, 4, 1, u64::MAX);
        assert!(g5.is_none(), "per-peer cap = 4 must reject 5th channel");
    }

    #[test]
    fn responder_limits_isolate_peers() {
        let limits = Arc::new(ResponderLimits::default());
        let alice = fake_peer();
        let bob = fake_peer();
        let _g1 = limits
            .try_acquire(alice, 1, 1, 1, u64::MAX)
            .expect("alice first");
        // Bob has his own per-peer budget.
        let g2 = limits.try_acquire(bob, 1, 1, 1, u64::MAX);
        assert!(
            g2.is_some(),
            "per-peer caps must NOT interfere across peers"
        );
    }

    #[test]
    fn responder_limits_enforce_total_envelopes_cap() {
        // Security Audit C2 (0.47.0): the cumulative envelopes-served
        // per (peer, channel) is bounded by `total_envelopes_cap`
        // across all paginated requests in this process, regardless
        // of how the peer paces them.
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        let g1 = limits
            .try_acquire(peer, 7, 4, 1, 100)
            .expect("first request must succeed");
        limits.add_served(peer, 7, 50);
        drop(g1);
        // Second request — cumulative 50 < cap 100 — still succeeds,
        // serves another 60. Cumulative jumps to 110, over the cap.
        let g2 = limits
            .try_acquire(peer, 7, 4, 1, 100)
            .expect("served 50 < cap 100, second request must succeed");
        limits.add_served(peer, 7, 60);
        drop(g2);
        // Third request — cumulative 110 >= cap 100 — must be denied.
        let g3 = limits.try_acquire(peer, 7, 4, 1, 100);
        assert!(
            g3.is_none(),
            "served 110 >= cap 100 must refuse subsequent requests"
        );
    }

    #[test]
    fn responder_limits_per_pair_served_isolated() {
        // The cumulative-envelopes cap is per (peer, channel) — a
        // peer that exhausted channel A's budget can still backfill
        // channel B.
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        limits.add_served(peer, 1, 200);
        let g_a = limits.try_acquire(peer, 1, 4, 1, 100);
        assert!(g_a.is_none(), "channel 1 exhausted");
        let g_b = limits
            .try_acquire(peer, 2, 4, 1, 100)
            .expect("channel 2 untouched");
        drop(g_b);
    }

    #[test]
    fn capped_response_signals_back_off() {
        let req = ReconcileRequest {
            channel_id: 7,
            max_age_secs: 86400,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };
        let resp = capped_response(&req);
        assert_eq!(resp.channel_id, 7);
        assert!(resp.envelopes.is_empty());
        assert!(resp.server_capped);
        assert!(!resp.has_more);
        assert!(resp.next_cursor.is_none());
    }

    #[test]
    fn cursor_compares_lexicographically() {
        // The cursor comparison is `(lamport_ts, msg_id) <= (cursor_lamport,
        // cursor_id)` — verify the tuple ordering is correct.
        let a = (10u64, [0u8; 32]);
        let b = (11u64, [0u8; 32]);
        let c = (10u64, [0xffu8; 32]);
        assert!(a < b);
        assert!(a < c);
        assert!(c < b);
    }

    #[test]
    fn request_default_round_is_zero() {
        let req = ReconcileRequest {
            channel_id: 1,
            max_age_secs: 86400,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };
        assert_eq!(req.round, 0);
        assert!(req.fingerprint.is_empty());
        assert!(req.epoch_root_known.is_none());
    }
}
