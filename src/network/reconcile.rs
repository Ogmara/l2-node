//! Channel-history reconciliation protocol (spec 1, l2-node 0.47.0+).
//!
//! Closes B1 in `docs/planning/mainnet-blockers-fix-plan.md`: fresh
//! nodes joining an existing channel were left with empty
//! `CHANNEL_MSGS` indexes — gossip catches future messages but never
//! backfills history. This module implements the cold-join backfill:
//! on `subscribe_channel(channel_id)` (every startup, and whenever the
//! chain scanner re-touches the channel), the node requests the
//! missing history from up to `fanout` peers in parallel, compares
//! their first-page responses rather than racing to whichever answers
//! first (l2-node 0.137.0 — see `NetworkService::finalize_reconcile_
//! comparison`), and pages through cursor-based batches with the
//! chosen candidate until it signals `has_more = false`.
//!
//! **Trigger condition** (`NetworkService::maybe_trigger_backfill`,
//! rewritten 2026-09-30): fires whenever `storage::schema::cf::
//! CHANNEL_BACKFILL_STATE` has no completion timestamp for the channel,
//! or the last completion is older than `[backfill]
//! channel_catchup_interval_hours` — NOT "does the channel have zero
//! local messages". The earlier any-row check flipped permanently
//! false (locking out backfill for the process's lifetime) the moment
//! a single message arrived via live gossip ahead of a full backfill,
//! leaving a channel stuck at whatever partial history it had at that
//! instant. A periodic sweep (`retry_incomplete_channel_backfills`,
//! piggybacked on the 30s bootstrap tick) also re-evaluates every
//! channel on a rotating cursor, so an incomplete channel keeps
//! getting retried without needing a restart.
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
//! empty envelopes. The requester ends that session there (there is no
//! in-session retry); the channel is tried again by a later backfill
//! sweep, from the first page. The per-peer/per-channel limits never
//! queue or block. Only the node-wide build-slot bound lets a
//! CONTINUATION page (cursor present) wait briefly for a slot instead of
//! being refused (round-5 C-W1, `network::MAX_CONCURRENT_RESPONDER_BUILDS`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::messages::envelope::Envelope;
use crate::messages::types::MessageType;
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

impl ReconcileRequest {
    /// A page AFTER the first of its session (round-5 C-W1): it carries the
    /// responder's `next_cursor`. Only a non-continuation (first-page)
    /// request is refused outright when every responder build slot is
    /// busy. The claim is the requester's own (cursors are not
    /// authenticated) — the wait it earns is bounded separately
    /// (`network::MAX_CONTINUATION_BUILD_WAITERS`).
    pub fn is_continuation(&self) -> bool {
        self.cursor.is_some()
    }
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
///
/// (Test convenience wrapper — production calls the `_metered` variant,
/// which also returns the work done.)
#[cfg(test)]
pub fn build_response(
    storage: &Storage,
    request: &ReconcileRequest,
    max_envelopes: usize,
    now_unix: u64,
) -> ReconcileResponse {
    build_response_metered(storage, request, max_envelopes, now_unix).0
}

/// `build_response` plus the storage work it did (one unit per seek and per
/// index row examined, ride-alongs included), for the responder's per-peer
/// budget (`budget_charge`). Runs off the swarm event loop
/// (`tokio::task::spawn_blocking`, see `NetworkService::
/// handle_reconcile_event`).
pub fn build_response_metered(
    storage: &Storage,
    request: &ReconcileRequest,
    max_envelopes: usize,
    now_unix: u64,
) -> (ReconcileResponse, u64) {
    // Security Audit C1 (0.47.0): private channels are not served
    // via the reconcile protocol — the wire types don't carry any
    // signed requester/proof fields, so there is no way to verify
    // the requester is actually a member. This refusal MUST stay
    // regardless of what (if anything) handles private-channel
    // history backfill elsewhere — refuse with an empty response so
    // a malicious peer cannot pull ciphertext + metadata for a
    // channel they were never a member of.
    //
    // Audit final pre-mainnet W8 (2026-08-19): the authenticated
    // alternative this comment used to point to
    // (`sync.rs::PrivateChannelMessages`, an authenticated libp2p
    // request-response path) was removed — confirmed unreachable,
    // no caller anywhere in the org ever constructed one. That means
    // there is currently NO working mechanism for a node to backfill
    // a private channel's message HISTORY it missed while offline
    // (live delivery still works via GossipSub once (re)joined; key
    // material still delivers via `PrivateChannelKeyDistribution`).
    // This is a real, pre-existing functional gap — not introduced by
    // removing dead code that nothing called — flagged for a future
    // session, not fixed here.
    if is_private_channel(storage, request.channel_id) {
        debug!(
            channel_id = request.channel_id,
            "reconcile: private channel — refusing (use authenticated sync)"
        );
        return (
            ReconcileResponse {
                channel_id: request.channel_id,
                envelopes: Vec::new(),
                has_more: false,
                next_cursor: None,
                // Use server_capped to signal "go away" without
                // disclosing whether the channel exists or not.
                server_capped: true,
                epoch_root: None,
            },
            1,
        );
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

    // KNOWN LIMITATION (code-audit finding, round 4, 2026-09-30) — not
    // fixed in this pass, recorded here so it isn't lost. `probe_limit`
    // bounds RAW rows fetched, not ELIGIBLE ones, and iteration is always
    // ascending from the OLDEST message (or from the cursor). If a
    // channel accumulates more than `probe_limit` (default 1001)
    // messages older than `request.max_age_secs`'s window (CHANNEL_MSGS
    // has no age-based reaper — old rows persist indefinitely) AND the
    // requester's window is finite (the default `[backfill] max_age_days
    // = 30`, not `u64::MAX`), the FIRST page (`cursor: None`) can fetch
    // only stale, out-of-window rows: every one hits the `env_secs <
    // min_timestamp` skip below, so `chat_count` never leaves 0 and the
    // response comes back `envelopes: [], has_more: false` —
    // indistinguishable from a genuinely-empty channel. The requester
    // (`NetworkService`'s reconcile handler) treats that shape as
    // uninformative and never supplies a cursor to page past the stale
    // prefix, so recent, genuinely in-window history can never be
    // delivered to a cold-joining node for such a channel — deterministic
    // and permanent for as long as the condition holds, the same failure
    // class this whole feature (l2-node 0.136.0) exists to close, just
    // reached via the time-window filter instead of the count cap.
    //
    // Not reachable at this project's current scale (requires substantial
    // real usage older than the window before this trips) and has an
    // immediate operator-level mitigation today: set `[backfill]
    // max_age_days = 18446744073709551615` (u64::MAX / "archive mode, no
    // time filter") — with no window filter to skip past, the ascending
    // scan reaches eligible rows normally regardless of table size. A
    // real fix needs `build_response` to keep scanning forward (bounded
    // by a raw-row budget larger than `cap`, with its own cursor
    // progress independent of whether anything eligible was found yet)
    // rather than a single `probe_limit`-sized fetch — deferred as a
    // separate, scoped follow-up rather than expanding this pass further.

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
            return (
                ReconcileResponse {
                    channel_id: request.channel_id,
                    envelopes: Vec::new(),
                    has_more: false,
                    next_cursor: None,
                    server_capped: false,
                    epoch_root: None,
                },
                1,
            );
        }
    };
    // Budget (one unit per seek and per index row examined, its MESSAGES
    // read included — `budget_charge`).
    let mut work: u64 = 1 + rows.len() as u64;

    let mut envelopes: Vec<Vec<u8>> = Vec::with_capacity(cap);

    // P-3b: on the FIRST page, ride the channel's L2 metadata + membership
    // envelopes (ChannelCreate/Update/Join/Leave) along with the chat history.
    // The chain scanner only writes a skeleton (slug/creator), so this is how a
    // node that chain-discovered a public channel gets its name/logo/members.
    // These are re-validated + applied by the requester like any synced
    // envelope (ChannelCreate apply is now merge-safe). Counted separately so
    // the chat `cap` below is unaffected.
    if request.cursor.is_none() {
        let (meta, meta_work) =
            channel_meta_envelopes_metered(storage, request.channel_id, CHANNEL_META_CAP);
        work += meta_work;
        envelopes.extend(meta);
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

        // Code-audit finding (2026-09-30): the old check here was
        // `if chat_count >= cap { hit_cap = true; break; }` AFTER
        // pushing — which set `hit_cap = true` the instant `cap`
        // qualifying rows had been pushed, regardless of whether a
        // genuine `(cap+1)`-th qualifying row actually followed. Any
        // channel whose eligible history landed EXACTLY on `cap` (the
        // default `max_envelopes_per_response` is 1000) got a false
        // `has_more = true`, forcing a pointless extra round-trip that
        // comes back empty+`has_more=false` — which the requester's
        // `NetworkService` (l2-node 0.136.0) treats as "uninformative,
        // ignore" rather than "session complete," so
        // `mark_channel_backfill_complete` never fires despite every
        // real envelope having already been correctly delivered and
        // accepted on the first page. That left such a channel
        // re-fanned-out by the periodic retry sweep forever, since
        // subsequent attempts see the same page as all-`Duplicate` and
        // never accumulate `total_accepted` either.
        //
        // Fix: `probe_limit` already over-fetches by one row precisely
        // so this can be checked correctly. Only declare `hit_cap` once
        // a genuine ADDITIONAL qualifying row is found beyond the first
        // `cap` — check BEFORE pushing/counting/advancing the cursor,
        // so the boundary row itself is never counted twice and the
        // cursor never advances past the last row actually returned.
        if chat_count >= cap {
            hit_cap = true;
            break;
        }

        envelopes.push(raw);
        chat_count += 1;
        last_cursor = Some(ReconcileCursor {
            after_lamport_ts: lamport_ts,
            after_msg_id: msg_id,
        });
    }

    // Audit final pre-mainnet W6: ride edit/delete envelopes along on the
    // session's LAST chat page only (`!hit_cap`). All pages of one reconcile
    // session are requested/applied strictly in order against a single
    // peer, so by the time this is the last page every original message the
    // session could have delivered has already been applied — which
    // `authorize_edit_delete` requires before an edit/delete can be accepted.
    if !hit_cap {
        let (ed, ed_work) = channel_edit_delete_envelopes_metered(
            storage,
            request.channel_id,
            min_timestamp,
            CHANNEL_EDIT_DELETE_CAP,
        );
        work += ed_work;
        envelopes.extend(ed);
    }

    (
        ReconcileResponse {
            channel_id: request.channel_id,
            envelopes,
            has_more: hit_cap,
            next_cursor: if hit_cap { last_cursor } else { None },
            server_capped: false,
            epoch_root: None,
        },
        work,
    )
}

/// Upper bound on metadata envelopes `channel_meta_envelopes` returns.
pub(crate) const CHANNEL_META_CAP: usize = 256;

/// Replay tiers of a channel's `CHANNEL_META_MSGS` rows (round-4, l2-node
/// 0.140.0). Serving order = replay order, because the requester applies a
/// response's envelopes strictly in vector order through
/// `process_synced_message`:
///
/// - **Tier 0: `ChannelCreate` only**, always first regardless of `ts`. A
///   PURE timestamp sort would let a `ChannelJoin`/`ChannelKick`/etc with an
///   (unvalidated on the sync path) earlier `ts` replay BEFORE the channel
///   exists — `add_channel_member` / the removal apply are no-ops without a
///   `CHANNELS` row, and the envelope is then deduped, so the effect would
///   be lost for good.
/// - **Tier 1: everything else, by `(ts, msg_id)`** — `ChannelUpdate`,
///   `ChannelJoin`/`Leave`, `ChannelAddModerator`/`RemoveModerator`,
///   `ChannelKick`/`Ban`/`Unban`, `ChannelDelete`. Chronological replay is
///   what reproduces the responder's state: the router authorises a
///   moderator's kick/ban/unban/update and a moderator-signed invite
///   against the moderator record AT REPLAY TIME, so each must replay after
///   the grant that authorised it and before any later demotion (audit B1);
///   and `ChannelBan`(0x17) < `ChannelUnban`(0x18) in key order, so key
///   order would replay ban@1, ban@3, unban@2 and converge "unbanned"
///   (W12). `ChannelUpdate` used to be tier 0 (with Create): that replayed
///   a MODERATOR's update before the `ChannelAddModerator` that authorises
///   it, so a fresh requester rejected it — it is chronological now.
///
/// Security-audit residual (unchanged, recorded): `ts` is the originating
/// envelope's self-reported timestamp, which the sync ingest path does not
/// drift-check, so a backfilled far-future envelope sorts last on every
/// serve. Every affected type is still authorised against the RECEIVING
/// node's state at replay, so this is ordering, not privilege.
pub(crate) const META_REPLAY_TIERS: [&[u8]; 2] = [
    &[MessageType::ChannelCreate as u8],
    &[
        MessageType::ChannelUpdate as u8,
        MessageType::ChannelJoin as u8,
        MessageType::ChannelLeave as u8,
        MessageType::ChannelAddModerator as u8,
        MessageType::ChannelRemoveModerator as u8,
        MessageType::ChannelKick as u8,
        MessageType::ChannelBan as u8,
        MessageType::ChannelUnban as u8,
        MessageType::ChannelDelete as u8,
    ],
];

/// Selection priority of the BOUNDED metadata ride-along
/// (`channel_meta_envelopes`: public reconcile's first page and the legacy
/// first page of private-channel sync). Identity and persistent removals
/// first, then the moderator records (creator-only, low volume — all of
/// them fit before anything high-volume), then `ChannelUpdate` AHEAD of
/// the cheap, high-volume `ChannelJoin`/`ChannelLeave` (round-4 B2': ~256
/// joins to a public channel used to push every update out), and
/// `ChannelLeave` AHEAD of `ChannelJoin` (round-5 C-N4): a leave REMOVES
/// access, so when the cap is hit the requester must learn who left before
/// learning who joined — the reverse order let a join flood push every leave
/// out and a requester then kept leavers as members.
const RIDE_ALONG_PRIORITY: [MessageType; 10] = [
    MessageType::ChannelCreate,
    MessageType::ChannelDelete,
    MessageType::ChannelRemoveModerator,
    MessageType::ChannelAddModerator,
    MessageType::ChannelKick,
    MessageType::ChannelBan,
    MessageType::ChannelUnban,
    MessageType::ChannelUpdate,
    MessageType::ChannelLeave,
    MessageType::ChannelJoin,
];

/// Replay tier of a `CHANNEL_META_MSGS` msg_type byte (see
/// `META_REPLAY_TIERS`).
fn replay_tier(msg_type: u8) -> u8 {
    if msg_type == MessageType::ChannelCreate as u8 {
        0
    } else {
        1
    }
}

/// Parse a `CHANNEL_META_MSGS` key (`channel_id:8 ++ msg_type:1 ++ ts:8 ++
/// msg_id:32`) into `(msg_type, ts, msg_id)`; `None` if malformed.
fn parse_meta_key(key: &[u8]) -> Option<(u8, u64, [u8; 32])> {
    if key.len() != 8 + 1 + 8 + 32 {
        return None;
    }
    let ts = u64::from_be_bytes(key[9..17].try_into().ok()?);
    let mut msg_id = [0u8; 32];
    msg_id.copy_from_slice(&key[17..49]);
    Some((key[8], ts, msg_id))
}

/// A BOUNDED selection of a channel's metadata envelopes, in replay order —
/// the ride-along for public reconcile's first page and for an older
/// private-channel-sync requester's first page (P-3b; the full, unbounded
/// set is only served by metadata paging, `channel_meta_page`).
///
/// Raw rows (round 4). The cap is applied to the INPUT
/// selection, never by truncating a replay-sorted list (that would cut by
/// timestamp and drop the newest kicks/bans first): rows are taken type by
/// type in `RIDE_ALONG_PRIORITY` order — newest-first within a type, except
/// `ChannelCreate` oldest-first (the genuine create precedes any contested
/// one) — until `cap` (≤ `CHANNEL_META_CAP`) rows are chosen, and only the
/// chosen rows are sorted into replay order `(tier, ts, msg_id)`. Each type
/// is read with one bounded seek, so the cost is O(cap + types), not a scan
/// of the channel's history. A row whose `MESSAGES` entry is gone is
/// skipped; undecodable stored bytes are forwarded as-is for the requester
/// to validate.
///
/// (Test convenience wrapper — production calls the `_metered` variant,
/// which also returns the work done.)
#[cfg(test)]
pub(crate) fn channel_meta_envelopes(storage: &Storage, channel_id: u64, cap: usize) -> Vec<Vec<u8>> {
    channel_meta_envelopes_metered(storage, channel_id, cap).0
}

/// `channel_meta_envelopes` plus the storage work it did (one unit per seek
/// and per index row read, its `MESSAGES` read included), for the
/// responder budget.
pub(crate) fn channel_meta_envelopes_metered(
    storage: &Storage,
    channel_id: u64,
    cap: usize,
) -> (Vec<Vec<u8>>, u64) {
    let cap = cap.min(CHANNEL_META_CAP);
    let mut work: u64 = 0;
    let mut chosen: Vec<(u8, u64, [u8; 32])> = Vec::with_capacity(cap);
    for msg_type in RIDE_ALONG_PRIORITY {
        let room = cap.saturating_sub(chosen.len());
        if room == 0 {
            break;
        }
        let mut prefix = channel_id.to_be_bytes().to_vec();
        prefix.push(msg_type as u8);
        let got = if msg_type == MessageType::ChannelCreate {
            storage.prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &prefix, room)
        } else {
            let mut upper = prefix.clone();
            upper.extend_from_slice(&[0xFFu8; 40]);
            storage.reverse_iter_cf(schema::cf::CHANNEL_META_MSGS, &upper, &prefix, room)
        };
        work += 1;
        let Ok(got) = got else { continue };
        work += got.len() as u64;
        chosen.extend(got.iter().filter_map(|(k, _)| parse_meta_key(k)).map(|(t, ts, id)| (replay_tier(t), ts, id)));
    }
    chosen.sort();
    let envelopes = chosen
        .into_iter()
        .filter_map(|(_, _, id)| storage.get_message(&id).ok().flatten())
        .collect();
    (envelopes, work)
}

/// Keyset cursor into a channel's metadata in replay order — the position
/// of the LAST row served (served or skipped because its `MESSAGES` entry
/// was gone). The next page starts strictly after it. Not authenticated: a
/// requester can only page its own session, and a garbled value only ever
/// costs that requester (see `channel_meta_page` for the exact rule).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MetaCursor {
    /// Replay tier of the last served row: 0 = `ChannelCreate`, 1 = every
    /// other metadata type (`META_REPLAY_TIERS`). Any larger value means
    /// "past the end".
    pub tier: u8,
    /// Signed envelope timestamp (unix ms) of the last served row.
    pub ts: u64,
    /// `msg_id` of the last served row (tie-breaker for equal `ts`).
    pub msg_id: [u8; 32],
}

/// One metadata page (`channel_meta_page`).
#[derive(Debug, Clone, Default)]
pub(crate) struct MetaPage {
    /// Stored envelope bytes in replay order (≤ the page cap).
    pub envelopes: Vec<Vec<u8>>,
    /// Position of the last row of this page; `None` for an empty page.
    pub next_cursor: Option<MetaCursor>,
    /// Another row exists after `next_cursor`.
    pub has_more: bool,
    /// Storage work done (iterator seeks and steps; a row's `MESSAGES`
    /// read is part of its step).
    pub work: u64,
}

/// One page of ALL of a channel's metadata rows (round 4: raw rows —
/// nothing is dropped) in replay order `(tier, ts, msg_id)`,
/// strictly after `after`, at most `cap` rows. Keyset paging: the per-type
/// key streams are SEEKED to the cursor and merged
/// (`Storage::channel_meta_replay_page`), so every page costs
/// O(cap + number of types) regardless of depth — never a rescan.
///
/// Cursor rule: `after == None` starts at the beginning; any
/// `(tier ∈ {0, 1}, ts, msg_id)` is a valid seek position (strictly-after
/// semantics, so equal-`ts` rows are neither duplicated nor skipped); a
/// `tier` above 1 (e.g. a tampered `tier = 255`) is past the end → an
/// empty, finished page, for one unit of work and no I/O. A row whose
/// `MESSAGES` entry is gone is skipped but still advances the cursor.
pub(crate) fn channel_meta_page(
    storage: &Storage,
    channel_id: u64,
    after: Option<&MetaCursor>,
    cap: usize,
) -> MetaPage {
    let cap = cap.max(1);
    let after = after.map(|c| (c.tier, c.ts, c.msg_id));
    let (rows, has_more, work) =
        match storage.channel_meta_replay_page(channel_id, &META_REPLAY_TIERS, after, cap) {
            Ok(r) => r,
            Err(e) => {
                warn!(channel_id, error = %e, "metadata page: CHANNEL_META_MSGS iteration failed");
                return MetaPage { work: 1, ..Default::default() };
            }
        };
    let next_cursor = rows
        .last()
        .map(|r| MetaCursor { tier: r.tier, ts: r.ts, msg_id: r.msg_id });
    let envelopes = rows
        .iter()
        .filter_map(|r| storage.get_message(&r.msg_id).ok().flatten())
        .collect();
    MetaPage { envelopes, next_cursor, has_more, work }
}

/// Per-peer responder budget charge for one served request (round 4): the
/// larger of envelopes sent and storage work done (one unit per seek and
/// per index row examined — a served row costs about one unit, like an
/// envelope did before), and never less than 1 — so an empty, filtered-out
/// or garbage-cursor page is not free.
pub fn budget_charge(envelopes_sent: usize, work: u64) -> u64 {
    (envelopes_sent as u64).max(work).max(1)
}

/// Fetch the known CREATOR's `ChannelCreate` (falling back to EARLIEST
/// only on a genuine first sight, with no local row to check against)
/// and ALL `ChannelUpdate` (ts-ascending) original signed envelopes for
/// `channel_id`, for federation bootstrap
/// (`api::routes::federate_channel` / `get_channel`'s restricted
/// response). Security-audit finding (2026-10-05): `federate_channel`
/// used to trust a bespoke JSON summary scraped from an unauthenticated
/// HTTP response for `creator`/`history_visibility`/`encryption_enabled`
/// — this function lets the caller instead re-serve the ORIGINAL signed
/// envelope(s) so the requester can independently verify them through
/// `process_synced_message`, the same never-trust-derived-JSON idiom
/// `dm_sync`/`identity_sync`/`private_channel_sync`/this module's own
/// `channel_meta_envelopes` already follow.
///
/// Deliberately narrower than `channel_meta_envelopes`: this is served
/// to an UNAUTHENTICATED caller (see `get_channel`'s restricted branch),
/// so it must NOT include `ChannelJoin`/`ChannelLeave`/`ChannelKick`/
/// `ChannelBan`/`ChannelUnban` — those would disclose OTHER users'
/// membership/moderation history at the same disclosure level as the
/// private-channel-sync protocol, which gates that content behind a
/// verified membership check. `ChannelCreate`/`ChannelUpdate` alone carry
/// nothing beyond what the existing JSON `channel` summary already
/// discloses to any caller today — this just makes those same fields
/// verifiable instead of merely claimed.
///
/// **Code-audit fix (2026-10-05, round 2)**: the first version of this
/// function selected the LATEST row of each type, reasoning (wrongly)
/// that `ChannelUpdate` is a full snapshot and that there's only ever one
/// `ChannelCreate`. Both were bugs:
///  - `ChannelUpdatePayload`'s fields are all `Option` and the apply arm
///    merges only the `Some` ones (`router.rs`) — it's a PARTIAL PATCH,
///    not a snapshot. Replaying only the latest permanently drops any
///    field set by an EARLIER update and never touched since (e.g. a
///    `display_name` set in update #1, then only `logo_cid` changed in
///    update #2 — bootstrapping from #2 alone loses the name). Fixed by
///    returning ALL updates, ts-ascending (the correct patch-apply
///    order), bounded the same way `channel_meta_envelopes` bounds its
///    own ride-along.
///  - `CHANNEL_META_MSGS` is NOT "one row per channel" — it's one row
///    per accepted `ChannelCreate` ENVELOPE, and `update_indexes` indexes
///    every one unconditionally, even when the apply step's existing-row
///    branch ignores a non-creator's competing claim for an ALREADY-
///    KNOWN channel_id (logged, not rejected — see that branch's own
///    comment). A registered wallet that knows the channel_id (which,
///    by this system's own design, anyone legitimately joining also
///    knows) can post such a competing `ChannelCreate` and have it
///    stored+indexed with a LATER timestamp than the genuine one.
///    Selecting the latest therefore handed a bootstrapping node the
///    IMPOSTOR's envelope instead of the real creator's. The genuine
///    `ChannelCreate` necessarily predates any such competing claim
///    (you have to already know a channel exists to contest its
///    creatorship) — so the EARLIEST row is the one that matches
///    whatever this node's own merge logic would already treat as
///    authoritative. A forward scan is already ts-ascending, so the
///    FIRST row is earliest.
///
/// Residual (recorded, not closed by this function alone): a node that
/// has NEVER seen `channel_id` before has no independent anchor to
/// distinguish a genuine first-sight `ChannelCreate` from an attacker's
/// self-signed one for the same id — private channels never exist
/// on-chain, so there is no third-party source of truth beyond "whoever
/// signed the envelope you encounter first." This is not unique to
/// federation bootstrap (any node's very first encounter with a
/// `channel_id`, by any path, has the same property) but federation is
/// what makes a brand-new node's first encounter attacker-reachable at
/// all. See `api::routes::federate_channel`'s doc comment for the
/// current status of this residual.
pub(crate) fn channel_bootstrap_envelopes(
    storage: &Storage,
    channel_id: u64,
) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
    const BOOTSTRAP_UPDATE_CAP: usize = 256;
    const BOOTSTRAP_CREATE_SCAN_CAP: usize = 256;

    // Security-audit finding (2026-10-06): taking the single oldest
    // `CHANNEL_META_MSGS` row unconditionally let an attacker who already
    // knows (or has federated) an EXISTING channel's id inject a
    // competing, artificially-backdated `ChannelCreate` — accepted via
    // the sync path (whose drift check is skipped) and indexed
    // unconditionally even though the merge step ignores its effect on
    // `CHANNELS` — that then became "the" bootstrap envelope served to
    // every future first-sight node. Since it carries no matching
    // derivation, every such node rejects it, turning a perfectly
    // legitimate, already-verified channel permanently unfederatable —
    // the fix for forged FIRST sight creating a second-order DoS on
    // genuine channels. Fixed: when this node already has an
    // authoritative `CHANNELS` row, prefer the create envelope whose
    // AUTHOR matches the row's real `creator` over merely "the
    // earliest" — a competing claim from any other author is excluded
    // regardless of timestamp.
    //
    // Round-3 re-audit found the round-2 fix above still didn't work:
    // (a) `envelope_author_is` compared the raw, possibly device-signed
    // `Envelope.author` against the WALLET-valued `creator` field, so it
    // silently never matched for any device-delegated create — now
    // resolved to the wallet before comparing, same as `update_indexes`'
    // own `resolved_author`; and (b) the "no match" fallback used to
    // retry at earliest-wins, which is exactly as gameable as the
    // original bug once (a) is accounted for. `update_indexes` now
    // refuses to even INDEX a non-creator's competing `ChannelCreate`
    // for an already-known channel (see its own comment), so "no match"
    // here should mean "no candidate at all," not "the real creator's
    // envelope must be hiding under a different author" — fall back to
    // nothing rather than to a row this node already knows isn't the
    // creator's. Only with NO local row at all (genuine first sight,
    // nothing to compare against yet) does this use earliest-wins, which
    // stays the documented, irreducible residual for that specific case
    // (see this function's doc comment above).
    let known_creator = storage
        .get_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes())
        .ok()
        .flatten()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("creator").and_then(|c| c.as_str()).map(|s| s.to_string()));

    let create = {
        let mut prefix = channel_id.to_be_bytes().to_vec();
        prefix.push(MessageType::ChannelCreate as u8);
        let rows = storage
            .prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &prefix, BOOTSTRAP_CREATE_SCAN_CAP)
            .unwrap_or_default();
        let mut candidates = rows
            .into_iter()
            .filter_map(|(key, _)| bootstrap_msg_id(&key))
            .filter_map(|msg_id| storage.get_message(&msg_id).ok().flatten());
        match &known_creator {
            // No fallback to earliest-wins here: `update_indexes` no
            // longer indexes a non-creator's competing create for a
            // known channel at all, so every remaining candidate really
            // is creator-authored (modulo device-key resolution, which
            // `envelope_author_is` now handles) — "no match" means no
            // candidate exists, and serving a known-non-creator's
            // envelope is strictly worse than serving none (the
            // requester rejects either outcome, but only the latter
            // can't be weaponized to permanently poison the selection).
            Some(creator) => candidates.find(|raw| envelope_author_is(storage, raw, creator)),
            None => candidates.next(),
        }
    };

    let updates = {
        let mut prefix = channel_id.to_be_bytes().to_vec();
        prefix.push(MessageType::ChannelUpdate as u8);
        let rows = storage
            .prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &prefix, BOOTSTRAP_UPDATE_CAP.saturating_add(1))
            .unwrap_or_default();
        if rows.len() > BOOTSTRAP_UPDATE_CAP {
            warn!(
                channel_id,
                cap = BOOTSTRAP_UPDATE_CAP,
                "channel_bootstrap_envelopes: channel has more ChannelUpdate envelopes than the \
                 bootstrap cap; oldest-in-window excess not served this call (live gossip / a \
                 later federation retry still covers it once this one applies)"
            );
        }
        rows.into_iter()
            .take(BOOTSTRAP_UPDATE_CAP)
            .filter_map(|(key, _)| bootstrap_msg_id(&key))
            .filter_map(|msg_id| storage.get_message(&msg_id).ok().flatten())
            .collect()
    };

    (create, updates)
}

/// Top-level `Envelope` decode only (never the payload) — safe regardless
/// of payload content, same pattern as every other "peek at a plain
/// struct field" decode in this module. Used by `channel_bootstrap_
/// envelopes` to filter candidate `ChannelCreate` envelopes by author
/// without needing to deserialize the payload at all.
///
/// `expected_author` (the `CHANNELS` row's `creator` field) is always a
/// WALLET address — `update_indexes` writes it from `resolved_author`,
/// never the raw envelope author. A device-delegated `ChannelCreate`'s
/// `Envelope.author` is the device's `ogd1...` address, not the wallet,
/// so comparing it directly (round-2's bug, caught in round-3 re-audit)
/// silently never matched any device-signed create — resolve to the
/// wallet first, same as `IdentityResolver::resolve`'s own fallback
/// (device unregistered/already-a-wallet → use the address as-is).
fn envelope_author_is(storage: &Storage, raw: &[u8], expected_author: &str) -> bool {
    match rmp_serde::from_slice::<crate::messages::envelope::Envelope>(raw) {
        Ok(env) => {
            let wallet = storage
                .resolve_wallet(&env.author)
                .ok()
                .flatten()
                .unwrap_or(env.author);
            wallet == expected_author
        }
        Err(_) => false,
    }
}

/// Extract the `msg_id` suffix from a `CHANNEL_META_MSGS` key
/// (`channel_id:8 ++ msg_type:1 ++ ts:8 ++ msg_id:32` = 49 bytes).
fn bootstrap_msg_id(key: &[u8]) -> Option<[u8; 32]> {
    if key.len() != 8 + 1 + 8 + 32 {
        return None;
    }
    let mut msg_id = [0u8; 32];
    msg_id.copy_from_slice(&key[17..49]);
    Some(msg_id)
}

/// Max edit/delete markers one ride-along carries (public reconcile).
pub(crate) const CHANNEL_EDIT_DELETE_CAP: usize = 2_000;

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
///
/// Returns the NEWEST `limit` (≤ `CHANNEL_EDIT_DELETE_CAP`) markers plus the
/// storage work done. Public reconcile passes the full cap; private-channel
/// sync passes the room left on its page, so it never reads (and discards)
/// 2,000 markers to keep a few.
pub(crate) fn channel_edit_delete_envelopes_metered(
    storage: &Storage,
    channel_id: u64,
    min_timestamp: u64,
    limit: usize,
) -> (Vec<Vec<u8>>, u64) {
    let limit = limit.min(CHANNEL_EDIT_DELETE_CAP);
    if limit == 0 {
        return (Vec::new(), 0);
    }
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
        limit.saturating_add(1),
    ) {
        Ok(r) => r,
        Err(_) => return (Vec::new(), 1),
    };
    let work: u64 = 1 + rows.len() as u64;
    if limit == CHANNEL_EDIT_DELETE_CAP && rows.len() > CHANNEL_EDIT_DELETE_CAP {
        warn!(
            channel_id,
            cap = CHANNEL_EDIT_DELETE_CAP,
            "reconcile: channel has more edit/delete markers than the ride-along cap; \
             oldest excess markers were not shipped this session"
        );
    }
    let mut out = Vec::new();
    for (key, _) in rows.into_iter().take(limit) {
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
    (out, work)
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
///
/// `pub(crate)` (not private) so `NetworkService::maybe_trigger_backfill`
/// can skip triggering reconciliation for a known-private channel at all
/// (code-audit follow-up, 2026-09-30) — `build_response` above refuses
/// every private-channel request unconditionally anyway, so attempting
/// one is pure wasted fanout traffic, retried every periodic-sweep tick
/// forever since a refused request can never reach natural completion.
pub(crate) fn is_private_channel(storage: &Storage, channel_id: u64) -> bool {
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

/// Free-function equivalent of `MessageRouter::is_channel_member`
/// ([router.rs](crate::messages::router)), for callers that only have a
/// `&Storage` (no full `MessageRouter`) — currently
/// `network::private_channel_sync::verify_request_membership`. Same logic,
/// same key encoding, just not behind `&self`: do not let this drift
/// from the router's copy.
pub(crate) fn is_channel_member(storage: &Storage, channel_id: u64, address: &str) -> bool {
    let key = schema::encode_channel_member_key(channel_id, address);
    storage
        .exists_cf(schema::cf::CHANNEL_MEMBERS, &key)
        .unwrap_or(false)
}

/// Resolve a channel's `history_visibility` (`0` = ForwardOnly, `1` =
/// FullHistory — see `messages::router::channel_encryption_defaults`).
/// Returns `None` for an unknown channel or a malformed/missing field —
/// callers must fail closed (treat `None` as ForwardOnly), never as
/// FullHistory.
pub(crate) fn channel_history_visibility(storage: &Storage, channel_id: u64) -> Option<u8> {
    let key = channel_id.to_be_bytes();
    let bytes = storage.get_cf(schema::cf::CHANNELS, &key).ok().flatten()?;
    let meta: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    meta.get("history_visibility").and_then(|v| v.as_u64()).map(|v| v as u8)
}

/// Look up `wallet`'s `joined_at` for `channel_id` from its
/// `CHANNEL_MEMBERS` row, normalized to unix SECONDS (matching the
/// second-granularity used throughout `reconcile`/`private_channel_sync`).
/// Returns `None` if the wallet has no membership row or the field is
/// missing/malformed.
///
/// Security-audit finding (2026-10-01): the writers of this row are NOT
/// unit-consistent. `routes.rs`'s `federate_channel`/join handlers and
/// `messages::router`'s `ChatMessage`/`ChannelInvite` auto-add all write
/// `now_ms` (unix MILLISECONDS) — but `chain::scanner`'s creator-row
/// writer (on `ChannelCreated`) writes the on-chain transaction's
/// `timestamp`, which `chain::parser` documents as unix SECONDS. A flat
/// `/ 1000` (this function's first version) silently divided an
/// already-in-seconds creator timestamp down to ~1970, disabling the
/// ForwardOnly floor for every channel's creator — a confidentiality
/// fail-OPEN, not fail-closed. Disambiguate by magnitude instead: any
/// real seconds-epoch value stays under 10_000_000_000 (unix seconds
/// don't reach that until the year 2286), while any real milliseconds-
/// epoch value for current and foreseeable dates is already far above
/// it (~1.7e12 today) — so this threshold cannot misclassify a genuine
/// value from either writer.
pub(crate) fn member_joined_at(storage: &Storage, channel_id: u64, wallet: &str) -> Option<u64> {
    const SECONDS_MS_DISAMBIGUATION_THRESHOLD: u64 = 10_000_000_000;
    let key = schema::encode_channel_member_key(channel_id, wallet);
    let bytes = storage.get_cf(schema::cf::CHANNEL_MEMBERS, &key).ok().flatten()?;
    let rec: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    rec.get("joined_at").and_then(|v| v.as_u64()).map(|raw| {
        if raw >= SECONDS_MS_DISAMBIGUATION_THRESHOLD {
            raw / 1000
        } else {
            raw
        }
    })
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
            buttons: vec![],
            via_button: false,
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

    /// Code-audit finding (2026-09-30): a channel whose eligible history
    /// lands EXACTLY on `cap` must report `has_more = false` on that same
    /// page — not a false `has_more = true` that forces a pointless extra
    /// empty round-trip. The old check (`chat_count >= cap` evaluated
    /// AFTER pushing) got this wrong; `mark_channel_backfill_complete`
    /// (l2-node 0.136.0) depends on this being right, since a channel
    /// that never sees a genuine `has_more = false` page can never be
    /// marked complete and gets re-fanned-out by the periodic retry sweep
    /// forever.
    #[test]
    fn exact_cap_boundary_reports_no_more_on_the_same_page() {
        let (s, _d) = db();
        let channel_id = 79u64;
        for i in 0..3u64 {
            put_chat_message(&s, channel_id, [i as u8 + 1; 32], 1_000 + i);
        }

        let req = ReconcileRequest {
            channel_id,
            max_age_secs: u64::MAX,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };
        // cap == the exact number of eligible messages.
        let resp = build_response(&s, &req, 3, 5_000);
        assert_eq!(resp.envelopes.len(), 3);
        assert!(
            !resp.has_more,
            "exactly `cap` real rows with nothing beyond must report \
             has_more = false on this page, not force a follow-up round-trip"
        );
        assert!(resp.next_cursor.is_none());
    }

    /// One genuine row beyond the exact boundary must still be detected
    /// correctly — the fix must not overcorrect into never capping at all.
    #[test]
    fn one_row_past_the_cap_boundary_still_reports_has_more() {
        let (s, _d) = db();
        let channel_id = 80u64;
        for i in 0..4u64 {
            put_chat_message(&s, channel_id, [i as u8 + 1; 32], 1_000 + i);
        }

        let req = ReconcileRequest {
            channel_id,
            max_age_secs: u64::MAX,
            cursor: None,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
        };
        let resp = build_response(&s, &req, 3, 5_000);
        assert_eq!(resp.envelopes.len(), 3, "must still cap at exactly `cap` rows");
        assert!(
            resp.has_more,
            "a genuine 4th row beyond cap=3 must still be detected"
        );
        assert!(resp.next_cursor.is_some());
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
mod channel_meta_order_tests {
    //! Audit final pre-mainnet W12: `CHANNEL_META_MSGS`'s key is
    //! `channel_id ++ msg_type ++ ts ++ msg_id`, so a naive `prefix_iter_cf`
    //! scan returns rows sorted by msg_type FIRST — `ChannelBan` (0x17)
    //! always sorts before `ChannelUnban` (0x18) regardless of real
    //! chronological order. `channel_meta_envelopes` must re-sort by the
    //! envelope's real signed `timestamp` before returning, or a
    //! backfilling node replays banned@t1, re-banned@t3, THEN unbanned@t2
    //! (raw key order) instead of the true banned@t1, unbanned@t2,
    //! re-banned@t3 — converging to the wrong final state (unbanned).
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::MessageType;
    use crate::storage::rocks::Storage;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    /// Index a bare envelope into `CHANNEL_META_MSGS` + `MESSAGES`, mirroring
    /// `router.rs`'s P-3b indexing (payload content is irrelevant to this
    /// ordering test — only `msg_type` and `timestamp` matter).
    fn put_meta_envelope(s: &Storage, channel_id: u64, msg_type: MessageType, msg_id: [u8; 32], ts: u64) {
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author: "klv1author".to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: Vec::new(),
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(
            schema::cf::CHANNEL_META_MSGS,
            &schema::encode_channel_meta_key(channel_id, msg_type as u8, ts, &msg_id),
            &[],
        )
        .unwrap();
        s.put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn msg_types_in_order(envelopes: &[Vec<u8>]) -> Vec<MessageType> {
        envelopes
            .iter()
            .map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_type)
            .collect()
    }

    #[test]
    fn moderation_envelopes_replay_in_chronological_not_key_order() {
        let (s, _d) = db();
        let channel_id = 42u64;
        // banned@1000, unbanned@2000, re-banned@3000 — real chronological
        // order. Raw CHANNEL_META_MSGS key order would instead group both
        // Bans (0x17) before the Unban (0x18): Ban(1000), Ban(3000), Unban(2000).
        put_meta_envelope(&s, channel_id, MessageType::ChannelBan, [1u8; 32], 1_000);
        put_meta_envelope(&s, channel_id, MessageType::ChannelUnban, [2u8; 32], 2_000);
        put_meta_envelope(&s, channel_id, MessageType::ChannelBan, [3u8; 32], 3_000);

        let out = channel_meta_envelopes(&s, channel_id, CHANNEL_META_CAP);
        assert_eq!(
            msg_types_in_order(&out),
            vec![MessageType::ChannelBan, MessageType::ChannelUnban, MessageType::ChannelBan],
            "must replay in real timestamp order (Ban,Unban,Ban → converges banned), \
             not raw CHANNEL_META_MSGS key order (Ban,Ban,Unban → would converge unbanned)"
        );
    }

    /// Code Audit follow-up: a PURE timestamp sort would let a `ChannelJoin`
    /// with an earlier `ts` than the channel's own `ChannelCreate` (client
    /// clock skew — the sync ingest path doesn't validate drift) replay
    /// BEFORE the create. `add_channel_member` is a no-op when the
    /// `CHANNELS` row doesn't exist yet, and the envelope is deduped, so
    /// that membership would be lost forever. The two-tier sort must always
    /// place `ChannelCreate` first regardless of its timestamp.
    #[test]
    fn channel_create_always_sorts_first_even_with_a_later_timestamp() {
        let (s, _d) = db();
        let channel_id = 43u64;
        // Join has an EARLIER timestamp than Create (clock skew) — raw
        // timestamp order alone would replay Join before Create.
        put_meta_envelope(&s, channel_id, MessageType::ChannelJoin, [1u8; 32], 500);
        put_meta_envelope(&s, channel_id, MessageType::ChannelCreate, [2u8; 32], 1_000);

        let out = channel_meta_envelopes(&s, channel_id, CHANNEL_META_CAP);
        assert_eq!(
            msg_types_in_order(&out),
            vec![MessageType::ChannelCreate, MessageType::ChannelJoin],
            "ChannelCreate must always replay first, regardless of timestamp — \
             otherwise a skewed-clock Join can be permanently lost \
             (add_channel_member no-ops when the channel doesn't exist yet)"
        );
    }
}

#[cfg(test)]
mod channel_bootstrap_envelopes_tests {
    //! `channel_bootstrap_envelopes` (security-audit fix, 2026-10-05) is
    //! the responder-side half of `federate_channel`'s verifiable
    //! bootstrap: it must return the `ChannelCreate` envelope and only
    //! the LATEST `ChannelUpdate`, never other meta types.
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::MessageType;
    use crate::storage::rocks::Storage;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn put_meta_envelope(s: &Storage, channel_id: u64, msg_type: MessageType, msg_id: [u8; 32], ts: u64) {
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author: "klv1author".to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: Vec::new(),
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(
            schema::cf::CHANNEL_META_MSGS,
            &schema::encode_channel_meta_key(channel_id, msg_type as u8, ts, &msg_id),
            &[],
        )
        .unwrap();
        s.put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn put_meta_envelope_by(
        s: &Storage,
        channel_id: u64,
        msg_type: MessageType,
        msg_id: [u8; 32],
        ts: u64,
        author: &str,
    ) {
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type,
            msg_id,
            author: author.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: Vec::new(),
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(
            schema::cf::CHANNEL_META_MSGS,
            &schema::encode_channel_meta_key(channel_id, msg_type as u8, ts, &msg_id),
            &[],
        )
        .unwrap();
        s.put_cf(schema::cf::MESSAGES, &msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn msg_id_of(raw: &[u8]) -> [u8; 32] {
        rmp_serde::from_slice::<Envelope>(raw).unwrap().msg_id
    }

    fn msg_ids_of(rows: &[Vec<u8>]) -> Vec<[u8; 32]> {
        rows.iter().map(|r| msg_id_of(r)).collect()
    }

    #[test]
    fn no_channel_create_returns_none_and_empty() {
        let (s, _d) = db();
        let (create, updates) = channel_bootstrap_envelopes(&s, 1u64);
        assert!(create.is_none());
        assert!(updates.is_empty());
    }

    #[test]
    fn create_only_returns_create_and_no_updates() {
        let (s, _d) = db();
        let channel_id = 2u64;
        put_meta_envelope(&s, channel_id, MessageType::ChannelCreate, [1u8; 32], 1_000);
        let (create, updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert_eq!(create.map(|r| msg_id_of(&r)), Some([1u8; 32]));
        assert!(updates.is_empty());
    }

    #[test]
    fn multiple_updates_returns_all_ts_ascending() {
        // Code-audit fix (2026-10-05, round 2): a prior version returned
        // only the latest update, silently dropping fields set by earlier
        // ones (ChannelUpdatePayload's fields are a partial PATCH, not a
        // snapshot). Must return ALL of them, oldest-first — the correct
        // patch-apply order.
        let (s, _d) = db();
        let channel_id = 3u64;
        put_meta_envelope(&s, channel_id, MessageType::ChannelCreate, [1u8; 32], 1_000);
        put_meta_envelope(&s, channel_id, MessageType::ChannelUpdate, [2u8; 32], 2_000);
        put_meta_envelope(&s, channel_id, MessageType::ChannelUpdate, [3u8; 32], 3_000);
        let (create, updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert_eq!(create.map(|r| msg_id_of(&r)), Some([1u8; 32]));
        assert_eq!(
            msg_ids_of(&updates),
            vec![[2u8; 32], [3u8; 32]],
            "must return every ChannelUpdate, oldest first"
        );
    }

    #[test]
    fn two_channel_creates_returns_the_earliest_not_the_latest() {
        // Code-audit CRITICAL fix (2026-10-05, round 2): `CHANNEL_META_MSGS`
        // indexes every ACCEPTED ChannelCreate envelope for a channel_id,
        // even one the apply step's existing-row branch ignored as a
        // non-creator's competing claim (logged, not rejected — the
        // envelope is still stored+indexed). A later-timestamped SECOND
        // ChannelCreate for the same id (the attack this regression-guards
        // against) must NOT be selected over the genuine, earlier one.
        let (s, _d) = db();
        let channel_id = 5u64;
        put_meta_envelope(&s, channel_id, MessageType::ChannelCreate, [1u8; 32], 1_000);
        // A later, competing ChannelCreate for the SAME channel_id — as
        // would result from an attacker's forged claim being accepted
        // (stored+indexed) but ignored by the merge logic.
        put_meta_envelope(&s, channel_id, MessageType::ChannelCreate, [9u8; 32], 9_000);
        let (create, _updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert_eq!(
            create.map(|r| msg_id_of(&r)),
            Some([1u8; 32]),
            "must return the EARLIEST ChannelCreate, not the latest"
        );
    }

    /// Security-audit fix (2026-10-06): "earliest wins" alone is
    /// defeatable once a channel is already known locally. An attacker
    /// can get their OWN competing `ChannelCreate` accepted+indexed with
    /// an artificially-backdated (earlier-than-genuine) timestamp via the
    /// sync path, since it skips the freshness check — "earliest" would
    /// then select the IMPOSTOR's envelope forever, and every future
    /// first-sight node rejects it (no matching derivation), permanently
    /// DoS-ing a perfectly legitimate channel's federation. Once a local
    /// `CHANNELS` row exists, the real `creator` field is a stronger
    /// anchor than raw timestamp order — the selection must prefer the
    /// candidate whose AUTHOR matches it, regardless of which one is
    /// chronologically earliest.
    #[test]
    fn once_a_channel_is_known_the_creators_envelope_wins_even_if_backdated_earlier() {
        let (s, _d) = db();
        let channel_id = 6u64;
        let real_creator = "klv1realcreator";
        let attacker = "klv1attacker";

        // Establish the authoritative CHANNELS row (as the real
        // ChannelCreate's own apply step would have done).
        let meta = serde_json::json!({
            "channel_id": channel_id,
            "channel_type": 2u8,
            "creator": real_creator,
        });
        s.put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), meta.to_string().as_bytes())
            .unwrap();

        // The genuine creator's envelope, indexed at ts=5000.
        put_meta_envelope_by(&s, channel_id, MessageType::ChannelCreate, [1u8; 32], 5_000, real_creator);
        // An attacker's competing claim, backdated to ts=100 — earlier
        // than the genuine one, exactly the forgery this test guards
        // against.
        put_meta_envelope_by(&s, channel_id, MessageType::ChannelCreate, [9u8; 32], 100, attacker);

        let (create, _updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert_eq!(
            create.map(|r| msg_id_of(&r)),
            Some([1u8; 32]),
            "must prefer the envelope authored by the row's REAL creator, not the chronologically \
             earliest one — an attacker's backdated claim must never win once the channel is known"
        );
    }

    /// Round-3 re-audit finding: the round-2 fix compared the raw
    /// `Envelope.author` against the `CHANNELS` row's WALLET-valued
    /// `creator`, so it silently never matched a device-delegated
    /// create — the genuine creator's envelope fell through to the "no
    /// match" path on every device-signed channel, which is the normal
    /// case, not an edge case. Register a device→wallet mapping and sign
    /// the real creator's envelope with the DEVICE address to prove the
    /// resolved comparison still picks it over the attacker's.
    #[test]
    fn creator_preference_resolves_a_device_signed_envelope_to_its_wallet() {
        let (s, _d) = db();
        let channel_id = 60u64;
        let real_wallet = "klv1realcreator";
        let real_device = "ogd1realdevice";
        let attacker = "klv1attacker";

        s.register_device(&crate::storage::rocks::DeviceClaim {
            device_address: real_device.to_string(),
            wallet_address: real_wallet.to_string(),
            device_pubkey_hex: "ab".repeat(32),
            wallet_signature: "cd".repeat(32),
            registered_at: 1,
        })
        .unwrap();

        let meta = serde_json::json!({
            "channel_id": channel_id,
            "channel_type": 2u8,
            "creator": real_wallet,
        });
        s.put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), meta.to_string().as_bytes())
            .unwrap();

        // Genuine creator's envelope, signed by their DEVICE key, backdated
        // later than the attacker's to isolate the author-match logic from
        // timestamp ordering.
        put_meta_envelope_by(&s, channel_id, MessageType::ChannelCreate, [1u8; 32], 5_000, real_device);
        put_meta_envelope_by(&s, channel_id, MessageType::ChannelCreate, [9u8; 32], 100, attacker);

        let (create, _updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert_eq!(
            create.map(|r| msg_id_of(&r)),
            Some([1u8; 32]),
            "a device-signed create from the real creator must still be preferred over an \
             attacker's — comparing raw envelope.author against the wallet-valued creator field \
             must not cause it to fall through to the no-match path"
        );
    }

    /// Round-3 re-audit finding: the prior fallback-to-earliest-wins
    /// logic for "no candidate matched the known creator" was itself
    /// gameable — once `update_indexes` stopped indexing a non-creator's
    /// competing create at all (this session's companion fix), "no
    /// match" can only mean "no candidate exists," so the only safe
    /// behavior left is to return no create, never to fall back to
    /// whatever the scan happens to contain.
    #[test]
    fn no_match_against_a_known_creator_returns_none_rather_than_falling_back() {
        let (s, _d) = db();
        let channel_id = 61u64;
        let real_creator = "klv1realcreator";

        let meta = serde_json::json!({
            "channel_id": channel_id,
            "channel_type": 2u8,
            "creator": real_creator,
        });
        s.put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), meta.to_string().as_bytes())
            .unwrap();

        // Only a non-creator candidate exists (e.g. the creator's own
        // envelope was never indexed, or hasn't arrived yet via this peer).
        put_meta_envelope_by(&s, channel_id, MessageType::ChannelCreate, [9u8; 32], 100, "klv1someoneelse");

        let (create, _updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert!(
            create.is_none(),
            "must return no create rather than falling back to a known-non-creator's envelope"
        );
    }

    #[test]
    fn updates_beyond_the_cap_are_truncated_not_silently_replaced_with_a_stale_one() {
        // Code-audit fix: a prior version used a forward scan bounded at
        // a cap, then took `.last()` — for more than `cap` updates that
        // returns the cap-th OLDEST row, not the true latest, silently.
        // Returning ALL rows up to the cap (oldest-first) at least never
        // claims to be "the latest" when it isn't — excess is logged.
        let (s, _d) = db();
        let channel_id = 6u64;
        put_meta_envelope(&s, channel_id, MessageType::ChannelCreate, [0u8; 32], 0);
        for n in 1u64..=300 {
            let mut mid = [0u8; 32];
            mid[0..8].copy_from_slice(&n.to_be_bytes());
            put_meta_envelope(&s, channel_id, MessageType::ChannelUpdate, mid, n * 1_000);
        }
        let (_create, updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert_eq!(updates.len(), 256, "must be capped, not unbounded");
        // The returned set is the OLDEST 256 (updates 1..=256) — a real
        // residual (the newest 44 are dropped this call), documented in
        // the function's own doc comment rather than silently hidden.
        let first_id = rmp_serde::from_slice::<Envelope>(&updates[0]).unwrap().timestamp;
        assert_eq!(first_id, 1_000);
    }

    #[test]
    fn other_meta_types_never_leak_into_bootstrap_response() {
        let (s, _d) = db();
        let channel_id = 4u64;
        put_meta_envelope(&s, channel_id, MessageType::ChannelCreate, [1u8; 32], 1_000);
        put_meta_envelope(&s, channel_id, MessageType::ChannelJoin, [2u8; 32], 2_000);
        put_meta_envelope(&s, channel_id, MessageType::ChannelBan, [3u8; 32], 3_000);
        let (create, updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert_eq!(create.map(|r| msg_id_of(&r)), Some([1u8; 32]));
        assert!(
            updates.is_empty(),
            "ChannelJoin/ChannelBan must never be mistaken for a ChannelUpdate — \
             this response is served to an UNAUTHENTICATED caller and must not \
             disclose other users' membership/moderation history"
        );
    }

    #[test]
    fn missing_messages_row_is_skipped_not_panicking() {
        // A CHANNEL_META_MSGS key whose MESSAGES row is gone (e.g. pruned)
        // must be skipped gracefully, not panic or surface as Some(garbage).
        let (s, _d) = db();
        let channel_id = 7u64;
        let msg_id = [1u8; 32];
        s.put_cf(
            schema::cf::CHANNEL_META_MSGS,
            &schema::encode_channel_meta_key(channel_id, MessageType::ChannelCreate as u8, 1_000, &msg_id),
            &[],
        )
        .unwrap();
        // Deliberately no MESSAGES row for msg_id.
        let (create, updates) = channel_bootstrap_envelopes(&s, channel_id);
        assert!(create.is_none());
        assert!(updates.is_empty());
    }
}

#[cfg(test)]
mod is_private_channel_tests {
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn put_channel(s: &Storage, channel_id: u64, channel_type: u64) {
        s.put_cf(
            schema::cf::CHANNELS,
            &channel_id.to_be_bytes(),
            serde_json::to_vec(&serde_json::json!({ "channel_type": channel_type }))
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    }

    #[test]
    fn private_channel_type_is_detected() {
        let (s, _d) = db();
        put_channel(&s, 1, 2);
        assert!(is_private_channel(&s, 1));
    }

    #[test]
    fn public_and_read_public_are_not_private() {
        let (s, _d) = db();
        put_channel(&s, 1, 0);
        put_channel(&s, 2, 1);
        assert!(!is_private_channel(&s, 1));
        assert!(!is_private_channel(&s, 2));
    }

    /// Unknown channel_id (no local row at all) defaults to "not private"
    /// — used by `NetworkService::maybe_trigger_backfill`'s skip check, so
    /// a channel this node hasn't chain-scanned yet still gets a normal
    /// backfill attempt rather than being silently skipped forever.
    #[test]
    fn unknown_channel_defaults_to_not_private() {
        let (s, _d) = db();
        assert!(!is_private_channel(&s, 999));
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

#[cfg(test)]
mod channel_meta_type_priority_tests {
    //! l2-node 0.140.0: `channel_meta_envelopes` (the bounded ride-along)
    //! selects per msg_type in `RIDE_ALONG_PRIORITY` order with the cap on
    //! the INPUT, so a channel with more Join rows than the 256 cap still
    //! serves its moderator grants/removals, kicks and updates (previously
    //! starved by the single msg_type-ordered scan).
    use super::*;

    fn put(s: &Storage, cid: u64, t: MessageType, ts: u64, id: u8, seq: u16) {
        let mut msg_id = [id; 32];
        msg_id[30..32].copy_from_slice(&seq.to_be_bytes());
        let key = schema::encode_channel_meta_key(cid, t as u8, ts, &msg_id);
        s.put_cf(schema::cf::CHANNEL_META_MSGS, &key, &[]).unwrap();
        // Body = [type, id, seq_hi, seq_lo] so tests can tell rows apart.
        let seq_b = seq.to_be_bytes();
        s.store_message(&msg_id, &[t as u8, id, seq_b[0], seq_b[1]]).unwrap();
    }

    #[test]
    fn moderator_and_kick_rows_survive_a_join_flood() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let cid = 1u64 << 40;
        put(&s, cid, MessageType::ChannelCreate, 1, 1, 0);
        for i in 0..400u16 {
            put(&s, cid, MessageType::ChannelJoin, 10 + i as u64, 2, i);
        }
        put(&s, cid, MessageType::ChannelAddModerator, 5, 3, 0);
        put(&s, cid, MessageType::ChannelRemoveModerator, 6, 4, 0);
        put(&s, cid, MessageType::ChannelKick, 7, 5, 0);
        let out = channel_meta_envelopes(&s, cid, CHANNEL_META_CAP);
        assert_eq!(out.len(), 256);
        for t in [
            MessageType::ChannelCreate,
            MessageType::ChannelAddModerator,
            MessageType::ChannelRemoveModerator,
            MessageType::ChannelKick,
        ] {
            assert!(out.iter().any(|raw| raw[0] == t as u8), "{t:?} starved");
        }
        // Replay order is still (tier, ts): Create first.
        assert_eq!(out[0][0], MessageType::ChannelCreate as u8);
    }

    #[test]
    fn many_channel_updates_no_longer_push_out_demotions_and_kicks() {
        // Security audit W4: ChannelUpdate used to be gathered right after
        // Create, so 256 metadata edits starved every moderation row.
        let dir = tempfile::TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let cid = 1u64 << 40;
        put(&s, cid, MessageType::ChannelCreate, 1, 1, 0);
        for i in 0..300u16 {
            put(&s, cid, MessageType::ChannelUpdate, 100 + i as u64, 6, i);
        }
        put(&s, cid, MessageType::ChannelRemoveModerator, 50, 4, 0);
        put(&s, cid, MessageType::ChannelKick, 60, 5, 0);
        put(&s, cid, MessageType::ChannelBan, 61, 7, 0);
        let out = channel_meta_envelopes(&s, cid, CHANNEL_META_CAP);
        assert_eq!(out.len(), 256);
        for t in [
            MessageType::ChannelRemoveModerator,
            MessageType::ChannelKick,
            MessageType::ChannelBan,
        ] {
            assert!(out.iter().any(|raw| raw[0] == t as u8), "{t:?} pushed out by updates");
        }
    }

    /// Round-4 B2': on a PUBLIC channel ~256 cheap joins used to push every
    /// `ChannelUpdate` out of the 256-row ride-along. Update now ranks ahead
    /// of Join/Leave in the selection.
    #[test]
    fn one_update_survives_three_hundred_joins_in_the_ride_along() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let cid = 77u64; // public id space
        put(&s, cid, MessageType::ChannelCreate, 1, 1, 0);
        put(&s, cid, MessageType::ChannelUpdate, 5, 6, 0);
        for i in 0..300u16 {
            put(&s, cid, MessageType::ChannelJoin, 10 + i as u64, 2, i);
        }
        let out = channel_meta_envelopes(&s, cid, CHANNEL_META_CAP);
        assert_eq!(out.len(), CHANNEL_META_CAP);
        assert!(out.iter().any(|raw| raw[0] == MessageType::ChannelUpdate as u8), "update pushed out by joins");
        // Replay order: Create (tier 0), then by ts — the update (ts 5)
        // precedes every kept join.
        assert_eq!(out[0][0], MessageType::ChannelCreate as u8);
        assert_eq!(out[1][0], MessageType::ChannelUpdate as u8);
        // And the whole selection reads O(cap + types) rows, not the channel.
        let (_, work) = channel_meta_envelopes_metered(&s, cid, CHANNEL_META_CAP);
        assert!(work <= 3 * CHANNEL_META_CAP as u64 + 20, "work {work}");
    }

    /// Round-5 C-N4: `ChannelLeave` ranks AHEAD of `ChannelJoin` — a join
    /// flood must not push the leaves (access removals) out of the cap.
    #[test]
    fn leaves_survive_a_join_flood_in_the_ride_along() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let cid = 77u64;
        put(&s, cid, MessageType::ChannelCreate, 1, 1, 0);
        for i in 0..20u16 {
            put(&s, cid, MessageType::ChannelLeave, 5 + i as u64, 8, i);
        }
        for i in 0..400u16 {
            put(&s, cid, MessageType::ChannelJoin, 1_000 + i as u64, 2, i);
        }
        let out = channel_meta_envelopes(&s, cid, CHANNEL_META_CAP);
        assert_eq!(out.len(), CHANNEL_META_CAP);
        let n = |t: MessageType| out.iter().filter(|raw| raw[0] == t as u8).count();
        assert_eq!(n(MessageType::ChannelLeave), 20, "every leave kept");
        assert_eq!(n(MessageType::ChannelJoin), CHANNEL_META_CAP - 21);
        // And the order of the constant itself.
        let pos = |t: MessageType| RIDE_ALONG_PRIORITY.iter().position(|x| *x == t).unwrap();
        assert!(pos(MessageType::ChannelUpdate) < pos(MessageType::ChannelLeave));
        assert!(pos(MessageType::ChannelLeave) < pos(MessageType::ChannelJoin));
    }

    /// All moderator grants/demotions (creator-only, low volume) are kept
    /// even when kicks alone would fill the cap.
    #[test]
    fn every_moderator_row_is_kept_under_a_kick_flood() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let cid = 1u64 << 40;
        put(&s, cid, MessageType::ChannelCreate, 1, 1, 0);
        for i in 0..20u16 {
            put(&s, cid, MessageType::ChannelAddModerator, 2 + i as u64, 3, i);
            put(&s, cid, MessageType::ChannelRemoveModerator, 100 + i as u64, 4, i);
        }
        for i in 0..400u16 {
            put(&s, cid, MessageType::ChannelKick, 1_000 + i as u64, 5, i);
        }
        let out = channel_meta_envelopes(&s, cid, CHANNEL_META_CAP);
        let n = |t: MessageType| out.iter().filter(|raw| raw[0] == t as u8).count();
        assert_eq!(n(MessageType::ChannelAddModerator), 20);
        assert_eq!(n(MessageType::ChannelRemoveModerator), 20);
        assert_eq!(n(MessageType::ChannelKick), CHANNEL_META_CAP - 41);
    }

    #[test]
    fn overflowing_type_keeps_its_newest_rows() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        let cid = 1u64 << 40;
        put(&s, cid, MessageType::ChannelCreate, 1, 1, 0);
        // 400 kicks, ts 1000..1399; only 255 fit after the create.
        for i in 0..400u16 {
            put(&s, cid, MessageType::ChannelKick, 1_000 + i as u64, 5, i);
        }
        let out = channel_meta_envelopes(&s, cid, CHANNEL_META_CAP);
        assert_eq!(out.len(), 256);
        let kick_seqs: Vec<u16> = out
            .iter()
            .filter(|raw| raw[0] == MessageType::ChannelKick as u8)
            .map(|raw| u16::from_be_bytes([raw[2], raw[3]]))
            .collect();
        assert_eq!(kick_seqs.len(), 255);
        // Newest 255 (seq 145..=399) kept, oldest dropped.
        assert!(kick_seqs.iter().all(|&q| q >= 145), "an old kick survived: {:?}", kick_seqs.iter().min());
        assert!(kick_seqs.contains(&399));
    }
}
