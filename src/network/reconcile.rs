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
//! Plus a rolling-window work budget per `(peer, channel)` (l2-node
//! 0.141.0, `budget::Gcra`): `[backfill] total_envelopes_cap` units of
//! burst, refilled at `[backfill] total_envelopes_refill_per_hour`, charged
//! with `budget_charge` after each build. Before 0.141.0 this was a
//! LIFETIME counter that only reset when the responder restarted.
//!
//! Excess requests get a response with `server_capped = true` and
//! empty envelopes. The requester ends that session there (there is no
//! in-session retry); the channel is tried again by a later backfill
//! sweep, from the first page, once its attempt throttle allows
//! (`budget::AttemptThrottle` — a refused attempt backs off). The per-peer/per-channel limits never
//! queue or block. Only the node-wide build-slot bound lets a
//! CONTINUATION page (cursor present) wait briefly for a slot instead of
//! being refused (round-5 C-W1, `network::MAX_CONCURRENT_RESPONDER_BUILDS`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::network::budget::{BudgetMap, Gcra, Refusal};

use crate::messages::envelope::Envelope;
use crate::messages::types::MessageType;
use crate::storage::rocks::Storage;
use crate::storage::schema;

/// Codec type alias for the reconcile protocol.
pub type ReconcileCodec =
    libp2p::request_response::cbor::Behaviour<ReconcileRequest, ReconcileResponse>;

/// Protocol-string builder — the single source for the reconcile
/// protocol name registered in `network::behaviour`.
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
    /// Metadata paging (l2-node 0.152.0, G7). `Some` makes this a METADATA
    /// page request: the responder answers with the channel's
    /// `CHANNEL_META_MSGS` rows in replay order strictly after this keyset
    /// position (`channel_meta_page`; [`MetaCursor::START`] = from the
    /// beginning) and no chat. Sent only after a first page reported
    /// `meta_truncated`, i.e. only to a 0.152+ responder. Absent (`None`)
    /// on every request of an older requester. Additive, `#[serde(default)]`.
    #[serde(default)]
    pub meta_cursor: Option<MetaCursor>,
    /// Requester protocol revision (l2-node 0.152.0): `0` (absent) = a
    /// 0.151-or-older requester, [`RECONCILE_REVISION`] = 0.152+. A
    /// revision-0 requester is served exactly the 0.151 page shape: no
    /// `ChannelMute`/`ChannelUnmute` in the metadata ride-along (it applies
    /// the mute before the chat pages and would count every refused message
    /// of the muted user as page taint — its tally predates the neutral
    /// moderation refusal) and no chat-reaction ride-along (its page-size
    /// guard predates `CHANNEL_REACTION_CAP` and would discard the whole
    /// last page). Additive, `#[serde(default)]`.
    #[serde(default)]
    pub revision: u8,
}

/// The reconcile revision this node speaks (l2-node 0.152.0): pins and
/// mutes in the metadata, the chat-reaction ride-along, and metadata
/// paging (`ReconcileRequest::meta_cursor`).
pub const RECONCILE_REVISION: u8 = 1;

impl ReconcileRequest {
    /// A page AFTER the first of its session (round-5 C-W1): it carries the
    /// responder's `next_cursor`, or it is a metadata page (G7 — those
    /// only follow a first page). Only a non-continuation (first-page)
    /// request is refused outright when every responder build slot is
    /// busy. The claim is the requester's own (cursors are not
    /// authenticated) — the wait it earns is bounded separately
    /// (`network::MAX_CONTINUATION_BUILD_WAITERS`).
    pub fn is_continuation(&self) -> bool {
        self.cursor.is_some() || self.meta_cursor.is_some()
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
    /// This is a METADATA page (the answer to a request with
    /// `meta_cursor`; l2-node 0.152.0, G7). Older responders never set it,
    /// so a requester can tell a metadata page from a chat page.
    #[serde(default)]
    pub meta_page: bool,
    /// More metadata exists than this response carried (G7). On a FIRST
    /// chat page: the bounded metadata ride-along (`CHANNEL_META_CAP` rows,
    /// byte budget) did not include every `CHANNEL_META_MSGS` row of the
    /// channel — the requester then pages the metadata once the chat
    /// session ends. On a metadata page: another metadata page follows
    /// `meta_next_cursor`. Older responders never set it.
    #[serde(default)]
    pub meta_truncated: bool,
    /// Keyset position of the last row of this metadata page (G7) — the
    /// next metadata request's `meta_cursor`. `None` on chat pages.
    #[serde(default)]
    pub meta_next_cursor: Option<MetaCursor>,
}

/// Opaque-to-the-wire cursor for paging within a single
/// reconciliation. Encodes the last-delivered `(lamport_ts, msg_id)`
/// so the next scan resumes immediately after.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileCursor {
    pub after_lamport_ts: u64,
    pub after_msg_id: [u8; 32],
}

/// Hard cap on `(peer, channel)` keys tracked by one responder's rolling
/// budget (l2-node 0.141.0). The key includes a requester-chosen
/// `channel_id` (an unknown channel still charges 1 unit), so the map must
/// be bounded: past the cap NEW keys are refused (`server_capped`) until a
/// prune frees room — see `budget::BudgetMap`.
pub const MAX_TRACKED_BUDGET_KEYS: usize = 200_000;

/// Server-side rate-limit state. One instance per `NetworkService`,
/// keyed internally by `(peer_id, channel_id)` and `peer_id`.
///
/// Uses `std::sync::Mutex` not tokio's because the critical section
/// is short (counter updates, one map lookup; a prune walks at most
/// `MAX_TRACKED_BUDGET_KEYS` entries every 30 s) and nothing awaits
/// while holding it.
#[derive(Debug)]
pub struct ResponderLimits {
    inner: Mutex<ResponderLimitsInner>,
}

impl Default for ResponderLimits {
    fn default() -> Self {
        Self {
            inner: Mutex::new(ResponderLimitsInner {
                per_peer: HashMap::new(),
                per_pair: HashMap::new(),
                budget: BudgetMap::new(MAX_TRACKED_BUDGET_KEYS),
            }),
        }
    }
}

#[derive(Debug)]
struct ResponderLimitsInner {
    /// `peer_id` → number of active requests across all channels.
    per_peer: HashMap<libp2p::PeerId, usize>,
    /// `(peer_id, channel_id)` → number of active requests on that
    /// specific channel.
    per_pair: HashMap<(libp2p::PeerId, u64), usize>,
    /// `(peer_id, channel_id)` → rolling-window budget state (l2-node
    /// 0.141.0; Security Audit C2, 0.47.0, introduced the budget as a
    /// lifetime counter). Charged with `budget_charge` after each build;
    /// refills at the configured rate (`[backfill]
    /// total_envelopes_refill_per_hour`) up to the burst (`[backfill]
    /// total_envelopes_cap`). Bounded (`MAX_TRACKED_BUDGET_KEYS`) and
    /// pruned on the 30 s tick — only full buckets are dropped.
    budget: BudgetMap<(libp2p::PeerId, u64)>,
}

impl ResponderLimits {
    /// Try to reserve a slot. Returns the `Guard` on success, or the
    /// reason for the refusal — caller responds with `server_capped =
    /// true` and empty envelopes. Refusals are never charged.
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: libp2p::PeerId,
        channel: u64,
        max_per_peer: usize,
        max_per_channel: usize,
        budget: &Gcra,
        now: Instant,
    ) -> Result<ResponderGuard, Refusal> {
        // A poisoned lock is treated like a busy slot (fail closed).
        let mut inner = self.inner.lock().map_err(|_| Refusal::Concurrency)?;
        // Security Audit C2 (0.47.0) / 0.141.0: refuse while this
        // (peer, channel)'s rolling budget is spent — stops a malicious
        // requester from inducing an unbounded scan via repeated paging,
        // without locking an honest peer out until restart.
        inner.budget.admit(&(peer, channel), budget, now)?;
        // Read both counts without holding entry()-mutable borrows,
        // so we can release the per_peer borrow before reaching for
        // per_pair (borrow checker — both maps live in `inner`).
        let pp_current = inner.per_peer.get(&peer).copied().unwrap_or(0);
        if pp_current >= max_per_peer {
            return Err(Refusal::Concurrency);
        }
        let pc_current = inner
            .per_pair
            .get(&(peer, channel))
            .copied()
            .unwrap_or(0);
        if pc_current >= max_per_channel {
            return Err(Refusal::Concurrency);
        }
        inner.per_peer.insert(peer, pp_current + 1);
        inner.per_pair.insert((peer, channel), pc_current + 1);
        Ok(ResponderGuard {
            limits: Arc::clone(self),
            peer,
            channel,
        })
    }

    /// Charge `units` (`budget_charge`) to the (peer, channel) budget.
    /// Called after a successful build, before the response is queued, so
    /// the peer's next request already sees it.
    pub fn charge(&self, peer: libp2p::PeerId, channel: u64, units: u64, budget: &Gcra, now: Instant) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.budget.charge((peer, channel), units, budget, now);
        }
    }

    /// Drop every budget entry whose bucket is full again (never one in
    /// debt). Run on the 30 s tick. Returns how many were removed.
    pub fn prune(&self, now: Instant) -> usize {
        self.inner.lock().map(|mut inner| inner.budget.prune(now)).unwrap_or(0)
    }

    /// Number of tracked budget keys (tests).
    #[cfg(test)]
    pub fn budget_len(&self) -> usize {
        self.inner.lock().map(|inner| inner.budget.len()).unwrap_or(0)
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
                // Use server_capped to signal "go away" without
                // disclosing whether the channel exists or not.
                server_capped: true,
                ..ReconcileResponse::empty(request.channel_id)
            },
            1,
        );
    }

    let cap = max_envelopes.min(MAX_ENVELOPES_PER_RESPONSE_CEILING);
    // A 0.151-or-older requester gets exactly the 0.151 page shape (see
    // `ReconcileRequest::revision`).
    let legacy = request.revision < RECONCILE_REVISION;

    // --- Metadata page (l2-node 0.152.0, G7) ---
    // ALL of the channel's metadata rows in replay order, keyset-paged and
    // byte-bounded — the same walk private-channel sync's metadata phase
    // does (`channel_meta_page`). No chat on these pages. Charged to the
    // same (peer, channel) rolling budget as chat pages (the caller).
    if let Some(after) = request.meta_cursor.as_ref() {
        let tiers: &[&[u8]] = if legacy { &META_REPLAY_TIERS_NO_MUTES } else { &META_REPLAY_TIERS };
        let page = channel_meta_page_with(
            storage,
            request.channel_id,
            tiers,
            Some(after),
            // Round-1 audit W1: a FIXED page size, independent of this
            // node's `max_envelopes_per_response`, so a requester with a
            // smaller configured cap never refuses a metadata page.
            CHANNEL_META_PAGE_MAX,
            MAX_RESPONSE_ENVELOPE_BYTES,
        );
        return (
            ReconcileResponse {
                envelopes: page.envelopes,
                meta_page: true,
                meta_truncated: page.has_more,
                meta_next_cursor: page.next_cursor,
                ..ReconcileResponse::empty(request.channel_id)
            },
            page.work,
        );
    }

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
    } else if min_timestamp > 0 {
        // G2 (l2-node 0.151.0): the FIRST page seeks straight to the window
        // start instead of the channel's oldest row. Before, `probe_limit`
        // bounded RAW rows from the oldest, so a channel with more than
        // ~1,000 messages older than the requester's window fetched only
        // stale rows, came back `envelopes: [], has_more: false` and the
        // requester never received ANY history for it. Valid because
        // `CHANNEL_MSGS` keys are `(channel_id, timestamp_ms, msg_id)` with
        // the envelope's signed wall-clock timestamp in MILLISECONDS
        // (`router::update_indexes`, re-keyed by the
        // `CHANNEL_MSGS_TS_REINDEXED` migration), while `min_timestamp` is
        // unix SECONDS: `env.timestamp / 1000 >= min_timestamp` ⇔
        // `env.timestamp >= min_timestamp * 1000`. The all-zero `msg_id`
        // sorts before every real one at that timestamp, and
        // `prefix_iter_cf_after` only skips an exactly-equal key (which no
        // real row can be), so the first in-window row is included.
        let start_key = schema::encode_channel_msg_key(
            request.channel_id,
            min_timestamp.saturating_mul(1000),
            &[0u8; 32],
        );
        storage.prefix_iter_cf_after(schema::cf::CHANNEL_MSGS, &start_key, &prefix, probe_limit)
    } else {
        // Archive mode (`max_age_secs == u64::MAX`) — or a window reaching
        // back to the epoch: every row is in window, start at the oldest.
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
            return (ReconcileResponse::empty(request.channel_id), 1);
        }
    };
    // Budget (one unit per seek and per index row examined, its MESSAGES
    // read included — `budget_charge`).
    let mut work: u64 = 1 + rows.len() as u64;

    let mut envelopes: Vec<Vec<u8>> = Vec::with_capacity(cap);
    // Wire bytes of the page so far (W5): a page always fits the transport's
    // response cap (`MAX_RESPONSE_ENVELOPE_BYTES`).
    let mut bytes: usize = 0;

    // P-3b: on the FIRST page, ride the channel's L2 metadata + membership
    // envelopes (ChannelCreate/Update/Join/Leave) along with the chat history.
    // The chain scanner only writes a skeleton (slug/creator), so this is how a
    // node that chain-discovered a public channel gets its name/logo/members.
    // These are re-validated + applied by the requester like any synced
    // envelope (ChannelCreate apply is now merge-safe). Counted separately so
    // the chat `cap` below is unaffected.
    //
    // G7 (l2-node 0.152.0): for a 0.152+ requester the ride-along is the
    // CHRONOLOGICAL PREFIX of the metadata — page 1 of the metadata walk
    // (`channel_meta_page_with` from `MetaCursor::START`, ≤ `CHANNEL_META_CAP`
    // rows, byte-bounded). When rows remain, the response says so
    // (`meta_truncated`) and carries the walk position (`meta_next_cursor`),
    // and the requester continues the walk from THERE after the chat pages.
    // Round-1 audit B2: the earlier priority selection (newest-first per
    // type) followed by a walk from the start replayed the cut, OLDER rows
    // after newer ones; mute/unmute, ban/unban and pin/unpin are applied
    // literally (not last-write-wins), so a re-muted / re-banned user ended
    // unmuted / unbanned and pins duplicated. A chronological prefix plus
    // its continuation replays every row exactly once, in order.
    // A 0.151 requester (revision 0) keeps the priority selection (its own
    // pre-existing limitation; it never pages).
    let mut meta_truncated = false;
    let mut first_meta_cursor: Option<MetaCursor> = None;
    if request.cursor.is_none() {
        if legacy {
            let ride = channel_meta_ride_along(storage, request.channel_id, CHANNEL_META_CAP, true);
            work += ride.work;
            bytes = append_within_byte_budget(&mut envelopes, ride.envelopes, bytes);
        } else {
            let page = channel_meta_page_with(
                storage,
                request.channel_id,
                &META_REPLAY_TIERS,
                Some(&MetaCursor::START),
                CHANNEL_META_CAP,
                MAX_RESPONSE_ENVELOPE_BYTES,
            );
            work += page.work;
            for raw in &page.envelopes {
                bytes = bytes.saturating_add(envelope_wire_cost(raw));
            }
            envelopes.extend(page.envelopes);
            meta_truncated = page.has_more;
            if meta_truncated {
                first_meta_cursor = page.next_cursor;
            }
        }
    }

    let mut last_cursor: Option<ReconcileCursor> = None;
    let mut hit_cap = false;
    let mut chat_count = 0usize;
    // The storage batch came back full: rows may exist beyond it even when
    // fewer than `cap` of these were eligible (window / D4 skips below).
    let truncated = rows.len() >= probe_limit;
    // Position of the last row EXAMINED (served or skipped) — the resume
    // point when a truncated batch ends without filling the page.
    let mut last_examined: Option<ReconcileCursor> = None;

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

        // A genuine (cap+1)-th eligible row is checked below, before this
        // row is consumed; until then every examined row moves the resume
        // point past it.
        if chat_count < cap {
            last_examined = Some(ReconcileCursor { after_lamport_ts: lamport_ts, after_msg_id: msg_id });
        }

        // D4 (l2-node 0.151.0): an original its author erased with a GDPR
        // DeletionRequest is never re-served. The request itself still rides
        // along on the last page (`channel_edit_delete_envelopes_metered`), so
        // a fresh requester learns of the erasure without the content.
        if storage.is_gdpr_erased(&msg_id) {
            continue;
        }

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
        // W5: the page is full by BYTES — continue on the next page from
        // the last delivered row (at least one row is always served).
        if chat_count > 0 && bytes.saturating_add(envelope_wire_cost(&raw)) > MAX_RESPONSE_ENVELOPE_BYTES {
            hit_cap = true;
            break;
        }

        bytes = bytes.saturating_add(envelope_wire_cost(&raw));
        envelopes.push(raw);
        chat_count += 1;
        last_cursor = Some(ReconcileCursor {
            after_lamport_ts: lamport_ts,
            after_msg_id: msg_id,
        });
    }

    // A truncated batch that did not fill the page (some examined rows were
    // skipped) still has rows beyond it: continue after the last examined
    // row instead of ending the session early (which would strand them).
    if !hit_cap && truncated {
        hit_cap = true;
        last_cursor = last_examined;
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
        // W5: newest markers first; whatever does not fit the byte budget
        // is not shipped this session (recorded limitation).
        let bytes = append_within_byte_budget(&mut envelopes, ed, bytes);
        // G6 (l2-node 0.152.0): chat reactions ride along after the
        // edit/delete markers (their targets are applied by now, like the
        // markers'), newest first, with their OWN cap and inside the same
        // byte budget. Only for a 0.152+ requester (`revision`): an older
        // one's page-size guard would refuse the whole page.
        if !legacy {
            let (re, re_work) = channel_reaction_envelopes_metered(
                storage,
                request.channel_id,
                min_timestamp,
                CHANNEL_REACTION_CAP,
            );
            work += re_work;
            append_within_byte_budget(&mut envelopes, re, bytes);
        }
    }

    (
        ReconcileResponse {
            envelopes,
            has_more: hit_cap,
            next_cursor: if hit_cap { last_cursor } else { None },
            meta_truncated,
            meta_next_cursor: first_meta_cursor,
            ..ReconcileResponse::empty(request.channel_id)
        },
        work,
    )
}

impl ReconcileResponse {
    /// An empty, finished, uncapped response for `channel_id` (every
    /// optional field at its default) — the base the builders override.
    pub fn empty(channel_id: u64) -> Self {
        ReconcileResponse {
            channel_id,
            envelopes: Vec::new(),
            has_more: false,
            next_cursor: None,
            server_capped: false,
            epoch_root: None,
            meta_page: false,
            meta_truncated: false,
            meta_next_cursor: None,
        }
    }
}

/// Upper bound on the summed envelope bytes of one backfill response page
/// (l2-node 0.151.0, audit W5) for reconcile, news-sync and dm-sync. The
/// libp2p CBOR codec refuses a response above 10 MiB; keeping the summed
/// worst-case wire cost of the envelopes (`envelope_wire_cost`) ≤ 8 MiB
/// leaves room for the rest of the CBOR structure, so an honest page never
/// fails in transport (which would end the session without completing it).
pub const MAX_RESPONSE_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;

/// Worst-case bytes one envelope costs on the wire. The responses carry
/// `Vec<Vec<u8>>` through serde, which CBOR encodes as an ARRAY of integers
/// (not a byte string): every byte ≥ 24 takes two bytes. So twice the
/// length, plus an allowance for the array header and slot.
pub fn envelope_wire_cost(raw: &[u8]) -> usize {
    raw.len().saturating_mul(2).saturating_add(16)
}

/// Append `items` (in order) to `envelopes` while the page stays within
/// `MAX_RESPONSE_ENVELOPE_BYTES`; returns the new byte total. Items that
/// do not fit are dropped (logged at debug) — used for ride-alongs, which
/// are best-effort and newest-first, so the oldest are the ones dropped.
pub(crate) fn append_within_byte_budget(envelopes: &mut Vec<Vec<u8>>, items: Vec<Vec<u8>>, mut bytes: usize) -> usize {
    let total = items.len();
    let mut taken = 0usize;
    for raw in items {
        let cost = envelope_wire_cost(&raw);
        if bytes.saturating_add(cost) > MAX_RESPONSE_ENVELOPE_BYTES {
            break;
        }
        bytes += cost;
        envelopes.push(raw);
        taken += 1;
    }
    if taken < total {
        debug!(dropped = total - taken, "backfill: ride-along truncated at the response byte budget");
    }
    bytes
}

/// Upper bound on metadata envelopes `channel_meta_envelopes` returns, and
/// on the first-page metadata prefix (l2-node 0.152.0).
pub(crate) const CHANNEL_META_CAP: usize = 256;

/// Rows per public-reconcile METADATA page (l2-node 0.152.0, round-1 audit
/// W1) — a protocol constant, independent of `[backfill]
/// max_envelopes_per_response`, so responder and requester agree whatever
/// their configs. The requester refuses (and stops the walk on) a larger
/// metadata page.
pub const CHANNEL_META_PAGE_MAX: usize = 500;

/// The largest reconcile page an honest responder with a primary page cap of
/// `max_envelopes` sends: the chat page plus the first-page metadata
/// ride-along plus the last-page edit/delete ride-along (l2-node 0.151.0).
/// The requester refuses (does not verify) anything larger. Before
/// 0.151.0 it compared against `max_envelopes` alone, so a first page of a
/// channel with a full chat page (plus its `ChannelCreate`) — or any last
/// page whose markers pushed it past the cap — was discarded whole.
///
/// l2-node 0.152.0: plus the chat-reaction ride-along
/// (`CHANNEL_REACTION_CAP`), which a 0.152+ responder sends only to a
/// requester that announced `RECONCILE_REVISION` — so this bound is never
/// exceeded towards an older requester, whose own bound lacks it.
pub fn max_page_with_ride_alongs(max_envelopes: usize) -> usize {
    max_envelopes
        .min(MAX_ENVELOPES_PER_RESPONSE_CEILING)
        .saturating_add(CHANNEL_META_CAP)
        .saturating_add(CHANNEL_EDIT_DELETE_CAP)
        .saturating_add(CHANNEL_REACTION_CAP)
}

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
///
/// l2-node 0.152.0 (G6): `ChannelPinMessage`/`ChannelUnpinMessage`
/// (`can_pin`) and `ChannelMute`/`ChannelUnmute` (`can_mute`) join tier 1.
/// They are authorised against the moderator record at replay time like a
/// kick, so chronological replay is what makes a pin/mute signed after a
/// grant succeed and one signed after a demotion fail; and pin/unpin and
/// mute/unmute pairs settle on the newest.
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
        MessageType::ChannelPinMessage as u8,
        MessageType::ChannelUnpinMessage as u8,
        MessageType::ChannelMute as u8,
        MessageType::ChannelUnmute as u8,
    ],
];

/// `META_REPLAY_TIERS` without `ChannelMute`/`ChannelUnmute` — what a
/// requester older than 0.152.0 is served (public reconcile
/// `ReconcileRequest::revision` 0, private-channel sync
/// `PrivateChannelSyncRequest::revision` 0). Such a requester applies a
/// mute before the chat pages, so it would refuse every message the muted
/// user posted before the mute and — its tally predating the neutral
/// moderation refusal (`router::is_moderation_refusal`) — count each as
/// page taint; its private-sync allow-list also lacks the mute types. Pins are harmless to
/// it and are served.
pub(crate) const META_REPLAY_TIERS_NO_MUTES: [&[u8]; 2] = [
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
        MessageType::ChannelPinMessage as u8,
        MessageType::ChannelUnpinMessage as u8,
    ],
];

/// `true` iff `raw` decodes (top-level `Envelope` only, never the payload)
/// to a type `CHANNEL_META_MSGS` holds (`META_REPLAY_TIERS`) — what a
/// metadata page may carry (l2-node 0.152.0, G7).
pub(crate) fn envelope_is_meta_type(raw: &[u8]) -> bool {
    rmp_serde::from_slice::<Envelope>(raw)
        .map(|env| META_REPLAY_TIERS.iter().any(|t| t.contains(&env.msg_type_u8())))
        .unwrap_or(false)
}

/// `true` for the two mute types withheld from requesters older than
/// 0.152.0 (`META_REPLAY_TIERS_NO_MUTES`).
pub(crate) fn is_mute_type(msg_type: MessageType) -> bool {
    matches!(msg_type, MessageType::ChannelMute | MessageType::ChannelUnmute)
}

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
///
/// l2-node 0.152.0 (G6): mutes and pins come after `ChannelUnban` and before
/// `ChannelUpdate` — moderation state ahead of the cosmetic and high-volume
/// rows. `ChannelMute` first (a missing mute lets a muted user post through
/// the requester), its `ChannelUnmute` next, then `ChannelUnpinMessage`
/// before `ChannelPinMessage` (an unpin without its pin is a no-op, a pin
/// without its later unpin resurrects it). Whatever the cap leaves out is
/// reported as `meta_truncated` and paged by a 0.152+ requester (G7).
const RIDE_ALONG_PRIORITY: [MessageType; 14] = [
    MessageType::ChannelCreate,
    MessageType::ChannelDelete,
    MessageType::ChannelRemoveModerator,
    MessageType::ChannelAddModerator,
    MessageType::ChannelKick,
    MessageType::ChannelBan,
    MessageType::ChannelUnban,
    MessageType::ChannelMute,
    MessageType::ChannelUnmute,
    MessageType::ChannelUnpinMessage,
    MessageType::ChannelPinMessage,
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
/// (Test convenience wrapper — production builds the first-page ride-along
/// with `channel_meta_ride_along`.)
#[cfg(test)]
pub(crate) fn channel_meta_envelopes(storage: &Storage, channel_id: u64, cap: usize) -> Vec<Vec<u8>> {
    channel_meta_envelopes_metered(storage, channel_id, cap).0
}

/// `channel_meta_envelopes` plus the storage work it did (one unit per seek
/// and per index row read, its `MESSAGES` read included), for the
/// responder budget. The full (0.152) type set. (Tests; production calls
/// `channel_meta_ride_along`.)
#[cfg(test)]
pub(crate) fn channel_meta_envelopes_metered(
    storage: &Storage,
    channel_id: u64,
    cap: usize,
) -> (Vec<Vec<u8>>, u64) {
    let ride = channel_meta_ride_along(storage, channel_id, cap, false);
    (ride.envelopes, ride.work)
}

/// One bounded metadata ride-along (`channel_meta_ride_along`).
#[derive(Debug, Default)]
pub(crate) struct MetaRideAlong {
    /// Stored envelope bytes in replay order.
    pub envelopes: Vec<Vec<u8>>,
    /// Storage work done (seeks and rows read).
    pub work: u64,
}

/// The selection behind `channel_meta_envelopes` (see its doc) — used only
/// for requesters older than 0.152.0 (the public first page of a revision-0
/// requester and the legacy private first page). `no_mutes` skips
/// `ChannelMute`/`ChannelUnmute` (`META_REPLAY_TIERS_NO_MUTES`). A 0.152+
/// public requester instead gets the chronological prefix
/// (`channel_meta_page_with`, round-1 audit B2).
pub(crate) fn channel_meta_ride_along(storage: &Storage, channel_id: u64, cap: usize, no_mutes: bool) -> MetaRideAlong {
    let cap = cap.min(CHANNEL_META_CAP);
    let mut work: u64 = 0;
    let mut chosen: Vec<(u8, u64, [u8; 32])> = Vec::with_capacity(cap);
    for msg_type in RIDE_ALONG_PRIORITY {
        if no_mutes && is_mute_type(msg_type) {
            continue;
        }
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
    MetaRideAlong { envelopes, work }
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

impl MetaCursor {
    /// The keyset position before every real row (l2-node 0.152.0, G7):
    /// "strictly after `(tier 0, ts 0, msg_id 0…0)`" includes every row,
    /// because no real envelope has an all-zero `msg_id` (it is a hash).
    /// The first metadata page request of a public reconcile session
    /// carries it (`None` there means "no metadata page").
    pub const START: MetaCursor = MetaCursor { tier: 0, ts: 0, msg_id: [0u8; 32] };
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
///
/// (Test convenience wrapper over the full tier set and the standard byte
/// budget — production calls `channel_meta_page_with`.)
#[cfg(test)]
pub(crate) fn channel_meta_page(
    storage: &Storage,
    channel_id: u64,
    after: Option<&MetaCursor>,
    cap: usize,
) -> MetaPage {
    channel_meta_page_with(storage, channel_id, &META_REPLAY_TIERS, after, cap, MAX_RESPONSE_ENVELOPE_BYTES)
}

/// `channel_meta_page` over an explicit tier set (`META_REPLAY_TIERS` or,
/// for a requester older than 0.152.0, `META_REPLAY_TIERS_NO_MUTES`) and
/// byte budget (l2-node 0.152.0): the page also stops once the summed
/// worst-case wire cost of its envelopes would pass `max_bytes` (at least
/// one envelope is always served); `next_cursor` is then the last row
/// served and `has_more` is set, so nothing is skipped.
pub(crate) fn channel_meta_page_with(
    storage: &Storage,
    channel_id: u64,
    tiers: &[&[u8]],
    after: Option<&MetaCursor>,
    cap: usize,
    max_bytes: usize,
) -> MetaPage {
    let cap = cap.max(1);
    let after = after.map(|c| (c.tier, c.ts, c.msg_id));
    let (rows, mut has_more, work) =
        match storage.channel_meta_replay_page(channel_id, tiers, after, cap) {
            Ok(r) => r,
            Err(e) => {
                warn!(channel_id, error = %e, "metadata page: CHANNEL_META_MSGS iteration failed");
                return MetaPage { work: 1, ..Default::default() };
            }
        };
    let mut envelopes = Vec::with_capacity(rows.len());
    let mut bytes = 0usize;
    let mut last: Option<&crate::storage::rocks::MetaIndexRow> = None;
    for r in &rows {
        if let Some(raw) = storage.get_message(&r.msg_id).ok().flatten() {
            let cost = envelope_wire_cost(&raw);
            if !envelopes.is_empty() && bytes.saturating_add(cost) > max_bytes {
                // Full by bytes: this row and the rest follow on the next
                // page (the cursor stays at the last row served).
                has_more = true;
                break;
            }
            bytes = bytes.saturating_add(cost);
            envelopes.push(raw);
        }
        // A row whose `MESSAGES` entry is gone still advances the cursor.
        last = Some(r);
    }
    let next_cursor = last.map(|r| MetaCursor { tier: r.tier, ts: r.ts, msg_id: r.msg_id });
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
            // D4: an edit (it carries the new plaintext) or delete of a
            // GDPR-erased message is not served — the original never is, so
            // the requester could not apply it anyway. The DeletionRequest
            // itself is indexed here too (l2-node 0.151.0) and IS served.
            if ride_along_target_erased(storage, &raw) {
                continue;
            }
            out.push(raw);
        }
    }
    (out, work)
}

/// Max chat reactions one ride-along carries (public reconcile, l2-node
/// 0.152.0, G6) — like news-sync's reaction ride-along.
pub(crate) const CHANNEL_REACTION_CAP: usize = 4_000;

/// Gather a channel's `ChatReaction` envelopes (`CHAT_REACTION_MSGS`,
/// l2-node 0.152.0, G6) to ride along on the LAST page of a reconcile
/// session, after the edit/delete markers — same rule as those: by the
/// last page every original the session could deliver is applied. Before
/// 0.152.0 chat reactions reached a backfilling node by no mechanism, so
/// its counts were 0 or different.
///
/// The NEWEST `limit` (≤ `CHANNEL_REACTION_CAP`) rows signed inside the
/// window (`min_timestamp`, unix seconds), newest first; under overflow the
/// OLDEST are not shipped this session. Order does not matter to the
/// requester: `Storage::toggle_chat_reaction` is last-write-wins. A reaction
/// to a GDPR-erased message is withheld (D4, `ride_along_target_erased`).
/// The index only holds rows keyed by the TARGET's own channel, so nothing
/// of another channel can be served here. Returns the envelopes plus the
/// storage work done. Private-channel sync passes the room left on its
/// page.
pub(crate) fn channel_reaction_envelopes_metered(
    storage: &Storage,
    channel_id: u64,
    min_timestamp: u64,
    limit: usize,
) -> (Vec<Vec<u8>>, u64) {
    let limit = limit.min(CHANNEL_REACTION_CAP);
    if limit == 0 {
        return (Vec::new(), 0);
    }
    let prefix = channel_id.to_be_bytes();
    let rows = match storage.reverse_iter_cf(
        schema::cf::CHAT_REACTION_MSGS,
        &schema::message_key_upper_bound(&prefix),
        &prefix,
        limit,
    ) {
        Ok(r) => r,
        Err(_) => return (Vec::new(), 1),
    };
    let work: u64 = 1 + rows.len() as u64;
    let mut out = Vec::with_capacity(rows.len());
    for (key, _) in rows {
        // Key shape matches CHANNEL_MSGS: channel_id:8 ++ timestamp:8 ++ msg_id:32.
        if key.len() != 48 {
            continue;
        }
        let Ok(ts_bytes) = <[u8; 8]>::try_from(&key[8..16]) else { continue };
        if u64::from_be_bytes(ts_bytes) / 1000 < min_timestamp {
            // Reverse scan: every further row is older still.
            break;
        }
        let Ok(msg_id) = <[u8; 32]>::try_from(&key[16..48]) else { continue };
        if let Ok(Some(raw)) = storage.get_message(&msg_id) {
            if ride_along_target_erased(storage, &raw) {
                continue;
            }
            out.push(raw);
        }
    }
    (out, work)
}

/// `true` iff `raw` is an edit / delete / reaction whose TARGET carries a
/// verified GDPR `DeletionRequest` record (l2-node 0.151.0, decision D4) —
/// such a ride-along is never served: an edit would re-serve erased
/// content, and none of them can be applied by a requester that never
/// receives the original. A `DeletionRequest` itself is never filtered
/// (that is how the requester learns of the erasure), nor is anything that
/// does not decode (the requester's router decides).
pub(crate) fn ride_along_target_erased(storage: &Storage, raw: &[u8]) -> bool {
    use crate::messages::types::{DeletePayload, EditPayload, ReactionPayload};
    let Ok(env) = rmp_serde::from_slice::<Envelope>(raw) else {
        return false;
    };
    let target = match env.msg_type {
        MessageType::ChatEdit | MessageType::DirectMessageEdit | MessageType::NewsEdit => {
            rmp_serde::from_slice::<EditPayload>(&env.payload).ok().map(|p| p.target_id)
        }
        MessageType::ChatDelete | MessageType::DirectMessageDelete | MessageType::NewsDelete => {
            rmp_serde::from_slice::<DeletePayload>(&env.payload).ok().map(|p| p.target_id)
        }
        MessageType::ChatReaction | MessageType::NewsReaction | MessageType::DirectMessageReaction => {
            rmp_serde::from_slice::<ReactionPayload>(&env.payload).ok().map(|p| p.target_id)
        }
        _ => None,
    };
    target.is_some_and(|t| storage.is_gdpr_erased(&t))
}

/// Inspect the `CHANNELS` metadata row for `channel_id` and return
/// `true` if it is marked `channel_type = 2` (private). Used by
/// [`build_response`] to refuse private-channel history over the
/// unauthenticated reconcile path. Returns `false` for unknown
/// channels (we don't have metadata yet) — those go through the
/// normal scan, but `CHANNEL_MSGS` will be empty for them anyway so
/// the response is empty regardless.
///
/// Mirrors `crate::messages::router::is_private_channel_meta`.
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
    ReconcileResponse { server_capped: true, ..ReconcileResponse::empty(request.channel_id) }
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
            meta_cursor: None,
            revision: 0,
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
            meta_cursor: None,
            revision: 0,
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
            meta_cursor: None,
            revision: 0,
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
            meta_cursor: None,
            revision: 0,
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
            meta_cursor: None,
            revision: 0,
        };
        let resp = build_response(&s, &req, 500, 5_000);
        assert!(!resp.has_more);
        assert!(contains_type(&resp.envelopes, MessageType::ChatDelete));
    }

    // --- G2 (l2-node 0.151.0): first page seeks from the window start ---

    fn id(n: u32) -> [u8; 32] {
        let mut id = [0x5Au8; 32];
        id[..4].copy_from_slice(&n.to_be_bytes());
        id
    }

    fn msg_ids(envelopes: &[Vec<u8>]) -> Vec<[u8; 32]> {
        envelopes.iter().map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_id).collect()
    }

    const NOW: u64 = 2_000_000_000; // unix SECONDS
    const DAY: u64 = 86_400;

    fn window_req(channel_id: u64, max_age_secs: u64, cursor: Option<ReconcileCursor>) -> ReconcileRequest {
        ReconcileRequest {
            channel_id,
            max_age_secs,
            cursor,
            fingerprint: Vec::new(),
            epoch_root_known: None,
            round: 0,
            meta_cursor: None,
            revision: 0,
        }
    }

    /// The KNOWN LIMITATION this release closes: 1,500 messages older than
    /// the 30-day window used to fill the whole first probe, so the page
    /// came back empty with `has_more = false` and the 10 in-window
    /// messages were never delivered.
    #[test]
    fn first_page_skips_a_stale_backlog_and_delivers_the_window() {
        let (s, _d) = db();
        let cid = 90u64;
        for n in 0..1_500u32 {
            // Key timestamps are MILLISECONDS.
            put_chat_message(&s, cid, id(n), (NOW - 40 * DAY) * 1000 + n as u64);
        }
        for n in 0..10u32 {
            put_chat_message(&s, cid, id(10_000 + n), (NOW - DAY) * 1000 + n as u64);
        }
        let resp = build_response(&s, &window_req(cid, 30 * DAY, None), 1_000, NOW);
        assert_eq!(resp.envelopes.len(), 10);
        assert!(!resp.has_more);
        assert!(resp.next_cursor.is_none());
        assert_eq!(msg_ids(&resp.envelopes), (0..10).map(|n| id(10_000 + n)).collect::<Vec<_>>());
    }

    /// Units: the seek converts the window start from seconds to the key's
    /// milliseconds — a row exactly at the boundary is in, one ms before is
    /// out (matching the per-row `timestamp / 1000 >= min` check).
    #[test]
    fn window_start_seek_is_in_milliseconds_and_inclusive() {
        let (s, _d) = db();
        let cid = 91u64;
        let start_ms = (NOW - 30 * DAY) * 1000;
        put_chat_message(&s, cid, id(1), start_ms - 1);
        put_chat_message(&s, cid, id(2), start_ms);
        put_chat_message(&s, cid, id(3), start_ms + 1);
        let resp = build_response(&s, &window_req(cid, 30 * DAY, None), 1_000, NOW);
        assert_eq!(msg_ids(&resp.envelopes), vec![id(2), id(3)]);
    }

    /// Archive mode (`u64::MAX`) is unchanged: it starts at the oldest row
    /// and pages by cursor.
    #[test]
    fn archive_mode_still_starts_at_the_oldest_row() {
        let (s, _d) = db();
        let cid = 92u64;
        for n in 0..15u32 {
            put_chat_message(&s, cid, id(n), (NOW - 400 * DAY) * 1000 + n as u64);
        }
        let p1 = build_response(&s, &window_req(cid, u64::MAX, None), 10, NOW);
        assert_eq!(msg_ids(&p1.envelopes), (0..10).map(id).collect::<Vec<_>>());
        assert!(p1.has_more);
        let p2 = build_response(&s, &window_req(cid, u64::MAX, p1.next_cursor), 10, NOW);
        assert_eq!(msg_ids(&p2.envelopes), (10..15).map(id).collect::<Vec<_>>());
        assert!(!p2.has_more);
    }

    // --- D4 (l2-node 0.151.0): erased originals are never served ---

    fn put_deletion_request(s: &Storage, target: [u8; 32], request_id: [u8; 32], ts: u64) {
        use crate::messages::types::{DeletionRequestPayload, DeletionType};
        let payload = DeletionRequestPayload { delete_type: DeletionType::SingleMessage, target_id: Some(target) };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DeletionRequest,
            msg_id: request_id,
            author: "klv1author".to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(schema::cf::MESSAGES, &request_id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
        s.put_verified_deletion_request(&target, &request_id, "klv1author", ts).unwrap();
        assert!(s.index_deletion_request(&target, &request_id, ts).unwrap(), "chat target → indexed");
    }

    /// The erased original, and a delete of it, are not served; the
    /// DeletionRequest is (on the last page).
    #[test]
    fn erased_original_is_withheld_and_its_request_rides_along() {
        let (s, _d) = db();
        let cid = 93u64;
        let base = (NOW - DAY) * 1000;
        put_chat_message(&s, cid, id(1), base);
        put_chat_message(&s, cid, id(2), base + 1);
        put_chat_delete(&s, cid, id(2), id(50), base + 2);
        put_deletion_request(&s, id(2), id(60), base + 3);
        let resp = build_response(&s, &window_req(cid, 30 * DAY, None), 1_000, NOW);
        let got = msg_ids(&resp.envelopes);
        assert!(got.contains(&id(1)));
        assert!(!got.contains(&id(2)), "erased original withheld");
        assert!(!got.contains(&id(50)), "a delete of an erased message is not served");
        assert!(got.contains(&id(60)), "the DeletionRequest rides along");
        assert!(contains_type(&resp.envelopes, MessageType::DeletionRequest));
    }

    /// Skipped (erased) rows inside a FULL storage batch must not end the
    /// session early: the page reports `has_more` with a cursor past the
    /// last examined row, and the next page delivers the rest.
    #[test]
    fn skipped_rows_in_a_full_batch_do_not_strand_later_rows() {
        let (s, _d) = db();
        let cid = 94u64;
        let base = (NOW - DAY) * 1000;
        for n in 0..8u32 {
            put_chat_message(&s, cid, id(n), base + n as u64);
        }
        put_deletion_request(&s, id(1), id(100), base + 20);
        put_deletion_request(&s, id(2), id(101), base + 21);
        // cap 4 → probe 5 raw rows (0..=4), two of them erased → 3 eligible.
        let p1 = build_response(&s, &window_req(cid, 30 * DAY, None), 4, NOW);
        assert_eq!(msg_ids(&p1.envelopes), vec![id(0), id(3), id(4)]);
        assert!(p1.has_more, "rows 5..8 exist beyond the batch");
        assert!(!contains_type(&p1.envelopes, MessageType::DeletionRequest), "ride-along only on the last page");
        let p2 = build_response(&s, &window_req(cid, 30 * DAY, p1.next_cursor), 4, NOW);
        let got = msg_ids(&p2.envelopes);
        assert!(got.starts_with(&[id(5), id(6), id(7)]));
        assert!(!p2.has_more);
        assert!(got.contains(&id(100)) && got.contains(&id(101)));
    }

    /// W5: ride-alongs stop at the byte budget instead of overflowing the
    /// page (newest first, the rest is not shipped this session).
    #[test]
    fn ride_alongs_stop_at_the_byte_budget() {
        let item = vec![0u8; (1024 * 1024 - 16) / 2]; // exactly 1 MiB of wire cost
        let mut page = Vec::new();
        let bytes = append_within_byte_budget(&mut page, vec![item.clone(); 20], 0);
        assert_eq!(page.len(), 8);
        assert_eq!(bytes, MAX_RESPONSE_ENVELOPE_BYTES);
        let mut page = vec![vec![0u8; 10]];
        let bytes = append_within_byte_budget(&mut page, vec![item; 20], 7 * 1024 * 1024 + 100);
        assert_eq!(page.len(), 1, "no room left for another MiB");
        assert_eq!(bytes, 7 * 1024 * 1024 + 100);
    }

    #[test]
    fn requester_page_bound_includes_the_ride_alongs() {
        assert_eq!(
            max_page_with_ride_alongs(1_000),
            1_000 + CHANNEL_META_CAP + CHANNEL_EDIT_DELETE_CAP + CHANNEL_REACTION_CAP
        );
        assert_eq!(
            max_page_with_ride_alongs(usize::MAX),
            MAX_ENVELOPES_PER_RESPONSE_CEILING + CHANNEL_META_CAP + CHANNEL_EDIT_DELETE_CAP + CHANNEL_REACTION_CAP
        );
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

    /// A budget large enough to never bite (concurrency tests).
    fn unlimited() -> Gcra {
        Gcra::new(u64::MAX / 4, u64::MAX / 4)
    }

    #[test]
    fn responder_limits_enforce_per_pair_cap() {
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        let now = Instant::now();
        let g1 = limits
            .try_acquire(peer, 42, 4, 1, &unlimited(), now)
            .expect("first acquire must succeed");
        let g2 = limits.try_acquire(peer, 42, 4, 1, &unlimited(), now);
        assert!(
            matches!(g2, Err(Refusal::Concurrency)),
            "per-pair cap = 1 must reject second concurrent request"
        );
        drop(g1);
        let g3 = limits
            .try_acquire(peer, 42, 4, 1, &unlimited(), now)
            .expect("after drop, slot is free again");
        drop(g3);
    }

    #[test]
    fn responder_limits_enforce_per_peer_cap() {
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        let now = Instant::now();
        let b = unlimited();
        // Four distinct channels under a per_peer cap of 4 + per_pair
        // cap of 1 — all four succeed.
        let _g1 = limits.try_acquire(peer, 1, 4, 1, &b, now).expect("ch1");
        let _g2 = limits.try_acquire(peer, 2, 4, 1, &b, now).expect("ch2");
        let _g3 = limits.try_acquire(peer, 3, 4, 1, &b, now).expect("ch3");
        let _g4 = limits.try_acquire(peer, 4, 4, 1, &b, now).expect("ch4");
        // Fifth channel is denied by the per-peer cap.
        let g5 = limits.try_acquire(peer, 5, 4, 1, &b, now);
        assert!(g5.is_err(), "per-peer cap = 4 must reject 5th channel");
    }

    #[test]
    fn responder_limits_isolate_peers() {
        let limits = Arc::new(ResponderLimits::default());
        let alice = fake_peer();
        let bob = fake_peer();
        let now = Instant::now();
        let _g1 = limits
            .try_acquire(alice, 1, 1, 1, &unlimited(), now)
            .expect("alice first");
        // Bob has his own per-peer budget.
        let g2 = limits.try_acquire(bob, 1, 1, 1, &unlimited(), now);
        assert!(
            g2.is_ok(),
            "per-peer caps must NOT interfere across peers"
        );
    }

    #[test]
    fn responder_limits_enforce_the_rolling_budget_and_refill_it() {
        // Security Audit C2 (0.47.0) + 0.141.0: the work served per
        // (peer, channel) is bounded by the burst (`total_envelopes_cap`)
        // regardless of how the peer paces its pages — but the budget
        // REFILLS (here 3,600/h = 1 unit/s) instead of lasting until the
        // responder restarts.
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        let budget = Gcra::new(100, 3_600);
        let t0 = Instant::now();
        let g1 = limits
            .try_acquire(peer, 7, 4, 1, &budget, t0)
            .expect("first request must succeed");
        limits.charge(peer, 7, 50, &budget, t0);
        drop(g1);
        // 50 < 100 spent: the second request still succeeds, serves 60.
        let g2 = limits
            .try_acquire(peer, 7, 4, 1, &budget, t0)
            .expect("50 of 100 spent, second request must succeed");
        limits.charge(peer, 7, 60, &budget, t0);
        drop(g2);
        // 110 >= 100: refused…
        let g3 = limits.try_acquire(peer, 7, 4, 1, &budget, t0);
        assert!(matches!(g3, Err(Refusal::OverBudget)), "spent budget must refuse");
        // …still refused 5 s later (debt 105 s), admitted once 11 units
        // refilled (debt 99 s < tolerance 100 s).
        assert!(limits.try_acquire(peer, 7, 4, 1, &budget, t0 + std::time::Duration::from_secs(5)).is_err());
        assert!(limits.try_acquire(peer, 7, 4, 1, &budget, t0 + std::time::Duration::from_secs(11)).is_ok());
    }

    #[test]
    fn responder_limits_per_pair_budget_isolated() {
        // The budget is per (peer, channel) — a peer that exhausted
        // channel A's budget can still backfill channel B.
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        let budget = Gcra::new(100, 1);
        let now = Instant::now();
        limits.charge(peer, 1, 200, &budget, now);
        let g_a = limits.try_acquire(peer, 1, 4, 1, &budget, now);
        assert!(g_a.is_err(), "channel 1 exhausted");
        let g_b = limits
            .try_acquire(peer, 2, 4, 1, &budget, now)
            .expect("channel 2 untouched");
        drop(g_b);
    }

    #[test]
    fn responder_budget_map_is_bounded_and_pruned() {
        // The key includes a requester-chosen channel_id: spraying ids is
        // bounded by MAX_TRACKED_BUDGET_KEYS (new keys refused, existing
        // ones unaffected) and cleared by the prune once refilled.
        let limits = Arc::new(ResponderLimits::default());
        let peer = fake_peer();
        let budget = Gcra::new(200_000, 10_000);
        let now = Instant::now();
        limits.charge(peer, 0, 150_000, &budget, now); // a real key, in debt
        for cid in 1..MAX_TRACKED_BUDGET_KEYS as u64 {
            limits.charge(peer, cid, 1, &budget, now);
        }
        assert_eq!(limits.budget_len(), MAX_TRACKED_BUDGET_KEYS);
        assert!(matches!(
            limits.try_acquire(peer, u64::MAX, 4, 1, &budget, now),
            Err(Refusal::MapFull)
        ));
        assert!(limits.try_acquire(peer, 0, 4, 1, &budget, now).is_ok(), "existing key unaffected");
        let later = now + std::time::Duration::from_secs(5);
        assert_eq!(limits.prune(later), MAX_TRACKED_BUDGET_KEYS - 1, "only refilled buckets dropped");
        assert_eq!(limits.budget_len(), 1, "the key in debt survives");
        assert!(limits.try_acquire(peer, u64::MAX, 4, 1, &budget, later).is_ok());
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
            meta_cursor: None,
            revision: 0,
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
            meta_cursor: None,
            revision: 0,
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
