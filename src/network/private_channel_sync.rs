//! Private-channel-sync — bounded, authenticated backfill of a private
//! channel's missed history (l2-node 0.138.0+).
//!
//! Private channels (`channel_type == 2`) federate forward-only:
//! `federate_channel` (`api/routes.rs`) fetches metadata and subscribes to
//! the channel's gossip topic, but fetches zero history. `network::reconcile`
//! (the general channel-history backfill protocol) refuses every
//! private-channel request outright — its wire format carries no signed
//! requester/membership proof, so there is no way to verify the requester is
//! actually a member (see `reconcile::build_response`'s refusal branch). A
//! node that federates late, or goes offline and comes back, permanently
//! misses whatever history it didn't personally witness live. This module
//! closes that gap.
//!
//! An earlier attempt at exactly this (`sync.rs::SyncRequestType::
//! PrivateChannelMessages`/`PrivateChannelKeys`) was a complete, working
//! responder, abandoned mid-pivot and removed as dead code ("audit W8") —
//! its fatal flaw, per that removal's own comment, was an un-host-bound
//! signed proof: a captured proof could be replayed against a different
//! anchor node. This module avoids that by directly porting the mechanism
//! that already gets this right in production: `network::dm_sync`'s
//! two-layer, host-bound authenticated backfill for DMs. The wire protocol,
//! auth scheme, and DoS limits below mirror `dm_sync.rs` closely — the ONE
//! gate DMs don't need, and this does, is channel membership
//! (`reconcile::is_channel_member`).
//!
//! Unlike `dm_sync` (unauthenticated-content-wise — a DM conversation has
//! exactly two participants and membership is implicit), a private
//! channel's membership can change over time and is the actual
//! confidentiality boundary, so the responder re-checks
//! `reconcile::is_channel_member` on every single request — never cached,
//! never assumed from a prior check.
//!
//! **Scope note: message history only, NOT encryption-key backfill.** An
//! earlier draft of this module planned to also ride missed
//! `ChannelKeyEnvelope` records along on the last page, reasoning that a
//! backfilled message encrypted under a since-rotated epoch is useless
//! ciphertext without the matching key. Verified against the actual
//! storage before implementing: `CHANNEL_KEYS`' stored value
//! (`router.rs`'s `MessageType::ChannelKeyEnvelope` handler) is a DERIVED
//! JSON cache (`eph_pub`/`nonce`/`wrapped`/`epoch` as hex strings) built
//! AFTER the original signed envelope was validated — the original
//! signature and `msg_id` are not preserved in a re-verifiable form
//! (channel-scope records even force `author` to an empty string). There
//! is therefore no way to re-serve a `CHANNEL_KEYS` row to another PEER
//! and have that peer independently re-verify it the way `CHANNEL_MSGS`'
//! original signed envelope bytes can be — a malicious responder could
//! forge or substitute a wrapped-key record with nothing to catch it.
//! Shipping that would trade a disclosed, bounded gap (a member offline
//! for an entire key rotation stays unable to decrypt until the NEXT
//! rotation re-covers them) for an unbounded one (a malicious peer
//! planting forged key material). Deliberately deferred — closing it
//! properly needs the `ChannelKeyEnvelope` ingest path to ALSO retain the
//! original signed envelope bytes (mirroring how `ChatMessage`/
//! `DirectMessage` already call `store_message`), which is a change to a
//! different, already-hardened code path and out of scope for this pass.
//!
//! **Known limitation: a ForwardOnly channel with a large pre-join
//! backlog can exhaust the requester's own unproductive-page backstop
//! before reaching visible history.** `build_response`'s cursor now
//! correctly advances over every row it examines — including ones
//! filtered out by the `history_visibility` floor — so a page of
//! entirely-too-old rows no longer strands the session (code-audit
//! finding, 2026-10-01). But such a page still has zero `Accepted`
//! envelopes, so it counts against the shared
//! `MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES` (5) requester-side backstop —
//! giving an effective skip budget of `5 * MAX_ENVELOPES_PER_RESPONSE`
//! (1,000) rows before the session gives up. A channel whose requesting
//! member joined after more than 1,000 earlier messages will abort
//! before reaching anything it's entitled to see, and — since the cursor
//! lives only in-memory on `PrivateChannelSyncPending`, never persisted —
//! every later retry (sweep or re-federation) restarts from the channel's
//! oldest message and burns the identical budget again, making zero
//! cumulative progress. Same shape as `reconcile::build_response`'s own
//! documented KNOWN LIMITATION (time-window filtering, not join-time
//! filtering), just reached sooner here (`MAX_ENVELOPES_PER_RESPONSE =
//! 200` vs reconcile's configurable, default-1000, cap). Not fixed in
//! this pass — a real fix needs either a persisted per-(wallet, channel)
//! cursor (surviving across retry attempts, not just within one) or not
//! counting a "filtered but cursor-advancing" page as unproductive.
//! Recorded rather than silently shipped past, per this project's audit-
//! triage rules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::warn;

use crate::crypto::signing;
use crate::network::budget::{BudgetMap, Gcra, Refusal};
use crate::network::reconcile::{self, is_channel_member, is_private_channel, MetaCursor};
use crate::storage::rocks::Storage;
use crate::storage::schema;

/// libp2p CBOR request/response codec for private-channel-sync.
pub type PrivateChannelSyncCodec =
    libp2p::request_response::cbor::Behaviour<PrivateChannelSyncRequest, PrivateChannelSyncResponse>;

/// Protocol string. Versioned independently of `dm_sync`/`reconcile`.
pub fn protocol_string(network_id: &str) -> String {
    format!("/ogmara/{}/private-channel-sync/1.0.0", network_id)
}

/// True iff `msg_type` is a type this protocol's response may legitimately
/// carry — the receiver's type-smuggling defense, mirroring
/// `dm_sync::is_dm_type`'s exact rationale ("so a responder can't inject
/// another type through this path", audit W6). Security-audit finding
/// (2026-10-01): the initial version reused `reconcile`'s shared
/// `envelope_targets_channel`, whose catch-all arm is `_ => true` BY
/// DESIGN for `reconcile` (every type it can't specifically bind is
/// already channel-scoped by construction of what's stored in
/// `CHANNEL_MSGS`/`CHANNEL_META_MSGS`/`CHANNEL_EDIT_DELETE_MSGS`, so
/// `reconcile` defers entirely to the router's own re-authorization).
/// That reasoning does not transfer here: a malicious responder's
/// RESPONSE is not actually bound by what is really stored anywhere —
/// without this allowlist, a captured, genuinely-signed envelope of ANY
/// OTHER type (a `DirectMessage`, a `ChannelKeyEnvelope`, a
/// `ProfileUpdate`) could be replayed through `process_synced_message`'s
/// `is_sync = true` path, which deliberately skips the timestamp-
/// freshness/per-wallet-rate-limit/PoW/registration gates that would
/// apply to a live-gossip-sourced copy. Exactly the gap `dm_sync` already
/// closed for its own protocol; this closes the equivalent gap here.
/// Covers every type `CHANNEL_MSGS`/`channel_meta_envelopes`/
/// `channel_edit_delete_envelopes_metered` can legitimately contain.
pub fn is_private_channel_sync_type(msg_type: u8) -> bool {
    use crate::messages::types::MessageType;
    matches!(
        MessageType::from_u8(msg_type),
        Some(
            MessageType::ChatMessage
                | MessageType::ChatEdit
                | MessageType::ChatDelete
                | MessageType::ChatReaction
                | MessageType::ChannelPinMessage
                | MessageType::ChannelUnpinMessage
                | MessageType::ChannelJoin
                | MessageType::ChannelLeave
                | MessageType::ChannelCreate
                | MessageType::ChannelUpdate
                | MessageType::ChannelDelete
                | MessageType::ChannelKick
                | MessageType::ChannelBan
                | MessageType::ChannelUnban
                // Moderator propagation (l2-node 0.140.0, B5): now indexed
                // into CHANNEL_META_MSGS, so a member's home node learns who
                // the moderators are (and accepts their invites/kicks).
                | MessageType::ChannelAddModerator
                | MessageType::ChannelRemoveModerator
        )
    )
}

/// Cheap top-level peek at `env_bytes`' `msg_type`, for the type-smuggling
/// check above — never touches the payload, so this is safe regardless of
/// what the payload contains (encrypted or not), same as every other
/// "top-level `Envelope` decode only" peek in this module family.
pub fn envelope_is_private_channel_sync_type(env_bytes: &[u8]) -> bool {
    match rmp_serde::from_slice::<crate::messages::envelope::Envelope>(env_bytes) {
        Ok(env) => is_private_channel_sync_type(env.msg_type_u8()),
        Err(_) => false,
    }
}

// --- Tuning ---

/// Max envelopes a responder returns per page. Same threat shape as
/// `dm_sync::MAX_ENVELOPES_PER_RESPONSE` — same value.
pub const MAX_ENVELOPES_PER_RESPONSE: usize = 200;
/// Share of a LEGACY first page (requester without metadata paging)
/// reserved for channel metadata, so a full chat page can never crowd the
/// removal/role state out (round-2 audit R2-1). Capped at half the page.
/// Paging requesters (0.140.0+) get ALL metadata rows on dedicated
/// metadata pages instead (round-3 audit R3-1, raw keyset paging since
/// round 4).
pub const META_RESERVE: usize = 64;
// Responder budget (l2-node 0.141.0, replaces the 0.138-0.140 lifetime
// `TOTAL_ENVELOPES_CAP = 20,000`): one rolling-window GCRA bucket per
// requesting PEER (all channels and wallets together), `[private_channel_
// sync] responder_budget_burst` units (default 20,000) refilled at
// `responder_budget_refill_per_hour` (default 5,000/h) — see
// `budget::Gcra`. Charged per request with `reconcile::budget_charge` —
// the larger of envelopes sent and storage rows examined, minimum 1 — so
// metadata rows count like chat rows and empty / garbage-cursor pages are
// not free (round 4). Refusals (auth, membership, concurrency, budget,
// build slot) are never charged. Keys are bounded by
// `MAX_TRACKED_SERVED_PEERS`; only full buckets are pruned and a full map
// refuses NEW peers, so cycling identities no longer buys a refill (the
// old FIFO eviction did).
//
// Before 0.141.0 the budget never refilled until the responder
// restarted, and a requester re-walked every already-in-sync (wallet,
// channel) pair on every 30 s sweep — burning the budget in hours. The
// requester side now also throttles its attempts (`budget::
// AttemptThrottle`): exponential backoff after a dispatch, an hourly
// recheck after a verified in-sync session (`SyncSession::advance`'s
// `in_sync`).
//
// **Recorded limitation (unchanged):** a channel whose single session
// costs more than the burst (≈ 20,000 metadata + chat rows) still cannot
// complete against one responder — every session restarts from the first
// page (no persisted cursor), so it hits the same wall each time; the
// requester then tries its other fanout peers.
//
// (No constant: the burst and refill are config, `PrivateChannelSyncConfig`.)

/// Requester backstop on METADATA pages per session, separate from the
/// chat-phase `MAX_PAGES_PER_SESSION` so a large metadata history cannot
/// eat the chat budget: 500 pages × 200 rows = 100,000 rows (more than one
/// responder's default burst can serve in one go anyway). With a strictly
/// increasing cursor check (`SyncSession::advance`) a hostile responder
/// cannot loop the requester; at most it spends this many pages.
pub const MAX_META_PAGES_PER_SESSION: u32 = 500;
/// Max concurrent inbound requests served to one peer. Same as `dm_sync`.
pub const SERVER_MAX_CONCURRENT_PER_PEER: usize = 2;
/// How many peers an outbound backfill races. Same as `dm_sync::FANOUT`.
pub const FANOUT: usize = 3;
/// Auth freshness window for the per-request/per-page NODE self-signature.
/// Same as `dm_sync::AUTH_MAX_AGE_SECS`.
pub const AUTH_MAX_AGE_SECS: u64 = 120;
/// Freshness window for the WALLET's authorization claim. Same as
/// `dm_sync::WALLET_AUTH_MAX_AGE_SECS` — see that constant's doc for why
/// this is wider (signed once per session, not refreshed per page).
pub const WALLET_AUTH_MAX_AGE_SECS: u64 = 300;

// --- Auth (node-signed, host-bound to the responder AND the channel) ---

/// Build the host-bound, channel-bound auth string a requester signs (and a
/// responder verifies). Mirrors `dm_sync::build_auth_string` exactly, with
/// one addition: `channel_id` is bound into the signed string. `dm_sync`
/// has no per-request variable content selector (a wallet's DM backfill
/// request always means "all of this wallet's DMs"); here `channel_id`
/// selects WHICH channel's history is being asked for, so it must be part
/// of what's signed — otherwise a captured proof for channel A could be
/// replayed verbatim to request channel B's history from the same
/// responder. The responder's PeerId is known to the requester (it's the
/// peer being dialed) and re-derived locally by the responder, so a
/// signature captured for one responder fails verification on any other —
/// this is the exact host-binding property the removed `sync.rs` design
/// was missing.
pub fn build_auth_string(
    network: &str,
    responder_peer_id: &str,
    wallet: &str,
    channel_id: u64,
    timestamp_ms: u64,
) -> String {
    format!("ogmara-private-channel-sync:{network}:{responder_peer_id}:{wallet}:{channel_id}:{timestamp_ms}")
}

/// Build the private-channel-sync WALLET-authorization claim string:
/// proves the wallet at `wallet` authorized `node_id` SPECIFICALLY to
/// backfill its private channels. Mirrors `dm_sync::build_wallet_auth_claim`
/// with a DISTINCT domain-separation prefix, so a dm-sync claim can never
/// verify here and vice versa. Deliberately NOT channel-scoped (one claim
/// per node/session covers every private channel that wallet is a member
/// of on this node) — same ergonomics as `dm_sync`.
pub fn build_wallet_auth_claim(network: &str, node_id: &str, wallet: &str, timestamp_ms: u64) -> String {
    format!("ogmara-private-channel-sync-auth:{network}:{node_id}:{wallet}:{timestamp_ms}")
}

/// Verify a wallet's private-channel-sync authorization claim against a
/// SPECIFIC `node_id`. Pure function, zero local-state dependency — mirrors
/// `dm_sync::verify_wallet_claim` exactly (same structure, different domain
/// separation string via `build_wallet_auth_claim` above).
pub fn verify_wallet_claim(
    claim: &WalletAuthClaim,
    network: &str,
    node_id: &str,
    wallet: &str,
    now_ms: u64,
) -> bool {
    if claim.signature.len() != 64 {
        return false;
    }
    if now_ms.abs_diff(claim.timestamp) > WALLET_AUTH_MAX_AGE_SECS.saturating_mul(1000) {
        return false;
    }
    let Ok(vk) = crate::crypto::address_to_verifying_key(wallet) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&claim.signature) else {
        return false;
    };
    let claim_string = build_wallet_auth_claim(network, node_id, wallet, claim.timestamp);
    signing::verify_klever_message(&vk, claim_string.as_bytes(), &sig).is_ok()
}

// --- Wire types ---

/// A wallet's own Ed25519 signature authorizing a SPECIFIC node (by
/// `node_id`) to backfill its private channels on its behalf. `None` on a
/// request means a pre-fix client, or one that didn't attach one — the
/// responder must reject either way (fail closed). Identical shape to
/// `dm_sync::WalletAuthClaim`; kept as a separate type (not re-exported)
/// so the two protocols' wire formats never implicitly couple.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAuthClaim {
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateChannelSyncRequest {
    /// Target channel. Bound into the signed auth string — see
    /// `build_auth_string`.
    pub channel_id: u64,
    /// Wallet whose channel membership is being asserted.
    pub wallet: String,
    /// Requesting node's Ed25519 public key (32 bytes). MUST equal the
    /// public key of the connected peer.
    pub requester_pubkey: Vec<u8>,
    /// Unix-ms timestamp the request was signed at (freshness).
    pub timestamp: u64,
    /// Ed25519 signature (64 bytes) over `build_auth_string(...)`.
    pub signature: Vec<u8>,
    /// Only serve messages newer than `now - max_age_secs`. `u64::MAX` =
    /// unlimited (bounded by the responder's own retention window
    /// regardless).
    pub max_age_secs: u64,
    /// Opaque paging cursor.
    pub cursor: Option<PrivateChannelSyncCursor>,
    /// Wallet-signed proof that `wallet` authorized THIS node to backfill
    /// on its behalf. `#[serde(default)]` keeps old-shaped CBOR bytes
    /// decodable (decodes to `None`); a request without one just gets
    /// `auth_failed_response()`.
    #[serde(default)]
    pub wallet_claim: Option<WalletAuthClaim>,
    /// Metadata paging (l2-node 0.140.0, round-3 audit R3-1). A requester
    /// that understands it sets `true` and walks ALL of the channel's
    /// metadata rows (raw, every indexed row) page by page (`meta_cursor`) before
    /// any chat; a responder then serves metadata-only pages
    /// (`meta_phase = true`) until `meta_done`. Absent/false (an older
    /// requester) = the legacy first page (reserved metadata share + chat).
    /// Additive, `#[serde(default)]`.
    #[serde(default)]
    pub meta_paging: bool,
    /// Keyset cursor into the metadata in replay order (`None` = start;
    /// see `reconcile::channel_meta_page` for the exact rule).
    #[serde(default)]
    pub meta_cursor: Option<MetaCursor>,
    /// The requester finished the metadata phase; serve chat pages only.
    #[serde(default)]
    pub meta_done: bool,
}

impl PrivateChannelSyncRequest {
    /// A page AFTER the first of its session (round-5 C-W1): a chat cursor,
    /// a metadata cursor, or `meta_done` (the first chat page after this
    /// session's metadata phase). Only a non-continuation request is
    /// refused outright when every responder build slot is busy. The claim
    /// is the requester's own (cursors are not authenticated) — the wait it
    /// earns is bounded separately (`network::MAX_CONTINUATION_BUILD_WAITERS`).
    pub fn is_continuation(&self) -> bool {
        self.cursor.is_some() || self.meta_cursor.is_some() || self.meta_done
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateChannelSyncResponse {
    pub channel_id: u64,
    /// Original signed `ChatMessage` (+ meta/edit/delete ride-along)
    /// envelopes. Receiver re-validates each through the standard router
    /// pipeline — a relaying/responding peer is never trusted. Does NOT
    /// include encryption-key material — see the module doc "Scope note".
    pub envelopes: Vec<Vec<u8>>,
    pub has_more: bool,
    pub next_cursor: Option<PrivateChannelSyncCursor>,
    /// Set when the responder rate-capped the request. The requester ends
    /// the session there — no in-session retry; a later sweep starts the
    /// pair over from the first page.
    pub server_capped: bool,
    /// Set when the request failed authentication (distinct from
    /// rate-capped — the requester should NOT retry without a fresh,
    /// correctly-bound token/claim).
    #[serde(default)]
    pub auth_failed: bool,
    /// This page is a METADATA page (answer to a `meta_paging` request in
    /// the metadata phase). Older responders never set it, which is how a
    /// new requester recognises a legacy page. Additive.
    #[serde(default)]
    pub meta_phase: bool,
    /// More metadata remains after this page.
    #[serde(default)]
    pub meta_has_more: bool,
    /// Cursor for the next metadata page (the last row of this one).
    #[serde(default)]
    pub meta_next_cursor: Option<MetaCursor>,
}

/// Cursor over one channel's `CHANNEL_MSGS` index — same `(lamport_ts,
/// msg_id)` shape as `reconcile::ReconcileCursor`, since both page the
/// same underlying index.
/// Ordered by `(after_lamport_ts, after_msg_id)` — the index key order — so
/// the requester can insist that each cursor strictly advances.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PrivateChannelSyncCursor {
    pub after_lamport_ts: u64,
    pub after_msg_id: [u8; 32],
}

/// A `server_capped` response carrying nothing — sent when rate-limited.
pub fn capped_response(channel_id: u64) -> PrivateChannelSyncResponse {
    PrivateChannelSyncResponse {
        channel_id,
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: true,
        auth_failed: false,
        meta_phase: false,
        meta_has_more: false,
        meta_next_cursor: None,
    }
}

/// An `auth_failed` response carrying nothing — sent when the request's
/// signature / binding / freshness / membership check fails.
pub fn auth_failed_response(channel_id: u64) -> PrivateChannelSyncResponse {
    PrivateChannelSyncResponse {
        channel_id,
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: false,
        auth_failed: true,
        meta_phase: false,
        meta_has_more: false,
        meta_next_cursor: None,
    }
}

/// What a requester does after applying one response (round-3 audit
/// R3-1). Produced by the pure `SyncSession::advance`, so the two-phase
/// loop is unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextStep {
    /// Ask for the next metadata page from this cursor.
    MetaPage(MetaCursor),
    /// Metadata exhausted: ask for the first chat page (`meta_done`).
    StartChat,
    /// Ask for the next chat page from this cursor.
    ChatPage(PrivateChannelSyncCursor),
    /// Session over. `complete` = persist the completion marker.
    /// `in_sync` (l2-node 0.141.0, never together with `complete`) = the
    /// session ended naturally with nothing new and every envelope it saw a
    /// byte-verified duplicate — a requester THROTTLE state only (recheck
    /// after `[private_channel_sync] in_sync_recheck_minutes`); it is never
    /// persisted and never written to the completion CF.
    Finish { complete: bool, in_sync: bool },
}

/// Requester-side state of ONE private-channel-sync session with one peer
/// (round 4). Lives in `NetworkService`'s pending-request map and is
/// advanced once per applied response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncSession {
    /// The chat phase has started (a chat/legacy page was received or
    /// `StartChat` was issued). A metadata page after this point is a
    /// protocol violation.
    pub in_chat: bool,
    /// Metadata pages received (`MAX_META_PAGES_PER_SESSION`).
    pub meta_pages: u32,
    /// Chat (or legacy) pages received (`MAX_PAGES_PER_SESSION`).
    pub chat_pages: u32,
    /// Consecutive chat pages that admitted nothing.
    pub consecutive_unproductive_pages: u32,
    /// Session-cumulative count of genuinely NEW (`Accepted`, never
    /// `Duplicate`) envelopes over BOTH phases.
    pub accepted_total: usize,
    /// Last metadata cursor followed — the next must be strictly greater.
    pub last_meta_cursor: Option<MetaCursor>,
    /// Last chat cursor followed — the next must be strictly greater.
    pub last_chat_cursor: Option<PrivateChannelSyncCursor>,
    /// Session-cumulative count of `Duplicate` envelopes whose received
    /// bytes are byte-identical to the locally stored (ingest-verified)
    /// copy (`network::duplicate_is_verified`, l2-node 0.141.0).
    pub verified_dups: usize,
    /// Set once any page of this session carried something that is not
    /// clean evidence: an envelope dropped by the type/channel checks, one
    /// rejected/invalid/PoW-gated by the router, an oversized page, or a
    /// `Duplicate` whose bytes do NOT match the stored copy (a forged
    /// envelope reusing a known msg_id). A tainted session can still be
    /// COMPLETE (that only needs `Accepted`) but never `in_sync`.
    pub tainted: bool,
}

impl SyncSession {
    /// Advance after applying `resp`, which admitted `admitted` envelopes
    /// (`Accepted` or `Duplicate`) of which `accepted` were `Accepted`.
    ///
    /// * **Metadata page** (`meta_phase`): never ends the session as
    ///   complete. Continues with the next metadata page while
    ///   `meta_has_more` and the cursor STRICTLY advances, then
    ///   `StartChat`. Metadata pages never count as "unproductive" (a
    ///   re-sync legitimately re-serves rows the requester already has, as
    ///   `Duplicate`); they are bounded instead by the strictly-increasing
    ///   cursor and `MAX_META_PAGES_PER_SESSION`. A metadata page after the
    ///   chat phase started, a non-advancing cursor, or `meta_has_more`
    ///   without a cursor ends the session INCOMPLETE — a hostile responder
    ///   can neither loop the requester nor skip from chat back to
    ///   metadata.
    /// * **Chat page** (or a legacy page from an older responder, which
    ///   never sets `meta_phase`): continues while `has_more` and the
    ///   cursor strictly advances; otherwise finishes, `complete` iff the
    ///   whole session admitted at least one `Accepted` envelope. The
    ///   page / unproductive-page backstops finish incomplete — but only
    ///   when another page would be needed: a final page (metadata or chat)
    ///   that lands exactly on a backstop still moves on / finishes
    ///   normally (round-5 C-N7).
    /// * **In sync** (l2-node 0.141.0): a natural end that is not complete
    ///   is reported `in_sync` iff `is_in_sync_end` holds — a throttle
    ///   hint for the requester, never a completion.
    ///
    /// Call `record_evidence` for the page BEFORE `advance`.
    pub fn advance(
        &mut self,
        resp: &PrivateChannelSyncResponse,
        admitted: usize,
        accepted: usize,
    ) -> NextStep {
        const INCOMPLETE: NextStep = NextStep::Finish { complete: false, in_sync: false };
        self.accepted_total += accepted;
        if resp.meta_phase {
            if self.in_chat {
                return INCOMPLETE;
            }
            self.meta_pages += 1;
            // The FINAL metadata page moves on to chat even when it is the
            // `MAX_META_PAGES_PER_SESSION`-th (round-5 C-N7: the backstop
            // used to be checked first, so a channel whose metadata ended
            // exactly on the last allowed page never reached its chat). The
            // backstop only stops a session that would need ANOTHER page.
            if !resp.meta_has_more {
                self.in_chat = true;
                return NextStep::StartChat;
            }
            if self.meta_pages >= MAX_META_PAGES_PER_SESSION {
                return INCOMPLETE;
            }
            return match &resp.meta_next_cursor {
                Some(c) if self.last_meta_cursor.as_ref().is_none_or(|l| c > l) => {
                    self.last_meta_cursor = Some(c.clone());
                    NextStep::MetaPage(c.clone())
                }
                _ => INCOMPLETE,
            };
        }
        self.in_chat = true;
        self.chat_pages += 1;
        self.consecutive_unproductive_pages = if admitted > 0 {
            0
        } else {
            self.consecutive_unproductive_pages + 1
        };
        // A FINAL chat page finishes normally even when it is the page that
        // reaches a backstop (round-5 C-N7); the backstops only refuse to
        // ask for ANOTHER page.
        let Some(c) = resp.next_cursor.as_ref().filter(|_| resp.has_more) else {
            let complete = self.accepted_total > 0;
            return NextStep::Finish { complete, in_sync: !complete && self.is_in_sync_end(resp) };
        };
        if self.chat_pages >= super::MAX_PAGES_PER_SESSION
            || self.consecutive_unproductive_pages >= super::MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES
        {
            return INCOMPLETE;
        }
        if self.last_chat_cursor.as_ref().is_some_and(|l| c <= l) {
            return INCOMPLETE;
        }
        self.last_chat_cursor = Some(c.clone());
        NextStep::ChatPage(c.clone())
    }

    /// Record one applied page's evidence for the in-sync decision:
    /// `verified_dups` byte-verified duplicates, `tainted` if the page had
    /// anything that is not clean evidence (see the field docs).
    pub fn record_evidence(&mut self, verified_dups: usize, tainted: bool) {
        self.verified_dups += verified_dups;
        self.tainted |= tainted;
    }

    /// The in-sync conditions, checked at a natural end of the chat phase
    /// (`resp` is the final chat page): the chat phase really ended
    /// (`has_more == false` — a `has_more` page without a cursor does not
    /// count); the responder walked metadata with us (`meta_pages >= 1`, so
    /// a legacy pre-0.140 responder never qualifies); nothing new was
    /// admitted; at least one byte-verified duplicate was seen; and the
    /// session is not tainted. Backstop / cursor-violation endings never
    /// reach this (they return `INCOMPLETE`).
    fn is_in_sync_end(&self, resp: &PrivateChannelSyncResponse) -> bool {
        !resp.has_more
            && self.meta_pages >= 1
            && self.accepted_total == 0
            && self.verified_dups >= 1
            && !self.tainted
    }
}

/// `true` for an empty, finished response that is the FIRST of its
/// session (`session` still at its default): the responder knows nothing
/// about the pair, so the requester ends the session without completion or
/// evidence (l2-node 0.141.0). Any later empty final page — after a
/// productive or an all-duplicate metadata phase — must instead reach
/// `SyncSession::advance`, which records COMPLETE or IN_SYNC. (Before
/// 0.141.0 the condition was `accepted_total == 0`, which also cut off the
/// empty final chat page of an all-duplicate session.)
pub fn is_empty_first_response(resp: &PrivateChannelSyncResponse, session: &SyncSession) -> bool {
    resp.envelopes.is_empty() && !resp.has_more && *session == SyncSession::default()
}

/// Sign a private-channel-sync request as the requesting node.
/// `responder_peer_id` is the `to_string()` of the peer being dialed
/// (host-binding target).
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    signing_key: &ed25519_dalek::SigningKey,
    network: &str,
    responder_peer_id: &str,
    wallet: &str,
    channel_id: u64,
    timestamp_ms: u64,
    max_age_secs: u64,
    cursor: Option<PrivateChannelSyncCursor>,
    wallet_claim: Option<WalletAuthClaim>,
) -> PrivateChannelSyncRequest {
    let auth_string = build_auth_string(network, responder_peer_id, wallet, channel_id, timestamp_ms);
    let sig = signing::sign_klever_message(signing_key, auth_string.as_bytes());
    PrivateChannelSyncRequest {
        channel_id,
        wallet: wallet.to_string(),
        requester_pubkey: signing_key.verifying_key().to_bytes().to_vec(),
        timestamp: timestamp_ms,
        signature: sig.to_bytes().to_vec(),
        max_age_secs,
        cursor,
        wallet_claim,
        meta_paging: false,
        meta_cursor: None,
        meta_done: false,
    }
}

/// Gate 5 — the channel must genuinely be private, and the wallet must be
/// a CURRENT member — re-checked fresh on every request, never cached.
/// The production handler (`NetworkService::
/// handle_private_channel_sync_event`) runs the gates in this order:
/// `verify_request_crypto_auth` (gates 1-4, pure crypto, no storage) →
/// per-peer `try_acquire` (DoS gate) → this storage-touching check (code-
/// audit finding 2026-10-01: a never-a-member peer must not force storage
/// I/O ahead of the per-peer rate limit). This is the SINGLE copy of the
/// membership gate. (The old combined `verify_request_auth` wrapper had no
/// production caller and was removed in round 4 — dead auth code is a
/// hazard; the tests compose the two gates themselves.)
pub fn verify_request_membership(storage: &Storage, channel_id: u64, wallet: &str) -> bool {
    is_private_channel(storage, channel_id) && is_channel_member(storage, channel_id, wallet)
}

/// Checks 1-4 of `verify_request_auth` ONLY — pure crypto, no storage
/// access. Security-audit finding (2026-10-01): the combined
/// `verify_request_auth` touched RocksDB (gate 5, membership) before the
/// responder's per-peer concurrency limit (`try_acquire`) was checked, so
/// a peer that never passes gate 5 at all (holds no valid membership for
/// any channel it asks about) could still force two point-lookups'
/// worth of storage I/O per request with no per-peer cap on request
/// rate. Split so the handler can run: cheap crypto (this function) →
/// `try_acquire` (DoS gate) → the storage-touching membership check —
/// gate 5 only runs for requests that already cleared both.
pub fn verify_request_crypto_auth(
    request: &PrivateChannelSyncRequest,
    responder_peer_id: &str,
    network: &str,
    now_ms: u64,
    peer: &libp2p::PeerId,
) -> bool {
    if request.requester_pubkey.len() != 32 || request.signature.len() != 64 {
        return false;
    }
    // 1. Bind the claimed node key to the transport-authenticated PeerId.
    let ed_pub =
        match libp2p::identity::ed25519::PublicKey::try_from_bytes(&request.requester_pubkey) {
            Ok(p) => p,
            Err(_) => return false,
        };
    let claimed_peer = libp2p::identity::PublicKey::from(ed_pub).to_peer_id();
    if &claimed_peer != peer {
        return false;
    }
    // 2. Freshness (tolerate small clock skew in either direction).
    if now_ms.abs_diff(request.timestamp) > AUTH_MAX_AGE_SECS.saturating_mul(1000) {
        return false;
    }
    // 3. Signature over the host-bound + channel-bound string.
    let pk_bytes: [u8; 32] = match request.requester_pubkey.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match ed25519_dalek::Signature::from_slice(&request.signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let auth_string = build_auth_string(
        network,
        responder_peer_id,
        &request.wallet,
        request.channel_id,
        request.timestamp,
    );
    if signing::verify_klever_message(&vk, auth_string.as_bytes(), &sig).is_err() {
        return false;
    }
    // 4. The wallet whose membership is claimed must have authorized THIS
    //    node specifically.
    let node_id = crate::crypto::compute_node_id(&vk);
    let claim_ok = match &request.wallet_claim {
        Some(claim) => verify_wallet_claim(claim, network, &node_id, &request.wallet, now_ms),
        None => false,
    };
    if !claim_ok {
        return false;
    }
    true
}

/// Build a response for an inbound request by scanning the local
/// `CHANNEL_MSGS` index forward from the cursor — same index, same key
/// layout, same paging shape as `reconcile::build_response`'s PUBLIC-channel
/// scan (private channels are already correctly indexed there; nothing
/// about `update_indexes` conditions on `channel_type`). The caller (the
/// swarm event handler) is responsible for calling `verify_request_auth`
/// BEFORE this — this function does no authorization itself, it assumes
/// the caller has already established the requester is a genuine member.
///
/// `history_visibility` enforcement (new relative to `reconcile`'s public
/// scan): when the channel's resolved `history_visibility == 0`
/// (ForwardOnly — the private-channel default), any message whose
/// timestamp predates the requester's own `CHANNEL_MEMBERS.joined_at` is
/// skipped. This is the FIRST code path capable of violating a creator's
/// ForwardOnly choice at all (live gossip has no history concept;
/// `reconcile` refuses private channels outright) — so this check is not
/// optional hardening, it is what keeps this new feature from being a
/// regression of an existing, explicit privacy setting. Fails closed: a
/// missing/malformed `history_visibility` or `joined_at` is treated as
/// ForwardOnly-since-right-now (serves nothing old) rather than
/// FullHistory.
///
/// (Test convenience wrapper — production calls the `_metered` variant,
/// which also returns the work done.)
#[cfg(test)]
pub fn build_response(
    storage: &Storage,
    request: &PrivateChannelSyncRequest,
    max_envelopes: usize,
    now_unix: u64,
    window_max_age_secs: u64,
) -> PrivateChannelSyncResponse {
    build_response_metered(storage, request, max_envelopes, now_unix, window_max_age_secs).0
}

/// `build_response` plus the storage work it did (index rows examined,
/// `MESSAGES` reads, ride-along work), which the responder charges to the
/// requesting peer's budget via `reconcile::budget_charge` (round 4: scan
/// work is charged, not only envelopes sent). Runs off the swarm event
/// loop (`tokio::task::spawn_blocking`, `NetworkService::
/// handle_private_channel_sync_event`).
pub fn build_response_metered(
    storage: &Storage,
    request: &PrivateChannelSyncRequest,
    max_envelopes: usize,
    now_unix: u64,
    window_max_age_secs: u64,
) -> (PrivateChannelSyncResponse, u64) {
    // Two point reads for the history floor below.
    let mut work: u64 = 2;
    let empty = PrivateChannelSyncResponse {
        channel_id: request.channel_id,
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: false,
        auth_failed: false,
        meta_phase: false,
        meta_has_more: false,
        meta_next_cursor: None,
    };

    let cap = max_envelopes.min(reconcile::MAX_ENVELOPES_PER_RESPONSE_CEILING);

    let effective_age = request.max_age_secs.min(window_max_age_secs);
    let min_timestamp = if effective_age == u64::MAX {
        0
    } else {
        now_unix.saturating_sub(effective_age)
    };

    // Fail-closed history-visibility floor: a message must be at or after
    // BOTH the time-window cutoff above AND (when ForwardOnly) the
    // requester's own join time. `CHANNEL_MEMBERS.joined_at` is stored in
    // unix MILLISECONDS (`routes::federate_channel` writes `now_ms`);
    // `reconcile::member_joined_at` converts to unix SECONDS, matching
    // `min_timestamp`/`now_unix`'s unit here.
    let history_floor = match reconcile::channel_history_visibility(storage, request.channel_id) {
        Some(1) => 0, // FullHistory — no join-time floor.
        _ => reconcile::member_joined_at(storage, request.channel_id, &request.wallet)
            .unwrap_or(now_unix), // Unknown/missing → serve nothing old.
    };
    let min_timestamp = min_timestamp.max(history_floor);

    // --- Metadata phase (paging requesters, round-3 audit R3-1) ---
    // ALL of the channel's metadata rows — raw, every indexed row (round 4:
    // a re-granted moderator's actions must survive, B1) — are served
    // on their own pages in replay order `(tier, ts, msg_id)` with a keyset
    // cursor, BEFORE any chat, so nothing is starved by a fixed per-page
    // share. Each page is O(page + types) seeks (`reconcile::
    // channel_meta_page`). `has_more` stays true (the chat phase is still
    // to come); the requester switches to chat with `meta_done` once
    // `meta_has_more` is false.
    if request.meta_paging && !request.meta_done {
        let page = reconcile::channel_meta_page(storage, request.channel_id, request.meta_cursor.as_ref(), cap);
        return (
            PrivateChannelSyncResponse {
                channel_id: request.channel_id,
                envelopes: page.envelopes,
                has_more: true,
                next_cursor: None,
                server_capped: false,
                auth_failed: false,
                meta_phase: true,
                meta_has_more: page.has_more,
                meta_next_cursor: page.next_cursor,
            },
            page.work,
        );
    }

    // --- Legacy first page (requester without metadata paging) ---
    // Metadata from a RESERVED share of the page (round-2 audit R2-1): up
    // to `META_RESERVE` (never more than half the page, so chat keeps >= 1
    // slot and `has_more`/`next_cursor` stay meaningful), and after the
    // chat scan it may also take whatever room the chat left (R3-1 (3)).
    // Selected by priority with the budget passed IN (never `.take()` a
    // replay-sorted list; `reconcile::channel_meta_envelopes`). Later legacy
    // pages and every page of a paging requester's chat phase carry no
    // metadata. The reservation only needs to know whether the channel has
    // at least that many metadata rows: a bounded key count, no scan.
    let legacy_first_page = !request.meta_paging && request.cursor.is_none();
    let reserved = if legacy_first_page {
        let want = META_RESERVE.min(cap / 2);
        work += 1 + want as u64;
        storage
            .count_prefix_cf(schema::cf::CHANNEL_META_MSGS, &request.channel_id.to_be_bytes(), want)
            .map(|n| n as usize)
            .unwrap_or(0)
            .min(want)
    } else {
        0
    };
    let chat_cap = cap - reserved;

    let prefix = request.channel_id.to_be_bytes();
    let probe_limit = chat_cap.saturating_add(1);

    let rows = if let Some(c) = request.cursor.as_ref() {
        let start_key =
            schema::encode_channel_msg_key(request.channel_id, c.after_lamport_ts, &c.after_msg_id);
        storage.prefix_iter_cf_after(schema::cf::CHANNEL_MSGS, &start_key, &prefix, probe_limit)
    } else {
        storage.prefix_iter_cf(schema::cf::CHANNEL_MSGS, &prefix, probe_limit)
    };
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            warn!(channel_id = request.channel_id, error = %e, "private-channel-sync: CHANNEL_MSGS iteration failed");
            return (empty, work + 1);
        }
    };
    // One unit per index row examined (its MESSAGES read included) —
    // filtered-out rows too, so a page of too-old rows is not free.
    work += 1 + rows.len() as u64;

    // Chat messages are collected into their own vec first — NEVER
    // shortchanged by ride-along content — and ride-alongs are appended
    // afterward, each truncated to whatever room remains under `cap`.
    // Code-audit finding (2026-10-01): the previous version appended
    // `channel_meta_envelopes` (up to 256) and `channel_edit_delete_
    // envelopes` (up to 2000) ON TOP of a full `cap` (200) of chat
    // envelopes, so any private channel with >=2 members (meta always
    // has at least the creator's `ChannelCreate`) and enough in-window
    // messages produced a page with MORE than `MAX_ENVELOPES_PER_
    // RESPONSE` total envelopes. The requester's own oversized-page
    // guard (`mod.rs`) then discarded the ENTIRE page — chat content
    // included — rather than just the overflow. For a single-page
    // channel this silently discarded the whole backfill, forever (the
    // cursor had already advanced, and completion can never be marked
    // without at least one `Accepted` envelope). Confirmed empirically
    // during audit: cap=3, 3 chat + 5 delete-markers => 8 envelopes.
    let mut chat_envelopes: Vec<Vec<u8>> = Vec::with_capacity(chat_cap);

    let mut last_cursor: Option<PrivateChannelSyncCursor> = None;
    // `rows` was fetched with `probe_limit = cap + 1` (see above) — the
    // same "fetch one extra, measure the raw count" trick `dm_sync` and
    // `reconcile` use to detect "more beyond this page" without needing
    // to actually process the extra row. Capture the raw count BEFORE
    // consuming `rows` into the loop below.
    let probed_count = rows.len();

    for (key, _val) in rows.into_iter().take(chat_cap) {
        if key.len() != 48 {
            continue;
        }
        let lamport_ts = u64::from_be_bytes(key[8..16].try_into().unwrap_or([0; 8]));
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&key[16..48]);

        // Security-audit finding (2026-10-01): advance the cursor over
        // EVERY row examined in this page — even one filtered out below
        // by the time/history-visibility window, or whose MESSAGES entry
        // is missing — mirroring `dm_sync::build_response`'s documented
        // "so a sparse page can't strand rows". Without this, a
        // ForwardOnly channel whose first `cap` CHANNEL_MSGS rows (by
        // lamport order, NOT wall-clock order — `CHANNEL_MSGS`' key
        // layout means these need not correlate) are all older than the
        // requester's own join time left `last_cursor` at `None` AND
        // `hit_cap`/`has_more` at `false`, so the response came back
        // `envelopes: [], has_more: false` — read by the requester as
        // "nothing to backfill, done", even though further, genuinely
        // in-window history could lie beyond this page. That is exactly
        // the channel this feature exists to backfill.
        last_cursor = Some(PrivateChannelSyncCursor {
            after_lamport_ts: lamport_ts,
            after_msg_id: msg_id,
        });

        let raw = match storage.get_message(&msg_id) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(_) => continue,
        };
        // Top-level `Envelope` decode only (never the inner `payload`
        // blob) — `timestamp` is a plain struct field, so this is safe
        // regardless of what the payload contains (encrypted or not).
        // This mirrors `reconcile::build_response`'s own window-check
        // decode exactly; it is NOT the class of bug 0.137.1 fixed (that
        // was about peeking inside the PAYLOAD via JSON/a narrow probe —
        // see `network::envelope_targets_channel`'s doc comment).
        let env: crate::messages::envelope::Envelope = match rmp_serde::from_slice(&raw) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let env_secs = env.timestamp / 1000;
        if env_secs < min_timestamp {
            continue;
        }

        chat_envelopes.push(raw);
    }
    // More beyond this page iff the probe actually returned the extra
    // sentinel row — same "probed_count > cap" shape as
    // `dm_sync::build_response`'s `conv_has_more`.
    let hit_cap = probed_count > chat_cap;

    let meta: Vec<Vec<u8>> = if legacy_first_page {
        let (meta, meta_work) = reconcile::channel_meta_envelopes_metered(
            storage,
            request.channel_id,
            cap.saturating_sub(chat_envelopes.len()),
        );
        work += meta_work;
        meta
    } else {
        Vec::new()
    };
    let mut envelopes: Vec<Vec<u8>> = Vec::with_capacity(cap);
    envelopes.extend(meta);
    envelopes.extend(chat_envelopes);
    if !hit_cap {
        let room = cap.saturating_sub(envelopes.len());
        if room > 0 {
            // Read only the newest `room` markers (same rows the old
            // read-2,000-then-`take(room)` kept), not the full ride-along.
            let (ed, ed_work) = reconcile::channel_edit_delete_envelopes_metered(
                storage,
                request.channel_id,
                min_timestamp,
                room,
            );
            work += ed_work;
            envelopes.extend(ed);
        }
    }

    (
        PrivateChannelSyncResponse {
            channel_id: request.channel_id,
            envelopes,
            has_more: hit_cap,
            next_cursor: if hit_cap { last_cursor } else { None },
            server_capped: false,
            auth_failed: false,
            meta_phase: false,
            meta_has_more: false,
            meta_next_cursor: None,
        },
        work,
    )
}

// --- Responder rate limiting (per peer) ---

/// Bounds how much one peer can pull: per-peer concurrency plus a
/// rolling-window budget per peer (l2-node 0.141.0, `budget::Gcra` — see
/// the "Responder budget" doc above `MAX_META_PAGES_PER_SESSION`). The
/// pre-0.141.0 lifetime counter evicted its oldest entry FIFO past
/// `MAX_TRACKED_SERVED_PEERS`, which handed a Sybil cycling identities its
/// budget back; the budget map instead prunes only refilled buckets and
/// refuses NEW peers when full.
#[derive(Debug)]
pub struct PrivateChannelSyncResponderLimits {
    inner: Mutex<LimitsInner>,
}

impl Default for PrivateChannelSyncResponderLimits {
    fn default() -> Self {
        Self {
            inner: Mutex::new(LimitsInner {
                per_peer: HashMap::new(),
                budget: BudgetMap::new(MAX_TRACKED_SERVED_PEERS),
            }),
        }
    }
}

/// Hard cap on peers tracked by the responder budget.
pub(crate) const MAX_TRACKED_SERVED_PEERS: usize = 100_000;

#[derive(Debug)]
struct LimitsInner {
    per_peer: HashMap<libp2p::PeerId, usize>,
    budget: BudgetMap<libp2p::PeerId>,
}

impl PrivateChannelSyncResponderLimits {
    /// Admit one inbound request, or the reason it is refused (→
    /// `capped_response`). Refusals are never charged.
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: libp2p::PeerId,
        max_concurrent_per_peer: usize,
        budget: &Gcra,
        now: Instant,
    ) -> Result<PrivateChannelSyncResponderGuard, Refusal> {
        // A poisoned lock is treated like a busy slot (fail closed).
        let mut inner = self.inner.lock().map_err(|_| Refusal::Concurrency)?;
        let in_flight = inner.per_peer.get(&peer).copied().unwrap_or(0);
        if in_flight >= max_concurrent_per_peer {
            return Err(Refusal::Concurrency);
        }
        inner.budget.admit(&peer, budget, now)?;
        inner.per_peer.insert(peer, in_flight + 1);
        Ok(PrivateChannelSyncResponderGuard {
            limits: Arc::clone(self),
            peer,
        })
    }

    /// Charge `units` (`reconcile::budget_charge`) to `peer`'s budget after
    /// a build, before the response is queued.
    pub fn charge(&self, peer: libp2p::PeerId, units: u64, budget: &Gcra, now: Instant) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.budget.charge(peer, units, budget, now);
        }
    }

    /// Drop every budget entry whose bucket is full again (never one in
    /// debt). Run on the 30 s tick. Returns how many were removed.
    pub fn prune(&self, now: Instant) -> usize {
        self.inner.lock().map(|mut inner| inner.budget.prune(now)).unwrap_or(0)
    }
}

/// RAII guard releasing a peer's in-flight slot on drop.
pub struct PrivateChannelSyncResponderGuard {
    limits: Arc<PrivateChannelSyncResponderLimits>,
    peer: libp2p::PeerId,
}

impl Drop for PrivateChannelSyncResponderGuard {
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
    use super::*;
    use crate::storage::rocks::Storage;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    /// Gates 1-5 composed exactly as the production handler runs them
    /// (crypto first, then membership). Test-only: the production path
    /// calls the two gates separately around `try_acquire`.
    fn verify_request_auth(
        request: &PrivateChannelSyncRequest,
        responder_peer_id: &str,
        network: &str,
        now_ms: u64,
        peer: &libp2p::PeerId,
        storage: &Storage,
    ) -> bool {
        verify_request_crypto_auth(request, responder_peer_id, network, now_ms, peer)
            && verify_request_membership(storage, request.channel_id, &request.wallet)
    }

    fn keypair() -> (SigningKey, libp2p::PeerId) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let ed_pub =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&sk.verifying_key().to_bytes())
                .unwrap();
        let peer = libp2p::identity::PublicKey::from(ed_pub).to_peer_id();
        (sk, peer)
    }

    fn wallet_keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let address = crate::crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        (sk, address)
    }

    fn valid_claim(
        wallet_sk: &SigningKey,
        node_sk: &SigningKey,
        network: &str,
        wallet: &str,
        timestamp_ms: u64,
    ) -> WalletAuthClaim {
        let node_id = crate::crypto::compute_node_id(&node_sk.verifying_key());
        let claim_string = build_wallet_auth_claim(network, &node_id, wallet, timestamp_ms);
        let sig = signing::sign_klever_message(wallet_sk, claim_string.as_bytes());
        WalletAuthClaim { timestamp: timestamp_ms, signature: sig.to_bytes().to_vec() }
    }

    /// Open a fresh store and register `wallet` as a member of a genuinely
    /// private channel `channel_id` — the storage state `verify_request_auth`'s
    /// 5th gate needs.
    fn storage_with_private_member(channel_id: u64, wallet: &str) -> (TempDir, Storage) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage
            .put_cf(
                schema::cf::CHANNELS,
                &channel_id.to_be_bytes(),
                br#"{"channel_type":2,"history_visibility":0}"#,
            )
            .unwrap();
        storage
            .put_cf(
                schema::cf::CHANNEL_MEMBERS,
                &schema::encode_channel_member_key(channel_id, wallet),
                br#"{"joined_at":0,"role":"member"}"#,
            )
            .unwrap();
        (dir, storage)
    }

    #[test]
    fn auth_roundtrip_accepts_valid_member_request() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let (_dir, storage) = storage_with_private_member(channel_id, &wallet);
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, channel_id, now, 3600, None, Some(claim));
        assert!(verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer, &storage));
    }

    #[test]
    fn auth_rejects_cross_responder_replay() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let (_dir, storage) = storage_with_private_member(channel_id, &wallet);
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", "RESPONDER_A", &wallet, channel_id, now, 3600, None, Some(claim));
        assert!(!verify_request_auth(&req, "RESPONDER_B", "testnet", now, &peer, &storage));
    }

    #[test]
    fn auth_rejects_cross_channel_replay() {
        // A proof signed for channel 42 must not verify for channel 99 —
        // the field `dm_sync` has no equivalent of, added specifically so
        // a captured proof can't be repointed at a different channel.
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let (_dir, storage) = storage_with_private_member(99, &wallet);
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let mut req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, 42, now, 3600, None, Some(claim));
        req.channel_id = 99; // tamper post-sign
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer, &storage));
    }

    #[test]
    fn auth_rejects_tampered_wallet() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let (_dir, storage) = storage_with_private_member(channel_id, &wallet);
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let mut req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, channel_id, now, 3600, None, Some(claim));
        req.wallet = "klv1evil000000000000000000000000000".into();
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer, &storage));
    }

    #[test]
    fn auth_rejects_stale_timestamp() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let signed_at = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let (_dir, storage) = storage_with_private_member(channel_id, &wallet);
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, signed_at);
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, channel_id, signed_at, 3600, None, Some(claim));
        let now = signed_at + (AUTH_MAX_AGE_SECS + 60) * 1000;
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer, &storage));
    }

    #[test]
    fn auth_rejects_pubkey_not_matching_connection_peer() {
        let (sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let (_dir, storage) = storage_with_private_member(channel_id, &wallet);
        let other_peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", &other_peer.to_string(), &wallet, channel_id, now, 3600, None, Some(claim));
        assert!(!verify_request_auth(&req, &other_peer.to_string(), "testnet", now, &other_peer, &storage));
    }

    #[test]
    fn verify_request_auth_rejects_missing_wallet_claim() {
        let (sk, peer) = keypair();
        let (_wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let (_dir, storage) = storage_with_private_member(channel_id, &wallet);
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, channel_id, now, 3600, None, None);
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer, &storage));
    }

    #[test]
    fn verify_request_auth_rejects_non_member() {
        // Everything about the request is genuinely valid EXCEPT the
        // wallet is not actually a member of the channel — the one gate
        // dm_sync has no equivalent of.
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage
            .put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), br#"{"channel_type":2}"#)
            .unwrap();
        // Deliberately no CHANNEL_MEMBERS row for `wallet`.
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, channel_id, now, 3600, None, Some(claim));
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer, &storage));
    }

    #[test]
    fn verify_request_auth_rejects_non_private_channel() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let channel_id = 42u64;
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage
            .put_cf(schema::cf::CHANNELS, &channel_id.to_be_bytes(), br#"{"channel_type":0}"#)
            .unwrap();
        storage
            .put_cf(
                schema::cf::CHANNEL_MEMBERS,
                &schema::encode_channel_member_key(channel_id, &wallet),
                br#"{"joined_at":0,"role":"member"}"#,
            )
            .unwrap();
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, channel_id, now, 3600, None, Some(claim));
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer, &storage));
    }

    // --- verify_wallet_claim ---

    #[test]
    fn verify_wallet_claim_accepts_valid_claim() {
        let (node_sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let node_id = crate::crypto::compute_node_id(&node_sk.verifying_key());
        let claim = valid_claim(&wallet_sk, &node_sk, "testnet", &wallet, now);
        assert!(verify_wallet_claim(&claim, "testnet", &node_id, &wallet, now));
    }

    #[test]
    fn verify_wallet_claim_rejects_wrong_node_id() {
        let (node_sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let claim = valid_claim(&wallet_sk, &node_sk, "testnet", &wallet, now);
        assert!(!verify_wallet_claim(&claim, "testnet", "not-the-authorized-node", &wallet, now));
    }

    #[test]
    fn verify_wallet_claim_rejects_stale_timestamp() {
        let (node_sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let signed_at = 1_700_000_000_000u64;
        let node_id = crate::crypto::compute_node_id(&node_sk.verifying_key());
        let claim = valid_claim(&wallet_sk, &node_sk, "testnet", &wallet, signed_at);
        let now = signed_at + (WALLET_AUTH_MAX_AGE_SECS + 60) * 1000;
        assert!(!verify_wallet_claim(&claim, "testnet", &node_id, &wallet, now));
    }

    #[test]
    fn verify_wallet_claim_rejects_tampered_wallet() {
        let (node_sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let (_other_sk, other_wallet) = {
            let sk = SigningKey::from_bytes(&[11u8; 32]);
            (sk.clone(), crate::crypto::pubkey_to_address(&sk.verifying_key()).unwrap())
        };
        let now = 1_700_000_000_000u64;
        let node_id = crate::crypto::compute_node_id(&node_sk.verifying_key());
        let claim = valid_claim(&wallet_sk, &node_sk, "testnet", &wallet, now);
        assert!(!verify_wallet_claim(&claim, "testnet", &node_id, &other_wallet, now));
    }

    // --- build_response ---

    fn make_private_channel(storage: &Storage, channel_id: u64, history_visibility: u8) {
        storage
            .put_cf(
                schema::cf::CHANNELS,
                &channel_id.to_be_bytes(),
                format!(r#"{{"channel_type":2,"history_visibility":{history_visibility}}}"#).as_bytes(),
            )
            .unwrap();
    }

    fn put_chat_message(storage: &Storage, channel_id: u64, lamport_ts: u64, ts: u64, msg_id: [u8; 32]) {
        use crate::messages::envelope::Envelope;
        use crate::messages::types::{ChatMessagePayload, ContentRating, MessageType};
        let payload = ChatMessagePayload {
            channel_id,
            content: String::new(),
            content_rating: ContentRating::default(),
            reply_to: None,
            mentions: vec![],
            attachments: vec![],
            enc_content: Some(vec![1, 2, 3]),
            enc_nonce: Some([7u8; 24]),
            key_epoch: Some(1),
            buttons: vec![],
            via_button: false,
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id,
            author: "klv1author".to_string(),
            timestamp: ts,
            lamport_ts,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![0u8; 64],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::CHANNEL_MSGS, &schema::encode_channel_msg_key(channel_id, lamport_ts, &msg_id), &[])
            .unwrap();
        storage.store_message(&msg_id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
    }

    fn base_request(channel_id: u64, wallet: &str, cursor: Option<PrivateChannelSyncCursor>) -> PrivateChannelSyncRequest {
        PrivateChannelSyncRequest {
            channel_id,
            wallet: wallet.into(),
            requester_pubkey: vec![0u8; 32],
            timestamp: 0,
            signature: vec![0u8; 64],
            max_age_secs: u64::MAX,
            cursor,
            wallet_claim: None,
            meta_paging: false,
            meta_cursor: None,
            meta_done: false,
        }
    }

    #[test]
    fn build_response_forward_only_excludes_pre_join_messages() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let channel_id = 1u64;
        make_private_channel(&storage, channel_id, 0); // ForwardOnly
        let base_ts = 1_700_000_000u64; // seconds
        put_chat_message(&storage, channel_id, 1, base_ts * 1000, [1u8; 32]); // before join
        put_chat_message(&storage, channel_id, 2, (base_ts + 100) * 1000, [2u8; 32]); // after join
        let wallet = "klv1wallet";
        storage
            .put_cf(
                schema::cf::CHANNEL_MEMBERS,
                &schema::encode_channel_member_key(channel_id, wallet),
                // CHANNEL_MEMBERS.joined_at is stored in unix MILLISECONDS
                // (routes::federate_channel writes `now_ms`) — mirror that
                // unit here, not seconds.
                format!(r#"{{"joined_at":{},"role":"member"}}"#, (base_ts + 50) * 1000).as_bytes(),
            )
            .unwrap();
        let req = base_request(channel_id, wallet, None);
        let resp = build_response(&storage, &req, 200, base_ts + 1000, u64::MAX);
        assert_eq!(resp.envelopes.len(), 1, "only the post-join message should be served");
        assert_eq!(resp.envelopes[0], rmp_serde::to_vec_named(&{
            let mut raw = storage.get_message(&[2u8; 32]).unwrap().unwrap();
            let env: crate::messages::envelope::Envelope = rmp_serde::from_slice(&raw).unwrap();
            raw.clear();
            env
        }).unwrap());
    }

    #[test]
    fn build_response_full_history_serves_everything() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let channel_id = 2u64;
        make_private_channel(&storage, channel_id, 1); // FullHistory
        let base_ts = 1_700_000_000u64;
        put_chat_message(&storage, channel_id, 1, base_ts * 1000, [1u8; 32]);
        put_chat_message(&storage, channel_id, 2, (base_ts + 100) * 1000, [2u8; 32]);
        let wallet = "klv1wallet";
        storage
            .put_cf(
                schema::cf::CHANNEL_MEMBERS,
                &schema::encode_channel_member_key(channel_id, wallet),
                format!(r#"{{"joined_at":{},"role":"member"}}"#, (base_ts + 50) * 1000).as_bytes(),
            )
            .unwrap();
        let req = base_request(channel_id, wallet, None);
        let resp = build_response(&storage, &req, 200, base_ts + 1000, u64::MAX);
        assert_eq!(resp.envelopes.len(), 2, "FullHistory must serve messages from before the join too");
    }

    /// Code-audit regression (2026-10-01): `build_response` must never
    /// return MORE than `cap` total envelopes, even after ride-alongs
    /// (`channel_meta_envelopes` on the first page, `channel_edit_delete_
    /// envelopes` on the last) are added on top of the chat scan. The
    /// requester (`NetworkService::handle_private_channel_sync_event`)
    /// discards an ENTIRE oversized page rather than just the overflow —
    /// so without this, a private channel with even a couple of chat
    /// messages plus its own `ChannelCreate` (always present) and a
    /// delete marker could have its whole backfill silently and
    /// permanently discarded. Uses a tiny `cap = 3` to make the overflow
    /// trivial to trigger with minimal seed data.
    #[test]
    fn build_response_never_exceeds_cap_even_with_ride_alongs() {
        use crate::messages::envelope::Envelope;
        use crate::messages::types::MessageType;

        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let channel_id = 99u64;
        make_private_channel(&storage, channel_id, 1); // FullHistory — simplest to reason about
        let wallet = "klv1wallet";
        storage
            .put_cf(
                schema::cf::CHANNEL_MEMBERS,
                &schema::encode_channel_member_key(channel_id, wallet),
                br#"{"joined_at":0,"role":"member"}"#,
            )
            .unwrap();
        let base_ts = 1_700_000_000u64;

        // 3 chat messages — exactly `cap`.
        for n in 0u64..3 {
            let mut mid = [0u8; 32];
            mid[0] = n as u8 + 1;
            put_chat_message(&storage, channel_id, n, (base_ts + n) * 1000, mid);
        }
        // 1 meta envelope (rides the first page) — mirrors
        // `reconcile::channel_meta_order_tests::put_meta_envelope`.
        let meta_mid = [10u8; 32];
        let meta_env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChannelCreate,
            msg_id: meta_mid,
            author: "klv1creator".to_string(),
            timestamp: base_ts * 1000,
            lamport_ts: 0,
            payload: Vec::new(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(
                schema::cf::CHANNEL_META_MSGS,
                &schema::encode_channel_meta_key(channel_id, MessageType::ChannelCreate as u8, base_ts * 1000, &meta_mid),
                &[],
            )
            .unwrap();
        storage
            .put_cf(schema::cf::MESSAGES, &meta_mid, &rmp_serde::to_vec_named(&meta_env).unwrap())
            .unwrap();
        // 5 edit/delete markers (would ride the LAST page) — key shape
        // matches `CHANNEL_MSGS`: channel_id:8 ++ timestamp_ms:8 ++ msg_id:32
        // (see `reconcile::channel_edit_delete_envelopes_metered`'s doc comment).
        for n in 0u64..5 {
            let mut mid = [0u8; 32];
            mid[1] = n as u8 + 1;
            let mut key = channel_id.to_be_bytes().to_vec();
            key.extend_from_slice(&((base_ts + n) * 1000).to_be_bytes());
            key.extend_from_slice(&mid);
            storage.put_cf(schema::cf::CHANNEL_EDIT_DELETE_MSGS, &key, &[]).unwrap();
            let env = Envelope {
                version: crate::messages::envelope::PROTOCOL_VERSION,
                msg_type: MessageType::ChatDelete,
                msg_id: mid,
                author: "klv1author".to_string(),
                timestamp: (base_ts + n) * 1000,
                lamport_ts: 0,
                payload: Vec::new(),
                signature: vec![],
                relay_path: vec![],
            };
            storage.put_cf(schema::cf::MESSAGES, &mid, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
        }

        let req = base_request(channel_id, wallet, None);
        let cap = 3usize;
        let resp = build_response(&storage, &req, cap, base_ts + 1000, u64::MAX);
        assert!(
            resp.envelopes.len() <= cap,
            "response carried {} envelopes, exceeding cap={cap} — the requester's own \
             oversized-page guard would discard this ENTIRE page, chat content included",
            resp.envelopes.len(),
        );
    }

    // --- responder budget (l2-node 0.141.0) ---

    /// Replaces the pre-0.141.0 `add_served_evicts_oldest_not_everyone`:
    /// the FIFO eviction is gone. A peer that spent its budget keeps its
    /// debt however many other peers arrive; a full map refuses NEW peers
    /// instead, and only refilled buckets are pruned.
    #[test]
    fn budget_never_evicts_a_peer_in_debt_and_refuses_new_peers_when_full() {
        let limits = Arc::new(PrivateChannelSyncResponderLimits::default());
        let budget = Gcra::new(20_000, 5_000);
        let now = std::time::Instant::now();
        let first_peer = libp2p::PeerId::random();
        // Overspent (two requests admitted together): 30,000 units of debt.
        limits.charge(first_peer, 30_000, &budget, now);
        for _ in 1..MAX_TRACKED_SERVED_PEERS {
            limits.charge(libp2p::PeerId::random(), 1, &budget, now);
        }
        let overflow_peer = libp2p::PeerId::random();
        assert!(matches!(
            limits.try_acquire(overflow_peer, SERVER_MAX_CONCURRENT_PER_PEER, &budget, now),
            Err(Refusal::MapFull)
        ));
        assert!(
            matches!(
                limits.try_acquire(first_peer, SERVER_MAX_CONCURRENT_PER_PEER, &budget, now),
                Err(Refusal::OverBudget)
            ),
            "the spent peer was not evicted and got no free refill"
        );
        // One unit refills in 0.72 s: the prune drops the Sybils only.
        let later = now + std::time::Duration::from_secs(1);
        assert_eq!(limits.prune(later), MAX_TRACKED_SERVED_PEERS - 1);
        assert!(limits.try_acquire(overflow_peer, SERVER_MAX_CONCURRENT_PER_PEER, &budget, later).is_ok());
        assert!(limits.try_acquire(first_peer, SERVER_MAX_CONCURRENT_PER_PEER, &budget, later).is_err());
        // …and the spent peer is admitted again once its budget refilled
        // (10,001 units at 5,000/h ≈ 2 h), not only after a restart.
        let refilled = now + std::time::Duration::from_secs(3 * 3_600);
        assert!(limits.try_acquire(first_peer, SERVER_MAX_CONCURRENT_PER_PEER, &budget, refilled).is_ok());
    }

    #[test]
    fn concurrency_cap_is_checked_and_released() {
        let limits = Arc::new(PrivateChannelSyncResponderLimits::default());
        let budget = Gcra::new(20_000, 5_000);
        let now = std::time::Instant::now();
        let peer = libp2p::PeerId::random();
        let g1 = limits.try_acquire(peer, 2, &budget, now).unwrap();
        let _g2 = limits.try_acquire(peer, 2, &budget, now).unwrap();
        assert!(matches!(limits.try_acquire(peer, 2, &budget, now), Err(Refusal::Concurrency)));
        drop(g1);
        assert!(limits.try_acquire(peer, 2, &budget, now).is_ok());
    }
}

#[cfg(test)]
mod meta_reserve_tests {
    //! Round-2 audit R2-1: the first page reserves room for channel
    //! metadata, selected by priority (cap passed IN), so neither 200
    //! ChannelUpdates nor a full chat page can crowd out kicks/demotions.
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::MessageType;
    use tempfile::TempDir;

    const CID: u64 = (1u64 << 40) + 11;
    const BASE: u64 = 1_700_000_000;

    fn setup() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        s.put_cf(
            schema::cf::CHANNELS,
            &CID.to_be_bytes(),
            br#"{"channel_type":2,"creator":"klv1c","history_visibility":1}"#,
        )
        .unwrap();
        s.put_cf(
            schema::cf::CHANNEL_MEMBERS,
            &schema::encode_channel_member_key(CID, "klv1w"),
            br#"{"joined_at":0,"role":"member"}"#,
        )
        .unwrap();
        (s, dir)
    }

    fn put_meta(s: &Storage, t: MessageType, ts_ms: u64, tag: u8, seq: u16) -> [u8; 32] {
        let mut id = [tag; 32];
        id[30..32].copy_from_slice(&seq.to_be_bytes());
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: t,
            msg_id: id,
            author: "klv1c".into(),
            timestamp: ts_ms,
            lamport_ts: 0,
            payload: vec![],
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(schema::cf::CHANNEL_META_MSGS, &schema::encode_channel_meta_key(CID, t as u8, ts_ms, &id), &[])
            .unwrap();
        s.put_cf(schema::cf::MESSAGES, &id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
        id
    }

    fn put_chat(s: &Storage, n: u64) {
        let mut id = [0xC0u8; 32];
        id[24..32].copy_from_slice(&n.to_be_bytes());
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::ChatMessage,
            msg_id: id,
            author: "klv1a".into(),
            timestamp: (BASE + n) * 1000,
            lamport_ts: 0,
            payload: vec![],
            signature: vec![],
            relay_path: vec![],
        };
        s.put_cf(schema::cf::CHANNEL_MSGS, &schema::encode_channel_msg_key(CID, (BASE + n) * 1000, &id), &[])
            .unwrap();
        s.put_cf(schema::cf::MESSAGES, &id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
    }

    fn req(cursor: Option<PrivateChannelSyncCursor>) -> PrivateChannelSyncRequest {
        PrivateChannelSyncRequest {
            channel_id: CID,
            wallet: "klv1w".into(),
            requester_pubkey: vec![0u8; 32],
            timestamp: 0,
            signature: vec![0u8; 64],
            max_age_secs: u64::MAX,
            cursor,
            wallet_claim: None,
            meta_paging: false,
            meta_cursor: None,
            meta_done: false,
        }
    }

    fn types(resp: &PrivateChannelSyncResponse) -> Vec<MessageType> {
        resp.envelopes
            .iter()
            .map(|raw| rmp_serde::from_slice::<Envelope>(raw).unwrap().msg_type)
            .collect()
    }

    fn has_id(resp: &PrivateChannelSyncResponse, id: &[u8; 32]) -> bool {
        resp.envelopes
            .iter()
            .any(|raw| &rmp_serde::from_slice::<Envelope>(raw).unwrap().msg_id == id)
    }

    #[test]
    fn many_updates_do_not_push_out_a_demotion_or_a_kick() {
        let (s, _d) = setup();
        put_meta(&s, MessageType::ChannelCreate, 1_000, 1, 0);
        for i in 0..200u16 {
            put_meta(&s, MessageType::ChannelUpdate, 10_000 + i as u64, 2, i);
        }
        let demote = put_meta(&s, MessageType::ChannelRemoveModerator, 5_000, 3, 0);
        let kick = put_meta(&s, MessageType::ChannelKick, 6_000, 4, 0);
        let resp = build_response(&s, &req(None), MAX_ENVELOPES_PER_RESPONSE, BASE + 10_000, u64::MAX);
        assert!(resp.envelopes.len() <= MAX_ENVELOPES_PER_RESPONSE);
        assert!(has_id(&resp, &demote), "demotion must be served");
        assert!(has_id(&resp, &kick), "kick must be served");
    }

    #[test]
    fn full_chat_first_page_still_carries_reserved_meta() {
        let (s, _d) = setup();
        put_meta(&s, MessageType::ChannelCreate, 1_000, 1, 0);
        let kick = put_meta(&s, MessageType::ChannelKick, 6_000, 4, 0);
        for n in 0..500u64 {
            put_chat(&s, n);
        }
        let resp = build_response(&s, &req(None), MAX_ENVELOPES_PER_RESPONSE, BASE + 10_000, u64::MAX);
        assert_eq!(resp.envelopes.len(), MAX_ENVELOPES_PER_RESPONSE);
        assert!(has_id(&resp, &kick), "a full chat page must not crowd metadata out");
        assert!(resp.has_more && resp.next_cursor.is_some());
        let t = types(&resp);
        assert_eq!(t.iter().filter(|m| **m == MessageType::ChatMessage).count(), 198);
        // Later pages: chat only, full page budget.
        let resp2 = build_response(&s, &req(resp.next_cursor), MAX_ENVELOPES_PER_RESPONSE, BASE + 10_000, u64::MAX);
        assert!(types(&resp2).iter().all(|m| *m == MessageType::ChatMessage));
        assert_eq!(resp2.envelopes.len(), MAX_ENVELOPES_PER_RESPONSE);
    }

    #[test]
    fn paging_and_completion_signals_unchanged_for_a_normal_channel() {
        // Walk every page: has_more/next_cursor must lead through ALL chat
        // exactly once and end with has_more=false, and every page is
        // within the cap.
        let (s, _d) = setup();
        put_meta(&s, MessageType::ChannelCreate, 1_000, 1, 0);
        for i in 0..100u16 {
            put_meta(&s, MessageType::ChannelJoin, 2_000 + i as u64, 5, i);
        }
        for n in 0..450u64 {
            put_chat(&s, n);
        }
        let mut cursor = None;
        let mut chat_seen = 0usize;
        let mut pages = 0;
        loop {
            let resp = build_response(&s, &req(cursor.clone()), MAX_ENVELOPES_PER_RESPONSE, BASE + 10_000, u64::MAX);
            pages += 1;
            assert!(resp.envelopes.len() <= MAX_ENVELOPES_PER_RESPONSE);
            assert!(!resp.envelopes.is_empty(), "no page may be empty");
            chat_seen += types(&resp).iter().filter(|m| **m == MessageType::ChatMessage).count();
            if !resp.has_more {
                assert!(resp.next_cursor.is_none());
                break;
            }
            cursor = resp.next_cursor.clone();
            assert!(cursor.is_some());
            assert!(pages < 10);
        }
        assert_eq!(chat_seen, 450);
        // Page 1 = 64 meta + 136 chat, page 2 = 200, page 3 = 114.
        assert_eq!(pages, 3);
    }

    #[test]
    fn tiny_cap_keeps_at_least_one_chat_slot() {
        let (s, _d) = setup();
        put_meta(&s, MessageType::ChannelCreate, 1_000, 1, 0);
        put_meta(&s, MessageType::ChannelKick, 2_000, 4, 0);
        for n in 0..5u64 {
            put_chat(&s, n);
        }
        let resp = build_response(&s, &req(None), 3, BASE + 10_000, u64::MAX);
        assert!(resp.envelopes.len() <= 3);
        assert!(types(&resp).contains(&MessageType::ChatMessage));
        assert!(resp.has_more && resp.next_cursor.is_some());
    }
}

#[cfg(test)]
mod meta_paging_tests {
    //! Round 4: ALL metadata rows, raw, served on keyset
    //! pages in replay order before chat. These tests drive
    //! `build_response` on a real responder store and apply every page
    //! through a real requester router, following `SyncSession::advance`
    //! exactly as the network loop does.
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::router::{MessageRouter, RouteResult};
    use crate::messages::types::*;
    use crate::network::reconcile::MetaCursor;
    use crate::storage::identity::IdentityResolver;
    use std::collections::HashSet;
    use tempfile::TempDir;

    const CID: u64 = (1u64 << 40) + 21;
    const T0: u64 = 1_700_000_000_000; // ms

    struct W {
        sk: ed25519_dalek::SigningKey,
        addr: String,
    }
    fn wallet() -> W {
        let sk = crate::crypto::generate_keypair();
        let addr = crate::crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        W { sk, addr }
    }

    fn node_with(activation_ms: u64) -> (MessageRouter, Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let identity = IdentityResolver::new(storage.clone());
        let cfg = crate::config::ChannelVerifyConfig {
            private_join_proof_activation_ms: activation_ms,
            ..Default::default()
        };
        let r = MessageRouter::new(
            storage.clone(),
            identity,
            None,
            "testnet".into(),
            usize::MAX,
            std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        )
        .with_channel_verify_config(cfg);
        (r, storage, dir)
    }
    /// Legacy (pre-activation) joins: the simplest valid history.
    fn node() -> (MessageRouter, Storage, TempDir) {
        node_with(u64::MAX / 2)
    }

    fn register(s: &Storage, addr: &str) {
        s.put_cf(
            schema::cf::USERS,
            addr.as_bytes(),
            serde_json::json!({"address": addr, "registered_at": 1}).to_string().as_bytes(),
        )
        .unwrap();
    }

    fn setup_channel(s: &Storage, creator: &str) {
        s.put_cf(
            schema::cf::CHANNELS,
            &CID.to_be_bytes(),
            serde_json::json!({"channel_id": CID, "channel_type": 2, "creator": creator,
                "history_visibility": 1, "member_count": 0}).to_string().as_bytes(),
        )
        .unwrap();
        s.add_channel_member(CID, creator, 1, "creator").unwrap();
        register(s, creator);
    }

    fn sign(w: &W, t: MessageType, payload: Vec<u8>, ts: u64) -> Vec<u8> {
        let pk: [u8; 32] = w.sk.verifying_key().to_bytes();
        let msg_id = crate::crypto::compute_msg_id("testnet", &pk, &payload, ts);
        let sig = signing::sign_ogmara_message(
            &w.sk, "testnet", crate::messages::envelope::PROTOCOL_VERSION, t as u8, &msg_id, ts, &payload,
        );
        rmp_serde::to_vec_named(&Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: t,
            msg_id,
            author: w.addr.clone(),
            timestamp: ts,
            lamport_ts: 0,
            payload,
            signature: sig.to_bytes().to_vec(),
            relay_path: vec![],
        })
        .unwrap()
    }
    fn join(w: &W, ts: u64) -> Vec<u8> {
        join_with(w, None, ts)
    }
    fn join_with(w: &W, invite: Option<Vec<u8>>, ts: u64) -> Vec<u8> {
        sign(w, MessageType::ChannelJoin, rmp_serde::to_vec_named(&ChannelJoinPayload { channel_id: CID, invite }).unwrap(), ts)
    }
    fn leave(w: &W, ts: u64) -> Vec<u8> {
        sign(w, MessageType::ChannelLeave, rmp_serde::to_vec_named(&ChannelLeavePayload { channel_id: CID }).unwrap(), ts)
    }
    fn kick(c: &W, target: &str, ts: u64) -> Vec<u8> {
        sign(c, MessageType::ChannelKick, rmp_serde::to_vec_named(&ChannelKickPayload { channel_id: CID, target_user: target.into(), reason: None }).unwrap(), ts)
    }
    fn ban(c: &W, target: &str, ts: u64) -> Vec<u8> {
        sign(c, MessageType::ChannelBan, rmp_serde::to_vec_named(&ChannelBanPayload { channel_id: CID, target_user: target.into(), reason: Some("x".into()), duration_secs: 0 }).unwrap(), ts)
    }
    fn unban(c: &W, target: &str, ts: u64) -> Vec<u8> {
        sign(c, MessageType::ChannelUnban, rmp_serde::to_vec_named(&ChannelUnbanPayload { channel_id: CID, target_user: target.into() }).unwrap(), ts)
    }
    fn add_mod(c: &W, target: &str, ts: u64) -> Vec<u8> {
        let permissions = ModeratorPermissions {
            can_mute: true,
            can_kick: true,
            can_ban: true,
            can_pin: true,
            can_edit_info: true,
            can_delete_msgs: true,
        };
        sign(c, MessageType::ChannelAddModerator, rmp_serde::to_vec_named(&ChannelAddModeratorPayload { channel_id: CID, target_user: target.into(), permissions }).unwrap(), ts)
    }
    fn remove_mod(c: &W, target: &str, ts: u64) -> Vec<u8> {
        sign(c, MessageType::ChannelRemoveModerator, rmp_serde::to_vec_named(&ChannelRemoveModeratorPayload { channel_id: CID, target_user: target.into() }).unwrap(), ts)
    }
    fn invite(by: &W, target: &str, ts: u64) -> Vec<u8> {
        let p = ChannelInvitePayload {
            channel_id: CID,
            target_user: target.into(),
            anchor_node: None,
            expires_at: None,
            inviter_grant: None,
        };
        sign(by, MessageType::ChannelInvite, rmp_serde::to_vec_named(&p).unwrap(), ts)
    }
    fn update_name(by: &W, name: &str, ts: u64) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct U<'a> { channel_id: u64, display_name: Option<&'a str> }
        sign(by, MessageType::ChannelUpdate, rmp_serde::to_vec_named(&U { channel_id: CID, display_name: Some(name) }).unwrap(), ts)
    }
    fn chat(w: &W, ts: u64) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct C { channel_id: u64, content: String }
        sign(w, MessageType::ChatMessage, rmp_serde::to_vec_named(&C { channel_id: CID, content: "hi".into() }).unwrap(), ts)
    }

    fn feed(r: &MessageRouter, raw: &[u8]) {
        let res = r.process_synced_message(raw);
        assert!(matches!(res, RouteResult::Accepted { .. }), "responder fixture rejected: {res:?}");
    }

    fn rows(s: &Storage, cf: &str) -> Vec<Vec<u8>> {
        s.prefix_iter_cf(cf, &CID.to_be_bytes(), 1_000_000).unwrap().into_iter().map(|(k, _)| k).collect()
    }
    fn rows_kv(s: &Storage, cf: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
        s.prefix_iter_cf(cf, &CID.to_be_bytes(), 1_000_000).unwrap()
    }
    fn display_name(s: &Storage) -> Option<String> {
        let row = s.get_cf(schema::cf::CHANNELS, &CID.to_be_bytes()).unwrap()?;
        serde_json::from_slice::<serde_json::Value>(&row).ok()?
            .get("display_name")?.as_str().map(String::from)
    }

    /// The requester ends with the SAME members, bans, removal/demotion
    /// watermarks and moderator set as the responder.
    fn assert_converged(rs: &Storage, qs: &Storage) {
        assert_eq!(rows(qs, schema::cf::CHANNEL_MEMBERS), rows(rs, schema::cf::CHANNEL_MEMBERS), "members");
        assert_eq!(rows(qs, schema::cf::CHANNEL_BANS), rows(rs, schema::cf::CHANNEL_BANS), "bans");
        assert_eq!(rows_kv(qs, schema::cf::CHANNEL_ROLE_WATERMARKS), rows_kv(rs, schema::cf::CHANNEL_ROLE_WATERMARKS), "watermarks");
        assert_eq!(rows(qs, schema::cf::CHANNEL_MODERATORS), rows(rs, schema::cf::CHANNEL_MODERATORS), "moderators");
    }

    struct SyncRun {
        pages: usize,
        last: NextStep,
        /// msg_ids served on METADATA pages, in order.
        meta_served: Vec<[u8; 32]>,
    }

    /// Drive the requester loop to the end, exactly like the network loop.
    fn sync(resp_store: &Storage, requester: &MessageRouter, req_store: &Storage, wallet: &str, paging: bool) -> SyncRun {
        sync_with(resp_store, requester, req_store, wallet, paging, |_| {})
    }

    /// `sync`, with `tamper` applied to every response before the
    /// requester sees it (a hostile responder). Records the in-sync
    /// evidence exactly like the network loop (`record_evidence` before
    /// `advance`; a `Duplicate` counts only when byte-verified).
    fn sync_with(
        resp_store: &Storage,
        requester: &MessageRouter,
        req_store: &Storage,
        wallet: &str,
        paging: bool,
        tamper: impl Fn(&mut PrivateChannelSyncResponse),
    ) -> SyncRun {
        let mut req = PrivateChannelSyncRequest {
            channel_id: CID,
            wallet: wallet.into(),
            requester_pubkey: vec![0; 32],
            timestamp: 0,
            signature: vec![0; 64],
            max_age_secs: u64::MAX,
            cursor: None,
            wallet_claim: None,
            meta_paging: paging,
            meta_cursor: None,
            meta_done: false,
        };
        let mut session = SyncSession::default();
        let mut meta_served = Vec::new();
        for page in 1..=2000 {
            let mut resp = build_response(resp_store, &req, MAX_ENVELOPES_PER_RESPONSE, T0 / 1000 + 10_000_000, u64::MAX);
            assert!(resp.envelopes.len() <= MAX_ENVELOPES_PER_RESPONSE);
            tamper(&mut resp);
            let (mut admitted, mut accepted, mut verified_dups, mut tainted) = (0, 0, 0, false);
            for env in &resp.envelopes {
                if resp.meta_phase {
                    if let Ok(e) = rmp_serde::from_slice::<Envelope>(env) {
                        meta_served.push(e.msg_id);
                    }
                }
                match requester.process_synced_message(env) {
                    RouteResult::Accepted { .. } => {
                        admitted += 1;
                        accepted += 1;
                    }
                    RouteResult::Duplicate => {
                        admitted += 1;
                        if crate::network::duplicate_is_verified(req_store, env) {
                            verified_dups += 1;
                        } else {
                            tainted = true;
                        }
                    }
                    _ => tainted = true,
                }
            }
            session.record_evidence(verified_dups, tainted);
            let step = session.advance(&resp, admitted, accepted);
            match step.clone() {
                NextStep::MetaPage(c) => req.meta_cursor = Some(c),
                NextStep::StartChat => {
                    req.meta_done = true;
                    req.meta_cursor = None;
                }
                NextStep::ChatPage(c) => req.cursor = Some(c),
                NextStep::Finish { .. } => return SyncRun { pages: page, last: step, meta_served },
            }
        }
        panic!("sync did not finish");
    }

    /// Every metadata row is served exactly once over the metadata pages.
    fn assert_exactly_once(rs: &Storage, run: &SyncRun) {
        let set: HashSet<[u8; 32]> = run.meta_served.iter().copied().collect();
        assert_eq!(set.len(), run.meta_served.len(), "a metadata row was served twice");
        let all: HashSet<[u8; 32]> = rows(rs, schema::cf::CHANNEL_META_MSGS)
            .iter()
            .map(|k| {
                let mut id = [0u8; 32];
                id.copy_from_slice(&k[17..49]);
                id
            })
            .collect();
        assert_eq!(set, all, "every indexed metadata row must be served");
    }

    // ---------------------------------------------------------------
    // (h) The auditor's earlier probe.
    // ---------------------------------------------------------------
    #[test]
    fn auditor_probe_everything_is_eventually_served() {
        // 1 creator + 100 joins + 20 leaves + 1 ban + 70 kicks + 5 chat.
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        let ws: Vec<W> = (0..100).map(|_| wallet()).collect();
        for (i, w) in ws.iter().enumerate() {
            feed(&resp, &join(w, T0 + i as u64));
        }
        for w in &ws[0..20] {
            feed(&resp, &leave(w, T0 + 1_000));
        }
        feed(&resp, &ban(&c, &ws[20].addr, T0 + 2_000));
        for (i, w) in ws[21..91].iter().enumerate() {
            feed(&resp, &kick(&c, &w.addr, T0 + 3_000 + i as u64));
        }
        for i in 0..5 {
            feed(&resp, &chat(&c, T0 + 5_000 + i));
        }
        let run = sync(&rs, &reqr, &qs, &c.addr, true);
        assert_eq!(run.last, NextStep::Finish { complete: true, in_sync: false });
        assert_eq!(run.pages, 2, "one metadata page (191 rows) + one chat page");
        assert_eq!(run.meta_served.len(), 191);
        assert_exactly_once(&rs, &run);
        assert_converged(&rs, &qs);
        assert_eq!(rows(&qs, schema::cf::CHANNEL_MSGS).len(), 5);
        assert_eq!(rows(&qs, schema::cf::CHANNEL_MEMBERS).len(), 1 + 100 - 20 - 1 - 70);
    }

    // ---------------------------------------------------------------
    // (a) Moderator re-grant history (audit B1).
    // ---------------------------------------------------------------
    fn moderator_history(regrant_after_demotion: bool) {
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        let m = wallet();
        let (x, y) = (wallet(), wallet());
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        register(&rs, &m.addr);
        register(&qs, &m.addr);
        feed(&resp, &add_mod(&c, &m.addr, T0 + 1));
        feed(&resp, &join(&x, T0 + 2));
        feed(&resp, &join(&y, T0 + 2));
        feed(&resp, &ban(&m, &x.addr, T0 + 3));
        feed(&resp, &kick(&m, &y.addr, T0 + 3));
        if regrant_after_demotion {
            feed(&resp, &remove_mod(&c, &m.addr, T0 + 4));
            feed(&resp, &add_mod(&c, &m.addr, T0 + 5));
        } else {
            feed(&resp, &add_mod(&c, &m.addr, T0 + 4));
        }
        assert_eq!(rows(&rs, schema::cf::CHANNEL_BANS).len(), 1);
        let run = sync(&rs, &reqr, &qs, &c.addr, true);
        assert_eq!(run.last, NextStep::Finish { complete: true, in_sync: false });
        assert_exactly_once(&rs, &run);
        assert_converged(&rs, &qs);
        assert_eq!(rows(&qs, schema::cf::CHANNEL_BANS).len(), 1, "the re-granted moderator's ban survives");
        assert_eq!(rows(&qs, schema::cf::CHANNEL_MEMBERS).len(), 1, "X banned + Y kicked: only the creator remains");
        // Two REMOVED watermarks (X, Y) — plus MODERATOR_REMOVED for M in
        // the demotion variant.
        let expected_wm = if regrant_after_demotion { 3 } else { 2 };
        assert_eq!(rows(&qs, schema::cf::CHANNEL_ROLE_WATERMARKS).len(), expected_wm);
    }

    #[test]
    fn moderator_regrant_keeps_the_moderators_earlier_actions() {
        moderator_history(false);
    }

    #[test]
    fn moderator_demoted_then_regranted_keeps_the_earlier_actions() {
        moderator_history(true);
    }

    // ---------------------------------------------------------------
    // (g) A moderator's Unban, Update and moderator-invited Join.
    // ---------------------------------------------------------------
    #[test]
    fn moderator_unban_update_and_invited_join_survive() {
        // Activation 0: every private join needs a real invite, so the
        // moderator-invited join only verifies on the requester if M's
        // grant replayed BEFORE it.
        let (resp, rs, _d1) = node_with(0);
        let (reqr, qs, _d2) = node_with(0);
        let c = wallet();
        let m = wallet();
        let x = wallet();
        let z = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        register(&rs, &m.addr);
        register(&qs, &m.addr);
        feed(&resp, &add_mod(&c, &m.addr, T0 + 1));
        feed(&resp, &ban(&m, &x.addr, T0 + 2));
        feed(&resp, &unban(&m, &x.addr, T0 + 3));
        feed(&resp, &update_name(&m, "renamed by moderator", T0 + 4));
        let inv = invite(&m, &z.addr, T0 + 5);
        feed(&resp, &join_with(&z, Some(inv), T0 + 6));
        assert_eq!(rows(&rs, schema::cf::CHANNEL_MEMBERS).len(), 2);
        let run = sync(&rs, &reqr, &qs, &c.addr, true);
        assert_eq!(run.last, NextStep::Finish { complete: true, in_sync: false });
        assert_exactly_once(&rs, &run);
        assert_converged(&rs, &qs);
        assert!(rows(&qs, schema::cf::CHANNEL_BANS).is_empty(), "the moderator's unban survived");
        assert_eq!(display_name(&qs).as_deref(), Some("renamed by moderator"), "the moderator's update survived");
        assert!(
            qs.exists_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(CID, &z.addr)).unwrap(),
            "the moderator-invited join survived"
        );
    }

    // ---------------------------------------------------------------
    // (c) 5 members + 10,050 junk Leaves from a non-member.
    // ---------------------------------------------------------------
    #[test]
    fn junk_leave_flood_is_not_indexed_and_members_converge() {
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        let members: Vec<W> = (0..5).map(|_| wallet()).collect();
        for (i, w) in members.iter().enumerate() {
            feed(&resp, &join(w, T0 + 10 + i as u64));
        }
        let junk = wallet(); // unregistered, never joined
        for i in 0..10_050u64 {
            feed(&resp, &leave(&junk, T0 + 100 + i));
        }
        assert_eq!(
            rows(&rs, schema::cf::CHANNEL_META_MSGS).len(),
            5,
            "the index holds the 5 joins only — no junk leave was indexed"
        );
        let run = sync(&rs, &reqr, &qs, &c.addr, true);
        assert_eq!(run.last, NextStep::Finish { complete: true, in_sync: false });
        assert_exactly_once(&rs, &run);
        assert_converged(&rs, &qs);
        assert_eq!(rows(&qs, schema::cf::CHANNEL_MEMBERS).len(), 6);
        assert!(run.pages <= 3, "one metadata page, one empty chat page");
    }

    /// Out-of-order delivery on the RESPONDER: a member's leave arrives
    /// before its own join (and a second wallet's rejoin before the kick it
    /// follows). Neither event is lost from the index, the responder's own
    /// state is right, and a requester converges to it.
    #[test]
    fn out_of_order_membership_events_are_not_lost() {
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        let a = wallet();
        let b = wallet();
        // a: join@10, leave@20 — delivered leave first.
        feed(&resp, &leave(&a, T0 + 20));
        feed(&resp, &join(&a, T0 + 10));
        assert!(
            !rs.exists_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(CID, &a.addr)).unwrap(),
            "a leave that overtook its join wins"
        );
        // b: join@10, kick@20, join@30 — delivered join, join, kick.
        feed(&resp, &join(&b, T0 + 10));
        feed(&resp, &join(&b, T0 + 30));
        feed(&resp, &kick(&c, &b.addr, T0 + 20));
        assert_eq!(rows(&rs, schema::cf::CHANNEL_META_MSGS).len(), 2 + 3, "a: join+leave, b: join, kick, rejoin");
        sync(&rs, &reqr, &qs, &c.addr, true);
        // The requester replays in true order: a left; b rejoined after
        // the kick. (The responder applied b's rejoin before the kick it
        // follows — a pre-existing apply-order limitation, recorded — so
        // only a's outcome is compared to the responder.)
        assert!(!qs.exists_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(CID, &a.addr)).unwrap());
        assert!(qs.exists_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(CID, &b.addr)).unwrap());
    }

    // ---------------------------------------------------------------
    // (d) 1000 kicks over many targets + an old ban.
    // ---------------------------------------------------------------
    #[test]
    fn thousand_kicks_over_many_targets_and_an_old_ban_all_arrive() {
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        let banned = wallet();
        feed(&resp, &ban(&c, &banned.addr, T0)); // oldest event of all
        for i in 0..1000u64 {
            feed(&resp, &kick(&c, &format!("klv1target{i:05}"), T0 + 10 + i));
        }
        let run = sync(&rs, &reqr, &qs, &c.addr, true);
        assert_eq!(run.last, NextStep::Finish { complete: true, in_sync: false });
        assert_exactly_once(&rs, &run);
        assert_eq!(rows(&qs, schema::cf::CHANNEL_ROLE_WATERMARKS).len(), 1001);
        assert_eq!(rows(&qs, schema::cf::CHANNEL_BANS).len(), 1, "a ban is never starved by kicks");
        assert_converged(&rs, &qs);
    }

    // ---------------------------------------------------------------
    // (e) Exactly-once across pages, including EQUAL timestamps.
    // ---------------------------------------------------------------
    #[test]
    fn exactly_once_across_pages_with_equal_timestamps() {
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        // 650 rows, all at ONE timestamp, across three types — every page
        // boundary falls inside a run of equal `ts`.
        for i in 0..450u64 {
            feed(&resp, &kick(&c, &format!("klv1same{i:04}"), T0 + 7));
        }
        for i in 0..100u64 {
            feed(&resp, &ban(&c, &format!("klv1bann{i:04}"), T0 + 7));
        }
        for _ in 0..100 {
            feed(&resp, &join(&wallet(), T0 + 7));
        }
        assert_eq!(rows(&rs, schema::cf::CHANNEL_META_MSGS).len(), 650);
        let run = sync(&rs, &reqr, &qs, &c.addr, true);
        assert_eq!(run.meta_served.len(), 650, "650 rows over 4 pages, none twice, none skipped");
        assert_exactly_once(&rs, &run);
        assert_converged(&rs, &qs);
        // Served order is replay order: (tier, ts, msg_id) ascending.
        let ids = run.meta_served.clone();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "equal-ts rows are served in msg_id order");
    }

    // ---------------------------------------------------------------
    // (f) A tampered / garbled cursor is cheap and safe.
    // ---------------------------------------------------------------
    #[test]
    fn tampered_meta_cursor_is_cheap_and_safe() {
        let (resp, rs, _d1) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        for i in 0..500u64 {
            feed(&resp, &kick(&c, &format!("klv1t{i:04}"), T0 + i));
        }
        let req = |cursor: Option<MetaCursor>| PrivateChannelSyncRequest {
            channel_id: CID,
            wallet: c.addr.clone(),
            requester_pubkey: vec![0; 32],
            timestamp: 0,
            signature: vec![0; 64],
            max_age_secs: u64::MAX,
            cursor: None,
            wallet_claim: None,
            meta_paging: true,
            meta_cursor: cursor,
            meta_done: false,
        };
        // Past the end (tier 255): empty, finished, ONE unit of work.
        let (r, work) = build_response_metered(&rs, &req(Some(MetaCursor { tier: 255, ts: u64::MAX, msg_id: [0xFF; 32] })), MAX_ENVELOPES_PER_RESPONSE, T0 / 1000, u64::MAX);
        assert!(r.meta_phase && r.envelopes.is_empty() && !r.meta_has_more && r.meta_next_cursor.is_none());
        assert!(work <= 4, "a past-the-end cursor must cost O(1), got {work}");
        assert!(reconcile::budget_charge(r.envelopes.len(), work) >= 1, "never free");
        // Tier 1 at ts MAX: seeks only (one per type), empty, finished.
        let (r, work) = build_response_metered(&rs, &req(Some(MetaCursor { tier: 1, ts: u64::MAX, msg_id: [0xFF; 32] })), MAX_ENVELOPES_PER_RESPONSE, T0 / 1000, u64::MAX);
        assert!(r.envelopes.is_empty() && !r.meta_has_more);
        assert!(work <= 2 + 2 * 9, "an at-the-end cursor costs a seek per type, got {work}");
        // A garbled msg_id mid-history: a normal page from that position,
        // bounded by the page cap, never a rescan.
        let (r, work) = build_response_metered(&rs, &req(Some(MetaCursor { tier: 1, ts: T0 + 100, msg_id: [0xAB; 32] })), MAX_ENVELOPES_PER_RESPONSE, T0 / 1000, u64::MAX);
        assert_eq!(r.envelopes.len(), MAX_ENVELOPES_PER_RESPONSE);
        assert!(r.meta_has_more);
        assert!(work <= 3 * MAX_ENVELOPES_PER_RESPONSE as u64 + 40, "page work is O(page + types), got {work}");
        let first: Envelope = rmp_serde::from_slice(&r.envelopes[0]).unwrap();
        assert!(first.timestamp > T0 + 100 || (first.timestamp == T0 + 100 && first.msg_id > [0xAB; 32]), "strictly after the cursor");
    }

    #[test]
    fn deep_pages_cost_the_same_as_the_first() {
        let (resp, rs, _d1) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        for i in 0..1_200u64 {
            feed(&resp, &kick(&c, &format!("klv1d{i:05}"), T0 + i));
        }
        let mut cursor = None;
        let mut works = Vec::new();
        loop {
            let page = crate::network::reconcile::channel_meta_page(&rs, CID, cursor.as_ref(), MAX_ENVELOPES_PER_RESPONSE);
            works.push(page.work);
            if !page.has_more {
                break;
            }
            cursor = page.next_cursor;
        }
        assert_eq!(works.len(), 6);
        let (min, max) = (works.iter().min().unwrap(), works.iter().max().unwrap());
        assert!(max - min <= 20, "per-page work must not grow with depth: {works:?}");
    }

    // ---------------------------------------------------------------
    // Requester state machine.
    // ---------------------------------------------------------------
    fn meta_resp(has_more: bool, cursor: Option<MetaCursor>) -> PrivateChannelSyncResponse {
        PrivateChannelSyncResponse {
            channel_id: CID,
            envelopes: vec![],
            has_more: true,
            next_cursor: None,
            server_capped: false,
            auth_failed: false,
            meta_phase: true,
            meta_has_more: has_more,
            meta_next_cursor: cursor,
        }
    }
    fn chat_resp(has_more: bool, cursor: Option<PrivateChannelSyncCursor>) -> PrivateChannelSyncResponse {
        PrivateChannelSyncResponse {
            meta_phase: false,
            meta_has_more: false,
            has_more,
            next_cursor: cursor,
            ..meta_resp(false, None)
        }
    }
    fn mc(ts: u64) -> MetaCursor {
        MetaCursor { tier: 1, ts, msg_id: [1; 32] }
    }
    fn cc(ts: u64) -> PrivateChannelSyncCursor {
        PrivateChannelSyncCursor { after_lamport_ts: ts, after_msg_id: [2; 32] }
    }

    #[test]
    fn completion_only_after_both_phases() {
        let mut s = SyncSession::default();
        // A metadata page never finishes the session, even with Accepted.
        assert_eq!(s.advance(&meta_resp(true, Some(mc(5))), 3, 3), NextStep::MetaPage(mc(5)));
        assert_eq!(s.advance(&meta_resp(false, None), 3, 3), NextStep::StartChat);
        assert_eq!(s.advance(&chat_resp(true, Some(cc(1))), 1, 0), NextStep::ChatPage(cc(1)));
        assert_eq!(s.advance(&chat_resp(false, None), 1, 0), NextStep::Finish { complete: true, in_sync: false });
        // Nothing Accepted in the whole session → not complete.
        let mut s = SyncSession::default();
        s.advance(&meta_resp(false, None), 0, 0);
        assert_eq!(s.advance(&chat_resp(false, None), 0, 0), NextStep::Finish { complete: false, in_sync: false });
        // Duplicates alone never complete.
        let mut s = SyncSession::default();
        s.advance(&meta_resp(false, None), 50, 0);
        assert_eq!(s.advance(&chat_resp(false, None), 9, 0), NextStep::Finish { complete: false, in_sync: false });
    }

    #[test]
    fn hostile_responder_cannot_loop_rewind_or_switch_phase() {
        // Non-advancing metadata cursor → incomplete stop.
        let mut s = SyncSession::default();
        assert_eq!(s.advance(&meta_resp(true, Some(mc(5))), 1, 1), NextStep::MetaPage(mc(5)));
        assert_eq!(s.advance(&meta_resp(true, Some(mc(5))), 1, 1), NextStep::Finish { complete: false, in_sync: false });
        let mut s = SyncSession::default();
        s.advance(&meta_resp(true, Some(mc(5))), 1, 1);
        assert_eq!(s.advance(&meta_resp(true, Some(mc(4))), 1, 1), NextStep::Finish { complete: false, in_sync: false });
        // `meta_has_more` without a cursor → incomplete stop.
        let mut s = SyncSession::default();
        assert_eq!(s.advance(&meta_resp(true, None), 1, 1), NextStep::Finish { complete: false, in_sync: false });
        // A metadata page once chat started → incomplete stop.
        let mut s = SyncSession::default();
        s.advance(&meta_resp(false, None), 1, 1);
        assert_eq!(s.advance(&meta_resp(true, Some(mc(9))), 1, 1), NextStep::Finish { complete: false, in_sync: false });
        // Non-advancing chat cursor → incomplete stop.
        let mut s = SyncSession::default();
        s.advance(&chat_resp(true, Some(cc(3))), 1, 1);
        assert_eq!(s.advance(&chat_resp(true, Some(cc(3))), 1, 1), NextStep::Finish { complete: false, in_sync: false });
        // Metadata page budget.
        let mut s = SyncSession::default();
        let mut last = NextStep::StartChat;
        for i in 1..=MAX_META_PAGES_PER_SESSION as u64 {
            last = s.advance(&meta_resp(true, Some(mc(i))), 1, 1);
            if last == (NextStep::Finish { complete: false, in_sync: false }) {
                break;
            }
        }
        assert_eq!(last, NextStep::Finish { complete: false, in_sync: false });
        assert_eq!(s.meta_pages, MAX_META_PAGES_PER_SESSION);
        // Chat backstop: unproductive pages.
        let mut s = SyncSession::default();
        let mut last = NextStep::StartChat;
        for i in 1..=10 {
            last = s.advance(&chat_resp(true, Some(cc(i))), 0, 0);
            if matches!(last, NextStep::Finish { .. }) {
                break;
            }
        }
        assert_eq!(last, NextStep::Finish { complete: false, in_sync: false });
        assert_eq!(s.chat_pages, crate::network::MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES);
    }

    #[test]
    fn continuation_classification() {
        let sk = crate::crypto::generate_keypair();
        let mut r = sign_request(&sk, "testnet", "peer", "klv1w", CID, 1, u64::MAX, None, None);
        r.meta_paging = true;
        assert!(!r.is_continuation(), "first metadata page starts a session");
        r.meta_paging = false;
        assert!(!r.is_continuation(), "legacy first page starts a session");
        r.meta_cursor = Some(mc(1));
        assert!(r.is_continuation());
        r.meta_cursor = None;
        r.meta_done = true;
        assert!(r.is_continuation(), "first chat page after the metadata phase");
        r.meta_done = false;
        r.cursor = Some(cc(1));
        assert!(r.is_continuation());
    }

    /// Round-5 C-N7: a FINAL page that lands exactly on a backstop moves on
    /// (metadata → chat) or finishes normally instead of ending incomplete.
    #[test]
    fn final_page_on_a_backstop_is_not_cut_off() {
        // Metadata: 499 continuation pages, then the 500th is the last.
        let mut s = SyncSession::default();
        for i in 1..MAX_META_PAGES_PER_SESSION as u64 {
            assert_eq!(s.advance(&meta_resp(true, Some(mc(i))), 1, 1), NextStep::MetaPage(mc(i)));
        }
        assert_eq!(s.advance(&meta_resp(false, None), 1, 1), NextStep::StartChat);
        assert_eq!(s.meta_pages, MAX_META_PAGES_PER_SESSION);
        // ...but a 500th page that still has more is cut off.
        let mut s = SyncSession::default();
        for i in 1..MAX_META_PAGES_PER_SESSION as u64 {
            s.advance(&meta_resp(true, Some(mc(i))), 1, 1);
        }
        assert_eq!(
            s.advance(&meta_resp(true, Some(mc(10_000))), 1, 1),
            NextStep::Finish { complete: false, in_sync: false }
        );
        // Chat: the MAX_PAGES_PER_SESSION-th page is the final one.
        let max = crate::network::MAX_PAGES_PER_SESSION;
        let mut s = SyncSession::default();
        for i in 1..max as u64 {
            assert_eq!(s.advance(&chat_resp(true, Some(cc(i))), 1, 1), NextStep::ChatPage(cc(i)));
        }
        assert_eq!(s.advance(&chat_resp(false, None), 1, 1), NextStep::Finish { complete: true, in_sync: false });
        // ...and one that still has more is cut off.
        let mut s = SyncSession::default();
        for i in 1..max as u64 {
            s.advance(&chat_resp(true, Some(cc(i))), 1, 1);
        }
        assert_eq!(
            s.advance(&chat_resp(true, Some(cc(1_000_000))), 1, 1),
            NextStep::Finish { complete: false, in_sync: false }
        );
        // Unproductive backstop reached on the final page: finishes by the
        // session's own merit (an earlier Accepted → complete).
        let unprod = crate::network::MAX_CONSECUTIVE_UNPRODUCTIVE_PAGES;
        let mut s = SyncSession::default();
        s.advance(&meta_resp(false, None), 1, 1);
        for i in 1..unprod as u64 {
            assert_eq!(s.advance(&chat_resp(true, Some(cc(i))), 0, 0), NextStep::ChatPage(cc(i)));
        }
        assert_eq!(s.advance(&chat_resp(false, None), 0, 0), NextStep::Finish { complete: true, in_sync: false });
    }

    #[test]
    fn all_duplicate_metadata_pages_are_not_unproductive() {
        // A re-sync: the requester already has everything, so every
        // metadata row comes back Duplicate. Hundreds of such pages must
        // walk to the chat phase, never trip the unproductive backstop.
        let mut s = SyncSession::default();
        for i in 1..=50 {
            assert_eq!(s.advance(&meta_resp(true, Some(mc(i))), 0, 0), NextStep::MetaPage(mc(i)));
        }
        assert_eq!(s.advance(&meta_resp(false, None), 0, 0), NextStep::StartChat);
        // And end-to-end: a second sync of an already-synced requester.
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        for i in 0..1_100u64 {
            feed(&resp, &kick(&c, &format!("klv1r{i:05}"), T0 + i));
        }
        assert_eq!(sync(&rs, &reqr, &qs, &c.addr, true).last, NextStep::Finish { complete: true, in_sync: false });
        let again = sync(&rs, &reqr, &qs, &c.addr, true);
        assert_eq!(again.meta_served.len(), 1_100, "all 6 duplicate metadata pages walked");
        assert_eq!(
            again.last,
            NextStep::Finish { complete: false, in_sync: true },
            "nothing new: not re-marked complete, but verified in sync (a throttle state)"
        );
        assert_converged(&rs, &qs);
    }

    // ---------------------------------------------------------------
    // In-sync evidence (l2-node 0.141.0): a throttle state, never COMPLETE.
    // ---------------------------------------------------------------
    const IN_SYNC: NextStep = NextStep::Finish { complete: false, in_sync: true };
    const NOT_IN_SYNC: NextStep = NextStep::Finish { complete: false, in_sync: false };

    /// A clean walk: one metadata page and one final chat page, every
    /// envelope a byte-verified duplicate.
    fn clean_walk(s: &mut SyncSession, final_chat: &PrivateChannelSyncResponse) -> NextStep {
        s.record_evidence(4, false);
        assert_eq!(s.advance(&meta_resp(false, None), 4, 0), NextStep::StartChat);
        s.record_evidence(2, false);
        s.advance(final_chat, 2, 0)
    }

    #[test]
    fn clean_all_duplicate_walk_is_in_sync() {
        let mut s = SyncSession::default();
        assert_eq!(clean_walk(&mut s, &chat_resp(false, None)), IN_SYNC);
        // Also over several chat pages, and with an EMPTY final chat page.
        let mut s = SyncSession::default();
        s.record_evidence(4, false);
        s.advance(&meta_resp(false, None), 4, 0);
        s.record_evidence(3, false);
        assert_eq!(s.advance(&chat_resp(true, Some(cc(1))), 3, 0), NextStep::ChatPage(cc(1)));
        s.record_evidence(0, false);
        assert_eq!(s.advance(&chat_resp(false, None), 0, 0), IN_SYNC);
    }

    #[test]
    fn in_sync_negative_controls() {
        // Forged duplicate (same msg_id, different bytes) on any page.
        let mut s = SyncSession::default();
        s.record_evidence(3, true);
        s.advance(&meta_resp(false, None), 4, 0);
        s.record_evidence(2, false);
        assert_eq!(s.advance(&chat_resp(false, None), 2, 0), NOT_IN_SYNC, "forged duplicate");
        // A dropped / rejected envelope on the final page.
        let mut s = SyncSession::default();
        s.record_evidence(4, false);
        s.advance(&meta_resp(false, None), 4, 0);
        s.record_evidence(1, true);
        assert_eq!(s.advance(&chat_resp(false, None), 1, 0), NOT_IN_SYNC, "dropped/rejected");
        // Backstop end (unproductive chat pages) — never in sync.
        let mut s = SyncSession::default();
        s.record_evidence(4, false);
        s.advance(&meta_resp(false, None), 4, 0);
        let mut last = NextStep::StartChat;
        for i in 1..=10 {
            s.record_evidence(0, false);
            last = s.advance(&chat_resp(true, Some(cc(i))), 0, 0);
            if matches!(last, NextStep::Finish { .. }) {
                break;
            }
        }
        assert_eq!(last, NOT_IN_SYNC, "backstop end");
        // A non-advancing chat cursor — never in sync.
        let mut s = SyncSession::default();
        s.record_evidence(4, false);
        s.advance(&meta_resp(false, None), 4, 0);
        s.advance(&chat_resp(true, Some(cc(3))), 1, 0);
        assert_eq!(s.advance(&chat_resp(true, Some(cc(3))), 1, 0), NOT_IN_SYNC, "cursor violation");
        // `has_more` without a cursor ends the session, but not in sync.
        let mut s = SyncSession::default();
        assert_eq!(clean_walk(&mut s, &chat_resp(true, None)), NOT_IN_SYNC, "has_more without cursor");
        // Empty session: no verified duplicate at all.
        let mut s = SyncSession::default();
        s.advance(&meta_resp(false, None), 0, 0);
        assert_eq!(s.advance(&chat_resp(false, None), 0, 0), NOT_IN_SYNC, "empty session");
        // Legacy responder: no metadata page.
        let mut s = SyncSession::default();
        s.record_evidence(5, false);
        assert_eq!(s.advance(&chat_resp(false, None), 5, 0), NOT_IN_SYNC, "legacy responder");
        // Accepted content wins over taint: COMPLETE, never in sync.
        let mut s = SyncSession::default();
        s.record_evidence(1, true);
        s.advance(&meta_resp(false, None), 2, 1);
        assert_eq!(
            s.advance(&chat_resp(false, None), 0, 0),
            NextStep::Finish { complete: true, in_sync: false },
            "Accepted + taint is still COMPLETE"
        );
    }

    #[test]
    fn only_the_first_empty_response_short_circuits() {
        let empty_final = chat_resp(false, None);
        assert!(is_empty_first_response(&empty_final, &SyncSession::default()));
        // After an all-duplicate metadata page (nothing accepted) the empty
        // final chat page must reach `advance` (→ IN_SYNC), not end early.
        let mut s = SyncSession::default();
        s.record_evidence(3, false);
        s.advance(&meta_resp(false, None), 3, 0);
        assert!(!is_empty_first_response(&empty_final, &s));
        assert_eq!(s.advance(&empty_final, 0, 0), IN_SYNC);
        // A non-empty or has_more first response is never short-circuited.
        assert!(!is_empty_first_response(&chat_resp(true, Some(cc(1))), &SyncSession::default()));
        let mut one = chat_resp(false, None);
        one.envelopes.push(vec![1]);
        assert!(!is_empty_first_response(&one, &SyncSession::default()));
    }

    #[test]
    fn hostile_responder_serving_forged_duplicates_is_neither_complete_nor_in_sync() {
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        for i in 0..20u64 {
            feed(&resp, &kick(&c, &format!("klv1f{i:04}"), T0 + i));
        }
        for i in 0..5 {
            feed(&resp, &chat(&c, T0 + 1_000 + i));
        }
        assert_eq!(sync(&rs, &reqr, &qs, &c.addr, true).last.clone(), NextStep::Finish { complete: true, in_sync: false });
        // Positive control: an honest re-walk is verified in sync.
        assert_eq!(sync(&rs, &reqr, &qs, &c.addr, true).last, IN_SYNC);
        // Hostile: every envelope keeps its msg_id (so the router answers
        // `Duplicate` before any signature check) but its bytes differ.
        let forge = |r: &mut PrivateChannelSyncResponse| {
            for env in r.envelopes.iter_mut() {
                let mut e: Envelope = rmp_serde::from_slice(env).unwrap();
                e.signature = vec![0xAB; 64];
                *env = rmp_serde::to_vec_named(&e).unwrap();
            }
        };
        let run = sync_with(&rs, &reqr, &qs, &c.addr, true, forge);
        assert_eq!(run.last, NOT_IN_SYNC, "forged duplicates prove nothing");
        // A legacy (non-paging) walk of the same in-sync channel: no
        // metadata phase → never in sync.
        assert_eq!(sync(&rs, &reqr, &qs, &c.addr, false).last, NOT_IN_SYNC);
    }

    #[test]
    fn metadata_only_channel_completes_after_empty_chat_phase() {
        let (resp, rs, _d1) = node();
        let (reqr, qs, _d2) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        setup_channel(&qs, &c.addr);
        feed(&resp, &join(&wallet(), T0));
        assert_eq!(sync(&rs, &reqr, &qs, &c.addr, true).last, NextStep::Finish { complete: true, in_sync: false });
    }

    #[test]
    fn old_peer_without_cursor_gets_the_legacy_first_page() {
        let (resp, rs, _d1) = node();
        let c = wallet();
        setup_channel(&rs, &c.addr);
        for i in 0..300u64 {
            feed(&resp, &kick(&c, &format!("klv1t{i:04}"), T0 + i));
        }
        for i in 0..10 {
            feed(&resp, &chat(&c, T0 + 1_000 + i));
        }
        let req = PrivateChannelSyncRequest {
            channel_id: CID,
            wallet: c.addr.clone(),
            requester_pubkey: vec![0; 32],
            timestamp: 0,
            signature: vec![0; 64],
            max_age_secs: u64::MAX,
            cursor: None,
            wallet_claim: None,
            meta_paging: false,
            meta_cursor: None,
            meta_done: false,
        };
        let r = build_response(&rs, &req, MAX_ENVELOPES_PER_RESPONSE, T0 / 1000 + 10_000_000, u64::MAX);
        assert!(!r.meta_phase && r.meta_next_cursor.is_none());
        assert_eq!(r.envelopes.len(), MAX_ENVELOPES_PER_RESPONSE, "meta fills the room chat left");
        // A pre-0.140 request (no new fields at all) decodes to the same thing.
        #[derive(serde::Serialize)]
        struct Old {
            channel_id: u64,
            wallet: String,
            requester_pubkey: Vec<u8>,
            timestamp: u64,
            signature: Vec<u8>,
            max_age_secs: u64,
            cursor: Option<PrivateChannelSyncCursor>,
        }
        let bytes = serde_json::to_vec(&Old {
            channel_id: CID, wallet: "w".into(), requester_pubkey: vec![], timestamp: 0,
            signature: vec![], max_age_secs: 0, cursor: None,
        })
        .unwrap();
        let decoded: PrivateChannelSyncRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(!decoded.meta_paging && !decoded.meta_done && decoded.meta_cursor.is_none());
        // And a new requester reading a legacy response treats it as chat.
        let mut s = SyncSession::default();
        assert_eq!(s.advance(&r, 1, 1), NextStep::Finish { complete: true, in_sync: false });
    }
}
