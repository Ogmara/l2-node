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
use tracing::warn;

use crate::crypto::signing;
use crate::network::reconcile::{
    self, channel_edit_delete_envelopes, channel_meta_envelopes, is_channel_member,
    is_private_channel,
};
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
/// `channel_edit_delete_envelopes` can legitimately contain.
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
/// Hard ceiling on cumulative envelopes one peer may pull for one channel
/// per process lifetime. Higher than `dm_sync::TOTAL_ENVELOPES_CAP` (5,000):
/// one node can host multiple local wallets, each independently catching up
/// on multiple private channels, unlike dm_sync's one-wallet-at-a-time
/// scope. Kept well below `reconcile`'s 200,000 public-channel ceiling
/// since this serves E2E ciphertext + membership metadata, not
/// already-public content.
pub const TOTAL_ENVELOPES_CAP: u64 = 20_000;
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
    /// Set when the responder rate-capped the request (back off + retry
    /// later).
    pub server_capped: bool,
    /// Set when the request failed authentication (distinct from
    /// rate-capped — the requester should NOT retry without a fresh,
    /// correctly-bound token/claim).
    #[serde(default)]
    pub auth_failed: bool,
}

/// Cursor over one channel's `CHANNEL_MSGS` index — same `(lamport_ts,
/// msg_id)` shape as `reconcile::ReconcileCursor`, since both page the
/// same underlying index.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    }
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
    }
}

/// Verify a private-channel-sync request's auth. Returns `true` iff ALL
/// hold:
///  1. `requester_pubkey` is a valid 32-byte Ed25519 key whose derived
///     PeerId equals the connected `peer`;
///  2. the signed `timestamp` is within `AUTH_MAX_AGE_SECS` of `now_ms`;
///  3. the signature verifies over the host-bound, channel-bound auth
///     string built with the RESPONDER's own PeerId;
///  4. `wallet_claim` is present and verifies for the `node_id` derived
///     from the already-verified `requester_pubkey`;
///  5. (the gate `dm_sync` doesn't need) `request.channel_id` is actually
///     a private channel, AND `request.wallet` is a CURRENT member of it —
///     re-checked fresh on every request, never cached. Mirrors the exact
///     existing precedent at `ChannelKeyEnvelope` ingest (`messages::router`):
///     "non-members can neither distribute nor receive a channel key."
pub fn verify_request_auth(
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

/// Gate 5 alone — the channel must genuinely be private, and the wallet
/// must be a CURRENT member — re-checked fresh on every request, never
/// cached. Code-audit finding (2026-10-01): the production handler
/// (`NetworkService::handle_private_channel_sync_event`) runs this AFTER
/// `try_acquire` (so a never-a-member peer can't force storage I/O ahead
/// of the per-peer rate limit — see `verify_request_crypto_auth`'s doc
/// comment), so it can't call the combined `verify_request_auth` above.
/// Extracted here as the SINGLE copy of the membership gate so the
/// production call site and `verify_request_auth` (now test-only, kept
/// for the existing combined-auth test suite) can never drift apart.
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
pub fn build_response(
    storage: &Storage,
    request: &PrivateChannelSyncRequest,
    max_envelopes: usize,
    now_unix: u64,
    window_max_age_secs: u64,
) -> PrivateChannelSyncResponse {
    let empty = PrivateChannelSyncResponse {
        channel_id: request.channel_id,
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: false,
        auth_failed: false,
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

    let prefix = request.channel_id.to_be_bytes();
    let probe_limit = cap.saturating_add(1);

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
            return empty;
        }
    };

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
    let mut chat_envelopes: Vec<Vec<u8>> = Vec::with_capacity(cap);

    let mut last_cursor: Option<PrivateChannelSyncCursor> = None;
    // `rows` was fetched with `probe_limit = cap + 1` (see above) — the
    // same "fetch one extra, measure the raw count" trick `dm_sync` and
    // `reconcile` use to detect "more beyond this page" without needing
    // to actually process the extra row. Capture the raw count BEFORE
    // consuming `rows` into the loop below.
    let probed_count = rows.len();

    for (key, _val) in rows.into_iter().take(cap) {
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
    let hit_cap = probed_count > cap;

    let mut envelopes: Vec<Vec<u8>> = Vec::with_capacity(cap);
    if request.cursor.is_none() {
        let room = cap.saturating_sub(chat_envelopes.len());
        envelopes.extend(
            channel_meta_envelopes(storage, request.channel_id)
                .into_iter()
                .take(room),
        );
    }
    envelopes.extend(chat_envelopes);
    if !hit_cap {
        let room = cap.saturating_sub(envelopes.len());
        if room > 0 {
            envelopes.extend(
                channel_edit_delete_envelopes(storage, request.channel_id, min_timestamp)
                    .into_iter()
                    .take(room),
            );
        }
    }

    PrivateChannelSyncResponse {
        channel_id: request.channel_id,
        envelopes,
        has_more: hit_cap,
        next_cursor: if hit_cap { last_cursor } else { None },
        server_capped: false,
        auth_failed: false,
    }
}

// --- Responder rate limiting (per peer) ---

/// Bounds how much one peer can pull, byte-for-byte mirroring
/// `dm_sync::DmResponderLimits` (including the bounded-eviction fix for the
/// "Sybil clear-all" class of bug: the single oldest `served` entry is
/// evicted on overflow, not the whole map).
#[derive(Debug, Default)]
pub struct PrivateChannelSyncResponderLimits {
    inner: Mutex<LimitsInner>,
}

pub(crate) const MAX_TRACKED_SERVED_PEERS: usize = 100_000;

#[derive(Debug, Default)]
struct LimitsInner {
    per_peer: HashMap<libp2p::PeerId, usize>,
    served: HashMap<libp2p::PeerId, u64>,
    served_order: std::collections::VecDeque<libp2p::PeerId>,
}

impl PrivateChannelSyncResponderLimits {
    /// Admit one inbound request, or `None` if over a cap (→
    /// `capped_response`).
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: libp2p::PeerId,
        max_concurrent_per_peer: usize,
        total_envelopes_cap: u64,
    ) -> Option<PrivateChannelSyncResponderGuard> {
        let mut inner = self.inner.lock().ok()?;
        let in_flight = inner.per_peer.get(&peer).copied().unwrap_or(0);
        if in_flight >= max_concurrent_per_peer {
            return None;
        }
        if inner.served.get(&peer).copied().unwrap_or(0) >= total_envelopes_cap {
            return None;
        }
        inner.per_peer.insert(peer, in_flight + 1);
        Some(PrivateChannelSyncResponderGuard {
            limits: Arc::clone(self),
            peer,
        })
    }

    pub fn add_served(&self, peer: libp2p::PeerId, count: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            let is_new = !inner.served.contains_key(&peer);
            if is_new {
                if inner.served.len() >= MAX_TRACKED_SERVED_PEERS {
                    if let Some(oldest) = inner.served_order.pop_front() {
                        inner.served.remove(&oldest);
                    }
                }
                inner.served_order.push_back(peer);
            }
            *inner.served.entry(peer).or_insert(0) += count;
        }
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
        // (see `reconcile::channel_edit_delete_envelopes`'s doc comment).
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

    // --- responder limits eviction ---

    #[test]
    fn add_served_evicts_oldest_not_everyone() {
        let limits = PrivateChannelSyncResponderLimits::default();
        let first_peer = libp2p::PeerId::random();
        limits.add_served(first_peer, 1);
        for _ in 1..MAX_TRACKED_SERVED_PEERS - 1 {
            limits.add_served(libp2p::PeerId::random(), 1);
        }
        let last_peer = libp2p::PeerId::random();
        limits.add_served(last_peer, 1);
        let overflow_peer = libp2p::PeerId::random();
        limits.add_served(overflow_peer, 1);

        let inner = limits.inner.lock().unwrap();
        assert_eq!(inner.served.len(), MAX_TRACKED_SERVED_PEERS);
        assert!(!inner.served.contains_key(&first_peer));
        assert!(inner.served.contains_key(&last_peer));
        assert!(inner.served.contains_key(&overflow_peer));
    }
}
