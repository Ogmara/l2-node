//! DM-sync — bounded, authenticated backfill of a single wallet's missed DMs
//! (Phase 2 offline store-and-forward, l2-node 0.69.0+).
//!
//! Phase 1 (persistent DM subscription, [`super::TopicManager::subscribe_dm`])
//! covers the common "recipient offline but their home node is up" case. DM-sync
//! covers the rest: a FRESH node, or one whose home-node was DOWN when a DM was
//! sent. On a user's first auth this process, the node pulls that user's recent
//! DMs from a few peers.
//!
//! Unlike news-sync (global, unauthenticated), DM-sync is PER-WALLET and
//! AUTHENTICATED: the requesting node signs each request with its own node key,
//! host-bound to the responder's PeerId (see [`verify_request_auth`]), so a
//! request is neither replayable to another responder nor forgeable by a node
//! that isn't the connected peer. Confidentiality of the DM bodies rests on E2E
//! encryption — the responder only ever serves ciphertext; the auth + per-peer
//! caps defend against DoS and bulk metadata scraping. The `/dm/<wallet>` gossip
//! topic is itself openly subscribable, so DM-sync exposes nothing the live
//! gossip path does not.
//!
//! Mirrors `network/news_sync.rs`: libp2p CBOR request/response, cursor paging,
//! capped + rate-limited responses; the responder re-serves the ORIGINAL signed
//! envelopes and the requester re-validates each through
//! `router::process_synced_message`, so a relaying peer is never trusted.
//!
//! **Revision 1 (l2-node 0.153.0, G4, owner decision D2).** A requester that
//! sends `revision ≥ 1` additionally receives, for the authorizing wallet
//! only:
//!  * on the session's FIRST page (no cursor) — the wallet's current
//!    `KeyVaultSync` (0x38) and `SettingsSync` (0x33) envelopes (each
//!    preceded by the signing device's `DeviceDelegation` (0x31) when a
//!    delegated device signed it; a revoked device's copy is not served)
//!    and the DM-scope `ChannelKeyEnvelope`s (0x61) wrapped FOR the wallet
//!    (`target == wallet`) in its conversations. None of them depends on a
//!    DM being applied first. On the last page a byte-full primary scan
//!    could cut them every session; on the first page they come before the
//!    DMs. They fit the 8 MiB page budget when the client encodes the
//!    ciphertext as MessagePack `bin` (as the SDK does: a 2 MiB vault then
//!    costs ~4 MiB on the wire); an item that does not fit is skipped, the
//!    next one still tried;
//!  * on the LAST page — the `DirectMessageReaction`s (0x08) of its
//!    conversations within the window, after the edit/delete ride-along
//!    (a reaction needs its target DM applied first).
//!
//! These never travel through identity-sync: identity-sync is
//! unauthenticated, dm-sync is wallet-authorized (D2; protocol §8.4.3).
//! A requester that sends no `revision` (0.152 and older) is served exactly
//! the 0.152 page shape; an older responder ignores the field.

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::network::reconcile::{append_within_byte_budget, envelope_wire_cost, MAX_RESPONSE_ENVELOPE_BYTES};

use crate::crypto::signing;
use crate::storage::rocks::Storage;
use crate::storage::schema;

/// libp2p CBOR request/response codec for dm-sync.
pub type DmSyncCodec =
    libp2p::request_response::cbor::Behaviour<DmSyncRequest, DmSyncResponse>;

/// Protocol string. Versioned independently.
pub fn protocol_string(network_id: &str) -> String {
    format!("/ogmara/{}/dm-sync/1.0.0", network_id)
}

// --- Tuning (window comes from config; these bound it further) ---

/// Max envelopes a responder returns per page — the primary `DM_MESSAGES`
/// scan only; the LAST page also carries the edit/delete ride-along.
pub const MAX_ENVELOPES_PER_RESPONSE: usize = 200;
/// Max edit/delete (and, since l2-node 0.151.0, GDPR `DeletionRequest`)
/// envelopes the last-page ride-along carries.
pub const DM_EDIT_DELETE_CAP: usize = 1_000;
/// The largest page an honest responder sends (a full primary page plus a
/// full ride-along). Before l2-node 0.151.0 the requester refused anything
/// above `MAX_ENVELOPES_PER_RESPONSE`, discarding every last page whose
/// ride-along pushed it past 200 envelopes.
pub const MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS: usize =
    MAX_ENVELOPES_PER_RESPONSE + DM_EDIT_DELETE_CAP;
/// The dm-sync revision this node speaks (l2-node 0.153.0, G4): the
/// first-page vault / settings / DM key envelopes and the last-page DM
/// reaction ride-along (see the module doc). Sent in every request.
pub const DM_SYNC_REVISION: u8 = 1;
/// Max DM-scope key envelopes (0x61) the revision-1 first page carries,
/// across all of the wallet's conversations (most recently active first).
pub const DM_KEY_ENVELOPE_CAP: usize = 1_000;
/// Per conversation, max key envelopes served per AUTHOR (round-1 audit
/// W4): the wallet's own wraps are scanned first, then the counterpart's,
/// each with this budget, so neither sender (nor a counterpart flooding its
/// own slots with fake device ids) can starve the other.
pub const DM_KEYS_PER_AUTHOR: usize = 32;
/// Per author, max key envelopes served per DEVICE (its newest epochs).
pub const DM_KEYS_PER_DEVICE: usize = 8;
/// Per author, max distinct devices visited (one seek each).
pub const DM_KEY_DEVICES_PER_AUTHOR: usize = 16;
/// Max `DirectMessageReaction`s the revision-1 last page carries (newest
/// first per conversation, most recently active conversation first).
pub const DM_REACTION_CAP: usize = 2_000;
/// Max `DM_REACTION_MSGS` rows the reaction ride-along EXAMINES per page
/// (served or skipped), across all conversations (round-2 audit N3).
pub const DM_REACTION_SCAN_CAP: usize = 4 * DM_REACTION_CAP;
/// Max envelopes of the revision-1 first-page head: vault + settings, up to
/// two device delegations, and the key envelopes.
pub const DM_HEAD_CAP: usize = 4 + DM_KEY_ENVELOPE_CAP;
/// The most envelopes an honest revision-1 responder puts on one page
/// (round-1 audit N2): the primary page, plus the head only on the FIRST
/// page (the request had no cursor), plus the edit/delete and reaction
/// ride-alongs only on the FINAL page (`has_more = false`). A revision-0
/// responder's pages are always within this bound.
pub fn max_page_envelopes(first_page: bool, final_page: bool) -> usize {
    let mut n = if final_page {
        MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS + DM_REACTION_CAP
    } else {
        MAX_ENVELOPES_PER_RESPONSE
    };
    if first_page {
        n += DM_HEAD_CAP;
    }
    n
}
/// Wire bytes of the vault / settings envelopes charged as ONE extra unit of
/// the responder's rolling budget (l2-node 0.153.0). The budget otherwise
/// counts envelopes and rows, and a 2 MiB vault re-fetched in a loop by an
/// authorized node would cost one unit each time.
pub const BLOB_WIRE_BYTES_PER_BUDGET_UNIT: usize = 16 * 1024;
/// Max concurrent inbound dm-sync requests served to one peer.
pub const SERVER_MAX_CONCURRENT_PER_PEER: usize = 2;
/// How many peers an outbound backfill races (first non-empty wins).
pub const FANOUT: usize = 3;
/// Max conversations a responder scans for one wallet per request stream. A
/// wallet with more than this many conversations backfills only the first
/// `MAX_CONVERSATIONS` (in stable conversation_id order); the rest still arrive
/// via live gossip once the node is subscribed. The caller logs when this cap is
/// hit — NEVER a silent truncation.
pub const MAX_CONVERSATIONS: usize = 2_000;
/// Auth freshness window: a request's signed timestamp must be within this many
/// seconds of the responder's clock (in either direction, to tolerate skew).
pub const AUTH_MAX_AGE_SECS: u64 = 120;
/// Freshness window for the WALLET's dm-sync authorization claim (audit W5).
/// Wider than `AUTH_MAX_AGE_SECS`, which governs the per-request/per-page
/// NODE self-signature (refreshed every page) — this claim is signed ONCE
/// by the wallet at login/connect and reused for the whole session's
/// backfill, including pagination and fanout to multiple peers.
pub const WALLET_AUTH_MAX_AGE_SECS: u64 = 300;

/// True iff `msg_type` is a DM-sync content type — the receiver's
/// type-smuggling defense so a responder can't inject another type through
/// this path. Originally `DirectMessage` (`0x05`) only; widened to also
/// accept `DirectMessageEdit` (`0x06`) / `DirectMessageDelete` (`0x07`)
/// (audit final pre-mainnet W6) so the edit/delete ride-along
/// (`dm_edit_delete_envelopes`) isn't silently dropped on receipt.
/// Revision 1 (l2-node 0.153.0) adds the five [`is_dm_sync_v1_type`]s;
/// those are additionally bound to the requested wallet by
/// [`dm_envelope_fit`].
pub fn is_dm_type(msg_type: u8) -> bool {
    use crate::messages::types::MessageType;
    matches!(
        MessageType::from_u8(msg_type),
        Some(
            MessageType::DirectMessage
                | MessageType::DirectMessageEdit
                | MessageType::DirectMessageDelete
                // GDPR DeletionRequest (l2-node 0.151.0, G5): indexed into
                // DM_EDIT_DELETE_MSGS under its DM target's conversation. The
                // receiver also checks the target (`network::deletion_request_fit`).
                | MessageType::DeletionRequest
        )
    ) || is_dm_sync_v1_type(msg_type)
}

/// The types dm-sync revision 1 adds (l2-node 0.153.0, G4):
/// `DirectMessageReaction` (0x08), `SettingsSync` (0x33), `KeyVaultSync`
/// (0x38), `ChannelKeyEnvelope` (0x61, DM scope only) and — so a vault or
/// settings blob signed by a delegated device can be verified on a fresh
/// node (round-1 audit W2) — the wallet's own `DeviceDelegation` (0x31).
pub fn is_dm_sync_v1_type(msg_type: u8) -> bool {
    use crate::messages::types::MessageType;
    matches!(
        MessageType::from_u8(msg_type),
        Some(
            MessageType::DirectMessageReaction
                | MessageType::SettingsSync
                | MessageType::KeyVaultSync
                | MessageType::ChannelKeyEnvelope
                | MessageType::DeviceDelegation
        )
    )
}

/// The revision-1 HEAD types: what a first page carries before the DMs and
/// what a cancelled fanout sibling's first page still contributes (round-1
/// audit N7) — all apply order-independently (LWW / first-write-wins).
pub fn is_dm_sync_head_type(msg_type: u8) -> bool {
    use crate::messages::types::MessageType;
    matches!(
        MessageType::from_u8(msg_type),
        Some(
            MessageType::SettingsSync
                | MessageType::KeyVaultSync
                | MessageType::ChannelKeyEnvelope
                | MessageType::DeviceDelegation
        )
    )
}

/// How a dm-sync receiver classifies one envelope BEFORE routing it
/// (l2-node 0.153.0): the scope binding of the revision-1 types to the
/// wallet the session is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmSyncFit {
    /// Route it.
    Fits,
    /// Skip it silently: an honest responder can legitimately send it and
    /// this node cannot use it yet (a reaction whose target DM is not
    /// stored here; a vault / settings envelope signed by a device this
    /// node cannot resolve). Neither progress nor a peer fault.
    Neutral,
    /// Drop and count it (taint): not a dm-sync type, undecodable, or
    /// outside the wallet's scope — an honest responder never sends it.
    Foreign,
}

/// `true` for a Ogmara device address (`ogd1…`).
fn is_device_address(addr: &str) -> bool {
    addr.strip_prefix(crate::crypto::DEVICE_HRP).is_some_and(|rest| rest.starts_with('1'))
}

/// Bind one received dm-sync envelope to `wallet` (l2-node 0.153.0, G4).
/// The router still re-validates everything it routes; this only keeps a
/// responder from using the wallet-authorized session to deliver content
/// of another scope:
///  * `ChannelKeyEnvelope` — DM scope only, wrapped FOR `wallet`
///    (`target == wallet`), and in one of `wallet`'s conversations: either
///    `wallet` authored it (`key_scope == conversation_id(wallet, peer)`) or
///    names `wallet` as the `peer` (the router then proves `key_scope ==
///    conversation_id(author, wallet)`);
///  * `SettingsSync` / `KeyVaultSync` — authored by `wallet` itself or by a
///    device (`ogd1…`) this node maps to `wallet`; another wallet, or a
///    device it maps to ANOTHER wallet, is `Foreign`; an unknown device is
///    `Neutral` (the router would file it under the device address, never
///    under `wallet`). The responder sends the device's delegation first,
///    so on an honest page the device is known by then;
///  * `DeviceDelegation` — authored (wallet-signed) by `wallet` only;
///  * `DirectMessageReaction` — its target, when stored here, must be a DM
///    of `wallet` (`recipient == wallet`, or `wallet` sent it:
///    `conversation_id == conversation_id(wallet, recipient)` — DM
///    conversation ids are validated against sender / recipient at ingest);
///    an unknown target is `Neutral`.
///
/// The older types pass on their type alone (unchanged; the deletion
/// request has its own check, `network::deletion_request_fit`).
pub fn dm_envelope_fit(storage: &Storage, wallet: &str, env_bytes: &[u8]) -> DmSyncFit {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{key_scope_kind, ChannelKeyEnvelopePayload, MessageType, ReactionPayload};
    let Ok(env) = rmp_serde::from_slice::<Envelope>(env_bytes) else {
        return DmSyncFit::Foreign;
    };
    let t = env.msg_type_u8();
    if !is_dm_type(t) {
        return DmSyncFit::Foreign;
    }
    match env.msg_type {
        MessageType::ChannelKeyEnvelope => {
            let Ok(p) = rmp_serde::from_slice::<ChannelKeyEnvelopePayload>(&env.payload) else {
                return DmSyncFit::Foreign;
            };
            let in_scope = p.scope_kind == key_scope_kind::DM
                && p.target == wallet
                && p.peer.as_deref().is_some_and(|peer| {
                    peer == wallet || p.key_scope == crate::crypto::compute_conversation_id(wallet, peer)
                });
            if in_scope {
                DmSyncFit::Fits
            } else {
                DmSyncFit::Foreign
            }
        }
        MessageType::DeviceDelegation => {
            if env.author == wallet {
                DmSyncFit::Fits
            } else {
                DmSyncFit::Foreign
            }
        }
        MessageType::SettingsSync | MessageType::KeyVaultSync => {
            if env.author == wallet {
                return DmSyncFit::Fits;
            }
            // Signed directly by ANOTHER wallet: foreign. Only a device key
            // (`ogd1…`) can still be this wallet's.
            if !is_device_address(&env.author) {
                return DmSyncFit::Foreign;
            }
            match storage.resolve_wallet(&env.author) {
                Ok(Some(w)) if w == wallet => DmSyncFit::Fits,
                Ok(Some(_)) => DmSyncFit::Foreign,
                Ok(None) | Err(_) => DmSyncFit::Neutral,
            }
        }
        MessageType::DirectMessageReaction => {
            let Ok(p) = rmp_serde::from_slice::<ReactionPayload>(&env.payload) else {
                return DmSyncFit::Foreign;
            };
            if storage.get_cf(schema::cf::MESSAGES, &p.target_id).ok().flatten().is_none() {
                return DmSyncFit::Neutral;
            }
            match storage.dm_message_target(&p.target_id) {
                Some(dm)
                    if dm.recipient == wallet
                        || dm.conversation_id == crate::crypto::compute_conversation_id(wallet, &dm.recipient) =>
                {
                    DmSyncFit::Fits
                }
                // Stored, but not a DM of this wallet (or not a DM at all).
                _ => DmSyncFit::Foreign,
            }
        }
        _ => DmSyncFit::Fits,
    }
}

/// `true` when a router REFUSAL (`Rejected`, never `Invalid`) of a synced
/// revision-1 envelope is neutral for a dm-sync session (l2-node 0.153.0,
/// round-1 audit N1) — exactly the refusals an honest responder can cause
/// on a fresh node:
///  * the registration requirement (`REGISTRATION_REQUIRED_REASON`; this
///    node's `USERS` rows may lag the chain);
///  * a full key scope (`key_scope_full` / "scope is full");
///  * a reaction whose target DM is not stored ("target message not
///    found");
///  * an envelope authored by a device (`ogd1…`) this node cannot resolve
///    yet, or a reaction to a DM whose device author it cannot resolve
///    (the participant / scope binding then fails on the device address).
///
/// Every other refusal warns.
pub fn is_neutral_dm_sync_refusal(storage: &Storage, env_bytes: &[u8], reason: &str) -> bool {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{MessageType, ReactionPayload};
    let Ok(env) = rmp_serde::from_slice::<Envelope>(env_bytes) else {
        return false;
    };
    if !is_dm_sync_v1_type(env.msg_type_u8()) {
        return false;
    }
    if reason == crate::messages::router::REGISTRATION_REQUIRED_REASON
        || reason.contains("key_scope_full")
        || reason.contains("scope is full")
        || reason.contains("target message not found")
    {
        return true;
    }
    let unresolved = |addr: &str| is_device_address(addr) && matches!(storage.resolve_wallet(addr), Ok(None));
    if unresolved(&env.author) {
        return true;
    }
    if env.msg_type == MessageType::DirectMessageReaction {
        let target_author = rmp_serde::from_slice::<ReactionPayload>(&env.payload)
            .ok()
            .and_then(|p| storage.get_cf(schema::cf::MESSAGES, &p.target_id).ok().flatten())
            .and_then(|raw| rmp_serde::from_slice::<Envelope>(&raw).ok())
            .map(|e| e.author);
        if target_author.is_some_and(|a| unresolved(&a)) {
            return true;
        }
    }
    false
}

// --- Auth (node-signed, host-bound to the responder; spec 3) ---

/// Build the host-bound auth string a requester signs (and a responder verifies).
///
/// Binds: protocol domain + network + the RESPONDER's PeerId + the target wallet
/// + a fresh ms timestamp. The responder's PeerId is known to the requester (it
/// is the peer it dials) and re-derived locally by the responder, so a signature
/// captured for one responder fails verification on any other — defeating
/// cross-responder replay. Freshness (the timestamp) defeats delayed replay.
pub fn build_auth_string(
    network: &str,
    responder_peer_id: &str,
    wallet: &str,
    timestamp_ms: u64,
) -> String {
    format!("ogmara-dm-sync:{network}:{responder_peer_id}:{wallet}:{timestamp_ms}")
}

/// Build the dm-sync WALLET-authorization claim string (audit W5): proves
/// the wallet at `wallet` authorized `node_id` SPECIFICALLY to backfill its
/// DMs. Mirrors the domain-separated claim pattern already used for
/// `DeviceDelegation`/`DeviceEncBinding` (`ogmara-device-claim:`/
/// `ogmara-enc-bind:`, see `messages::router::verify_device_delegation_claim`/
/// `verify_device_enc_claim`). `node_id` is the SAME value a client already
/// fetches from `GET /api/v1/health` for the existing host-bound REST/WS
/// auth — no new node-identity discovery mechanism needed.
///
/// Deliberately wallet-direct only (v1) — no delegated-device signing
/// support. This keeps `verify_wallet_claim` a pure bech32-decode with zero
/// local-state/lookup dependency, matching the same property
/// `crypto::address_to_verifying_key` already gives `DeviceDelegation`/
/// `DeviceEncBinding` claims: a dm-sync RESPONDER that has never seen this
/// wallet before can still verify the claim. Extending this to delegated
/// device keys is a deliberate, deferred follow-up, not an oversight.
pub fn build_wallet_auth_claim(network: &str, node_id: &str, wallet: &str, timestamp_ms: u64) -> String {
    format!("ogmara-dm-sync-auth:{network}:{node_id}:{wallet}:{timestamp_ms}")
}

/// Verify a wallet's dm-sync authorization claim against a SPECIFIC
/// `node_id`. Pure function, zero local-state dependency. Called from BOTH
/// the requesting node (self-check on receipt, before using the claim) and
/// the responder (the real security gate, inside `verify_request_auth`).
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
/// `node_id`) to backfill its DMs on its behalf (audit W5). `None` on a
/// `DmSyncRequest` means a pre-fix client, or one that didn't attach one —
/// the responder must reject either way (fail closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAuthClaim {
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmSyncRequest {
    /// Wallet whose missed DMs are requested.
    pub wallet: String,
    /// Requesting node's Ed25519 public key (32 bytes). MUST equal the public
    /// key of the connected peer — the responder checks `pk.to_peer_id() ==
    /// peer`, binding this app-layer identity to the transport-authenticated one.
    pub requester_pubkey: Vec<u8>,
    /// Unix-ms timestamp the request was signed at (freshness).
    pub timestamp: u64,
    /// Ed25519 signature (64 bytes) over `build_auth_string(...)`, made with the
    /// requester's node signing key.
    pub signature: Vec<u8>,
    /// Only serve DMs newer than `now - max_age_secs`. `u64::MAX` = unlimited.
    /// Bounded by the responder's own retention window regardless.
    pub max_age_secs: u64,
    /// Opaque paging cursor (continue after this point, across conversations).
    pub cursor: Option<DmCursor>,
    /// Wallet-signed proof that `wallet` authorized THIS node (by node_id)
    /// to backfill on its behalf (audit W5). `#[serde(default)]` keeps
    /// old-shaped CBOR bytes decodable (decode to `None`) — no
    /// `protocol_string()` bump needed; a pre-fix peer's request just gets
    /// `auth_failed_response()` once the new check runs.
    #[serde(default)]
    pub wallet_claim: Option<WalletAuthClaim>,
    /// Requester protocol revision (l2-node 0.153.0): `0` (absent) = a
    /// 0.152-or-older requester, served exactly the 0.152 page shape (its
    /// type allow-list and page-size guard predate the revision-1 types);
    /// [`DM_SYNC_REVISION`] = 0.153+. Not part of the signed auth string
    /// (the transport is authenticated; like `ReconcileRequest::revision`).
    /// Additive, `#[serde(default)]`; an older responder ignores it.
    #[serde(default)]
    pub revision: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmSyncResponse {
    /// Original signed DM envelopes (MessagePack). Receiver re-validates each.
    pub envelopes: Vec<Vec<u8>>,
    pub has_more: bool,
    pub next_cursor: Option<DmCursor>,
    /// Set when the responder rate-capped the request (back off + retry later).
    pub server_capped: bool,
    /// Set when the request failed authentication (distinct from rate-capped —
    /// the requester should NOT retry without a fresh, correctly-bound token).
    #[serde(default)]
    pub auth_failed: bool,
}

/// Cursor over a wallet's DMs. Conversations are paged in STABLE ascending
/// `conversation_id` order (NOT last-activity, which churns as new DMs arrive);
/// within a conversation, `DM_MESSAGES` is forward-chronological (timestamp
/// ascending). This is the main complexity over news-sync's single-stream feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmCursor {
    /// Conversation the previous page stopped in.
    pub conversation_id: [u8; 32],
    /// Timestamp (ms) of the last served message in that conversation.
    pub after_timestamp: u64,
    /// msg_id of the last served message (tiebreak within an identical timestamp).
    pub after_msg_id: [u8; 32],
}

/// A `server_capped` response carrying nothing — sent when rate-limited.
pub fn capped_response() -> DmSyncResponse {
    DmSyncResponse {
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: true,
        auth_failed: false,
    }
}

/// An `auth_failed` response carrying nothing — sent when the request's
/// signature / binding / freshness check fails.
pub fn auth_failed_response() -> DmSyncResponse {
    DmSyncResponse {
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: false,
        auth_failed: true,
    }
}

/// Sign a DM-sync request as the requesting node. `responder_peer_id` is the
/// `to_string()` of the peer being dialed (host-binding target).
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    signing_key: &ed25519_dalek::SigningKey,
    network: &str,
    responder_peer_id: &str,
    wallet: &str,
    timestamp_ms: u64,
    max_age_secs: u64,
    cursor: Option<DmCursor>,
    wallet_claim: Option<WalletAuthClaim>,
) -> DmSyncRequest {
    let auth_string = build_auth_string(network, responder_peer_id, wallet, timestamp_ms);
    let sig = signing::sign_klever_message(signing_key, auth_string.as_bytes());
    DmSyncRequest {
        wallet: wallet.to_string(),
        requester_pubkey: signing_key.verifying_key().to_bytes().to_vec(),
        timestamp: timestamp_ms,
        signature: sig.to_bytes().to_vec(),
        max_age_secs,
        cursor,
        wallet_claim,
        revision: DM_SYNC_REVISION,
    }
}

/// Verify a DM-sync request's auth. Returns `true` iff ALL hold:
///  1. `requester_pubkey` is a valid 32-byte Ed25519 key whose derived PeerId
///     equals the connected `peer` (binds app identity to the transport identity
///     — a node can't claim another's key);
///  2. the signed `timestamp` is within `AUTH_MAX_AGE_SECS` of `now_ms`;
///  3. the signature verifies over the host-bound auth string built with the
///     RESPONDER's own PeerId (so a captured request can't be replayed to a
///     different node);
///  4. (audit W5) `wallet_claim` is present and verifies: the WALLET whose
///     DMs are requested must have itself authorized THIS specific node.
///     `node_id` is derived from the ALREADY-VERIFIED `requester_pubkey`
///     (step 1 proved this node controls it), so a claim minted for a
///     different node can never satisfy this — closes the Sybil-scraping
///     gap where any freshly-generated node key could request any wallet's
///     history.
pub fn verify_request_auth(
    request: &DmSyncRequest,
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
    // 3. Signature over the host-bound string, with the requester's dalek key.
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
    let auth_string = build_auth_string(network, responder_peer_id, &request.wallet, request.timestamp);
    if signing::verify_klever_message(&vk, auth_string.as_bytes(), &sig).is_err() {
        return false;
    }
    // 4. Wallet W5: the wallet whose DMs are requested must have authorized
    //    THIS node specifically.
    let node_id = crate::crypto::compute_node_id(&vk);
    match &request.wallet_claim {
        Some(claim) => verify_wallet_claim(claim, network, &node_id, &request.wallet, now_ms),
        None => false,
    }
}

/// Build a response: page a wallet's DMs across conversations (stable ascending
/// `conversation_id` order), re-serving the ORIGINAL signed envelopes from
/// `MESSAGES`. Caps total envelopes at `max_envelopes`. `window_max_age_secs` is
/// the RESPONDER's own retention window; we serve the tighter of it and the
/// request's `max_age_secs`. Returns `(response, scanned_all_conversations)` —
/// the caller logs when `scanned_all` is false so a conversation-count cap is
/// never silent.
///
/// Also returns the storage work done (one unit per seek and per index row
/// examined, ride-along rows included) for the responder's rolling budget
/// (`reconcile::budget_charge`, l2-node 0.151.0): `(response, scanned_all,
/// work)`. A DM erased by a GDPR `DeletionRequest` (decision D4) is never
/// re-served, nor is an edit/delete of one; the request rides along.
///
/// Revision 1 (l2-node 0.153.0, G4; `request.revision ≥ DM_SYNC_REVISION`):
/// the first page (no cursor) starts with the wallet's vault, settings and
/// DM key envelopes ([`dm_sync_head_envelopes`]) — served even when the
/// wallet has no conversation — and the last page ends with its DM
/// reactions ([`dm_reaction_envelopes`]). `max_envelopes` bounds the
/// PRIMARY rows only, as before. The vault / settings wire bytes add
/// `bytes / BLOB_WIRE_BYTES_PER_BUDGET_UNIT` to `work`.
pub fn build_response(
    storage: &Storage,
    wallet: &str,
    request: &DmSyncRequest,
    max_envelopes: usize,
    now_ms: u64,
    window_max_age_secs: u64,
) -> (DmSyncResponse, bool, u64) {
    let v1 = request.revision >= DM_SYNC_REVISION;

    // Honour the tighter of the requester's ask and our own retention window.
    let effective_age = request.max_age_secs.min(window_max_age_secs);
    let min_ts = if effective_age == u64::MAX {
        0
    } else {
        now_ms.saturating_sub(effective_age.saturating_mul(1000))
    };

    // 1. Collect the wallet's conversation_ids in STABLE ascending order.
    //    DM_CONVERSATIONS is keyed (wallet, !last_activity, conversation_id) —
    //    reverse-chrono, which churns; we re-sort by conversation_id for a
    //    paging order that's stable across requests.
    //    The prefix is the bare wallet bytes (no delimiter), matching the
    //    writer (`router::update_indexes`) and the REST DM path. This is safe
    //    only because Klever `klv1…` addresses are fixed-length bech32 — no valid
    //    address is a byte-prefix of another, so the scan never crosses wallets.
    let prefix = wallet.as_bytes();
    let conv_rows = match storage.prefix_iter_cf(
        schema::cf::DM_CONVERSATIONS,
        prefix,
        MAX_CONVERSATIONS.saturating_add(1),
    ) {
        Ok(r) => r,
        Err(_) => return (empty_response(Vec::new()), true, 1),
    };
    let mut work: u64 = 1 + conv_rows.len() as u64;
    // Revision 1: the same conversations in RECENCY order (key order —
    // most recently active first, deduplicated keeping the first), which the
    // capped extras walk so the active conversations come first.
    // Each comes with its counterpart (the row value), kept only when it
    // really is the conversation's other participant
    // (`conversation_id(wallet, peer) == cid`), for the per-author key scan.
    let mut conv_recent: Vec<[u8; 32]> = Vec::new();
    let mut conv_heads: Vec<([u8; 32], Option<String>)> = Vec::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut conv_ids: Vec<[u8; 32]> = Vec::with_capacity(conv_rows.len());
    for (key, value) in &conv_rows {
        if key.len() < prefix.len() + 8 + 32 {
            continue; // malformed
        }
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&key[key.len() - 32..]);
        conv_ids.push(cid);
        if v1 && seen.insert(cid) {
            conv_recent.push(cid);
            let peer = std::str::from_utf8(value)
                .ok()
                .filter(|p| crate::crypto::compute_conversation_id(wallet, p) == cid)
                .map(str::to_owned);
            conv_heads.push((cid, peer));
        }
    }
    conv_ids.sort_unstable();
    conv_ids.dedup();
    let scanned_all = conv_ids.len() <= MAX_CONVERSATIONS;
    conv_ids.truncate(MAX_CONVERSATIONS);
    conv_recent.truncate(MAX_CONVERSATIONS);
    conv_heads.truncate(MAX_CONVERSATIONS);

    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    // Wire bytes of the page so far, and whether they filled it (W5).
    let mut bytes: usize = 0;

    // Revision 1, first page: vault + settings + DM key envelopes.
    if v1 && request.cursor.is_none() {
        let head = dm_sync_head_envelopes(storage, wallet, &conv_heads);
        work += head.work;
        work += (head.blob_wire_bytes / BLOB_WIRE_BYTES_PER_BUDGET_UNIT) as u64;
        // Round-1 audit N3: skip (not stop at) an item that does not fit.
        for raw in head.envelopes {
            let cost = envelope_wire_cost(&raw);
            if bytes.saturating_add(cost) <= MAX_RESPONSE_ENVELOPE_BYTES {
                bytes += cost;
                envelopes.push(raw);
            }
        }
    }

    if conv_ids.is_empty() {
        return (empty_response(envelopes), scanned_all, work);
    }

    // 2. Resume point: the cursor's conversation (or its insertion slot if that
    //    conversation has since vanished), else the first conversation.
    let (start_idx, resume_cursor) = match request.cursor.as_ref() {
        Some(c) => match conv_ids.binary_search(&c.conversation_id) {
            Ok(i) => (i, Some(c.clone())),
            Err(i) => (i, None),
        },
        None => (0, None),
    };

    let mut next_cursor: Option<DmCursor> = None;
    let mut has_more = false;
    let mut byte_full = false;
    // PRIMARY (`DM_MESSAGES`) rows served on this page — what
    // `max_envelopes` bounds and what guarantees progress: at least one is
    // always served whatever the head extras took (they stay far below the
    // byte budget), so `has_more` never comes without a cursor.
    let mut primaries: usize = 0;

    for (ci, cid) in conv_ids.iter().enumerate().skip(start_idx) {
        if primaries >= max_envelopes {
            has_more = true;
            break;
        }
        // Resume after the cursor only in the cursor's OWN conversation; every
        // later conversation starts at the window cutoff.
        let start_key = match resume_cursor.as_ref() {
            Some(c) if ci == start_idx => {
                schema::encode_dm_msg_key(cid, c.after_timestamp, &c.after_msg_id)
            }
            _ => schema::encode_dm_msg_key(cid, min_ts, &[0u8; 32]),
        };
        let budget = max_envelopes - primaries;
        // budget + 1 detects whether this conversation has more beyond the page.
        let rows = match storage.prefix_iter_cf_after(
            schema::cf::DM_MESSAGES,
            &start_key,
            &cid[..],
            budget.saturating_add(1),
        ) {
            Ok(r) => r,
            Err(_) => continue,
        };
        work += 1 + rows.len() as u64;
        let conv_has_more = rows.len() > budget;
        for (key, _) in rows.iter().take(budget) {
            // key = (conversation_id:32, timestamp:8 BE, msg_id:32) = 72 bytes.
            if key.len() < 72 {
                continue;
            }
            let ts = u64::from_be_bytes(match key[32..40].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            });
            if ts < min_ts {
                continue; // defensive — the seek already excludes these
            }
            let mut msg_id = [0u8; 32];
            msg_id.copy_from_slice(&key[40..72]);
            // D4 (l2-node 0.151.0): never re-serve a GDPR-erased DM.
            let raw = if storage.is_gdpr_erased(&msg_id) {
                None
            } else {
                storage.get_cf(schema::cf::MESSAGES, &msg_id).ok().flatten()
            };
            // W5 (l2-node 0.151.0): page full by BYTES — stop before this row
            // (the cursor stays on the previous one).
            if let Some(r) = raw.as_ref() {
                if primaries > 0 && bytes.saturating_add(envelope_wire_cost(r)) > MAX_RESPONSE_ENVELOPE_BYTES {
                    byte_full = true;
                    break;
                }
            }
            // Advance the cursor over EVERY in-window row examined (even if its
            // MESSAGES entry is missing) so a sparse page can't strand rows.
            next_cursor = Some(DmCursor {
                conversation_id: *cid,
                after_timestamp: ts,
                after_msg_id: msg_id,
            });
            if let Some(r) = raw {
                bytes = bytes.saturating_add(envelope_wire_cost(&r));
                envelopes.push(r);
                primaries += 1;
            }
        }
        if byte_full {
            has_more = true;
            break;
        }
        if conv_has_more {
            has_more = true;
            break; // resume THIS conversation on the next page (cursor points here)
        }
        // conversation exhausted → fall through to the next conversation
    }

    if !has_more {
        next_cursor = None;
        // Audit final pre-mainnet W6: ride edit/delete envelopes along on the
        // session's LAST page only. All pages of one dm-sync session are
        // requested/applied strictly in order against a single peer, so by
        // the last page every original DM the session could have delivered
        // has already been applied — which `authorize_edit_delete` requires
        // before an edit/delete can be accepted.
        let (ed, ed_work) = dm_edit_delete_envelopes(storage, &conv_ids, min_ts);
        work += ed_work;
        // W5: within the response byte budget.
        bytes = append_within_byte_budget(&mut envelopes, ed, bytes);
        // Revision 1 (G4): the DM reactions, after the edits/deletes — the
        // same last-page ordering argument (`authorize_dm_reaction` needs
        // the target DM stored).
        if v1 {
            let (re, re_work) = dm_reaction_envelopes(storage, &conv_recent, min_ts);
            work += re_work;
            append_within_byte_budget(&mut envelopes, re, bytes);
        }
    }

    (
        DmSyncResponse {
            envelopes,
            has_more,
            next_cursor,
            server_capped: false,
            auth_failed: false,
        },
        scanned_all,
        work,
    )
}

/// A final (`has_more = false`) response carrying `envelopes`.
fn empty_response(envelopes: Vec<Vec<u8>>) -> DmSyncResponse {
    DmSyncResponse {
        envelopes,
        has_more: false,
        next_cursor: None,
        server_capped: false,
        auth_failed: false,
    }
}

/// The revision-1 first-page extras ([`dm_sync_head_envelopes`]).
pub(crate) struct DmSyncHead {
    /// Delegations, vault, settings, then key envelopes — in priority
    /// order (an item that does not fit the byte budget is skipped).
    pub envelopes: Vec<Vec<u8>>,
    /// Storage work (seeks + rows examined).
    pub work: u64,
    /// Wire bytes of the vault + settings envelopes.
    pub blob_wire_bytes: usize,
}

/// The wallet's `DeviceDelegation` envelope for `device` (newest first
/// among the wallet's last 64 delegations in `IDENTITY_ENVELOPES`), and the
/// work spent finding it.
fn device_delegation_envelope(storage: &Storage, wallet: &str, device: &str) -> (Option<Vec<u8>>, u64) {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{DeviceDelegationPayload, MessageType};
    let mut prefix = Vec::with_capacity(wallet.len() + 2);
    prefix.extend_from_slice(wallet.as_bytes());
    prefix.push(0xFF);
    prefix.push(MessageType::DeviceDelegation as u8);
    let mut upper = prefix.clone();
    upper.extend_from_slice(&[0xFF; 40]);
    let Ok(rows) = storage.reverse_iter_cf(schema::cf::IDENTITY_ENVELOPES, &upper, &prefix, 64) else {
        return (None, 1);
    };
    let mut work = 1 + rows.len() as u64;
    for (key, _) in rows {
        if key.len() < 32 {
            continue;
        }
        let Ok(msg_id) = <[u8; 32]>::try_from(&key[key.len() - 32..]) else {
            continue;
        };
        work += 1;
        let Some(raw) = storage.get_cf(schema::cf::MESSAGES, &msg_id).ok().flatten() else {
            continue;
        };
        let matches = rmp_serde::from_slice::<Envelope>(&raw)
            .ok()
            .filter(|e| e.msg_type == MessageType::DeviceDelegation && e.author == wallet)
            .and_then(|e| rmp_serde::from_slice::<DeviceDelegationPayload>(&e.payload).ok())
            .and_then(|p| crate::storage::identity::device_address_from_hex_key(&p.device_pub_key.to_ascii_lowercase()))
            .is_some_and(|addr| addr == device);
        if matches {
            return (Some(raw), work);
        }
    }
    (None, work)
}

/// The wallet's own revision-1 first-page envelopes (l2-node 0.153.0, G4),
/// all re-served as the ORIGINAL signed envelopes from `MESSAGES`:
///  1. the `KeyVaultSync` and 2. the `SettingsSync` that produced the
///     wallet's CURRENT `key_vault` / `settings_sync` rows (their recorded
///     origin, `Storage::get_key_vault_origin` / `get_settings_origin`; a
///     row with no recorded origin — written before 0.153.0 and not yet
///     reached by the `DM_SYNC_V11_INDEXED` migration — or a tombstone is
///     not served). When a delegated DEVICE signed it (round-1 audit W2),
///     the device's `DeviceDelegation` is served right before it, so a
///     fresh node can verify and attribute it in the same page; a copy
///     signed by a device that is revoked, or no longer maps to the wallet,
///     is not served at all;
///  3. the DM-scope `ChannelKeyEnvelope`s wrapped FOR the wallet in its
///     conversations (key layout `key_scope ‖ target ‖ 0xFF ‖ author ‖ 0xFF
///     ‖ device ‖ epoch`). Per conversation (most recently active first)
///     the scan is per AUTHOR (round-1 audit W4): the wallet's own wraps
///     first, then the counterpart's, each ≤ [`DM_KEYS_PER_AUTHOR`];
///     within an author, devices are visited one seek each (≤
///     [`DM_KEY_DEVICES_PER_AUTHOR`]) taking each device's newest ≤
///     [`DM_KEYS_PER_DEVICE`] epochs; ≤ [`DM_KEY_ENVELOPE_CAP`] in total.
///     Each record's stored `msg_id` locates the original (rows without
///     one are skipped).
///
/// Every served envelope is checked to decode as its expected type.
pub(crate) fn dm_sync_head_envelopes(
    storage: &Storage,
    wallet: &str,
    convs: &[([u8; 32], Option<String>)],
) -> DmSyncHead {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::MessageType;
    let mut head = DmSyncHead { envelopes: Vec::new(), work: 0, blob_wire_bytes: 0 };
    let original = |msg_id: &[u8; 32], want: MessageType| -> Option<(Vec<u8>, Envelope)> {
        let raw = storage.get_cf(schema::cf::MESSAGES, msg_id).ok().flatten()?;
        let env = rmp_serde::from_slice::<Envelope>(&raw).ok()?;
        (env.msg_type == want).then_some((raw, env))
    };
    let mut delegated: Vec<String> = Vec::new();
    for (origin, want) in [
        (storage.get_key_vault_origin(wallet), MessageType::KeyVaultSync),
        (storage.get_settings_origin(wallet), MessageType::SettingsSync),
    ] {
        head.work += 1;
        let Ok(Some(o)) = origin else {
            continue;
        };
        head.work += 1;
        let Some((raw, env)) = original(&o.msg_id, want) else {
            continue;
        };
        if env.author != wallet {
            // Device-signed: only while the device is unrevoked and still
            // maps to this wallet; its delegation goes first.
            head.work += 2;
            // Revoked = signed at or before the device's revocation
            // tombstone (the router's delegation rule); a vault signed
            // after a later re-delegation is served (round-2 audit N1).
            // Global or scoped to this wallet (round-3 audit B1).
            let revoked = match storage.get_device_revoked_at_for(&env.author, wallet) {
                Ok(Some(revoked_at)) => env.timestamp <= revoked_at,
                Ok(None) => false,
                Err(_) => true,
            };
            let mapped = matches!(storage.resolve_wallet(&env.author), Ok(Some(ref w)) if w == wallet);
            if revoked || !mapped {
                continue;
            }
            if !delegated.contains(&env.author) {
                let (deleg, w) = device_delegation_envelope(storage, wallet, &env.author);
                head.work += w;
                if let Some(d) = deleg {
                    head.envelopes.push(d);
                }
                delegated.push(env.author.clone());
            }
        }
        head.blob_wire_bytes = head.blob_wire_bytes.saturating_add(envelope_wire_cost(&raw));
        head.envelopes.push(raw);
    }
    let mut keys = 0usize;
    'convs: for (cid, peer) in convs {
        let authors: Vec<&str> = std::iter::once(wallet).chain(peer.as_deref()).collect();
        for author in authors {
            // Prefix of one author's wraps for the wallet in this scope.
            let mut ap = Vec::with_capacity(32 + wallet.len() + author.len() + 2);
            ap.extend_from_slice(cid);
            ap.extend_from_slice(wallet.as_bytes());
            ap.push(0xFF);
            ap.extend_from_slice(author.as_bytes());
            ap.push(0xFF);
            // Sorts after every key under `ap` (device id 64 + epoch 8).
            let mut start = ap.clone();
            start.extend_from_slice(&[0xFF; 80]);
            let mut author_taken = 0usize;
            for _ in 0..DM_KEY_DEVICES_PER_AUTHOR {
                if keys >= DM_KEY_ENVELOPE_CAP {
                    break 'convs;
                }
                if author_taken >= DM_KEYS_PER_AUTHOR {
                    break;
                }
                let limit = DM_KEYS_PER_DEVICE
                    .min(DM_KEYS_PER_AUTHOR - author_taken)
                    .min(DM_KEY_ENVELOPE_CAP - keys);
                let rows = match storage.reverse_iter_cf(schema::cf::CHANNEL_KEYS, &start, &ap, limit) {
                    Ok(r) => r,
                    Err(_) => break,
                };
                head.work += 1 + rows.len() as u64;
                let Some(device) = rows
                    .first()
                    .filter(|(k, _)| k.len() >= ap.len() + 8)
                    .map(|(k, _)| k[ap.len()..k.len() - 8].to_vec())
                else {
                    break;
                };
                for (key, value) in &rows {
                    if key.len() < ap.len() + 8 || key[ap.len()..key.len() - 8] != device[..] {
                        break; // the next (lower) device: visited by its own seek
                    }
                    let Ok(rec) = serde_json::from_slice::<serde_json::Value>(value) else {
                        continue;
                    };
                    if rec.get("scope_kind").and_then(|v| v.as_u64())
                        != Some(u64::from(crate::messages::types::key_scope_kind::DM))
                    {
                        continue;
                    }
                    let Some(msg_id) = rec
                        .get("msg_id")
                        .and_then(|v| v.as_str())
                        .and_then(|h| hex::decode(h).ok())
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    else {
                        continue;
                    };
                    head.work += 1;
                    if let Some((raw, _)) = original(&msg_id, MessageType::ChannelKeyEnvelope) {
                        head.envelopes.push(raw);
                        keys += 1;
                        author_taken += 1;
                    }
                }
                // Continue strictly below this device: `ap ‖ device` sorts
                // before all of its rows and after every lower device's.
                start = ap.clone();
                start.extend_from_slice(&device);
            }
        }
    }
    head
}

/// The wallet's `DirectMessageReaction`s for the revision-1 last page
/// (l2-node 0.153.0, G4): `DM_REACTION_MSGS` reverse-scanned per
/// conversation (newest first; conversations most recently active first),
/// at most [`DM_REACTION_CAP`] in total and [`DM_REACTION_SCAN_CAP`] rows
/// examined, inside the window (`ts ≥
/// min_ts`). A reaction is withheld when its target DM is GDPR-erased (D4),
/// no longer stored, or older than the window (the requester cannot hold
/// it, so its router would refuse the reaction). Returns `(envelopes,
/// work)`.
pub(crate) fn dm_reaction_envelopes(storage: &Storage, conv_recent: &[[u8; 32]], min_ts: u64) -> (Vec<Vec<u8>>, u64) {
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{MessageType, ReactionPayload};
    let mut out = Vec::new();
    let mut work: u64 = 0;
    // Round-2 audit N3: bound the rows EXAMINED, not only those served — a
    // window full of reactions to erased / missing targets would otherwise
    // make every conversation read up to the cap.
    let mut examined: usize = 0;
    for cid in conv_recent {
        if out.len() >= DM_REACTION_CAP || examined >= DM_REACTION_SCAN_CAP {
            break;
        }
        let budget = (DM_REACTION_CAP - out.len()).min(DM_REACTION_SCAN_CAP - examined);
        let rows = match storage.reverse_iter_cf(
            schema::cf::DM_REACTION_MSGS,
            &schema::message_key_upper_bound(&cid[..]),
            &cid[..],
            budget,
        ) {
            Ok(r) => r,
            Err(_) => continue,
        };
        work += 1 + rows.len() as u64;
        examined += rows.len();
        for (key, _) in rows {
            if key.len() < 72 {
                continue;
            }
            let ts = u64::from_be_bytes(match key[32..40].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            });
            if ts < min_ts {
                break; // newest first: the rest of this conversation is older
            }
            let mut msg_id = [0u8; 32];
            msg_id.copy_from_slice(&key[40..72]);
            work += 2;
            let Some(raw) = storage.get_cf(schema::cf::MESSAGES, &msg_id).ok().flatten() else {
                continue;
            };
            let Some(p) = rmp_serde::from_slice::<Envelope>(&raw)
                .ok()
                .filter(|e| e.msg_type == MessageType::DirectMessageReaction)
                .and_then(|e| rmp_serde::from_slice::<ReactionPayload>(&e.payload).ok())
            else {
                continue;
            };
            if storage.is_gdpr_erased(&p.target_id) {
                continue;
            }
            match storage.dm_message_target(&p.target_id) {
                Some(t) if t.conversation_id == *cid && t.timestamp >= min_ts => out.push(raw),
                _ => {}
            }
        }
    }
    (out, work)
}

/// Gather the wallet's `DirectMessageEdit`/`DirectMessageDelete` envelopes
/// (audit final pre-mainnet W6) across all of `conv_ids`. Without this,
/// edit/delete envelopes never reach a backfilling node at all — the
/// primary `DM_MESSAGES` scan above only ever contains original
/// `DirectMessage` rows — so "deleted for everyone" content is re-served
/// forever. Bounded + best-effort, same tradeoff already accepted for the
/// main scan's `MAX_CONVERSATIONS` cap: a wallet with more markers than the
/// cap just doesn't get its excess markers this session (they'll still
/// arrive via live gossip for anything edited/deleted going forward).
fn dm_edit_delete_envelopes(
    storage: &Storage,
    conv_ids: &[[u8; 32]],
    min_ts: u64,
) -> (Vec<Vec<u8>>, u64) {
    let mut out = Vec::new();
    let mut work: u64 = 0;
    for cid in conv_ids {
        if out.len() >= DM_EDIT_DELETE_CAP {
            warn!(
                cap = DM_EDIT_DELETE_CAP,
                "dm-sync: wallet has more edit/delete markers than the ride-along cap; \
                 remaining conversations' markers were not shipped this session"
            );
            break;
        }
        let budget = DM_EDIT_DELETE_CAP - out.len();
        // Security-audit follow-up (2026-08-18): `DM_EDIT_DELETE_MSGS` keys
        // use a forward (non-negated) timestamp, so a FORWARD prefix scan
        // is oldest-first — `.take(budget)` on that would silently drop the
        // NEWEST excess markers in a conversation that exceeds its budget.
        // Reverse-scan from the upper bound instead so overflow drops the
        // OLDEST markers within this conversation.
        let rows = match storage.reverse_iter_cf(
            schema::cf::DM_EDIT_DELETE_MSGS,
            &schema::message_key_upper_bound(&cid[..]),
            &cid[..],
            budget.saturating_add(1),
        ) {
            Ok(r) => r,
            Err(_) => continue,
        };
        work += 1 + rows.len() as u64;
        for (key, _) in rows.into_iter().take(budget) {
            // key = (conversation_id:32, timestamp:8 BE, msg_id:32) = 72 bytes,
            // same shape as DM_MESSAGES.
            if key.len() < 72 {
                continue;
            }
            let ts = u64::from_be_bytes(match key[32..40].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            });
            if ts < min_ts {
                continue;
            }
            let mut msg_id = [0u8; 32];
            msg_id.copy_from_slice(&key[40..72]);
            if let Ok(Some(raw)) = storage.get_cf(schema::cf::MESSAGES, &msg_id) {
                // D4: no edit/delete of a GDPR-erased DM (the request itself
                // is indexed here too and is served).
                if crate::network::reconcile::ride_along_target_erased(storage, &raw) {
                    continue;
                }
                out.push(raw);
            }
        }
    }
    (out, work)
}

// --- Responder rate limiting (per peer) ---

/// Responder admission for dm-sync (l2-node 0.151.0): per-peer concurrency
/// (`SERVER_MAX_CONCURRENT_PER_PEER`) plus a rolling budget per peer (all
/// wallets together) — `[dm] sync_responder_budget_burst` units (default
/// 5,000) refilled at `sync_responder_budget_refill_per_hour` (default
/// 2,500/h), charged with `reconcile::budget_charge`. Before 0.151.0 this was
/// a LIFETIME counter of envelopes served (`TOTAL_ENVELOPES_CAP = 5,000`)
/// that never refilled until the responder restarted, and it evicted its
/// oldest entry FIFO past 100k peers (a Sybil cycling identities got its
/// budget back); the budget map instead prunes only refilled buckets and
/// refuses NEW peers when full.
pub type DmResponderLimits = crate::network::budget::PeerBudgetLimits<libp2p::PeerId>;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn keypair() -> (SigningKey, libp2p::PeerId) {
        // Deterministic-ish key from fixed bytes so the test never needs RNG.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let ed_pub =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&sk.verifying_key().to_bytes())
                .unwrap();
        let peer = libp2p::identity::PublicKey::from(ed_pub).to_peer_id();
        (sk, peer)
    }

    /// A separate, real WALLET keypair (distinct from the node's own key
    /// above) whose bech32 address can round-trip through
    /// `crypto::address_to_verifying_key` — required for `verify_wallet_claim`
    /// (audit W5), unlike the old placeholder `"klv1abc"` string.
    fn wallet_keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let address = crate::crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        (sk, address)
    }

    /// Build a valid wallet claim authorizing `node_sk`'s node (by its
    /// derived node_id) to backfill `wallet`'s DMs, signed by `wallet_sk`.
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

    #[test]
    fn auth_roundtrip_accepts_valid_request() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, now, 3600, None, Some(claim));
        assert!(verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer));
    }

    #[test]
    fn auth_rejects_cross_responder_replay() {
        // A request signed for responder A must fail verification at responder B.
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", "RESPONDER_A", &wallet, now, 3600, None, Some(claim));
        // Responder B re-derives its OWN peer id into the auth string → mismatch.
        assert!(!verify_request_auth(&req, "RESPONDER_B", "testnet", now, &peer));
    }

    #[test]
    fn auth_rejects_tampered_wallet() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let mut req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, now, 3600, None, Some(claim));
        req.wallet = "klv1evil000000000000000000000000000".into(); // signature no longer covers this wallet
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer));
    }

    #[test]
    fn auth_rejects_stale_timestamp() {
        let (sk, peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let signed_at = 1_700_000_000_000u64;
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, signed_at);
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, signed_at, 3600, None, Some(claim));
        // now is well beyond AUTH_MAX_AGE_SECS past the signed timestamp.
        let now = signed_at + (AUTH_MAX_AGE_SECS + 60) * 1000;
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer));
    }

    #[test]
    fn auth_rejects_pubkey_not_matching_connection_peer() {
        let (sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        // Sign honestly, but present the request over a DIFFERENT peer's stream.
        let other_peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        let claim = valid_claim(&wallet_sk, &sk, "testnet", &wallet, now);
        let req = sign_request(&sk, "testnet", &other_peer.to_string(), &wallet, now, 3600, None, Some(claim));
        assert!(!verify_request_auth(&req, &other_peer.to_string(), "testnet", now, &other_peer));
    }

    // --- W5: wallet-signed dm-sync authorization claim ---

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
        // The wallet's claim for node N doesn't verify when presented as
        // node C — the whole point of binding the claim to a node_id.
        let (node_sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let claim = valid_claim(&wallet_sk, &node_sk, "testnet", &wallet, now);
        let wrong_node_id = "not-the-authorized-node".to_string();
        assert!(!verify_wallet_claim(&claim, "testnet", &wrong_node_id, &wallet, now));
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
        // Signed for one wallet, presented as authorizing a different one.
        let (node_sk, _peer) = keypair();
        let (wallet_sk, wallet) = wallet_keypair();
        let (_other_sk, other_wallet) = {
            let sk = SigningKey::from_bytes(&[11u8; 32]);
            let addr = crate::crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
            (sk, addr)
        };
        let now = 1_700_000_000_000u64;
        let node_id = crate::crypto::compute_node_id(&node_sk.verifying_key());
        let claim = valid_claim(&wallet_sk, &node_sk, "testnet", &wallet, now);
        assert!(!verify_wallet_claim(&claim, "testnet", &node_id, &other_wallet, now));
    }

    #[test]
    fn verify_request_auth_rejects_missing_wallet_claim() {
        // A pre-fix client (or one that omitted the claim) — everything ELSE
        // about the request is valid, isolating the failure to the new check.
        let (sk, peer) = keypair();
        let (_wallet_sk, wallet) = wallet_keypair();
        let now = 1_700_000_000_000u64;
        let req = sign_request(&sk, "testnet", &peer.to_string(), &wallet, now, 3600, None, None);
        assert!(!verify_request_auth(&req, &peer.to_string(), "testnet", now, &peer));
    }

    // --- build_response multi-conversation cursor paging ---

    fn msg_id(conv: u8, n: u8) -> [u8; 32] {
        let mut m = [0u8; 32];
        m[0] = conv;
        m[1] = n;
        m
    }

    #[test]
    fn build_response_pages_across_conversations_without_dup_or_loss() {
        use crate::storage::rocks::Storage;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let wallet = "klv1wallet";
        let base_ts = 1_700_000_000_000u64;

        // Two conversations, 3 messages each, all within the window.
        let conv_a = [0xAAu8; 32];
        let conv_b = [0xBBu8; 32];
        let mut expected: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for (ci, conv) in [(0u8, conv_a), (1u8, conv_b)] {
            for n in 0u8..3 {
                let ts = base_ts + n as u64 * 1000;
                let mid = msg_id(ci, n);
                expected.insert(mid);
                // index row
                storage
                    .put_cf(
                        schema::cf::DM_MESSAGES,
                        &schema::encode_dm_msg_key(&conv, ts, &mid),
                        &[],
                    )
                    .unwrap();
                // raw envelope stand-in (build_response just re-serves the bytes)
                storage.store_message(&mid, &mid.to_vec()).unwrap();
            }
            // one conversation-list row per participant conversation
            storage
                .put_cf(
                    schema::cf::DM_CONVERSATIONS,
                    &schema::encode_dm_conversation_key(wallet.as_bytes(), base_ts, &conv),
                    b"peer",
                )
                .unwrap();
        }

        // Page with a tiny per-response cap (2) to force multi-page + multi-conv.
        let now = base_ts + 10_000;
        let mut cursor = None;
        let mut got: Vec<[u8; 32]> = Vec::new();
        for _ in 0..20 {
            let req = DmSyncRequest {
                wallet: wallet.into(),
                requester_pubkey: vec![0u8; 32],
                timestamp: now,
                signature: vec![0u8; 64],
                max_age_secs: u64::MAX,
                cursor: cursor.clone(),
                wallet_claim: None,
                revision: 0,
            };
            let (resp, scanned_all, _) = build_response(&storage, wallet, &req, 2, now, u64::MAX);
            assert!(scanned_all);
            for env in &resp.envelopes {
                let mut m = [0u8; 32];
                m.copy_from_slice(env);
                got.push(m);
            }
            if !resp.has_more {
                break;
            }
            cursor = resp.next_cursor;
            assert!(cursor.is_some(), "has_more set but no cursor");
        }

        // Every message returned exactly once, none lost.
        assert_eq!(got.len(), 6, "expected 6 messages across 2 conversations");
        let got_set: std::collections::HashSet<[u8; 32]> = got.iter().copied().collect();
        assert_eq!(got_set, expected);
    }

    #[test]
    fn build_response_honours_window_cutoff() {
        use crate::storage::rocks::Storage;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let wallet = "klv1wallet";
        let now = 1_700_000_000_000u64;
        let conv = [0xCCu8; 32];

        // One old message (2 days ago) + one recent (1 min ago).
        let old_ts = now - 2 * 24 * 3600 * 1000;
        let new_ts = now - 60 * 1000;
        let old_id = msg_id(0, 0);
        let new_id = msg_id(0, 1);
        for (ts, id) in [(old_ts, old_id), (new_ts, new_id)] {
            storage
                .put_cf(schema::cf::DM_MESSAGES, &schema::encode_dm_msg_key(&conv, ts, &id), &[])
                .unwrap();
            storage.store_message(&id, &id.to_vec()).unwrap();
        }
        storage
            .put_cf(
                schema::cf::DM_CONVERSATIONS,
                &schema::encode_dm_conversation_key(wallet.as_bytes(), new_ts, &conv),
                b"peer",
            )
            .unwrap();

        // 1-day window → only the recent message is served.
        let req = DmSyncRequest {
            wallet: wallet.into(),
            requester_pubkey: vec![0u8; 32],
            timestamp: now,
            signature: vec![0u8; 64],
            max_age_secs: 24 * 3600,
            cursor: None,
            wallet_claim: None,
            revision: 0,
        };
        let (resp, _, _) = build_response(&storage, wallet, &req, 200, now, u64::MAX);
        assert_eq!(resp.envelopes.len(), 1);
        assert_eq!(resp.envelopes[0].as_slice(), new_id.as_slice());
    }

    // --- l2-node 0.151.0: rolling budget replaces the lifetime counter ---

    /// The pre-0.151.0 lifetime counter is gone: a peer that spent the
    /// default 5,000-unit burst is refused, keeps its debt however many
    /// other peers arrive (no FIFO eviction), and is served again once the
    /// budget refilled (2,500/h) — no responder restart needed.
    #[test]
    fn dm_budget_refills_and_never_evicts_a_peer_in_debt() {
        use crate::network::budget::{Gcra, Refusal};
        use std::time::{Duration, Instant};
        let limits = std::sync::Arc::new(DmResponderLimits::new(1_000));
        let gcra = Gcra::new(5_000, 2_500);
        let now = Instant::now();
        let spent = libp2p::PeerId::random();
        limits.charge(spent, 5_000, &gcra, now);
        for _ in 1..1_000 {
            limits.charge(libp2p::PeerId::random(), 1, &gcra, now);
        }
        assert!(matches!(
            limits.try_acquire(libp2p::PeerId::random(), &libp2p::PeerId::random(), SERVER_MAX_CONCURRENT_PER_PEER, &gcra, now),
            Err(Refusal::MapFull)
        ));
        assert!(matches!(
            limits.try_acquire(spent, &spent, SERVER_MAX_CONCURRENT_PER_PEER, &gcra, now),
            Err(Refusal::OverBudget)
        ));
        // One unit refills in 1.44 s: the prune drops the one-unit peers only.
        let later = now + Duration::from_secs(2);
        assert_eq!(limits.prune(later), 999);
        assert_eq!(limits.budget_len(), 1);
        let refilled = now + Duration::from_secs(3_600);
        assert!(limits.try_acquire(spent, &spent, SERVER_MAX_CONCURRENT_PER_PEER, &gcra, refilled).is_ok());
    }
}

#[cfg(test)]
mod edit_delete_ride_along_tests {
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{DeletePayload, DirectMessagePayload, MessageType};
    use crate::storage::rocks::Storage;
    use tempfile::TempDir;

    fn put_dm(storage: &Storage, wallet: &str, peer: &str, conv: [u8; 32], msg_id: [u8; 32], ts: u64) {
        let payload = DirectMessagePayload {
            recipient: peer.to_string(),
            conversation_id: conv,
            content: vec![1, 2, 3],
            nonce: [0u8; 24],
            key_epoch: 1,
            reply_to: None,
            attachments: vec![],
        };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessage,
            msg_id,
            author: wallet.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::DM_MESSAGES, &schema::encode_dm_msg_key(&conv, ts, &msg_id), &[])
            .unwrap();
        storage
            .store_message(&msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
        storage
            .put_cf(
                schema::cf::DM_CONVERSATIONS,
                &schema::encode_dm_conversation_key(wallet.as_bytes(), ts, &conv),
                peer.as_bytes(),
            )
            .unwrap();
    }

    fn put_dm_delete(
        storage: &Storage,
        wallet: &str,
        conv: [u8; 32],
        target_id: [u8; 32],
        msg_id: [u8; 32],
        ts: u64,
    ) {
        let payload = DeletePayload { target_id, channel_id: None };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DirectMessageDelete,
            msg_id,
            author: wallet.to_string(),
            timestamp: ts,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage
            .put_cf(schema::cf::DM_EDIT_DELETE_MSGS, &schema::encode_dm_msg_key(&conv, ts, &msg_id), &[])
            .unwrap();
        storage
            .store_message(&msg_id, &rmp_serde::to_vec_named(&env).unwrap())
            .unwrap();
    }

    fn contains_type(envelopes: &[Vec<u8>], msg_type: MessageType) -> bool {
        envelopes.iter().any(|e| {
            rmp_serde::from_slice::<Envelope>(e)
                .map(|env| env.msg_type == msg_type)
                .unwrap_or(false)
        })
    }

    /// Regression for audit final pre-mainnet W6: without the ride-along, a
    /// fresh node backfilling via dm-sync would receive the wallet's 3
    /// original DMs but never learn one was deleted. Also proves the
    /// ordering constraint: the ride-along must NOT appear on a non-final
    /// (`has_more = true`) page, since the target might not have been
    /// delivered yet.
    #[test]
    fn ride_along_only_appears_on_the_final_page() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let wallet = "klv1wallet";
        let conv = [0xDDu8; 32];
        let base_ts = 1_700_000_000_000u64;
        let mut deleted_target = [0u8; 32];
        for n in 0u8..3 {
            let mut mid = [0u8; 32];
            mid[0] = n + 1;
            if n == 0 {
                deleted_target = mid;
            }
            put_dm(&storage, wallet, "klv1peer", conv, mid, base_ts + n as u64);
        }
        put_dm_delete(&storage, wallet, conv, deleted_target, [9u8; 32], base_ts + 100);

        // Page 1: cap=2 DMs (< 3 total) → has_more → no ride-along.
        let req1 = DmSyncRequest {
            wallet: wallet.into(),
            requester_pubkey: vec![0u8; 32],
            timestamp: base_ts,
            signature: vec![0u8; 64],
            max_age_secs: u64::MAX,
            cursor: None,
            wallet_claim: None,
            revision: 0,
        };
        let (resp1, _, _) = build_response(&storage, wallet, &req1, 2, base_ts + 1000, u64::MAX);
        assert!(resp1.has_more, "page 1 should be capped (2 of 3 DMs)");
        assert!(
            !contains_type(&resp1.envelopes, MessageType::DirectMessageDelete),
            "delete must not ride along on a non-final page"
        );

        // Page 2 (final): remaining DM, under cap → ride-along present.
        let req2 = DmSyncRequest {
            wallet: wallet.into(),
            requester_pubkey: vec![0u8; 32],
            timestamp: base_ts,
            signature: vec![0u8; 64],
            max_age_secs: u64::MAX,
            cursor: resp1.next_cursor,
            wallet_claim: None,
            revision: 0,
        };
        let (resp2, _, _) = build_response(&storage, wallet, &req2, 2, base_ts + 1000, u64::MAX);
        assert!(!resp2.has_more, "page 2 should be the final page");
        assert!(
            contains_type(&resp2.envelopes, MessageType::DirectMessageDelete),
            "delete must ride along on the final page"
        );
    }

    /// D4 + G5 (l2-node 0.151.0): an erased DM is never served, nor is a
    /// delete of it; its DeletionRequest (indexed into DM_EDIT_DELETE_MSGS
    /// under the DM's own conversation) rides along on the last page.
    #[test]
    fn erased_dm_is_withheld_and_its_request_rides_along() {
        use crate::messages::types::{DeletionRequestPayload, DeletionType};
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let wallet = "klv1wallet";
        let conv = [0xDEu8; 32];
        let base_ts = 1_700_000_000_000u64;
        let (keep, erase, del, req_id) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        put_dm(&storage, wallet, "klv1peer", conv, keep, base_ts);
        put_dm(&storage, wallet, "klv1peer", conv, erase, base_ts + 1);
        put_dm_delete(&storage, wallet, conv, erase, del, base_ts + 2);
        let payload = DeletionRequestPayload { delete_type: DeletionType::SingleMessage, target_id: Some(erase) };
        let env = Envelope {
            version: crate::messages::envelope::PROTOCOL_VERSION,
            msg_type: MessageType::DeletionRequest,
            msg_id: req_id,
            author: wallet.to_string(),
            timestamp: base_ts + 3,
            lamport_ts: 0,
            payload: rmp_serde::to_vec_named(&payload).unwrap(),
            signature: vec![],
            relay_path: vec![],
        };
        storage.store_message(&req_id, &rmp_serde::to_vec_named(&env).unwrap()).unwrap();
        storage.put_verified_deletion_request(&erase, &req_id, wallet, base_ts + 3).unwrap();
        assert!(storage.index_deletion_request(&erase, &req_id, base_ts + 3).unwrap());

        let req = DmSyncRequest {
            wallet: wallet.into(),
            requester_pubkey: vec![0u8; 32],
            timestamp: base_ts,
            signature: vec![0u8; 64],
            max_age_secs: u64::MAX,
            cursor: None,
            wallet_claim: None,
            revision: 0,
        };
        let (resp, _, work) = build_response(&storage, wallet, &req, 10, base_ts + 1000, u64::MAX);
        let ids: Vec<[u8; 32]> = resp
            .envelopes
            .iter()
            .map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_id)
            .collect();
        assert_eq!(ids, vec![keep, req_id]);
        assert!(work > 1, "storage work is metered: {work}");
        assert!(is_dm_type(MessageType::DeletionRequest as u8));
    }
}
