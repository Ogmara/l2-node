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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

/// Max envelopes a responder returns per page.
pub const MAX_ENVELOPES_PER_RESPONSE: usize = 200;
/// Hard ceiling on cumulative envelopes one peer may pull per process lifetime.
pub const TOTAL_ENVELOPES_CAP: u64 = 5_000;
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

/// True iff `msg_type` is the DirectMessage type (`0x05`) — the only type DM-sync
/// serves or accepts. The receiver's type-smuggling defense so a responder can't
/// inject another type through this path.
pub fn is_dm_type(msg_type: u8) -> bool {
    use crate::messages::types::MessageType;
    matches!(
        MessageType::from_u8(msg_type),
        Some(MessageType::DirectMessage)
    )
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
pub fn build_response(
    storage: &Storage,
    wallet: &str,
    request: &DmSyncRequest,
    max_envelopes: usize,
    now_ms: u64,
    window_max_age_secs: u64,
) -> (DmSyncResponse, bool) {
    let empty = DmSyncResponse {
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: false,
        auth_failed: false,
    };

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
        Err(_) => return (empty, true),
    };
    let mut conv_ids: Vec<[u8; 32]> = Vec::with_capacity(conv_rows.len());
    for (key, _) in &conv_rows {
        if key.len() < prefix.len() + 8 + 32 {
            continue; // malformed
        }
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&key[key.len() - 32..]);
        conv_ids.push(cid);
    }
    conv_ids.sort_unstable();
    conv_ids.dedup();
    let scanned_all = conv_ids.len() <= MAX_CONVERSATIONS;
    conv_ids.truncate(MAX_CONVERSATIONS);

    if conv_ids.is_empty() {
        return (empty, scanned_all);
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

    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    let mut next_cursor: Option<DmCursor> = None;
    let mut has_more = false;

    for (ci, cid) in conv_ids.iter().enumerate().skip(start_idx) {
        if envelopes.len() >= max_envelopes {
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
        let budget = max_envelopes - envelopes.len();
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
            // Advance the cursor over EVERY in-window row examined (even if its
            // MESSAGES entry is missing) so a sparse page can't strand rows.
            next_cursor = Some(DmCursor {
                conversation_id: *cid,
                after_timestamp: ts,
                after_msg_id: msg_id,
            });
            if let Ok(Some(raw)) = storage.get_cf(schema::cf::MESSAGES, &msg_id) {
                envelopes.push(raw);
            }
        }
        if conv_has_more {
            has_more = true;
            break; // resume THIS conversation on the next page (cursor points here)
        }
        // conversation exhausted → fall through to the next conversation
    }

    if !has_more {
        next_cursor = None;
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
    )
}

// --- Responder rate limiting (per peer) ---

/// Bounds how much one peer can pull, mirroring `news_sync::NewsResponderLimits`.
#[derive(Debug, Default)]
pub struct DmResponderLimits {
    inner: Mutex<DmLimitsInner>,
}

/// Soft ceiling on distinct per-peer cumulative-served entries. Previously
/// cleared WHOLESALE on overflow — a Sybil cycling fresh PeerIds could reset
/// everyone's cumulative "served" counter, defeating `TOTAL_ENVELOPES_CAP`
/// (audit W5, bundled fix). Now the single oldest entry is evicted per
/// overflow insert instead, so a new identity can only ever displace ONE
/// other peer's counter, not all of them.
pub(crate) const MAX_TRACKED_SERVED_PEERS: usize = 100_000;

#[derive(Debug, Default)]
struct DmLimitsInner {
    per_peer: HashMap<libp2p::PeerId, usize>,
    served: HashMap<libp2p::PeerId, u64>,
    /// Insertion order of `served` keys, oldest-first — lets `add_served`
    /// evict a single oldest entry on overflow (audit W5).
    served_order: std::collections::VecDeque<libp2p::PeerId>,
}

impl DmResponderLimits {
    /// Admit one inbound request, or `None` if over a cap (→ `capped_response`).
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: libp2p::PeerId,
        max_concurrent_per_peer: usize,
        total_envelopes_cap: u64,
    ) -> Option<DmResponderGuard> {
        let mut inner = self.inner.lock().ok()?;
        let in_flight = inner.per_peer.get(&peer).copied().unwrap_or(0);
        if in_flight >= max_concurrent_per_peer {
            return None;
        }
        if inner.served.get(&peer).copied().unwrap_or(0) >= total_envelopes_cap {
            return None;
        }
        inner.per_peer.insert(peer, in_flight + 1);
        Some(DmResponderGuard {
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
pub struct DmResponderGuard {
    limits: Arc<DmResponderLimits>,
    peer: libp2p::PeerId,
}

impl Drop for DmResponderGuard {
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
            };
            let (resp, scanned_all) = build_response(&storage, wallet, &req, 2, now, u64::MAX);
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
        };
        let (resp, _) = build_response(&storage, wallet, &req, 200, now, u64::MAX);
        assert_eq!(resp.envelopes.len(), 1);
        assert_eq!(resp.envelopes[0].as_slice(), new_id.as_slice());
    }

    // --- W5 bundled fix: DmResponderLimits eviction, not clear-all ---

    #[test]
    fn add_served_evicts_oldest_not_everyone() {
        // `PeerId::random()` (no real keypair derivation needed — this test
        // only exercises the eviction bookkeeping, not signature validity)
        // keeps 100k inserts fast enough for a unit test.
        let limits = DmResponderLimits::default();
        let first_peer = libp2p::PeerId::random();
        limits.add_served(first_peer, 1);
        for _ in 1..MAX_TRACKED_SERVED_PEERS - 1 {
            limits.add_served(libp2p::PeerId::random(), 1);
        }
        let last_peer = libp2p::PeerId::random();
        limits.add_served(last_peer, 1);

        // One more, over capacity — must evict the FIRST-inserted peer only,
        // not clear the whole map (audit W5).
        let overflow_peer = libp2p::PeerId::random();
        limits.add_served(overflow_peer, 1);

        let inner = limits.inner.lock().unwrap();
        assert_eq!(inner.served.len(), MAX_TRACKED_SERVED_PEERS);
        assert!(
            !inner.served.contains_key(&first_peer),
            "oldest peer's counter must be evicted"
        );
        assert!(
            inner.served.contains_key(&last_peer),
            "a recently-inserted peer's counter must survive"
        );
        assert!(
            inner.served.contains_key(&overflow_peer),
            "the new insert itself must be present"
        );
    }
}
