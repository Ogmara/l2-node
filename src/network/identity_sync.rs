//! Identity-sync — lazy, per-wallet backfill of a user's signed identity
//! envelopes (P-1, l2-node 0.50.0+).
//!
//! When a user connects to a node that was offline while their delegation /
//! profile / follows were gossiped, that state is missing there. Identity-sync
//! closes the gap **lazily and per-wallet**: the first time a wallet is seen on
//! a node (login / node-switch, or a device the node can't resolve), the node
//! pulls that ONE wallet's identity bundle from peers — it is NOT a 1:1
//! transfer between all nodes. A node does work proportional to the wallets
//! that actually use it.
//!
//! This mirrors the channel-reconcile protocol (`network/reconcile.rs`): a
//! libp2p request/response with cursor paging, capped + rate-limited responses,
//! and — crucially — the responder serves the **original signed envelopes**,
//! never derived rows. The receiver re-runs every envelope through
//! `router::process_synced_message`, so a relaying peer is never trusted.
//!
//! Only the five PUBLIC identity message types are ever indexed/served
//! (DeviceDelegation, DeviceRevocation, ProfileUpdate, Follow, Unfollow); DMs,
//! private-channel content, and encrypted settings are never in this index, so
//! identity-sync cannot leak private data.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::messages::types::MessageType;
use crate::storage::rocks::Storage;
use crate::storage::schema;

/// libp2p CBOR request/response codec for identity-sync.
pub type IdentitySyncCodec =
    libp2p::request_response::cbor::Behaviour<IdentitySyncRequest, IdentitySyncResponse>;

/// Protocol string. Versioned independently of channel-reconcile.
pub fn protocol_string(network_id: &str) -> String {
    format!("/ogmara/{}/identity-sync/1.0.0", network_id)
}

// --- Tuning (bounded by design; a wallet's identity bundle is small) ---

/// Max envelopes a responder returns per page.
pub const MAX_ENVELOPES_PER_RESPONSE: usize = 200;
/// Max concurrent inbound identity-sync requests served to one peer.
pub const SERVER_MAX_CONCURRENT_PER_PEER: usize = 4;
/// Cumulative envelopes one peer may pull about one wallet per process
/// lifetime — stops cursor-paging abuse.
pub const TOTAL_ENVELOPES_CAP: u64 = 4_000;
/// How many peers an outbound pull races (first non-empty wins).
pub const FANOUT: usize = 3;

// --- Scope bitflags (which parts of the identity bundle to pull) ---

pub const SCOPE_DELEGATIONS: u8 = 1; // DeviceDelegation (0x31) + DeviceRevocation (0x32)
pub const SCOPE_PROFILE: u8 = 2; // ProfileUpdate (0x30)
pub const SCOPE_FOLLOWS: u8 = 4; // Follow (0x34) + Unfollow (0x35)
pub const SCOPE_ALL: u8 = SCOPE_DELEGATIONS | SCOPE_PROFILE | SCOPE_FOLLOWS;

/// Map an identity message-type byte to its scope bit. Returns 0 for any type
/// that is not an indexed identity type (so it is never served).
fn scope_of(msg_type: u8) -> u8 {
    match msg_type {
        t if t == MessageType::DeviceDelegation as u8 => SCOPE_DELEGATIONS,
        t if t == MessageType::DeviceRevocation as u8 => SCOPE_DELEGATIONS,
        t if t == MessageType::ProfileUpdate as u8 => SCOPE_PROFILE,
        t if t == MessageType::Follow as u8 => SCOPE_FOLLOWS,
        t if t == MessageType::Unfollow as u8 => SCOPE_FOLLOWS,
        _ => 0,
    }
}

/// Returns true iff `msg_type` is an identity type the caller asked for.
pub fn type_in_scopes(msg_type: u8, scopes: u8) -> bool {
    let s = scope_of(msg_type);
    s != 0 && (s & scopes) != 0
}

/// Max characters in a valid Ogmara address (bech32 `klv1…`/`ogd1…`).
const MAX_SUBJECT_LEN: usize = 70;

/// Cheap validation that `subject` is a plausible Ogmara address before it is
/// used as a RocksDB key prefix or a rate-limiter map key. Rejects the
/// attacker-controlled, otherwise-unbounded `request.wallet` string (a peer
/// could otherwise send many distinct multi-KB strings to grow the responder's
/// per-(peer,wallet) map). bech32 is ASCII-alphanumeric and `0xFF` (our key
/// separator) can never appear in it.
pub fn is_plausible_subject(subject: &str) -> bool {
    (subject.starts_with("klv1") || subject.starts_with("ogd1"))
        && subject.len() <= MAX_SUBJECT_LEN
        && subject.bytes().all(|b| b.is_ascii_alphanumeric())
}

// --- Wire types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySyncRequest {
    /// The subject wallet (klv1…) whose identity bundle is requested.
    pub wallet: String,
    /// Bitflags of scopes to serve (`SCOPE_*`).
    pub scopes: u8,
    /// Opaque paging cursor (continue after this key).
    pub cursor: Option<IdentityCursor>,
    /// RESERVED — future "overlap digest" steady-state handshake. Always empty.
    #[serde(default)]
    pub overlap_digest: Vec<u8>,
    /// RESERVED — multi-round handshake. Always 0.
    #[serde(default)]
    pub round: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySyncResponse {
    pub wallet: String,
    /// Original signed envelopes (MessagePack bytes). Receiver re-validates.
    pub envelopes: Vec<Vec<u8>>,
    pub has_more: bool,
    pub next_cursor: Option<IdentityCursor>,
    /// True when the responder declined to serve (rate-limited / over cap).
    pub server_capped: bool,
    /// RESERVED — future completeness proof. Always None.
    #[serde(default)]
    pub completeness_root: Option<[u8; 32]>,
}

/// Cursor over the `(msg_type, timestamp, msg_id)` tail of an
/// `IDENTITY_ENVELOPES` key (the wallet prefix is implied by `request.wallet`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCursor {
    pub after_msg_type: u8,
    pub after_timestamp: u64,
    pub after_msg_id: [u8; 32],
}

/// A `server_capped` response carrying nothing — sent when the responder is
/// over its rate limit for this (peer, wallet).
pub fn capped_response(request: &IdentitySyncRequest) -> IdentitySyncResponse {
    IdentitySyncResponse {
        wallet: request.wallet.clone(),
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: true,
        completeness_root: None,
    }
}

/// Build a response: scan the wallet's `IDENTITY_ENVELOPES` prefix, filter by
/// requested scopes, page from the cursor, and re-serve the original signed
/// envelopes from `MESSAGES`. Caps at `max_envelopes`.
pub fn build_response(
    storage: &Storage,
    request: &IdentitySyncRequest,
    max_envelopes: usize,
) -> IdentitySyncResponse {
    let empty = || IdentitySyncResponse {
        wallet: request.wallet.clone(),
        envelopes: Vec::new(),
        has_more: false,
        next_cursor: None,
        server_capped: false,
        completeness_root: None,
    };

    // Self-defending: never use an unvalidated subject as a DB prefix, even if
    // a future caller forgets the handler-side check.
    if !is_plausible_subject(&request.wallet) {
        return empty();
    }

    // A device-resolve-miss pull arrives keyed by the DEVICE address
    // (`ogd1…`): the requester saw the device sign but can't map it. Resolve
    // it to the owning wallet HERE (we have the delegation) and serve that
    // wallet's bundle — the delegation in it lets the requester resolve the
    // device thereafter. A `klv1…` subject is used directly.
    let subject = if request.wallet.starts_with("ogd1") {
        match storage.resolve_wallet(&request.wallet) {
            Ok(Some(w)) => w,
            _ => return empty(),
        }
    } else {
        request.wallet.clone()
    };

    let prefix = schema::identity_envelope_prefix(&subject);
    // Probe one extra row to detect `has_more` precisely.
    let probe_limit = max_envelopes.saturating_add(1);

    let rows = if let Some(c) = request.cursor.as_ref() {
        let start_key = schema::encode_identity_envelope_key(
            &subject,
            c.after_msg_type,
            c.after_timestamp,
            &c.after_msg_id,
        );
        storage.prefix_iter_cf_after(schema::cf::IDENTITY_ENVELOPES, &start_key, &prefix, probe_limit)
    } else {
        storage.prefix_iter_cf(schema::cf::IDENTITY_ENVELOPES, &prefix, probe_limit)
    };

    let rows = match rows {
        Ok(r) => r,
        Err(_) => {
            // Storage fault → serve nothing (the requester races other peers).
            return IdentitySyncResponse {
                wallet: request.wallet.clone(),
                envelopes: Vec::new(),
                has_more: false,
                next_cursor: None,
                server_capped: false,
                completeness_root: None,
            };
        }
    };

    let tail_at = prefix.len(); // key tail = msg_type(1) ++ ts(8) ++ msg_id(32)
    // The storage layer returned at most `probe_limit` rows; if it returned
    // exactly that many, there may be more beyond this batch.
    let truncated = rows.len() >= probe_limit;
    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    let mut next_cursor: Option<IdentityCursor> = None;
    let mut more_in_batch = false;

    for (key, _) in rows {
        // Parse the fixed-width tail. Our index keys are always exactly this
        // width, so these guards are defensive (never hit for our own rows).
        if key.len() < tail_at + 1 + 8 + 32 {
            continue;
        }
        let msg_type = key[tail_at];
        let ts = u64::from_be_bytes(match key[tail_at + 1..tail_at + 9].try_into() {
            Ok(b) => b,
            Err(_) => continue,
        });
        let mut msg_id = [0u8; 32];
        msg_id.copy_from_slice(&key[tail_at + 9..tail_at + 41]);

        // Page is full — stop BEFORE consuming this row so the next page
        // resumes at it (cursor stays at the previous row).
        if envelopes.len() >= max_envelopes {
            more_in_batch = true;
            break;
        }

        // Code Audit C-1: advance the cursor over EVERY well-formed row,
        // in-scope or not. The index sorts by msg_type first, so a subset
        // `scopes` request would otherwise fill the probe window with
        // out-of-scope rows and strand the in-scope rows beyond it (the scope
        // filter is NOT monotonic with the key sort, unlike reconcile's
        // timestamp filter). Advancing past skipped rows keeps paging correct.
        next_cursor = Some(IdentityCursor {
            after_msg_type: msg_type,
            after_timestamp: ts,
            after_msg_id: msg_id,
        });

        // Scope filter — never serve a type the caller didn't ask for.
        if !type_in_scopes(msg_type, request.scopes) {
            continue;
        }
        // Re-serve the ORIGINAL signed envelope; receiver re-validates it.
        // A missing MESSAGES entry (shouldn't happen) just advances the cursor.
        if let Ok(Some(raw)) = storage.get_cf(schema::cf::MESSAGES, &msg_id) {
            envelopes.push(raw);
        }
    }

    // More pages exist if we stopped at the page cap OR the storage batch was
    // truncated (there are rows we didn't fetch).
    let has_more = more_in_batch || truncated;
    if !has_more {
        next_cursor = None;
    }

    IdentitySyncResponse {
        wallet: request.wallet.clone(),
        envelopes,
        has_more,
        next_cursor,
        server_capped: false,
        completeness_root: None,
    }
}

// --- Responder rate limiting (per (peer, wallet)) ---

/// Bounds how much one peer can pull about one wallet, mirroring
/// `reconcile::ResponderLimits` but keyed by `(PeerId, wallet)`. Prevents a
/// peer from cursor-paging a wallet's bundle unboundedly or fanning a flood of
/// concurrent identity-sync requests.
#[derive(Debug, Default)]
pub struct IdentityResponderLimits {
    inner: Mutex<IdentityLimitsInner>,
}

#[derive(Debug, Default)]
struct IdentityLimitsInner {
    /// Active in-flight requests per peer.
    per_peer: HashMap<libp2p::PeerId, usize>,
    /// Cumulative envelopes served per (peer, wallet) this process lifetime.
    served: HashMap<(libp2p::PeerId, String), u64>,
}

impl IdentityResponderLimits {
    /// Try to admit one inbound request. Returns a guard that releases the
    /// per-peer slot on drop, or `None` if over a cap (caller sends a
    /// `capped_response`).
    pub fn try_acquire(
        self: &Arc<Self>,
        peer: libp2p::PeerId,
        wallet: &str,
        max_concurrent_per_peer: usize,
        total_envelopes_cap: u64,
    ) -> Option<IdentityResponderGuard> {
        /// Soft ceiling on distinct `(peer, wallet)` cumulative-served entries.
        /// On overflow the whole map is cleared — it's an abuse limiter, not a
        /// security invariant, so the worst case is a few peers re-earning
        /// their cap. Bounds the otherwise process-lifetime growth.
        const MAX_TRACKED: usize = 100_000;
        let mut inner = self.inner.lock().ok()?;
        if inner.served.len() >= MAX_TRACKED {
            inner.served.clear();
        }
        let in_flight = inner.per_peer.get(&peer).copied().unwrap_or(0);
        if in_flight >= max_concurrent_per_peer {
            return None;
        }
        let served = inner
            .served
            .get(&(peer, wallet.to_string()))
            .copied()
            .unwrap_or(0);
        if served >= total_envelopes_cap {
            return None;
        }
        inner.per_peer.insert(peer, in_flight + 1);
        Some(IdentityResponderGuard {
            limits: Arc::clone(self),
            peer,
        })
    }

    /// Record envelopes served toward the per-(peer, wallet) cumulative cap.
    pub fn add_served(&self, peer: libp2p::PeerId, wallet: &str, count: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            *inner.served.entry((peer, wallet.to_string())).or_insert(0) += count;
        }
    }
}

/// RAII guard releasing a peer's in-flight slot on drop.
pub struct IdentityResponderGuard {
    limits: Arc<IdentityResponderLimits>,
    peer: libp2p::PeerId,
}

impl Drop for IdentityResponderGuard {
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
