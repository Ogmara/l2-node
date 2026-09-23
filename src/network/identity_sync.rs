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

// --- Broadened trigger: fire identity-sync on first OBSERVING an
// incomplete-looking author via live gossip, not only when that wallet
// personally authenticates to this node (design doc: "Closing the
// Identity-Sync Coverage Gap"). ---

/// Returns true iff a message of this type, when its author turns out to
/// have an incomplete-looking local identity record, is worth triggering a
/// backfill pull over. Deliberately an ALLOW-list (not a deny-list): a new
/// message type added later is excluded by default rather than silently
/// starting to trigger checks on every gossip message, which matters as the
/// mesh grows toward mainnet's larger peer/message volume.
///
/// Any of the five identity types themselves (`scope_of != 0`) qualify —
/// a ProfileUpdate/Follow/Unfollow/DeviceDelegation/DeviceRevocation from a
/// wallet with no local record is itself the strongest possible signal.
/// Beyond those, only types whose AUTHOR is shown to a viewer somewhere
/// (chat, news, reactions, the sender half of a DM) qualify — types that
/// carry no author-facing display surface gain nothing from a pull.
pub fn triggers_identity_check(msg_type: u8) -> bool {
    if scope_of(msg_type) != 0 {
        return true;
    }
    matches!(
        msg_type,
        t if t == MessageType::ChatMessage as u8
            || t == MessageType::NewsPost as u8
            || t == MessageType::NewsComment as u8
            || t == MessageType::ChatReaction as u8
            || t == MessageType::DirectMessage as u8
    )
}

/// Returns true iff `users_row` (a `USERS[wallet]` value, i.e. serialized
/// user-record JSON) shows no evidence this node has ever actually applied a
/// `ProfileUpdate` for the wallet — as opposed to a wallet that DID apply one
/// and legitimately set no `display_name`.
///
/// `profile_updated_at` is written into the record ONLY by the ProfileUpdate
/// apply path (`MessageRouter::process_message_inner`,
/// `MessageType::ProfileUpdate` arm) — never by Follow, DeviceDelegation, or
/// chain-scan registration, which can all create a bare `USERS` row with no
/// such key. Its presence is therefore an unambiguous, already-persisted
/// signal: present (any value) = "a ProfileUpdate landed here, whatever it
/// said" = complete, never re-trigger for this reason alone; absent = "no
/// ProfileUpdate has ever landed here" = incomplete, worth a pull. This is
/// the distinction that keeps a wallet who genuinely has no display name
/// from being re-pulled forever.
pub fn profile_looks_incomplete_json(users_row: &[u8]) -> bool {
    match serde_json::from_slice::<serde_json::Value>(users_row) {
        Ok(serde_json::Value::Object(map)) => !map.contains_key("profile_updated_at"),
        // Unparseable/non-object row — treat as incomplete rather than
        // silently skipping it; a corrupt row is exactly the kind of gap
        // this mechanism exists to self-heal.
        _ => true,
    }
}

/// Storage-backed wrapper around [`profile_looks_incomplete_json`]: a wallet
/// with no `USERS` row at all is incomplete by definition (the darkworld
/// case in the design doc — `get_user`'s `Ok(None)` branch).
pub fn identity_looks_incomplete(storage: &Storage, wallet: &str) -> bool {
    match storage.get_cf(schema::cf::USERS, wallet.as_bytes()) {
        Ok(Some(bytes)) => profile_looks_incomplete_json(&bytes),
        Ok(None) => true,
        // Storage error: don't treat a transient read failure as a green
        // light to hammer peers — fail toward "looks complete" (no pull)
        // here; the periodic sweep (§2) will reconsider this wallet again
        // on its next tick regardless.
        Err(e) => {
            tracing::warn!(
                wallet = %wallet,
                error = %e,
                "identity_looks_incomplete: USERS read failed, treating as complete"
            );
            false
        }
    }
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

/// Soft ceiling on distinct `(peer, wallet)` cumulative-served entries.
/// Previously cleared WHOLESALE on overflow — a Sybil cycling fresh PeerIds
/// could reset everyone's cumulative "served" counters, defeating
/// `total_envelopes_cap` (audit W5, bundled fix — identical bug shape to
/// `dm_sync::DmResponderLimits`). Now the single oldest entry is evicted per
/// overflow insert instead.
const MAX_TRACKED_SERVED: usize = 100_000;

#[derive(Debug, Default)]
struct IdentityLimitsInner {
    /// Active in-flight requests per peer.
    per_peer: HashMap<libp2p::PeerId, usize>,
    /// Cumulative envelopes served per (peer, wallet) this process lifetime.
    served: HashMap<(libp2p::PeerId, String), u64>,
    /// Insertion order of `served` keys, oldest-first (audit W5).
    served_order: std::collections::VecDeque<(libp2p::PeerId, String)>,
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
        let mut inner = self.inner.lock().ok()?;
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
            let key = (peer, wallet.to_string());
            let is_new = !inner.served.contains_key(&key);
            if is_new {
                if inner.served.len() >= MAX_TRACKED_SERVED {
                    if let Some(oldest) = inner.served_order.pop_front() {
                        inner.served.remove(&oldest);
                    }
                }
                inner.served_order.push_back(key.clone());
            }
            *inner.served.entry(key).or_insert(0) += count;
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

#[cfg(test)]
mod coverage_gap_tests {
    //! Design doc "Closing the Identity-Sync Coverage Gap" — the broadened
    //! observed-author trigger's core distinguishing logic
    //! (`triggers_identity_check`/`profile_looks_incomplete_json`/
    //! `identity_looks_incomplete`). `network::mod`'s
    //! `identity_staleness_sweep_tests` module covers the periodic sweep's
    //! pure planning logic (`plan_identity_staleness_sweep`) the same way.
    //! Neither module constructs a live `NetworkService`/`Swarm`, so there is
    //! currently no end-to-end "actually converges without a restart" test
    //! exercising the real trigger wiring in `handle_gossip_message` — a gap
    //! worth closing with an integration-style test if this area regresses
    //! again, rather than a claim this module previously made about a test
    //! that does not exist.
    use super::*;

    #[test]
    fn triggers_identity_check_true_for_all_five_identity_types() {
        for t in [
            MessageType::DeviceDelegation,
            MessageType::DeviceRevocation,
            MessageType::ProfileUpdate,
            MessageType::Follow,
            MessageType::Unfollow,
        ] {
            assert!(triggers_identity_check(t as u8), "{:?} should trigger", t);
        }
    }

    #[test]
    fn triggers_identity_check_true_for_author_facing_content_types() {
        for t in [
            MessageType::ChatMessage,
            MessageType::NewsPost,
            MessageType::NewsComment,
            MessageType::ChatReaction,
            MessageType::DirectMessage,
        ] {
            assert!(triggers_identity_check(t as u8), "{:?} should trigger", t);
        }
    }

    #[test]
    fn triggers_identity_check_false_for_excluded_types() {
        // Network-internal / no author-facing display surface — an
        // allow-list miss here must stay a no-trigger, not a crash.
        for t in [
            MessageType::ChatEdit,
            MessageType::ChatDelete,
            MessageType::ChannelJoin,
            MessageType::ChannelPinMessage,
        ] {
            assert!(!triggers_identity_check(t as u8), "{:?} should NOT trigger", t);
        }
    }

    #[test]
    fn profile_looks_incomplete_true_for_row_missing_profile_updated_at() {
        // A USERS row that exists only from a Follow-edge or chain-scan
        // side effect — never had a ProfileUpdate applied to it.
        let row = serde_json::json!({
            "address": "klv1example",
            "public_key": "",
            "registered_at": 0,
        });
        assert!(profile_looks_incomplete_json(
            &serde_json::to_vec(&row).unwrap()
        ));
    }

    #[test]
    fn profile_looks_incomplete_false_for_row_with_profile_updated_at_and_no_display_name() {
        // The critical negative case: a wallet that DID apply a
        // ProfileUpdate and legitimately set no display_name must never be
        // treated as "incomplete" — otherwise it would be re-pulled
        // forever, exactly the failure mode the requirements warn against.
        let row = serde_json::json!({
            "address": "klv1example",
            "public_key": "",
            "registered_at": 0,
            "profile_updated_at": 1_700_000_000_000u64,
        });
        assert!(!profile_looks_incomplete_json(
            &serde_json::to_vec(&row).unwrap()
        ));
    }

    #[test]
    fn profile_looks_incomplete_false_for_row_with_display_name_and_timestamp() {
        let row = serde_json::json!({
            "address": "klv1example",
            "display_name": "Test0r",
            "profile_updated_at": 1_700_000_000_000u64,
        });
        assert!(!profile_looks_incomplete_json(
            &serde_json::to_vec(&row).unwrap()
        ));
    }

    #[test]
    fn profile_looks_incomplete_true_for_corrupt_row() {
        assert!(profile_looks_incomplete_json(b"not valid json"));
        assert!(profile_looks_incomplete_json(b"[1,2,3]")); // valid JSON, not an object
    }

    #[test]
    fn identity_looks_incomplete_true_when_no_users_row_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        assert!(identity_looks_incomplete(&storage, "klv1nobodyhome"));
    }

    #[test]
    fn identity_looks_incomplete_false_once_profile_updated_at_is_stored() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let row = serde_json::json!({
            "address": "klv1example",
            "profile_updated_at": 1_700_000_000_000u64,
        });
        storage
            .put_cf(
                schema::cf::USERS,
                b"klv1example",
                &serde_json::to_vec(&row).unwrap(),
            )
            .unwrap();
        assert!(!identity_looks_incomplete(&storage, "klv1example"));
    }
}
