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
//! Only the seven PUBLIC identity message types are ever served
//! (DeviceDelegation, DeviceRevocation, ProfileUpdate, Follow, Unfollow, and
//! since l2-node 0.151.0 the encryption-key directory entries DeviceEncBinding /
//! DeviceEncRevoke — the "5+2 list"); DMs, private-channel content, and
//! encrypted settings are never in this index, so identity-sync cannot leak
//! private data.
//!
//! Old-peer compatibility of the 0.151.0 `SCOPE_ENC_KEYS` bit: a 0.150 (or
//! older) responder maps 0x36/0x37 to scope 0 and so never serves them, whatever
//! the request asks for; an old requester never sets bit 8, and a new responder
//! filters by the requested scopes, so it never sends enc-key rows to it.

use serde::{Deserialize, Serialize};

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
/// How many peers an outbound pull races (first non-empty wins).
pub const FANOUT: usize = 3;

// --- Scope bitflags (which parts of the identity bundle to pull) ---

pub const SCOPE_DELEGATIONS: u8 = 1; // DeviceDelegation (0x31) + DeviceRevocation (0x32)
pub const SCOPE_PROFILE: u8 = 2; // ProfileUpdate (0x30)
pub const SCOPE_FOLLOWS: u8 = 4; // Follow (0x34) + Unfollow (0x35)
/// DeviceEncBinding (0x36) + DeviceEncRevoke (0x37) — the wallet's public
/// encryption-key directory (l2-node 0.151.0). Protocol §2.4 calls these keys
/// "cheaply re-fetchable"; this scope is that fetch path.
pub const SCOPE_ENC_KEYS: u8 = 8;
pub const SCOPE_ALL: u8 = SCOPE_DELEGATIONS | SCOPE_PROFILE | SCOPE_FOLLOWS | SCOPE_ENC_KEYS;

/// Map an identity message-type byte to its scope bit. Returns 0 for any type
/// that is not an indexed identity type (so it is never served).
fn scope_of(msg_type: u8) -> u8 {
    match msg_type {
        t if t == MessageType::DeviceDelegation as u8 => SCOPE_DELEGATIONS,
        t if t == MessageType::DeviceRevocation as u8 => SCOPE_DELEGATIONS,
        t if t == MessageType::ProfileUpdate as u8 => SCOPE_PROFILE,
        t if t == MessageType::Follow as u8 => SCOPE_FOLLOWS,
        t if t == MessageType::Unfollow as u8 => SCOPE_FOLLOWS,
        t if t == MessageType::DeviceEncBinding as u8 => SCOPE_ENC_KEYS,
        t if t == MessageType::DeviceEncRevoke as u8 => SCOPE_ENC_KEYS,
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
/// Any of the seven identity types themselves (`scope_of != 0`) qualify —
/// a ProfileUpdate/Follow/Unfollow/DeviceDelegation/DeviceRevocation/
/// DeviceEncBinding/DeviceEncRevoke from a wallet with no local record is
/// itself the strongest possible signal.
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

/// Serving order of a wallet's identity envelopes (l2-node 0.151.0, audit
/// W3) — segments served one after the other; within a segment rows go by
/// `(timestamp, msg_id)`:
///
/// 1. `DeviceEncRevoke` (0x37) FIRST, before any binding: a session cut
///    short (page backstop, hostile or failing responder) can then never
///    leave a revoked encryption key looking active on the requester. The
///    apply is order-safe: a revoke of an unknown key leaves a tombstone, an
///    older binding of it loses last-write-wins, and that losing binding
///    still supersedes its device's older keys (router, `DeviceEncBinding`).
/// 2. `DeviceDelegation` (0x31) and `DeviceRevocation` (0x32) MERGED
///    chronologically. A revocation cannot be served before the delegation
///    it revokes: applying it needs the device mapped (and its signer
///    resolvable), and an unmapped revocation is stored without effect and
///    then deduplicated forever. In time order every prefix of the stream is
///    a state that really existed — never "all delegations, no revocations"
///    as with the pre-0.151.0 key order.
/// 3. `ProfileUpdate` (0x30), `Follow` (0x34), `Unfollow` (0x35),
///    `DeviceEncBinding` (0x36) — each in key order (after the delegations,
///    so a device-signed one resolves to its wallet).
const SERVE_ORDER: [&[u8]; 6] = [
    &[0x37],
    &[0x31, 0x32],
    &[0x30],
    &[0x34],
    &[0x35],
    &[0x36],
];

/// Index of the `SERVE_ORDER` segment holding `msg_type`.
fn segment_of(msg_type: u8) -> Option<usize> {
    SERVE_ORDER.iter().position(|seg| seg.contains(&msg_type))
}

/// Up to `limit` rows of one `SERVE_ORDER` segment of `subject`'s
/// `IDENTITY_ENVELOPES`, strictly after `(ts, msg_id)` when given, merged by
/// `(timestamp, msg_id)`. Also returns the work done (one unit per seek and
/// per row read).
fn segment_rows(
    storage: &Storage,
    subject: &str,
    types: &[u8],
    after: Option<(u64, [u8; 32])>,
    limit: usize,
) -> anyhow::Result<(Vec<(u8, u64, [u8; 32])>, u64)> {
    let base = schema::identity_envelope_prefix(subject);
    let tail_at = base.len() + 1;
    let mut out = Vec::new();
    let mut work = 0u64;
    for &t in types {
        let mut prefix = base.clone();
        prefix.push(t);
        let got = match after {
            Some((ts, id)) => {
                let start = schema::encode_identity_envelope_key(subject, t, ts, &id);
                storage.prefix_iter_cf_after(schema::cf::IDENTITY_ENVELOPES, &start, &prefix, limit)?
            }
            None => storage.prefix_iter_cf(schema::cf::IDENTITY_ENVELOPES, &prefix, limit)?,
        };
        work += 1 + got.len() as u64;
        for (key, _) in got {
            // Fixed-width tail ts(8) ++ msg_id(32); defensive for our own rows.
            if key.len() != tail_at + 8 + 32 {
                continue;
            }
            let Ok(ts) = <[u8; 8]>::try_from(&key[tail_at..tail_at + 8]) else { continue };
            let Ok(id) = <[u8; 32]>::try_from(&key[tail_at + 8..]) else { continue };
            out.push((t, u64::from_be_bytes(ts), id));
        }
    }
    out.sort_by(|a, b| (a.1, a.2).cmp(&(b.1, b.2)));
    out.truncate(limit);
    Ok((out, work))
}

/// Build a response: scan the wallet's `IDENTITY_ENVELOPES` prefix, filter by
/// requested scopes, page from the cursor, and re-serve the original signed
/// envelopes from `MESSAGES`. Caps at `max_envelopes`.
///
/// (Test convenience wrapper — production calls the `_metered` variant.)
#[cfg(test)]
pub fn build_response(
    storage: &Storage,
    request: &IdentitySyncRequest,
    max_envelopes: usize,
) -> IdentitySyncResponse {
    build_response_metered(storage, request, max_envelopes).0
}

/// `build_response` plus the storage work it did (one unit for the seek and
/// one per index row examined, its `MESSAGES` read included), for the
/// responder's rolling budget (`reconcile::budget_charge`, l2-node 0.151.0).
///
/// An envelope erased by a GDPR `DeletionRequest` (a verified
/// `DELETION_REQUESTS` record, decision D4) is never re-served; the cursor
/// still advances over it.
pub fn build_response_metered(
    storage: &Storage,
    request: &IdentitySyncRequest,
    max_envelopes: usize,
) -> (IdentitySyncResponse, u64) {
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
        return (empty(), 1);
    }

    // A device-resolve-miss pull arrives keyed by the DEVICE address
    // (`ogd1…`): the requester saw the device sign but can't map it. Resolve
    // it to the owning wallet HERE (we have the delegation) and serve that
    // wallet's bundle — the delegation in it lets the requester resolve the
    // device thereafter. A `klv1…` subject is used directly.
    let subject = if request.wallet.starts_with("ogd1") {
        match storage.resolve_wallet(&request.wallet) {
            Ok(Some(w)) => w,
            _ => return (empty(), 1),
        }
    } else {
        request.wallet.clone()
    };

    // Probe one extra row to detect `has_more` precisely.
    let probe_limit = max_envelopes.saturating_add(1);
    let start_seg = match request.cursor.as_ref() {
        None => 0,
        Some(c) => match segment_of(c.after_msg_type) {
            Some(i) => i,
            // Not a type this protocol serves: past the end.
            None => return (empty(), 1),
        },
    };
    let mut rows: Vec<(u8, u64, [u8; 32])> = Vec::new();
    let mut work: u64 = 0;
    for (seg_idx, seg) in SERVE_ORDER.iter().enumerate().skip(start_seg) {
        let room = probe_limit.saturating_sub(rows.len());
        if room == 0 {
            break;
        }
        // Skip a segment the caller asked nothing from (no rows examined).
        if !seg.iter().any(|t| type_in_scopes(*t, request.scopes)) {
            continue;
        }
        let after = request
            .cursor
            .as_ref()
            .filter(|_| seg_idx == start_seg)
            .map(|c| (c.after_timestamp, c.after_msg_id));
        match segment_rows(storage, &subject, seg, after, room) {
            Ok((mut got, w)) => {
                work += w;
                rows.append(&mut got);
            }
            // Storage fault → serve nothing (the requester races other peers).
            Err(_) => return (empty(), work.max(1)),
        }
    }
    let work = work.max(1);

    // The storage batch returned at most `probe_limit` rows; if it returned
    // exactly that many, there may be more beyond this batch.
    let truncated = rows.len() >= probe_limit;
    let mut envelopes: Vec<Vec<u8>> = Vec::new();
    let mut next_cursor: Option<IdentityCursor> = None;
    let mut more_in_batch = false;

    for (msg_type, ts, msg_id) in rows {
        // Page is full — stop BEFORE consuming this row so the next page
        // resumes at it (cursor stays at the previous row).
        if envelopes.len() >= max_envelopes {
            more_in_batch = true;
            break;
        }

        // Code Audit C-1: advance the cursor over EVERY row examined, in-scope
        // or not (a merged segment can hold a type outside a subset
        // `scopes`), so out-of-scope rows never strand in-scope ones.
        next_cursor = Some(IdentityCursor {
            after_msg_type: msg_type,
            after_timestamp: ts,
            after_msg_id: msg_id,
        });

        // Scope filter — never serve a type the caller didn't ask for.
        if !type_in_scopes(msg_type, request.scopes) {
            continue;
        }
        // Identity envelopes are NEVER withheld for a GDPR erasure (l2-node
        // 0.151.0, audit B1): hiding a wallet's own DeviceRevocation /
        // DeviceEncRevoke would keep a revoked device or key alive on every
        // fresh node. (`DELETION_REQUESTS` is not written for these types
        // either; this is the second line.)
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

    (
        IdentitySyncResponse {
            wallet: request.wallet.clone(),
            envelopes,
            has_more,
            next_cursor,
            server_capped: false,
            completeness_root: None,
        },
        work,
    )
}

// --- Responder rate limiting (per (peer, wallet)) ---

/// Responder admission for identity-sync (l2-node 0.151.0): per-peer
/// concurrency (`SERVER_MAX_CONCURRENT_PER_PEER`) plus a rolling budget per
/// `(peer, wallet)` — `[identity_resync] responder_budget_burst` units
/// (default 4,000) refilled at `responder_budget_refill_per_hour` (default
/// 1,000/h). Before 0.151.0 this was a LIFETIME counter of envelopes served
/// that never refilled until the responder restarted. Keys are bounded by
/// `budget::MAX_TRACKED_RESPONDER_KEYS`; the requester-chosen `wallet` half
/// of the key is validated (`is_plausible_subject`) before it is used.
pub type IdentityResponderLimits = crate::network::budget::PeerBudgetLimits<(libp2p::PeerId, String)>;

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
    fn triggers_identity_check_true_for_all_seven_identity_types() {
        for t in [
            MessageType::DeviceDelegation,
            MessageType::DeviceRevocation,
            MessageType::ProfileUpdate,
            MessageType::Follow,
            MessageType::Unfollow,
            MessageType::DeviceEncBinding,
            MessageType::DeviceEncRevoke,
        ] {
            assert!(triggers_identity_check(t as u8), "{:?} should trigger", t);
        }
    }

    /// G1 (l2-node 0.151.0) scope map, and old-peer compatibility in both
    /// directions: the 0.150 mapping (`scope_of` without the enc arms)
    /// never serves 0x36/0x37 whatever bits are asked for — so a new
    /// requester's bit 8 is simply ignored by an old responder — and a new
    /// responder serves enc rows only when bit 8 is set, which no old
    /// requester ever does.
    #[test]
    fn enc_key_scope_is_bit_8_and_old_peer_compatible() {
        let enc = [MessageType::DeviceEncBinding as u8, MessageType::DeviceEncRevoke as u8];
        for t in enc {
            assert_eq!(scope_of(t), SCOPE_ENC_KEYS);
            assert!(type_in_scopes(t, SCOPE_ENC_KEYS));
            assert!(type_in_scopes(t, SCOPE_ALL));
            assert!(!type_in_scopes(t, SCOPE_DELEGATIONS | SCOPE_PROFILE | SCOPE_FOLLOWS));
        }
        assert_eq!(SCOPE_ALL, 15);
        // The 0.150 responder's mapping.
        fn scope_of_0150(t: u8) -> u8 {
            match scope_of(t) {
                SCOPE_ENC_KEYS => 0,
                s => s,
            }
        }
        for t in enc {
            let s = scope_of_0150(t);
            assert!(s == 0 || (s & SCOPE_ALL) == 0, "an old responder never serves enc rows");
        }
        // Nothing else moved.
        assert_eq!(scope_of(MessageType::DeviceDelegation as u8), SCOPE_DELEGATIONS);
        assert_eq!(scope_of(MessageType::ProfileUpdate as u8), SCOPE_PROFILE);
        assert_eq!(scope_of(MessageType::Follow as u8), SCOPE_FOLLOWS);
        assert_eq!(scope_of(MessageType::SettingsSync as u8), 0, "encrypted settings never served");
        assert_eq!(scope_of(MessageType::KeyVaultSync as u8), 0, "key vault never served");
    }

    /// B1 (audit, l2-node 0.151.0): identity envelopes are NEVER withheld
    /// — even a (hypothetical) GDPR record on one does not hide it, so a
    /// wallet cannot "erase" its own revocation from fresh nodes.
    #[test]
    fn identity_envelopes_are_never_withheld() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let wallet = "klv1erasedprofile";
        let ids = [[1u8; 32], [2u8; 32]];
        for (i, (t, id)) in [(MessageType::DeviceRevocation, ids[0]), (MessageType::DeviceEncRevoke, ids[1])]
            .iter()
            .enumerate()
        {
            let key = schema::encode_identity_envelope_key(wallet, *t as u8, 100 + i as u64, id);
            storage.put_cf(schema::cf::IDENTITY_ENVELOPES, &key, &[]).unwrap();
            storage.put_cf(schema::cf::MESSAGES, id, &[i as u8 + 1]).unwrap();
            storage.put_verified_deletion_request(id, &[9u8; 32], wallet, 200).unwrap();
        }
        let req = IdentitySyncRequest {
            wallet: wallet.to_string(),
            scopes: SCOPE_ALL,
            cursor: None,
            overlap_digest: Vec::new(),
            round: 0,
        };
        let (resp, work) = build_response_metered(&storage, &req, 200);
        // Serve order: enc revokes first, then delegations/revocations.
        assert_eq!(resp.envelopes, vec![vec![2u8], vec![1u8]]);
        assert!(work >= 2);
    }

    /// W3: `DeviceEncRevoke` is served before any `DeviceEncBinding`, and
    /// delegations/revocations merge chronologically — so a session cut at
    /// any page boundary never shows a revoked key/device "all bindings, no
    /// revocations". Paging by cursor covers every row exactly once.
    #[test]
    fn serve_order_puts_revocations_first_and_pages_cleanly() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let wallet = "klv1ordertest";
        let rows: Vec<(MessageType, u64, u8)> = vec![
            (MessageType::DeviceEncBinding, 10, 1),
            (MessageType::DeviceEncBinding, 11, 2),
            (MessageType::DeviceEncRevoke, 12, 3),
            (MessageType::DeviceDelegation, 5, 4),
            (MessageType::DeviceRevocation, 7, 5),
            (MessageType::DeviceDelegation, 9, 6),
            (MessageType::ProfileUpdate, 1, 7),
        ];
        for (t, ts, n) in &rows {
            let id = [*n; 32];
            let key = schema::encode_identity_envelope_key(wallet, *t as u8, *ts, &id);
            storage.put_cf(schema::cf::IDENTITY_ENVELOPES, &key, &[]).unwrap();
            storage.put_cf(schema::cf::MESSAGES, &id, &[*n]).unwrap();
        }
        let mut cursor = None;
        let mut served = Vec::new();
        for _ in 0..10 {
            let req = IdentitySyncRequest {
                wallet: wallet.to_string(),
                scopes: SCOPE_ALL,
                cursor: cursor.clone(),
                overlap_digest: Vec::new(),
                round: 0,
            };
            // Page size 2 — every boundary is exercised.
            let resp = build_response(&storage, &req, 2);
            assert!(resp.envelopes.len() <= 2);
            served.extend(resp.envelopes.iter().map(|e| e[0]));
            if !resp.has_more {
                break;
            }
            cursor = resp.next_cursor;
        }
        // enc revoke (3); delegation(5)=4, revocation(7)=5, delegation(9)=6;
        // profile 7; enc bindings 1, 2.
        assert_eq!(served, vec![3, 4, 5, 6, 7, 1, 2]);
        // Truncated after the first page: the revoke is already there, no
        // binding yet.
        let first = build_response(
            &storage,
            &IdentitySyncRequest { wallet: wallet.to_string(), scopes: SCOPE_ENC_KEYS, cursor: None, overlap_digest: vec![], round: 0 },
            1,
        );
        assert_eq!(first.envelopes, vec![vec![3u8]]);
        // A cursor on a type this protocol never serves is past the end.
        let bogus = build_response(
            &storage,
            &IdentitySyncRequest {
                wallet: wallet.to_string(),
                scopes: SCOPE_ALL,
                cursor: Some(IdentityCursor { after_msg_type: 0x33, after_timestamp: 0, after_msg_id: [0; 32] }),
                overlap_digest: vec![],
                round: 0,
            },
            10,
        );
        assert!(bogus.envelopes.is_empty() && !bogus.has_more);
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
