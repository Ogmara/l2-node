//! `POST /api/v1/channels/{channel_id}/member-proofs` (l2-node 0.142.0,
//! protocol §3.9.1 Phase 2 "verify before cover").
//!
//! A client about to wrap a private channel's epoch key to other members
//! asks its node for the raw, signed evidence behind each member's
//! membership, and verifies it ITSELF (sdk `verifyPrivateMemberProof`)
//! before covering them. The node never vouches for anything here: every
//! item is an original signed envelope (or a wallet+device-signed device
//! delegation) the client re-verifies; the node only decides what to look
//! up.
//!
//! What a malicious node can still do is WITHHOLD (omit a removal, a
//! grant, a device claim). Forgery is closed, withholding is narrowed —
//! the client fails closed on anything it cannot verify, so withholding
//! the evidence FOR a member only gets that member not covered, and
//! withholding evidence AGAINST a member (a removal) is the recorded W3
//! residual.
//!
//! Response shape (plan "Claim wire format" §8): per-member items
//! (`join`, `removals`) inside `members[]`; items several members share
//! (`moderator_grants`, `moderator_removals`, `device_claims`) ONCE in
//! top-level maps keyed by address, so one moderator's grant is not
//! repeated for every member they invited (B2).
//!
//! Bounds per request: ≤ `MAX_ADDRESSES` addresses, a 16 KiB body,
//! `SCAN_ROWS_PER_TYPE` index rows per scanned type, `LEGACY_JOIN_SCAN_ROWS`
//! join rows (legacy fallback, only when needed), no served envelope above
//! `MAX_EVIDENCE_BYTES` (a member whose evidence includes one is served as
//! `unavailable` — fail closed), a `RESPONSE_BYTE_BUDGET` total (members past
//! it are `unavailable` with `"truncated": true`), one in-flight build per
//! wallet, `MAX_CONCURRENT_BUILDS` node-wide, and a per-wallet rate limit.
//! The build runs on the blocking pool.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use serde::Deserialize;

use crate::messages::envelope::Envelope;
use crate::messages::types::{deserialize_payload, DeserializedPayload, MessageType};
use crate::network::private_channel_sync::{
    device_delegated_at, lookup_device_revocations, lookup_pop_delegations,
};
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;
use crate::storage::schema::{self, cf};

use super::auth::AuthUser;
use super::state::AppState;

/// Max addresses per request.
pub const MAX_ADDRESSES: usize = 100;
/// Max request body size (bytes).
pub const MAX_BODY_BYTES: usize = 16 * 1024;
/// Max removal envelopes returned per target (newest first).
pub const MAX_REMOVALS_PER_TARGET: usize = 16;
/// Max moderator grants returned per moderator (newest first).
pub const MAX_GRANTS_PER_MODERATOR: usize = 4;
/// Max distinct removers whose grants one member's removals pull in
/// (newest removals first).
pub const MAX_REMOVERS_PER_MEMBER: usize = 8;
/// Max PoP delegations / revocations served per device.
pub const MAX_DEVICE_ITEMS: usize = 4;
/// `CHANNEL_META_MSGS` rows examined per scanned type (Kick, Ban,
/// RemoveModerator, AddModerator), newest first.
pub const SCAN_ROWS_PER_TYPE: usize = 1024;
/// `CHANNEL_META_MSGS` join rows examined by the legacy fallback (members
/// with no `CHANNEL_MEMBERSHIP_INDEX` rows), newest first.
pub const LEGACY_JOIN_SCAN_ROWS: usize = 2048;
/// Largest evidence envelope ever served (raw bytes). The largest
/// legitimate one is a join carrying a 2 KiB invite (which itself embeds a
/// ≤ 1 KiB grant): byte fields are msgpack int arrays in the map wire form
/// (up to 2 bytes per byte), nested twice (invite in payload, payload in
/// envelope), so a legitimate join reaches ≈ 9 KiB — a 4 KiB cap rejected
/// real moderator-invite joins in testing. Anything above 16 KiB is a
/// padded envelope and makes the member it concerns `unavailable` instead
/// of being amplified (B2).
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024;
/// Total serialized-evidence budget of one response (approximate bytes).
pub const RESPONSE_BYTE_BUDGET: usize = 2 * 1024 * 1024;
/// Requests per wallet per `RATE_WINDOW`.
pub const RATE_MAX_REQUESTS: u32 = 20;
/// Rate-limit window.
pub const RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Max wallets tracked by the limiter (oldest evicted when full).
const RATE_MAX_TRACKED_WALLETS: usize = 10_000;
/// Max member-proofs builds running on the blocking pool node-wide; a
/// request that finds none free gets 503 (never queued).
pub const MAX_CONCURRENT_BUILDS: usize = 4;

fn build_slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BUILDS)))
}

/// Wallets with a build in flight (W5: at most one per wallet).
fn in_flight() -> &'static Mutex<HashSet<String>> {
    static SET: std::sync::OnceLock<Mutex<HashSet<String>>> = std::sync::OnceLock::new();
    SET.get_or_init(Default::default)
}

/// RAII: the wallet's in-flight slot, released on drop. The set never holds
/// more than `MAX_CONCURRENT_BUILDS` entries (taken after a build slot).
struct InFlight(String);

impl InFlight {
    fn take(wallet: &str) -> Option<Self> {
        let mut set = in_flight().lock().unwrap_or_else(|p| p.into_inner());
        set.insert(wallet.to_string()).then(|| InFlight(wallet.to_string()))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        in_flight().lock().unwrap_or_else(|p| p.into_inner()).remove(&self.0);
    }
}

/// Request body.
#[derive(Debug, Deserialize)]
pub struct MemberProofsRequest {
    /// Wallet addresses (klv1…) to return proofs for, 1..=`MAX_ADDRESSES`.
    pub addresses: Vec<String>,
}

/// Why a member's membership can or cannot be proven from this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofBasis {
    /// The address is the channel creator (proven by `channel_create`).
    Creator,
    /// The newest indexed join carries an invite.
    Invite,
    /// The newest indexed join carries no invite (pre-activation join).
    Legacy,
    /// Not a member, no join available, oversized evidence, or truncated.
    Unavailable,
}

impl ProofBasis {
    fn as_str(self) -> &'static str {
        match self {
            ProofBasis::Creator => "creator",
            ProofBasis::Invite => "invite",
            ProofBasis::Legacy => "legacy",
            ProofBasis::Unavailable => "unavailable",
        }
    }
}

/// Per-wallet fixed-window limiter (in-memory, node-local).
#[derive(Default)]
struct RateLimiter {
    per_wallet: HashMap<String, (std::time::Instant, u32)>,
}

impl RateLimiter {
    /// Count one request by `wallet`; `false` = over the limit (a refused
    /// request is not counted). Full map: prune expired windows, then evict
    /// the oldest window — new wallets are never refused outright.
    fn check(&mut self, wallet: &str, now: std::time::Instant) -> bool {
        if !self.per_wallet.contains_key(wallet) && self.per_wallet.len() >= RATE_MAX_TRACKED_WALLETS {
            self.per_wallet
                .retain(|_, (start, _)| now.saturating_duration_since(*start) < RATE_WINDOW);
            if self.per_wallet.len() >= RATE_MAX_TRACKED_WALLETS {
                if let Some(oldest) = self
                    .per_wallet
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(k, _)| k.clone())
                {
                    self.per_wallet.remove(&oldest);
                }
            }
        }
        let entry = self.per_wallet.entry(wallet.to_string()).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= RATE_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= RATE_MAX_REQUESTS {
            return false;
        }
        entry.1 += 1;
        true
    }
}

fn limiter() -> &'static Mutex<RateLimiter> {
    static LIMITER: std::sync::OnceLock<Mutex<RateLimiter>> = std::sync::OnceLock::new();
    LIMITER.get_or_init(Default::default)
}

/// Validate and dedupe the requested addresses (order preserved).
pub fn validate_addresses(addresses: &[String]) -> Result<Vec<String>, &'static str> {
    if addresses.is_empty() {
        return Err("addresses must not be empty");
    }
    if addresses.len() > MAX_ADDRESSES {
        return Err("too many addresses (max 100)");
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(addresses.len());
    for a in addresses {
        if a.len() > 128
            || !a.starts_with("klv1")
            || crate::crypto::address_to_pubkey_bytes(a).is_err()
        {
            return Err("invalid wallet address");
        }
        if seen.insert(a.as_str()) {
            out.push(a.clone());
        }
    }
    Ok(out)
}

/// POST /api/v1/channels/{channel_id}/member-proofs — see the module doc
/// and the plan's "Claim wire format" §8 for the response shape.
///
/// 403 caller not a current member (also for an unknown channel — nothing
/// about the channel is revealed to a non-member), 400 bad body / not a
/// private channel, 413 body over 16 KiB, 429 per-wallet limit or a build
/// of the same wallet already in flight, 503 all `MAX_CONCURRENT_BUILDS`
/// build slots busy.
pub async fn get_member_proofs(
    Extension(state): Extension<Arc<AppState>>,
    Extension(auth_user): Extension<AuthUser>,
    Path(channel_id): Path<u64>,
    body: axum::body::Bytes,
) -> Response {
    if body.len() > MAX_BODY_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
    }
    let req: MemberProofsRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON body").into_response(),
    };
    let addresses = match validate_addresses(&req.addresses) {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    // N7: membership FIRST, so a non-member learns nothing (not even
    // whether the channel exists or is private).
    match state
        .storage
        .exists_cf(cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(channel_id, &auth_user.address))
    {
        Ok(true) => {}
        Ok(false) => return (StatusCode::FORBIDDEN, "not a member of this channel").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "member-proofs: membership lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    }
    let row = match state.storage.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::FORBIDDEN, "not a member of this channel").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "member-proofs: channel lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response();
        }
    };
    if !crate::network::reconcile::is_private_channel(&state.storage, channel_id) {
        return (StatusCode::BAD_REQUEST, "not a private channel").into_response();
    }
    let creator = serde_json::from_slice::<serde_json::Value>(&row)
        .ok()
        .and_then(|v| v.get("creator").and_then(|c| c.as_str()).map(String::from));
    // Slot first, so a 503 never costs the caller rate-limit budget.
    let Ok(permit) = build_slots().clone().try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "member-proofs busy, retry shortly").into_response();
    };
    let Some(flight) = InFlight::take(&auth_user.address) else {
        return (StatusCode::TOO_MANY_REQUESTS, "a member-proofs request of this wallet is in flight")
            .into_response();
    };
    let allowed = limiter()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .check(&auth_user.address, std::time::Instant::now());
    if !allowed {
        return (StatusCode::TOO_MANY_REQUESTS, "member-proofs rate limit exceeded").into_response();
    }

    let storage = state.storage.clone();
    let identity = state.identity.clone();
    let network = state.klever_network.clone();
    let built = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _flight = flight;
        build_member_proofs(
            &storage,
            &identity,
            &network,
            channel_id,
            creator.as_deref(),
            &addresses,
            RESPONSE_BYTE_BUDGET,
        )
    })
    .await;
    match built {
        Ok(v) => Json(v).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "member-proofs: build task failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        }
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Serialized size of `n` raw bytes as a JSON base64 string (+ quotes/comma).
fn b64_cost(n: usize) -> usize {
    n.div_ceil(3) * 4 + 3
}

/// Decode a raw envelope; `None` when it does not decode.
fn decode(raw: &[u8]) -> Option<Envelope> {
    rmp_serde::from_slice::<Envelope>(raw).ok()
}

/// Load a stored envelope by msg_id.
fn load(storage: &Storage, msg_id: &[u8; 32]) -> Option<Vec<u8>> {
    storage.get_message(msg_id).ok().flatten()
}

/// The msg_id at the end of a `CHANNEL_META_MSGS` key.
fn key_msg_id(key: &[u8]) -> Option<[u8; 32]> {
    key.len().checked_sub(32).and_then(|at| <[u8; 32]>::try_from(&key[at..]).ok())
}

/// Newest-first `CHANNEL_META_MSGS` rows of one msg_type for a channel.
fn meta_rows_newest_first(storage: &Storage, channel_id: u64, msg_type: u8, limit: usize) -> Vec<[u8; 32]> {
    let mut prefix = channel_id.to_be_bytes().to_vec();
    prefix.push(msg_type);
    let mut start = prefix.clone();
    start.extend_from_slice(&[0xFF; 40]);
    storage
        .reverse_iter_cf(cf::CHANNEL_META_MSGS, &start, &prefix, limit)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(k, _)| key_msg_id(&k))
        .collect()
}

/// `(channel_id, target_user)` of a removal-type (or moderator-grant)
/// envelope.
fn targeted(env: &Envelope) -> Option<(u64, String)> {
    match deserialize_payload(env.msg_type, &env.payload).ok()? {
        DeserializedPayload::ChannelAddModerator(p) => Some((p.channel_id, p.target_user)),
        DeserializedPayload::ChannelKick(p) => Some((p.channel_id, p.target_user)),
        DeserializedPayload::ChannelBan(p) => Some((p.channel_id, p.target_user)),
        DeserializedPayload::ChannelRemoveModerator(p) => Some((p.channel_id, p.target_user)),
        _ => None,
    }
}

/// One scanned envelope: the few decoded fields the build needs, plus the
/// raw bytes ONLY when they are within `MAX_EVIDENCE_BYTES` (Note 6: an
/// oversized envelope found by a scan is reduced to a size flag at once, so
/// per-build memory stays bounded by `MAX_EVIDENCE_BYTES` per kept item).
#[derive(Clone)]
struct Item {
    /// Raw envelope bytes; EMPTY when the envelope was oversized.
    raw: Vec<u8>,
    /// Original raw size.
    size: usize,
    author: String,
    timestamp: u64,
    msg_id: [u8; 32],
}

impl Item {
    fn new(raw: Vec<u8>, env: &Envelope) -> Self {
        let size = raw.len();
        Item {
            raw: if size > MAX_EVIDENCE_BYTES { Vec::new() } else { raw },
            size,
            author: env.author.clone(),
            timestamp: env.timestamp,
            msg_id: env.msg_id,
        }
    }

    fn oversized(&self) -> bool {
        self.size > MAX_EVIDENCE_BYTES
    }
}

/// Collect envelopes of `msg_type` (Kick, Ban, RemoveModerator or
/// AddModerator) targeting any of `wanted`, newest first, ≤ `per_target`
/// per target. Oversized ones are kept only as a size flag (the caller
/// fails the member closed on them) and are never served.
fn scan_targeted(
    storage: &Storage,
    channel_id: u64,
    msg_type: MessageType,
    wanted: &HashSet<String>,
    per_target: usize,
) -> HashMap<String, Vec<Item>> {
    let mut out: HashMap<String, Vec<Item>> = HashMap::new();
    if wanted.is_empty() {
        return out;
    }
    for id in meta_rows_newest_first(storage, channel_id, msg_type as u8, SCAN_ROWS_PER_TYPE) {
        let Some(raw) = load(storage, &id) else { continue };
        let Some(env) = decode(&raw) else { continue };
        if env.msg_type != msg_type {
            continue;
        }
        let Some((cid, target)) = targeted(&env) else { continue };
        if cid != channel_id || !wanted.contains(&target) {
            continue;
        }
        let list = out.entry(target).or_default();
        if list.len() < per_target {
            list.push(Item::new(raw, &env));
        }
    }
    out
}

/// `true` when `raw` is a `ChannelJoin` of `channel_id` whose author is
/// `address`, a device CURRENTLY mapped to it, or a device that was
/// delegated by it (proof-of-possession) at the join's timestamp — W4: a
/// join signed by a since-revoked device stays verifiable.
fn join_matches(
    storage: &Storage,
    identity: &IdentityResolver,
    network: &str,
    raw: &[u8],
    channel_id: u64,
    address: &str,
) -> bool {
    let Some(env) = decode(raw) else { return false };
    if env.msg_type != MessageType::ChannelJoin {
        return false;
    }
    let cid_ok = matches!(
        deserialize_payload(env.msg_type, &env.payload),
        Ok(DeserializedPayload::ChannelJoin(ref p)) if p.channel_id == channel_id
    );
    if !cid_ok {
        return false;
    }
    if env.author == address || identity.resolve(&env.author).is_ok_and(|w| w == address) {
        return true;
    }
    crate::crypto::is_device_address(&env.author)
        && device_delegated_at(storage, network, &env.author, address, env.timestamp)
}

/// The join envelope behind a member's newest `CHANNEL_MEMBERSHIP_INDEX`
/// join row, if it is still stored and genuinely the member's join.
fn indexed_join(
    storage: &Storage,
    identity: &IdentityResolver,
    network: &str,
    channel_id: u64,
    address: &str,
) -> Option<Vec<u8>> {
    let st = storage.membership_index_state(channel_id, address).ok().flatten()?;
    let mut joins: Vec<_> = st
        .rows
        .iter()
        .filter(|r| r.0 == MessageType::ChannelJoin as u8)
        .collect();
    joins.sort_by_key(|r| std::cmp::Reverse((r.1, r.2)));
    joins
        .into_iter()
        .filter_map(|r| load(storage, &r.2))
        .find(|raw| join_matches(storage, identity, network, raw, channel_id, address))
}

/// Legacy fallback (members whose joins predate the 0.140.0 membership
/// index): newest join per resolved author among the channel's newest
/// `LEGACY_JOIN_SCAN_ROWS` join rows.
fn legacy_join_map(storage: &Storage, identity: &IdentityResolver, channel_id: u64) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    for id in meta_rows_newest_first(storage, channel_id, MessageType::ChannelJoin as u8, LEGACY_JOIN_SCAN_ROWS) {
        let Some(raw) = load(storage, &id) else { continue };
        let Some(env) = decode(&raw) else { continue };
        let Ok(wallet) = identity.resolve(&env.author) else { continue };
        if out.contains_key(&wallet) {
            continue;
        }
        let is_join = env.msg_type == MessageType::ChannelJoin
            && matches!(
                deserialize_payload(env.msg_type, &env.payload),
                Ok(DeserializedPayload::ChannelJoin(ref p)) if p.channel_id == channel_id
            );
        if is_join {
            out.insert(wallet, raw);
        }
    }
    out
}

/// What a join carries: `(invite envelope, embedded grant envelope)`;
/// `None` when the join has no decodable invite.
fn join_invite(join_raw: &[u8]) -> Option<(Envelope, Option<Envelope>)> {
    let env = decode(join_raw)?;
    let invite_raw = match deserialize_payload(env.msg_type, &env.payload).ok()? {
        DeserializedPayload::ChannelJoin(p) => p.invite?,
        _ => return None,
    };
    let inv = decode(&invite_raw)?;
    let grant = match deserialize_payload(inv.msg_type, &inv.payload) {
        Ok(DeserializedPayload::ChannelInvite(p)) => p.inviter_grant.and_then(|g| decode(&g)),
        _ => None,
    };
    Some((inv, grant))
}

/// `true` when the join carries an invite field at all (decodable or not).
fn join_has_invite(join_raw: &[u8]) -> bool {
    decode(join_raw)
        .and_then(|e| match deserialize_payload(e.msg_type, &e.payload).ok()? {
            DeserializedPayload::ChannelJoin(p) => Some(p.invite.is_some()),
            _ => None,
        })
        .unwrap_or(false)
}

/// The device-claim object for `device_address` under `wallet` (plan §6):
/// ≤ `MAX_DEVICE_ITEMS` stored dual-signed delegations (wallet AND device
/// proof-of-possession signatures — never a wallet-only registration row,
/// W2) plus ≤ `MAX_DEVICE_ITEMS` stored `DeviceRevocation` envelopes naming
/// the device. `Err(())` when a revocation is oversized (the caller fails
/// the member closed); `Ok(None)` when no PoP delegation is stored.
pub(crate) fn device_claim_json(
    storage: &Storage,
    network: &str,
    device_address: &str,
    wallet: &str,
) -> Result<Option<serde_json::Value>, ()> {
    let mut dels = lookup_pop_delegations(storage, network, device_address, wallet);
    if dels.is_empty() {
        return Ok(None);
    }
    dels.truncate(MAX_DEVICE_ITEMS);
    let mut revs = lookup_device_revocations(storage, device_address, wallet);
    revs.truncate(MAX_DEVICE_ITEMS);
    if revs.iter().any(|r| r.len() > MAX_EVIDENCE_BYTES) {
        return Err(());
    }
    let device_pubkey = crate::crypto::address_to_pubkey_bytes(device_address).map(hex::encode).map_err(|_| ())?;
    Ok(Some(serde_json::json!({
        "device_address": device_address,
        "device_pubkey": device_pubkey,
        "wallet": wallet,
        "delegations": dels.iter().map(|d| serde_json::json!({
            "timestamp": d.timestamp,
            "wallet_signature": b64(&d.wallet_signature),
            "device_signature": b64(&d.device_signature),
        })).collect::<Vec<_>>(),
        "revocations": revs.iter().map(|r| b64(r)).collect::<Vec<_>>(),
    })))
}

/// One member's bundle under construction.
struct MemberDraft {
    address: String,
    member: bool,
    basis: ProofBasis,
    reason: Option<&'static str>,
    join: Option<Vec<u8>>,
    inviter: Option<String>,
    /// The invite embeds no grant and the inviter is not the creator.
    needs_inviter_grant: bool,
    /// `(author, wallet)` of every envelope in this bundle; `wallet` is the
    /// resolved wallet, or the member for a revoked join device (W4).
    authors: Vec<(String, String)>,
}

impl MemberDraft {
    fn unavailable(&mut self, reason: &'static str) {
        self.basis = ProofBasis::Unavailable;
        self.reason = Some(reason);
        self.join = None;
        self.inviter = None;
        self.needs_inviter_grant = false;
        self.authors.clear();
    }
}

/// Build the member-proofs response (sync; called on the blocking pool).
/// `byte_budget` bounds the served evidence (≈ serialized bytes); members
/// that would exceed it are `unavailable` with `"truncated": true`.
pub fn build_member_proofs(
    storage: &Storage,
    identity: &IdentityResolver,
    network: &str,
    channel_id: u64,
    creator: Option<&str>,
    addresses: &[String],
    byte_budget: usize,
) -> serde_json::Value {
    let resolve = |a: &str| identity.resolve(a).unwrap_or_else(|_| a.to_string());
    let (create_raw, _) = crate::network::reconcile::channel_bootstrap_envelopes(storage, channel_id);
    // An oversized ChannelCreate is never served: every member then lacks
    // the creator anchor and the verifier fails closed.
    let create_raw = create_raw.filter(|r| r.len() <= MAX_EVIDENCE_BYTES);
    let create_author = create_raw.as_deref().and_then(decode).map(|e| e.author);

    let mut legacy: Option<HashMap<String, Vec<u8>>> = None;
    let mut drafts = Vec::with_capacity(addresses.len());
    for address in addresses {
        let member = storage
            .exists_cf(cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(channel_id, address))
            .unwrap_or(false);
        let mut d = MemberDraft {
            address: address.clone(),
            member,
            basis: ProofBasis::Unavailable,
            reason: None,
            join: None,
            inviter: None,
            needs_inviter_grant: false,
            authors: Vec::new(),
        };
        if !member {
            d.reason = Some("not_member");
            drafts.push(d);
            continue;
        }
        if creator == Some(address.as_str()) {
            d.basis = ProofBasis::Creator;
            if let Some(a) = create_author.as_ref() {
                d.authors.push((a.clone(), address.clone()));
            }
            drafts.push(d);
            continue;
        }
        let join = indexed_join(storage, identity, network, channel_id, address).or_else(|| {
            legacy
                .get_or_insert_with(|| legacy_join_map(storage, identity, channel_id))
                .get(address)
                .cloned()
        });
        let Some(join) = join else {
            d.reason = Some("no_join");
            drafts.push(d);
            continue;
        };
        if join.len() > MAX_EVIDENCE_BYTES {
            // Same inclusive boundary as `Item::oversized`.
            d.unavailable("oversized_evidence");
            drafts.push(d);
            continue;
        }
        if let Some(env) = decode(&join) {
            // The member is the wallet even when the join device has since
            // been revoked (W4).
            d.authors.push((env.author, address.clone()));
        }
        match join_invite(&join) {
            Some((inv, grant)) => {
                d.basis = ProofBasis::Invite;
                let inviter = resolve(&inv.author);
                d.authors.push((inv.author.clone(), inviter.clone()));
                match grant {
                    Some(g) => d.authors.push((g.author.clone(), resolve(&g.author))),
                    None => d.needs_inviter_grant = creator != Some(inviter.as_str()),
                }
                d.inviter = Some(inviter);
            }
            None => {
                // An undecodable invite is still served as `invite` so the
                // verifier rejects it; only a join with no invite is legacy.
                d.basis = if join_has_invite(&join) { ProofBasis::Invite } else { ProofBasis::Legacy };
            }
        }
        if let Some(a) = create_author.as_ref() {
            d.authors.push((a.clone(), creator.unwrap_or_default().to_string()));
        }
        d.join = Some(join);
        drafts.push(d);
    }

    // Scans, restricted to the targets actually needed.
    let member_targets: HashSet<String> =
        drafts.iter().filter(|d| d.join.is_some()).map(|d| d.address.clone()).collect();
    let inviter_targets: HashSet<String> = drafts
        .iter()
        .filter_map(|d| d.inviter.clone())
        .filter(|i| creator != Some(i.as_str()))
        .collect();
    let mut removals = scan_targeted(storage, channel_id, MessageType::ChannelKick, &member_targets, MAX_REMOVALS_PER_TARGET);
    for (t, mut list) in scan_targeted(storage, channel_id, MessageType::ChannelBan, &member_targets, MAX_REMOVALS_PER_TARGET) {
        removals.entry(t).or_default().append(&mut list);
    }
    for list in removals.values_mut() {
        list.sort_by_key(|i| std::cmp::Reverse((i.timestamp, i.msg_id)));
        list.truncate(MAX_REMOVALS_PER_TARGET);
    }
    let mod_removals = scan_targeted(
        storage,
        channel_id,
        MessageType::ChannelRemoveModerator,
        &inviter_targets,
        MAX_REMOVALS_PER_TARGET,
    );
    let mut removers: HashSet<String> = HashSet::new();
    for item in removals.values().chain(mod_removals.values()).flatten() {
        let signer = resolve(&item.author);
        if creator != Some(signer.as_str()) {
            removers.insert(signer);
        }
    }
    // Moderator grants from the metadata index (a moderator demoted later
    // still needs the grant that authorized them), creator-signed only.
    let grant_targets: HashSet<String> = removers.union(&inviter_targets).cloned().collect();
    let mut grants =
        scan_targeted(storage, channel_id, MessageType::ChannelAddModerator, &grant_targets, MAX_GRANTS_PER_MODERATOR);
    for list in grants.values_mut() {
        list.retain(|i| creator == Some(resolve(&i.author).as_str()));
    }
    // Grants per moderator, computed once: indexed (newest first), else the
    // current moderator record.
    for who in &grant_targets {
        if grants.get(who).is_none_or(|l| l.is_empty()) {
            let current: Vec<Item> = crate::api::routes::lookup_moderator_grant(storage, channel_id, who)
                .ok()
                .flatten()
                .and_then(|raw| decode(&raw).map(|env| Item::new(raw, &env)))
                .into_iter()
                .collect();
            grants.insert(who.clone(), current);
        }
    }
    let grants_for = |who: &str| -> &[Item] { grants.get(who).map(Vec::as_slice).unwrap_or(&[]) };
    let mut claim_cache: HashMap<(String, String), Result<Option<serde_json::Value>, ()>> = HashMap::new();

    // Shared top-level maps (B2) and the byte budget.
    let mut moderator_grants: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut moderator_removals: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut device_claims: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut used = create_raw.as_ref().map_or(0, |r| b64_cost(r.len())) + 256;
    let mut truncated = false;
    let mut members = Vec::with_capacity(drafts.len());

    for mut d in drafts {
        // Gather this member's evidence: own items + shared items it needs
        // (borrowed — nothing is cloned per member).
        let own_removals: &[Item] = removals.get(&d.address).map(Vec::as_slice).unwrap_or(&[]);
        let inv_removals: &[Item] =
            d.inviter.as_ref().and_then(|i| mod_removals.get(i)).map(Vec::as_slice).unwrap_or(&[]);
        let mut need_grants: BTreeSet<String> = BTreeSet::new();
        if d.needs_inviter_grant {
            if let Some(i) = d.inviter.clone() {
                need_grants.insert(i);
            }
        }
        for item in own_removals.iter().chain(inv_removals.iter()) {
            let remover = resolve(&item.author);
            d.authors.push((item.author.clone(), remover.clone()));
            if creator == Some(remover.as_str())
                || need_grants.contains(&remover)
                || need_grants.len() >= MAX_REMOVERS_PER_MEMBER
            {
                continue;
            }
            need_grants.insert(remover);
        }
        for who in &need_grants {
            for g in grants_for(who) {
                d.authors.push((g.author.clone(), resolve(&g.author)));
            }
        }
        let oversized = own_removals.iter().chain(inv_removals.iter()).any(Item::oversized)
            || need_grants.iter().flat_map(|w| grants_for(w)).any(Item::oversized);
        let mut needed_claims: Vec<(String, serde_json::Value)> = Vec::new();
        let mut claim_oversized = false;
        let mut seen = HashSet::new();
        for (author, wallet) in &d.authors {
            if !crate::crypto::is_device_address(author) || !seen.insert(author.clone()) {
                continue;
            }
            let entry = claim_cache
                .entry((author.clone(), wallet.clone()))
                .or_insert_with(|| device_claim_json(storage, network, author, wallet))
                .clone();
            match entry {
                Ok(Some(v)) => needed_claims.push((author.clone(), v)),
                Ok(None) => {}
                Err(()) => claim_oversized = true,
            }
        }
        if d.basis != ProofBasis::Unavailable && (oversized || claim_oversized) {
            d.unavailable("oversized_evidence");
        }

        // Byte cost of everything NEW this member adds.
        let mut cost = 200 + d.address.len() + d.join.as_ref().map_or(0, |j| b64_cost(j.len()));
        if d.basis != ProofBasis::Unavailable {
            cost += own_removals.iter().map(|i| b64_cost(i.raw.len())).sum::<usize>();
            if let Some(i) = d.inviter.as_ref().filter(|i| !moderator_removals.contains_key(*i)) {
                cost += i.len() + inv_removals.iter().map(|x| b64_cost(x.raw.len())).sum::<usize>();
            }
            for who in &need_grants {
                if !moderator_grants.contains_key(who) {
                    cost += who.len() + grants_for(who).iter().map(|x| b64_cost(x.raw.len())).sum::<usize>();
                }
            }
            for (dev, v) in &needed_claims {
                if !device_claims.contains_key(dev) {
                    cost += v.to_string().len();
                }
            }
        }
        if truncated || used + cost > byte_budget {
            truncated = true;
            if d.basis != ProofBasis::Unavailable {
                d.unavailable("truncated");
            }
        }
        if d.basis != ProofBasis::Unavailable {
            used += cost;
            if let Some(i) = d.inviter.as_ref() {
                if !inv_removals.is_empty() {
                    moderator_removals
                        .entry(i.clone())
                        .or_insert_with(|| inv_removals.iter().map(|x| b64(&x.raw)).collect());
                }
            }
            for who in need_grants {
                let list = grants_for(&who);
                if !list.is_empty() {
                    moderator_grants.entry(who).or_insert_with(|| list.iter().map(|x| b64(&x.raw)).collect());
                }
            }
            for (dev, v) in needed_claims {
                device_claims.entry(dev).or_insert(v);
            }
        } else {
            used += 200 + d.address.len();
        }
        let ok = d.basis != ProofBasis::Unavailable;
        members.push(serde_json::json!({
            "address": d.address,
            "member": d.member,
            "basis": d.basis.as_str(),
            "reason": d.reason,
            "join": d.join.as_deref().filter(|_| ok).map(b64),
            "removals": if ok { own_removals.iter().map(|i| b64(&i.raw)).collect::<Vec<_>>() } else { Vec::new() },
            "inviter": d.inviter.filter(|_| ok),
        }));
    }

    serde_json::json!({
        "channel_id": channel_id,
        "creator": creator,
        "channel_create": create_raw.as_deref().map(b64),
        "truncated": truncated,
        "members": members,
        "moderator_grants": moderator_grants,
        "moderator_removals": moderator_removals,
        "device_claims": device_claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation_bounds_and_dedupes() {
        assert!(validate_addresses(&[]).is_err());
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let a = crate::crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
        let out = validate_addresses(&[a.clone(), a.clone()]).unwrap();
        assert_eq!(out, vec![a.clone()]);
        assert!(validate_addresses(&vec![a.clone(); MAX_ADDRESSES + 1]).is_err());
        assert!(validate_addresses(&["klv1notanaddress".to_string()]).is_err());
        let dev = crate::crypto::device_pubkey_to_address(&sk.verifying_key()).unwrap();
        assert!(validate_addresses(&[dev]).is_err(), "device addresses are not wallets");
    }

    #[test]
    fn rate_limiter_window() {
        let mut l = RateLimiter::default();
        let now = std::time::Instant::now();
        for _ in 0..RATE_MAX_REQUESTS {
            assert!(l.check("klv1a", now));
        }
        assert!(!l.check("klv1a", now));
        assert!(l.check("klv1b", now), "per wallet");
        assert!(l.check("klv1a", now + RATE_WINDOW), "window resets");
    }

    #[test]
    fn one_build_in_flight_per_wallet() {
        let a = InFlight::take("klv1inflight_a").expect("first");
        assert!(InFlight::take("klv1inflight_a").is_none(), "second refused");
        assert!(InFlight::take("klv1inflight_b").is_some(), "other wallets unaffected");
        drop(a);
        assert!(InFlight::take("klv1inflight_a").is_some(), "released on drop");
    }

    #[test]
    fn evidence_size_boundary_is_inclusive_at_16_kib() {
        let env = Envelope {
            version: 2,
            msg_type: MessageType::ChannelKick,
            msg_id: [1; 32],
            author: "klv1x".into(),
            timestamp: 5,
            lamport_ts: 0,
            payload: vec![],
            signature: vec![],
            relay_path: vec![],
        };
        let at = Item::new(vec![0; MAX_EVIDENCE_BYTES], &env);
        assert!(!at.oversized());
        assert_eq!(at.raw.len(), MAX_EVIDENCE_BYTES, "exactly 16384 bytes is served");
        let over = Item::new(vec![0; MAX_EVIDENCE_BYTES + 1], &env);
        assert!(over.oversized());
        assert!(over.raw.is_empty(), "16385 bytes is never held or served");
        assert_eq!((over.size, over.timestamp, over.msg_id), (MAX_EVIDENCE_BYTES + 1, 5, [1; 32]));
    }
}
