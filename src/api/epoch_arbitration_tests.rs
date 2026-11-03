//! Test-only: key-epoch arbitration (l2-node 0.143.0) over the REAL router
//! pipeline and the HTTP handlers — key_status, 409/400/429 bodies, the
//! GET endpoints' membership gate and `proof=1`, the gossip verdict, wire
//! decoding (JS map form + positional array form) — plus the generator of
//! the cross-implementation fixtures in `tests/fixtures/epoch-arbitration/`.
//!
//! Regenerate the fixtures with
//! `OGMARA_REGEN_EPOCH_FIXTURES=1 cargo test epoch_arbitration_golden_vectors`;
//! without the variable the test fails if the committed file differs.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::json;
use tempfile::TempDir;

use crate::api::auth::AuthUser;
use crate::api::routes;
use crate::api::state::AppState;
use crate::crypto::{self, signing};
use crate::messages::envelope::{Envelope, PROTOCOL_VERSION};
use crate::messages::router::{self as router_mod, KeyStatus, MessageRouter, RouteResult};
use crate::messages::types::*;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;
use crate::storage::schema;

const NET: &str = "testnet";
const NODE: &str = "ogmara-test-node";
/// Fixed fixture timestamp (2026-09-21); live-path tests use `now()`.
const T: u64 = 1_790_000_000_000;
const COMMIT_DOMAIN: &[u8] = b"ogmara-chankey-commit-v1";

#[derive(Clone)]
struct Key {
    seed: [u8; 32],
    sk: SigningKey,
    addr: String,
}

fn wallet(seed: u8) -> Key {
    let seed = [seed; 32];
    let sk = SigningKey::from_bytes(&seed);
    let addr = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
    Key { seed, sk, addr }
}

fn device(seed: u8) -> Key {
    let seed = [seed; 32];
    let sk = SigningKey::from_bytes(&seed);
    let addr = crypto::device_pubkey_to_address(&sk.verifying_key()).unwrap();
    Key { seed, sk, addr }
}

fn pub_hex(k: &Key) -> String {
    hex::encode(k.sk.verifying_key().to_bytes())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// `keccak256("ogmara-chankey-commit-v1" || scope || epoch_be8 ||
/// key_ts_be8 || key)` — the client-side commitment (the node never computes
/// it in production). `key_ts` is bound into the hash so a pair
/// `(key_ts, C)` cannot be re-ranked by changing `key_ts` alone.
fn key_commitment(scope: &[u8; 32], epoch: u64, key_ts: u64, key: &[u8; 32]) -> [u8; 32] {
    crypto::keccak256(&commitment_preimage(scope, epoch, key_ts, key))
}

fn commitment_preimage(scope: &[u8; 32], epoch: u64, key_ts: u64, key: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(COMMIT_DOMAIN.len() + 80);
    v.extend_from_slice(COMMIT_DOMAIN);
    v.extend_from_slice(scope);
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(&key_ts.to_be_bytes());
    v.extend_from_slice(key);
    v
}

// --- minimal MessagePack writer reproducing @msgpack/msgpack's output ---

fn mp_map(out: &mut Vec<u8>, n: usize) {
    assert!(n < 16);
    out.push(0x80 | n as u8);
}
fn mp_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    if b.len() < 32 {
        out.push(0xa0 | b.len() as u8);
    } else {
        assert!(b.len() < 256);
        out.extend_from_slice(&[0xd9, b.len() as u8]);
    }
    out.extend_from_slice(b);
}
fn mp_bin(out: &mut Vec<u8>, b: &[u8]) {
    assert!(b.len() < 256);
    out.extend_from_slice(&[0xc4, b.len() as u8]);
    out.extend_from_slice(b);
}
fn mp_uint(out: &mut Vec<u8>, v: u64) {
    if v < 0x80 {
        out.push(v as u8);
    } else if v <= 0xff {
        out.extend_from_slice(&[0xcc, v as u8]);
    } else if v <= 0xffff {
        out.push(0xcd);
        out.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xffff_ffff {
        out.push(0xce);
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Fields of a channel-scope key envelope payload.
#[derive(Clone)]
struct KeyPayload {
    scope: [u8; 32],
    epoch: u64,
    target: String,
    device_id: String,
    channel_id: u64,
    eph_pub: [u8; 32],
    nonce: [u8; 24],
    wrapped: Vec<u8>,
    commit: Option<([u8; 32], u64)>,
}

/// Payload bytes exactly as sdk-js `buildChannelKeyEnvelope` emits them
/// (`@msgpack/msgpack`, insertion-ordered map, `Uint8Array` → bin,
/// `peer: null` → nil, integers as the smallest uint).
fn js_payload(p: &KeyPayload) -> Vec<u8> {
    let mut o = Vec::new();
    mp_map(&mut o, if p.commit.is_some() { 12 } else { 10 });
    mp_str(&mut o, "key_scope");
    mp_bin(&mut o, &p.scope);
    mp_str(&mut o, "scope_kind");
    mp_uint(&mut o, 1);
    mp_str(&mut o, "epoch");
    mp_uint(&mut o, p.epoch);
    mp_str(&mut o, "target");
    mp_str(&mut o, &p.target);
    mp_str(&mut o, "device_id");
    mp_str(&mut o, &p.device_id);
    mp_str(&mut o, "peer");
    o.push(0xc0);
    mp_str(&mut o, "channel_id");
    mp_uint(&mut o, p.channel_id);
    mp_str(&mut o, "eph_pub");
    mp_bin(&mut o, &p.eph_pub);
    mp_str(&mut o, "nonce");
    mp_bin(&mut o, &p.nonce);
    mp_str(&mut o, "wrapped");
    mp_bin(&mut o, &p.wrapped);
    if let Some((c, kts)) = p.commit {
        mp_str(&mut o, "key_commitment");
        mp_bin(&mut o, &c);
        mp_str(&mut o, "key_ts");
        mp_uint(&mut o, kts);
    }
    o
}

/// Sign an envelope (Ogmara format) over raw payload bytes.
fn sign_env(k: &Key, msg_type: MessageType, payload: Vec<u8>, ts: u64) -> Vec<u8> {
    let pk = k.sk.verifying_key().to_bytes();
    let msg_id = crypto::compute_msg_id(NET, &pk, &payload, ts);
    let sig = signing::sign_ogmara_message(&k.sk, NET, PROTOCOL_VERSION, msg_type as u8, &msg_id, ts, &payload);
    rmp_serde::to_vec_named(&Envelope {
        version: PROTOCOL_VERSION,
        msg_type,
        msg_id,
        author: k.addr.clone(),
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: sig.to_bytes().to_vec(),
        relay_path: vec![],
    })
    .unwrap()
}

fn msg_id_of(raw: &[u8]) -> [u8; 32] {
    rmp_serde::from_slice::<Envelope>(raw).unwrap().msg_id
}

/// A dual-signed DeviceDelegation (wallet authorizes, device PoP).
fn delegation(w: &Key, dev: &Key, ts: u64) -> Vec<u8> {
    let claim = crate::network::private_channel_sync::device_delegation_claim_string(NET, &pub_hex(dev), &w.addr, ts);
    let p = DeviceDelegationPayload {
        device_pub_key: pub_hex(dev),
        permissions: DelegationPermissions {
            can_send_messages: true,
            can_create_channels: true,
            can_update_profile: true,
        },
        expires_at: None,
        device_signature: hex::encode(signing::sign_klever_message(&dev.sk, claim.as_bytes()).to_bytes()),
    };
    let payload = rmp_serde::to_vec_named(&p).unwrap();
    let pk = w.sk.verifying_key().to_bytes();
    let msg_id = crypto::compute_msg_id(NET, &pk, &payload, ts);
    rmp_serde::to_vec_named(&Envelope {
        version: PROTOCOL_VERSION,
        msg_type: MessageType::DeviceDelegation,
        msg_id,
        author: w.addr.clone(),
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: signing::sign_klever_message(&w.sk, claim.as_bytes()).to_bytes().to_vec(),
        relay_path: vec![],
    })
    .unwrap()
}

fn router() -> (MessageRouter, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let identity = IdentityResolver::new(storage.clone());
    (
        MessageRouter::new(
            storage,
            identity,
            None,
            NET.to_string(),
            usize::MAX,
            Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        ),
        dir,
    )
}

/// Seed a channel (`channel_type`, floor) + members directly.
fn seed_channel(s: &Storage, cid: u64, channel_type: u8, floor: u64, members: &[&str]) {
    let meta = json!({ "channel_id": cid, "channel_type": channel_type, "creator": members[0], "key_epoch_floor": floor });
    s.put_cf(schema::cf::CHANNELS, &cid.to_be_bytes(), meta.to_string().as_bytes()).unwrap();
    for m in members {
        s.put_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(cid, m), b"{}").unwrap();
    }
}

const CID: u64 = 9_000_000_123;

fn payload_for(target: &Key, epoch: u64, dev_seed: u8, commit: Option<([u8; 32], u64)>) -> KeyPayload {
    KeyPayload {
        scope: crypto::compute_channel_scope(CID),
        epoch,
        target: target.addr.clone(),
        device_id: hex::encode(SigningKey::from_bytes(&[dev_seed; 32]).verifying_key().to_bytes()),
        channel_id: CID,
        eph_pub: [dev_seed; 32],
        nonce: [7; 24],
        wrapped: vec![dev_seed; 48],
        commit,
    }
}

fn key_env(author: &Key, p: &KeyPayload, ts: u64) -> Vec<u8> {
    sign_env(author, MessageType::ChannelKeyEnvelope, js_payload(p), ts)
}

fn rejection_code(res: &RouteResult) -> Option<String> {
    match res {
        RouteResult::Rejected(r) => router_mod::parse_key_envelope_rejection(r).map(|(c, _)| c.to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Router pipeline
// ---------------------------------------------------------------------

#[test]
fn pipeline_arbitrates_reports_key_status_and_conflicts() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let scope = crypto::compute_channel_scope(CID);
    let ca = key_commitment(&scope, 1, ts - 1000, &[0xaa; 32]);
    let cb = key_commitment(&scope, 1, ts - 500, &[0xbb; 32]);
    // b's key ranks worse (later key_ts).
    let first = key_env(&a, &payload_for(&b, 1, 10, Some((ca, ts - 1000))), ts);
    match r.process_message(&first) {
        RouteResult::Accepted { key_status, .. } => assert_eq!(key_status, Some(KeyStatus::Stored)),
        o => panic!("{o:?}"),
    }
    let worse = key_env(&b, &payload_for(&a, 1, 11, Some((cb, ts - 500))), ts);
    match r.process_message(&worse) {
        RouteResult::KeyConflict(info) => {
            assert_eq!((info.channel_id, info.epoch, info.state), (CID, 1, "arbitrated"));
            assert_eq!(info.winner.key_commitment, ca);
            assert_eq!(info.winner.msg_id, Some(msg_id_of(&first)));
            assert!(!info.winner.is_final);
        }
        o => panic!("{o:?}"),
    }
    assert!(!r.storage().message_exists(&msg_id_of(&worse)).unwrap(), "a conflict stores nothing");
    // Same key, another device of b → stored; exact resubmission → duplicate.
    let again = key_env(&a, &payload_for(&b, 1, 12, Some((ca, ts - 1000))), ts);
    assert!(matches!(r.process_message(&again), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
    assert!(matches!(r.process_message(&first), RouteResult::Duplicate));
    // Same (target, device) slot, different envelope of the winning key.
    let same_slot = key_env(&a, &payload_for(&b, 1, 10, Some((ca, ts - 1000))), ts + 1);
    assert!(matches!(
        r.process_message(&same_slot),
        RouteResult::Accepted { key_status: Some(KeyStatus::AlreadyPresent), .. }
    ));
    // The stored record carries the arbitration fields.
    let rec = r
        .storage()
        .get_channel_key_envelope(&scope, &b.addr, "", &payload_for(&b, 1, 10, None).device_id, 1)
        .unwrap()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&rec).unwrap();
    assert_eq!(v["key_commitment"], hex::encode(ca));
    assert_eq!(v["key_ts"], ts - 1000);
    assert_eq!(v["msg_id"], hex::encode(msg_id_of(&first)));
}

#[test]
fn pipeline_better_rank_supersedes_within_finality() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let scope = crypto::compute_channel_scope(CID);
    let ca = key_commitment(&scope, 1, ts - 100, &[0xaa; 32]);
    let cb = key_commitment(&scope, 1, ts - 5000, &[0xbb; 32]);
    let a_env = key_env(&a, &payload_for(&b, 1, 10, Some((ca, ts - 100))), ts);
    assert!(matches!(r.process_message(&a_env), RouteResult::Accepted { .. }));
    let b_env = key_env(&b, &payload_for(&b, 1, 10, Some((cb, ts - 5000))), ts);
    assert!(matches!(r.process_message(&b_env), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
    let view = r.storage().key_commit_view(&scope, 1).unwrap();
    assert_eq!(view.record.unwrap().c, Some(hex::encode(cb)));
}

#[test]
fn pipeline_commitment_validation_codes() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 3, &[&a.addr, &b.addr]);
    let ts = now();
    let c = [9u8; 32];
    // Commitment-less at a fresh epoch (STRICT policy).
    let res = r.process_message(&key_env(&a, &payload_for(&b, 3, 10, None), ts));
    assert_eq!(rejection_code(&res).as_deref(), Some("key_commitment_required"));
    // All-zero commitment.
    let res = r.process_message(&key_env(&a, &payload_for(&b, 3, 10, Some(([0; 32], ts))), ts));
    assert_eq!(rejection_code(&res).as_deref(), Some("key_commitment_invalid"));
    // key_ts after the envelope / zero.
    let res = r.process_message(&key_env(&a, &payload_for(&b, 3, 10, Some((c, ts + 1))), ts));
    assert_eq!(rejection_code(&res).as_deref(), Some("key_commitment_invalid"));
    let res = r.process_message(&key_env(&a, &payload_for(&b, 3, 10, Some((c, 0))), ts));
    assert_eq!(rejection_code(&res).as_deref(), Some("key_commitment_invalid"));
    // Only one of the pair (hand-built map with key_commitment but no key_ts).
    let mut p = js_payload(&payload_for(&b, 3, 10, None));
    p[0] = 0x80 | 11;
    mp_str(&mut p, "key_commitment");
    mp_bin(&mut p, &c);
    let res = r.process_message(&sign_env(&a, MessageType::ChannelKeyEnvelope, p, ts));
    assert_eq!(rejection_code(&res).as_deref(), Some("key_commitment_invalid"));
    // Private channel: below key_epoch_floor (3).
    let res = r.process_message(&key_env(&a, &payload_for(&b, 2, 10, Some((c, ts))), ts));
    assert_eq!(rejection_code(&res).as_deref(), Some("key_epoch_below_floor"));
    // key_ts more than 15 min before the envelope, not the winner → stale.
    let old = ts - crate::storage::key_commits::KEY_TS_MAX_AGE_MS - 1;
    let res = r.process_message(&key_env(&a, &payload_for(&b, 3, 10, Some((c, old))), ts));
    assert_eq!(rejection_code(&res).as_deref(), Some("key_ts_stale"));
    // At the floor: accepted.
    assert!(matches!(r.process_message(&key_env(&a, &payload_for(&b, 3, 10, Some((c, ts))), ts)), RouteResult::Accepted { .. }));
}

#[test]
fn dm_scope_ignores_commitment_fields() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    let p = ChannelKeyEnvelopePayload {
        key_scope: crypto::compute_conversation_id(&a.addr, &b.addr),
        scope_kind: key_scope_kind::DM,
        epoch: 1,
        target: b.addr.clone(),
        device_id: "ab".repeat(32),
        peer: Some(b.addr.clone()),
        channel_id: None,
        eph_pub: [3; 32],
        nonce: [4; 24],
        wrapped: vec![5; 48],
        key_commitment: Some([0; 32]),
        key_ts: Some(u64::MAX),
    };
    let raw = sign_env(&a, MessageType::ChannelKeyEnvelope, rmp_serde::to_vec_named(&p).unwrap(), now());
    match r.process_message(&raw) {
        RouteResult::Accepted { key_status, .. } => assert_eq!(key_status, None),
        o => panic!("{o:?}"),
    }
    let rec = r.storage().get_channel_key_envelope(&p.key_scope, &b.addr, &a.addr, &p.device_id, 1).unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&rec).unwrap();
    assert_eq!(v["msg_id"], hex::encode(msg_id_of(&raw)), "DM records gain msg_id too");
}

#[test]
fn key_envelope_rate_limit_carries_retry_after() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    // Five channels: the per-(wallet, scope) budget is 60/min, the
    // per-wallet one 240/min across all scopes.
    for k in 0..5 {
        seed_channel(r.storage(), CID + k, 2, 0, &[&a.addr, &b.addr]);
    }
    let ts = now();
    let c = [9u8; 32];
    let send = |cid: u64, i: u32| {
        let mut p = payload_for(&b, 1, 10, Some((c, ts)));
        p.channel_id = cid;
        p.scope = crypto::compute_channel_scope(cid);
        p.device_id = format!("{:064x}", i + 1);
        r.process_message(&key_env(&a, &p, ts))
    };
    // Per scope: 60 accepted, the 61st limited (429-mapped reason).
    for i in 0..60 {
        assert!(matches!(send(CID, i), RouteResult::Accepted { .. }), "#{i}");
    }
    match send(CID, 60) {
        RouteResult::Rejected(reason) => {
            let retry = router_mod::parse_key_envelope_retry_after(&reason).expect("KeyEnvelope prefix");
            assert!((1..=60_001).contains(&retry), "{retry}");
        }
        o => panic!("{o:?}"),
    }
    // Per wallet: 240 per minute across all scopes. The per-scope refusal
    // above consumed NOTHING (both buckets are checked before either is
    // counted), so 60 of the wallet's 240 are used.
    let mut accepted_steps = 60u32;
    let mut limited = None;
    'outer: for k in 1..5u64 {
        for i in 0..60u32 {
            match send(CID + k, 1000 + i) {
                RouteResult::Accepted { .. } => accepted_steps += 1,
                RouteResult::Rejected(reason) => {
                    limited = Some(reason);
                    break 'outer;
                }
                o => panic!("{o:?}"),
            }
        }
    }
    assert_eq!(accepted_steps, 240, "240 per minute per wallet");
    let reason = limited.expect("per-wallet limit engages");
    assert!(router_mod::parse_key_envelope_retry_after(&reason).is_some());
    // Other categories keep the plain reason.
    assert_eq!(router_mod::parse_key_envelope_retry_after("rate limited (Other)"), None);
}

/// Key envelopes relayed by GOSSIP are exempt from the home node's
/// fixed-window budgets and only meet the wider gossip TOKEN buckets
/// (per wallet:scope capacity 180, +1/s): 180 pass (more than the 120 a
/// home node can admit in any 60 s span), the flood beyond is refused, and
/// the wallet's LOCAL budget is untouched (round-3 W2 / round-4 W1a).
#[test]
fn gossip_key_envelopes_use_token_buckets_not_home_windows() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let c = [9u8; 32];
    for i in 0..180u32 {
        let mut p = payload_for(&b, 1, 10, Some((c, ts)));
        p.device_id = format!("{:064x}", i + 1);
        assert!(
            matches!(r.process_gossip_message_at(&key_env(&a, &p, ts), ts), RouteResult::Accepted { .. }),
            "gossip #{i}"
        );
    }
    let mut p = payload_for(&b, 1, 10, Some((c, ts)));
    p.device_id = format!("{:064x}", 5000);
    match r.process_gossip_message_at(&key_env(&a, &p, ts), ts) {
        RouteResult::Rejected(reason) => assert_eq!(reason, crate::messages::router::GOSSIP_KEY_RATE_LIMITED_REASON),
        o => panic!("{o:?}"),
    }
    // The same wallet's LOCAL ingress budget is untouched by that traffic.
    let mut p = payload_for(&b, 1, 10, Some((c, ts)));
    p.device_id = format!("{:064x}", 9999);
    assert!(matches!(r.process_message_at(&key_env(&a, &p, ts), ts), RouteResult::Accepted { .. }));
}

/// Round-4 audit W1b: a wrap for an already-filled slot is not stored in
/// MESSAGES and not relayed (gossip verdict Ignore), so replays cannot grow
/// the database.
#[test]
fn already_present_wraps_are_neither_stored_nor_relayed() {
    use libp2p::gossipsub::MessageAcceptance;
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let c = [9u8; 32];
    let first = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts);
    assert!(matches!(r.process_message(&first), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
    let replay = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts + 1);
    let res = r.process_gossip_message_at(&replay, ts + 1);
    assert!(matches!(res, RouteResult::Accepted { key_status: Some(KeyStatus::AlreadyPresent), .. }));
    assert!(matches!(crate::network::gossip_acceptance_for(&res), MessageAcceptance::Ignore));
    assert!(!r.storage().message_exists(&msg_id_of(&replay)).unwrap(), "not stored");
    assert!(r.storage().message_exists(&msg_id_of(&first)).unwrap());
}

/// Round-2 audit W-C: a channel key envelope arriving over a sync path is
/// only accepted when it wraps the recorded winner; the reconcile pre-check
/// refuses key envelopes outright.
#[test]
fn sync_paths_only_carry_known_winner_wraps() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let c = [9u8; 32];
    // A back-dated pair via sync on a node that never saw the epoch.
    let backdated = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts - 3_600_000))), ts - 3_600_000);
    assert_eq!(rejection_code(&r.process_synced_message(&backdated)).as_deref(), Some("key_sync_not_winner"));
    // Reconcile never even hands a key envelope to the router.
    assert!(!crate::network::envelope_targets_channel_for_tests(&backdated, CID));
    // Once the epoch is established live, another cover of THAT pair via
    // sync is fine.
    assert!(matches!(r.process_message(&key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts)), RouteResult::Accepted { .. }));
    assert!(matches!(
        r.process_synced_message(&key_env(&a, &payload_for(&b, 1, 11, Some((c, ts))), ts)),
        RouteResult::Accepted { .. }
    ));
}

#[test]
fn gossip_maps_key_conflict_to_ignore() {
    use libp2p::gossipsub::MessageAcceptance;
    let info = router_mod::KeyConflictInfo {
        channel_id: 1,
        epoch: 1,
        state: "arbitrated",
        winner: crate::storage::key_commits::KeyCommitWinner {
            key_commitment: [1; 32],
            key_ts: 1,
            author: None,
            msg_id: None,
            is_final: true,
        },
    };
    let v = crate::network::gossip_acceptance_for(&RouteResult::KeyConflict(Box::new(info)));
    assert!(matches!(v, MessageAcceptance::Ignore));
    assert!(matches!(crate::network::gossip_acceptance_for(&RouteResult::Invalid("x".into())), MessageAcceptance::Reject));
    assert!(matches!(crate::network::gossip_acceptance_for(&RouteResult::Rejected("x".into())), MessageAcceptance::Ignore));
    assert!(matches!(crate::network::gossip_acceptance_for(&RouteResult::Duplicate), MessageAcceptance::Ignore));
}

// ---------------------------------------------------------------------
// Wire decoding
// ---------------------------------------------------------------------

#[test]
fn decodes_js_map_form_and_positional_array_forms() {
    let a = wallet(2);
    let p = payload_for(&a, 5, 10, Some(([0x42; 32], T)));
    // JS map form (bin32 commitment, uint64 key_ts).
    let d: ChannelKeyEnvelopePayload = rmp_serde::from_slice(&js_payload(&p)).unwrap();
    assert_eq!(d.key_commitment, Some([0x42; 32]));
    assert_eq!(d.key_ts, Some(T));
    assert_eq!(d.channel_id, Some(CID));
    assert_eq!(d.peer, None);
    // Commitment-less JS map.
    let d: ChannelKeyEnvelopePayload = rmp_serde::from_slice(&js_payload(&payload_for(&a, 5, 10, None))).unwrap();
    assert_eq!((d.key_commitment, d.key_ts), (None, None));
    // Frozen pre-0.143 positional (array) form: 10 elements.
    #[derive(serde::Serialize)]
    struct Legacy {
        key_scope: [u8; 32],
        scope_kind: u8,
        epoch: u64,
        target: String,
        device_id: String,
        peer: Option<String>,
        channel_id: Option<u64>,
        eph_pub: [u8; 32],
        nonce: [u8; 24],
        wrapped: Vec<u8>,
    }
    let legacy = rmp_serde::to_vec(&Legacy {
        key_scope: p.scope,
        scope_kind: 1,
        epoch: 5,
        target: p.target.clone(),
        device_id: p.device_id.clone(),
        peer: None,
        channel_id: Some(CID),
        eph_pub: p.eph_pub,
        nonce: p.nonce,
        wrapped: p.wrapped.clone(),
    })
    .unwrap();
    assert_eq!(legacy[0], 0x9a, "10-element fixarray");
    let d: ChannelKeyEnvelopePayload = rmp_serde::from_slice(&legacy).unwrap();
    assert_eq!((d.epoch, d.key_commitment, d.key_ts), (5, None, None));
    // Full 12-element positional form round-trips.
    let mut full = d.clone();
    full.key_commitment = Some([1; 32]);
    full.key_ts = Some(T);
    let arr = rmp_serde::to_vec(&full).unwrap();
    assert_eq!(arr[0], 0x9c, "12-element fixarray");
    let d2: ChannelKeyEnvelopePayload = rmp_serde::from_slice(&arr).unwrap();
    assert_eq!((d2.key_commitment, d2.key_ts), (Some([1; 32]), Some(T)));
    // The gossip topic router decodes both forms (narrow-probe regression).
    for bytes in [js_payload(&p), arr] {
        let env = Envelope {
            version: PROTOCOL_VERSION,
            msg_type: MessageType::ChannelKeyEnvelope,
            msg_id: [0; 32],
            author: a.addr.clone(),
            timestamp: T,
            lamport_ts: 0,
            payload: bytes,
            signature: vec![0; 64],
            relay_path: vec![],
        };
        assert_eq!(
            routes::gossip_topic_for_envelope(&env, NET),
            Some(crate::network::gossip::channel_topic(NET, CID))
        );
    }
}

// ---------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------

fn state_for(r: MessageRouter) -> Arc<AppState> {
    let storage = r.storage().clone();
    let identity = r.identity().clone();
    Arc::new(AppState::new(
        storage, r, NODE.to_string(), NET.to_string(), String::new(), String::new(), None, identity, None, None, None,
    ))
}

fn auth(k: &Key) -> Extension<AuthUser> {
    Extension(AuthUser { address: k.addr.clone(), signing_address: k.addr.clone() })
}

async fn body_of(res: axum::response::Response) -> (StatusCode, Vec<u8>) {
    let status = res.status();
    (status, axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap().to_vec())
}

async fn post(state: &Arc<AppState>, k: &Key, raw: Vec<u8>) -> (StatusCode, Vec<u8>) {
    body_of(
        routes::post_message(Extension(state.clone()), auth(k), axum::body::Bytes::from(raw))
            .await
            .into_response(),
    )
    .await
}

#[tokio::test]
async fn post_message_response_shapes() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let state = state_for(r);
    let ts = now();
    let (ca, cb) = ([0x0a; 32], [0x0b; 32]);
    // 200 with key_status.
    let first = key_env(&a, &payload_for(&b, 1, 10, Some((ca, ts - 1000))), ts);
    let (st, body) = post(&state, &a, first.clone()).await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["key_status"], "stored");
    // Duplicate: the PLAIN-TEXT 409 (stored = success for the SDK).
    let (st, body) = post(&state, &a, first.clone()).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(body, b"message already exists");
    // Arbitration conflict: a DISTINCT JSON 409 naming the winner.
    let (st, body) = post(&state, &b, key_env(&b, &payload_for(&a, 1, 11, Some((cb, ts))), ts)).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"], "key_commitment_conflict");
    assert_eq!(v["channel_id"], CID);
    assert_eq!(v["epoch"], 1);
    assert_eq!(v["state"], "arbitrated");
    assert_eq!(v["winner"]["key_commitment"], hex::encode(ca));
    assert_eq!(v["winner"]["key_ts"], ts - 1000);
    assert_eq!(v["winner"]["author"], a.addr);
    assert_eq!(v["winner"]["msg_id"], hex::encode(msg_id_of(&first)));
    assert_eq!(v["winner"]["final"], false);
    // 400 JSON code.
    let (st, body) = post(&state, &a, key_env(&a, &payload_for(&b, 2, 10, None), ts)).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"], "key_commitment_required");
    // 429 with retry_after_ms once the KeyEnvelope budget is spent (3 used).
    let mut got = None;
    for i in 0..300u32 {
        let mut p = payload_for(&b, 1, 10, Some((ca, ts - 1000)));
        p.device_id = format!("{:064x}", i + 100);
        let (st, body) = post(&state, &a, key_env(&a, &p, ts)).await;
        if st == StatusCode::TOO_MANY_REQUESTS {
            got = Some(body);
            break;
        }
        assert_eq!(st, StatusCode::OK);
    }
    let v: serde_json::Value = serde_json::from_slice(&got.expect("429")).unwrap();
    assert_eq!(v["error"], "rate_limited");
    assert!(v["retry_after_ms"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn get_key_commitment_is_member_only() {
    let (r, _d) = router();
    let (a, b, outsider) = (wallet(1), wallet(2), wallet(3));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let c = [0x0c; 32];
    let env1 = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts - 10))), ts);
    assert!(matches!(r.process_message(&env1), RouteResult::Accepted { .. }));
    let state = state_for(r);
    let get = |k: Key, cid: u64, epoch: Option<u64>| {
        let state = state.clone();
        async move {
            body_of(
                routes::get_key_commitment(
                    Extension(state),
                    auth(&k),
                    Path(cid),
                    Query(routes::KeyCommitmentParams { epoch }),
                )
                .await
                .into_response(),
            )
            .await
        }
    };
    assert_eq!(get(outsider.clone(), CID, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get(a.clone(), CID + 1, None).await.0, StatusCode::NOT_FOUND);
    let (st, body) = get(b.clone(), CID, None).await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["epoch"], 1, "omitted epoch = highest");
    assert_eq!(v["state"], "arbitrated");
    assert_eq!(v["key_commitment"], hex::encode(c));
    assert_eq!(v["key_ts"], ts - 10);
    assert_eq!(v["author"], a.addr);
    assert_eq!(v["msg_id"], hex::encode(msg_id_of(&env1)));
    assert_eq!(v["final"], false);
    assert_eq!(v["finality_ms"], 120_000);
    let (_, body) = get(b, CID, Some(7)).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((v["state"].as_str(), v["final"].as_bool()), (Some("none"), Some(false)));
}

#[tokio::test]
async fn get_key_commitment_reports_legacy_as_final() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let scope = crypto::compute_channel_scope(CID);
    // A pre-0.143 row at epoch 5 (no commit row, no msg_id).
    let k = schema::encode_channel_key(&scope, &b.addr, "", &"ab".repeat(32), 5);
    r.storage().put_cf(schema::cf::CHANNEL_KEYS, &k, br#"{"scope_kind":1}"#).unwrap();
    let state = state_for(r);
    let (st, body) = body_of(
        routes::get_key_commitment(
            Extension(state),
            auth(&b),
            Path(CID),
            Query(routes::KeyCommitmentParams { epoch: None }),
        )
        .await
        .into_response(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["epoch"], 5);
    assert_eq!(v["state"], "legacy");
    assert_eq!(v["final"], true, "a legacy epoch can never be re-arbitrated");
    assert!(v["key_commitment"].is_null());
}

#[tokio::test]
async fn get_keys_proof_serves_signed_envelope_and_device_claim() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    let dev = device(40);
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    assert!(matches!(r.process_message(&delegation(&a, &dev, ts - 1)), RouteResult::Accepted { .. }));
    // Device-signed wrap (resolves to wallet a) for b's device 10.
    let p = payload_for(&b, 1, 10, Some(([0x0d; 32], ts - 10)));
    let raw = sign_env(&dev, MessageType::ChannelKeyEnvelope, js_payload(&p), ts);
    assert!(matches!(r.process_message(&raw), RouteResult::Accepted { .. }), "device-signed accepted");
    let state = state_for(r);
    let scope_hex = hex::encode(p.scope);
    let fetch = |proof: Option<&str>| {
        let state = state.clone();
        let params = routes::KeyEnvelopeParams {
            epoch: None,
            device_id: p.device_id.clone(),
            author: Some(String::new()),
            proof: proof.map(str::to_string),
        };
        let b = b.clone();
        let scope_hex = scope_hex.clone();
        async move {
            body_of(
                routes::get_key_envelope(Extension(state), auth(&b), Path(scope_hex), Query(params))
                    .await
                    .into_response(),
            )
            .await
        }
    };
    let (st, body) = fetch(Some("1")).await;
    assert_eq!(st, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let env = &v["envelope"];
    assert_eq!(env["key_commitment"], hex::encode([0x0d; 32]));
    let signed = base64::engine::general_purpose::STANDARD
        .decode(env["signed_envelope"].as_str().unwrap())
        .unwrap();
    assert_eq!(signed, raw, "exact stored bytes");
    assert_eq!(env["device_claim"]["device_address"], dev.addr);
    assert_eq!(env["device_claim"]["wallet"], a.addr);
    assert_eq!(env["device_claim"]["delegations"].as_array().unwrap().len(), 1);
    // Without proof=1 the record is unchanged.
    let (_, body) = fetch(None).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["envelope"].get("signed_envelope").is_none());
}

#[tokio::test]
async fn health_advertises_key_commitment_feature() {
    let (r, _d) = router();
    let state = state_for(r);
    let res = routes::health(Extension(state)).await.into_response();
    let (_, body) = body_of(res).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["features"], json!(["key_commitment_v1"]));
}

/// Pins the key-commitment known-answer vectors (key_ts bound into the
/// hash, l2-node 0.143.0 audit B2). The values were cross-checked against an
/// independent Keccak-256 (`@noble/hashes` `keccak_256`); sdk-js
/// `channelKeyCommit.test.ts` and spec 01 §8.1 must carry the same ones.
#[test]
fn key_commitment_kat() {
    assert_eq!(
        hex::encode(crypto::compute_channel_scope(4_294_967_297)),
        "7085627c18f35c684cf3c70bf45ace585fea2da90932c1a52da8992cc9bdc952"
    );
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_eq!(
        hex::encode(key_commitment(&crypto::compute_channel_scope(4_294_967_297), 7, KAT_KEY_TS, &key)),
        KAT_VECTOR_1
    );
    assert_eq!(hex::encode(key_commitment(&[0; 32], 1, 1, &[0; 32])), KAT_VECTOR_2);
}

/// `key_ts` of KAT vector 1 (2026-09-21T…, an ordinary ms timestamp).
const KAT_KEY_TS: u64 = 1_790_000_000_000;
/// scope(2^32+1), epoch 7, key_ts `KAT_KEY_TS`, key `00..1f`.
const KAT_VECTOR_1: &str = "8016166a572c3b83cf9547a51877d8f7bd66ee26ac19d2ca74c74fe55268a5d4";
/// scope 32×00, epoch 1, key_ts 1, key 32×00.
const KAT_VECTOR_2: &str = "bcd39e590bd58ecaf69b25e13032a70829f47e98c1f33d20d976dd2ed9208d32";

// ---------------------------------------------------------------------
// Golden vectors (tests/fixtures/epoch-arbitration/vectors.json)
// ---------------------------------------------------------------------

#[test]
fn epoch_arbitration_golden_vectors() {
    let creator = wallet(0x11);
    let member = wallet(0x22);
    let kat_inputs: [(u64, u64, u64, [u8; 32]); 3] = [
        (CID, 1, 1, [0x00; 32]),
        (CID, 2, T - 1_000, [0x5a; 32]),
        // KAT vector 1 (channel_id 2^32+1, epoch 7, key_ts KAT_KEY_TS, key 0..31).
        (4_294_967_297, 7, KAT_KEY_TS, {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = i as u8;
            }
            k
        }),
    ];
    let kats: Vec<serde_json::Value> = kat_inputs
        .iter()
        .map(|(cid, epoch, key_ts, key)| {
            let scope = crypto::compute_channel_scope(*cid);
            json!({
                "channel_id": cid,
                "key_scope_hex": hex::encode(scope),
                "epoch": epoch,
                "key_ts": key_ts,
                "channel_key_hex": hex::encode(key),
                "preimage_hex": hex::encode(commitment_preimage(&scope, *epoch, *key_ts, key)),
                "key_commitment_hex": hex::encode(key_commitment(&scope, *epoch, *key_ts, key)),
            })
        })
        .collect();

    // A valid, signed epoch-key envelope (JS map-form payload).
    let channel_key = [0x5a; 32];
    let scope = crypto::compute_channel_scope(CID);
    let commit = key_commitment(&scope, 2, T - 1_000, &channel_key);
    let p = KeyPayload {
        commit: Some((commit, T - 1_000)),
        ..payload_for(&member, 2, 0x33, None)
    };
    let payload = js_payload(&p);
    let raw = key_env(&creator, &p, T);
    let env: Envelope = rmp_serde::from_slice(&raw).unwrap();
    // Every vector is verified against the node: submitted on a fresh router
    // through the LIVE pipeline at a fixed node clock (T + 1 s), since only
    // live ingestion may establish an epoch (sync accepts winner wraps only).
    let (r, _d) = router();
    seed_channel(r.storage(), CID, 2, 0, &[&creator.addr, &member.addr]);
    assert!(matches!(r.process_message_at(&raw, T + 1_000), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
    // A worse-ranked competitor for the same epoch → conflict.
    let rival_key = [0x77; 32];
    let rival = KeyPayload { commit: Some((key_commitment(&scope, 2, T - 500, &rival_key), T - 500)), ..payload_for(&creator, 2, 0x44, None) };
    let rival_raw = key_env(&member, &rival, T);
    assert!(matches!(r.process_message_at(&rival_raw, T + 1_000), RouteResult::KeyConflict(_)));
    let legacy_raw = key_env(&creator, &payload_for(&member, 3, 0x33, None), T);
    assert_eq!(rejection_code(&r.process_message_at(&legacy_raw, T + 1_000)).as_deref(), Some("key_commitment_required"));

    let envelope_case = |name: &str, signer: &Key, p: &KeyPayload, raw: &[u8], expected: serde_json::Value| {
        let e: Envelope = rmp_serde::from_slice(raw).unwrap();
        json!({
            "name": name,
            "signer_seed_hex": hex::encode(signer.seed),
            "author": signer.addr,
            "timestamp": T,
            "payload_fields": {
                "key_scope_hex": hex::encode(p.scope),
                "scope_kind": 1,
                "epoch": p.epoch,
                "target": p.target,
                "device_id": p.device_id,
                "peer": null,
                "channel_id": p.channel_id,
                "eph_pub_hex": hex::encode(p.eph_pub),
                "nonce_hex": hex::encode(p.nonce),
                "wrapped_hex": hex::encode(&p.wrapped),
                "key_commitment_hex": p.commit.map(|c| hex::encode(c.0)),
                "key_ts": p.commit.map(|c| c.1),
            },
            "payload_msgpack_hex": hex::encode(js_payload(p)),
            "msg_id_hex": hex::encode(e.msg_id),
            "signature_hex": hex::encode(&e.signature),
            "envelope_msgpack_hex": hex::encode(raw),
            "expected": expected,
        })
    };
    let doc = json!({
        "format": "ogmara-epoch-arbitration-vectors/1",
        "generated_by": "l2-node api::epoch_arbitration_tests::epoch_arbitration_golden_vectors",
        "network": NET,
        "commitment": {
            "formula": "keccak256(domain || key_scope[32] || epoch_be8 || key_ts_be8 || channel_key[32])",
            "domain_utf8": "ogmara-chankey-commit-v1",
            "kat": kats,
        },
        "rank": {
            "rule": "rank = (key_ts, key_commitment bytes); LOWEST wins (u64 compare, then bytewise)",
            "finality_ms": crate::storage::key_commits::KEY_FINALITY_MS,
            "key_ts_max_age_ms": crate::storage::key_commits::KEY_TS_MAX_AGE_MS,
        },
        "channel": { "channel_id": CID, "channel_type": 2, "members": [creator.addr, member.addr] },
        "envelopes": [
            envelope_case("winner_epoch2", &creator, &p, &raw, json!({ "route": "accepted", "key_status": "stored" })),
            envelope_case("rival_epoch2_worse_rank", &member, &rival, &rival_raw, json!({
                "route": "key_conflict",
                "http_409": key_conflict_example(&commit, &creator.addr, &env.msg_id),
            })),
            envelope_case("commitment_less_new_epoch", &creator, &payload_for(&member, 3, 0x33, None), &legacy_raw,
                json!({ "route": "rejected", "http_400_error": "key_commitment_required" })),
        ],
        "payload_msgpack_note": "payload bytes reproduce sdk-js buildChannelKeyEnvelope (@msgpack/msgpack map, insertion order key_scope, scope_kind, epoch, target, device_id, peer(nil), channel_id, eph_pub, nonce, wrapped, key_commitment, key_ts). msg_id and signature cover ONLY these bytes + author key + timestamp + network, so a JS encoder must match them byte for byte; the outer envelope here is Rust-encoded (to_vec_named) and the node accepts any equivalent outer encoding.",
    });
    let _ = payload;
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epoch-arbitration/vectors.json");
    if std::env::var("OGMARA_REGEN_EPOCH_FIXTURES").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
    } else {
        let committed = std::fs::read_to_string(&path).expect("fixture missing — regenerate with OGMARA_REGEN_EPOCH_FIXTURES=1");
        assert_eq!(committed, text, "fixture drifted — regenerate with OGMARA_REGEN_EPOCH_FIXTURES=1 and review the diff");
    }
}

/// The 409 body the rival vector produces (shape documentation).
fn key_conflict_example(commit: &[u8; 32], author: &str, msg_id: &[u8; 32]) -> serde_json::Value {
    routes::key_conflict_body(&router_mod::KeyConflictInfo {
        channel_id: CID,
        epoch: 2,
        state: "arbitrated",
        winner: crate::storage::key_commits::KeyCommitWinner {
            key_commitment: *commit,
            key_ts: T - 1_000,
            author: Some(author.to_string()),
            msg_id: Some(*msg_id),
            is_final: false,
        },
    })
}

// ---------------------------------------------------------------------
// Round-5 regressions
// ---------------------------------------------------------------------

/// Round-5 audit B1 (auditor reproduction, inverted): a third party that
/// re-submits a victim's already-present wrap over GOSSIP must not burn the
/// victim's gossip token buckets — the replay is answered from the
/// unstored-envelope seen-cache at Step 3 (`Duplicate`).
#[test]
fn r46_replayed_already_present_does_not_burn_victim_gossip_bucket() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let c = [9u8; 32];
    let first = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts);
    assert!(matches!(r.process_message_at(&first, ts), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
    let dup = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts + 1);
    assert!(matches!(
        r.process_gossip_message_at(&dup, ts + 1),
        RouteResult::Accepted { key_status: Some(KeyStatus::AlreadyPresent), .. }
    ));
    for _ in 0..500 {
        assert!(matches!(r.process_gossip_message_at(&dup, ts + 1), RouteResult::Duplicate));
    }
    let mut p = payload_for(&b, 1, 10, Some((c, ts)));
    p.device_id = format!("{:064x}", 4242);
    let res = r.process_gossip_message_at(&key_env(&a, &p, ts + 2), ts + 2);
    assert!(matches!(res, RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }), "{res:?}");
}

/// Same over LOCAL ingress: replays never consume the victim's 60/min
/// per-scope window.
#[test]
fn r46_replayed_already_present_does_not_burn_victim_local_window() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let c = [9u8; 32];
    let first = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts);
    assert!(matches!(r.process_message_at(&first, ts), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
    let dup = key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts + 1);
    assert!(matches!(r.process_message_at(&dup, ts + 1), RouteResult::Accepted { key_status: Some(KeyStatus::AlreadyPresent), .. }));
    for _ in 0..100 {
        assert!(matches!(r.process_message_at(&dup, ts + 1), RouteResult::Duplicate));
    }
    // A conflicting envelope replayed is answered with the SAME conflict
    // (never a Duplicate, which a client would read as success).
    let rival = key_env(&b, &payload_for(&a, 1, 11, Some(([0xee; 32], ts + 5))), ts + 5);
    assert!(matches!(r.process_message_at(&rival, ts + 5), RouteResult::KeyConflict(_)));
    for _ in 0..100 {
        assert!(matches!(r.process_message_at(&rival, ts + 5), RouteResult::KeyConflict(_)));
    }
    // The victim still has its full local budget: 58 more new slots pass
    // (60 per scope minus the first wrap and the already-present one).
    for i in 0..58u32 {
        let mut p = payload_for(&b, 1, 10, Some((c, ts)));
        p.device_id = format!("{:064x}", 10_000 + i);
        let res = r.process_message_at(&key_env(&a, &p, ts + 2), ts + 2);
        assert!(matches!(res, RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }), "#{i}: {res:?}");
    }
}

/// Round-5 audit M8: the REST path must NOT relay an already-present wrap.
#[tokio::test]
async fn rest_does_not_relay_already_present_wraps() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let storage = r.storage().clone();
    let identity = r.identity().clone();
    let mut st = AppState::new(
        storage, r, NODE.to_string(), NET.to_string(), String::new(), String::new(), None, identity, None, None, None,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::network::GossipPublish>();
    st.gossip_tx = tx;
    let state = Arc::new(st);
    // Answer publishes immediately so post_message does not wait.
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = counter.clone();
    tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(tx) = p.respond_to {
                let _ = tx.send(crate::network::PublishOutcome::Propagated);
            }
        }
    });
    let ts = now();
    let c = [9u8; 32];
    let (st1, _) = post(&state, &a, key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts)).await;
    assert_eq!(st1, StatusCode::OK);
    let (st2, body) = post(&state, &a, key_env(&a, &payload_for(&b, 1, 10, Some((c, ts))), ts + 1)).await;
    assert_eq!(st2, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["key_status"], "already_present");
    tokio::task::yield_now().await;
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1, "only the stored wrap was relayed");
}

// ---------------------------------------------------------------------
// Round-6 regressions (seen-cache rules)
// ---------------------------------------------------------------------

/// Round-6 F2 (auditor probe): a key envelope first seen on a SYNC path
/// (refused there: sync carries winner wraps only) must not shadow a later
/// LIVE delivery of the same bytes — sync outcomes are never cached.
#[test]
fn sync_refusal_is_not_cached_for_live() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let env = key_env(&a, &payload_for(&b, 1, 10, Some(([9u8; 32], ts))), ts);
    assert_eq!(rejection_code(&r.process_synced_message(&env)).as_deref(), Some("key_sync_not_winner"));
    assert!(matches!(r.process_message_at(&env, ts), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
}

/// Round-6 F3: `key_ts_stale` is NOT cached — a stale late cover refused
/// before its pair was established is accepted once the pair has won.
#[test]
fn stale_refusal_is_not_cached() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 0, &[&a.addr, &b.addr]);
    let ts = now();
    let kts = ts - crate::storage::key_commits::KEY_TS_MAX_AGE_MS - 1_000;
    let c = [9u8; 32];
    // Late cover (stale relative to key_ts) arrives before the establishing
    // envelope of the same pair.
    let late = key_env(&a, &payload_for(&b, 1, 10, Some((c, kts))), ts);
    assert_eq!(rejection_code(&r.process_message_at(&late, ts)).as_deref(), Some("key_ts_stale"));
    // The pair is established by a fresh envelope (gossip-delayed, timestamp
    // within 15 min of key_ts; evaluated at a node clock inside its drift).
    let est = key_env(&a, &payload_for(&a, 1, 11, Some((c, kts))), kts + 1_000);
    assert!(matches!(r.process_message_at(&est, kts + 1_000), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
    // Now the late cover wraps the WINNER → accepted (not a cached refusal).
    assert!(matches!(r.process_message_at(&late, ts), RouteResult::Accepted { key_status: Some(KeyStatus::Stored), .. }));
}

/// Round-6 M3: a cacheable refusal replayed returns the SAME 400 code (from
/// the cache — the local window is not consumed by the replays).
#[test]
fn cached_refusal_replays_the_same_code() {
    let (r, _d) = router();
    let (a, b) = (wallet(1), wallet(2));
    seed_channel(r.storage(), CID, 2, 5, &[&a.addr, &b.addr]);
    let ts = now();
    let below = key_env(&a, &payload_for(&b, 2, 10, Some(([9u8; 32], ts))), ts);
    for _ in 0..100 {
        assert_eq!(rejection_code(&r.process_message_at(&below, ts)).as_deref(), Some("key_epoch_below_floor"));
    }
    // Only the FIRST evaluation consumed a slot (every outcome after Step 6
    // does); the 99 cached replays consumed nothing: exactly 59 fresh wraps
    // still fit the 60/min scope window, the 60th is limited.
    for i in 0..60u32 {
        let mut p = payload_for(&b, 5, 10, Some(([9u8; 32], ts)));
        p.device_id = format!("{:064x}", 7_000 + i);
        let res = r.process_message_at(&key_env(&a, &p, ts), ts);
        if i < 59 {
            assert!(matches!(res, RouteResult::Accepted { .. }), "#{i}: {res:?}");
        } else {
            assert!(matches!(res, RouteResult::Rejected(ref m) if m.starts_with("rate limited (KeyEnvelope)")), "#{i}: {res:?}");
        }
    }
}

