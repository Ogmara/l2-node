//! Test-only support for the Phase-2 "verify before cover" work (l2-node
//! 0.142.0): deterministic signed-envelope builders, end-to-end tests of
//! `POST /channels/{id}/member-proofs`' builder over the real router
//! pipeline, and the GOLDEN-VECTOR generator whose output
//! (`tests/fixtures/phase2/vectors.json`) the sdk-js verifier must agree
//! with byte for byte and verdict for verdict.
//!
//! Every golden case's `expected` verdict is not hand-written: it is
//! asserted against the NODE's own join gate (`verify_embedded_envelope`
//! and then `verify_private_join`, sync semantics) on a fresh router holding
//! the case's channel state, so the fixture cannot drift from the node rules.
//!
//! Regenerate with `OGMARA_REGEN_PHASE2_FIXTURES=1 cargo test golden_vectors`;
//! without the variable the test fails if the committed file differs.

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::collections::BTreeMap;
use tempfile::TempDir;

use crate::crypto::{self, signing};
use crate::messages::envelope::{Envelope, PROTOCOL_VERSION};
use crate::messages::router::{MessageRouter, RouteResult};
use crate::messages::types::*;
use crate::network::private_channel_sync as pcs;
use crate::storage::identity::IdentityResolver;
use crate::storage::rocks::Storage;
use crate::storage::schema;

const NET: &str = "testnet";
/// Fixed base timestamp (2026-09-21) so every vector is deterministic.
const T: u64 = 1_790_000_000_000;
const MIN: u64 = 60_000;
const DAY: u64 = 24 * 3600 * 1000;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// A deterministic wallet (klv1) or device (ogd1) key.
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

/// Sign an envelope in the Ogmara format on `network`.
fn env_on(network: &str, k: &Key, msg_type: MessageType, payload: Vec<u8>, ts: u64) -> Vec<u8> {
    let pk = k.sk.verifying_key().to_bytes();
    let msg_id = crypto::compute_msg_id(network, &pk, &payload, ts);
    let sig = signing::sign_ogmara_message(&k.sk, network, PROTOCOL_VERSION, msg_type as u8, &msg_id, ts, &payload);
    let env = Envelope {
        version: PROTOCOL_VERSION,
        msg_type,
        msg_id,
        author: k.addr.clone(),
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: sig.to_bytes().to_vec(),
        relay_path: vec![],
    };
    rmp_serde::to_vec_named(&env).unwrap()
}

fn env(k: &Key, msg_type: MessageType, payload: Vec<u8>, ts: u64) -> Vec<u8> {
    env_on(NET, k, msg_type, payload, ts)
}

/// Same, but signed in the Klever-message wrapping (wallet extensions).
fn env_klever(k: &Key, msg_type: MessageType, payload: Vec<u8>, ts: u64) -> Vec<u8> {
    let pk = k.sk.verifying_key().to_bytes();
    let msg_id = crypto::compute_msg_id(NET, &pk, &payload, ts);
    let bytes = signing::ogmara_signed_bytes(NET, PROTOCOL_VERSION, msg_type as u8, &msg_id, ts, &payload);
    let sig = signing::sign_klever_message(&k.sk, &bytes);
    let env = Envelope {
        version: PROTOCOL_VERSION,
        msg_type,
        msg_id,
        author: k.addr.clone(),
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: sig.to_bytes().to_vec(),
        relay_path: vec![],
    };
    rmp_serde::to_vec_named(&env).unwrap()
}

fn mp<P: serde::Serialize>(p: &P) -> Vec<u8> {
    rmp_serde::to_vec_named(p).unwrap()
}

/// A private ChannelCreate with a valid id derivation. Returns (raw, cid).
fn create(creator: &Key, slug: &str, ts: u64) -> (Vec<u8>, u64) {
    let mut dts = ts;
    let cid = loop {
        let h = crypto::keccak256(format!("{}{slug}{dts}", creator.addr).as_bytes());
        let id = u64::from_be_bytes(h[..8].try_into().unwrap()) % ((1u64 << 53) - 1);
        if id > PRIVATE_CHANNEL_ID_FLOOR {
            break id;
        }
        dts += 1;
    };
    let p = ChannelCreatePayload {
        channel_id: cid,
        slug: slug.to_string(),
        channel_type: ChannelType::Private,
        display_name: None,
        description: None,
        content_rating: Default::default(),
        moderation: ModerationPolicy { admins: vec![], rules: None },
        encryption_enabled: None,
        history_visibility: None,
        id_derivation_ts: Some(dts),
    };
    (env(creator, MessageType::ChannelCreate, mp(&p), dts), cid)
}

fn grant(by: &Key, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    let p = ChannelAddModeratorPayload {
        channel_id: cid,
        target_user: target.to_string(),
        permissions: ModeratorPermissions {
            can_mute: true,
            can_kick: true,
            can_ban: true,
            can_pin: true,
            can_edit_info: false,
            can_delete_msgs: false,
        },
    };
    env(by, MessageType::ChannelAddModerator, mp(&p), ts)
}

fn invite_payload(cid: u64, target: &str, grant: Option<Vec<u8>>, anchor: &str) -> Vec<u8> {
    mp(&ChannelInvitePayload {
        channel_id: cid,
        target_user: target.to_string(),
        anchor_node: Some(anchor.to_string()),
        expires_at: None,
        inviter_grant: grant,
    })
}

fn invite(by: &Key, cid: u64, target: &str, ts: u64, grant: Option<Vec<u8>>) -> Vec<u8> {
    env(by, MessageType::ChannelInvite, invite_payload(cid, target, grant, "https://host.example"), ts)
}

fn join(by: &Key, cid: u64, invite: Option<Vec<u8>>, ts: u64) -> Vec<u8> {
    env(by, MessageType::ChannelJoin, mp(&ChannelJoinPayload { channel_id: cid, invite }), ts)
}

fn kick(by: &Key, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    let p = ChannelKickPayload { channel_id: cid, target_user: target.to_string(), reason: None };
    env(by, MessageType::ChannelKick, mp(&p), ts)
}

fn remove_mod(by: &Key, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    let p = ChannelRemoveModeratorPayload { channel_id: cid, target_user: target.to_string() };
    env(by, MessageType::ChannelRemoveModerator, mp(&p), ts)
}

/// The canonical device-delegation claim string.
fn delegation_claim(dev: &Key, w: &Key, ts: u64) -> String {
    pcs::device_delegation_claim_string(NET, &pub_hex(dev), &w.addr, ts)
}

/// A dual-signed DeviceDelegation envelope (wallet authorizes, device PoP).
fn delegation(w: &Key, dev: &Key, ts: u64) -> Vec<u8> {
    let claim = delegation_claim(dev, w, ts);
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
    let payload = mp(&p);
    let pk = w.sk.verifying_key().to_bytes();
    let msg_id = crypto::compute_msg_id(NET, &pk, &payload, ts);
    let e = Envelope {
        version: PROTOCOL_VERSION,
        msg_type: MessageType::DeviceDelegation,
        msg_id,
        author: w.addr.clone(),
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: signing::sign_klever_message(&w.sk, claim.as_bytes()).to_bytes().to_vec(),
        relay_path: vec![],
    };
    rmp_serde::to_vec_named(&e).unwrap()
}

/// A device claim object (plan §6): `delegations` signed by `signer`
/// (the wallet for a genuine one) + the device's PoP, and `revocations`.
fn device_claim_obj(dev: &Key, w: &Key, signer: &Key, ts: u64, revocations: &[Vec<u8>]) -> serde_json::Value {
    let claim = delegation_claim(dev, w, ts);
    let wsig = signing::sign_klever_message(&signer.sk, claim.as_bytes());
    let dsig = signing::sign_klever_message(&dev.sk, claim.as_bytes());
    json!({
        "device_address": dev.addr,
        "device_pubkey": pub_hex(dev),
        "wallet": w.addr,
        "delegations": [{
            "timestamp": ts,
            "wallet_signature": b64(&wsig.to_bytes()),
            "device_signature": b64(&dsig.to_bytes()),
        }],
        "revocations": revocations.iter().map(|r| b64(r)).collect::<Vec<_>>(),
    })
}

/// A wallet-signed DeviceRevocation envelope.
fn revocation(w: &Key, dev: &Key, ts: u64) -> Vec<u8> {
    env(w, MessageType::DeviceRevocation, mp(&DeviceRevocationPayload { device_pub_key: pub_hex(dev) }), ts)
}

/// Client-side device-claim rule (plan §6): the object authorizes an
/// envelope signed by the device at `at_ts` iff some delegation verifies
/// (wallet AND device signature over the device claim), has
/// `timestamp <= at_ts`, and no served revocation naming the device has
/// `delegation.ts <= revocation.ts <= at_ts`.
fn device_claim_covers(c: &serde_json::Value, at_ts: u64) -> bool {
    let s = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let dec = |x: String| base64::engine::general_purpose::STANDARD.decode(x).ok();
    let Ok(pk) = hex::decode(s(c, "device_pubkey")) else { return false };
    let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) else { return false };
    let Ok(dvk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
    if crypto::device_pubkey_to_address(&dvk).ok() != Some(s(c, "device_address")) {
        return false;
    }
    let Ok(wvk) = crypto::address_to_verifying_key(&s(c, "wallet")) else { return false };
    let revs: Vec<u64> = c["revocations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| dec(r.as_str()?.to_string()))
        .filter_map(|raw| rmp_serde::from_slice::<Envelope>(&raw).ok())
        .filter(|e| {
            e.msg_type == MessageType::DeviceRevocation
                && rmp_serde::from_slice::<DeviceRevocationPayload>(&e.payload)
                    .is_ok_and(|p| p.device_pub_key.eq_ignore_ascii_case(&s(c, "device_pubkey")))
        })
        .map(|e| e.timestamp)
        .collect();
    c["delegations"].as_array().into_iter().flatten().any(|d| {
        let Some(ts) = d.get("timestamp").and_then(|v| v.as_u64()) else { return false };
        let msg = pcs::device_delegation_claim_string(NET, &s(c, "device_pubkey"), &s(c, "wallet"), ts);
        let ok = |vk: &ed25519_dalek::VerifyingKey, k: &str| {
            dec(s(d, k))
                .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
                .is_some_and(|sig| signing::verify_klever_message(vk, msg.as_bytes(), &sig).is_ok())
        };
        ts <= at_ts && ok(&wvk, "wallet_signature") && ok(&dvk, "device_signature")
            && !revs.iter().any(|&r| ts <= r && r <= at_ts)
    })
}

fn b64d(v: &serde_json::Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap()
}

fn router(activation: u64) -> (MessageRouter, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let identity = IdentityResolver::new(storage.clone());
    let cfg = crate::config::ChannelVerifyConfig {
        private_join_proof_activation_ms: activation,
        ..Default::default()
    };
    (
        MessageRouter::new(
            storage,
            identity,
            None,
            NET.to_string(),
            usize::MAX,
            std::sync::Arc::new(crate::metrics::counters::NetworkCounters::new()),
            crate::config::RateLimitsConfig::default(),
        )
        .with_channel_verify_config(cfg),
        dir,
    )
}

fn register(r: &MessageRouter, addr: &str) {
    let rec = json!({ "address": addr, "registered_at": 1_000u64 });
    r.storage().put_cf(schema::cf::USERS, addr.as_bytes(), rec.to_string().as_bytes()).unwrap();
}

#[track_caller]
fn ok(res: RouteResult) {
    assert!(matches!(res, RouteResult::Accepted { .. }), "not accepted: {res:?}");
}

fn is_member(r: &MessageRouter, cid: u64, addr: &str) -> bool {
    r.storage()
        .exists_cf(schema::cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(cid, addr))
        .unwrap()
}

// ---------------------------------------------------------------------
// member-proofs end-to-end
// ---------------------------------------------------------------------

fn proofs(r: &MessageRouter, cid: u64, creator: &Key, addrs: &[String], budget: usize) -> serde_json::Value {
    super::member_proofs::build_member_proofs(r.storage(), r.identity(), NET, cid, Some(&creator.addr), addrs, budget)
}

const BUDGET: usize = super::member_proofs::RESPONSE_BYTE_BUDGET;

#[test]
fn member_proofs_end_to_end_over_the_router_pipeline() {
    let (r, _d) = router(0);
    let (c, m, j1, j2, j3, j4, f, n) =
        (wallet(1), wallet(2), wallet(3), wallet(4), wallet(5), wallet(6), wallet(7), wallet(8));
    let d3 = device(55);
    for w in [&c, &m, &j1, &j2, &j3, &j4, &f, &n] {
        register(&r, &w.addr);
    }
    let (create_raw, cid) = create(&c, "phase2", T);
    ok(r.process_synced_message(&create_raw));
    assert!(is_member(&r, cid, &c.addr), "creator is a member");

    let g = grant(&c, cid, &m.addr, T + MIN);
    ok(r.process_synced_message(&g));
    // j1: creator invite.
    ok(r.process_synced_message(&join(&j1, cid, Some(invite(&c, cid, &j1.addr, T + 2 * MIN, None)), T + 3 * MIN)));
    // j2: moderator invite carrying the grant.
    let inv2 = invite(&m, cid, &j2.addr, T + 2 * MIN, Some(g.clone()));
    ok(r.process_synced_message(&join(&j2, cid, Some(inv2), T + 3 * MIN)));
    // j3: device-signed join (delegated device d3), device later REVOKED (W4).
    ok(r.process_synced_message(&delegation(&j3, &d3, T + MIN)));
    let j3_join = join(&d3, cid, Some(invite(&c, cid, &j3.addr, T + 2 * MIN, None)), T + 3 * MIN);
    ok(r.process_synced_message(&j3_join));
    let rev = revocation(&j3, &d3, T + 20 * MIN);
    ok(r.process_synced_message(&rev));
    assert_eq!(r.storage().resolve_wallet(&d3.addr).unwrap(), None, "device unmapped after revoke");
    // j4: joined, kicked by the moderator, re-invited by the moderator WITHOUT
    // an embedded grant, rejoined.
    ok(r.process_synced_message(&join(&j4, cid, Some(invite(&c, cid, &j4.addr, T + 2 * MIN, None)), T + 3 * MIN)));
    let k = kick(&m, cid, &j4.addr, T + 4 * MIN);
    ok(r.process_synced_message(&k));
    assert!(!is_member(&r, cid, &j4.addr));
    ok(r.process_synced_message(&join(&j4, cid, Some(invite(&m, cid, &j4.addr, T + 5 * MIN, None)), T + 6 * MIN)));
    assert!(is_member(&r, cid, &j4.addr), "rejoined with a post-kick invite");
    // f: federate-only member (no join anywhere).
    r.storage().add_channel_member(cid, &f.addr, T, "member").unwrap();
    // The inviter of j2/j4 is later demoted.
    let rm = remove_mod(&c, cid, &m.addr, T + 10 * MIN);
    ok(r.process_synced_message(&rm));

    let addrs: Vec<String> = [&c, &j1, &j2, &j3, &j4, &f, &n].iter().map(|w| w.addr.clone()).collect();
    let out = proofs(&r, cid, &c, &addrs, BUDGET);
    assert_eq!(out["channel_create"], json!(b64(&create_raw)));
    assert_eq!(out["truncated"], json!(false));
    let mem = |w: &Key| -> serde_json::Value {
        out["members"].as_array().unwrap().iter().find(|m| m["address"] == json!(w.addr)).unwrap().clone()
    };
    assert_eq!(mem(&c)["basis"], "creator");
    assert_eq!(mem(&j1)["basis"], "invite");
    assert_eq!(mem(&j1)["inviter"], json!(c.addr));
    assert_eq!(mem(&j2)["inviter"], json!(m.addr));
    // Shared items once, top level (B2).
    assert_eq!(out["moderator_removals"][&m.addr], json!([b64(&rm)]));
    assert_eq!(out["moderator_grants"][&m.addr], json!([b64(&g)]), "served though m was demoted");
    // j3: device-signed join of a since-revoked device stays verifiable (W4).
    assert_eq!(mem(&j3)["basis"], "invite");
    assert_eq!(mem(&j3)["join"], json!(b64(&j3_join)));
    let dc = &out["device_claims"][&d3.addr];
    assert_eq!(dc["revocations"], json!([b64(&rev)]));
    assert!(device_claim_covers(dc, T + 3 * MIN), "join inside the delegation window");
    assert!(!device_claim_covers(dc, T + 21 * MIN), "nothing after the revocation");
    // j4: newest join + the moderator's kick.
    let m4 = mem(&j4);
    let j4_env: Envelope = rmp_serde::from_slice(&b64d(&m4["join"])).unwrap();
    assert_eq!(j4_env.timestamp, T + 6 * MIN, "newest indexed join");
    assert_eq!(m4["removals"], json!([b64(&k)]));
    // f: federate-only member → unavailable; n: not a member.
    assert_eq!(mem(&f)["basis"], "unavailable");
    assert_eq!(mem(&f)["reason"], "no_join");
    assert_eq!(mem(&n)["member"], json!(false));
    assert_eq!(mem(&n)["basis"], "unavailable");
}

#[test]
fn legacy_join_without_index_rows_is_found_by_the_fallback_scan() {
    let (r, _d) = router(T + DAY);
    let (c, j) = (wallet(11), wallet(12));
    register(&r, &c.addr);
    register(&r, &j.addr);
    let (create_raw, cid) = create(&c, "legacy", T);
    ok(r.process_synced_message(&create_raw));
    let jr = join(&j, cid, None, T + MIN);
    ok(r.process_synced_message(&jr));
    // Simulate a pre-0.140.0 join: drop the membership-index bookkeeping
    // (the CHANNEL_META_MSGS row stays).
    r.storage()
        .delete_cf(
            schema::cf::CHANNEL_MEMBERSHIP_INDEX,
            &schema::encode_channel_membership_index_key(cid, &j.addr),
        )
        .unwrap();
    let out = proofs(&r, cid, &c, std::slice::from_ref(&j.addr), BUDGET);
    assert_eq!(out["members"][0]["basis"], "legacy");
    assert_eq!(out["members"][0]["join"], json!(b64(&jr)));
}

/// A signed envelope whose payload carries `pad` extra bytes (an unknown
/// map field — still a valid, verifiable envelope).
fn padded(k: &Key, msg_type: MessageType, cid: u64, target: Option<&str>, pad: usize, ts: u64) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct P<'a> {
        channel_id: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        target_user: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(with = "serde_bytes_compat")]
        pad: Vec<u8>,
    }
    mod serde_bytes_compat {
        pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(v)
        }
    }
    let reason = target.map(|_| "x".to_string());
    env(k, msg_type, mp(&P { channel_id: cid, target_user: target, reason, pad: vec![7u8; pad] }), ts)
}

/// Store an envelope directly with its index rows (bypassing the router's
/// size gates — how a padded envelope could already sit on a node).
fn plant(r: &MessageRouter, raw: &[u8], cid: u64, member: Option<&str>) {
    let e: Envelope = rmp_serde::from_slice(raw).unwrap();
    r.storage().store_message(&e.msg_id, raw).unwrap();
    match member {
        Some(w) => {
            r.storage()
                .index_membership_event(cid, w, crate::storage::rocks::MembershipEvent::Join, e.timestamp, &e.msg_id)
                .unwrap();
            r.storage().add_channel_member(cid, w, e.timestamp, "member").unwrap();
        }
        None => r
            .storage()
            .put_cf(
                schema::cf::CHANNEL_META_MSGS,
                &schema::encode_channel_meta_key(cid, e.msg_type as u8, e.timestamp, &e.msg_id),
                &[],
            )
            .unwrap(),
    }
}

#[test]
fn padded_evidence_is_never_served_and_fails_the_member_closed() {
    let (r, _d) = router(T + DAY);
    let (c, j1, j5) = (wallet(41), wallet(42), wallet(43));
    for w in [&c, &j1, &j5] {
        register(&r, &w.addr);
    }
    let (create_raw, cid) = create(&c, "padded", T);
    ok(r.process_synced_message(&create_raw));
    ok(r.process_synced_message(&join(&j1, cid, None, T + MIN)));
    // j5's join is a 200 KB padded envelope.
    plant(&r, &padded(&j5, MessageType::ChannelJoin, cid, None, 200_000, T + 2 * MIN), cid, Some(&j5.addr));
    let out = proofs(&r, cid, &c, &[j1.addr.clone(), j5.addr.clone()], BUDGET);
    assert_eq!(out["members"][0]["basis"], "legacy");
    assert_eq!(out["members"][1]["basis"], "unavailable");
    assert_eq!(out["members"][1]["reason"], "oversized_evidence");
    assert!(out.to_string().len() < 16 * 1024, "nothing padded served");
    // A padded KICK targeting j1 (newer than its join) also fails j1 closed.
    plant(&r, &padded(&c, MessageType::ChannelKick, cid, Some(&j1.addr), 200_000, T + 3 * MIN), cid, None);
    let out = proofs(&r, cid, &c, std::slice::from_ref(&j1.addr), BUDGET);
    assert_eq!(out["members"][0]["basis"], "unavailable");
    assert_eq!(out["members"][0]["reason"], "oversized_evidence");
    assert!(out.to_string().len() < 16 * 1024);
}

#[test]
fn oversized_revocation_and_channel_create_are_never_served() {
    // A padded DeviceRevocation of the member's join device → fail closed.
    let (r, _d) = router(0);
    let (c, j, d) = (wallet(81), wallet(82), device(83));
    register(&r, &c.addr);
    register(&r, &j.addr);
    let (create_raw, cid) = create(&c, "padrev", T);
    ok(r.process_synced_message(&create_raw));
    ok(r.process_synced_message(&delegation(&j, &d, T + MIN)));
    ok(r.process_synced_message(&join(&d, cid, Some(invite(&c, cid, &j.addr, T + MIN, None)), T + 2 * MIN)));
    #[derive(serde::Serialize)]
    struct PadRev {
        device_pub_key: String,
        pad: Vec<u8>,
    }
    let rev = env(&j, MessageType::DeviceRevocation, mp(&PadRev { device_pub_key: pub_hex(&d), pad: vec![9; 20_000] }), T + 30 * MIN);
    let e: Envelope = rmp_serde::from_slice(&rev).unwrap();
    assert!(rev.len() > super::member_proofs::MAX_EVIDENCE_BYTES);
    r.storage().store_message(&e.msg_id, &rev).unwrap();
    r.storage()
        .put_cf(
            schema::cf::IDENTITY_ENVELOPES,
            &schema::encode_identity_envelope_key(&j.addr, MessageType::DeviceRevocation as u8, e.timestamp, &e.msg_id),
            &[],
        )
        .unwrap();
    let out = proofs(&r, cid, &c, std::slice::from_ref(&j.addr), BUDGET);
    assert_eq!(out["members"][0]["basis"], "unavailable");
    assert_eq!(out["members"][0]["reason"], "oversized_evidence");
    assert!(out.to_string().len() < 16 * 1024, "padded revocation not served");

    // A padded ChannelCreate is never served (creator anchor missing →
    // verifiers fail closed).
    let (r2, _d2) = router(0);
    let cid2 = (1u64 << 40) + 77;
    let row = json!({ "channel_id": cid2, "channel_type": 2, "creator": c.addr });
    r2.storage().put_cf(schema::cf::CHANNELS, &cid2.to_be_bytes(), row.to_string().as_bytes()).unwrap();
    r2.storage().add_channel_member(cid2, &c.addr, T, "creator").unwrap();
    let big_create = padded(&c, MessageType::ChannelCreate, cid2, None, 20_000, T);
    plant(&r2, &big_create, cid2, None);
    assert_eq!(
        crate::network::reconcile::channel_bootstrap_envelopes(r2.storage(), cid2).0.map(|b| b.len()),
        Some(big_create.len()),
        "the padded create is the bootstrap candidate"
    );
    let out = proofs(&r2, cid2, &c, std::slice::from_ref(&c.addr), BUDGET);
    assert!(out["channel_create"].is_null());
    assert!(out.to_string().len() < 16 * 1024);
}

#[test]
fn one_hundred_members_fit_and_a_small_budget_truncates() {
    let (r, _d) = router(0);
    let c = wallet(60);
    register(&r, &c.addr);
    let (create_raw, cid) = create(&c, "hundred", T);
    ok(r.process_synced_message(&create_raw));
    let mut addrs = Vec::new();
    for i in 0..100u32 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&i.to_be_bytes());
        seed[31] = 0xAB;
        let sk = SigningKey::from_bytes(&seed);
        let w = Key { seed, addr: crypto::pubkey_to_address(&sk.verifying_key()).unwrap(), sk };
        register(&r, &w.addr);
        ok(r.process_synced_message(&join(&w, cid, Some(invite(&c, cid, &w.addr, T + MIN, None)), T + 2 * MIN)));
        addrs.push(w.addr);
    }
    let out = proofs(&r, cid, &c, &addrs, BUDGET);
    assert_eq!(out["truncated"], json!(false));
    assert!(out["members"].as_array().unwrap().iter().all(|m| m["basis"] == "invite"));
    let size = out.to_string().len();
    assert!(size < BUDGET, "{size} bytes");
    // A tiny budget: the first members fit, the rest are failed closed.
    let out = proofs(&r, cid, &c, &addrs, 20_000);
    assert_eq!(out["truncated"], json!(true));
    let ms = out["members"].as_array().unwrap();
    assert_eq!(ms[0]["basis"], "invite");
    assert_eq!(ms[99]["basis"], "unavailable");
    assert_eq!(ms[99]["reason"], "truncated");
    assert!(ms[99]["join"].is_null());
    assert!(out.to_string().len() < 40_000);
}

// ---------------------------------------------------------------------
// enc-key binding signature is stored and served
// ---------------------------------------------------------------------

/// The canonical enc-bind string (protocol §2.4).
fn enc_bind_claim(w: &Key, enc_pub: &str, device_id: &str, ts: u64) -> String {
    format!("ogmara-enc-bind:{NET}:{enc_pub}:{device_id}:{}:{ts}", w.addr)
}

fn enc_binding(w: &Key, enc_pub: &str, device_id: &str, ts: u64) -> Vec<u8> {
    let payload = mp(&DeviceEncBindingPayload { device_id: device_id.into(), enc_pub: enc_pub.into() });
    let pk = w.sk.verifying_key().to_bytes();
    let e = Envelope {
        version: PROTOCOL_VERSION,
        msg_type: MessageType::DeviceEncBinding,
        msg_id: crypto::compute_msg_id(NET, &pk, &payload, ts),
        author: w.addr.clone(),
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: signing::sign_klever_message(&w.sk, enc_bind_claim(w, enc_pub, device_id, ts).as_bytes())
            .to_bytes()
            .to_vec(),
        relay_path: vec![],
    };
    rmp_serde::to_vec_named(&e).unwrap()
}

#[test]
fn enc_binding_signature_is_stored_and_verifies() {
    let (r, _d) = router(0);
    let w = wallet(21);
    register(&r, &w.addr);
    let enc_pub = "ab".repeat(32);
    let dev = pub_hex(&device(22));
    ok(r.process_synced_message(&enc_binding(&w, &enc_pub, &dev, T)));
    let row = r
        .storage()
        .get_cf(schema::cf::DEVICE_ENC_KEYS, &schema::encode_device_enc_key(&w.addr, &enc_pub))
        .unwrap()
        .unwrap();
    let row: serde_json::Value = serde_json::from_slice(&row).unwrap();
    let sig = base64::engine::general_purpose::STANDARD.decode(row["wallet_signature"].as_str().unwrap()).unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
    let msg = enc_bind_claim(&w, &enc_pub, &dev, row["ts"].as_u64().unwrap());
    signing::verify_klever_message(&w.sk.verifying_key(), msg.as_bytes(), &sig).unwrap();
}

// ---------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------

/// One verifier case: the channel state envelopes to replay first, then
/// the bundle the client verifies (same field names as `member-proofs`).
struct Case {
    name: &'static str,
    description: &'static str,
    activation_ms: u64,
    setup: Vec<Vec<u8>>,
    wallet: Key,
    join: Vec<u8>,
    removals: Vec<Vec<u8>>,
    moderator_grants: BTreeMap<String, Vec<Vec<u8>>>,
    moderator_removals: BTreeMap<String, Vec<Vec<u8>>>,
    device_claims: BTreeMap<String, serde_json::Value>,
    expected_valid: bool,
}

fn case(name: &'static str, description: &'static str, wallet: &Key, join: Vec<u8>, expected_valid: bool) -> Case {
    Case {
        name,
        description,
        activation_ms: 0,
        setup: vec![],
        wallet: wallet.clone(),
        join,
        removals: vec![],
        moderator_grants: BTreeMap::new(),
        moderator_removals: BTreeMap::new(),
        device_claims: BTreeMap::new(),
        expected_valid,
    }
}

/// The node's own verdict for a case: join envelope genuine, authored by
/// (a device of) the wallet, for this channel, and passing the join gate
/// with sync semantics against the case's channel state.
fn node_verdict(cid: u64, create_raw: &[u8], case: &Case, wallets: &[&Key]) -> Result<(), String> {
    let (r, _d) = router(case.activation_ms);
    for w in wallets {
        register(&r, &w.addr);
    }
    if !matches!(r.process_synced_message(create_raw), RouteResult::Accepted { .. }) {
        return Err("setup: create".into());
    }
    for raw in &case.setup {
        let res = r.process_synced_message(raw);
        if !matches!(res, RouteResult::Accepted { .. }) {
            return Err(format!("setup step rejected: {res:?}"));
        }
    }
    // A device claim the node itself would not accept has no effect: the
    // forged-claim case relies on the device simply not resolving.
    let (env, signer) = r.verify_embedded_envelope(&case.join, MessageType::ChannelJoin, 64 * 1024)?;
    if signer != case.wallet.addr {
        return Err("join signer does not resolve to the wallet".into());
    }
    let p = match deserialize_payload(MessageType::ChannelJoin, &env.payload) {
        Ok(DeserializedPayload::ChannelJoin(p)) => p,
        _ => return Err("join payload".into()),
    };
    if p.channel_id != cid {
        return Err("join for another channel".into());
    }
    r.verify_private_join(cid, &case.wallet.addr, env.timestamp, p.invite.as_deref(), true)
        .map(|_| ())
}

#[test]
fn golden_vectors() {
    let c = wallet(101);
    let m = wallet(102);
    let j = wallet(103);
    let x = wallet(104); // unrelated / attacker wallet
    let d = device(105); // j's delegated device
    let df = device(106); // device with a FORGED claim for j
    let (create_raw, cid) = create(&c, "golden", T);
    let (_, other_cid) = create(&c, "golden-other", T);
    let g = grant(&c, cid, &m.addr, T + MIN);
    let jts = T + 10 * MIN;
    let inv_c = invite(&c, cid, &j.addr, T + 5 * MIN, None);
    let grants_m = || BTreeMap::from([(m.addr.clone(), vec![g.clone()])]);

    let mut cases = vec![
        case("valid_creator_invite", "join carrying a creator-signed invite", &j, join(&j, cid, Some(inv_c.clone()), jts), true),
        case(
            "moderator_invite_with_grant",
            "moderator invite embedding the creator-signed grant (grant.ts <= invite.ts)",
            &j,
            join(&j, cid, Some(invite(&m, cid, &j.addr, T + 5 * MIN, Some(g.clone()))), jts),
            true,
        ),
        case(
            "grant_signed_by_non_creator",
            "moderator invite whose grant is signed by someone other than the creator",
            &j,
            join(&j, cid, Some(invite(&m, cid, &j.addr, T + 5 * MIN, Some(grant(&x, cid, &m.addr, T + MIN)))), jts),
            false,
        ),
        case("wrong_target", "invite addressed to another wallet", &j,
            join(&j, cid, Some(invite(&c, cid, &x.addr, T + 5 * MIN, None)), jts), false),
        case("wrong_channel", "invite for a different channel", &j,
            join(&j, cid, Some(invite(&c, other_cid, &j.addr, T + 5 * MIN, None)), jts), false),
        case("expired", "join dated after the invite's default 7-day expiry", &j,
            join(&j, cid, Some(inv_c.clone()), T + 5 * MIN + 7 * DAY + 1), false),
        case("invite_after_join_plus_5min", "invite.ts > join.ts + 5 min", &j,
            join(&j, cid, Some(invite(&c, cid, &j.addr, jts + 5 * MIN + 1, None)), jts), false),
    ];

    // Moderator invite WITHOUT an embedded grant: the verifier uses
    // `moderator_grants[inviter]` (newest grant with ts <= invite.ts).
    let mut cs = case(
        "moderator_invite_grant_fallback",
        "moderator invite with no embedded grant; grant served in moderator_grants",
        &j,
        join(&j, cid, Some(invite(&m, cid, &j.addr, T + 5 * MIN, None)), jts),
        true,
    );
    cs.setup = vec![g.clone()];
    cs.moderator_grants = grants_m();
    cases.push(cs);

    // Kick cutoff: j joined with inv_c, was kicked at/after inv_c's ts,
    // and replays inv_c.
    let first_join = join(&j, cid, Some(inv_c.clone()), T + 6 * MIN);
    let k = kick(&c, cid, &j.addr, T + 7 * MIN);
    let mut cs = case("kick_cutoff", "a kick with ts >= invite.ts kills that invite (replayed after the kick)",
        &j, join(&j, cid, Some(inv_c.clone()), jts), false);
    cs.setup = vec![first_join.clone(), k.clone()];
    cs.removals = vec![k];
    cases.push(cs);

    // Kick by a MODERATOR (remover grant in moderator_grants): replaying
    // the old invite is dead; a fresh post-kick invite is valid.
    let km = kick(&m, cid, &j.addr, T + 7 * MIN);
    let mut cs = case("moderator_kick_cutoff", "kick signed by a moderator (grant served) kills the earlier invite",
        &j, join(&j, cid, Some(inv_c.clone()), jts), false);
    cs.setup = vec![g.clone(), first_join.clone(), km.clone()];
    cs.removals = vec![km.clone()];
    cs.moderator_grants = grants_m();
    cases.push(cs);
    let mut cs = case("kicked_then_reinvited", "kicked by a moderator, then re-invited after the kick — valid",
        &j, join(&j, cid, Some(invite(&c, cid, &j.addr, T + 8 * MIN, None)), jts), true);
    cs.setup = vec![g.clone(), first_join, km.clone()];
    cs.removals = vec![km];
    cs.moderator_grants = grants_m();
    cases.push(cs);

    // Grant killed: RemoveModerator m with grant.ts < m <= invite.ts.
    let rm = remove_mod(&c, cid, &m.addr, T + 3 * MIN);
    let mut cs = case("grant_killed_by_remove_moderator", "inviter demoted after the grant and before the invite",
        &j, join(&j, cid, Some(invite(&m, cid, &j.addr, T + 5 * MIN, Some(g.clone()))), jts), false);
    cs.setup = vec![g.clone(), rm.clone()];
    cs.moderator_removals = BTreeMap::from([(m.addr.clone(), vec![rm])]);
    cases.push(cs);

    // Device-signed joins.
    let mut cs = case("device_signed_join_valid", "join authored by j's delegated device; device claim verifies",
        &j, join(&d, cid, Some(inv_c.clone()), jts), true);
    cs.setup = vec![delegation(&j, &d, T + MIN)];
    cs.device_claims = BTreeMap::from([(d.addr.clone(), device_claim_obj(&d, &j, &j, T + MIN, &[]))]);
    cases.push(cs);
    let mut cs = case("device_signed_join_forged_claim", "device claim for j signed by another wallet (forged delegation)",
        &j, join(&df, cid, Some(inv_c.clone()), jts), false);
    cs.device_claims = BTreeMap::from([(df.addr.clone(), device_claim_obj(&df, &j, &x, T + MIN, &[]))]);
    cases.push(cs);
    // Revoked device: a join signed BEFORE the revocation stays valid
    // (node verdict taken at join time), one signed AFTER it is not.
    let late_rev = revocation(&j, &d, jts + MIN);
    let mut cs = case("device_join_before_revocation", "device revoked after it signed the join — still valid",
        &j, join(&d, cid, Some(inv_c.clone()), jts), true);
    cs.setup = vec![delegation(&j, &d, T + MIN)];
    cs.device_claims = BTreeMap::from([(d.addr.clone(), device_claim_obj(&d, &j, &j, T + MIN, &[late_rev]))]);
    cases.push(cs);
    let early_rev = revocation(&j, &d, T + 8 * MIN);
    let mut cs = case("device_join_after_revocation", "join signed by the device after its revocation",
        &j, join(&d, cid, Some(inv_c.clone()), jts), false);
    cs.setup = vec![delegation(&j, &d, T + MIN), early_rev.clone()];
    cs.device_claims = BTreeMap::from([(d.addr.clone(), device_claim_obj(&d, &j, &j, T + MIN, &[early_rev]))]);
    cases.push(cs);

    cases.push(case(
        "klever_wrapped_signature",
        "invite signed in the Klever-message wrapping (extension wallets) — valid",
        &j,
        join(
            &j,
            cid,
            Some(env_klever(&c, MessageType::ChannelInvite, invite_payload(cid, &j.addr, None, "https://host.example"), T + 5 * MIN)),
            jts,
        ),
        true,
    ));
    let tampered = {
        let mut e: Envelope = rmp_serde::from_slice(&join(&j, cid, Some(inv_c.clone()), jts)).unwrap();
        e.msg_id[0] ^= 0x01;
        rmp_serde::to_vec_named(&e).unwrap()
    };
    cases.push(case("tampered_msg_id", "join envelope whose msg_id no longer matches its contents", &j, tampered, false));
    cases.push(case(
        "wrong_network",
        "invite built and signed for mainnet presented on testnet",
        &j,
        join(
            &j,
            cid,
            Some(env_on("mainnet", &c, MessageType::ChannelInvite, invite_payload(cid, &j.addr, None, "https://host.example"), T + 5 * MIN)),
            jts,
        ),
        false,
    ));
    cases.push(case("nested_join", "a ChannelJoin envelope smuggled into the invite slot", &j,
        join(&j, cid, Some(join(&c, cid, None, T + 5 * MIN)), jts), false));
    let big_anchor = format!("https://{}.example", "a".repeat(2100));
    cases.push(case(
        "oversized_invite",
        "invite envelope larger than MAX_JOIN_INVITE_BYTES (2048)",
        &j,
        join(&j, cid, Some(env(&c, MessageType::ChannelInvite, invite_payload(cid, &j.addr, None, &big_anchor), T + 5 * MIN)), jts),
        false,
    ));
    let mut cs = case("legacy_before_activation", "proofless join dated before the activation timestamp",
        &j, join(&j, cid, None, jts), true);
    cs.activation_ms = jts + 1;
    cases.push(cs);
    cases.push(case("legacy_after_activation", "proofless join at/after activation (activation 0 = enforced)",
        &j, join(&j, cid, None, jts), false));

    let all = [&c, &m, &j, &x];
    let mut case_json = Vec::new();
    for case in &cases {
        let verdict = node_verdict(cid, &create_raw, case, &all);
        assert_eq!(
            verdict.is_ok(),
            case.expected_valid,
            "case {}: node verdict {:?} disagrees with expected",
            case.name,
            verdict
        );
        let join_ts = rmp_serde::from_slice::<Envelope>(&case.join).map(|e| e.timestamp).unwrap_or(0);
        for dc in case.device_claims.values() {
            assert_eq!(device_claim_covers(dc, join_ts), case.expected_valid, "case {} device claim", case.name);
        }
        let map = |m: &BTreeMap<String, Vec<Vec<u8>>>| -> BTreeMap<String, Vec<String>> {
            m.iter().map(|(k, v)| (k.clone(), v.iter().map(|r| b64(r)).collect())).collect()
        };
        case_json.push(json!({
            "name": case.name,
            "description": case.description,
            "activation_ms": case.activation_ms,
            "channel_id": cid,
            "creator": c.addr,
            "wallet": case.wallet.addr,
            "channel_create": b64(&create_raw),
            "join": b64(&case.join),
            "removals": case.removals.iter().map(|r| b64(r)).collect::<Vec<_>>(),
            "moderator_grants": map(&case.moderator_grants),
            "moderator_removals": map(&case.moderator_removals),
            "device_claims": case.device_claims,
            "setup_envelopes": case.setup.iter().map(|r| b64(r)).collect::<Vec<_>>(),
            "expected": if case.expected_valid { "valid" } else { "invalid" },
            "node_reason": verdict.err(),
        }));
    }

    // Claim vectors (plan §2/§5): wallet-direct and device-signed.
    let node_sk = SigningKey::from_bytes(&[201u8; 32]);
    let node_id = crypto::compute_node_id(&node_sk.verifying_key());
    let cts = T + 30 * MIN;
    let wmsg = pcs::build_wallet_auth_claim(NET, &node_id, &j.addr, cts);
    let wsig = signing::sign_klever_message(&j.sk, wmsg.as_bytes()).to_bytes();
    let wclaim = pcs::WalletAuthClaim { timestamp: cts, signature: wsig.to_vec(), device: None };
    assert!(pcs::verify_wallet_claim(&wclaim, NET, &node_id, &j.addr, cts));
    let dmsg = pcs::build_device_auth_claim(NET, &node_id, &j.addr, &pub_hex(&d), cts);
    let dsig = signing::sign_klever_message(&d.sk, dmsg.as_bytes()).to_bytes();
    let delmsg = delegation_claim(&d, &j, T + MIN);
    let delsig = signing::sign_klever_message(&j.sk, delmsg.as_bytes()).to_bytes();
    let dclaim = pcs::WalletAuthClaim {
        timestamp: cts,
        signature: dsig.to_vec(),
        device: Some(pcs::DeviceAuthProof {
            device_pubkey: d.sk.verifying_key().to_bytes().to_vec(),
            delegation_timestamp: T + MIN,
            delegation_signature: delsig.to_vec(),
        }),
    };
    assert!(pcs::verify_wallet_claim(&dclaim, NET, &node_id, &j.addr, cts));

    // Enc-binding vector (plan §7).
    let enc_pub = "cd".repeat(32);
    let ebmsg = enc_bind_claim(&j, &enc_pub, &pub_hex(&d), T + 2 * MIN);
    let ebsig = signing::sign_klever_message(&j.sk, ebmsg.as_bytes()).to_bytes();

    let key_json = |k: &Key| {
        json!({ "seed_hex": hex::encode(k.seed), "pubkey_hex": pub_hex(k), "address": k.addr })
    };
    let doc = json!({
        "format": "ogmara-phase2-golden-vectors/2",
        "generator": "l2-node 0.142.0 src/api/phase2_fixtures.rs::golden_vectors",
        "network": NET,
        "base_timestamp_ms": T,
        "keys": {
            "creator": key_json(&c),
            "moderator": key_json(&m),
            "joiner": key_json(&j),
            "attacker": key_json(&x),
            "joiner_device": key_json(&d),
            "forged_device": key_json(&df),
        },
        "claims": {
            "node_id": node_id,
            "wallet_direct": {
                "wallet": j.addr,
                "timestamp": cts,
                "message": wmsg,
                "signature_b64": b64(&wsig),
                "header_timestamp": cts.to_string(),
            },
            "device_signed": {
                "wallet": j.addr,
                "device_address": d.addr,
                "device_pubkey": pub_hex(&d),
                "timestamp": cts,
                "message": dmsg,
                "signature_b64": b64(&dsig),
                "delegation": { "timestamp": T + MIN, "message": delmsg, "signature_b64": b64(&delsig) },
            },
        },
        "enc_binding": {
            "wallet": j.addr,
            "enc_pub": enc_pub,
            "device_id": pub_hex(&d),
            "ts": T + 2 * MIN,
            "message": ebmsg,
            "wallet_signature": b64(&ebsig),
        },
        "cases": case_json,
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase2/vectors.json");
    // N2: a missing fixture is a FAILURE unless regeneration is requested.
    if std::env::var_os("OGMARA_REGEN_PHASE2_FIXTURES").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
    } else {
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!("tests/fixtures/phase2/vectors.json is missing — run with OGMARA_REGEN_PHASE2_FIXTURES=1")
        });
        assert!(
            committed == text,
            "tests/fixtures/phase2/vectors.json is stale — rerun with OGMARA_REGEN_PHASE2_FIXTURES=1 and review the diff"
        );
    }
}

// ---------------------------------------------------------------------
// HTTP level: auth middleware claim handling + the member-proofs handler
// ---------------------------------------------------------------------

mod http {
    use super::*;
    use crate::api::state::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt;

    const NODE: &str = "phase2TestNode";

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn nonce() -> String {
        static N: AtomicU64 = AtomicU64::new(1);
        format!("{:032x}", N.fetch_add(1, Ordering::Relaxed))
    }

    fn app(state: Arc<AppState>) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/v1/channels/{channel_id}/member-proofs",
                axum::routing::post(crate::api::member_proofs::get_member_proofs),
            )
            .layer(axum::middleware::from_fn(crate::api::auth::auth_middleware))
            .layer(axum::Extension(state))
    }

    /// POST member-proofs signed by `signer`, optionally with a pchansync
    /// claim signature over `claim_msg` by `claim_signer`.
    async fn post(
        app: &axum::Router,
        signer: &Key,
        cid: u64,
        body: String,
        claim: Option<(u64, Vec<u8>)>,
    ) -> axum::response::Response {
        let path = format!("/api/v1/channels/{cid}/member-proofs");
        let ts = now();
        let n = nonce();
        let sig = signing::sign_auth_header(&signer.sk, NET, NODE, &n, ts, "POST", &path);
        let mut b = Request::builder()
            .method("POST")
            .uri(&path)
            .header("content-type", "application/json")
            .header("x-ogmara-auth", b64(&sig.to_bytes()))
            .header("x-ogmara-address", &signer.addr)
            .header("x-ogmara-timestamp", ts.to_string())
            .header("x-ogmara-nonce", n);
        if let Some((cts, csig)) = claim {
            b = b
                .header("x-ogmara-pchansync-auth-timestamp", cts.to_string())
                .header("x-ogmara-pchansync-auth", b64(&csig));
        }
        app.clone().oneshot(b.body(Body::from(body)).unwrap()).await.unwrap()
    }

    fn wallet_claim(w: &Key, ts: u64) -> (u64, Vec<u8>) {
        let msg = pcs::build_wallet_auth_claim(NET, NODE, &w.addr, ts);
        (ts, signing::sign_klever_message(&w.sk, msg.as_bytes()).to_bytes().to_vec())
    }

    fn device_claim(dev: &Key, w: &Key, ts: u64) -> (u64, Vec<u8>) {
        let msg = pcs::build_device_auth_claim(NET, NODE, &w.addr, &pub_hex(dev), ts);
        (ts, signing::sign_klever_message(&dev.sk, msg.as_bytes()).to_bytes().to_vec())
    }

    #[tokio::test]
    async fn claims_are_forwarded_once_per_minute_and_member_proofs_are_gated() {
        let (r, _d) = router(0);
        let (c, j1, j3, n) = (wallet(31), wallet(32), wallet(33), wallet(34));
        let d3 = device(35);
        for w in [&c, &j1, &j3, &n] {
            register(&r, &w.addr);
        }
        let (create_raw, cid) = create(&c, "http", T);
        ok(r.process_synced_message(&create_raw));
        ok(r.process_synced_message(&join(&j1, cid, Some(invite(&c, cid, &j1.addr, T + MIN, None)), T + 2 * MIN)));
        ok(r.process_synced_message(&delegation(&j3, &d3, T + MIN)));
        ok(r.process_synced_message(&join(&d3, cid, Some(invite(&c, cid, &j3.addr, T + MIN, None)), T + 2 * MIN)));

        // d6: a second device of j3, mapped WITHOUT any stored proof.
        let d6 = device(38);
        r.storage()
            .register_device(&crate::storage::rocks::DeviceClaim {
                device_address: d6.addr.clone(),
                wallet_address: j3.addr.clone(),
                device_pubkey_hex: pub_hex(&d6),
                wallet_signature: String::new(),
                registered_at: T,
            })
            .unwrap();
        // j5: device d5 mapped WITHOUT any stored wallet-signed proof.
        let (j5, d5) = (wallet(36), device(37));
        r.storage()
            .register_device(&crate::storage::rocks::DeviceClaim {
                device_address: d5.addr.clone(),
                wallet_address: j5.addr.clone(),
                device_pubkey_hex: pub_hex(&d5),
                wallet_signature: String::new(),
                registered_at: T,
            })
            .unwrap();
        // N3: claims are only processed for wallets with a federated
        // private channel here.
        for w in [&j1, &j3, &j5] {
            r.storage()
                .put_cf(
                    schema::cf::LOCAL_CHANNEL_FED,
                    &schema::encode_local_channel_fed_key(&w.addr, cid),
                    &T.to_be_bytes(),
                )
                .unwrap();
        }
        let storage = r.storage().clone();
        let identity = r.identity().clone();
        let mut state = AppState::new(
            storage,
            r,
            NODE.to_string(),
            NET.to_string(),
            String::new(),
            String::new(),
            None,
            identity,
            None,
            None,
            None,
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        state.private_channel_sync_tx = tx;
        let app = app(Arc::new(state));
        let body = |addrs: &[&Key]| {
            json!({ "addresses": addrs.iter().map(|w| w.addr.clone()).collect::<Vec<_>>() }).to_string()
        };

        // Member, wallet-direct claim → 200 + one forwarded claim.
        let res = post(&app, &j1, cid, body(&[&c, &j1]), Some(wallet_claim(&j1, now()))).await;
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["members"][0]["basis"], "creator");
        assert_eq!(v["members"][1]["basis"], "invite");
        let t = rx.try_recv().expect("claim forwarded");
        assert_eq!((t.channel_id, t.wallet.as_str()), (None, j1.addr.as_str()));
        // N3: a wallet with nothing federated here is never processed.
        let res = post(&app, &c, cid, body(&[&c]), Some(wallet_claim(&c, now()))).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(rx.try_recv().is_err(), "no LOCAL_CHANNEL_FED row → nothing forwarded");
        assert!(t.wallet_claim.unwrap().device.is_none());
        // A second valid claim inside the minute is not forwarded.
        let res = post(&app, &j1, cid, body(&[&j1]), Some(wallet_claim(&j1, now()))).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(rx.try_recv().is_err(), "gated for 60 s");

        // M6a: j3's SECOND device d6 has no proof → negative entry for
        // (j3, d6) only; d3 (with a stored dual-signed delegation) is still
        // forwarded right after.
        let res = post(&app, &d6, cid, body(&[&j3]), Some(device_claim(&d6, &j3, now()))).await;
        assert_eq!(res.status(), StatusCode::OK, "d6 resolves to member j3");
        assert!(rx.try_recv().is_err(), "no proof for d6 → not forwarded");
        // Device-signed request + device-signed claim → forwarded with the
        // wallet's delegation proof attached.
        let res = post(&app, &d3, cid, body(&[&j3]), Some(device_claim(&d3, &j3, now()))).await;
        assert_eq!(res.status(), StatusCode::OK, "device resolves to member j3");
        let t = rx.try_recv().expect("device claim forwarded");
        assert_eq!(t.wallet, j3.addr);
        let proof = t.wallet_claim.unwrap().device.expect("delegation proof");
        assert_eq!(proof.delegation_timestamp, T + MIN);

        // W1: a device WITHOUT a delegation proof (gossip-style mapping, no
        // stored envelope) is remembered per (wallet, device) and does not
        // block the same wallet's wallet-direct claim.
        let res = post(&app, &d5, cid, body(&[&j5]), Some(device_claim(&d5, &j5, now()))).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "j5 is not a member");
        assert!(rx.try_recv().is_err(), "no proof → not forwarded");
        post(&app, &j5, cid, body(&[&j5]), Some(wallet_claim(&j5, now()))).await;
        let t = rx.try_recv().expect("wallet-direct claim of the same wallet still forwarded");
        assert_eq!(t.wallet, j5.addr);

        // A non-member: 403, and a bad claim is never forwarded.
        let res = post(&app, &n, cid, body(&[&j1]), Some(wallet_claim(&j1, now()))).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(rx.try_recv().is_err(), "a claim by another wallet does not verify");
        // Unknown channel: same 403 as a non-member (N7); malformed bodies.
        assert_eq!(post(&app, &j1, cid + 1, body(&[&j1]), None).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(post(&app, &j1, cid, "{".into(), None).await.status(), StatusCode::BAD_REQUEST);
        let many = json!({ "addresses": vec![j1.addr.clone(); 101] }).to_string();
        assert_eq!(post(&app, &j1, cid, many, None).await.status(), StatusCode::BAD_REQUEST);
        // Per-wallet rate limit (2 counted so far for j1).
        let mut limited = false;
        for _ in 0..crate::api::member_proofs::RATE_MAX_REQUESTS {
            if post(&app, &j1, cid, body(&[&j1]), None).await.status() == StatusCode::TOO_MANY_REQUESTS {
                limited = true;
                break;
            }
        }
        assert!(limited, "per-wallet limit engages");
    }

    #[tokio::test]
    async fn device_signed_device_registration_is_refused() {
        let (r, _d) = router(0);
        let (w, d) = (wallet(71), device(72));
        let storage = r.storage().clone();
        let identity = r.identity().clone();
        let state = Arc::new(AppState::new(
            storage.clone(), r, NODE.to_string(), NET.to_string(), String::new(), String::new(), None, identity,
            None, None, None,
        ));
        let app = axum::Router::new()
            .route("/api/v1/devices/register", axum::routing::post(crate::api::routes::register_device))
            .layer(axum::middleware::from_fn(crate::api::auth::auth_middleware))
            .layer(axum::Extension(state));
        let ts = now();
        let claim = delegation_claim(&d, &w, ts);
        let register = |signer: &Key| {
            let sig = signing::sign_klever_message(&signer.sk, claim.as_bytes());
            json!({
                "device_pubkey_hex": pub_hex(&d),
                "wallet_address": w.addr,
                "wallet_signature": hex::encode(sig.to_bytes()),
                "timestamp": ts,
            })
            .to_string()
        };
        let send = |body: String| {
            let path = "/api/v1/devices/register";
            let t = now();
            let n = nonce();
            let sig = signing::sign_auth_header(&d.sk, NET, NODE, &n, t, "POST", path);
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("x-ogmara-auth", b64(&sig.to_bytes()))
                .header("x-ogmara-address", &d.addr)
                .header("x-ogmara-timestamp", t.to_string())
                .header("x-ogmara-nonce", n)
                .body(Body::from(body))
                .unwrap()
        };
        // The DEVICE signed its own claim (the removed K5 fallback) → 401.
        let res = app.clone().oneshot(send(register(&d))).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(storage.resolve_wallet(&d.addr).unwrap(), None, "no mapping written");
        // Control: the wallet's signature is accepted.
        let res = app.clone().oneshot(send(register(&w))).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(storage.resolve_wallet(&d.addr).unwrap().as_deref(), Some(w.addr.as_str()));
    }
}
