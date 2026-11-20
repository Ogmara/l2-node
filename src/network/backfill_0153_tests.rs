//! l2-node 0.153.0 (plan `docs/planning/fresh-node-backfill-gaps-plan.md`,
//! G4, owner decision D2): dm-sync revision 1 carries the authorizing
//! wallet's key vault, settings, DM-scope key envelopes and DM reactions.
//!
//! A responder router + storage builds the real pages
//! (`dm_sync::build_response`); a requester applies them through the same
//! function the network task uses (`tally_dm_sync_envelopes`).

use super::*;
use crate::crypto::{self, signing};
use crate::messages::types::{
    key_scope_kind, ChannelKeyEnvelopePayload, DirectMessagePayload, KeyVaultSyncPayload, MessageType, ReactionPayload,
    SettingsSyncPayload,
};
use crate::storage::identity::IdentityResolver;
use tempfile::TempDir;

const DAY_MS: u64 = 86_400_000;

fn config() -> Config {
    let mut c: Config = toml::from_str(&Config::default_toml()).unwrap();
    c.network.listen_port = 0;
    c.network.enable_mdns = false;
    c
}

fn net() -> String {
    config().network_id().to_string()
}

struct W {
    sk: ed25519_dalek::SigningKey,
    addr: String,
}

fn wallet() -> W {
    let sk = crypto::generate_keypair();
    let addr = crypto::pubkey_to_address(&sk.verifying_key()).unwrap();
    W { sk, addr }
}

fn router() -> (MessageRouter, Storage, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let r = MessageRouter::new(
        storage.clone(),
        IdentityResolver::new(storage.clone()),
        None,
        net(),
        usize::MAX,
        Arc::new(NetworkCounters::new()),
        crate::config::RateLimitsConfig::default(),
    );
    (r, storage, dir)
}

fn signed<P: serde::Serialize>(w: &W, msg_type: MessageType, payload: &P, ts: u64) -> (Vec<u8>, [u8; 32]) {
    let net = net();
    let payload = rmp_serde::to_vec_named(payload).unwrap();
    let msg_id = crypto::compute_msg_id(&net, &w.sk.verifying_key().to_bytes(), &payload, ts);
    let sig = signing::sign_ogmara_message(
        &w.sk,
        &net,
        crate::messages::envelope::PROTOCOL_VERSION,
        msg_type as u8,
        &msg_id,
        ts,
        &payload,
    );
    let env = Envelope {
        version: crate::messages::envelope::PROTOCOL_VERSION,
        msg_type,
        msg_id,
        author: w.addr.clone(),
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: sig.to_bytes().to_vec(),
        relay_path: vec![],
    };
    (rmp_serde::to_vec_named(&env).unwrap(), msg_id)
}

fn dm(from: &W, to: &str, ts: u64, content_len: usize) -> (Vec<u8>, [u8; 32]) {
    let p = DirectMessagePayload {
        recipient: to.to_string(),
        conversation_id: crypto::compute_conversation_id(&from.addr, to),
        content: vec![0x5A; content_len],
        nonce: [7; 24],
        key_epoch: 1,
        reply_to: None,
        attachments: vec![],
    };
    signed(from, MessageType::DirectMessage, &p, ts)
}

fn vault(w: &W, tag: u8, updated_at: u64, ts: u64, len: usize) -> (Vec<u8>, [u8; 32]) {
    let p = KeyVaultSyncPayload { encrypted_vault: vec![tag; len], nonce: [tag; 24], format_version: 1, updated_at };
    signed(w, MessageType::KeyVaultSync, &p, ts)
}

fn settings(w: &W, tag: u8, updated_at: u64, ts: u64, len: usize) -> (Vec<u8>, [u8; 32]) {
    let p = SettingsSyncPayload { encrypted_settings: vec![tag; len], nonce: [tag; 12], key_epoch: 1, updated_at };
    signed(w, MessageType::SettingsSync, &p, ts)
}

/// A DM-scope key envelope authored by `author`, wrapped for `target`'s
/// device `dev`, in the conversation `(author, peer)` unless `scope` overrides.
fn dm_key(author: &W, peer: &str, target: &str, dev: u8, epoch: u64, ts: u64, scope: Option<[u8; 32]>) -> (Vec<u8>, [u8; 32]) {
    let p = ChannelKeyEnvelopePayload {
        key_scope: scope.unwrap_or_else(|| crypto::compute_conversation_id(&author.addr, peer)),
        scope_kind: key_scope_kind::DM,
        epoch,
        target: target.to_string(),
        device_id: hex::encode([dev; 32]),
        peer: Some(peer.to_string()),
        channel_id: None,
        eph_pub: [dev; 32],
        nonce: [3; 24],
        wrapped: vec![dev; 48],
        key_commitment: None,
        key_ts: None,
    };
    signed(author, MessageType::ChannelKeyEnvelope, &p, ts)
}

fn dm_reaction(w: &W, target: [u8; 32], emoji: &str, remove: bool, ts: u64) -> (Vec<u8>, [u8; 32]) {
    let p = ReactionPayload { target_id: target, channel_id: None, emoji: emoji.to_string(), remove };
    signed(w, MessageType::DirectMessageReaction, &p, ts)
}

fn feed(r: &MessageRouter, raw: &[u8]) {
    let res = r.process_synced_message(raw);
    assert!(matches!(res, RouteResult::Accepted { .. }), "fixture rejected: {res:?}");
}

fn types_of(envs: &[Vec<u8>]) -> Vec<MessageType> {
    envs.iter().map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_type).collect()
}

fn ids_of(envs: &[Vec<u8>]) -> Vec<[u8; 32]> {
    envs.iter().map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_id).collect()
}

fn dm_req(wallet: &str, revision: u8, cursor: Option<dm_sync::DmCursor>) -> dm_sync::DmSyncRequest {
    dm_sync::DmSyncRequest {
        wallet: wallet.to_string(),
        requester_pubkey: vec![0; 32],
        timestamp: 0,
        signature: vec![0; 64],
        max_age_secs: 30 * 24 * 3600,
        cursor,
        wallet_claim: None,
        revision,
    }
}

/// One full session against `rs` (pages in order), applied on `r2`/`s2`.
fn session(rs: &Storage, r2: &MessageRouter, s2: &Storage, wallet: &str, revision: u8) -> (DmSyncTally, Vec<Vec<u8>>) {
    let now = crate::util::now_ms();
    let mut cursor = None;
    let mut total = DmSyncTally::default();
    let mut all = Vec::new();
    for _ in 0..50 {
        let (resp, _, _) = dm_sync::build_response(rs, wallet, &dm_req(wallet, revision, cursor), 200, now, u64::MAX);
        all.extend(resp.envelopes.iter().cloned());
        let t = tally_dm_sync_envelopes(r2, s2, wallet, resp.envelopes, 0, false, &PeerId::random());
        total.admitted += t.admitted;
        total.dropped += t.dropped;
        total.neutral += t.neutral;
        if !resp.has_more {
            break;
        }
        cursor = resp.next_cursor;
        assert!(cursor.is_some());
    }
    (total, all)
}

fn vault_blob(s: &Storage, w: &str) -> Option<serde_json::Value> {
    s.get_key_vault(w).unwrap().map(|b| serde_json::from_slice(&b).unwrap())
}

fn vault_tag(s: &Storage, w: &str) -> Option<u64> {
    vault_blob(s, w).and_then(|v| v["nonce"][0].as_u64())
}

/// A fresh node restores the wallet's vault and settings from dm-sync —
/// also when the wallet has no conversation at all — and a revision-0
/// (0.152) requester is never served them.
#[test]
fn fresh_node_restores_vault_and_settings() {
    let w = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &vault(&w, 1, t, t, 64).0);
    feed(&r, &settings(&w, 2, t, t, 32).0);
    assert!(s.get_key_vault_origin(&w.addr).unwrap().is_some());

    let (r2, s2, _d2) = router();
    let (tally, envs) = session(&s, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert_eq!(types_of(&envs), vec![MessageType::KeyVaultSync, MessageType::SettingsSync]);
    assert_eq!(tally.admitted, 2);
    assert_eq!(s2.get_key_vault(&w.addr).unwrap(), s.get_key_vault(&w.addr).unwrap());
    assert_eq!(s2.get_settings(&w.addr).unwrap(), s.get_settings(&w.addr).unwrap());

    let (r3, s3, _d3) = router();
    let (_, envs) = session(&s, &r3, &s3, &w.addr, 0);
    assert!(envs.is_empty(), "a revision-0 requester gets the 0.152 shape");
    assert!(s3.get_key_vault(&w.addr).unwrap().is_none());
}

/// The vault is the user's key backup: an older copy must never replace a
/// newer one, whichever arrives first and on whichever path (dm-sync vs
/// live). Equal LWW `ts` from two different envelopes converges on the one
/// signed later, in both orders.
#[test]
fn older_vault_never_overwrites_newer_in_any_order_or_path() {
    let w = wallet();
    let now = crate::util::now_ms();
    let (old, _) = vault(&w, 1, now - 10_000, now - 10_000, 64);
    let (new, _) = vault(&w, 2, now - 5_000, now - 1_000, 64);
    for (first_live, first, second) in [
        (true, &new, &old),
        (false, &new, &old),
        (true, &old, &new),
        (false, &old, &new),
    ] {
        let (r, s, _d) = router();
        let apply = |raw: &[u8], live: bool| {
            let res = if live { r.process_message_at(raw, now) } else { r.process_synced_message_at(raw, now) };
            assert!(matches!(res, RouteResult::Accepted { .. }), "{res:?}");
        };
        apply(first, first_live);
        apply(second, !first_live);
        assert_eq!(vault_tag(&s, &w.addr), Some(2), "newer vault kept (first live: {first_live})");
        assert_eq!(s.get_key_vault_ts(&w.addr).unwrap(), now - 5_000);
    }
    // Same updated_at, different envelopes: the later-signed one wins in
    // both arrival orders (sync and live), so nodes converge.
    let (a, _) = vault(&w, 3, now - 2_000, now - 3_000, 64);
    let (b, _) = vault(&w, 4, now - 2_000, now - 2_500, 64);
    for (x, y) in [(&a, &b), (&b, &a)] {
        let (r, s, _d) = router();
        assert!(matches!(r.process_synced_message_at(x, now), RouteResult::Accepted { .. }));
        assert!(matches!(r.process_message_at(y, now), RouteResult::Accepted { .. }));
        assert_eq!(vault_tag(&s, &w.addr), Some(4));
    }
    // A dm-sync responder holding the older vault cannot roll back a fresh
    // node that already has the newer one.
    let (r_old, s_old, _d1) = router();
    feed(&r_old, &old);
    let (r2, s2, _d2) = router();
    feed(&r2, &new);
    session(&s_old, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert_eq!(vault_tag(&s2, &w.addr), Some(2));
}

/// DM key envelopes wrapped FOR the wallet in its conversations are
/// served on the first page and land in the requester's `CHANNEL_KEYS`;
/// envelopes for other targets or other conversations are not served.
#[test]
fn dm_key_envelopes_backfill_for_the_wallet_only() {
    let (w, p, q) = (wallet(), wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &dm(&p, &w.addr, t, 16).0);
    feed(&r, &dm(&q, &p.addr, t, 16).0); // a conversation W is not in
    let (k_pw, _) = dm_key(&p, &w.addr, &w.addr, 1, 1, t + 1, None); // P's key for W's device
    let (k_ww, _) = dm_key(&w, &p.addr, &w.addr, 2, 1, t + 2, None); // W's own key for W's device
    let (k_pp, _) = dm_key(&p, &w.addr, &p.addr, 3, 1, t + 3, None); // P's key for P's device
    let (k_qp, _) = dm_key(&q, &p.addr, &p.addr, 4, 1, t + 4, None); // Q–P conversation
    for k in [&k_pw, &k_ww, &k_pp, &k_qp] {
        feed(&r, k);
    }
    let (r2, s2, _d2) = router();
    let (tally, envs) = session(&s, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    let keys: Vec<[u8; 32]> = envs
        .iter()
        .filter(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_type == MessageType::ChannelKeyEnvelope)
        .map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_id)
        .collect();
    let want: std::collections::HashSet<[u8; 32]> =
        [&k_pw, &k_ww].iter().map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_id).collect();
    assert_eq!(keys.iter().copied().collect::<std::collections::HashSet<_>>(), want);
    assert_eq!(tally.dropped, 0);
    let scope = crypto::compute_conversation_id(&w.addr, &p.addr);
    assert!(s2.get_channel_key_envelope(&scope, &w.addr, &p.addr, &hex::encode([1u8; 32]), 1).unwrap().is_some());
    assert!(s2.get_channel_key_envelope(&scope, &w.addr, &w.addr, &hex::encode([2u8; 32]), 1).unwrap().is_some());
    assert!(s2.get_channel_key_envelope(&scope, &p.addr, &p.addr, &hex::encode([3u8; 32]), 1).unwrap().is_none());
}

/// A responder cannot use W's session to plant key envelopes of another
/// conversation, of channel scope, or for another target; nor W's vault or
/// settings signed by someone else, nor reactions on others' DMs.
#[test]
fn foreign_scope_envelopes_are_refused_as_taint() {
    let (w, x, y) = (wallet(), wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r2, s2, _d2) = router();
    // X–Y conversation key wrapped "for W" (peer is Y, not W).
    let foreign_scope = dm_key(&x, &y.addr, &w.addr, 1, 1, t, None).0;
    // Claims peer W but the scope is the X–Y conversation: the router's
    // binding refuses it (a WARNED refusal since round-1 N1; nothing stored).
    let lying_peer = dm_key(&x, &w.addr, &w.addr, 2, 1, t, Some(crypto::compute_conversation_id(&x.addr, &y.addr))).0;
    // W's own conversation, but wrapped for X.
    let other_target = dm_key(&w, &x.addr, &x.addr, 3, 1, t, None).0;
    // Channel scope.
    let mut chan = dm_key(&w, &x.addr, &w.addr, 4, 1, t, None).0;
    {
        let mut env: Envelope = rmp_serde::from_slice(&chan).unwrap();
        let mut p: ChannelKeyEnvelopePayload = rmp_serde::from_slice(&env.payload).unwrap();
        p.scope_kind = key_scope_kind::CHANNEL;
        p.channel_id = Some(9);
        env.payload = rmp_serde::to_vec_named(&p).unwrap();
        chan = rmp_serde::to_vec_named(&env).unwrap();
    }
    // A vault and settings by X.
    let x_vault = vault(&x, 9, t, t, 64).0;
    let x_settings = settings(&x, 9, t, t, 32).0;
    // A reaction to a stored X→Y DM.
    let (xy_dm, xy_id) = dm(&x, &y.addr, t, 16);
    feed(&r2, &xy_dm);
    let react = dm_reaction(&x, xy_id, "x", false, t + 1).0;

    let out = tally_dm_sync_envelopes(
        &r2,
        &s2,
        &w.addr,
        vec![foreign_scope, other_target, chan, x_vault, x_settings, react, lying_peer],
        0,
        false,
        &PeerId::random(),
    );
    assert_eq!(out.dropped, 6, "{out:?}");
    assert_eq!(out.admitted, 0, "{out:?}");
    assert_eq!(out.neutral, 0, "a wallet-authored scope mismatch is not neutral: {out:?}");
    assert!(s2.get_key_vault(&x.addr).unwrap().is_none());
    assert!(s2.get_settings(&x.addr).unwrap().is_none());
    assert!(s2.prefix_iter_cf(schema::cf::CHANNEL_KEYS, &[], 10).unwrap().is_empty());
}

/// DM reactions ride the last page after the DMs; the requester converges
/// on the responder's state (add / remove / re-add LWW), and a reaction
/// whose target the requester lacks is neutral.
#[test]
fn dm_reactions_backfill_and_converge() {
    let (w, p) = (wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    let (m1, id1) = dm(&p, &w.addr, t, 16);
    let (m2, id2) = dm(&w, &p.addr, t + 10, 16);
    feed(&r, &m1);
    feed(&r, &m2);
    let reacts = [
        dm_reaction(&w, id1, "👍", false, t + 20).0,
        dm_reaction(&w, id1, "👍", true, t + 21).0,
        dm_reaction(&w, id1, "👍", false, t + 22).0,
        dm_reaction(&p, id2, "❤", false, t + 23).0,
        dm_reaction(&p, id2, "❤", true, t + 24).0,
    ];
    for x in &reacts {
        feed(&r, x);
    }
    let (r2, s2, _d2) = router();
    let (tally, envs) = session(&s, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    let types = types_of(&envs);
    let first_reaction = types.iter().position(|t| *t == MessageType::DirectMessageReaction).unwrap();
    let last_dm = types.iter().rposition(|t| *t == MessageType::DirectMessage).unwrap();
    assert!(last_dm < first_reaction, "reactions after the DMs: {types:?}");
    assert_eq!(types.iter().filter(|t| **t == MessageType::DirectMessageReaction).count(), 5);
    assert_eq!(tally.dropped, 0);
    let counts = |st: &Storage| {
        (
            st.get_chat_reaction_count(&id1, "👍").unwrap(),
            st.get_chat_reaction_count(&id2, "❤").unwrap(),
        )
    };
    assert_eq!(counts(&s), (1, 0));
    assert_eq!(counts(&s2), counts(&s));
    // Reverse arrival order converges too.
    let (r3, s3, _d3) = router();
    feed(&r3, &m1);
    feed(&r3, &m2);
    for x in reacts.iter().rev() {
        assert!(matches!(r3.process_synced_message(x), RouteResult::Accepted { .. }));
    }
    assert_eq!(counts(&s3), counts(&s));
    // A reaction whose target DM the requester does not hold: neutral.
    let (r4, s4, _d4) = router();
    let out = tally_dm_sync_envelopes(&r4, &s4, &w.addr, vec![reacts[0].clone()], 0, false, &PeerId::random());
    assert_eq!((out.admitted, out.dropped, out.neutral), (0, 0, 1));
}

/// The one-time migration records the producing envelope of pre-0.153
/// vault / settings / DM key rows and indexes stored DM reactions; it is
/// resumable at any budget and idempotent.
#[test]
fn dm_sync_v11_migration_resumes_and_restores_servability() {
    let (w, p) = (wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    let (m1, id1) = dm(&p, &w.addr, t, 16);
    feed(&r, &m1);
    feed(&r, &vault(&w, 1, t, t, 64).0); // superseded below — never matches
    let (v2, v2_id) = vault(&w, 2, t + 5, t + 5, 64);
    feed(&r, &v2);
    feed(&r, &settings(&w, 3, t, t, 32).0);
    let (k, k_id) = dm_key(&p, &w.addr, &w.addr, 1, 1, t + 1, None);
    feed(&r, &k);
    let (re, re_id) = dm_reaction(&w, id1, "x", false, t + 2);
    feed(&r, &re);

    // Simulate a pre-0.153 database: no origins, no reaction index.
    for c in [schema::cf::KEY_VAULT, schema::cf::SETTINGS_SYNC] {
        let raw = s.get_cf(c, w.addr.as_bytes()).unwrap().unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let o = v.as_object_mut().unwrap();
        o.remove("msg_id");
        o.remove("env_ts");
        s.put_cf(c, w.addr.as_bytes(), v.to_string().as_bytes()).unwrap();
    }
    let krows = s.prefix_iter_cf(schema::cf::CHANNEL_KEYS, &[], 10).unwrap();
    assert_eq!(krows.len(), 1);
    let mut kv: serde_json::Value = serde_json::from_slice(&krows[0].1).unwrap();
    kv.as_object_mut().unwrap().remove("msg_id");
    s.put_cf(schema::cf::CHANNEL_KEYS, &krows[0].0, &serde_json::to_vec(&kv).unwrap()).unwrap();
    for (key, _) in s.prefix_iter_cf(schema::cf::DM_REACTION_MSGS, &[], 10).unwrap() {
        s.delete_cf(schema::cf::DM_REACTION_MSGS, &key).unwrap();
    }
    assert!(s.get_key_vault_origin(&w.addr).unwrap().is_none());
    let (_, before) = session(&s, &router().0, &router().1, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert_eq!(types_of(&before), vec![MessageType::DirectMessage], "nothing extra is servable before the migration");

    // Budget 1 per "boot": resumes until done.
    let mut boots = 0;
    loop {
        boots += 1;
        let (_, done) = s.backfill_dm_sync_v11(1).unwrap();
        if done {
            break;
        }
        assert!(boots < 100);
    }
    assert!(boots > 3, "the scan resumed across boots");
    assert_eq!(s.get_stat(schema::state_keys::DM_SYNC_V11_INDEXED).unwrap(), 1);
    assert_eq!(s.get_key_vault_origin(&w.addr).unwrap().unwrap().msg_id, v2_id);
    assert!(s.get_settings_origin(&w.addr).unwrap().is_some());
    // Idempotent: a re-run changes nothing.
    let cursor_key = schema::state_keys::DM_SYNC_V11_INDEX_CURSOR;
    s.delete_cf(schema::cf::NODE_STATE, cursor_key).unwrap();
    s.backfill_dm_sync_v11(1_000).unwrap();
    assert_eq!(s.get_key_vault_origin(&w.addr).unwrap().unwrap().msg_id, v2_id);

    let (r2, s2, _d2) = router();
    let (_, after) = session(&s, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    let ids = ids_of(&after);
    assert!(ids.contains(&v2_id) && ids.contains(&k_id) && ids.contains(&re_id), "{:?}", types_of(&after));
    assert_eq!(vault_tag(&s2, &w.addr), Some(2));
}

/// The first page always delivers a maximum-size vault and settings, stays
/// inside the transport byte budget, still makes primary progress, and
/// charges the blob bytes to the responder budget.
#[test]
fn byte_budget_holds_with_maximum_size_blobs() {
    let (w, p) = (wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &vault(&w, 1, t, t, crate::messages::validation::MAX_KEY_VAULT_SIZE).0);
    feed(&r, &settings(&w, 2, t, t, crate::messages::validation::MAX_SETTINGS_SIZE).0);
    for i in 0..200u64 {
        feed(&r, &dm(&p, &w.addr, t + i, crate::messages::validation::MAX_DM_CONTENT).0);
    }
    let now = crate::util::now_ms();
    let (page, _, work) = dm_sync::build_response(&s, &w.addr, &dm_req(&w.addr, 1, None), 200, now, u64::MAX);
    let bytes: usize = page.envelopes.iter().map(|e| reconcile::envelope_wire_cost(e)).sum();
    assert!(bytes <= reconcile::MAX_RESPONSE_ENVELOPE_BYTES, "{bytes}");
    let types = types_of(&page.envelopes);
    assert_eq!(&types[..2], &[MessageType::KeyVaultSync, MessageType::SettingsSync]);
    let primaries = types.iter().filter(|t| **t == MessageType::DirectMessage).count();
    assert!(primaries > 0 && primaries < 200, "{primaries}");
    assert!(page.has_more && page.next_cursor.is_some());
    assert!(work >= (3 * 1024 * 1024 * 2 / dm_sync::BLOB_WIRE_BYTES_PER_BUDGET_UNIT) as u64, "{work}");
    // The rest arrives on the next pages, without the blobs again.
    let (r2, s2, _d2) = router();
    let (tally, all) = session(&s, &r2, &s2, &w.addr, 1);
    assert_eq!(types_of(&all).iter().filter(|t| **t == MessageType::DirectMessage).count(), 200);
    assert_eq!(types_of(&all).iter().filter(|t| **t == MessageType::KeyVaultSync).count(), 1);
    assert_eq!(tally.admitted, 202);
    assert!(all.len() <= 202);
}

/// A cancelled fanout sibling's first page contributes only its head
/// envelopes (LWW keeps the newest vault of all fanout peers); the DMs are
/// not applied.
#[test]
fn cancelled_sibling_page_applies_only_head_envelopes() {
    let (w, p) = (wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &dm(&p, &w.addr, t, 16).0);
    feed(&r, &vault(&w, 5, t + 9, t + 9, 64).0);
    let (page, _, _) = dm_sync::build_response(&s, &w.addr, &dm_req(&w.addr, 1, None), 200, crate::util::now_ms(), u64::MAX);
    let (r2, s2, _d2) = router();
    feed(&r2, &vault(&w, 4, t, t, 64).0);
    let out = tally_dm_sync_envelopes(&r2, &s2, &w.addr, page.envelopes, 0, true, &PeerId::random());
    assert_eq!(out.admitted, 1);
    assert_eq!(vault_tag(&s2, &w.addr), Some(5));
    assert!(s2.prefix_iter_cf(schema::cf::DM_MESSAGES, &[], 10).unwrap().is_empty());
}

mod v152 {
    //! The 0.152 dm-sync request shape (no `revision`).
    use serde::{Deserialize, Serialize};
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DmSyncRequest {
        pub wallet: String,
        pub requester_pubkey: Vec<u8>,
        pub timestamp: u64,
        pub signature: Vec<u8>,
        pub max_age_secs: u64,
        pub cursor: Option<crate::network::dm_sync::DmCursor>,
        #[serde(default)]
        pub wallet_claim: Option<crate::network::dm_sync::WalletAuthClaim>,
    }
}

fn cbor_roundtrip_req<A, B>(a: A) -> B
where
    A: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    B: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
{
    use futures::executor::block_on;
    use libp2p::request_response::Codec;
    let proto = libp2p::StreamProtocol::new("/test");
    let mut buf = Vec::new();
    let mut enc = libp2p::request_response::cbor::codec::Codec::<A, ()>::default();
    block_on(enc.write_request(&proto, &mut futures::io::Cursor::new(&mut buf), a)).unwrap();
    let mut dec = libp2p::request_response::cbor::codec::Codec::<B, ()>::default();
    block_on(dec.read_request(&proto, &mut futures::io::Cursor::new(&buf))).expect("decodes")
}

/// 0.152 ↔ 0.153 request compatibility both ways, and a revision-0
/// requester gets exactly the 0.152 page shape within its page bound.
#[test]
fn wire_compatible_with_0152_peers_both_ways() {
    let old = v152::DmSyncRequest {
        wallet: "klv1w".into(),
        requester_pubkey: vec![1; 32],
        timestamp: 5,
        signature: vec![2; 64],
        max_age_secs: 10,
        cursor: Some(dm_sync::DmCursor { conversation_id: [1; 32], after_timestamp: 3, after_msg_id: [2; 32] }),
        wallet_claim: None,
    };
    let as_new: dm_sync::DmSyncRequest = cbor_roundtrip_req(old);
    assert_eq!(as_new.revision, 0);
    assert_eq!(as_new.cursor.unwrap().after_timestamp, 3);
    let new = dm_req("klv1w", dm_sync::DM_SYNC_REVISION, None);
    let as_old: v152::DmSyncRequest = cbor_roundtrip_req(new);
    assert_eq!(as_old.wallet, "klv1w");
    assert!(as_old.cursor.is_none());
    let back: dm_sync::DmSyncRequest = cbor_roundtrip_req(as_old);
    assert_eq!(back.revision, 0, "an old requester reads as revision 0");

    // Behaviour: a revision-0 page has no revision-1 type and fits the
    // 0.152 bound even with every extra present on the responder.
    let (w, p) = (wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    let (m, id) = dm(&p, &w.addr, t, 16);
    feed(&r, &m);
    feed(&r, &vault(&w, 1, t, t, 64).0);
    feed(&r, &dm_key(&p, &w.addr, &w.addr, 1, 1, t, None).0);
    feed(&r, &dm_reaction(&w, id, "x", false, t + 1).0);
    let (page, _, _) = dm_sync::build_response(&s, &w.addr, &dm_req(&w.addr, 0, None), 200, crate::util::now_ms(), u64::MAX);
    assert_eq!(types_of(&page.envelopes), vec![MessageType::DirectMessage]);
    assert!(page.envelopes.len() <= dm_sync::MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS);
    // And signed requests always speak the current revision.
    let sk = crypto::generate_keypair();
    let signed_req = dm_sync::sign_request(&sk, "net", "peer", "klv1w", 1, 1, None, None);
    assert_eq!(signed_req.revision, dm_sync::DM_SYNC_REVISION);
}

/// The DM retention reaper's reaction pass removes expired index rows and
/// their envelopes (keyed by the reaction's own timestamp).
#[tokio::test]
async fn dm_reaper_removes_expired_reaction_rows() {
    let dir = TempDir::new().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let mut cfg = config();
    cfg.dm.retention_days = 1;
    let svc_storage = storage.clone();
    let (w, p) = (wallet(), wallet());
    let old = crate::util::now_ms() - 3 * DAY_MS;
    let r = MessageRouter::new(
        storage.clone(),
        IdentityResolver::new(storage.clone()),
        None,
        net(),
        usize::MAX,
        Arc::new(NetworkCounters::new()),
        crate::config::RateLimitsConfig::default(),
    );
    let (m, id) = dm(&p, &w.addr, old, 16);
    feed(&r, &m);
    let (re, re_id) = dm_reaction(&w, id, "x", false, old + 1);
    feed(&r, &re);
    assert_eq!(storage.prefix_iter_cf(schema::cf::DM_REACTION_MSGS, &[], 10).unwrap().len(), 1);
    let mut svc = test_service(&cfg, svc_storage).await;
    svc.reap_expired_dms();
    assert!(storage.prefix_iter_cf(schema::cf::DM_REACTION_MSGS, &[], 10).unwrap().is_empty());
    assert!(storage.get_cf(schema::cf::MESSAGES, &re_id).unwrap().is_none());
}

async fn test_service(cfg: &Config, storage: Storage) -> NetworkService {
    let identity = IdentityResolver::new(storage.clone());
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    NetworkService::new(
        cfg,
        storage,
        identity,
        keypair,
        None,
        Arc::new(AtomicU32::new(0)),
        crypto::generate_keypair(),
        "node".into(),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(NetworkCounters::new()),
        Arc::new(RwLock::new(None)),
        rx,
        Arc::new(AtomicU64::new(0)),
        Arc::new(RwLock::new(HashSet::new())),
        mesh_stats::PublishFailureCounters::default(),
        mesh_stats::shared_empty(),
        None,
        cfg.backfill.clone(),
        cfg.dm.clone(),
        cfg.identity_resync.clone(),
        cfg.private_channel_sync.clone(),
    )
    .await
    .unwrap()
}

// --- l2-node 0.153.0 round-1 audit fixes ---

fn register(s: &Storage, addr: &str) {
    s.put_cf(
        schema::cf::USERS,
        addr.as_bytes(),
        serde_json::json!({"address": addr, "registered_at": 1}).to_string().as_bytes(),
    )
    .unwrap();
}

/// A device key: signs as its `ogd1…` address.
fn device() -> W {
    let sk = crypto::generate_keypair();
    let addr = crypto::device_pubkey_to_address(&sk.verifying_key()).unwrap();
    W { sk, addr }
}

/// A dual-signed `DeviceDelegation` of `dev` by wallet `w`.
fn delegation(w: &W, dev: &W, ts: u64) -> Vec<u8> {
    use crate::messages::types::{DelegationPermissions, DeviceDelegationPayload};
    let dev_hex = hex::encode(dev.sk.verifying_key().to_bytes());
    let claim = crate::network::private_channel_sync::device_delegation_claim_string(&net(), &dev_hex, &w.addr, ts);
    let p = DeviceDelegationPayload {
        device_pub_key: dev_hex,
        permissions: DelegationPermissions { can_send_messages: true, can_create_channels: true, can_update_profile: true },
        expires_at: None,
        device_signature: hex::encode(signing::sign_klever_message(&dev.sk, claim.as_bytes()).to_bytes()),
    };
    let payload = rmp_serde::to_vec_named(&p).unwrap();
    let msg_id = crypto::compute_msg_id(&net(), &w.sk.verifying_key().to_bytes(), &payload, ts);
    rmp_serde::to_vec_named(&Envelope {
        version: crate::messages::envelope::PROTOCOL_VERSION,
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

/// Blocker: `updated_at` beyond the envelope's own time plus the drift
/// window is refused on every ingress path; exactly at the bound passes.
#[test]
fn far_future_updated_at_is_refused_on_every_path() {
    let w = wallet();
    let now = crate::util::now_ms();
    let drift = crate::messages::envelope::MAX_TIMESTAMP_DRIFT_MS;
    let (bad_v, _) = vault(&w, 1, now + drift + 1, now, 64);
    let (bad_s, _) = settings(&w, 1, u64::MAX, now, 32);
    let (r, s, _d) = router();
    for raw in [&bad_v, &bad_s] {
        for res in [r.process_message_at(raw, now), r.process_gossip_message_at(raw, now), r.process_synced_message_at(raw, now)] {
            assert!(matches!(&res, RouteResult::Rejected(m) if m.contains("updated_at")), "{res:?}");
        }
    }
    assert!(s.get_key_vault(&w.addr).unwrap().is_none());
    let (ok, _) = vault(&w, 2, now + drift, now, 64);
    assert!(matches!(r.process_message_at(&ok, now), RouteResult::Accepted { .. }));
}

/// Blocker: a row an older node pinned at `ts = u64::MAX` heals with the
/// next honest upload, on the sync path and the live path.
#[test]
fn poisoned_vault_row_heals() {
    let w = wallet();
    let now = crate::util::now_ms();
    for live in [false, true] {
        let (r, s, _d) = router();
        s.put_cf(
            schema::cf::KEY_VAULT,
            w.addr.as_bytes(),
            serde_json::json!({"_sv": 1, "ts": u64::MAX, "blob": {"encrypted_vault": [1], "nonce": [9], "format_version": 1}})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let (good, _) = vault(&w, 7, now, now, 64);
        let res = if live { r.process_message_at(&good, now) } else { r.process_synced_message_at(&good, now) };
        assert!(matches!(res, RouteResult::Accepted { .. }));
        assert_eq!(vault_tag(&s, &w.addr), Some(7), "healed (live: {live})");
    }
}

/// W1: account deletion tombstones the vault / settings; an old signed copy
/// from a dm-sync responder (or gossip) never resurrects them, and the
/// deleted node serves nothing.
#[test]
fn account_deletion_tombstone_blocks_resurrection() {
    use crate::messages::types::{DeletionRequestPayload, DeletionType};
    let w = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (old_v, _) = vault(&w, 1, t, t, 64);
    let (old_s, _) = settings(&w, 1, t, t, 32);
    let (r1, s1, _d1) = router();
    feed(&r1, &old_v);
    feed(&r1, &old_s);
    let (r2, s2, _d2) = router();
    register(&s2, &w.addr);
    feed(&r2, &old_v);
    let del = DeletionRequestPayload { delete_type: DeletionType::AllUserContent, target_id: None };
    feed(&r2, &signed(&w, MessageType::DeletionRequest, &del, t + 10).0);
    assert!(s2.get_key_vault(&w.addr).unwrap().is_none());
    // The pre-deletion copies come back via dm-sync: refused by the tombstone.
    session(&s1, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert!(s2.get_key_vault(&w.addr).unwrap().is_none());
    assert!(s2.get_settings(&w.addr).unwrap().is_none());
    // The deleted node serves nothing to a fresh one.
    let (r3, s3, _d3) = router();
    let (_, envs) = session(&s2, &r3, &s3, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert!(envs.is_empty(), "{:?}", types_of(&envs));
    // A strictly newer upload is accepted again.
    feed(&r2, &vault(&w, 3, t + 11, t + 11, 64).0);
    assert_eq!(vault_tag(&s2, &w.addr), Some(3));
}

/// W2: a vault signed by a delegated device travels with the device's
/// delegation (served first), so a fresh node restores it in one session;
/// a revoked device's vault is not served at all.
#[test]
fn device_signed_vault_travels_with_its_delegation() {
    let w = wallet();
    let dev = device();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &delegation(&w, &dev, t));
    feed(&r, &vault(&dev, 6, t + 5, t + 5, 64).0);
    assert_eq!(s.resolve_wallet(&dev.addr).unwrap().as_deref(), Some(w.addr.as_str()));
    assert!(s.get_key_vault_origin(&w.addr).unwrap().is_some());

    let (r2, s2, _d2) = router();
    let (tally, envs) = session(&s, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert_eq!(types_of(&envs), vec![MessageType::DeviceDelegation, MessageType::KeyVaultSync]);
    assert_eq!((tally.admitted, tally.dropped, tally.neutral), (2, 0, 0));
    assert_eq!(vault_tag(&s2, &w.addr), Some(6));

    // A delegation by another wallet is foreign in W's session.
    let x = wallet();
    let other = tally_dm_sync_envelopes(&r2, &s2, &w.addr, vec![delegation(&x, &device(), t)], 0, false, &PeerId::random());
    assert_eq!(other.dropped, 1);

    // Revoked device: neither the vault nor its delegation is served.
    s.put_cf(schema::cf::DEVICE_REVOCATIONS, dev.addr.as_bytes(), &(t + 6).to_be_bytes()).unwrap();
    let (r3, s3, _d3) = router();
    let (_, envs) = session(&s, &r3, &s3, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert!(envs.is_empty(), "{:?}", types_of(&envs));
}

/// W4: the key scan is per author and per device — the wallet's own wraps
/// are always served, the counterpart's capped at 32 with at most 8 epochs
/// per device, however many devices / epochs the counterpart floods.
#[test]
fn key_scan_is_per_author_and_per_device() {
    let (w, p) = (wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &dm(&p, &w.addr, t, 16).0);
    for dev in 100u8..140 {
        feed(&r, &dm_key(&p, &w.addr, &w.addr, dev, 1, t + 1, None).0);
    }
    for epoch in 1..=20u64 {
        feed(&r, &dm_key(&p, &w.addr, &w.addr, 200, epoch, t + 2, None).0);
    }
    let own: Vec<[u8; 32]> = (1u8..=2).map(|dev| {
        let (raw, id) = dm_key(&w, &p.addr, &w.addr, dev, 1, t + 3, None);
        feed(&r, &raw);
        id
    }).collect();
    let (_, envs) = session(&s, &router().0, &router().1, &w.addr, dm_sync::DM_SYNC_REVISION);
    let keys: Vec<ChannelKeyEnvelopePayload> = envs
        .iter()
        .map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap())
        .filter(|e| e.msg_type == MessageType::ChannelKeyEnvelope)
        .map(|e| rmp_serde::from_slice(&e.payload).unwrap())
        .collect();
    let ids = ids_of(&envs);
    assert!(own.iter().all(|i| ids.contains(i)), "the wallet's own wraps are always served");
    let from_p = keys.iter().filter(|k| k.peer.as_deref() == Some(w.addr.as_str())).count();
    // ≤ 16 devices visited: the 20-epoch device gives 8, 15 others 1 each.
    assert_eq!(from_p, dm_sync::DM_KEYS_PER_DEVICE + dm_sync::DM_KEY_DEVICES_PER_AUTHOR - 1);
    assert!(from_p <= dm_sync::DM_KEYS_PER_AUTHOR);
    let dev200 = keys.iter().filter(|k| k.device_id == hex::encode([200u8; 32])).collect::<Vec<_>>();
    assert_eq!(dev200.len(), dm_sync::DM_KEYS_PER_DEVICE);
    assert!(dev200.iter().all(|k| k.epoch > 12), "newest epochs of a device first");
}

/// N1: a key envelope authored by a device this node cannot resolve is a
/// neutral refusal; N2: the per-page bound depends on first / final page.
#[test]
fn neutral_refusals_and_page_bounds() {
    let (w, x) = (wallet(), wallet());
    let dev = device();
    let t = crate::util::now_ms() - DAY_MS;
    let (r2, s2, _d2) = router();
    // Device of X (unknown here) claiming peer W in the (X, W) scope.
    let raw = dm_key(&dev, &w.addr, &w.addr, 1, 1, t, Some(crypto::compute_conversation_id(&x.addr, &w.addr))).0;
    let out = tally_dm_sync_envelopes(&r2, &s2, &w.addr, vec![raw], 0, false, &PeerId::random());
    assert_eq!((out.admitted, out.dropped, out.neutral), (0, 0, 1));

    use dm_sync::max_page_envelopes as b;
    assert_eq!(b(false, false), dm_sync::MAX_ENVELOPES_PER_RESPONSE);
    assert_eq!(b(true, false), dm_sync::MAX_ENVELOPES_PER_RESPONSE + dm_sync::DM_HEAD_CAP);
    assert_eq!(b(false, true), dm_sync::MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS + dm_sync::DM_REACTION_CAP);
    assert_eq!(b(true, true), dm_sync::MAX_ENVELOPES_PER_PAGE_WITH_RIDE_ALONGS + dm_sync::DM_HEAD_CAP + dm_sync::DM_REACTION_CAP);
}

/// N7: a cancelled sibling's DM key envelopes (and delegations) apply too.
#[test]
fn cancelled_sibling_applies_key_envelopes() {
    let (w, p) = (wallet(), wallet());
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &dm(&p, &w.addr, t, 16).0);
    feed(&r, &dm_key(&p, &w.addr, &w.addr, 1, 1, t + 1, None).0);
    let (page, _, _) = dm_sync::build_response(&s, &w.addr, &dm_req(&w.addr, 1, None), 200, crate::util::now_ms(), u64::MAX);
    let (r2, s2, _d2) = router();
    let out = tally_dm_sync_envelopes(&r2, &s2, &w.addr, page.envelopes, 0, true, &PeerId::random());
    assert_eq!(out.admitted, 1);
    assert_eq!(s2.prefix_iter_cf(schema::cf::CHANNEL_KEYS, &[], 10).unwrap().len(), 1);
    assert!(s2.prefix_iter_cf(schema::cf::DM_MESSAGES, &[], 10).unwrap().is_empty());
}

// --- l2-node 0.153.0 round-2 audit fixes ---

fn revocation(w: &W, dev: &W, ts: u64) -> Vec<u8> {
    let p = crate::messages::types::DeviceRevocationPayload { device_pub_key: hex::encode(dev.sk.verifying_key().to_bytes()) };
    signed(w, MessageType::DeviceRevocation, &p, ts).0
}

/// W1: a settings `updated_at` may run up to TWICE the drift window ahead
/// (merged items from skewed devices); the vault keeps one window.
#[test]
fn settings_updated_at_allows_twice_the_drift() {
    let w = wallet();
    let now = crate::util::now_ms();
    let drift = crate::messages::envelope::MAX_TIMESTAMP_DRIFT_MS;
    let (r, s, _d) = router();
    let (ok, _) = settings(&w, 1, now + 2 * drift, now, 32);
    assert!(matches!(r.process_gossip_message_at(&ok, now), RouteResult::Accepted { .. }));
    assert_eq!(s.get_settings_ts(&w.addr).unwrap(), now + 2 * drift, "not capped below the bound");
    let (bad, _) = settings(&w, 2, now + 2 * drift + 1, now, 32);
    assert!(matches!(r.process_synced_message_at(&bad, now), RouteResult::Rejected(_)));
    let (bad_v, _) = vault(&w, 3, now + drift + 1, now, 64);
    assert!(matches!(r.process_message_at(&bad_v, now), RouteResult::Rejected(_)));
}

/// SEC-PRE: a revocation processed BEFORE the delegation (fresh node,
/// reordered sync) records a tombstone scoped to the revoking wallet: that
/// wallet's stale delegation is refused, a newer one maps the device, and
/// another wallet's delegation of the same key is unaffected.
#[test]
fn revoke_before_delegate_blocks_stale_delegation_of_that_wallet_only() {
    let (w, y) = (wallet(), wallet());
    let dev = device();
    let t = crate::util::now_ms() - DAY_MS;
    // L2 revocation first.
    let (r, s, _d) = router();
    feed(&r, &revocation(&w, &dev, t + 10));
    assert!(s.resolve_wallet(&dev.addr).unwrap().is_none());
    assert_eq!(s.get_device_revoked_at(&dev.addr).unwrap(), None, "no global tombstone");
    assert_eq!(s.get_device_revoked_at_for(&dev.addr, &w.addr).unwrap(), Some(t + 10));
    assert_eq!(s.get_device_revoked_at_for(&dev.addr, &y.addr).unwrap(), None);
    let _ = r.process_synced_message(&delegation(&w, &dev, t + 5));
    assert!(s.resolve_wallet(&dev.addr).unwrap().is_none(), "stale delegation refused");
    let _ = r.process_synced_message(&delegation(&w, &dev, t + 10));
    assert!(s.resolve_wallet(&dev.addr).unwrap().is_none(), "equal timestamp refused");
    feed(&r, &delegation(&w, &dev, t + 11));
    assert_eq!(s.resolve_wallet(&dev.addr).unwrap().as_deref(), Some(w.addr.as_str()), "newer re-delegation maps");

    // Another wallet: X's (here W's) unmapped revocation never blocks Y.
    let (r2, s2, _d2) = router();
    feed(&r2, &revocation(&w, &dev, t + 10));
    feed(&r2, &delegation(&y, &dev, t + 5));
    assert_eq!(s2.resolve_wallet(&dev.addr).unwrap().as_deref(), Some(y.addr.as_str()));

    // Chain revocation first (no claim row): same scoped rule.
    let (r3, s3, _d3) = router();
    let ident = IdentityResolver::new(s3.clone());
    assert!(!ident.revoke_device_from_chain(&dev.addr, &w.addr, t + 10).unwrap());
    assert_eq!(s3.get_device_revoked_at_for(&dev.addr, &w.addr).unwrap(), Some(t + 10));
    let _ = r3.process_synced_message(&delegation(&w, &dev, t + 5));
    assert!(s3.resolve_wallet(&dev.addr).unwrap().is_none());
    feed(&r3, &delegation(&y, &dev, t + 6));
    assert_eq!(s3.resolve_wallet(&dev.addr).unwrap().as_deref(), Some(y.addr.as_str()));
}

/// N1: a vault signed by a device AFTER it was revoked and re-delegated is
/// served (with the current delegation).
#[test]
fn vault_of_a_re_delegated_device_is_served() {
    let w = wallet();
    let dev = device();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &delegation(&w, &dev, t));
    feed(&r, &revocation(&w, &dev, t + 6));
    assert_eq!(s.get_device_revoked_at(&dev.addr).unwrap(), Some(t + 6));
    feed(&r, &delegation(&w, &dev, t + 7));
    feed(&r, &vault(&dev, 8, t + 8, t + 8, 64).0);
    let (r2, s2, _d2) = router();
    let (_, envs) = session(&s, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert_eq!(types_of(&envs), vec![MessageType::DeviceDelegation, MessageType::KeyVaultSync]);
    assert_eq!(vault_tag(&s2, &w.addr), Some(8));
}

// --- l2-node 0.153.0 round-3 audit B1: every authorization reader applies
// the wallet-scoped tombstone (only the scoped key present in each test) ---

/// Write ONLY a scoped tombstone of `dev` for `w` at `at` (no global key).
fn scoped_tomb(s: &Storage, dev: &W, w: &W, at: u64) {
    let mut k = dev.addr.as_bytes().to_vec();
    k.push(0xFF);
    k.extend_from_slice(w.addr.as_bytes());
    s.put_cf(schema::cf::DEVICE_REVOCATIONS, &k, &at.to_be_bytes()).unwrap();
    assert_eq!(s.get_device_revoked_at(&dev.addr).unwrap(), None);
}

/// Store a dual-signed delegation the way the router does (MESSAGES +
/// IDENTITY_ENVELOPES) WITHOUT mapping the device — what a refused stale
/// delegation leaves behind.
fn store_unapplied_delegation(s: &Storage, w: &W, dev: &W, ts: u64) {
    let raw = delegation(w, dev, ts);
    let env: Envelope = rmp_serde::from_slice(&raw).unwrap();
    s.store_message(&env.msg_id, &raw).unwrap();
    s.put_cf(
        schema::cf::IDENTITY_ENVELOPES,
        &schema::encode_identity_envelope_key(&w.addr, MessageType::DeviceDelegation as u8, ts, &env.msg_id),
        &[],
    )
    .unwrap();
}

#[test]
fn scoped_tombstone_gates_pchansync_claims_proofs_and_join_attribution() {
    use crate::network::private_channel_sync as pcs;
    let (w, y) = (wallet(), wallet());
    let dev = device();
    let t = crate::util::now_ms() - DAY_MS;
    let (_r, s, _d) = router();
    store_unapplied_delegation(&s, &w, &dev, t);
    let dev_hex = hex::encode(dev.sk.verifying_key().to_bytes());
    let claim = pcs::WalletAuthClaim {
        timestamp: t + 100,
        signature: vec![0; 64],
        device: Some(pcs::DeviceAuthProof {
            device_pubkey: dev.sk.verifying_key().to_bytes().to_vec(),
            delegation_timestamp: t,
            delegation_signature: signing::sign_klever_message(
                &w.sk,
                pcs::device_delegation_claim_string(&net(), &dev_hex, &w.addr, t).as_bytes(),
            )
            .to_bytes()
            .to_vec(),
        }),
    };
    // Before the revocation: the stale delegation counts.
    assert!(pcs::device_claim_unrevoked(&s, &w.addr, Some(&claim)));
    assert!(pcs::lookup_device_delegation_proof(&s, &net(), &dev.addr, &w.addr).is_some());
    assert!(pcs::device_delegated_at(&s, &net(), &dev.addr, &w.addr, t + 50));

    scoped_tomb(&s, &dev, &w, t + 10);
    // PCHANSYNC device claim refused.
    assert!(!pcs::device_claim_unrevoked(&s, &w.addr, Some(&claim)));
    // No delegation proof.
    assert!(pcs::lookup_device_delegation_proof(&s, &net(), &dev.addr, &w.addr).is_none());
    // A ChannelJoin signed by the device after the revocation is not the wallet's.
    assert!(!pcs::device_delegated_at(&s, &net(), &dev.addr, &w.addr, t + 50));
    // ...but one signed before it still is (W4 history rule unchanged).
    assert!(pcs::device_delegated_at(&s, &net(), &dev.addr, &w.addr, t + 5));
    // Another wallet's view is unaffected by W's scoped tombstone.
    assert!(pcs::device_claim_unrevoked(&s, &y.addr, Some(&claim)));
}

#[test]
fn dm_sync_head_skips_vault_signed_before_a_scoped_revocation() {
    let w = wallet();
    let dev = device();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    feed(&r, &delegation(&w, &dev, t));
    feed(&r, &vault(&dev, 5, t + 5, t + 5, 64).0);
    scoped_tomb(&s, &dev, &w, t + 6);
    let (r2, s2, _d2) = router();
    let (_, envs) = session(&s, &r2, &s2, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert!(envs.is_empty(), "{:?}", types_of(&envs));
    // Signed after it: served.
    feed(&r, &vault(&dev, 7, t + 7, t + 7, 64).0);
    let (r3, s3, _d3) = router();
    let (_, envs) = session(&s, &r3, &s3, &w.addr, dm_sync::DM_SYNC_REVISION);
    assert!(types_of(&envs).contains(&MessageType::KeyVaultSync));
}

#[test]
fn device_registration_refused_at_or_before_a_scoped_revocation() {
    let (w, y) = (wallet(), wallet());
    let dev = device();
    let (_r, s, _d) = router();
    scoped_tomb(&s, &dev, &w, 1_000);
    use crate::api::routes::device_registration_revoked as revoked;
    assert!(revoked(&s, &dev.addr, &w.addr, 999).unwrap());
    assert!(revoked(&s, &dev.addr, &w.addr, 1_000).unwrap());
    assert!(!revoked(&s, &dev.addr, &w.addr, 1_001).unwrap());
    assert!(!revoked(&s, &dev.addr, &y.addr, 999).unwrap(), "another wallet is unaffected");
}
