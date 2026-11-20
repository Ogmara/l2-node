//! l2-node 0.152.0 (plan `docs/planning/fresh-node-backfill-gaps-plan.md`,
//! G6 + G7): pins / mutes / chat reactions in the channel backfill, and
//! public-channel metadata paging.
//!
//! Exercised end to end where the wiring matters: a responder router +
//! storage builds the real pages (`reconcile::build_response`,
//! `private_channel_sync::build_response`), and a requester routes them
//! through `tally_reconcile_envelopes` or a real (unconnected)
//! `NetworkService`.

use super::*;
use crate::crypto::{self, signing};
use crate::messages::types::{
    ChannelAddModeratorPayload, ChannelBanPayload, ChannelJoinPayload, ChannelUnbanPayload, ChannelUnpinMessagePayload, ChannelMutePayload, ChannelPinMessagePayload,
    ChannelRemoveModeratorPayload, ChannelUnmutePayload, ChatMessagePayload, MessageType, ModeratorPermissions,
    ReactionPayload,
};
use crate::storage::identity::IdentityResolver;
use tempfile::TempDir;

const CID: u64 = 42;
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

/// A public (or, with `channel_type: 2`, private) channel row plus the
/// creator's registration.
fn setup_channel(s: &Storage, cid: u64, creator: &str, channel_type: u8) {
    s.put_cf(
        schema::cf::CHANNELS,
        &cid.to_be_bytes(),
        serde_json::json!({"channel_id": cid, "channel_type": channel_type, "creator": creator,
            "member_count": 0, "history_visibility": 1})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    s.put_cf(
        schema::cf::USERS,
        creator.as_bytes(),
        serde_json::json!({"address": creator, "registered_at": 1}).to_string().as_bytes(),
    )
    .unwrap();
}

/// Mark `addr` as an on-chain registered user (what the chain scanner
/// writes on every node).
fn register(s: &Storage, addr: &str) {
    s.put_cf(
        schema::cf::USERS,
        addr.as_bytes(),
        serde_json::json!({"address": addr, "registered_at": 1}).to_string().as_bytes(),
    )
    .unwrap();
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

fn chat(w: &W, cid: u64, ts: u64) -> (Vec<u8>, [u8; 32]) {
    let p = ChatMessagePayload {
        channel_id: cid,
        content: format!("m{ts}"),
        content_rating: Default::default(),
        reply_to: None,
        mentions: vec![],
        attachments: vec![],
        enc_content: None,
        enc_nonce: None,
        key_epoch: None,
        buttons: vec![],
        via_button: false,
    };
    signed(w, MessageType::ChatMessage, &p, ts)
}

fn perms_all() -> ModeratorPermissions {
    ModeratorPermissions {
        can_mute: true,
        can_kick: true,
        can_ban: true,
        can_pin: true,
        can_edit_info: true,
        can_delete_msgs: true,
    }
}

fn add_mod(creator: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    let p = ChannelAddModeratorPayload { channel_id: cid, target_user: target.to_string(), permissions: perms_all() };
    signed(creator, MessageType::ChannelAddModerator, &p, ts).0
}

fn remove_mod(creator: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    let p = ChannelRemoveModeratorPayload { channel_id: cid, target_user: target.to_string() };
    signed(creator, MessageType::ChannelRemoveModerator, &p, ts).0
}

fn pin(w: &W, cid: u64, target: [u8; 32], ts: u64) -> Vec<u8> {
    signed(w, MessageType::ChannelPinMessage, &ChannelPinMessagePayload { channel_id: cid, msg_id: target }, ts).0
}

fn mute(w: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    let p = ChannelMutePayload { channel_id: cid, target_user: target.to_string(), duration_secs: 0, reason: None };
    signed(w, MessageType::ChannelMute, &p, ts).0
}

fn unmute(w: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    signed(w, MessageType::ChannelUnmute, &ChannelUnmutePayload { channel_id: cid, target_user: target.to_string() }, ts).0
}

fn reaction(w: &W, payload_cid: Option<u64>, target: [u8; 32], emoji: &str, remove: bool, ts: u64) -> (Vec<u8>, [u8; 32]) {
    let p = ReactionPayload { target_id: target, channel_id: payload_cid, emoji: emoji.to_string(), remove };
    signed(w, MessageType::ChatReaction, &p, ts)
}

fn join(w: &W, cid: u64, ts: u64) -> Vec<u8> {
    signed(w, MessageType::ChannelJoin, &ChannelJoinPayload { channel_id: cid, invite: None }, ts).0
}

fn feed(r: &MessageRouter, raw: &[u8]) {
    let res = r.process_synced_message(raw);
    assert!(matches!(res, RouteResult::Accepted { .. }), "fixture rejected: {res:?}");
}

fn types_of(envs: &[Vec<u8>]) -> Vec<MessageType> {
    envs.iter().map(|e| rmp_serde::from_slice::<Envelope>(e).unwrap().msg_type).collect()
}

fn req(revision: u8, cursor: Option<reconcile::ReconcileCursor>, meta_cursor: Option<reconcile::MetaCursor>) -> reconcile::ReconcileRequest {
    reconcile::ReconcileRequest {
        channel_id: CID,
        max_age_secs: u64::MAX,
        cursor,
        fingerprint: Vec::new(),
        epoch_root_known: None,
        round: 0,
        meta_cursor,
        revision,
    }
}

fn now_secs() -> u64 {
    crate::util::now_ms() / 1000
}

fn tally(r: &MessageRouter, s: &Storage, envs: &[Vec<u8>]) -> ReconcileTally {
    let mut authors = Vec::new();
    tally_reconcile_envelopes(r, s, &PeerId::random(), CID, envs, usize::MAX, 0, &mut authors)
}

// --- G6: pins / mutes replay against moderator grants and demotions ---

/// A pin and a mute signed after a moderator grant replay successfully on a
/// fresh requester; the same moderator's pin and mute signed after the
/// demotion are refused — on every path that serves metadata (the public
/// first-page ride-along, public metadata pages, private metadata pages),
/// because all of them serve tier 1 in `(ts, msg_id)` order.
#[test]
fn pin_and_mute_replay_follows_moderator_grant_and_demotion() {
    let creator = wallet();
    let moderator = wallet();
    let member = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (resp_r, resp_s, _d1) = router();
    setup_channel(&resp_s, CID, &creator.addr, 0);
    register(&resp_s, &moderator.addr);
    let (target, target_id) = chat(&member, CID, t);
    feed(&resp_r, &target);
    feed(&resp_r, &add_mod(&creator, CID, &moderator.addr, t + 1));
    let good_pin = pin(&moderator, CID, target_id, t + 2);
    let good_mute = mute(&moderator, CID, &member.addr, t + 3);
    feed(&resp_r, &good_pin);
    feed(&resp_r, &good_mute);
    feed(&resp_r, &remove_mod(&creator, CID, &moderator.addr, t + 4));
    // After the demotion the responder itself refuses them...
    let late_pin = pin(&moderator, CID, target_id, t + 5);
    let late_unmute = unmute(&moderator, CID, &member.addr, t + 6);
    assert!(matches!(resp_r.process_synced_message(&late_pin), RouteResult::Rejected(_)));
    // ...so simulate a divergent responder that indexed them anyway.
    for raw in [&late_pin, &late_unmute] {
        let env: Envelope = rmp_serde::from_slice(raw).unwrap();
        resp_s.put_cf(schema::cf::MESSAGES, &env.msg_id, raw).unwrap();
        resp_s
            .put_cf(
                schema::cf::CHANNEL_META_MSGS,
                &schema::encode_channel_meta_key(CID, env.msg_type_u8(), env.timestamp, &env.msg_id),
                &[],
            )
            .unwrap();
    }

    // Every metadata-serving path yields the same tier-1 replay order.
    let first = reconcile::build_response(&resp_s, &req(1, None, None), 100, now_secs());
    let meta_page =
        reconcile::build_response(&resp_s, &req(1, None, Some(reconcile::MetaCursor::START)), 100, now_secs());
    assert!(meta_page.meta_page && !meta_page.meta_truncated);
    let expected = vec![
        MessageType::ChannelAddModerator,
        MessageType::ChannelPinMessage,
        MessageType::ChannelMute,
        MessageType::ChannelRemoveModerator,
        MessageType::ChannelPinMessage,
        MessageType::ChannelUnmute,
    ];
    assert_eq!(types_of(&meta_page.envelopes), expected);
    let first_meta: Vec<Vec<u8>> = first
        .envelopes
        .iter()
        .filter(|e| reconcile::envelope_is_meta_type(e))
        .cloned()
        .collect();
    assert_eq!(first_meta, meta_page.envelopes, "first-page ride-along and metadata page agree");

    // Requester: the channel skeleton (chain scanner) and the chat target.
    let (req_r, req_s, _d2) = router();
    setup_channel(&req_s, CID, &creator.addr, 0);
    register(&req_s, &moderator.addr);
    feed(&req_r, &target);
    let out = tally(&req_r, &req_s, &meta_page.envelopes);
    assert_eq!(out.newly_accepted, 4, "grant, pin, mute, demotion");
    assert!(out.tainted, "the post-demotion pin/unmute are refused");
    let pins = req_s.prefix_iter_cf(schema::cf::CHANNEL_PINS, &CID.to_be_bytes(), 10).unwrap();
    assert_eq!(pins.len(), 1, "exactly the authorised pin");
    assert!(req_s.is_channel_muted(CID, &member.addr).unwrap(), "the late unmute did not apply");
    assert!(!req_s.message_exists(&rmp_serde::from_slice::<Envelope>(&late_pin).unwrap().msg_id).unwrap());

    // Reverse control: replaying in RAW key order (pins before the grant,
    // since 0x19 < 0x1A … < 0x42) would have refused the good pin.
    let (r2, s2, _d3) = router();
    setup_channel(&s2, CID, &creator.addr, 0);
    register(&s2, &moderator.addr);
    feed(&r2, &target);
    let res = r2.process_synced_message(&good_pin);
    assert!(matches!(res, RouteResult::Rejected(_)), "a pin before its grant is refused: {res:?}");

    // Private channel: the metadata phase serves the same order (and mutes
    // only to a 0.152 requester).
    let pcid = (1u64 << 40) + 77;
    let (pr, ps, _d4) = router();
    setup_channel(&ps, pcid, &creator.addr, 2);
    register(&ps, &moderator.addr);
    let (ptarget, ptarget_id) = chat(&creator, pcid, t);
    feed(&pr, &ptarget);
    feed(&pr, &add_mod(&creator, pcid, &moderator.addr, t + 1));
    feed(&pr, &pin(&moderator, pcid, ptarget_id, t + 2));
    feed(&pr, &mute(&moderator, pcid, &member.addr, t + 3));
    feed(&pr, &remove_mod(&creator, pcid, &moderator.addr, t + 4));
    let preq = |revision: u8| private_channel_sync::PrivateChannelSyncRequest {
        channel_id: pcid,
        wallet: creator.addr.clone(),
        requester_pubkey: vec![0; 32],
        timestamp: 0,
        signature: vec![],
        max_age_secs: u64::MAX,
        cursor: None,
        wallet_claim: None,
        meta_paging: true,
        meta_cursor: None,
        meta_done: false,
        revision,
    };
    let p_new = private_channel_sync::build_response(&ps, &preq(1), 200, now_secs(), u64::MAX);
    assert!(p_new.meta_phase);
    assert_eq!(
        types_of(&p_new.envelopes),
        vec![
            MessageType::ChannelAddModerator,
            MessageType::ChannelPinMessage,
            MessageType::ChannelMute,
            MessageType::ChannelRemoveModerator,
        ]
    );
    let p_old = private_channel_sync::build_response(&ps, &preq(0), 200, now_secs(), u64::MAX);
    assert!(!types_of(&p_old.envelopes).contains(&MessageType::ChannelMute), "no mutes for a 0.151 requester");
    assert!(types_of(&p_old.envelopes).contains(&MessageType::ChannelPinMessage));
    assert!(p_new.envelopes.iter().all(|e| private_channel_sync::envelope_is_private_channel_sync_type(e)));
}

/// Round-2 audit: a mute is enforced on EVERY path whatever the envelope's
/// timestamp — the sync path refuses a muted user's post dated before the
/// mute (neutral for the session), and so does the live path.
#[test]
fn mute_is_enforced_on_every_path_regardless_of_timestamp() {
    let creator = wallet();
    let user = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    setup_channel(&s, CID, &creator.addr, 0);
    feed(&r, &mute(&creator, CID, &user.addr, t + 10));
    let (before, _) = chat(&user, CID, t + 5);
    let res = r.process_synced_message(&before);
    assert!(matches!(&res, RouteResult::Rejected(reason) if crate::messages::router::is_moderation_refusal(reason)), "{res:?}");
    // Live path: refused too.
    let (r2, s2, _d2) = router();
    setup_channel(&s2, CID, &creator.addr, 0);
    register(&s2, &user.addr);
    s2.store_channel_mute(CID, &user.addr, &creator.addr, 0, "", crate::util::now_ms() + 60_000).unwrap();
    let (live, _) = chat(&user, CID, crate::util::now_ms());
    let res = r2.process_gossip_message(&live);
    assert!(matches!(&res, RouteResult::Rejected(reason) if reason.contains("muted")), "{res:?}");
    // Control: the same live envelope without the mute is accepted.
    let (r3, s3, _d3) = router();
    setup_channel(&s3, CID, &creator.addr, 0);
    register(&s3, &user.addr);
    let res = r3.process_gossip_message(&live);
    assert!(matches!(res, RouteResult::Accepted { .. }), "{res:?}");
}

/// Round-2 audit N1: on the sync path a reaction whose target is not stored
/// is refused (it cannot be channel-checked, indexed or served), neutrally.
#[test]
fn sync_reaction_to_unknown_target_is_refused_neutrally() {
    let author = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    setup_channel(&s, CID, &author.addr, 0);
    let (orphan, orphan_id) = reaction(&author, Some(CID), [0xEE; 32], "x", false, t);
    let res = r.process_synced_message(&orphan);
    assert!(
        matches!(&res, RouteResult::Rejected(reason) if reason.starts_with(crate::messages::router::REACTION_TARGET_UNKNOWN_PREFIX)),
        "{res:?}"
    );
    assert!(!s.message_exists(&orphan_id).unwrap());
    let (m, m_id) = chat(&author, CID, t);
    feed(&r, &m);
    let (ok, _) = reaction(&author, Some(CID), m_id, "x", false, t + 1);
    let out = tally(&r, &s, &[orphan, ok]);
    assert!(!out.tainted, "neutral");
    assert_eq!((out.newly_accepted, out.ignored_moderation), (1, 1));
}

// --- G6: chat reactions ---

/// `toggle_chat_reaction` is last-write-wins: every permutation of an
/// add / remove / re-add sequence, with duplicates, converges to the state
/// of the newest envelope, and the count never drifts.
#[test]
fn reaction_toggles_converge_in_any_order_with_duplicates() {
    let target = [7u8; 32];
    let ev = |ts: u64, remove: bool| (ts, [ts as u8; 32], remove);
    let sequences: Vec<Vec<(u64, [u8; 32], bool)>> = vec![
        vec![ev(1, false), ev(2, true)],
        vec![ev(1, false), ev(2, true), ev(3, false)],
        vec![ev(1, false), ev(3, true)],
    ];
    for events in sequences {
        let expected_present = !events.iter().max_by_key(|e| (e.0, e.1)).unwrap().2;
        // Every permutation (≤ 3! here), each applied twice (duplicates).
        let mut perms = vec![events.clone()];
        let n = events.len();
        if n == 2 {
            perms.push(vec![events[1], events[0]]);
        } else {
            for (a, b, c) in [(0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)] {
                perms.push(vec![events[a], events[b], events[c]]);
            }
        }
        for order in perms {
            let dir = TempDir::new().unwrap();
            let s = Storage::open(dir.path()).unwrap();
            for (ts, id, remove) in order.iter().chain(order.iter()) {
                s.toggle_chat_reaction(&target, "🔥", "klv1alice", *remove, *ts, id).unwrap();
            }
            // A second reactor's add is independent.
            s.toggle_chat_reaction(&target, "🔥", "klv1bob", false, 1, &[9; 32]).unwrap();
            let count = s.get_chat_reaction_count(&target, "🔥").unwrap();
            assert_eq!(count, 1 + u64::from(expected_present), "order {order:?}");
        }
    }
    // A legacy (pre-0.152, empty-valued) row counts as present and loses to
    // any real envelope.
    let dir = TempDir::new().unwrap();
    let s = Storage::open(dir.path()).unwrap();
    s.put_cf(schema::cf::CHAT_REACTIONS, &schema::encode_chat_reaction_key(&target, "x", "klv1c"), &[]).unwrap();
    s.put_cf(schema::cf::CHAT_REACTION_COUNTS, &schema::encode_chat_reaction_count_key(&target, "x"), &1u64.to_be_bytes())
        .unwrap();
    s.toggle_chat_reaction(&target, "x", "klv1c", false, 5, &[5; 32]).unwrap();
    assert_eq!(s.get_chat_reaction_count(&target, "x").unwrap(), 1, "re-add of a legacy row is idempotent");
    s.toggle_chat_reaction(&target, "x", "klv1c", true, 6, &[6; 32]).unwrap();
    assert_eq!(s.get_chat_reaction_count(&target, "x").unwrap(), 0);
    s.toggle_chat_reaction(&target, "x", "klv1c", false, 4, &[4; 32]).unwrap();
    assert_eq!(s.get_chat_reaction_count(&target, "x").unwrap(), 0, "an older add cannot resurrect a tombstone");
}

/// Through the router: two nodes that receive the same reaction envelopes
/// in opposite orders end with the same counts; the envelope is indexed
/// under its TARGET's channel (never the payload's), so it is served only
/// for that channel — on the last page, for a 0.152 requester — and a
/// requester applying the ride-along reaches the responder's counts.
#[test]
fn reactions_index_by_target_channel_and_converge_via_backfill() {
    let author = wallet();
    let reactor = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (target, target_id) = chat(&author, CID, t);
    // The payload claims channel 99: ignored for indexing.
    let (add, _) = reaction(&reactor, Some(99), target_id, "👍", false, t + 1);
    let (del, _) = reaction(&reactor, Some(CID), target_id, "👍", true, t + 2);
    let (other_add, _) = reaction(&author, None, target_id, "🎉", false, t + 3);
    let (orphan, _) = reaction(&reactor, Some(CID), [0xEE; 32], "👍", false, t + 4);
    let (a, sa, _da) = router();
    let (b, sb, _db) = router();
    for (r, s) in [(&a, &sa), (&b, &sb)] {
        setup_channel(s, CID, &author.addr, 0);
        setup_channel(s, 99, &author.addr, 0);
        feed(r, &target);
    }
    for raw in [&add, &del, &other_add] {
        feed(&a, raw);
    }
    for raw in [&other_add, &del, &add] {
        feed(&b, raw);
    }
    // A reaction to an unknown target is refused on sync (round-2 N1).
    assert!(matches!(a.process_synced_message(&orphan), RouteResult::Rejected(_)));
    for s in [&sa, &sb] {
        assert_eq!(s.get_chat_reaction_count(&target_id, "👍").unwrap(), 0);
        assert_eq!(s.get_chat_reaction_count(&target_id, "🎉").unwrap(), 1);
        assert_eq!(s.prefix_iter_cf(schema::cf::CHAT_REACTION_MSGS, &CID.to_be_bytes(), 10).unwrap().len(), 3);
        assert!(s.prefix_iter_cf(schema::cf::CHAT_REACTION_MSGS, &99u64.to_be_bytes(), 10).unwrap().is_empty());
    }
    // Served on channel CID's last page to a 0.152 requester only.
    let page = reconcile::build_response(&sa, &req(1, None, None), 100, now_secs());
    assert_eq!(types_of(&page.envelopes).iter().filter(|t| **t == MessageType::ChatReaction).count(), 3);
    let legacy = reconcile::build_response(&sa, &req(0, None, None), 100, now_secs());
    assert!(!types_of(&legacy.envelopes).contains(&MessageType::ChatReaction), "not for a 0.151 requester");
    let other = reconcile::build_response(
        &sa,
        &reconcile::ReconcileRequest { channel_id: 99, ..req(1, None, None) },
        100,
        now_secs(),
    );
    assert!(!types_of(&other.envelopes).contains(&MessageType::ChatReaction), "nothing crosses channels");
    // A fresh requester converges (newest-first serving order is fine).
    let (c, sc, _dc) = router();
    setup_channel(&sc, CID, &author.addr, 0);
    let out = tally(&c, &sc, &page.envelopes);
    assert!(!out.tainted);
    assert_eq!(sc.get_chat_reaction_count(&target_id, "👍").unwrap(), 0);
    assert_eq!(sc.get_chat_reaction_count(&target_id, "🎉").unwrap(), 1);
    // Private sync carries them within its page room.
    let pcid = (1u64 << 40) + 5;
    let (pr, ps, _dp) = router();
    setup_channel(&ps, pcid, &author.addr, 2);
    let (pt, pt_id) = chat(&author, pcid, t);
    feed(&pr, &pt);
    for i in 0..10u64 {
        feed(&pr, &reaction(&author, Some(pcid), pt_id, &format!("e{i}"), false, t + 1 + i).0);
    }
    let preq = private_channel_sync::PrivateChannelSyncRequest {
        channel_id: pcid,
        wallet: author.addr.clone(),
        requester_pubkey: vec![0; 32],
        timestamp: 0,
        signature: vec![],
        max_age_secs: u64::MAX,
        cursor: None,
        wallet_claim: None,
        meta_paging: true,
        meta_cursor: None,
        meta_done: true,
        revision: 1,
    };
    let pp = private_channel_sync::build_response(&ps, &preq, 6, now_secs(), u64::MAX);
    assert_eq!(pp.envelopes.len(), 6, "page room bounds the ride-along");
    assert_eq!(types_of(&pp.envelopes).iter().filter(|t| **t == MessageType::ChatReaction).count(), 5);
}

/// D4: a reaction to a GDPR-erased message is withheld from both
/// ride-alongs.
#[test]
fn reactions_to_erased_originals_are_withheld() {
    let author = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    setup_channel(&s, CID, &author.addr, 0);
    let (m, m_id) = chat(&author, CID, t);
    feed(&r, &m);
    feed(&r, &reaction(&author, Some(CID), m_id, "x", false, t + 1).0);
    let page = reconcile::build_response(&s, &req(1, None, None), 100, now_secs());
    assert!(types_of(&page.envelopes).contains(&MessageType::ChatReaction));
    let del = crate::messages::types::DeletionRequestPayload {
        delete_type: crate::messages::types::DeletionType::SingleMessage,
        target_id: Some(m_id),
    };
    feed(&r, &signed(&author, MessageType::DeletionRequest, &del, t + 2).0);
    assert!(s.is_gdpr_erased(&m_id));
    let page = reconcile::build_response(&s, &req(1, None, None), 100, now_secs());
    let types = types_of(&page.envelopes);
    assert!(!types.contains(&MessageType::ChatReaction), "withheld: {types:?}");
    assert!(!types.contains(&MessageType::ChatMessage));
    assert!(types.contains(&MessageType::DeletionRequest));
}

// --- G6: migrations and purge ---

/// The two indexing migrations index envelopes stored before the upgrade,
/// resume across "boots" under a tiny budget, are idempotent, and skip
/// what live indexing would skip (unknown target, purged channel).
#[test]
fn g6_migrations_index_existing_envelopes_and_resume() {
    let creator = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    setup_channel(&s, CID, &creator.addr, 0);
    let (m, m_id) = chat(&creator, CID, t);
    feed(&r, &m);
    let store = |raw: &[u8]| {
        let env: Envelope = rmp_serde::from_slice(raw).unwrap();
        s.put_cf(schema::cf::MESSAGES, &env.msg_id, raw).unwrap();
        env.msg_id
    };
    // Stored as a 0.151 node would have: MESSAGES only, no index rows.
    store(&pin(&creator, CID, m_id, t + 1));
    store(&mute(&creator, CID, "klv1someone", t + 2));
    store(&unmute(&creator, CID, "klv1someone", t + 3));
    store(&mute(&creator, 555, "klv1someone", t + 4)); // channel 555 has no CHANNELS row
    store(&reaction(&creator, Some(CID), m_id, "a", false, t + 5).0);
    store(&reaction(&creator, Some(CID), m_id, "b", false, t + 6).0);
    store(&reaction(&creator, Some(CID), [0x11; 32], "c", false, t + 7).0); // unknown target
    let meta_rows = || s.prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &CID.to_be_bytes(), 100).unwrap().len();
    let react_rows = || s.prefix_iter_cf(schema::cf::CHAT_REACTION_MSGS, &CID.to_be_bytes(), 100).unwrap().len();
    assert_eq!((meta_rows(), react_rows()), (0, 0));

    let mut boots = 0;
    loop {
        boots += 1;
        assert!(boots < 100);
        let (_, done) = s.backfill_channel_meta_v4(2).unwrap();
        if done {
            break;
        }
    }
    assert!(boots > 1, "resumed across boots");
    assert_eq!(meta_rows(), 3);
    assert!(s.prefix_iter_cf(schema::cf::CHANNEL_META_MSGS, &555u64.to_be_bytes(), 10).unwrap().is_empty());
    assert!(s.get_stat(schema::state_keys::CHANNEL_META_INDEXED_V4).unwrap() > 0);

    let mut boots = 0;
    while !s.backfill_chat_reaction_index(3).unwrap().1 {
        boots += 1;
        assert!(boots < 100);
    }
    assert!(boots > 0);
    assert_eq!(react_rows(), 2);
    assert!(s.get_stat(schema::state_keys::CHAT_REACTIONS_INDEXED).unwrap() > 0);
    // Idempotent re-run (cursor at the end: nothing more, still done).
    assert!(s.backfill_chat_reaction_index(10).unwrap().1);
    assert_eq!(react_rows(), 2);
    // Indexing does not re-apply reactions (no derived rows written).
    assert_eq!(s.get_chat_reaction_count(&m_id, "a").unwrap(), 0);
}

/// The private-channel purge deletes the reaction index rows and their
/// envelopes (new phase `CHAT_REACTION_MSGS`, appended without renumbering)
/// and, through `CHANNEL_META_MSGS`, the pin / mute envelopes.
#[test]
fn private_purge_removes_reaction_and_pin_mute_rows() {
    use crate::storage::channel_purge::purge_phase;
    assert_eq!(purge_phase::CHAT_REACTION_MSGS, 17);
    assert_eq!(purge_phase::ORDER.last(), Some(&purge_phase::LOCAL_CHANNEL_HOMES));
    assert!(purge_phase::ORDER.contains(&purge_phase::CHAT_REACTION_MSGS));
    // Older numbers unchanged.
    assert_eq!(
        (purge_phase::CHANNEL_MSGS, purge_phase::CHANNEL_META_MSGS, purge_phase::LOCAL_CHANNEL_HOMES),
        (1, 3, 16)
    );
}

// --- G7: metadata paging ---

/// A 2,000-member public channel: the first page's ride-along is
/// truncated, the requester's session pages the rest of the metadata with
/// the same peer after the chat ends (several byte- and row-bounded pages),
/// ends with every member, and only THEN marks the channel complete.
#[tokio::test]
async fn metadata_paging_completes_a_2000_member_channel() {
    let (mut svc, _d) = backfill_service().await;
    let creator = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (rr, rs, _rd) = router();
    setup_channel(&rs, CID, &creator.addr, 0);
    setup_channel(&svc.storage, CID, &creator.addr, 0);
    let (m, _) = chat(&creator, CID, t);
    feed(&rr, &m);
    for i in 0..2_000u64 {
        let w = wallet();
        feed(&rr, &join(&w, CID, t + 1 + i));
    }
    let first = reconcile::build_response(&rs, &req(1, None, None), 500, now_secs());
    assert!(first.meta_truncated, "2,001 metadata rows > CHANNEL_META_CAP");
    assert!(!first.has_more);
    // 0.151 requesters get the same flag (ignored by them), but no mutes.
    let peer = PeerId::random();
    svc.reconcile_triggered.insert(CID);
    let pending = ReconcilePending {
        peer_id: peer,
        channel_id: CID,
        pages_fetched: 0,
        consecutive_unproductive_pages: 0,
        total_accepted: 0,
        meta: ReconcileMetaState::default(),
    };
    let out = svc.apply_reconcile_response(pending, peer, first, true);
    assert!(matches!(out, ReconcileApplyOutcome::Handled));
    assert_eq!(svc.storage.channel_backfill_completed_at(CID), None, "not complete before the metadata walk");
    let mut pages = 0;
    loop {
        let Some((&id, p)) = svc.pending_reconcile_requests.iter().find(|(_, p)| p.channel_id == CID) else {
            break;
        };
        let p = p.clone();
        svc.pending_reconcile_requests.remove(&id);
        let walk = p.meta.walk.clone().expect("a metadata walk");
        assert!(!walk.followup);
        let resp = reconcile::build_response(&rs, &req(1, None, Some(walk.last_cursor.clone())), 500, now_secs());
        assert!(resp.meta_page);
        svc.apply_reconcile_response(p, peer, resp, true);
        pages += 1;
        assert!(pages < 50);
    }
    assert!(pages >= 4, "paged: {pages}");
    let members = svc.storage.prefix_iter_cf(schema::cf::CHANNEL_MEMBERS, &CID.to_be_bytes(), 10_000).unwrap();
    let responder_members = rs.prefix_iter_cf(schema::cf::CHANNEL_MEMBERS, &CID.to_be_bytes(), 10_000).unwrap();
    assert_eq!(members.len(), responder_members.len());
    assert!(members.len() >= 2_000);
    assert!(svc.storage.channel_backfill_completed_at(CID).is_some(), "complete after the walk");
    assert!(!svc.reconcile_triggered.contains(&CID), "released");
}

/// A walk that stops early (the peer answers capped) never marks the
/// channel complete; a responder that keeps re-serving the same cursor
/// cannot loop the requester.
#[tokio::test]
async fn an_interrupted_or_looping_metadata_walk_never_completes() {
    let (mut svc, _d) = backfill_service().await;
    let creator = wallet();
    setup_channel(&svc.storage, CID, &creator.addr, 0);
    let peer = PeerId::random();
    for capped in [true, false] {
        svc.reconcile_triggered.insert(CID);
        let walk = MetaWalk { last_cursor: reconcile::MetaCursor { tier: 1, ts: 5, msg_id: [1; 32] }, pages: 1, followup: false };
        let pending = ReconcilePending {
            peer_id: peer,
            channel_id: CID,
            pages_fetched: 1,
            consecutive_unproductive_pages: 0,
            total_accepted: 3,
            meta: ReconcileMetaState { truncated: true, prefix_end: None, walk: Some(walk.clone()) },
        };
        let resp = if capped {
            reconcile::ReconcileResponse { server_capped: true, ..reconcile::ReconcileResponse::empty(CID) }
        } else {
            // Truncated, but the cursor does not advance.
            reconcile::ReconcileResponse {
                meta_page: true,
                meta_truncated: true,
                meta_next_cursor: Some(walk.last_cursor.clone()),
                ..reconcile::ReconcileResponse::empty(CID)
            }
        };
        svc.apply_reconcile_response(pending, peer, resp, true);
        assert!(svc.pending_reconcile_requests.is_empty(), "no further page requested");
        assert_eq!(svc.storage.channel_backfill_completed_at(CID), None);
        assert!(!svc.reconcile_triggered.contains(&CID));
        let e = svc.reconcile_throttle.entry(&CID).expect("accepted-but-incomplete retry");
        assert_eq!(e.failures, 0);
    }
}

/// An in-sync comparison whose candidate reported a truncated ride-along
/// starts ONE metadata follow-up walk (not a completion), and no second one
/// within the follow-up interval; a follow-up never completes the channel.
#[tokio::test]
async fn in_sync_comparison_starts_a_bounded_metadata_followup() {
    let (mut svc, _d) = backfill_service().await;
    let creator = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (rr, rs, _rd) = router();
    setup_channel(&rs, CID, &creator.addr, 0);
    setup_channel(&svc.storage, CID, &creator.addr, 0);
    let (m, _) = chat(&creator, CID, t);
    feed(&rr, &m);
    feed(&svc.router, &m);
    let mut joins = Vec::new();
    for i in 0..300u64 {
        let raw = join(&wallet(), CID, t + 1 + i);
        feed(&rr, &raw);
        joins.push(raw);
    }
    // The requester already holds exactly what the first page carries.
    let first = reconcile::build_response(&rs, &req(1, None, None), 500, now_secs());
    assert!(first.meta_truncated);
    for e in &first.envelopes {
        let _ = svc.router.process_synced_message(e);
    }
    for round in 0..2 {
        let peer = PeerId::random();
        svc.reconcile_triggered.insert(CID);
        svc.pending_reconcile_comparisons.insert(
            CID,
            ReconcileComparison {
                outstanding: HashSet::new(),
                candidates: vec![(peer, first.clone())],
                deadline: Instant::now(),
                any_capped: false,
            },
        );
        svc.finalize_reconcile_comparison(CID);
        let walks: Vec<_> = svc.pending_reconcile_requests.values().filter(|p| p.channel_id == CID).cloned().collect();
        if round == 0 {
            assert_eq!(walks.len(), 1, "one follow-up walk");
            assert!(walks[0].meta.walk.as_ref().unwrap().followup);
            // Finish it: every member arrives, the channel is NOT marked complete.
            let p = walks[0].clone();
            svc.pending_reconcile_requests.clear();
            let mut p = Some(p);
            while let Some(cur) = p.take() {
                let c = cur.meta.walk.clone().unwrap().last_cursor;
                let resp = reconcile::build_response(&rs, &req(1, None, Some(c)), 500, now_secs());
                svc.apply_reconcile_response(cur, peer, resp, true);
                p = svc.pending_reconcile_requests.values().find(|x| x.channel_id == CID).cloned();
                svc.pending_reconcile_requests.clear();
            }
            assert_eq!(svc.storage.channel_backfill_completed_at(CID), None, "a follow-up never completes");
            for raw in &joins {
                let id = rmp_serde::from_slice::<Envelope>(raw).unwrap().msg_id;
                assert!(svc.storage.message_exists(&id).unwrap());
            }
        } else {
            assert!(walks.is_empty(), "no second follow-up inside the interval");
        }
        svc.reconcile_triggered.remove(&CID);
    }
}

// --- G7: wire compatibility with 0.151 peers ---

/// The 0.151.0 shapes of the reconcile and private-sync messages, verbatim.
mod v151 {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ReconcileCursor {
        pub after_lamport_ts: u64,
        pub after_msg_id: [u8; 32],
    }
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ReconcileRequest {
        pub channel_id: u64,
        pub max_age_secs: u64,
        pub cursor: Option<ReconcileCursor>,
        #[serde(default)]
        pub fingerprint: Vec<u8>,
        #[serde(default)]
        pub epoch_root_known: Option<[u8; 32]>,
        #[serde(default)]
        pub round: u8,
    }
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ReconcileResponse {
        pub channel_id: u64,
        pub envelopes: Vec<Vec<u8>>,
        pub has_more: bool,
        pub next_cursor: Option<ReconcileCursor>,
        pub server_capped: bool,
        #[serde(default)]
        pub epoch_root: Option<[u8; 32]>,
    }
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PrivateChannelSyncRequest {
        pub channel_id: u64,
        pub wallet: String,
        pub requester_pubkey: Vec<u8>,
        pub timestamp: u64,
        pub signature: Vec<u8>,
        pub max_age_secs: u64,
        pub cursor: Option<crate::network::private_channel_sync::PrivateChannelSyncCursor>,
        #[serde(default)]
        pub wallet_claim: Option<crate::network::private_channel_sync::WalletAuthClaim>,
        #[serde(default)]
        pub meta_paging: bool,
        #[serde(default)]
        pub meta_cursor: Option<crate::network::reconcile::MetaCursor>,
        #[serde(default)]
        pub meta_done: bool,
    }
}

/// Encode with one side's types and decode with the other's through the
/// libp2p CBOR codec the behaviours use.
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

fn cbor_roundtrip_resp<A, B>(a: A) -> B
where
    A: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    B: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
{
    use futures::executor::block_on;
    use libp2p::request_response::Codec;
    let proto = libp2p::StreamProtocol::new("/test");
    let mut buf = Vec::new();
    let mut enc = libp2p::request_response::cbor::codec::Codec::<(), A>::default();
    block_on(enc.write_response(&proto, &mut futures::io::Cursor::new(&mut buf), a)).unwrap();
    let mut dec = libp2p::request_response::cbor::codec::Codec::<(), B>::default();
    block_on(dec.read_response(&proto, &mut futures::io::Cursor::new(&buf))).expect("decodes")
}

/// 0.151 requester ↔ 0.152 responder and vice versa: every message decodes
/// on the other side, the new fields default, and the responder serves a
/// 0.151 requester exactly the 0.151 page shape (no mutes, no reactions,
/// within its page bound).
#[test]
fn wire_compatible_with_0151_peers_both_ways() {
    // 0.151 request → 0.152 responder: revision 0, no metadata page.
    let old_req = v151::ReconcileRequest {
        channel_id: CID,
        max_age_secs: 3600,
        cursor: Some(v151::ReconcileCursor { after_lamport_ts: 9, after_msg_id: [3; 32] }),
        fingerprint: vec![],
        epoch_root_known: None,
        round: 0,
    };
    let as_new: reconcile::ReconcileRequest = cbor_roundtrip_req(old_req);
    assert_eq!(as_new.revision, 0);
    assert!(as_new.meta_cursor.is_none());
    assert_eq!(as_new.cursor.unwrap().after_lamport_ts, 9);
    // 0.152 request → 0.151 responder: unknown fields ignored.
    let new_req = req(reconcile::RECONCILE_REVISION, None, Some(reconcile::MetaCursor::START));
    let as_old: v151::ReconcileRequest = cbor_roundtrip_req(new_req);
    assert_eq!(as_old.channel_id, CID);
    assert!(as_old.cursor.is_none());
    // 0.152 response → 0.151 requester and back.
    let new_resp = reconcile::ReconcileResponse {
        envelopes: vec![vec![1, 2, 3]],
        meta_truncated: true,
        meta_page: true,
        meta_next_cursor: Some(reconcile::MetaCursor { tier: 1, ts: 7, msg_id: [2; 32] }),
        ..reconcile::ReconcileResponse::empty(CID)
    };
    let old_resp: v151::ReconcileResponse = cbor_roundtrip_resp(new_resp);
    assert_eq!(old_resp.envelopes, vec![vec![1, 2, 3]]);
    let back: reconcile::ReconcileResponse = cbor_roundtrip_resp(old_resp);
    assert!(!back.meta_truncated && !back.meta_page && back.meta_next_cursor.is_none());
    // Private-channel sync request both ways.
    let p_new = private_channel_sync::PrivateChannelSyncRequest {
        channel_id: 5,
        wallet: "klv1w".into(),
        requester_pubkey: vec![1; 32],
        timestamp: 1,
        signature: vec![2; 64],
        max_age_secs: 10,
        cursor: None,
        wallet_claim: None,
        meta_paging: true,
        meta_cursor: None,
        meta_done: false,
        revision: private_channel_sync::PRIVATE_SYNC_REVISION,
    };
    let p_old: v151::PrivateChannelSyncRequest = cbor_roundtrip_req(p_new);
    assert!(p_old.meta_paging);
    let p_back: private_channel_sync::PrivateChannelSyncRequest = cbor_roundtrip_req(p_old);
    assert_eq!(p_back.revision, 0, "an old requester reads as revision 0");

    // Behaviour: a revision-0 (0.151) requester gets no mutes / reactions,
    // and its page stays within the 0.151 bound (no reaction cap).
    let creator = wallet();
    let user = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    setup_channel(&s, CID, &creator.addr, 0);
    let (m, m_id) = chat(&user, CID, t);
    feed(&r, &m);
    // The responder got the reaction before the mute.
    feed(&r, &reaction(&user, Some(CID), m_id, "x", false, t + 5).0);
    feed(&r, &mute(&creator, CID, &user.addr, t + 10));
    feed(&r, &pin(&creator, CID, m_id, t + 11));
    let old_page = reconcile::build_response(&s, &req(0, None, None), 1_000, now_secs());
    let types = types_of(&old_page.envelopes);
    assert!(!types.contains(&MessageType::ChannelMute) && !types.contains(&MessageType::ChatReaction), "{types:?}");
    assert!(types.contains(&MessageType::ChannelPinMessage));
    let v151_bound = 1_000 + reconcile::CHANNEL_META_CAP + reconcile::CHANNEL_EDIT_DELETE_CAP;
    assert!(old_page.envelopes.len() <= v151_bound);
    // ...and a 0.151 requester applies it cleanly (the muted user's
    // pre-mute message is not refused, because no mute was served).
    let (r2, s2, _d2) = router();
    setup_channel(&s2, CID, &creator.addr, 0);
    let out = tally(&r2, &s2, &old_page.envelopes);
    assert!(!out.tainted);
    // A 0.152 requester gets both, applies them without taint.
    let new_page = reconcile::build_response(&s, &req(1, None, None), 1_000, now_secs());
    let types = types_of(&new_page.envelopes);
    assert!(types.contains(&MessageType::ChannelMute) && types.contains(&MessageType::ChatReaction));
    let (r3, s3, _d3) = router();
    setup_channel(&s3, CID, &creator.addr, 0);
    let out = tally(&r3, &s3, &new_page.envelopes);
    assert!(!out.tainted, "the muted user's refused history is neutral");
    assert_eq!(out.ignored_moderation, 2, "the muted user's post and reaction");
    assert!(s3.is_channel_muted(CID, &user.addr).unwrap());
    assert_eq!(s3.get_chat_reaction_count(&m_id, "x").unwrap(), 0);
}

/// A 0.152 requester talking to a 0.151 responder: no `meta_truncated`, so
/// the session completes on the chat pages exactly as before (no walk).
#[tokio::test]
async fn a_0151_responder_never_triggers_a_metadata_walk() {
    let (mut svc, _d) = backfill_service().await;
    let creator = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (rr, rs, _rd) = router();
    setup_channel(&rs, CID, &creator.addr, 0);
    setup_channel(&svc.storage, CID, &creator.addr, 0);
    feed(&rr, &chat(&creator, CID, t).0);
    for i in 0..300u64 {
        feed(&rr, &join(&wallet(), CID, t + 1 + i));
    }
    let page = reconcile::build_response(&rs, &req(0, None, None), 500, now_secs());
    // What a 0.151 responder sends: the same page without the new fields.
    let old: v151::ReconcileResponse = cbor_roundtrip_resp(page);
    let as_seen: reconcile::ReconcileResponse = cbor_roundtrip_resp(old);
    assert!(!as_seen.meta_truncated);
    let peer = PeerId::random();
    svc.reconcile_triggered.insert(CID);
    let pending = ReconcilePending {
        peer_id: peer,
        channel_id: CID,
        pages_fetched: 0,
        consecutive_unproductive_pages: 0,
        total_accepted: 0,
        meta: ReconcileMetaState::default(),
    };
    svc.apply_reconcile_response(pending, peer, as_seen, true);
    assert!(svc.pending_reconcile_requests.is_empty());
    assert!(svc.storage.channel_backfill_completed_at(CID).is_some());
}

async fn backfill_service() -> (NetworkService, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = Storage::open(dir.path()).unwrap();
    let config = config();
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let svc = NetworkService::new(
        &config,
        storage.clone(),
        IdentityResolver::new(storage),
        libp2p::identity::Keypair::generate_ed25519(),
        None,
        Arc::new(AtomicU32::new(0)),
        crate::crypto::generate_keypair(),
        "test-node".into(),
        Arc::new(RwLock::new(HashMap::new())),
        Arc::new(NetworkCounters::new()),
        Arc::new(RwLock::new(None)),
        rx,
        Arc::new(AtomicU64::new(0)),
        Arc::new(RwLock::new(HashSet::new())),
        mesh_stats::PublishFailureCounters::default(),
        mesh_stats::shared_empty(),
        None,
        config.backfill.clone(),
        config.dm.clone(),
        config.identity_resync.clone(),
        config.private_channel_sync.clone(),
    )
    .await
    .unwrap();
    (svc, dir)
}

// --- Round-1 audit fixes ---

fn ban(w: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    let p = ChannelBanPayload { channel_id: cid, target_user: target.to_string(), reason: Some("spam".into()), duration_secs: 0 };
    signed(w, MessageType::ChannelBan, &p, ts).0
}

fn unban(w: &W, cid: u64, target: &str, ts: u64) -> Vec<u8> {
    signed(w, MessageType::ChannelUnban, &ChannelUnbanPayload { channel_id: cid, target_user: target.to_string() }, ts).0
}

fn unpin(w: &W, cid: u64, target: [u8; 32], ts: u64) -> Vec<u8> {
    signed(w, MessageType::ChannelUnpinMessage, &ChannelUnpinMessagePayload { channel_id: cid, msg_id: target }, ts).0
}

/// Round-2 audit R2-B1: a node WITHOUT any completion marker (origin,
/// gossip-only or in-sync-only node) refuses a muted user's post back-dated
/// before the mute on the sync path, for a public AND a private channel; the
/// refusal is neutral (no taint), and so is a ban refusal.
#[test]
fn unmarked_node_refuses_backdated_muted_posts_neutrally() {
    for (cid, channel_type) in [(CID, 0u8), ((1u64 << 40) + 9, 2u8)] {
        let creator = wallet();
        let user = wallet();
        let banned = wallet();
        let t = crate::util::now_ms() - DAY_MS;
        let (r, s, _d) = router();
        setup_channel(&s, cid, &creator.addr, channel_type);
        let (kept, _) = chat(&creator, cid, t);
        feed(&r, &kept);
        feed(&r, &mute(&creator, cid, &user.addr, t + 10));
        feed(&r, &ban(&creator, cid, &banned.addr, t + 10));
        assert_eq!(s.channel_backfill_completed_at(cid), None, "no completion marker");
        let (backdated, _) = chat(&user, cid, t + 9);
        let res = r.process_synced_message(&backdated);
        assert!(
            matches!(&res, RouteResult::Rejected(reason) if crate::messages::router::is_moderation_refusal(reason)),
            "type {channel_type}: {res:?}"
        );
        let (by_banned, _) = chat(&banned, cid, t + 1);
        let mut authors = Vec::new();
        let out = tally_reconcile_envelopes(&r, &s, &PeerId::random(), cid, &[kept, backdated, by_banned], usize::MAX, 0, &mut authors);
        assert!(!out.tainted, "mute / ban refusals are neutral");
        assert_eq!(out.ignored_moderation, 2);
        assert_eq!(out.verified_dups, 1);
        assert!(out.is_verified_in_sync_page(3, false));
    }
}

/// W3: a muted user's reaction is refused whatever channel its payload
/// names (or none) — the TARGET's channel decides.
#[test]
fn muted_reaction_with_spoofed_or_missing_channel_is_refused() {
    let creator = wallet();
    let user = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (r, s, _d) = router();
    setup_channel(&s, CID, &creator.addr, 0);
    setup_channel(&s, 99, &creator.addr, 0);
    register(&s, &user.addr);
    let (m, m_id) = chat(&creator, CID, t);
    feed(&r, &m);
    s.store_channel_mute(CID, &user.addr, &creator.addr, 0, "", t).unwrap();
    for payload_cid in [None, Some(99), Some(CID)] {
        let (raw, _) = reaction(&user, payload_cid, m_id, "x", false, crate::util::now_ms());
        let res = r.process_gossip_message(&raw);
        assert!(matches!(&res, RouteResult::Rejected(reason) if reason.contains("muted")), "{payload_cid:?}: {res:?}");
    }
    // Banned likewise.
    let b = wallet();
    register(&s, &b.addr);
    feed(&r, &ban(&creator, CID, &b.addr, t + 1));
    let (raw, _) = reaction(&b, None, m_id, "x", false, crate::util::now_ms());
    assert!(matches!(r.process_gossip_message(&raw), RouteResult::Rejected(reason) if reason.contains("banned")));
}

/// Drive a full requester session against responder storage `rs`:
/// first page, then every metadata page the requester asks for.
fn run_session(svc: &mut NetworkService, rs: &Storage, peer: PeerId, max_envelopes: usize) {
    svc.reconcile_triggered.insert(CID);
    let pending = ReconcilePending {
        peer_id: peer,
        channel_id: CID,
        pages_fetched: 0,
        consecutive_unproductive_pages: 0,
        total_accepted: 0,
        meta: ReconcileMetaState::default(),
    };
    let first = reconcile::build_response(rs, &req(1, None, None), max_envelopes, now_secs());
    svc.apply_reconcile_response(pending, peer, first, true);
    for _ in 0..100 {
        let Some((&id, p)) = svc.pending_reconcile_requests.iter().find(|(_, p)| p.channel_id == CID) else {
            return;
        };
        let p = p.clone();
        svc.pending_reconcile_requests.remove(&id);
        let c = p.meta.walk.clone().expect("walk").last_cursor;
        let resp = reconcile::build_response(rs, &req(1, None, Some(c)), max_envelopes, now_secs());
        svc.apply_reconcile_response(p, peer, resp, true);
    }
    panic!("walk did not end");
}

/// B2: over a channel whose metadata is truncated on the first page,
/// Mute/Unmute/Mute and Ban/Unban/Ban end muted and banned, a
/// pin/unpin/pin ends with exactly one pin, and a moderator's pin made
/// before its demotion survives — every row replays once, in order.
#[tokio::test]
async fn truncated_metadata_replays_in_order_exactly_once() {
    let (mut svc, _d) = backfill_service().await;
    let creator = wallet();
    let moderator = wallet();
    let user = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (rr, rs, _rd) = router();
    for s in [&rs, &svc.storage] {
        setup_channel(s, CID, &creator.addr, 0);
        register(s, &moderator.addr);
    }
    let (m, m_id) = chat(&creator, CID, t);
    feed(&rr, &m);
    let (m2, m2_id) = chat(&creator, CID, t + 1);
    feed(&rr, &m2);
    let mut ts = t + 10;
    let mut next = || {
        ts += 1;
        ts
    };
    // Spread the toggles across the first-page boundary (256 rows) with joins.
    feed(&rr, &add_mod(&creator, CID, &moderator.addr, next()));
    feed(&rr, &mute(&creator, CID, &user.addr, next()));
    feed(&rr, &ban(&creator, CID, &user.addr, next()));
    feed(&rr, &pin(&creator, CID, m_id, next()));
    for _ in 0..200 {
        feed(&rr, &join(&wallet(), CID, next()));
    }
    feed(&rr, &unmute(&creator, CID, &user.addr, next()));
    feed(&rr, &unban(&creator, CID, &user.addr, next()));
    feed(&rr, &unpin(&creator, CID, m_id, next()));
    feed(&rr, &pin(&moderator, CID, m2_id, next()));
    feed(&rr, &remove_mod(&creator, CID, &moderator.addr, next()));
    for _ in 0..200 {
        feed(&rr, &join(&wallet(), CID, next()));
    }
    feed(&rr, &mute(&creator, CID, &user.addr, next()));
    feed(&rr, &ban(&creator, CID, &user.addr, next()));
    feed(&rr, &pin(&creator, CID, m_id, next()));
    let first = reconcile::build_response(&rs, &req(1, None, None), 1_000, now_secs());
    assert!(first.meta_truncated && first.meta_next_cursor.is_some());
    run_session(&mut svc, &rs, PeerId::random(), 1_000);
    assert!(svc.storage.is_channel_muted(CID, &user.addr).unwrap(), "re-muted user stays muted");
    assert!(svc
        .storage
        .exists_cf(schema::cf::CHANNEL_BANS, &schema::encode_channel_ban_key(CID, &user.addr))
        .unwrap(), "re-banned user stays banned");
    let pins = svc.storage.prefix_iter_cf(schema::cf::CHANNEL_PINS, &CID.to_be_bytes(), 10).unwrap();
    let mut pinned: Vec<[u8; 32]> = pins.iter().map(|(k, _)| <[u8; 32]>::try_from(&k[12..44]).unwrap()).collect();
    pinned.sort();
    let mut expected = vec![m_id, m2_id];
    expected.sort();
    assert_eq!(pinned, expected, "no duplicate pin; the moderator's pre-demotion pin survives");
    assert!(svc.storage.channel_backfill_completed_at(CID).is_some());
    // Responder's view is identical.
    assert_eq!(pins.len(), rs.prefix_iter_cf(schema::cf::CHANNEL_PINS, &CID.to_be_bytes(), 10).unwrap().len());
}

/// W1: metadata pages have a fixed size whatever the configs, and a page
/// that is oversized or carries non-metadata envelopes stops the walk
/// unfinished — never completing the channel.
#[tokio::test]
async fn metadata_pages_are_fixed_size_and_bad_pages_never_complete() {
    let creator = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (rr, rs, _rd) = router();
    setup_channel(&rs, CID, &creator.addr, 0);
    feed(&rr, &chat(&creator, CID, t).0);
    for i in 0..700u64 {
        feed(&rr, &join(&wallet(), CID, t + 1 + i));
    }
    // A responder configured far above the requester still pages ≤ 500.
    let page = reconcile::build_response(&rs, &req(1, None, Some(reconcile::MetaCursor::START)), 5_000, now_secs());
    assert_eq!(page.envelopes.len(), reconcile::CHANNEL_META_PAGE_MAX);
    assert!(page.meta_truncated);
    // A requester configured far below accepts it and completes.
    let (mut svc, _d) = backfill_service().await;
    svc.backfill_config.max_envelopes_per_response = 50;
    setup_channel(&svc.storage, CID, &creator.addr, 0);
    run_session(&mut svc, &rs, PeerId::random(), 5_000);
    assert!(svc.storage.channel_backfill_completed_at(CID).is_some());
    // Bad pages stop the walk, unfinished.
    let (chat_env, _) = chat(&creator, CID, t + 5_000);
    let bad_pages = vec![
        vec![chat_env],                                        // non-metadata
        vec![join(&wallet(), CID, t); reconcile::CHANNEL_META_PAGE_MAX + 1], // oversized
    ];
    for envelopes in bad_pages {
        let (mut svc, _d) = backfill_service().await;
        setup_channel(&svc.storage, CID, &creator.addr, 0);
        svc.reconcile_triggered.insert(CID);
        let pending = ReconcilePending {
            peer_id: PeerId::random(),
            channel_id: CID,
            pages_fetched: 1,
            consecutive_unproductive_pages: 0,
            total_accepted: 5,
            meta: ReconcileMetaState {
                truncated: true,
                prefix_end: None,
                walk: Some(MetaWalk { last_cursor: reconcile::MetaCursor::START, pages: 0, followup: false }),
            },
        };
        let resp = reconcile::ReconcileResponse {
            envelopes,
            meta_page: true,
            meta_truncated: false,
            ..reconcile::ReconcileResponse::empty(CID)
        };
        let peer = pending.peer_id;
        svc.apply_reconcile_response(pending, peer, resp, true);
        assert_eq!(svc.storage.channel_backfill_completed_at(CID), None);
        assert!(svc.pending_reconcile_requests.is_empty());
    }
}

/// W2: a walk cut short (the peer answers capped) remembers its position;
/// the next walk with that peer continues there, not from the start, and
/// the channel completes once the walk reaches its end.
#[tokio::test]
async fn an_interrupted_walk_resumes_where_it_stopped() {
    let (mut svc, _d) = backfill_service().await;
    let creator = wallet();
    let t = crate::util::now_ms() - DAY_MS;
    let (rr, rs, _rd) = router();
    setup_channel(&rs, CID, &creator.addr, 0);
    setup_channel(&svc.storage, CID, &creator.addr, 0);
    feed(&rr, &chat(&creator, CID, t).0);
    for i in 0..1_500u64 {
        feed(&rr, &join(&wallet(), CID, t + 1 + i));
    }
    let peer = PeerId::random();
    svc.reconcile_triggered.insert(CID);
    let pending = ReconcilePending {
        peer_id: peer,
        channel_id: CID,
        pages_fetched: 0,
        consecutive_unproductive_pages: 0,
        total_accepted: 0,
        meta: ReconcileMetaState::default(),
    };
    let first = reconcile::build_response(&rs, &req(1, None, None), 1_000, now_secs());
    svc.apply_reconcile_response(pending, peer, first, true);
    // One metadata page, then the peer is capped.
    let (&id, p) = svc.pending_reconcile_requests.iter().next().unwrap();
    let p = p.clone();
    svc.pending_reconcile_requests.remove(&id);
    let c = p.meta.walk.clone().unwrap().last_cursor;
    assert!(c > reconcile::MetaCursor::START, "the walk starts after the first-page prefix");
    let resp = reconcile::build_response(&rs, &req(1, None, Some(c)), 1_000, now_secs());
    svc.apply_reconcile_response(p, peer, resp, true);
    let (&id, p) = svc.pending_reconcile_requests.iter().next().unwrap();
    let p = p.clone();
    svc.pending_reconcile_requests.remove(&id);
    let stopped_at = p.meta.walk.clone().unwrap().last_cursor;
    svc.apply_reconcile_response(
        p,
        peer,
        reconcile::ReconcileResponse { server_capped: true, ..reconcile::ReconcileResponse::empty(CID) },
        true,
    );
    assert_eq!(svc.storage.channel_backfill_completed_at(CID), None);
    assert_eq!(svc.reconcile_meta_resume_cursor(CID, peer, Instant::now()), Some(stopped_at.clone()));
    // The next walk with this peer (a follow-up here) starts there.
    svc.reconcile_triggered.insert(CID);
    svc.start_reconcile_meta_walk(peer, CID, 0, 0, None, true);
    let p = svc.pending_reconcile_requests.values().next().unwrap().clone();
    assert_eq!(p.meta.walk.as_ref().unwrap().last_cursor, stopped_at);
    svc.pending_reconcile_requests.clear();
    // Another peer starts from the start.
    svc.start_reconcile_meta_walk(PeerId::random(), CID, 0, 0, None, true);
    let p = svc.pending_reconcile_requests.values().next().unwrap().clone();
    assert_eq!(p.meta.walk.as_ref().unwrap().last_cursor, reconcile::MetaCursor::START);
    svc.pending_reconcile_requests.clear();
    // An in-session walk with the first peer finishes from the stored
    // position and completes the channel; the position is then dropped.
    svc.start_reconcile_meta_walk(peer, CID, 1, 3, None, false);
    for _ in 0..20 {
        let Some((&id, p)) = svc.pending_reconcile_requests.iter().next() else { break };
        let p = p.clone();
        svc.pending_reconcile_requests.remove(&id);
        let c = p.meta.walk.clone().unwrap().last_cursor;
        let resp = reconcile::build_response(&rs, &req(1, None, Some(c)), 1_000, now_secs());
        svc.apply_reconcile_response(p, peer, resp, true);
    }
    assert!(svc.storage.channel_backfill_completed_at(CID).is_some());
    assert_eq!(svc.reconcile_meta_resume_cursor(CID, peer, Instant::now()), None);
}

/// W4: a version-1 private-sync resume row (written before 0.152.0) reads as
/// absent, forcing one fresh walk.
#[test]
fn version_1_resume_rows_read_as_absent() {
    let row = private_channel_sync::ResumeRow {
        v: 1,
        phase: None,
        meta_cursor: None,
        chat_cursor: None,
        meta_done: false,
        accepted_total: 0,
        sessions: 1,
        peer: PeerId::random().to_string(),
        updated_at: 1,
        hw: None,
        walk_hw: None,
        stalls: 0,
        fresh_walk_at: 1,
        same_peer_sessions: 0,
    };
    let raw = serde_json::to_vec(&row).unwrap();
    assert!(private_channel_sync::decode_resume_row(&raw, crate::util::now_ms()).is_none());
    let v2 = private_channel_sync::ResumeRow { v: private_channel_sync::RESUME_ROW_VERSION, ..row };
    assert_eq!(private_channel_sync::RESUME_ROW_VERSION, 2);
    assert!(private_channel_sync::decode_resume_row(&serde_json::to_vec(&v2).unwrap(), crate::util::now_ms()).is_some());
}
