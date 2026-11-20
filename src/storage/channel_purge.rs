//! Private-channel purge reaper (l2-node 0.149.0, plan
//! `docs/planning/private-channel-lifecycle-plan.md` §4, phase C).
//!
//! Deletes the local data of a private channel whose
//! `PRIVATE_CHANNEL_LIFECYCLE` row (`storage::channel_lifecycle`) is due:
//! a `no_local_member` row past its grace, or a `deleted` row (owner
//! decision D4: due at once). Runs from a storage-only background task
//! (`node.rs`, `[private_channels] purge_interval_secs`), at most
//! `purge_batch_rows` deleted rows per pass.
//!
//! **Phase 1 — start** (`start_private_channel_purge`, under
//! `channel_membership_lock`, re-checking everything): the row is still an
//! understood, due `pending` row; the id is above `PRIVATE_CHANNEL_ID_FLOOR`
//! and the `CHANNELS` row is Private or absent; the channel is not pinned;
//! and — unless it is a genuinely deleted channel — no local member exists
//! (`has_local_member`), the channel is not single-host protected (created
//! here, no `federated_from`, creator still a member), and no current member
//! authenticated here since the row was written (`LOCAL_DM_USERS.
//! last_active_ms >= since_ms`; such a member gets a `LOCAL_CHANNEL_HOMES`
//! row and the pending row is deleted — the channel is kept). Activity of a
//! local home that is NOT a member re-arms the row ONCE instead (`since =
//! now`, deadline = now + grace, `activity_rearmed`): a member wrongly
//! removed by a replayed old kick/leave gets a second grace period for its
//! healing sync, a voluntary leaver's channel is purged after two. Then ONE
//! batch deletes the `CHANNELS` row
//! (decrementing `TOTAL_CHANNELS`) and flips the row to `purging` with the
//! captured wallet set and creator. With the `CHANNELS` row gone, joins
//! no-op; while the row says `purging`, re-creating the channel is refused
//! (`put_channel_and_replay_pending_member_removals`, the router's
//! `ChannelCreate` apply), the router refuses — without storing — every
//! envelope targeting the channel (Step 7f; the one exception is a
//! `ChannelDelete` by the captured creator, which writes the permanent
//! tombstone), federation answers 503 and private-sync pages for it are
//! dropped. A pin configured after the purge started does not stop it (a
//! pin only keeps a `pending` row from starting).
//!
//! **Phase 2 — delete** (`purge_step`): one step per [`purge_phase`] value,
//! each a bounded, cursor-resumed scan of one column family. Every pass
//! writes its deletes, the stat-counter decrements AND the advanced
//! `phase`/`cursor_hex` in ONE `WriteBatch`, so a crash at any point resumes
//! from the last persisted position and every step is idempotent (a
//! re-processed row is simply absent). The last step deletes the lifecycle
//! row itself.
//!
//! **Deliberately kept** (owner decision D5): `CHANNEL_ROLE_WATERMARKS`,
//! `CHANNEL_BANS` and `CHANNEL_MUTES` (without them an old pre-kick invite
//! would pass the join gate after a re-federation, and a ban or mute would
//! be lifted), the `DELETED_CHANNELS` tombstone, and `NOTIFICATIONS` (own
//! 30-day reaper). This matters for `no_local_member` purges only: for a
//! deleted channel `tombstone_channel` has already cleared bans and
//! watermarks, and the tombstone keeps the id from ever coming back.
//!
//! **Known residual (orphans).** Since l2-node 0.152.0 (G6) Pin/Unpin and
//! Mute/Unmute envelopes are indexed into `CHANNEL_META_MSGS` and chat
//! reactions into `CHAT_REACTION_MSGS` (step [`purge_phase::
//! CHAT_REACTION_MSGS`]), so their `MESSAGES` rows are purged too — a
//! re-delivered reaction or pin after a re-federation is then stored and
//! applied again instead of being a `Duplicate`. What remains: `ChatReaction`
//! envelopes whose target was not stored when they arrived (never indexed),
//! envelopes stored before the upgrade on a node whose indexing migrations
//! (`CHANNEL_META_INDEXED_V4`, `CHAT_REACTIONS_INDEXED`) had not finished
//! when the purge ran, and `ChannelInvite` envelopes (indexed by nothing):
//! they stay behind (small, opaque, unreachable through any channel read).
//! Likewise `CHANNEL_READ_STATE` rows
//! of wallets that were neither a local home nor a member (mark-read does
//! not check membership), per-wallet rows beyond [`WALLET_CAPTURE_CAP`], and
//! superseded `CHANNEL_KEYS` envelopes whose rows were already evicted
//! before the purge. A forward-only per-channel index of the auxiliary
//! envelopes (`CHANNEL_AUX_MSGS`) would close the first gap; it is not part
//! of this release.
//!
//! **Known limitation (pre-existing).** The router's `ChannelCreate` merge
//! of an EXISTING `CHANNELS` row is an unlocked read-modify-write; one that
//! read the row just before a purge started can write it back after the
//! purge deleted it. `purge_step` then sees the row again and abandons the
//! purge, keeping every remaining row (the safe direction).

use std::collections::HashSet;

use anyhow::{Context, Result};
use rocksdb::WriteBatch;

use super::channel_lifecycle::{
    encode_home, is_private_id, LifecycleReason, LifecycleState, PrivateChannelLifecycleRow,
};
use super::rocks::Storage;
use super::schema::{self, cf, state_keys};

/// Purge steps, persisted in the lifecycle row's `phase`. The numbers are
/// part of the on-disk format: never renumber or reuse one — a new step
/// gets a new number and a place in [`ORDER`](purge_phase::ORDER). A row
/// whose phase this release does not know is left untouched.
pub mod purge_phase {
    /// `CHANNEL_MSGS` (prefix cid) → each message's `MESSAGES` envelope,
    /// `DELETION_MARKERS` row, and `EDIT_HISTORY` / `CHAT_REACTIONS` /
    /// `CHAT_REACTION_COUNTS` / `REPORTS` / `COUNTER_VOTES` /
    /// `DELETION_REQUESTS` rows (prefix msg_id).
    pub const CHANNEL_MSGS: u8 = 1;
    /// `CHANNEL_EDIT_DELETE_MSGS` (prefix cid) → `MESSAGES`.
    pub const CHANNEL_EDIT_DELETE_MSGS: u8 = 2;
    /// `CHANNEL_META_MSGS` (prefix cid) → `MESSAGES`.
    pub const CHANNEL_META_MSGS: u8 = 3;
    /// `CHANNEL_KEYS` (prefix channel scope) → `MESSAGES` (value `msg_id`).
    pub const CHANNEL_KEYS: u8 = 4;
    /// `CHANNEL_KEY_COMMITS` (prefix channel scope, incl. the bare-scope
    /// meta row) → `MESSAGES` (value `msg_id`).
    pub const CHANNEL_KEY_COMMITS: u8 = 5;
    /// `CHANNEL_MEMBERS` (prefix cid).
    pub const CHANNEL_MEMBERS: u8 = 6;
    /// `CHANNEL_MODERATORS` (prefix cid).
    pub const CHANNEL_MODERATORS: u8 = 7;
    /// `CHANNEL_PINS` (prefix cid).
    pub const CHANNEL_PINS: u8 = 8;
    /// `CHANNEL_INVITES` (prefix cid; retired CF, legacy rows).
    pub const CHANNEL_INVITES: u8 = 9;
    /// Retired before release: a no-op step. `CHANNEL_MUTES` rows are KEPT
    /// like `CHANNEL_BANS` (a purge must not lift a moderator's mute after
    /// a re-federation). The number stays reserved in [`ORDER`].
    pub const CHANNEL_MUTES: u8 = 10;
    /// `CHANNEL_MEMBERSHIP_INDEX` (prefix cid).
    pub const CHANNEL_MEMBERSHIP_INDEX: u8 = 11;
    /// `PRIVATE_CHANNEL_KEYS` (prefix cid).
    pub const PRIVATE_CHANNEL_KEYS: u8 = 12;
    /// `PENDING_CHANNEL_MEMBER_REMOVALS` (prefix cid).
    pub const PENDING_CHANNEL_MEMBER_REMOVALS: u8 = 13;
    /// Exact keys: `CHANNEL_VERIFICATION`, `CHANNEL_BACKFILL_STATE`,
    /// `PENDING_CHANNEL_DELETES` (cid) and `NODE_STATE` `pin_seq:{cid}`.
    pub const EXACT_KEYS: u8 = 14;
    /// Per captured wallet (`Storage::stage_purge_wallet_channel_rows`).
    pub const WALLETS: u8 = 15;
    /// `LOCAL_CHANNEL_HOMES` (prefix cid) — last, so the local evidence
    /// outlives every other row of the channel.
    pub const LOCAL_CHANNEL_HOMES: u8 = 16;
    /// `CHAT_REACTION_MSGS` (prefix cid) → `MESSAGES` (the `ChatReaction`
    /// envelopes, l2-node 0.152.0, G6). A new number (the 0.149 numbers are
    /// unchanged), placed in [`ORDER`] after `WALLETS` and before
    /// `LOCAL_CHANNEL_HOMES`: a purge that was in progress when the node
    /// upgraded runs it unless it had already reached `LOCAL_CHANNEL_HOMES`
    /// (its reaction rows then stay behind as recorded orphans). While the
    /// channel is `purging` the router refuses every envelope targeting it
    /// (Step 7f; a reaction is matched by its TARGET's channel), and a
    /// reaction is only indexed while its target is stored — step
    /// `CHANNEL_MSGS` has deleted every target before this step — so no row
    /// is written behind its cursor.
    pub const CHAT_REACTION_MSGS: u8 = 17;

    /// Execution order. After the last step the lifecycle row is deleted.
    pub const ORDER: &[u8] = &[
        CHANNEL_MSGS,
        CHANNEL_EDIT_DELETE_MSGS,
        CHANNEL_META_MSGS,
        CHANNEL_KEYS,
        CHANNEL_KEY_COMMITS,
        CHANNEL_MEMBERS,
        CHANNEL_MODERATORS,
        CHANNEL_PINS,
        CHANNEL_INVITES,
        CHANNEL_MUTES,
        CHANNEL_MEMBERSHIP_INDEX,
        PRIVATE_CHANNEL_KEYS,
        PENDING_CHANNEL_MEMBER_REMOVALS,
        EXACT_KEYS,
        WALLETS,
        CHAT_REACTION_MSGS,
        LOCAL_CHANNEL_HOMES,
    ];
}

/// Max channels whose purge is STARTED per pass (each start scans the
/// channel's member list once).
pub const PURGE_STARTS_PER_PASS: usize = 16;

/// Lifecycle rows the reaper reads per pass (one page from its rotating
/// cursor, `PRIVATE_CHANNEL_PURGE_CURSOR`).
pub const PURGE_SCAN_PAGE: usize = 4096;

/// Phase 1 reads at most this many `CHANNEL_MEMBERS` rows for the
/// `LOCAL_DM_USERS` safety gate; a larger member list cancels the purge
/// (conservative: the gate could not be evaluated completely).
pub const MEMBER_GATE_SCAN_CAP: usize = 10_000;

/// Max wallets captured at the start of a purge whose per-wallet rows
/// (`LOCAL_CHANNEL_FED`, `PRIVATE_CHANNEL_SYNC_STATE`,
/// `PRIVATE_CHANNEL_SYNC_RESUME`, `CHANNEL_READ_STATE`) are deleted. Local homes come first; anything beyond is a recorded
/// residual (tiny node-local rows).
pub const WALLET_CAPTURE_CAP: usize = 4096;

/// Per message and per side column family (reactions, reports, …), at most
/// this many rows are deleted in one pass; a message with more keeps its
/// index row until a later pass has removed the rest.
pub const MSG_SIDE_ROWS_CAP: usize = 4096;

/// Side column families keyed by `msg_id(32) ++ …` that die with a chat
/// message (verified against `encode_edit_history_key`,
/// `encode_chat_reaction_key`, `encode_chat_reaction_count_key`,
/// `encode_report_key`, `encode_counter_vote_key`).
const MSG_SIDE_CFS: [&str; 6] = [
    cf::EDIT_HISTORY,
    cf::CHAT_REACTIONS,
    cf::CHAT_REACTION_COUNTS,
    cf::REPORTS,
    cf::COUNTER_VOTES,
    // l2-node 0.151.0: the verified GDPR deletion-request record of the
    // message (pending rows live in `PENDING_DELETIONS` and expire by TTL).
    cf::DELETION_REQUESTS,
];

/// What one purge pass did (for logging and the `private_channels_purged_
/// total` / `private_channel_purge_rows_total` metrics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgePassReport {
    /// Channels whose purge started (phase 1) this pass.
    pub started: usize,
    /// Due channels whose purge was cancelled at the start (a local member
    /// was found, or the gate could not be evaluated).
    pub cancelled: usize,
    /// Purges abandoned because the channel was re-created meanwhile
    /// (everything left in place).
    pub aborted: usize,
    /// Channels whose purge finished (lifecycle row deleted).
    pub completed: usize,
    /// Rows deleted.
    pub rows: u64,
}

/// Outcome of [`Storage::start_private_channel_purge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeStart {
    /// The channel is now `purging` (its `CHANNELS` row is gone).
    Started,
    /// The pending row was deleted: the channel is kept.
    Cancelled,
    /// A local home that is no longer a member used this node since the
    /// row was written: the row was re-armed ONCE (`since = now`, deadline
    /// = now + grace, `activity_rearmed`); the channel stays unsubscribed.
    Rearmed,
    /// Nothing to do (not due, not understood, pinned, public id, …).
    Skipped,
}

/// Outcome of one [`Storage::purge_step`] call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeStepOutcome {
    /// Rows deleted by this call.
    pub rows: u64,
    /// The purge finished (lifecycle row deleted).
    pub finished: bool,
    /// The purge was abandoned (channel re-created; lifecycle row deleted,
    /// data kept).
    pub aborted: bool,
    /// Nothing could be done (row gone, not `purging`, unknown phase).
    pub idle: bool,
}

/// Per-batch bookkeeping of a purge step.
#[derive(Default)]
struct PurgeAcc {
    rows: u64,
    messages_removed: i64,
    channel_msgs_removed: i64,
    seen_msgs: HashSet<[u8; 32]>,
}

/// Where a step stopped: `None` = the step is complete.
type StepCursor = Option<Vec<u8>>;

fn msg_id_suffix(key: &[u8]) -> Option<[u8; 32]> {
    if key.len() < 8 + 32 {
        return None;
    }
    <[u8; 32]>::try_from(&key[key.len() - 32..]).ok()
}

/// `msg_id` (hex) carried in a `CHANNEL_KEYS` / `CHANNEL_KEY_COMMITS` value.
fn value_msg_id(value: &[u8]) -> Option<[u8; 32]> {
    let v: serde_json::Value = serde_json::from_slice(value).ok()?;
    let raw = hex::decode(v.get("msg_id")?.as_str()?).ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

fn prefix_cf_for(phase: u8) -> Option<&'static str> {
    use purge_phase as p;
    Some(match phase {
        p::CHANNEL_MEMBERS => cf::CHANNEL_MEMBERS,
        p::CHANNEL_MODERATORS => cf::CHANNEL_MODERATORS,
        p::CHANNEL_PINS => cf::CHANNEL_PINS,
        p::CHANNEL_INVITES => cf::CHANNEL_INVITES,
        p::CHANNEL_MEMBERSHIP_INDEX => cf::CHANNEL_MEMBERSHIP_INDEX,
        p::PRIVATE_CHANNEL_KEYS => cf::PRIVATE_CHANNEL_KEYS,
        p::PENDING_CHANNEL_MEMBER_REMOVALS => cf::PENDING_CHANNEL_MEMBER_REMOVALS,
        // `LOCAL_CHANNEL_HOMES` has its own arm in `stage_purge_phase`
        // (each row is deleted together with its wallet-index entry).
        _ => return None,
    })
}

/// The step after `phase`; `None` when `phase` is the last one. `Err` for
/// a phase this release does not know.
fn next_phase(phase: u8) -> Result<Option<u8>, ()> {
    let pos = purge_phase::ORDER.iter().position(|&p| p == phase).ok_or(())?;
    Ok(purge_phase::ORDER.get(pos + 1).copied())
}

impl Storage {
    fn stage_delete(&self, batch: &mut WriteBatch, cf_name: &str, key: &[u8]) -> Result<()> {
        let handle = self.cf_handle(cf_name)?;
        batch.delete_cf(&handle, key);
        Ok(())
    }

    /// Stage the delete of `msg_id`'s `MESSAGES` envelope (once per batch;
    /// counted only if it exists, so `TOTAL_MESSAGES` is decremented
    /// exactly once per stored envelope).
    fn stage_message_delete(&self, batch: &mut WriteBatch, msg_id: &[u8; 32], acc: &mut PurgeAcc) -> Result<()> {
        if !acc.seen_msgs.insert(*msg_id) {
            return Ok(());
        }
        if self.exists_cf(cf::MESSAGES, msg_id)? {
            self.stage_delete(batch, cf::MESSAGES, msg_id)?;
            acc.rows += 1;
            acc.messages_removed += 1;
        }
        Ok(())
    }

    /// Up to `limit` rows of `cf_name` under `prefix`, strictly after
    /// `cursor` (empty cursor = from the start of the prefix, INCLUDING a
    /// key equal to the prefix itself, e.g. the bare-scope meta row of
    /// `CHANNEL_KEY_COMMITS`).
    /// A cursor outside `prefix` (corrupt row) restarts from the prefix —
    /// seeking to it could otherwise end the step early and skip rows.
    fn purge_scan(&self, cf_name: &str, prefix: &[u8], cursor: &[u8], limit: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if cursor.is_empty() || !cursor.starts_with(prefix) {
            self.prefix_iter_cf(cf_name, prefix, limit)
        } else {
            self.prefix_iter_cf_after(cf_name, cursor, prefix, limit)
        }
    }

    /// Per-wallet node-local state of `(wallet, channel_id)` removed by the
    /// purge (step [`purge_phase::WALLETS`]): the federation slot
    /// (`LOCAL_CHANNEL_FED`, which also frees one of the wallet's 256
    /// slots), the private-sync completion stamp
    /// (`PRIVATE_CHANNEL_SYNC_STATE`), the private-sync resume cursor
    /// (`PRIVATE_CHANNEL_SYNC_RESUME`, plan §6) and the read cursor
    /// (`CHANNEL_READ_STATE`) — all keyed `wallet ‖ 0xFF ‖ cid_be8`.
    ///
    /// This is THE place for any further per-`(wallet, channel)` row.
    /// Returns the rows that existed.
    pub(crate) fn stage_purge_wallet_channel_rows(
        &self,
        batch: &mut WriteBatch,
        wallet: &str,
        channel_id: u64,
    ) -> Result<u64> {
        // Same key bytes for all four (`encode_local_channel_fed_key` and
        // `encode_channel_read_key` are both `wallet ‖ 0xFF ‖ cid_be8`).
        let fed_key = schema::encode_local_channel_fed_key(wallet, channel_id);
        let read_key = schema::encode_channel_read_key(wallet, channel_id);
        let mut found = 0u64;
        for (cf_name, key) in [
            (cf::LOCAL_CHANNEL_FED, &fed_key),
            (cf::PRIVATE_CHANNEL_SYNC_STATE, &fed_key),
            (cf::PRIVATE_CHANNEL_SYNC_RESUME, &fed_key),
            (cf::CHANNEL_READ_STATE, &read_key),
        ] {
            if self.exists_cf(cf_name, key)? {
                self.stage_delete(batch, cf_name, key)?;
                found += 1;
            }
        }
        Ok(found)
    }

    /// Phase 1 of the purge of `channel_id` (see the module doc): under
    /// `channel_membership_lock`, re-check every condition against CURRENT
    /// state and either start the purge (delete the `CHANNELS` row and flip
    /// the lifecycle row to `purging` in one batch), cancel it (a local
    /// member exists — the channel is kept and re-subscribed), or skip.
    pub fn start_private_channel_purge(&self, channel_id: u64, now_ms: u64) -> Result<PurgeStart> {
        let outcome = self.with_channel_membership_lock(|| -> Result<PurgeStart> {
            let key = channel_id.to_be_bytes();
            let Some(raw) = self.get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &key)? else {
                return Ok(PurgeStart::Skipped);
            };
            let Ok(row) = serde_json::from_slice::<PrivateChannelLifecycleRow>(&raw) else {
                return Ok(PurgeStart::Skipped); // not understood: never acted on
            };
            let due = row.deadline_ms.is_some_and(|d| d <= now_ms);
            if row.v != 1
                || row.state != LifecycleState::Pending
                || !matches!(row.reason, LifecycleReason::NoLocalMember | LifecycleReason::Deleted)
                || !due
                || !is_private_id(channel_id)
                || self.is_pinned_channel(channel_id)
                || self.lifecycle_grace_ms().is_none()
            {
                return Ok(PurgeStart::Skipped);
            }
            let channel_row = self.get_cf(cf::CHANNELS, &key)?;
            let channel_meta = channel_row
                .as_ref()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());
            if channel_row.is_some() {
                let private = channel_meta.as_ref().is_some_and(|m| {
                    m.get("channel_type")
                        .is_some_and(super::rocks::json_channel_type_is_private)
                });
                if !private {
                    tracing::warn!(channel_id, "private-channel purge: channel row is not Private; cleanup cancelled, data kept");
                    return self.cancel_pending_purge(channel_id, None).map(|_| PurgeStart::Cancelled);
                }
            }
            // A genuinely deleted channel (tombstoned, row gone) has no
            // members to protect (D4). Anything else claiming "deleted"
            // gets the full member gates.
            let deleted = row.reason == LifecycleReason::Deleted
                && channel_row.is_none()
                && self.exists_cf(cf::DELETED_CHANNELS, &key)?;
            let members = self.prefix_iter_cf(cf::CHANNEL_MEMBERS, &key, MEMBER_GATE_SCAN_CAP + 1)?;
            if !deleted {
                if self.has_local_member(channel_id)? {
                    tracing::info!(channel_id, "private-channel purge: a local member is back; cleanup cancelled");
                    return self.cancel_pending_purge(channel_id, None).map(|_| PurgeStart::Cancelled);
                }
                // Single-host protection: a channel created here whose
                // creator is still a member may live on this node only.
                if let Some(meta) = &channel_meta {
                    if self.single_host_creator_protected(channel_id, meta, None)? {
                        tracing::info!(channel_id, "private-channel purge: channel created on this node and its creator is still a member; cleanup cancelled");
                        return self.cancel_pending_purge(channel_id, None).map(|_| PurgeStart::Cancelled);
                    }
                }
                if members.len() > MEMBER_GATE_SCAN_CAP {
                    tracing::warn!(channel_id, cap = MEMBER_GATE_SCAN_CAP, "private-channel purge: member list too large to check for local users; cleanup cancelled, data kept");
                    return self.cancel_pending_purge(channel_id, None).map(|_| PurgeStart::Cancelled);
                }
                let active_since = |wallet: &[u8]| -> Result<bool> {
                    Ok(self
                        .get_cf(cf::LOCAL_DM_USERS, wallet)?
                        .and_then(|v| schema::decode_local_dm_user(&v))
                        .is_some_and(|(_, last_active)| last_active >= row.since_ms))
                };
                // LOCAL_DM_USERS safety gate: a member who authenticated
                // here after the row was written is a local member whose
                // home row was missed — record it and keep the channel.
                for (member_key, _) in &members {
                    let Some(wallet) = member_key.get(8..) else { continue };
                    if active_since(wallet)? {
                        tracing::info!(channel_id, "private-channel purge: a member used this node since scheduling; cleanup cancelled");
                        return self
                            .cancel_pending_purge(channel_id, Some(member_key))
                            .map(|_| PurgeStart::Cancelled);
                    }
                }
                // The same gate over the channel's local homes that are NOT
                // (or no longer) members, re-arming the row ONCE: a home
                // whose membership was removed by a stale replay (an old
                // kick/leave learned late, its newer re-join not yet seen)
                // and who keeps using this node gets a second grace period
                // for its healing sync to restore the membership (which then
                // cancels the row properly). A voluntary leaver who keeps
                // using the node for anything else therefore delays the
                // purge by one grace period, never indefinitely: once
                // re-armed, home-only activity no longer holds it back.
                // Nothing is recorded for a non-member. `has_local_member`
                // above already returned `true` at its cap, so this list is
                // below it.
                if !row.activity_rearmed {
                    let homes = self.prefix_iter_cf(
                        cf::LOCAL_CHANNEL_HOMES,
                        &key,
                        super::channel_lifecycle::HAS_LOCAL_MEMBER_SCAN_CAP,
                    )?;
                    for (home_key, _) in &homes {
                        let Some(wallet) = home_key.get(8..) else { continue };
                        if active_since(wallet)? {
                            let grace = self.lifecycle_grace_ms().unwrap_or(0);
                            let rearmed = PrivateChannelLifecycleRow {
                                since_ms: now_ms,
                                deadline_ms: Some(now_ms.saturating_add(grace)),
                                activity_rearmed: true,
                                ..row
                            };
                            self.put_cf(
                                cf::PRIVATE_CHANNEL_LIFECYCLE,
                                &key,
                                &serde_json::to_vec(&rearmed).context("encoding lifecycle row")?,
                            )?;
                            tracing::info!(channel_id, "private-channel purge: a local home used this node since scheduling; cleanup re-armed once for another grace period");
                            return Ok(PurgeStart::Rearmed);
                        }
                    }
                }
            }

            // Wallets whose per-wallet rows die with the channel: local
            // homes first, then members, then (deleted) the member list the
            // tombstone captured.
            let mut seen: HashSet<String> = HashSet::new();
            let mut wallets: Vec<String> = Vec::new();
            let mut push = |w: &[u8]| {
                if wallets.len() >= WALLET_CAPTURE_CAP || w.is_empty() {
                    return;
                }
                if let Ok(s) = std::str::from_utf8(w) {
                    if seen.insert(s.to_string()) {
                        wallets.push(s.to_string());
                    }
                }
            };
            for (k, _) in self.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES, &key, WALLET_CAPTURE_CAP)? {
                push(&k[8..]);
            }
            for (k, _) in &members {
                push(&k[8..]);
            }
            if deleted {
                for w in self.deleted_channel_members(channel_id)? {
                    push(w.as_bytes());
                }
            }

            let creator = channel_meta
                .as_ref()
                .and_then(|m| m.get("creator"))
                .and_then(|v| v.as_str())
                .filter(|c| !c.is_empty())
                .map(str::to_string);
            let purging = PrivateChannelLifecycleRow {
                state: LifecycleState::Purging,
                phase: purge_phase::CHANNEL_MSGS,
                cursor_hex: String::new(),
                wallets,
                creator,
                ..row
            };
            let mut batch = WriteBatch::default();
            if channel_row.is_some() {
                self.stage_delete(&mut batch, cf::CHANNELS, &key)?;
                let state = self.cf_handle(cf::NODE_STATE)?;
                batch.merge_cf(&state, state_keys::TOTAL_CHANNELS, (-1i64).to_be_bytes());
            }
            let lifecycle = self.cf_handle(cf::PRIVATE_CHANNEL_LIFECYCLE)?;
            batch.put_cf(
                &lifecycle,
                key,
                serde_json::to_vec(&purging).context("encoding lifecycle row")?,
            );
            drop(lifecycle);
            self.write_batch(batch)?;
            tracing::info!(
                channel_id,
                reason = ?purging.reason,
                wallets = purging.wallets.len(),
                "private-channel purge started: channel removed, deleting its local data"
            );
            Ok(PurgeStart::Started)
        })?;
        if outcome == PurgeStart::Cancelled {
            self.notify_lifecycle(channel_id);
        }
        Ok(outcome)
    }

    /// Delete a pending row (caller holds `channel_membership_lock`),
    /// optionally recording `home_key` (a `CHANNEL_MEMBERS` key, byte-
    /// identical to the `LOCAL_CHANNEL_HOMES` key) as local evidence.
    fn cancel_pending_purge(&self, channel_id: u64, home_key: Option<&[u8]>) -> Result<()> {
        let mut batch = WriteBatch::default();
        if let Some(home) = home_key {
            if !self.exists_cf(cf::LOCAL_CHANNEL_HOMES, home)? {
                if let Some(cid) = home.get(..8).and_then(|b| <[u8; 8]>::try_from(b).ok()) {
                    let now = crate::util::now_ms();
                    self.stage_home_put(&mut batch, u64::from_be_bytes(cid), &home[8..], &encode_home(now, now))?;
                }
            }
        }
        self.stage_delete(&mut batch, cf::PRIVATE_CHANNEL_LIFECYCLE, &channel_id.to_be_bytes())?;
        self.write_batch(batch)
    }

    /// Run one bounded slice of phase 2 for a `purging` channel: the
    /// current step deletes up to about `budget` rows (always at least one
    /// unit of progress), then the advanced position is persisted in the
    /// same batch. Loops over further steps while budget is left. A
    /// channel whose `CHANNELS` row has reappeared (re-created by a path
    /// that bypassed the guards, e.g. an older binary while downgraded) is
    /// NOT purged further: the row is dropped and every remaining row kept.
    pub fn purge_step(&self, channel_id: u64, budget: u64) -> Result<PurgeStepOutcome> {
        let mut out = PurgeStepOutcome::default();
        let budget = budget.max(1);
        // Work spent: deleted rows, but at least 1 per persisted slice, so
        // slices that delete nothing (e.g. wallets without rows) still end
        // the call within `budget` slices.
        let mut spent = 0u64;
        loop {
            let key = channel_id.to_be_bytes();
            let Some(raw) = self.get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &key)? else {
                out.idle = out.rows == 0;
                return Ok(out);
            };
            let Ok(row) = serde_json::from_slice::<PrivateChannelLifecycleRow>(&raw) else {
                out.idle = out.rows == 0;
                return Ok(out);
            };
            if row.v != 1 || row.state != LifecycleState::Purging || !is_private_id(channel_id) {
                out.idle = out.rows == 0;
                return Ok(out);
            }
            let next = match next_phase(row.phase) {
                Ok(n) => n,
                Err(()) => {
                    tracing::warn!(channel_id, phase = row.phase, "private-channel purge: unknown phase (newer release?); left untouched");
                    out.idle = out.rows == 0;
                    return Ok(out);
                }
            };
            // Abandon (keep every remaining row) when the channel was
            // re-created behind the guards. A pin configured after the purge
            // began does NOT abandon it: the `CHANNELS` row is already gone
            // and a half-purged channel is useless — finishing is what lets
            // it be federated again (a pin only keeps a `pending` row from
            // starting).
            if self.exists_cf(cf::CHANNELS, &key)? {
                let aborted = self.with_channel_membership_lock(|| -> Result<bool> {
                    let still = self
                        .get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &key)?
                        .and_then(|r| serde_json::from_slice::<PrivateChannelLifecycleRow>(&r).ok())
                        .is_some_and(|r| r.v == 1 && r.state == LifecycleState::Purging);
                    if still && self.exists_cf(cf::CHANNELS, &key)? {
                        self.delete_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &key)?;
                        return Ok(true);
                    }
                    Ok(false)
                })?;
                if aborted {
                    tracing::warn!(channel_id, "private-channel purge abandoned (channel re-created meanwhile); remaining data kept");
                    self.notify_lifecycle(channel_id);
                    out.aborted = true;
                }
                return Ok(out);
            }
            // A malformed cursor restarts the step (every step is idempotent).
            let cursor = hex::decode(&row.cursor_hex).unwrap_or_default();
            let remaining = budget.saturating_sub(spent).max(1);
            let run = || -> Result<(u64, bool)> {
                let mut batch = WriteBatch::default();
                let mut acc = PurgeAcc::default();
                let stopped = self.stage_purge_phase(&mut batch, &mut acc, channel_id, &row, &cursor, remaining)?;
                let mut updated = row.clone();
                let finished = match (&stopped, next) {
                    (Some(c), _) => {
                        updated.cursor_hex = hex::encode(c);
                        false
                    }
                    (None, Some(n)) => {
                        updated.phase = n;
                        updated.cursor_hex.clear();
                        false
                    }
                    (None, None) => true,
                };
                let lifecycle = self.cf_handle(cf::PRIVATE_CHANNEL_LIFECYCLE)?;
                if finished {
                    batch.delete_cf(&lifecycle, key);
                } else {
                    batch.put_cf(
                        &lifecycle,
                        key,
                        serde_json::to_vec(&updated).context("encoding lifecycle row")?,
                    );
                }
                drop(lifecycle);
                let state = self.cf_handle(cf::NODE_STATE)?;
                if acc.messages_removed > 0 {
                    batch.merge_cf(&state, state_keys::TOTAL_MESSAGES, (-acc.messages_removed).to_be_bytes());
                }
                if acc.channel_msgs_removed > 0 {
                    batch.merge_cf(
                        &state,
                        state_keys::TOTAL_CHANNEL_MESSAGES,
                        (-acc.channel_msgs_removed).to_be_bytes(),
                    );
                }
                drop(state);
                self.write_batch(batch)?;
                Ok((acc.rows, finished))
            };
            // Key rows are read-decide-written by the key-epoch arbitration
            // under `channel_key_envelope_lock`; delete them under it too.
            let (rows, finished) = if matches!(row.phase, purge_phase::CHANNEL_KEYS | purge_phase::CHANNEL_KEY_COMMITS) {
                self.with_channel_key_envelope_lock(run)?
            } else {
                run()?
            };
            out.rows += rows;
            spent = spent.saturating_add(rows.max(1));
            if finished {
                tracing::info!(channel_id, "private-channel purge finished: local data deleted");
                self.notify_lifecycle(channel_id);
                out.finished = true;
                return Ok(out);
            }
            if spent >= budget {
                return Ok(out);
            }
        }
    }

    /// Stage one bounded slice of `row.phase` into `batch`. Returns where
    /// it stopped (`None` = the step is complete).
    fn stage_purge_phase(
        &self,
        batch: &mut WriteBatch,
        acc: &mut PurgeAcc,
        channel_id: u64,
        row: &PrivateChannelLifecycleRow,
        cursor: &[u8],
        budget: u64,
    ) -> Result<StepCursor> {
        use purge_phase as p;
        let cid = channel_id.to_be_bytes();
        let page = usize::try_from(budget).unwrap_or(usize::MAX).max(1);
        match row.phase {
            p::CHANNEL_MSGS => self.stage_purge_channel_msgs(batch, acc, &cid, cursor, page, budget),
            p::CHANNEL_EDIT_DELETE_MSGS | p::CHANNEL_META_MSGS | p::CHAT_REACTION_MSGS => {
                let cf_name = match row.phase {
                    p::CHANNEL_META_MSGS => cf::CHANNEL_META_MSGS,
                    p::CHAT_REACTION_MSGS => cf::CHAT_REACTION_MSGS,
                    _ => cf::CHANNEL_EDIT_DELETE_MSGS,
                };
                let rows = self.purge_scan(cf_name, &cid, cursor, page)?;
                for (k, _) in &rows {
                    if let Some(id) = msg_id_suffix(k) {
                        self.stage_message_delete(batch, &id, acc)?;
                    }
                    self.stage_delete(batch, cf_name, k)?;
                    acc.rows += 1;
                }
                Ok(if rows.len() < page { None } else { rows.last().map(|(k, _)| k.clone()) })
            }
            p::CHANNEL_KEYS | p::CHANNEL_KEY_COMMITS => {
                let cf_name = if row.phase == p::CHANNEL_KEYS { cf::CHANNEL_KEYS } else { cf::CHANNEL_KEY_COMMITS };
                let scope = crate::crypto::compute_channel_scope(channel_id);
                let rows = self.purge_scan(cf_name, &scope, cursor, page)?;
                for (k, v) in &rows {
                    if let Some(id) = value_msg_id(v) {
                        self.stage_message_delete(batch, &id, acc)?;
                    }
                    self.stage_delete(batch, cf_name, k)?;
                    acc.rows += 1;
                }
                Ok(if rows.len() < page { None } else { rows.last().map(|(k, _)| k.clone()) })
            }
            // Kept rows (see the constant): nothing to delete.
            p::CHANNEL_MUTES => Ok(None),
            p::EXACT_KEYS => {
                let pin_seq = format!("pin_seq:{channel_id}");
                for (cf_name, k) in [
                    (cf::CHANNEL_VERIFICATION, &cid[..]),
                    (cf::CHANNEL_BACKFILL_STATE, &cid[..]),
                    (cf::PENDING_CHANNEL_DELETES, &cid[..]),
                    (cf::NODE_STATE, pin_seq.as_bytes()),
                ] {
                    if self.exists_cf(cf_name, k)? {
                        self.stage_delete(batch, cf_name, k)?;
                        acc.rows += 1;
                    }
                }
                Ok(None)
            }
            p::WALLETS => {
                let start = <[u8; 8]>::try_from(cursor).map(u64::from_be_bytes).unwrap_or(0);
                let start = usize::try_from(start).unwrap_or(usize::MAX).min(row.wallets.len());
                // ~4 point reads + deletes per wallet.
                let take = (page / 4).max(1);
                let end = start.saturating_add(take).min(row.wallets.len());
                for wallet in &row.wallets[start..end] {
                    acc.rows += self.stage_purge_wallet_channel_rows(batch, wallet, channel_id)?;
                }
                Ok((end < row.wallets.len()).then(|| (end as u64).to_be_bytes().to_vec()))
            }
            p::LOCAL_CHANNEL_HOMES => {
                // Each HOMES row goes together with its
                // `LOCAL_CHANNEL_HOMES_BY_WALLET` entry (two deletes per
                // key), so half a page of keys per slice. Same cursor
                // semantics as the generic prefix arm.
                let half = (page / 2).max(1);
                let rows = self.purge_scan(cf::LOCAL_CHANNEL_HOMES, &cid, cursor, half)?;
                for (k, _) in &rows {
                    self.stage_home_delete(batch, k)?;
                    acc.rows += 2;
                }
                Ok(if rows.len() < half { None } else { rows.last().map(|(k, _)| k.clone()) })
            }
            phase => {
                let Some(cf_name) = prefix_cf_for(phase) else {
                    anyhow::bail!("purge phase {phase} has no handler");
                };
                let rows = self.purge_scan(cf_name, &cid, cursor, page)?;
                for (k, _) in &rows {
                    self.stage_delete(batch, cf_name, k)?;
                    acc.rows += 1;
                }
                Ok(if rows.len() < page { None } else { rows.last().map(|(k, _)| k.clone()) })
            }
        }
    }

    /// Step [`purge_phase::CHANNEL_MSGS`]: each `CHANNEL_MSGS` row with its
    /// envelope, deletion marker and side rows. A message whose side rows
    /// exceed [`MSG_SIDE_ROWS_CAP`] in one CF keeps its index row (and the
    /// cursor stays before it) until a later pass has removed the rest.
    fn stage_purge_channel_msgs(
        &self,
        batch: &mut WriteBatch,
        acc: &mut PurgeAcc,
        cid: &[u8; 8],
        cursor: &[u8],
        page: usize,
        budget: u64,
    ) -> Result<StepCursor> {
        let rows = self.purge_scan(cf::CHANNEL_MSGS, cid, cursor, page)?;
        let mut last: Option<Vec<u8>> = (!cursor.is_empty()).then(|| cursor.to_vec());
        let mut stopped_early = false;
        for (i, (key, _)) in rows.iter().enumerate() {
            if i > 0 && acc.rows >= budget {
                stopped_early = true;
                break;
            }
            if let Some(msg_id) = msg_id_suffix(key) {
                let mut complete = true;
                for side_cf in MSG_SIDE_CFS {
                    let side = self.prefix_iter_cf(side_cf, &msg_id, MSG_SIDE_ROWS_CAP)?;
                    if side.len() >= MSG_SIDE_ROWS_CAP {
                        complete = false;
                    }
                    for (k, _) in &side {
                        self.stage_delete(batch, side_cf, k)?;
                        acc.rows += 1;
                    }
                }
                if !complete {
                    return Ok(Some(last.unwrap_or_default()));
                }
                if self.exists_cf(cf::DELETION_MARKERS, &msg_id)? {
                    self.stage_delete(batch, cf::DELETION_MARKERS, &msg_id)?;
                    acc.rows += 1;
                }
                self.stage_message_delete(batch, &msg_id, acc)?;
            }
            self.stage_delete(batch, cf::CHANNEL_MSGS, key)?;
            acc.rows += 1;
            acc.channel_msgs_removed += 1;
            last = Some(key.clone());
        }
        if stopped_early || rows.len() >= page {
            Ok(Some(last.unwrap_or_default()))
        } else {
            Ok(None)
        }
    }

    /// One pass of the purge reaper: start up to [`PURGE_STARTS_PER_PASS`]
    /// due channels, then advance `purging` channels until `batch_rows`
    /// rows have been deleted. Never purges a row whose deadline is `None`
    /// (`purge_grace_hours = 0`), a public id, a pinned channel's `pending`
    /// row, or a row it does not understand.
    ///
    /// Rows are read in one bounded page of [`PURGE_SCAN_PAGE`] from a
    /// persisted, rotating cursor (`PRIVATE_CHANNEL_PURGE_CURSOR`), wrapping
    /// to the start when the end of the column family is reached — so the
    /// whole CF is covered every pass while it fits one page, and no row
    /// beyond any cap is ever starved when it does not.
    pub fn run_private_channel_purge_pass(&self, now_ms: u64, batch_rows: u64) -> Result<PurgePassReport> {
        self.run_private_channel_purge_pass_paged(now_ms, batch_rows, PURGE_SCAN_PAGE)
    }

    /// [`run_private_channel_purge_pass`](Self::run_private_channel_purge_pass)
    /// with an explicit scan page size (tests).
    fn run_private_channel_purge_pass_paged(
        &self,
        now_ms: u64,
        batch_rows: u64,
        page: usize,
    ) -> Result<PurgePassReport> {
        let page = page.max(1);
        let mut report = PurgePassReport::default();
        let cursor = self
            .get_cf(cf::NODE_STATE, state_keys::PRIVATE_CHANNEL_PURGE_CURSOR)?
            .unwrap_or_default();
        // Rotation order: the rows after the cursor, then (wrapping) the
        // rows from the start up to and including the cursor.
        let mut rows = if cursor.is_empty() {
            self.prefix_iter_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &[], page)?
        } else {
            self.prefix_iter_cf_after(cf::PRIVATE_CHANNEL_LIFECYCLE, &cursor, &[], page)?
        };
        let mut wrapped = false;
        if rows.len() < page && !cursor.is_empty() {
            wrapped = true;
            let head = self.prefix_iter_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &[], page - rows.len())?;
            rows.extend(head.into_iter().filter(|(k, _)| k.as_slice() <= cursor.as_slice()));
        }
        // Where the next pass starts: after the last row of a full page, or
        // from the start once the end was reached; moved back to the last
        // START attempted when the start cap cut the page short, so the due
        // rows after it get the first chance next pass.
        let mut next_cursor: Vec<u8> = if rows.len() >= page && !wrapped {
            rows.last().map(|(k, _)| k.clone()).unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut purging = Vec::new();
        let mut starts = 0usize;
        for (k, v) in &rows {
            let Ok(cid_bytes) = <[u8; 8]>::try_from(k.as_slice()) else { continue };
            let cid = u64::from_be_bytes(cid_bytes);
            if !is_private_id(cid) {
                continue;
            }
            let Ok(row) = serde_json::from_slice::<PrivateChannelLifecycleRow>(v) else { continue };
            if row.v != 1 {
                continue;
            }
            match row.state {
                LifecycleState::Purging => purging.push(cid),
                LifecycleState::Pending
                    if row.deadline_ms.is_some_and(|d| d <= now_ms) && !self.is_pinned_channel(cid) =>
                {
                    if starts >= PURGE_STARTS_PER_PASS {
                        continue;
                    }
                    starts += 1;
                    if starts == PURGE_STARTS_PER_PASS {
                        next_cursor = k.clone();
                    }
                    match self.start_private_channel_purge(cid, now_ms) {
                        Ok(PurgeStart::Started) => {
                            report.started += 1;
                            purging.push(cid);
                        }
                        Ok(PurgeStart::Cancelled) => report.cancelled += 1,
                        Ok(PurgeStart::Rearmed | PurgeStart::Skipped) => {}
                        Err(e) => tracing::warn!(channel_id = cid, error = %e, "private-channel purge: start failed; retried next pass"),
                    }
                }
                _ => {}
            }
        }
        self.put_cf(cf::NODE_STATE, state_keys::PRIVATE_CHANNEL_PURGE_CURSOR, &next_cursor)?;
        let budget = batch_rows.max(1);
        for cid in purging {
            if report.rows >= budget {
                break;
            }
            match self.purge_step(cid, budget - report.rows) {
                Ok(o) => {
                    report.rows += o.rows;
                    report.completed += usize::from(o.finished);
                    report.aborted += usize::from(o.aborted);
                }
                Err(e) => tracing::warn!(channel_id = cid, error = %e, "private-channel purge: step failed; resumes next pass"),
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::types::PRIVATE_CHANNEL_ID_FLOOR;
    use crate::storage::channel_lifecycle::PrivateChannelPolicy;
    use tempfile::TempDir;

    const HOUR: u64 = 3_600_000;
    const MSGS: u8 = 6;
    const DEFAULT_GRACE_MS: u64 =
        crate::storage::channel_lifecycle::DEFAULT_PURGE_GRACE_HOURS * HOUR;

    fn pcid(n: u64) -> u64 {
        PRIVATE_CHANNEL_ID_FLOOR + 1000 + n
    }

    fn seeded(dir: &TempDir) -> Storage {
        let s = Storage::open(dir.path()).unwrap();
        s.run_private_channel_homes_seeding(1000, 1).unwrap();
        s
    }

    fn far_future() -> u64 {
        crate::util::now_ms() + 10_000 * HOUR
    }

    fn id(tag: u8, kind: u8, i: u8) -> [u8; 32] {
        let mut m = [0u8; 32];
        m[0] = tag;
        m[1] = kind;
        m[2] = i;
        m
    }

    fn put(s: &Storage, cf_name: &str, key: &[u8], v: &[u8]) {
        s.put_cf(cf_name, key, v).unwrap();
    }

    fn put_channel(s: &Storage, cid: u64, ctype: u64) {
        let row = serde_json::json!({"channel_id": cid, "channel_type": ctype, "creator": "klv1creator", "member_count": 0});
        put(s, cf::CHANNELS, &cid.to_be_bytes(), &serde_json::to_vec(&row).unwrap());
        s.increment_stat(state_keys::TOTAL_CHANNELS).unwrap();
    }

    /// Every message id the fixture stored for channel `tag`.
    fn all_msg_ids(tag: u8) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        for i in 0..MSGS {
            out.push(id(tag, 1, i)); // chat
            out.push(id(tag, 2, i)); // edit envelope
        }
        out.push(id(tag, 3, 0)); // channel meta (join)
        out.push(id(tag, 4, 0)); // channel key envelope
        out.push(id(tag, 5, 0)); // key commit winner
        out.push(id(tag, 6, 0)); // chat reaction envelope (0.152.0)
        out.push(id(tag, 7, 0)); // pin envelope (0.152.0, in CHANNEL_META_MSGS)
        out
    }

    /// A private channel `cid` with a full set of local data; `klv1a` is a
    /// local member (home), `klv1b` a remote member.
    fn populate(s: &Storage, cid: u64, tag: u8) {
        put_channel(s, cid, 2);
        s.add_channel_member(cid, "klv1a", 1, "member").unwrap();
        s.add_channel_member(cid, "klv1b", 1, "member").unwrap();
        if !s.record_local_channel_home(cid, "klv1a", crate::util::now_ms()).unwrap().recorded {
            // A public id never gets one through the API; force it.
            s.put_local_channel_home_for_test(cid, "klv1a", 1, 1).unwrap();
        }
        for i in 0..MSGS {
            let chat = id(tag, 1, i);
            let edit = id(tag, 2, i);
            s.store_message(&chat, b"env").unwrap();
            s.store_message(&edit, b"env").unwrap();
            put(s, cf::CHANNEL_MSGS, &schema::encode_channel_msg_key(cid, 100 + i as u64, &chat), &[]);
            s.increment_stat(state_keys::TOTAL_CHANNEL_MESSAGES).unwrap();
            put(s, cf::CHANNEL_EDIT_DELETE_MSGS, &schema::encode_channel_msg_key(cid, 200 + i as u64, &edit), &[]);
            put(s, cf::EDIT_HISTORY, &schema::encode_edit_history_key(&chat, 200 + i as u64), &edit);
            put(s, cf::CHAT_REACTIONS, &schema::encode_chat_reaction_key(&chat, "x", "klv1b"), &[]);
            put(s, cf::CHAT_REACTION_COUNTS, &schema::encode_chat_reaction_count_key(&chat, "x"), &1u64.to_be_bytes());
            put(s, cf::REPORTS, &schema::encode_report_key(&chat, "klv1b"), b"{}");
            put(s, cf::COUNTER_VOTES, &schema::encode_counter_vote_key(&chat, "klv1a"), &1u64.to_be_bytes());
            put(s, cf::DELETION_MARKERS, &chat, b"{}");
        }
        let meta = id(tag, 3, 0);
        s.store_message(&meta, b"env").unwrap();
        put(s, cf::CHANNEL_META_MSGS, &schema::encode_channel_meta_key(cid, 0x12, 5, &meta), &[]);
        // l2-node 0.152.0 (G6): a chat reaction indexed under the channel,
        // and a pin in the metadata index.
        let react = id(tag, 6, 0);
        s.store_message(&react, b"env").unwrap();
        put(s, cf::CHAT_REACTION_MSGS, &schema::encode_channel_msg_key(cid, 300, &react), &[]);
        let pin = id(tag, 7, 0);
        s.store_message(&pin, b"env").unwrap();
        put(s, cf::CHANNEL_META_MSGS, &schema::encode_channel_meta_key(cid, 0x19, 6, &pin), &[]);
        let scope = crate::crypto::compute_channel_scope(cid);
        let key_env = id(tag, 4, 0);
        s.store_message(&key_env, b"env").unwrap();
        put(s, cf::CHANNEL_KEYS, &schema::encode_channel_key(&scope, "klv1a", "", "dev", 1),
            serde_json::json!({"msg_id": hex::encode(key_env)}).to_string().as_bytes());
        let commit = id(tag, 5, 0);
        s.store_message(&commit, b"env").unwrap();
        put(s, cf::CHANNEL_KEY_COMMITS, &schema::encode_key_commit_key(&scope, 1),
            serde_json::json!({"msg_id": hex::encode(commit), "recorded_at": 1, "state": "arbitrated"}).to_string().as_bytes());
        put(s, cf::CHANNEL_KEY_COMMITS, &schema::encode_key_commit_scope_meta_key(&scope), b"{}");
        for cf_name in [cf::CHANNEL_MODERATORS, cf::CHANNEL_INVITES, cf::CHANNEL_MUTES, cf::CHANNEL_MEMBERSHIP_INDEX, cf::PENDING_CHANNEL_MEMBER_REMOVALS] {
            put(s, cf_name, &schema::encode_channel_member_key(cid, "klv1b"), b"{}");
        }
        put(s, cf::CHANNEL_PINS, &schema::encode_channel_pin_key(cid, 0, &id(tag, 1, 0)), &[]);
        put(s, cf::PRIVATE_CHANNEL_KEYS, &schema::encode_private_channel_key(cid, 1), b"{}");
        for cf_name in [cf::CHANNEL_VERIFICATION, cf::CHANNEL_BACKFILL_STATE, cf::PENDING_CHANNEL_DELETES] {
            put(s, cf_name, &cid.to_be_bytes(), b"{}");
        }
        put(s, cf::NODE_STATE, format!("pin_seq:{cid}").as_bytes(), &0u32.to_be_bytes());
        put(s, cf::LOCAL_CHANNEL_FED, &schema::encode_local_channel_fed_key("klv1a", cid), &1u64.to_be_bytes());
        s.mark_private_channel_sync_complete("klv1a", cid, 1).unwrap();
        s.put_private_channel_sync_resume("klv1a", cid, b"{}").unwrap();
        put(s, cf::CHANNEL_READ_STATE, &schema::encode_channel_read_key("klv1a", cid), &1u64.to_be_bytes());
        // Kept by design (D5).
        s.raise_channel_role_watermark(cid, schema::role_watermark_kind::REMOVED, "klv1x", 7).unwrap();
        put(s, cf::CHANNEL_BANS, &schema::encode_channel_ban_key(cid, "klv1x"), b"{}");
        put(s, cf::NOTIFICATIONS, &schema::encode_notification_key("klv1a", 5, &id(tag, 1, 0)), b"{}");
    }

    /// Row count of every column family the purge must empty for `cid`.
    fn purged_cf_counts(s: &Storage, cid: u64, tag: u8) -> Vec<(&'static str, usize)> {
        let p = cid.to_be_bytes();
        let scope = crate::crypto::compute_channel_scope(cid);
        let n = |cf_name: &'static str, prefix: &[u8]| (cf_name, s.prefix_iter_cf(cf_name, prefix, 10_000).unwrap().len());
        let mut out = vec![
            n(cf::CHANNELS, &p),
            n(cf::CHANNEL_MSGS, &p),
            n(cf::CHANNEL_EDIT_DELETE_MSGS, &p),
            n(cf::CHANNEL_META_MSGS, &p),
            n(cf::CHAT_REACTION_MSGS, &p),
            n(cf::CHANNEL_KEYS, &scope),
            n(cf::CHANNEL_KEY_COMMITS, &scope),
            n(cf::CHANNEL_MEMBERS, &p),
            n(cf::CHANNEL_MODERATORS, &p),
            n(cf::CHANNEL_PINS, &p),
            n(cf::CHANNEL_INVITES, &p),
            n(cf::CHANNEL_MEMBERSHIP_INDEX, &p),
            n(cf::PRIVATE_CHANNEL_KEYS, &p),
            n(cf::PENDING_CHANNEL_MEMBER_REMOVALS, &p),
            n(cf::CHANNEL_VERIFICATION, &p),
            n(cf::CHANNEL_BACKFILL_STATE, &p),
            n(cf::PENDING_CHANNEL_DELETES, &p),
            n(cf::LOCAL_CHANNEL_HOMES, &p),
            n(cf::LOCAL_CHANNEL_HOMES_BY_WALLET, &schema::encode_local_channel_home_wallet_key(b"klv1a", cid)),
            n(cf::LOCAL_CHANNEL_HOMES_BY_WALLET, &schema::encode_local_channel_home_wallet_key(b"klv1b", cid)),
            n(cf::PRIVATE_CHANNEL_LIFECYCLE, &p),
            n(cf::LOCAL_CHANNEL_FED, &schema::encode_local_channel_fed_key("klv1a", cid)),
            n(cf::PRIVATE_CHANNEL_SYNC_STATE, &schema::encode_local_channel_fed_key("klv1a", cid)),
            n(cf::PRIVATE_CHANNEL_SYNC_RESUME, &schema::encode_local_channel_fed_key("klv1a", cid)),
            n(cf::CHANNEL_READ_STATE, &schema::encode_channel_read_key("klv1a", cid)),
            ("pin_seq", usize::from(s.exists_cf(cf::NODE_STATE, format!("pin_seq:{cid}").as_bytes()).unwrap())),
        ];
        for m in all_msg_ids(tag) {
            for cf_name in [cf::MESSAGES, cf::DELETION_MARKERS] {
                if s.exists_cf(cf_name, &m).unwrap() {
                    out.push((cf_name, 1));
                }
            }
            for cf_name in MSG_SIDE_CFS {
                let c = s.prefix_iter_cf(cf_name, &m, 10).unwrap().len();
                if c > 0 {
                    out.push((cf_name, c));
                }
            }
        }
        out.retain(|(_, c)| *c > 0);
        out
    }

    /// (watermark, ban and mute kept, notifications kept).
    fn kept_rows(s: &Storage, cid: u64) -> (bool, bool, bool) {
        (
            s.channel_role_watermark(cid, schema::role_watermark_kind::REMOVED, "klv1x").unwrap().is_some(),
            s.exists_cf(cf::CHANNEL_BANS, &schema::encode_channel_ban_key(cid, "klv1x")).unwrap()
                && s.exists_cf(cf::CHANNEL_MUTES, &schema::encode_channel_member_key(cid, "klv1b")).unwrap(),
            !s.prefix_iter_cf(cf::NOTIFICATIONS, b"klv1a", 10).unwrap().is_empty(),
        )
    }

    fn row(s: &Storage, cid: u64) -> Option<PrivateChannelLifecycleRow> {
        s.private_channel_lifecycle_row(cid).unwrap()
    }

    /// Schedule `cid` the normal way: its only local member leaves.
    fn schedule(s: &Storage, cid: u64) {
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert_eq!(row(s, cid).unwrap().state, LifecycleState::Pending);
    }

    fn run_to_completion(s: &Storage, now: u64, batch: u64) -> PurgePassReport {
        let mut total = PurgePassReport::default();
        for _ in 0..10_000 {
            let r = s.run_private_channel_purge_pass(now, batch).unwrap();
            total.started += r.started;
            total.cancelled += r.cancelled;
            total.aborted += r.aborted;
            total.completed += r.completed;
            total.rows += r.rows;
            if r.rows == 0 && r.started == 0 && r.cancelled == 0 {
                return total;
            }
        }
        panic!("purge did not converge");
    }

    #[test]
    fn full_purge_empties_every_listed_cf_and_keeps_the_rest() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(1);
        let b = pcid(2);
        populate(&s, a, 0xA1);
        populate(&s, b, 0xB2);
        let before_b = purged_cf_counts(&s, b, 0xB2);
        let msgs = s.get_stat(state_keys::TOTAL_MESSAGES).unwrap();
        let chat = s.get_stat(state_keys::TOTAL_CHANNEL_MESSAGES).unwrap();
        let chans = s.get_stat(state_keys::TOTAL_CHANNELS).unwrap();
        schedule(&s, a);
        // Not due yet: nothing happens.
        assert_eq!(s.run_private_channel_purge_pass(crate::util::now_ms(), 5000).unwrap(), PurgePassReport::default());
        let r = run_to_completion(&s, far_future(), 5000);
        assert_eq!((r.started, r.completed, r.cancelled, r.aborted), (1, 1, 0, 0));
        assert!(r.rows > 50);
        assert_eq!(purged_cf_counts(&s, a, 0xA1), Vec::<(&str, usize)>::new(), "every listed CF is empty for the purged channel");
        assert_eq!(kept_rows(&s, a), (true, true, true), "watermarks, bans, mutes and notifications are kept (D5)");
        // The other private channel is untouched.
        assert_eq!(purged_cf_counts(&s, b, 0xB2), before_b);
        assert_eq!(kept_rows(&s, b), (true, true, true));
        // Stats: one channel, its MSGS chat index rows and all 15 envelopes.
        assert_eq!(s.get_stat(state_keys::TOTAL_CHANNELS).unwrap(), chans - 1);
        assert_eq!(s.get_stat(state_keys::TOTAL_CHANNEL_MESSAGES).unwrap(), chat - MSGS as u64);
        assert_eq!(s.get_stat(state_keys::TOTAL_MESSAGES).unwrap(), msgs - all_msg_ids(0xA1).len() as u64);
        // After the purge the channel may be created again.
        assert!(s.put_channel_and_replay_pending_member_removals(a, br#"{"channel_type":2}"#).unwrap());
    }

    #[test]
    fn crash_resume_from_a_mid_phase_cursor_converges() {
        let dir = TempDir::new().unwrap();
        let a = pcid(3);
        let b = pcid(4);
        let before_b;
        {
            let s = seeded(&dir);
            populate(&s, a, 0xA3);
            populate(&s, b, 0xB4);
            before_b = purged_cf_counts(&s, b, 0xB4);
            schedule(&s, a);
            assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Started);
            let o = s.purge_step(a, 3).unwrap();
            assert!(!o.finished && o.rows >= 3);
            let r = row(&s, a).unwrap();
            assert_eq!((r.state, r.phase), (LifecycleState::Purging, purge_phase::CHANNEL_MSGS));
            assert!(!r.cursor_hex.is_empty(), "a mid-phase cursor is persisted");
        }
        // "Crash": reopen the DB after every tiny step.
        let mut steps = 0;
        loop {
            let s = Storage::open(dir.path()).unwrap();
            // A stale or corrupt cursor must be harmless: it restarts the
            // current step, which is idempotent.
            if steps == 5 {
                let mut r = row(&s, a).unwrap();
                r.cursor_hex = "ffff".into(); // corrupt: outside the step's prefix
                s.put_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &a.to_be_bytes(), &serde_json::to_vec(&r).unwrap()).unwrap();
            }
            let o = s.purge_step(a, 4).unwrap();
            steps += 1;
            assert!(steps < 500, "no progress");
            if o.finished {
                assert_eq!(purged_cf_counts(&s, a, 0xA3), Vec::<(&str, usize)>::new());
                assert_eq!(purged_cf_counts(&s, b, 0xB4), before_b);
                assert_eq!(kept_rows(&s, a), (true, true, true));
                break;
            }
        }
        assert!(steps > 10, "the purge really ran in many resumed slices");
    }

    #[test]
    fn member_returning_between_schedule_and_start_cancels() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        s.set_channel_lifecycle_notifier(tx);
        let a = pcid(5);
        populate(&s, a, 0xA5);
        schedule(&s, a);
        let _ = rx.try_recv();
        // klv1a re-joined while no hook could see it (e.g. an older binary
        // ran): its home row and membership exist, the row is still pending.
        put(&s, cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(a, "klv1a"), b"{}");
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Cancelled);
        assert!(row(&s, a).is_none());
        assert_eq!(rx.try_recv().ok(), Some(a), "network told to resubscribe");
        assert!(s.exists_cf(cf::CHANNELS, &a.to_be_bytes()).unwrap(), "channel kept");
        assert_eq!(run_to_completion(&s, far_future(), 5000).rows, 0);
    }

    #[test]
    fn local_dm_user_gate_records_a_home_and_cancels() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(6);
        let b = pcid(7);
        populate(&s, a, 0xA6);
        populate(&s, b, 0xB7);
        schedule(&s, a);
        schedule(&s, b);
        let since = row(&s, a).unwrap().since_ms;
        // klv1b (member, no home row) authenticated here after scheduling.
        put(&s, cf::LOCAL_DM_USERS, b"klv1b", &schema::encode_local_dm_user(1, since));
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Cancelled);
        assert!(s.exists_cf(cf::LOCAL_CHANNEL_HOMES, &schema::encode_local_channel_home_key(a, "klv1b")).unwrap());
        assert!(s.has_local_member(a).unwrap());
        // Activity BEFORE the schedule is no evidence (that is what the
        // home rows cover): channel b, whose row is newer, is purged.
        let since_b = row(&s, b).unwrap().since_ms;
        put(&s, cf::LOCAL_DM_USERS, b"klv1b", &schema::encode_local_dm_user(1, since_b - 1));
        assert_eq!(s.start_private_channel_purge(b, far_future()).unwrap(), PurgeStart::Started);
    }

    #[test]
    fn none_deadline_is_never_purged() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        s.set_private_channel_policy(PrivateChannelPolicy::new(0, []));
        let a = pcid(8);
        let d = pcid(9);
        populate(&s, a, 0xA8);
        populate(&s, d, 0xA9);
        schedule(&s, a);
        s.tombstone_channel(d, 1, Some("klv1creator")).unwrap();
        assert_eq!(row(&s, a).unwrap().deadline_ms, None);
        assert_eq!(row(&s, d).unwrap().deadline_ms, None, "grace 0 opts out of purging deleted channels too");
        assert_eq!(run_to_completion(&s, u64::MAX, 5000), PurgePassReport::default());
        assert_eq!(s.start_private_channel_purge(a, u64::MAX).unwrap(), PurgeStart::Skipped);
        assert!(s.exists_cf(cf::CHANNELS, &a.to_be_bytes()).unwrap());
        assert!(s.exists_cf(cf::MESSAGES, &id(0xA9, 1, 0)).unwrap());
    }

    #[test]
    fn deleted_channel_is_purged_on_the_next_pass_and_tombstone_kept() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let d = pcid(10);
        populate(&s, d, 0xAA);
        // klv1a is even still a local member: a deletion is final (D4).
        s.tombstone_channel(d, 1, Some("klv1creator")).unwrap();
        let r = run_to_completion(&s, crate::util::now_ms() + 1, 5000);
        assert_eq!((r.started, r.completed), (1, 1));
        assert_eq!(purged_cf_counts(&s, d, 0xAA), Vec::<(&str, usize)>::new());
        assert!(s.exists_cf(cf::DELETED_CHANNELS, &d.to_be_bytes()).unwrap(), "tombstone kept forever");
        assert_eq!(s.deleted_channel_members(d).unwrap().len(), 2);
    }

    #[test]
    fn nothing_recreates_or_cancels_a_purging_channel() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(11);
        populate(&s, a, 0xAB);
        schedule(&s, a);
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Started);
        assert!(s.private_channel_purge_in_progress(a).unwrap());
        assert!(!s.exists_cf(cf::CHANNELS, &a.to_be_bytes()).unwrap());
        // Create refused (storage path used by the router, the scanner and
        // the anchored-state repair).
        assert!(!s.put_channel_and_replay_pending_member_removals(a, br#"{"channel_type":2}"#).unwrap());
        assert!(!s.exists_cf(cf::CHANNELS, &a.to_be_bytes()).unwrap());
        // Join / home / lazy touch never cancel a purging row.
        assert!(!s.add_channel_member(a, "klv1a", 9, "member").unwrap());
        assert_eq!(s.record_local_channel_home(a, "klv1a", far_future()).unwrap(), Default::default());
        s.prepare_private_channel_lifecycle(far_future()).unwrap();
        assert_eq!(row(&s, a).unwrap().state, LifecycleState::Purging);
        // A delete arriving mid-purge does not reset it either.
        s.tombstone_channel(a, 1, None).unwrap();
        assert_eq!(row(&s, a).unwrap().state, LifecycleState::Purging);
        assert_eq!(run_to_completion(&s, far_future(), 5000).completed, 1);
        assert!(!s.private_channel_purge_in_progress(a).unwrap());
    }

    #[test]
    fn channel_recreated_behind_the_guards_aborts_and_keeps_data() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(12);
        populate(&s, a, 0xAC);
        schedule(&s, a);
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Started);
        s.purge_step(a, 3).unwrap();
        // e.g. an older binary (no guard) re-created it while downgraded.
        put(&s, cf::CHANNELS, &a.to_be_bytes(), br#"{"channel_type":2}"#);
        let o = s.purge_step(a, 5000).unwrap();
        assert!(o.aborted && o.rows == 0);
        assert!(row(&s, a).is_none());
        assert!(s.exists_cf(cf::MESSAGES, &id(0xAC, 1, MSGS - 1)).unwrap(), "remaining data kept");
    }

    #[test]
    fn public_ids_with_forged_rows_are_never_purged() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        for (cid, state) in [(42u64, "pending"), (43u64, "purging"), (PRIVATE_CHANNEL_ID_FLOOR, "purging")] {
            populate(&s, cid, cid as u8);
            let forged = format!(r#"{{"v":1,"state":"{state}","since_ms":1,"deadline_ms":1,"reason":"deleted","phase":1}}"#);
            put(&s, cf::PRIVATE_CHANNEL_LIFECYCLE, &cid.to_be_bytes(), forged.as_bytes());
        }
        assert_eq!(run_to_completion(&s, u64::MAX, 5000), PurgePassReport::default());
        for cid in [42u64, 43, PRIVATE_CHANNEL_ID_FLOOR] {
            assert_eq!(s.start_private_channel_purge(cid, u64::MAX).unwrap(), PurgeStart::Skipped);
            assert!(s.purge_step(cid, 5000).unwrap().idle);
            assert!(s.exists_cf(cf::CHANNELS, &cid.to_be_bytes()).unwrap());
            assert!(s.exists_cf(cf::MESSAGES, &id(cid as u8, 1, 0)).unwrap());
            assert!(!s.private_channel_purge_in_progress(cid).unwrap());
            assert!(s.put_channel_and_replay_pending_member_removals(cid, br#"{"channel_type":0}"#).unwrap(), "public creates are never blocked");
        }
    }

    #[test]
    fn private_range_id_with_a_public_typed_row_is_cancelled_not_purged() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(13);
        populate(&s, a, 0xAD);
        schedule(&s, a);
        put(&s, cf::CHANNELS, &a.to_be_bytes(), br#"{"channel_type":0}"#);
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Cancelled);
        assert!(s.exists_cf(cf::MESSAGES, &id(0xAD, 1, 0)).unwrap());
    }

    #[test]
    fn pinned_channels_are_never_purged() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(14);
        let b = pcid(15);
        populate(&s, a, 0xAE);
        populate(&s, b, 0xAF);
        schedule(&s, a); // scheduled before the pin was configured
        let forged = br#"{"v":1,"state":"purging","since_ms":1,"deadline_ms":1,"reason":"deleted","phase":1}"#;
        put(&s, cf::PRIVATE_CHANNEL_LIFECYCLE, &b.to_be_bytes(), forged);
        assert!(s.set_private_channel_policy(PrivateChannelPolicy::new(168, [a, b])));
        let r = run_to_completion(&s, u64::MAX, 5000);
        assert_eq!((r.started, r.rows, r.aborted), (0, 0, 1));
        assert_eq!(s.start_private_channel_purge(a, u64::MAX).unwrap(), PurgeStart::Skipped);
        assert!(s.purge_step(a, 5000).unwrap().idle, "a pending row is never stepped");
        // The forged purging row of a channel whose CHANNELS row still
        // exists was abandoned by the pass above (re-created behind the
        // guards): row gone, every row kept.
        assert!(row(&s, b).is_none());
        assert!(!s.private_channel_purge_in_progress(b).unwrap());
        for (cid, tag) in [(a, 0xAE), (b, 0xAF)] {
            assert!(s.exists_cf(cf::CHANNELS, &cid.to_be_bytes()).unwrap());
            assert!(s.exists_cf(cf::MESSAGES, &id(tag, 1, 0)).unwrap());
        }
    }

    #[test]
    fn unknown_rows_and_phases_are_left_untouched() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(16);
        populate(&s, a, 0xB0);
        for raw in [
            br#"{"v":2,"state":"purging","since_ms":1,"deadline_ms":1,"reason":"deleted","phase":1}"#.to_vec(),
            br#"{"v":1,"state":"purging","since_ms":1,"deadline_ms":1,"reason":"deleted","phase":99}"#.to_vec(),
            br#"{"v":1,"state":"pending","since_ms":1,"deadline_ms":1,"reason":"spring_cleaning"}"#.to_vec(),
            b"not json".to_vec(),
        ] {
            put(&s, cf::PRIVATE_CHANNEL_LIFECYCLE, &a.to_be_bytes(), &raw);
            run_to_completion(&s, u64::MAX, 5000);
            assert_eq!(s.get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &a.to_be_bytes()).unwrap(), Some(raw));
            assert!(s.exists_cf(cf::MESSAGES, &id(0xB0, 1, 0)).unwrap());
        }
    }

    #[test]
    fn a_pin_after_the_purge_started_does_not_stop_it() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(17);
        populate(&s, a, 0xB1);
        schedule(&s, a);
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Started);
        s.purge_step(a, 3).unwrap();
        // The operator pins the channel while its CHANNELS row is already
        // gone: the guards stay on and the purge runs to completion.
        assert!(s.set_private_channel_policy(PrivateChannelPolicy::new(168, [a])));
        assert!(s.private_channel_purge_in_progress(a).unwrap(), "503 / Step 7f stay on");
        assert!(s.lifecycle_blocks_subscription(a).unwrap(), "not re-subscribed mid-purge");
        assert!(!s.put_channel_and_replay_pending_member_removals(a, br#"{"channel_type":2}"#).unwrap());
        let r = run_to_completion(&s, far_future(), 5000);
        assert_eq!((r.completed, r.aborted), (1, 0));
        assert_eq!(purged_cf_counts(&s, a, 0xB1), Vec::<(&str, usize)>::new());
        // Re-federatable afterwards, and pinned from now on.
        assert!(!s.private_channel_purge_in_progress(a).unwrap());
        assert!(s.put_channel_and_replay_pending_member_removals(a, br#"{"channel_type":2}"#).unwrap());
        assert!(!s.lifecycle_blocks_subscription(a).unwrap());
    }

    #[test]
    fn an_active_local_home_that_is_no_longer_a_member_rearms_once() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(18);
        populate(&s, a, 0xB3);
        // An OLD kick learned late removed klv1a (its newer re-join is
        // withheld): scheduled, klv1a is a home but no member.
        schedule(&s, a);
        let since = row(&s, a).unwrap().since_ms;
        // klv1a keeps using this node after the schedule.
        put(&s, cf::LOCAL_DM_USERS, b"klv1a", &schema::encode_local_dm_user(1, since));
        let now = far_future();
        assert_eq!(s.start_private_channel_purge(a, now).unwrap(), PurgeStart::Rearmed);
        let r = row(&s, a).expect("row kept: the channel stays unsubscribed");
        assert_eq!(r.state, LifecycleState::Pending);
        assert!(r.activity_rearmed);
        assert_eq!(r.since_ms, now);
        assert_eq!(r.deadline_ms, Some(now + DEFAULT_GRACE_MS));
        assert!(s.lifecycle_blocks_subscription(a).unwrap());
        assert!(s.exists_cf(cf::CHANNELS, &a.to_be_bytes()).unwrap(), "channel kept");
        assert!(
            !s.exists_cf(cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(a, "klv1a")).unwrap(),
            "nothing makes a non-member a member"
        );
        assert!(
            !s.exists_cf(cf::LOCAL_CHANNEL_HOMES, &schema::encode_local_channel_home_key(a, "klv1b")).unwrap(),
            "no home recorded for anyone else"
        );
        // Not due before the new deadline.
        assert_eq!(s.start_private_channel_purge(a, now + 1).unwrap(), PurgeStart::Skipped);
        // The healing sync restores the membership → the add hook cancels.
        assert!(s.add_channel_member(a, "klv1a", now, "member").unwrap());
        assert!(row(&s, a).is_none(), "restored membership cancels properly");
    }

    #[test]
    fn home_only_activity_after_the_rearm_no_longer_holds_the_purge() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(21);
        populate(&s, a, 0xB7);
        schedule(&s, a); // klv1a left voluntarily; keeps using the node
        let now = far_future();
        put(&s, cf::LOCAL_DM_USERS, b"klv1a", &schema::encode_local_dm_user(1, now));
        assert_eq!(s.start_private_channel_purge(a, now).unwrap(), PurgeStart::Rearmed);
        // Still active at the second deadline: proceeds to purge.
        let later = now + DEFAULT_GRACE_MS;
        put(&s, cf::LOCAL_DM_USERS, b"klv1a", &schema::encode_local_dm_user(1, later));
        assert_eq!(s.start_private_channel_purge(a, later).unwrap(), PurgeStart::Started);
        let r = run_to_completion(&s, later, 5000);
        assert_eq!(r.completed, 1);
        assert_eq!(purged_cf_counts(&s, a, 0xB7), Vec::<(&str, usize)>::new());
        // Current-MEMBER activity still cancels after a re-arm.
        let b = pcid(22);
        populate(&s, b, 0xB8);
        schedule(&s, b);
        put(&s, cf::LOCAL_DM_USERS, b"klv1a", &schema::encode_local_dm_user(1, now));
        assert_eq!(s.start_private_channel_purge(b, now).unwrap(), PurgeStart::Rearmed);
        put(&s, cf::LOCAL_DM_USERS, b"klv1b", &schema::encode_local_dm_user(1, later));
        assert_eq!(s.start_private_channel_purge(b, later).unwrap(), PurgeStart::Cancelled);
        assert!(s.exists_cf(cf::LOCAL_CHANNEL_HOMES, &schema::encode_local_channel_home_key(b, "klv1b")).unwrap());
    }

    #[test]
    fn a_channel_created_here_is_kept_while_its_creator_is_a_member() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(19);
        let fed = pcid(20);
        for (cid, tag) in [(a, 0xB4), (fed, 0xB5)] {
            populate(&s, cid, tag);
            s.add_channel_member(cid, "klv1creator", 1, "creator").unwrap();
        }
        // `fed` was federated from a host: no single-host protection.
        let mut meta: serde_json::Value =
            serde_json::from_slice(&s.get_cf(cf::CHANNELS, &fed.to_be_bytes()).unwrap().unwrap()).unwrap();
        meta["federated_from"] = serde_json::json!("https://host.example");
        put(&s, cf::CHANNELS, &fed.to_be_bytes(), &serde_json::to_vec(&meta).unwrap());
        // The last local home leaves: only the created-here channel is kept.
        s.remove_channel_member_and_raise_epoch_floor(a, "klv1a").unwrap();
        assert!(row(&s, a).is_none(), "created here, creator still a member: never scheduled");
        schedule(&s, fed);
        assert_eq!(s.start_private_channel_purge(fed, far_future()).unwrap(), PurgeStart::Started);
        // A row that exists anyway (written before the creator re-joined,
        // or by an older binary) is cancelled at boot and at purge start.
        let pending = br#"{"v":1,"state":"pending","since_ms":1,"deadline_ms":1,"reason":"no_local_member"}"#;
        put(&s, cf::PRIVATE_CHANNEL_LIFECYCLE, &a.to_be_bytes(), pending);
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Cancelled);
        put(&s, cf::PRIVATE_CHANNEL_LIFECYCLE, &a.to_be_bytes(), pending);
        assert_eq!(s.prepare_private_channel_lifecycle(far_future()).unwrap().cancelled, 1);
        assert!(row(&s, a).is_none());
        // Once the creator itself has left, the protection ends.
        s.remove_channel_member_and_raise_epoch_floor(a, "klv1creator").unwrap();
        assert_eq!(row(&s, a).unwrap().state, LifecycleState::Pending, "creator gone → scheduled");
    }

    #[test]
    fn the_reaper_rotates_so_rows_past_a_page_are_never_starved() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        // Ten never-due rows sort BEFORE the due one.
        for i in 0..10 {
            let blocker = br#"{"v":1,"state":"pending","since_ms":1,"deadline_ms":null,"reason":"no_local_member"}"#;
            put(&s, cf::PRIVATE_CHANNEL_LIFECYCLE, &pcid(30 + i).to_be_bytes(), blocker);
        }
        let due = pcid(60);
        populate(&s, due, 0xB6);
        schedule(&s, due);
        let mut done = false;
        for _ in 0..50 {
            let r = s.run_private_channel_purge_pass_paged(far_future(), 5000, 3).unwrap();
            if r.completed == 1 {
                done = true;
                break;
            }
        }
        assert!(done, "the row behind three full pages was reached");
        assert_eq!(purged_cf_counts(&s, due, 0xB6), Vec::<(&str, usize)>::new());
        for i in 0..10 {
            assert!(row(&s, pcid(30 + i)).is_some(), "never-due rows untouched");
        }
    }

    // ---- l2-node 0.150.0 (Phase E): HOMES ⇔ LOCAL_CHANNEL_HOMES_BY_WALLET ----

    fn index_has(s: &Storage, cid: u64, w: &str) -> bool {
        s.exists_cf(cf::LOCAL_CHANNEL_HOMES_BY_WALLET, &schema::encode_local_channel_home_wallet_key(w.as_bytes(), cid))
            .unwrap()
    }

    /// HOMES ⇔ index, over the whole database.
    fn assert_mirror(s: &Storage) {
        let homes = s.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES, &[], 1_000_000).unwrap();
        let index = s.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES_BY_WALLET, &[], 1_000_000).unwrap();
        assert_eq!(homes.len(), index.len(), "HOMES and its wallet index differ in size");
        for (k, _) in &homes {
            let cid = u64::from_be_bytes(k[..8].try_into().unwrap());
            assert!(
                s.exists_cf(cf::LOCAL_CHANNEL_HOMES_BY_WALLET, &schema::encode_local_channel_home_wallet_key(&k[8..], cid))
                    .unwrap(),
                "HOMES row without index entry"
            );
        }
    }

    #[test]
    fn cancel_records_the_home_with_its_index_entry() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(40);
        populate(&s, a, 0xC1);
        schedule(&s, a);
        let since = row(&s, a).unwrap().since_ms;
        put(&s, cf::LOCAL_DM_USERS, b"klv1b", &schema::encode_local_dm_user(1, since));
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Cancelled);
        assert!(s.exists_cf(cf::LOCAL_CHANNEL_HOMES, &schema::encode_local_channel_home_key(a, "klv1b")).unwrap());
        assert!(index_has(&s, a, "klv1b"));
        assert_mirror(&s);
    }

    #[test]
    fn homes_phase_in_many_slices_leaves_no_index_rows() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let a = pcid(41);
        let b = pcid(42);
        populate(&s, a, 0xC2);
        populate(&s, b, 0xC3);
        for i in 0..9 {
            s.put_local_channel_home_for_test(a, &format!("klv1h{i}"), 1, 1).unwrap();
            s.put_local_channel_home_for_test(b, &format!("klv1h{i}"), 1, 1).unwrap();
        }
        schedule(&s, a);
        assert_eq!(s.start_private_channel_purge(a, far_future()).unwrap(), PurgeStart::Started);
        // Tiny slices: the HOMES step is split across several calls.
        let mut homes_slices = 0;
        for _ in 0..10_000 {
            let in_homes = row(&s, a).is_some_and(|r| r.phase == purge_phase::LOCAL_CHANNEL_HOMES);
            let o = s.purge_step(a, 3).unwrap();
            if in_homes {
                homes_slices += 1;
                assert_mirror(&s);
            }
            if o.finished {
                break;
            }
        }
        assert!(homes_slices > 2, "the HOMES step ran in several slices ({homes_slices})");
        assert!(row(&s, a).is_none());
        assert!(s.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES, &a.to_be_bytes(), 10).unwrap().is_empty());
        for i in 0..9 {
            let w = format!("klv1h{i}");
            assert!(!index_has(&s, a, &w), "no index row left for the purged channel");
            assert!(index_has(&s, b, &w), "the other channel keeps its index rows");
        }
        assert!(index_has(&s, b, "klv1a"));
        assert_mirror(&s);
    }

    /// Randomized: any interleaving of the HOMES writers (record, both
    /// seedings, cancel) and deleters (the purge HOMES step, in slices)
    /// keeps HOMES ⇔ index.
    #[test]
    fn randomized_writers_and_purge_keep_homes_and_index_in_step() {
        let dir = TempDir::new().unwrap();
        let s = seeded(&dir);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = |n: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n
        };
        let cids: Vec<u64> = (0..4).map(|i| pcid(50 + i)).collect();
        for &c in &cids {
            put_channel(&s, c, 2);
        }
        let wallets: Vec<String> = (0..6).map(|i| format!("klv1r{i}")).collect();
        for _ in 0..400 {
            let cid = cids[rnd(cids.len() as u64) as usize];
            let w = wallets[rnd(wallets.len() as u64) as usize].as_str();
            match rnd(6) {
                0 => {
                    let _ = s.add_channel_member(cid, w, 1, "member");
                    s.record_local_channel_home(cid, w, crate::util::now_ms() + rnd(10) * 7_200_000).unwrap();
                }
                1 => {
                    put(&s, cf::LOCAL_CHANNEL_FED, &schema::encode_local_channel_fed_key(w, cid), &1u64.to_be_bytes());
                    s.seed_local_channel_homes_from_fed(1).unwrap();
                }
                2 => {
                    let _ = s.add_channel_member(cid, w, 1, "member");
                    put(&s, cf::LOCAL_DM_USERS, w.as_bytes(), &schema::encode_local_dm_user(1, 1));
                    // Re-run the one-time seeding from scratch.
                    s.reset_homes_seeding_for_test().unwrap();
                    while !s.run_private_channel_homes_seeding(3, 1).unwrap().1 {}
                }
                3 => {
                    let key = schema::encode_channel_member_key(cid, w);
                    s.with_channel_membership_lock(|| s.cancel_pending_purge(cid, Some(&key))).unwrap();
                }
                _ => {
                    // One slice of the HOMES purge step for `cid`.
                    let row = PrivateChannelLifecycleRow {
                        v: 1,
                        state: LifecycleState::Purging,
                        since_ms: 1,
                        deadline_ms: Some(1),
                        reason: LifecycleReason::NoLocalMember,
                        phase: purge_phase::LOCAL_CHANNEL_HOMES,
                        cursor_hex: String::new(),
                        wallets: Vec::new(),
                        creator: None,
                        activity_rearmed: false,
                    };
                    let mut batch = WriteBatch::default();
                    let mut acc = PurgeAcc::default();
                    s.stage_purge_phase(&mut batch, &mut acc, cid, &row, &[], 1 + rnd(5)).unwrap();
                    s.write_batch(batch).unwrap();
                }
            }
            assert_mirror(&s);
        }
        assert!(!s.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES, &[], 10).unwrap().is_empty(), "the run produced homes");
    }
}
