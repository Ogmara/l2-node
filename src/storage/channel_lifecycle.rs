//! Private-channel lifecycle on a node (l2-node 0.149.0, plan
//! `docs/planning/private-channel-lifecycle-plan.md`, phases A + B; the
//! purge itself — phase C — lives in `storage::channel_purge`).
//!
//! A node keeps a private channel's gossip subscription (and, later, its
//! data) only while at least one LOCAL member uses it. Two column families
//! carry the state:
//!
//! - `LOCAL_CHANNEL_HOMES` (`cid_be8 ‖ wallet` → `first_seen_ms ‖
//!   last_seen_ms`): node-local proof that `wallet` uses this node for the
//!   private channel `cid`. Written only for an authenticated caller acting
//!   as itself on a channel it is a member of (`record_local_channel_home`),
//!   and by the boot-time seeding below.
//! - `PRIVATE_CHANNEL_LIFECYCLE` (`cid_be8` → JSON
//!   [`PrivateChannelLifecycleRow`]): the channel has no local member any
//!   more (or its creator deleted it) and is pending local cleanup. While a
//!   row exists the network task does not subscribe the channel's topic.
//!
//! **Level-triggered.** The row is recomputed from the CURRENT state inside
//! the membership critical section (`channel_membership_lock`, same
//! `WriteBatch` as the membership write) after every removal and every add,
//! so replay order and duplicate delivery cannot leave a stale decision: a
//! leave followed by a promoted re-join nets to "no row".
//!
//! **Safe by default.** A channel is scheduled only when it has at least one
//! `LOCAL_CHANNEL_HOMES` row and none of those wallets is still a member; a
//! channel with no local evidence at all is never scheduled. Nothing is
//! scheduled before the one-time seeding pass has completed. Pinned channels
//! and public channel ids are never scheduled, and neither is a channel
//! created on THIS node (no `federated_from`) while its creator is still a
//! member — this node may be its only host (single-host protection). A
//! deleted private channel gets a row only when this node holds local data
//! for it (a home, or a chat / metadata index row). Wrongly keeping a channel
//! costs disk; wrongly dropping one loses a member's history — every
//! ambiguous case here resolves to "keep".
//!
//! A due `pending` row is turned into a `purging` row by the purge reaper
//! (`storage::channel_purge`), which then deletes the channel's local data
//! step by step (`phase`, `cursor_hex`, `wallets`) and finally the row
//! itself. Nothing in this module ever cancels or rewrites a `purging` row,
//! and any row it does not understand is left untouched.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};

use super::rocks::Storage;
use super::schema::{self, cf, state_keys};
use crate::messages::types::PRIVATE_CHANNEL_ID_FLOOR;

/// `has_local_member` scans at most this many `LOCAL_CHANNEL_HOMES` rows
/// of one channel; a channel with this many local homes is reported as
/// HAVING a local member (conservative — it is never scheduled).
pub const HAS_LOCAL_MEMBER_SCAN_CAP: usize = 1024;

/// Grace period used when no policy was installed (`set_private_channel_
/// policy` is called once at startup; tests and tools may skip it). Same as
/// the `[private_channels] purge_grace_hours` default.
pub const DEFAULT_PURGE_GRACE_HOURS: u64 = 168;

/// Rows examined per batch by the one-time seeding pass.
const HOMES_SEED_BATCH: usize = 10_000;

/// Rows of the private `CHANNEL_MEMBERS` range the one-time seeding pass
/// examines per boot; a larger range continues on the next boot from its
/// cursor (no channel is scheduled meanwhile — the sentinel gates that).
pub const HOMES_SEED_BUDGET_PER_BOOT: usize = 500_000;

/// Max `LOCAL_CHANNEL_FED` rows re-seeded per boot (the per-boot re-seed
/// covers federations made while an older binary ran).
pub const FED_RESEED_CAP: usize = 500_000;

/// Max lifecycle rows read by the boot-time normalization
/// (`prepare_private_channel_lifecycle`). The runtime paths never scan the
/// whole CF: the network backstop and the purge reaper each read one
/// bounded page per tick from a rotating cursor.
pub const LIFECYCLE_SCAN_CAP: usize = 100_000;

/// Max local members a re-subscribe asks the private-sync requester to
/// backfill for (each is throttled and needs a cached wallet claim anyway).
pub const RESUBSCRIBE_SYNC_WALLETS: usize = 16;

/// How stale a `LOCAL_CHANNEL_HOMES` `last_seen_ms` may get before a
/// `record_local_channel_home` call refreshes it (keeps the hot chat path to
/// one lock-free point read).
const HOME_REFRESH_INTERVAL_MS: u64 = 60 * 60 * 1000;

/// Lifecycle row state. Any value this release does not know (a later
/// release's states) is read as `Other` and the row is left untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Waiting for its deadline; cancelled when a local member returns.
    Pending,
    /// The purge reaper has started deleting the channel's local data
    /// (`CHANNELS` row already gone). Never cancelled: a returning member
    /// re-federates once the purge has finished (federate answers 503
    /// meanwhile). See `storage::channel_purge`.
    Purging,
    /// A state written by a newer release.
    #[serde(other)]
    Other,
}

/// Why a channel was scheduled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleReason {
    /// Its last local member left or was removed.
    NoLocalMember,
    /// Its creator deleted it (deadline = now, owner decision D4; the
    /// tombstone is permanent, so no member can return).
    Deleted,
    /// A reason written by a newer release.
    #[serde(other)]
    Other,
}

/// One `PRIVATE_CHANNEL_LIFECYCLE` row (JSON, plan §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateChannelLifecycleRow {
    /// Row format version (1).
    pub v: u8,
    pub state: LifecycleState,
    /// Unix ms the channel was scheduled.
    pub since_ms: u64,
    /// Unix ms from which cleanup may run; `None` = never
    /// (`purge_grace_hours = 0`).
    pub deadline_ms: Option<u64>,
    pub reason: LifecycleReason,
    /// Purge step in progress (`storage::channel_purge::purge_phase`); 0
    /// while `pending`.
    #[serde(default)]
    pub phase: u8,
    /// Resume cursor of the current purge step, hex (empty = start of the
    /// step).
    #[serde(default)]
    pub cursor_hex: String,
    /// Wallets captured when the purge started, whose per-wallet rows for
    /// this channel the purge deletes (empty while `pending`).
    #[serde(default)]
    pub wallets: Vec<String>,
    /// The channel's creator, captured from the `CHANNELS` row when the
    /// purge started (that row is deleted then). Lets a `ChannelDelete` by
    /// that creator still write the permanent tombstone while the purge
    /// runs (`MessageRouter` Step 7f). `None` while `pending`, or when the
    /// row had no creator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    /// The purge-start activity gate already re-armed this `pending` row
    /// once because a local home that is no longer a member used this node
    /// after `since_ms` (`storage::channel_purge`). Such activity re-arms a
    /// row at most ONCE; afterwards it no longer holds the purge back.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub activity_rearmed: bool,
}

impl PrivateChannelLifecycleRow {
    fn pending(since_ms: u64, deadline_ms: Option<u64>, reason: LifecycleReason) -> Self {
        Self {
            v: 1,
            state: LifecycleState::Pending,
            since_ms,
            deadline_ms,
            reason,
            phase: 0,
            cursor_hex: String::new(),
            wallets: Vec::new(),
            creator: None,
            activity_rearmed: false,
        }
    }

    /// `true` for a row a returning local member may cancel: pending, and
    /// scheduled because the last local member left (never a deletion).
    pub fn cancellable(&self) -> bool {
        self.state == LifecycleState::Pending && self.reason == LifecycleReason::NoLocalMember
    }
}

/// Operator policy, installed once at startup from `[private_channels]` and
/// `[storage] pinned_channels`.
#[derive(Debug, Clone, Default)]
pub struct PrivateChannelPolicy {
    /// Grace before cleanup, ms; `None` = never clean up (rows are still
    /// written so the topic is unsubscribed).
    pub grace_ms: Option<u64>,
    /// Channels never scheduled (and always subscribed).
    pub pinned: HashSet<u64>,
}

impl PrivateChannelPolicy {
    /// Build from config values: `purge_grace_hours = 0` means never.
    pub fn new(purge_grace_hours: u64, pinned: impl IntoIterator<Item = u64>) -> Self {
        Self {
            grace_ms: (purge_grace_hours > 0)
                .then(|| purge_grace_hours.saturating_mul(3_600_000)),
            pinned: pinned.into_iter().collect(),
        }
    }
}

/// Lifecycle state shared by every `Storage` clone (one `Arc` per open DB).
#[derive(Debug, Default)]
pub struct LifecycleShared {
    policy: OnceLock<PrivateChannelPolicy>,
    notifier: OnceLock<tokio::sync::mpsc::UnboundedSender<u64>>,
    homes_seeded: AtomicBool,
    migrated_at_ms: AtomicU64,
}

/// Result of `record_local_channel_home`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalHomeOutcome {
    /// A `LOCAL_CHANNEL_HOMES` row was written (new or refreshed).
    pub recorded: bool,
    /// A pending cleanup was cancelled — the caller should make sure the
    /// channel is subscribed again and its gap backfilled.
    pub cancelled: bool,
}

/// What the boot-time lifecycle preparation did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LifecyclePrepareReport {
    /// Another binary advanced the chain cursor since this release last
    /// ran: every pending deadline was re-armed to `now + grace`.
    pub rearmed: bool,
    /// Rows cancelled because a local member exists now (or the channel is
    /// pinned / not private).
    pub cancelled: usize,
    /// Rows whose deadline was changed.
    pub updated: usize,
}

pub(super) fn is_private_id(channel_id: u64) -> bool {
    channel_id > PRIVATE_CHANNEL_ID_FLOOR
}

fn decode_home(value: &[u8]) -> Option<(u64, u64)> {
    if value.len() != 16 {
        return None;
    }
    let first = u64::from_be_bytes(value[..8].try_into().ok()?);
    let last = u64::from_be_bytes(value[8..].try_into().ok()?);
    Some((first, last))
}

pub(super) fn encode_home(first_seen_ms: u64, last_seen_ms: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&first_seen_ms.to_be_bytes());
    out[8..].copy_from_slice(&last_seen_ms.to_be_bytes());
    out
}

impl Storage {
    /// Install the operator policy (once; later calls are ignored and
    /// return `false`). Must run before any membership change is applied.
    pub fn set_private_channel_policy(&self, policy: PrivateChannelPolicy) -> bool {
        self.lifecycle.policy.set(policy).is_ok()
    }

    /// Install the channel the storage layer notifies (with the channel id)
    /// whenever a lifecycle row is written or removed, so the network task
    /// can unsubscribe/resubscribe at once (owner decision D7). Once;
    /// later calls return `false`.
    pub fn set_channel_lifecycle_notifier(
        &self,
        tx: tokio::sync::mpsc::UnboundedSender<u64>,
    ) -> bool {
        self.lifecycle.notifier.set(tx).is_ok()
    }

    /// `true` if `channel_id` is in `[storage] pinned_channels`.
    pub fn is_pinned_channel(&self, channel_id: u64) -> bool {
        self.lifecycle
            .policy
            .get()
            .is_some_and(|p| p.pinned.contains(&channel_id))
    }

    pub(super) fn lifecycle_grace_ms(&self) -> Option<u64> {
        match self.lifecycle.policy.get() {
            Some(p) => p.grace_ms,
            None => Some(DEFAULT_PURGE_GRACE_HOURS * 3_600_000),
        }
    }

    /// Deadline for a row scheduled at `base_ms`: never earlier than the
    /// first boot of this release plus the grace (plan §5 first-boot floor).
    fn lifecycle_deadline(&self, base_ms: u64) -> Option<u64> {
        let grace = self.lifecycle_grace_ms()?;
        let floor = self.lifecycle.migrated_at_ms.load(Ordering::Acquire);
        Some(base_ms.saturating_add(grace).max(floor.saturating_add(grace)))
    }

    /// Whether the one-time `LOCAL_CHANNEL_HOMES` seeding has completed.
    pub fn private_channel_homes_seeded(&self) -> bool {
        self.lifecycle.homes_seeded.load(Ordering::Acquire)
    }

    /// Load the persisted lifecycle markers into the shared state (called
    /// by `Storage::open`). A read error leaves "not seeded", which only
    /// suppresses scheduling (safe).
    pub(super) fn load_lifecycle_markers(&self) {
        if self.get_stat(state_keys::PRIVATE_CHANNEL_HOMES_SEEDED_V1).unwrap_or(0) > 0 {
            self.lifecycle.homes_seeded.store(true, Ordering::Release);
        }
        let migrated = self.get_stat(state_keys::PRIVATE_LIFECYCLE_MIGRATED_AT_MS).unwrap_or(0);
        self.lifecycle.migrated_at_ms.store(migrated, Ordering::Release);
    }

    /// Tell the network task that `channel_id`'s lifecycle row changed.
    pub(super) fn notify_lifecycle(&self, channel_id: u64) {
        if let Some(tx) = self.lifecycle.notifier.get() {
            // The receiver only goes away at shutdown; the backstop tick
            // re-reads every row anyway.
            let _ = tx.send(channel_id);
        }
    }

    /// The lifecycle row of `channel_id`, if any. An unparseable row is an
    /// error (callers that only need "is there a row" use
    /// `has_private_channel_lifecycle_row`).
    pub fn private_channel_lifecycle_row(
        &self,
        channel_id: u64,
    ) -> Result<Option<PrivateChannelLifecycleRow>> {
        match self.get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &channel_id.to_be_bytes())? {
            None => Ok(None),
            Some(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .context("decoding PRIVATE_CHANNEL_LIFECYCLE row"),
        }
    }

    /// `true` if any lifecycle row (understood or not) exists.
    pub fn has_private_channel_lifecycle_row(&self, channel_id: u64) -> Result<bool> {
        self.exists_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &channel_id.to_be_bytes())
    }

    /// `true` while the purge reaper is deleting `channel_id`'s local data
    /// (an understood `purging` row of a private id). Creating the channel
    /// again (`put_channel_and_replay_pending_member_removals`, the router's
    /// `ChannelCreate` apply), federating it (503) and applying private-sync
    /// pages for it are refused meanwhile. Public ids are always `false`; an
    /// unparseable row reads as `false` (it is never purged either).
    ///
    /// A channel pinned AFTER its purge started still reads `true`: the
    /// `CHANNELS` row is already gone, so the purge runs to completion (a
    /// pin only keeps a `pending` row from starting) and every guard must
    /// stay on until it has.
    pub fn private_channel_purge_in_progress(&self, channel_id: u64) -> Result<bool> {
        if !is_private_id(channel_id) {
            return Ok(false);
        }
        Ok(self
            .get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &channel_id.to_be_bytes())?
            .and_then(|raw| serde_json::from_slice::<PrivateChannelLifecycleRow>(&raw).ok())
            .is_some_and(|r| r.state == LifecycleState::Purging))
    }

    /// The creator captured by an in-progress purge of `channel_id` (see
    /// [`PrivateChannelLifecycleRow::creator`]); `None` when no purge is in
    /// progress or none was captured.
    pub fn purging_channel_creator(&self, channel_id: u64) -> Result<Option<String>> {
        Ok(self.purging_lifecycle_row(channel_id)?.and_then(|r| r.creator))
    }

    /// The understood `purging` lifecycle row of a private `channel_id`, if
    /// a purge is in progress.
    pub fn purging_lifecycle_row(&self, channel_id: u64) -> Result<Option<PrivateChannelLifecycleRow>> {
        if !is_private_id(channel_id) {
            return Ok(None);
        }
        Ok(self
            .get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &channel_id.to_be_bytes())?
            .and_then(|raw| serde_json::from_slice::<PrivateChannelLifecycleRow>(&raw).ok())
            .filter(|r| r.state == LifecycleState::Purging))
    }

    /// Whether the node should currently stay OFF `channel_id`'s gossip
    /// topic: a private id with a lifecycle row, unless it is pinned (a
    /// pinned channel is always subscribed — except while a purge that
    /// started before the pin is still running). Public ids are always
    /// `false`.
    pub fn lifecycle_blocks_subscription(&self, channel_id: u64) -> Result<bool> {
        if !is_private_id(channel_id) {
            return Ok(false);
        }
        if self.is_pinned_channel(channel_id) {
            return self.private_channel_purge_in_progress(channel_id);
        }
        self.has_private_channel_lifecycle_row(channel_id)
    }

    /// `true` if `wallet` may still have a stake in `channel_id` on this
    /// node: it is a current member, OR it has a `LOCAL_CHANNEL_HOMES` row
    /// or a `LOCAL_CHANNEL_FED` row for the channel. Used by the private-
    /// sync requester: a local member whose membership was removed by a
    /// stale replay (an old kick learned late) must still be able to run
    /// the healing walk that replays its newer re-join, and persist its
    /// progress.
    pub fn wallet_has_local_channel_standing(&self, channel_id: u64, wallet: &str) -> Result<bool> {
        let member_key = schema::encode_channel_member_key(channel_id, wallet);
        if self.exists_cf(cf::CHANNEL_MEMBERS, &member_key)? {
            return Ok(true);
        }
        // A HOMES key is byte-identical to the CHANNEL_MEMBERS key.
        if self.exists_cf(cf::LOCAL_CHANNEL_HOMES, &member_key)? {
            return Ok(true);
        }
        self.exists_cf(
            cf::LOCAL_CHANNEL_FED,
            &schema::encode_local_channel_fed_key(wallet, channel_id),
        )
    }

    /// Single-host protection: `true` when `channel_meta` (a `CHANNELS`
    /// row) describes a channel CREATED on this node — no `federated_from`
    /// (that field is written only by `federate_channel`, recording the host
    /// this node federated the channel from) — whose creator is still a
    /// member (ignoring `removed`, a member whose removal is staged but not
    /// yet written). Such a node may be the channel's only host: it is never
    /// scheduled for cleanup while its creator remains a member, local
    /// evidence or not. A channel learned from the chain scanner or gossip
    /// without a federation also lacks `federated_from`; protecting it too
    /// only costs disk (the safe direction).
    pub(super) fn single_host_creator_protected(
        &self,
        channel_id: u64,
        channel_meta: &serde_json::Value,
        removed: Option<&str>,
    ) -> Result<bool> {
        if channel_meta.get("federated_from").is_some_and(|v| !v.is_null()) {
            return Ok(false);
        }
        let Some(creator) = channel_meta.get("creator").and_then(|v| v.as_str()) else {
            return Ok(false);
        };
        if creator.is_empty() || removed == Some(creator) {
            return Ok(false);
        }
        self.exists_cf(cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(channel_id, creator))
    }

    /// [`single_host_creator_protected`](Self::single_host_creator_protected)
    /// for the channel's current `CHANNELS` row (absent or unparseable →
    /// `false`).
    pub(super) fn single_host_creator_protected_now(&self, channel_id: u64) -> Result<bool> {
        let Some(meta) = self
            .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())?
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        else {
            return Ok(false);
        };
        self.single_host_creator_protected(channel_id, &meta, None)
    }

    /// `true` if some wallet with a `LOCAL_CHANNEL_HOMES` row for
    /// `channel_id` is currently a member (plan §1 predicate). Hitting the
    /// scan cap counts as `true`.
    pub fn has_local_member(&self, channel_id: u64) -> Result<bool> {
        Ok(self.local_member_scan(channel_id, None)?.0)
    }

    /// `(has_local_member, homes_rows_seen)`, ignoring `exclude` (a member
    /// whose removal is staged but not yet written).
    fn local_member_scan(&self, channel_id: u64, exclude: Option<&str>) -> Result<(bool, usize)> {
        let prefix = channel_id.to_be_bytes();
        let rows = self.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES, &prefix, HAS_LOCAL_MEMBER_SCAN_CAP)?;
        if rows.len() >= HAS_LOCAL_MEMBER_SCAN_CAP {
            return Ok((true, rows.len()));
        }
        for (key, _) in &rows {
            let Some(wallet) = key.get(8..) else { continue };
            if exclude.is_some_and(|ex| ex.as_bytes() == wallet) {
                continue;
            }
            // A HOMES key is byte-identical to the CHANNEL_MEMBERS key.
            if self.exists_cf(cf::CHANNEL_MEMBERS, key)? {
                return Ok((true, rows.len()));
            }
        }
        Ok((false, rows.len()))
    }

    /// Up to `cap` wallets that have a local home for `channel_id` AND are
    /// currently members of it.
    pub fn local_member_wallets(&self, channel_id: u64, cap: usize) -> Result<Vec<String>> {
        let prefix = channel_id.to_be_bytes();
        let rows = self.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES, &prefix, HAS_LOCAL_MEMBER_SCAN_CAP)?;
        let mut out = Vec::new();
        for (key, _) in &rows {
            if out.len() >= cap {
                break;
            }
            let Some(wallet) = key.get(8..).and_then(|w| std::str::from_utf8(w).ok()) else {
                continue;
            };
            if self.exists_cf(cf::CHANNEL_MEMBERS, key)? {
                out.push(wallet.to_string());
            }
        }
        Ok(out)
    }

    /// Removal hook: called by `remove_channel_member_and_raise_epoch_
    /// floor_locked` (lock held) after it staged the delete of `removed`'s
    /// member row, with the channel's current `CHANNELS` JSON. Stages a
    /// `pending` row when the channel is private, not pinned, seeding is
    /// complete, no row exists yet, it has at least one local home, no
    /// local home is still a member, and it is not single-host protected
    /// (`single_host_creator_protected`). Returns `true` if a row was staged.
    pub(super) fn stage_lifecycle_on_removal(
        &self,
        batch: &mut WriteBatch,
        channel_id: u64,
        removed: &str,
        channel_meta: &serde_json::Value,
        now_ms: u64,
    ) -> Result<bool> {
        if !is_private_id(channel_id)
            || !channel_meta
                .get("channel_type")
                .is_some_and(super::rocks::json_channel_type_is_private)
            || self.is_pinned_channel(channel_id)
            || !self.private_channel_homes_seeded()
            || self.has_private_channel_lifecycle_row(channel_id)?
        {
            return Ok(false);
        }
        let (has_member, homes) = self.local_member_scan(channel_id, Some(removed))?;
        if homes == 0 || has_member {
            return Ok(false);
        }
        if self.single_host_creator_protected(channel_id, channel_meta, Some(removed))? {
            return Ok(false);
        }
        let row = PrivateChannelLifecycleRow::pending(
            now_ms,
            self.lifecycle_deadline(now_ms),
            LifecycleReason::NoLocalMember,
        );
        let bytes = serde_json::to_vec(&row).context("encoding lifecycle row")?;
        let handle = self.cf_handle(cf::PRIVATE_CHANNEL_LIFECYCLE)?;
        batch.put_cf(&handle, channel_id.to_be_bytes(), bytes);
        tracing::info!(channel_id, "private channel has no local member left; scheduled for cleanup");
        Ok(true)
    }

    /// Add hook: called by `add_channel_member_locked` (lock held) when it
    /// stages `address` as a member. Cancels a cancellable pending row if
    /// `address` has a local home here. Returns `true` if a delete was
    /// staged.
    pub(super) fn stage_lifecycle_on_add(
        &self,
        batch: &mut WriteBatch,
        channel_id: u64,
        address: &str,
    ) -> Result<bool> {
        if !is_private_id(channel_id) {
            return Ok(false);
        }
        let Some(row) = self.private_channel_lifecycle_row(channel_id).ok().flatten() else {
            return Ok(false);
        };
        if !row.cancellable() {
            return Ok(false);
        }
        let home_key = schema::encode_local_channel_home_key(channel_id, address);
        if !self.exists_cf(cf::LOCAL_CHANNEL_HOMES, &home_key)? {
            return Ok(false);
        }
        let handle = self.cf_handle(cf::PRIVATE_CHANNEL_LIFECYCLE)?;
        batch.delete_cf(&handle, channel_id.to_be_bytes());
        tracing::info!(channel_id, "local member re-joined; cleanup cancelled");
        Ok(true)
    }

    /// Tombstone hook (owner decision D4): a deleted private channel gets a
    /// `deleted` row with deadline = now (or never when the grace is 0).
    /// `channel_row` is the `CHANNELS` value read before the delete; a
    /// missing or non-private row stages nothing, nor does a channel without
    /// any local data (no home, no `CHANNEL_MSGS` / `CHANNEL_META_MSGS` row)
    /// or one whose row is already `purging` (or not understood). Returns
    /// `true` if staged.
    pub(super) fn stage_lifecycle_on_tombstone(
        &self,
        batch: &mut WriteBatch,
        channel_id: u64,
        channel_row: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<bool> {
        if !is_private_id(channel_id) || self.is_pinned_channel(channel_id) {
            return Ok(false);
        }
        let private = channel_row
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .is_some_and(|m| {
                m.get("channel_type")
                    .is_some_and(super::rocks::json_channel_type_is_private)
            });
        if !private {
            return Ok(false);
        }
        // Never rewrite a purge already running (or a row this release does
        // not understand).
        if let Some(raw) = self.get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &channel_id.to_be_bytes())? {
            let rewritable = serde_json::from_slice::<PrivateChannelLifecycleRow>(&raw)
                .is_ok_and(|r| r.v == 1 && r.state == LifecycleState::Pending);
            if !rewritable {
                return Ok(false);
            }
        }
        // Only a channel with local data needs a cleanup row: a local home,
        // or any chat / metadata index row (one key each, a prefix seek).
        // Without any, `tombstone_channel` has already cleared the metadata
        // and the permanent tombstone prevents resurrection — a row would
        // only cost a lifecycle entry per deleted channel id (and a flood of
        // deletes for unknown private ids would grow the CF).
        let prefix = channel_id.to_be_bytes();
        let has_local_data = !self.prefix_iter_cf(cf::LOCAL_CHANNEL_HOMES, &prefix, 1)?.is_empty()
            || !self.prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, 1)?.is_empty()
            || !self.prefix_iter_cf(cf::CHANNEL_META_MSGS, &prefix, 1)?.is_empty();
        if !has_local_data {
            return Ok(false);
        }
        let deadline = self.lifecycle_grace_ms().map(|_| now_ms);
        let row = PrivateChannelLifecycleRow::pending(now_ms, deadline, LifecycleReason::Deleted);
        let bytes = serde_json::to_vec(&row).context("encoding lifecycle row")?;
        let handle = self.cf_handle(cf::PRIVATE_CHANNEL_LIFECYCLE)?;
        batch.put_cf(&handle, channel_id.to_be_bytes(), bytes);
        Ok(true)
    }

    /// Record that `wallet` (the AUTHENTICATED caller, acting as itself)
    /// uses this node for the private channel `channel_id`: writes its
    /// `LOCAL_CHANNEL_HOMES` row and cancels a pending cleanup. A no-op
    /// unless the channel is private and `wallet` is a member — callers
    /// must never pass an address taken from an envelope that the caller
    /// did not author (anyone could replay a member's join otherwise; the
    /// worst case of that is over-retention, never loss).
    ///
    /// Lock-free fast path: a home row refreshed within the last hour and
    /// no lifecycle row → nothing to write.
    pub fn record_local_channel_home(
        &self,
        channel_id: u64,
        wallet: &str,
        now_ms: u64,
    ) -> Result<LocalHomeOutcome> {
        if !is_private_id(channel_id) || wallet.is_empty() {
            return Ok(LocalHomeOutcome::default());
        }
        let home_key = schema::encode_local_channel_home_key(channel_id, wallet);
        let fresh = self
            .get_cf(cf::LOCAL_CHANNEL_HOMES, &home_key)?
            .and_then(|v| decode_home(&v))
            .is_some_and(|(_, last)| now_ms.saturating_sub(last) < HOME_REFRESH_INTERVAL_MS);
        if fresh && !self.has_private_channel_lifecycle_row(channel_id)? {
            return Ok(LocalHomeOutcome::default());
        }
        let outcome = self.with_channel_membership_lock(|| -> Result<LocalHomeOutcome> {
            let Some(meta) = self.get_cf(cf::CHANNELS, &channel_id.to_be_bytes())? else {
                return Ok(LocalHomeOutcome::default());
            };
            let private = serde_json::from_slice::<serde_json::Value>(&meta)
                .ok()
                .is_some_and(|m| {
                    m.get("channel_type")
                        .is_some_and(super::rocks::json_channel_type_is_private)
                });
            // A HOMES key is byte-identical to the CHANNEL_MEMBERS key.
            if !private || !self.exists_cf(cf::CHANNEL_MEMBERS, &home_key)? {
                return Ok(LocalHomeOutcome::default());
            }
            let first = self
                .get_cf(cf::LOCAL_CHANNEL_HOMES, &home_key)?
                .and_then(|v| decode_home(&v))
                .map(|(f, _)| f)
                .unwrap_or(now_ms);
            let mut batch = WriteBatch::default();
            let homes = self.cf_handle(cf::LOCAL_CHANNEL_HOMES)?;
            batch.put_cf(&homes, &home_key, encode_home(first, now_ms));
            drop(homes);
            let cancelled = self
                .private_channel_lifecycle_row(channel_id)
                .ok()
                .flatten()
                .is_some_and(|r| r.cancellable());
            if cancelled {
                let handle = self.cf_handle(cf::PRIVATE_CHANNEL_LIFECYCLE)?;
                batch.delete_cf(&handle, channel_id.to_be_bytes());
            }
            self.write_batch(batch)?;
            Ok(LocalHomeOutcome { recorded: true, cancelled })
        })?;
        if outcome.cancelled {
            tracing::info!(channel_id, "local member returned; private-channel cleanup cancelled");
            self.notify_lifecycle(channel_id);
        }
        Ok(outcome)
    }

    /// Insert a home row for `(channel_id, wallet)` if none exists (seeding;
    /// caller holds the lock or runs before any concurrent writer).
    fn seed_home_if_missing(
        &self,
        batch: &mut WriteBatch,
        channel_id: u64,
        wallet: &[u8],
        seen_ms: u64,
    ) -> Result<bool> {
        let mut key = channel_id.to_be_bytes().to_vec();
        key.extend_from_slice(wallet);
        if self.exists_cf(cf::LOCAL_CHANNEL_HOMES, &key)? {
            return Ok(false);
        }
        let handle = self.cf_handle(cf::LOCAL_CHANNEL_HOMES)?;
        batch.put_cf(&handle, &key, encode_home(seen_ms, seen_ms));
        Ok(true)
    }

    /// `true` if `channel_id`'s `CHANNELS` row exists and is Private.
    fn channel_row_is_private(&self, channel_id: u64) -> Result<bool> {
        Ok(self
            .get_cf(cf::CHANNELS, &channel_id.to_be_bytes())?
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .is_some_and(|m| {
                m.get("channel_type")
                    .is_some_and(super::rocks::json_channel_type_is_private)
            }))
    }

    /// Seed `LOCAL_CHANNEL_HOMES` from every `LOCAL_CHANNEL_FED` row of a
    /// known private channel (plan §1 source (a)). Runs on EVERY boot: it
    /// covers federations made while an older binary ran. Never overwrites
    /// an existing row. Returns rows written.
    pub fn seed_local_channel_homes_from_fed(&self, now_ms: u64) -> Result<usize> {
        let rows = self.prefix_iter_cf(cf::LOCAL_CHANNEL_FED, &[], FED_RESEED_CAP)?;
        if rows.len() >= FED_RESEED_CAP {
            tracing::warn!(cap = FED_RESEED_CAP, "LOCAL_CHANNEL_FED re-seed hit its per-boot cap");
        }
        let mut written = 0usize;
        for chunk in rows.chunks(HOMES_SEED_BATCH) {
            written += self.with_channel_membership_lock(|| -> Result<usize> {
                let mut batch = WriteBatch::default();
                let mut n = 0usize;
                for (key, value) in chunk {
                    // (wallet, 0xFF, cid_be8)
                    if key.len() < 10 || key[key.len() - 9] != 0xFF {
                        continue;
                    }
                    let (wallet, rest) = key.split_at(key.len() - 9);
                    let Ok(cid_bytes) = <[u8; 8]>::try_from(&rest[1..]) else { continue };
                    let cid = u64::from_be_bytes(cid_bytes);
                    if !is_private_id(cid) || !self.channel_row_is_private(cid)? {
                        continue;
                    }
                    let seen = <[u8; 8]>::try_from(value.as_slice())
                        .map(u64::from_be_bytes)
                        .unwrap_or(now_ms);
                    if self.seed_home_if_missing(&mut batch, cid, wallet, seen)? {
                        n += 1;
                    }
                }
                if n > 0 {
                    self.write_batch(batch)?;
                }
                Ok(n)
            })?;
        }
        Ok(written)
    }

    /// One-time seeding (plan §1 sources (b) and (c)): for every member row
    /// of a private channel whose wallet authenticated here
    /// (`LOCAL_DM_USERS`) or keeps a read cursor here
    /// (`CHANNEL_READ_STATE`), write a home row. Bounded by `budget` rows
    /// per call and resumable (`PRIVATE_CHANNEL_HOMES_SEED_CURSOR`); sets
    /// `PRIVATE_CHANNEL_HOMES_SEEDED_V1` once the range is exhausted.
    /// Returns `(homes written, done)`.
    pub fn run_private_channel_homes_seeding(&self, budget: usize, now_ms: u64) -> Result<(usize, bool)> {
        if self.private_channel_homes_seeded() {
            return Ok((0, true));
        }
        let mut cursor = self
            .get_cf(cf::NODE_STATE, state_keys::PRIVATE_CHANNEL_HOMES_SEED_CURSOR)?
            .unwrap_or_else(|| PRIVATE_CHANNEL_ID_FLOOR.saturating_add(1).to_be_bytes().to_vec());
        let mut examined = 0usize;
        let mut written = 0usize;
        loop {
            if examined >= budget {
                self.put_cf(cf::NODE_STATE, state_keys::PRIVATE_CHANNEL_HOMES_SEED_CURSOR, &cursor)?;
                return Ok((written, false));
            }
            let take = HOMES_SEED_BATCH.min(budget - examined);
            let rows = self.prefix_iter_cf_after(cf::CHANNEL_MEMBERS, &cursor, &[], take)?;
            let exhausted = rows.len() < take;
            examined += rows.len();
            written += self.with_channel_membership_lock(|| -> Result<usize> {
                let mut batch = WriteBatch::default();
                let mut n = 0usize;
                let mut last_cid: Option<(u64, bool)> = None;
                for (key, _) in &rows {
                    let Some(cid) = key
                        .get(..8)
                        .and_then(|b| <[u8; 8]>::try_from(b).ok())
                        .map(u64::from_be_bytes)
                    else {
                        continue;
                    };
                    let wallet = &key[8..];
                    if wallet.is_empty() || !is_private_id(cid) {
                        continue;
                    }
                    let private = match last_cid {
                        Some((c, p)) if c == cid => p,
                        _ => {
                            let p = self.channel_row_is_private(cid)?;
                            last_cid = Some((cid, p));
                            p
                        }
                    };
                    if !private {
                        continue;
                    }
                    let Ok(wallet_str) = std::str::from_utf8(wallet) else { continue };
                    let evidence = self.exists_cf(cf::LOCAL_DM_USERS, wallet)?
                        || self.exists_cf(
                            cf::CHANNEL_READ_STATE,
                            &schema::encode_channel_read_key(wallet_str, cid),
                        )?;
                    if evidence && self.seed_home_if_missing(&mut batch, cid, wallet, now_ms)? {
                        n += 1;
                    }
                }
                if n > 0 {
                    self.write_batch(batch)?;
                }
                Ok(n)
            })?;
            if let Some((key, _)) = rows.last() {
                cursor = key.clone();
            }
            if exhausted {
                let handle = self.cf_handle(cf::NODE_STATE)?;
                let mut batch = WriteBatch::default();
                batch.put_cf(&handle, state_keys::PRIVATE_CHANNEL_HOMES_SEEDED_V1, 1u64.to_be_bytes());
                batch.delete_cf(&handle, state_keys::PRIVATE_CHANNEL_HOMES_SEED_CURSOR);
                drop(handle);
                self.write_batch(batch)?;
                self.lifecycle.homes_seeded.store(true, Ordering::Release);
                return Ok((written, true));
            }
        }
    }

    /// Boot-time lifecycle preparation, run after the seeding above and
    /// before the network task starts:
    ///
    /// 1. First boot of this release: record `PRIVATE_LIFECYCLE_MIGRATED_AT_MS`
    ///    (the deadline floor).
    /// 2. Downgrade detection: `PRIVATE_LIFECYCLE_CHAIN_CURSOR` behind
    ///    `CHAIN_CURSOR` means an older binary ran the scanner (and recorded
    ///    no local evidence) — every pending deadline is re-armed to
    ///    `now + grace`.
    /// 3. Every understood pending row is re-evaluated: cancelled when the
    ///    channel is pinned, not private, or (`no_local_member` rows) has a
    ///    local member again or is single-host protected; its
    ///    deadline follows the current grace (`0` → never) and is never
    ///    shortened.
    pub fn prepare_private_channel_lifecycle(&self, now_ms: u64) -> Result<LifecyclePrepareReport> {
        let mut report = LifecyclePrepareReport::default();
        if self.get_stat(state_keys::PRIVATE_LIFECYCLE_MIGRATED_AT_MS)? == 0 {
            self.put_cf(cf::NODE_STATE, state_keys::PRIVATE_LIFECYCLE_MIGRATED_AT_MS, &now_ms.to_be_bytes())?;
            self.lifecycle.migrated_at_ms.store(now_ms, Ordering::Release);
        }
        let cursor = self.get_chain_cursor()?;
        // No stamp = first boot of this release: nothing to re-arm (no rows
        // yet). An unreadable stamp re-arms (the conservative direction).
        if let Some(raw) = self.get_cf(cf::NODE_STATE, state_keys::PRIVATE_LIFECYCLE_CHAIN_CURSOR)? {
            let stamp = <[u8; 8]>::try_from(raw.as_slice()).map(u64::from_be_bytes).unwrap_or(0);
            report.rearmed = stamp < cursor;
        }
        self.put_cf(cf::NODE_STATE, state_keys::PRIVATE_LIFECYCLE_CHAIN_CURSOR, &cursor.to_be_bytes())?;

        let rows = self.prefix_iter_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &[], LIFECYCLE_SCAN_CAP)?;
        let grace = self.lifecycle_grace_ms();
        for (key, value) in rows {
            let Ok(cid_bytes) = <[u8; 8]>::try_from(key.as_slice()) else { continue };
            let cid = u64::from_be_bytes(cid_bytes);
            let Ok(row) = serde_json::from_slice::<PrivateChannelLifecycleRow>(&value) else {
                continue; // a newer release's row: leave it alone
            };
            if row.state != LifecycleState::Pending {
                continue;
            }
            let changed = self.with_channel_membership_lock(|| -> Result<Option<bool>> {
                // Re-read under the lock (TOCTOU with nothing at boot, but cheap).
                let Some(row) = self.private_channel_lifecycle_row(cid).ok().flatten() else {
                    return Ok(None);
                };
                if row.state != LifecycleState::Pending {
                    return Ok(None);
                }
                let cancel = !is_private_id(cid)
                    || self.is_pinned_channel(cid)
                    || (row.reason == LifecycleReason::NoLocalMember
                        && (self.has_local_member(cid)? || self.single_host_creator_protected_now(cid)?));
                if cancel {
                    self.delete_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &key)?;
                    return Ok(Some(true));
                }
                let deadline = match (grace, row.reason) {
                    (None, _) => None,
                    (Some(_), LifecycleReason::Deleted) => Some(row.deadline_ms.unwrap_or(now_ms)),
                    (Some(_), _) => {
                        let base = if report.rearmed || row.deadline_ms.is_none() { now_ms } else { row.since_ms };
                        let target = self.lifecycle_deadline(base).unwrap_or(u64::MAX);
                        Some(target.max(row.deadline_ms.unwrap_or(0)))
                    }
                };
                if deadline == row.deadline_ms {
                    return Ok(None);
                }
                let updated = PrivateChannelLifecycleRow { deadline_ms: deadline, ..row };
                let bytes = serde_json::to_vec(&updated).context("encoding lifecycle row")?;
                self.put_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &key, &bytes)?;
                Ok(Some(false))
            })?;
            match changed {
                Some(true) => report.cancelled += 1,
                Some(false) => report.updated += 1,
                None => {}
            }
        }
        Ok(report)
    }

    /// One page of lifecycle row ids, strictly after `after` (empty = from
    /// the start), at most `limit`, each with whether it is an understood
    /// `pending` row — for the network task's rotating backstop scan and the
    /// pending gauge. Returns the page and the cursor of the next page
    /// (`None` once the end of the column family was reached).
    pub fn private_channel_lifecycle_page(
        &self,
        after: &[u8],
        limit: usize,
    ) -> Result<(Vec<(u64, bool)>, Option<Vec<u8>>)> {
        let limit = limit.max(1);
        let rows = if after.is_empty() {
            self.prefix_iter_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &[], limit)?
        } else {
            self.prefix_iter_cf_after(cf::PRIVATE_CHANNEL_LIFECYCLE, after, &[], limit)?
        };
        let next = (rows.len() >= limit).then(|| rows.last().map(|(k, _)| k.clone())).flatten();
        let ids = rows
            .into_iter()
            .filter_map(|(k, v)| {
                let cid = u64::from_be_bytes(<[u8; 8]>::try_from(k.as_slice()).ok()?);
                let pending = serde_json::from_slice::<PrivateChannelLifecycleRow>(&v)
                    .is_ok_and(|r| r.state == LifecycleState::Pending);
                Some((cid, pending))
            })
            .collect();
        Ok((ids, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const NOW: u64 = 1_800_000_000_000;
    const HOUR: u64 = 3_600_000;

    fn pcid(n: u64) -> u64 {
        PRIVATE_CHANNEL_ID_FLOOR + n
    }

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        let s = Storage::open(dir.path()).unwrap();
        (s, dir)
    }

    /// Storage with the seeding sentinel set (an empty DB seeds instantly).
    fn seeded_db() -> (Storage, TempDir) {
        let (s, d) = db();
        assert_eq!(s.run_private_channel_homes_seeding(1000, NOW).unwrap(), (0, true));
        (s, d)
    }

    fn put_channel(s: &Storage, cid: u64, ctype: u64) {
        let row = serde_json::json!({"channel_id": cid, "channel_type": ctype, "creator": "klv1creator", "member_count": 0});
        s.put_cf(cf::CHANNELS, &cid.to_be_bytes(), &serde_json::to_vec(&row).unwrap()).unwrap();
    }

    fn row(s: &Storage, cid: u64) -> Option<PrivateChannelLifecycleRow> {
        s.private_channel_lifecycle_row(cid).unwrap()
    }

    fn is_member(s: &Storage, cid: u64, w: &str) -> bool {
        s.exists_cf(cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(cid, w)).unwrap()
    }

    /// Private channel with `w` a member and a local home.
    fn local_member(s: &Storage, cid: u64, w: &str) {
        assert!(s.add_channel_member(cid, w, NOW, "member").unwrap() || is_member(s, cid, w));
        assert!(s.record_local_channel_home(cid, w, NOW).unwrap().recorded);
    }

    #[test]
    fn predicate_needs_a_home_that_is_still_a_member() {
        let (s, _d) = seeded_db();
        let cid = pcid(1);
        put_channel(&s, cid, 2);
        assert!(!s.has_local_member(cid).unwrap(), "no homes at all");
        s.add_channel_member(cid, "klv1a", NOW, "member").unwrap();
        assert!(!s.has_local_member(cid).unwrap(), "member without a home is not local evidence");
        assert!(s.record_local_channel_home(cid, "klv1a", NOW).unwrap().recorded);
        assert!(s.has_local_member(cid).unwrap());
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert!(!s.has_local_member(cid).unwrap(), "home row alone is not membership");
    }

    #[test]
    fn predicate_cap_is_conservative() {
        let (s, _d) = seeded_db();
        let cid = pcid(2);
        let h = s.cf_handle(cf::LOCAL_CHANNEL_HOMES).unwrap();
        let mut b = WriteBatch::default();
        for i in 0..HAS_LOCAL_MEMBER_SCAN_CAP {
            b.put_cf(&h, schema::encode_local_channel_home_key(cid, &format!("klv1w{i}")), encode_home(NOW, NOW));
        }
        drop(h);
        s.write_batch(b).unwrap();
        assert!(s.has_local_member(cid).unwrap(), "cap hit → treated as having a local member");
    }

    #[test]
    fn record_home_requires_private_membership() {
        let (s, _d) = seeded_db();
        let cid = pcid(3);
        put_channel(&s, cid, 2);
        assert!(!s.record_local_channel_home(cid, "klv1x", NOW).unwrap().recorded, "not a member");
        // Public channel (id below the floor): never.
        put_channel(&s, 42, 0);
        s.add_channel_member(42, "klv1x", NOW, "member").unwrap();
        assert!(!s.record_local_channel_home(42, "klv1x", NOW).unwrap().recorded);
        // Private-range id whose row is typed public: never.
        let odd = pcid(4);
        put_channel(&s, odd, 0);
        s.add_channel_member(odd, "klv1x", NOW, "member").unwrap();
        assert!(!s.record_local_channel_home(odd, "klv1x", NOW).unwrap().recorded);
    }

    #[test]
    fn last_local_member_leaving_schedules_with_grace_deadline() {
        let (s, _d) = seeded_db();
        let cid = pcid(5);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        local_member(&s, cid, "klv1b");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert!(row(&s, cid).is_none(), "klv1b is still a local member");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1b").unwrap();
        let r = row(&s, cid).expect("scheduled");
        assert_eq!(r.state, LifecycleState::Pending);
        assert_eq!(r.reason, LifecycleReason::NoLocalMember);
        let d = r.deadline_ms.unwrap();
        assert!(d >= r.since_ms + DEFAULT_PURGE_GRACE_HOURS * HOUR);
        assert!(s.lifecycle_blocks_subscription(cid).unwrap());
    }

    #[test]
    fn remote_members_do_not_keep_a_channel() {
        let (s, _d) = seeded_db();
        let cid = pcid(6);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1local");
        s.add_channel_member(cid, "klv1remote", NOW, "member").unwrap();
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1local").unwrap();
        assert!(row(&s, cid).is_some(), "only a remote member is left");
    }

    #[test]
    fn channel_without_any_home_is_never_scheduled() {
        let (s, _d) = seeded_db();
        let cid = pcid(7);
        put_channel(&s, cid, 2);
        s.add_channel_member(cid, "klv1a", NOW, "member").unwrap();
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert!(row(&s, cid).is_none(), "legacy channel with no local evidence stays");
    }

    #[test]
    fn nothing_is_scheduled_before_seeding_completes() {
        let (s, _d) = db();
        assert!(!s.private_channel_homes_seeded());
        let cid = pcid(8);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert!(row(&s, cid).is_none());
    }

    #[test]
    fn public_ids_are_never_scheduled_or_blocked() {
        let (s, _d) = seeded_db();
        put_channel(&s, 9, 2); // legacy pre-floor row typed private
        s.add_channel_member(9, "klv1a", NOW, "member").unwrap();
        // Force a home row (the API would refuse one for a public id).
        s.put_cf(cf::LOCAL_CHANNEL_HOMES, &schema::encode_local_channel_home_key(9, "klv1a"), &encode_home(NOW, NOW)).unwrap();
        s.remove_channel_member_and_raise_epoch_floor(9, "klv1a").unwrap();
        assert!(row(&s, 9).is_none());
        s.tombstone_channel(9, NOW / 1000, None).unwrap();
        assert!(row(&s, 9).is_none(), "a deleted public id never gets a row");
        // Even a forged row never blocks a public id.
        s.put_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &9u64.to_be_bytes(), b"{}").unwrap();
        assert!(!s.lifecycle_blocks_subscription(9).unwrap());
    }

    #[test]
    fn pinned_channels_are_skipped() {
        let (s, _d) = seeded_db();
        let cid = pcid(10);
        assert!(s.set_private_channel_policy(PrivateChannelPolicy::new(168, [cid])));
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert!(row(&s, cid).is_none(), "pinned: never scheduled");
        s.tombstone_channel(cid, NOW / 1000, None).unwrap();
        assert!(row(&s, cid).is_none(), "pinned: not even when deleted");
        s.put_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &cid.to_be_bytes(), b"{}").unwrap();
        assert!(!s.lifecycle_blocks_subscription(cid).unwrap(), "pinned: always subscribed");
    }

    #[test]
    fn leave_then_rejoin_cancels_and_is_idempotent_under_replay() {
        let (s, _d) = seeded_db();
        let cid = pcid(11);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        let first = row(&s, cid).unwrap();
        // Replayed removal: same row, `since` not moved.
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert_eq!(row(&s, cid).unwrap(), first);
        // Re-join (e.g. a promoted held join, or a gossiped join) by a wallet
        // with a home here cancels within the same membership write.
        assert!(s.add_channel_member(cid, "klv1a", NOW + 1, "member").unwrap());
        assert!(row(&s, cid).is_none());
        // Replayed join: still no row.
        assert!(!s.add_channel_member(cid, "klv1a", NOW + 1, "member").unwrap());
        assert!(row(&s, cid).is_none());
    }

    #[test]
    fn join_by_a_wallet_without_a_home_does_not_cancel() {
        let (s, _d) = seeded_db();
        let cid = pcid(12);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        s.add_channel_member(cid, "klv1remote", NOW, "member").unwrap();
        assert!(row(&s, cid).is_some(), "a remote join is not a local member");
        // The remote wallet later uses this node: the lazy touch cancels.
        let out = s.record_local_channel_home(cid, "klv1remote", NOW + HOUR).unwrap();
        assert_eq!(out, LocalHomeOutcome { recorded: true, cancelled: true });
        assert!(row(&s, cid).is_none());
    }

    #[test]
    fn old_kick_replayed_after_federate_schedules_and_refederate_cancels() {
        let (s, _d) = seeded_db();
        let cid = pcid(13);
        put_channel(&s, cid, 2);
        // Federate: add + home.
        local_member(&s, cid, "klv1a");
        // Private sync replays an OLD kick: the member is removed (pre-
        // existing ordering residual, plan §2) → scheduled, inside grace.
        s.raise_channel_role_watermark(cid, schema::role_watermark_kind::REMOVED, "klv1a", NOW - 10).unwrap();
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        let r = row(&s, cid).unwrap();
        assert!(r.deadline_ms.unwrap() > r.since_ms, "the grace absorbs it");
        // A newer re-add (re-federate) lands and cancels.
        assert!(s.add_channel_member_unless_removed(cid, "klv1a", NOW + 5, "member").unwrap());
        assert!(row(&s, cid).is_none());
    }

    #[test]
    fn promoted_join_inside_one_replay_nets_to_no_row() {
        let (s, _d) = seeded_db();
        let cid = pcid(14);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        // Leave then the promoted held join, as `reapply_promoted_join` does.
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        s.add_channel_member_unless_removed(cid, "klv1a", NOW + 2, "member").unwrap();
        assert!(row(&s, cid).is_none());
        assert!(s.has_local_member(cid).unwrap());
    }

    #[test]
    fn deleted_private_channel_is_due_now_and_never_cancelled() {
        let (s, _d) = seeded_db();
        let cid = pcid(15);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        s.tombstone_channel(cid, NOW / 1000, Some("klv1creator")).unwrap();
        let r = row(&s, cid).unwrap();
        assert_eq!(r.reason, LifecycleReason::Deleted);
        assert_eq!(r.deadline_ms, Some(r.since_ms), "D4: deadline = now");
        assert!(!r.cancellable());
        // No membership can come back (CHANNELS row gone); a stray touch is a no-op.
        assert!(!s.record_local_channel_home(cid, "klv1a", NOW).unwrap().cancelled);
        assert!(row(&s, cid).is_some());
        // A deleted channel with local data but no home is scheduled too.
        let other = pcid(16);
        put_channel(&s, other, 2);
        s.put_cf(cf::CHANNEL_MSGS, &schema::encode_channel_msg_key(other, 5, &[7; 32]), &[]).unwrap();
        s.tombstone_channel(other, NOW / 1000, None).unwrap();
        assert_eq!(row(&s, other).unwrap().reason, LifecycleReason::Deleted);
    }

    #[test]
    fn deleted_channel_without_local_data_gets_no_row() {
        let (s, _d) = seeded_db();
        // No home, no chat, no metadata: nothing to clean up; the tombstone
        // alone keeps the id from coming back (and a flood of deletes for
        // unknown ids cannot grow the lifecycle CF).
        let bare = pcid(40);
        put_channel(&s, bare, 2);
        s.tombstone_channel(bare, NOW / 1000, None).unwrap();
        assert!(row(&s, bare).is_none());
        assert!(s.exists_cf(cf::DELETED_CHANNELS, &bare.to_be_bytes()).unwrap());
        // Metadata alone (e.g. its ChannelCreate) is local data.
        let meta = pcid(41);
        put_channel(&s, meta, 2);
        s.put_cf(cf::CHANNEL_META_MSGS, &schema::encode_channel_meta_key(meta, 0x10, 5, &[8; 32]), &[]).unwrap();
        s.tombstone_channel(meta, NOW / 1000, None).unwrap();
        assert_eq!(row(&s, meta).unwrap().reason, LifecycleReason::Deleted);
    }

    #[test]
    fn zero_grace_means_never_but_still_blocks() {
        let (s, _d) = seeded_db();
        s.set_private_channel_policy(PrivateChannelPolicy::new(0, []));
        let cid = pcid(17);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert_eq!(row(&s, cid).unwrap().deadline_ms, None);
        assert!(s.lifecycle_blocks_subscription(cid).unwrap());
        let del = pcid(18);
        put_channel(&s, del, 2);
        s.put_cf(cf::CHANNEL_MSGS, &schema::encode_channel_msg_key(del, 5, &[7; 32]), &[]).unwrap();
        s.tombstone_channel(del, NOW / 1000, None).unwrap();
        assert_eq!(row(&s, del).unwrap().deadline_ms, None);
    }

    #[test]
    fn lazy_touch_cancels_a_pending_row_and_notifies() {
        let (s, _d) = seeded_db();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        assert!(s.set_channel_lifecycle_notifier(tx));
        let cid = pcid(19);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        // A second local member without a home row yet (legacy user).
        s.add_channel_member(cid, "klv1b", NOW, "member").unwrap();
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        assert!(row(&s, cid).is_some());
        assert_eq!(rx.try_recv().ok(), Some(cid), "schedule notified");
        let out = s.record_local_channel_home(cid, "klv1b", NOW + HOUR).unwrap();
        assert!(out.cancelled);
        assert!(row(&s, cid).is_none());
        assert_eq!(rx.try_recv().ok(), Some(cid), "cancel notified");
        // Fast path: a fresh home and no row → nothing written.
        assert_eq!(s.record_local_channel_home(cid, "klv1b", NOW + HOUR + 1).unwrap(), LocalHomeOutcome::default());
    }

    #[test]
    fn seeding_covers_fed_dm_users_and_read_state() {
        let (s, _d) = db();
        let a = pcid(20);
        let b = pcid(21);
        let public = 77;
        put_channel(&s, a, 2);
        put_channel(&s, b, 2);
        put_channel(&s, public, 0);
        for (cid, w) in [(a, "klv1dm"), (a, "klv1read"), (a, "klv1none"), (b, "klv1dm"), (public, "klv1dm")] {
            s.add_channel_member(cid, w, NOW, "member").unwrap();
        }
        s.put_cf(cf::LOCAL_DM_USERS, b"klv1dm", &schema::encode_local_dm_user(NOW, NOW)).unwrap();
        s.put_cf(cf::CHANNEL_READ_STATE, &schema::encode_channel_read_key("klv1read", a), &NOW.to_be_bytes()).unwrap();
        // A federation row of a wallet that has since left (still evidence of use).
        s.put_cf(cf::LOCAL_CHANNEL_FED, &schema::encode_local_channel_fed_key("klv1fed", b), &NOW.to_be_bytes()).unwrap();
        // Budget 1 per call: resumable across "boots".
        let mut total = 0;
        let mut calls = 0;
        loop {
            let (n, done) = s.run_private_channel_homes_seeding(1, NOW).unwrap();
            total += n;
            calls += 1;
            if done {
                break;
            }
            assert!(!s.private_channel_homes_seeded());
            assert!(calls < 50);
        }
        assert!(calls > 1, "the pass resumed from its cursor");
        assert_eq!(total, 3);
        assert_eq!(s.seed_local_channel_homes_from_fed(NOW).unwrap(), 1);
        assert_eq!(s.seed_local_channel_homes_from_fed(NOW).unwrap(), 0, "idempotent");
        let home = |cid, w: &str| s.exists_cf(cf::LOCAL_CHANNEL_HOMES, &schema::encode_local_channel_home_key(cid, w)).unwrap();
        assert!(home(a, "klv1dm") && home(a, "klv1read") && home(b, "klv1dm") && home(b, "klv1fed"));
        assert!(!home(a, "klv1none"), "no local evidence");
        assert!(!home(public, "klv1dm"), "public channels get no homes");
        assert!(s.private_channel_homes_seeded());
        // Sentinel survives a reopen.
        let reopened_seeded = s.get_stat(state_keys::PRIVATE_CHANNEL_HOMES_SEEDED_V1).unwrap();
        assert_eq!(reopened_seeded, 1);
    }

    #[test]
    fn downgrade_rearms_and_returning_member_cancels_at_boot() {
        let (s, _d) = seeded_db();
        s.prepare_private_channel_lifecycle(NOW).unwrap();
        s.set_chain_cursor_with_mirror(100).unwrap();
        let cid = pcid(22);
        let back = pcid(23);
        for c in [cid, back] {
            put_channel(&s, c, 2);
            local_member(&s, c, "klv1a");
            s.remove_channel_member_and_raise_epoch_floor(c, "klv1a").unwrap();
        }
        let before = row(&s, cid).unwrap().deadline_ms.unwrap();
        // No other binary ran: nothing re-armed.
        let later = NOW + 10 * HOUR;
        let rep = s.prepare_private_channel_lifecycle(later).unwrap();
        assert!(!rep.rearmed);
        assert_eq!(row(&s, cid).unwrap().deadline_ms.unwrap(), before);
        // An older binary advanced the cursor without the stamp, and meanwhile
        // the wallet re-joined `back` (no hooks ran on that binary).
        s.put_cf(cf::NODE_STATE, state_keys::CHAIN_CURSOR, &200u64.to_be_bytes()).unwrap();
        s.put_cf(cf::CHANNEL_MEMBERS, &schema::encode_channel_member_key(back, "klv1a"), b"{}").unwrap();
        let rep = s.prepare_private_channel_lifecycle(later).unwrap();
        assert!(rep.rearmed);
        assert_eq!(rep.cancelled, 1);
        assert!(row(&s, back).is_none(), "member returned while downgraded → cancelled");
        let rearmed = row(&s, cid).unwrap().deadline_ms.unwrap();
        assert!(rearmed >= later + DEFAULT_PURGE_GRACE_HOURS * HOUR && rearmed > before);
        // The stamp caught up: the next boot does not re-arm again.
        assert!(!s.prepare_private_channel_lifecycle(later).unwrap().rearmed);
    }

    #[test]
    fn boot_never_shortens_and_follows_zero_grace() {
        let (s, _d) = seeded_db();
        let cid = pcid(24);
        put_channel(&s, cid, 2);
        let r = PrivateChannelLifecycleRow::pending(NOW, Some(NOW + 1000 * HOUR), LifecycleReason::NoLocalMember);
        s.put_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &cid.to_be_bytes(), &serde_json::to_vec(&r).unwrap()).unwrap();
        s.prepare_private_channel_lifecycle(NOW).unwrap();
        assert_eq!(row(&s, cid).unwrap().deadline_ms, Some(NOW + 1000 * HOUR), "not shortened to since+168h");
        // An unknown (newer-release) row is left untouched.
        let other = pcid(25);
        let raw = br#"{"v":2,"state":"archived","since_ms":1,"deadline_ms":1,"reason":"no_local_member","phase":3}"#;
        s.put_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &other.to_be_bytes(), raw).unwrap();
        s.prepare_private_channel_lifecycle(NOW).unwrap();
        assert_eq!(s.get_cf(cf::PRIVATE_CHANNEL_LIFECYCLE, &other.to_be_bytes()).unwrap().unwrap(), raw.to_vec());
        assert!(s.lifecycle_blocks_subscription(other).unwrap(), "an unknown row still keeps the topic off");
        let (ids, next) = s.private_channel_lifecycle_page(&[], 100).unwrap();
        assert!(ids.contains(&(cid, true)) && ids.contains(&(other, false)));
        assert_eq!(next, None, "the whole CF fit one page");
        // Paging: one row per page, the cursor walks every row exactly once.
        let (first, cur) = s.private_channel_lifecycle_page(&[], 1).unwrap();
        let (second, _) = s.private_channel_lifecycle_page(&cur.unwrap(), 1).unwrap();
        assert_eq!(first.len() + second.len(), 2);
        assert_ne!(first, second);
    }

    #[test]
    fn first_boot_floor_applies_to_deadlines() {
        let (s, _d) = seeded_db();
        s.prepare_private_channel_lifecycle(NOW + 50 * HOUR).unwrap();
        let cid = pcid(26);
        put_channel(&s, cid, 2);
        local_member(&s, cid, "klv1a");
        s.remove_channel_member_and_raise_epoch_floor(cid, "klv1a").unwrap();
        // The hook uses the wall clock; whatever it is, the deadline is never
        // below migration time + grace.
        let d = row(&s, cid).unwrap().deadline_ms.unwrap();
        assert!(d >= NOW + 50 * HOUR + DEFAULT_PURGE_GRACE_HOURS * HOUR);
    }
}
