//! RocksDB storage implementation.
//!
//! Provides the persistent storage backend using column families
//! for namespaced data (spec 3.5).

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rocksdb::{BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options, WriteBatch};

use super::schema::{cf, encode_wallet_device_key};

/// Type alias for the multi-threaded RocksDB instance.
pub type RocksDb = DBWithThreadMode<MultiThreaded>;

/// Associative merge operator for `NODE_STATE`'s `stat_*`/`TOTAL_*` counter
/// keys (audit final pre-mainnet W19b) — accumulates signed `i64` deltas
/// (`+1`/`-1`, 8-byte big-endian) without any application-level lock,
/// replacing the prior racy get-then-put on the hottest write path in the
/// node (`store_message`, called for every message ingested).
///
/// RocksDB invokes this SAME callback for both "full merge" (an existing
/// base value + operands → the value a `Get` returns) and "partial merge"
/// (operands + operands → one combined operand, used internally during
/// compaction) — the function cannot tell which case it's in from its
/// arguments. This is why the accumulation below is UNCLAMPED: a per-call
/// `saturating_sub`-at-zero (mirroring the old `decrement_stat`'s per-call
/// behavior) would not be associative — RocksDB is free to combine operands
/// in any order/grouping during compaction, and clamping mid-accumulation
/// would silently produce a different final value depending on which
/// grouping happened to run. Instead: sum unclamped as `i64` here, and clamp
/// to zero only at READ time, in `Storage::get_stat`.
///
/// Code Audit follow-up: clamping only at read means an unmatched
/// `decrement_stat` (a decrement with no corresponding earlier increment for
/// that specific entity) is no longer self-correcting the way the old
/// get-then-put was — the debt persists in storage and silently absorbs
/// future genuine increments until enough of them pay it down, rather than
/// the old behavior of clamping to 0 on that same write. The one call site
/// this was concretely reachable from (`tombstone_channel` decrementing
/// `TOTAL_CHANNELS` for a channel whose `CHANNELS` row it never actually
/// counted, e.g. a backfilled `ChannelDelete` for a channel this node never
/// locally created) is fixed at its call site (gated on
/// `Storage::exists_cf(cf::CHANNELS, ...)` before decrementing) rather than
/// here — any FUTURE decrement call site must observe the same discipline
/// (only decrement what it can show was actually counted).
///
/// Security Audit follow-up, operational note: once any key in `NODE_STATE`
/// has merge operands recorded, downgrading to a build that predates this
/// merge-operator registration will fail `Get`/compaction on that key —
/// this is effectively a one-way schema change, not just a code change.
/// Treat it as a hard-cutover deploy (same class as prior PROTOCOL_VERSION
/// bumps), not a droppable-in-place patch.
fn stat_counter_merge(
    _key: &[u8],
    existing: Option<&[u8]>,
    operands: &rocksdb::MergeOperands,
) -> Option<Vec<u8>> {
    let mut total: i64 = existing
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(i64::from_be_bytes)
        .unwrap_or(0);
    for op in operands {
        if let Ok(d) = <[u8; 8]>::try_from(op) {
            total = total.saturating_add(i64::from_be_bytes(d));
        }
    }
    Some(total.to_be_bytes().to_vec())
}

/// Outcome of a first-write-wins channel-key-envelope store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEnvelopeStore {
    /// The envelope was stored.
    Stored,
    /// A key already existed for `(key_scope, epoch, target, device)` — kept (FWW).
    AlreadyPresent,
    /// The scope already holds its maximum number of envelopes — rejected.
    ScopeFull,
}

/// A device registration claim proving a wallet authorized a device key.
///
/// The wallet signs a claim string binding the device to the wallet address.
/// Claim format: `"ogmara-device-claim:{network}:{device_pubkey_hex}:{wallet_address}:{timestamp}"`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceClaim {
    /// The device's ogd1... address (derived from device Ed25519 key).
    pub device_address: String,
    /// The wallet's klv1... address that authorized this device.
    pub wallet_address: String,
    /// Hex-encoded device public key (used in the claim string).
    pub device_pubkey_hex: String,
    /// Wallet signature over the claim string (hex-encoded).
    pub wallet_signature: String,
    /// Unix timestamp (ms) when the claim was created.
    pub registered_at: u64,
}

/// Anchor verification status for a node.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnchorStatus {
    pub verified: bool,
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_anchor_age_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchoring_since: Option<u64>,
    pub total_anchors: u64,
}

/// Self anchor status for the /network/stats endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelfAnchorStatus {
    pub is_anchorer: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_anchor_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_anchor_age_seconds: Option<u64>,
    pub total_anchors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchoring_since: Option<u64>,
}

/// Wrapper around RocksDB with typed column family access.
#[derive(Clone)]
pub struct Storage {
    db: Arc<RocksDb>,
    /// Serializes `put_pending_channel_delete`/`take_pending_channel_delete`
    /// (audit final pre-mainnet W14 Security Audit follow-up) — without
    /// this, a concurrent read-then-delete (create consuming a stale claim)
    /// racing a write (a genuine delete claim arriving for the same
    /// channel_id) could silently drop the genuine claim. `Storage` is
    /// cloned freely (both `MessageRouter` and the chain scanner hold their
    /// own clone), so this must be an `Arc` to actually serialize across
    /// them, not a per-clone lock.
    pending_channel_delete_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes `add_channel_member`/`remove_channel_member_and_raise_epoch_floor`
    /// (audit final pre-mainnet W18) — both read-modify-write the SAME
    /// `CHANNELS` row (`member_count`, and for private channels
    /// `key_epoch_floor`). One global (not per-channel) lock, same
    /// tolerance already accepted for `dm_recipient_cap_lock` (a
    /// `MessageRouter` field, `messages/router.rs`), which gates a far
    /// hotter path (every `DirectMessage`) than channel
    /// join/leave/kick/ban ever will. `Arc` for the same cross-clone reason
    /// as `pending_channel_delete_lock`.
    channel_membership_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes `put_channel_key_envelope_fww` (audit final pre-mainnet
    /// W19a) — without this, two concurrent publishers for the same
    /// `(key_scope, target, author, device, epoch)` can both pass the
    /// existence check and both `put_cf`, with the LAST write physically
    /// winning — violating the documented first-write-wins guarantee that
    /// exists specifically to stop a hostile publisher from clobbering a
    /// victim's already-published wrapped key.
    ///
    /// Security Audit follow-up, accepted tradeoff (not fixed here): the
    /// guarded body includes a bounded (`MAX_CHANNEL_KEY_ENVELOPES_PER_
    /// SCOPE` = 4096) `prefix_iter_cf` scope scan, now serialized
    /// node-wide instead of running concurrently, and `ChannelKeyEnvelope`
    /// skips per-wallet rate limiting on the sync/backfill ingest path
    /// (`is_sync`, `router.rs`) same as every other type. A peer flooding
    /// key envelopes during reconcile could contend this lock more than
    /// before. Judged acceptable given W19a's actual exploit (silent key
    /// clobber) is worse than a throughput/contention concern, and the
    /// underlying scan cost is pre-existing (not introduced by this lock) —
    /// candidate for per-`key_scope` striping if contention shows up in
    /// practice, same class of note as W10's per-IP-limiting deferral.
    channel_key_envelope_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes `follow`/`unfollow`/`toggle_news_reaction`/
    /// `toggle_chat_reaction`/`add_repost` (audit final pre-mainnet W19b) —
    /// each is an idempotency-checked (exists-then-count-then-write) RMW;
    /// grouped under one lock since all five share the identical shape and
    /// are low-frequency relative to message sends (drift-only if raced,
    /// not a security bypass — contrast `channel_key_envelope_lock` above).
    social_counters_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes `put_pending_channel_member_removal`/
    /// `take_pending_channel_member_removals` (W18 residual, found+fixed
    /// 2026-08-19) — same TOCTOU rationale as `pending_channel_delete_lock`,
    /// but a DEDICATED lock rather than reusing it or `channel_membership_lock`:
    /// `put_pending_channel_member_removal` is called from inside
    /// `remove_channel_member_and_raise_epoch_floor`'s "CHANNELS absent"
    /// branch, which already holds `channel_membership_lock` — reusing that
    /// lock here would be redundant (already exclusive) but reusing
    /// `pending_channel_delete_lock` would conflate two unrelated claim
    /// types under one lock for no reason. A dedicated lock avoids any
    /// lock-ordering question entirely: `take_pending_channel_member_removals`
    /// (called from router.rs/scanner.rs, which don't hold
    /// `channel_membership_lock`) only ever acquires this one.
    pending_channel_member_removal_lock: Arc<std::sync::Mutex<()>>,
}

impl Storage {
    /// Read the node's private key from a RocksDB database using read-only mode.
    ///
    /// This works even while the node is running (no write lock). Used by the
    /// `export-key` CLI command to back up the key without stopping the node.
    pub fn read_node_key_readonly(db_path: &Path) -> Result<Option<[u8; 32]>> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(false);

        let cf_names: Vec<String> = match DBWithThreadMode::<MultiThreaded>::list_cf(&db_opts, db_path) {
            Ok(names) => names,
            Err(_) => return Ok(None), // DB doesn't exist yet
        };

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf_names
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(name.as_str(), Options::default()))
            .collect();

        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors_read_only(
            &db_opts, db_path, cf_descriptors, false,
        ).map_err(|e| anyhow::anyhow!("opening RocksDB read-only: {}", e))?;

        let cf = db.cf_handle(cf::NODE_STATE)
            .ok_or_else(|| anyhow::anyhow!("NODE_STATE CF not found"))?;

        match db.get_cf(&cf, super::schema::state_keys::NODE_PRIVATE_KEY)
            .map_err(|e| anyhow::anyhow!("reading node key: {}", e))? {
            Some(bytes) if bytes.len() == 32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(key))
            }
            _ => Ok(None),
        }
    }

    /// Open or create the RocksDB database at the given path.
    ///
    /// Creates all column families defined in the schema if they don't exist.
    pub fn open(path: &Path) -> Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_background_jobs(4);
        db_opts.set_max_write_buffer_number(3);
        db_opts.increase_parallelism(num_cpus());

        // Create column family descriptors with default options
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf::ALL
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                // Use prefix bloom filters for index CFs
                if *name == cf::CHANNEL_MSGS || *name == cf::CHANNEL_EDIT_DELETE_MSGS {
                    // Key: (channel_id:8, lamport_ts:8, msg_id:32) — prefix by channel_id
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
                }
                if *name == cf::DM_MESSAGES
                    || *name == cf::NEWS_COMMENTS
                    || *name == cf::DM_EDIT_DELETE_MSGS
                {
                    // DM_MESSAGES key: (conversation_id:32, timestamp:8, msg_id:32)
                    // NEWS_COMMENTS key: (post_id:32, timestamp:8, msg_id:32)
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                }
                if *name == cf::DM_CONVERSATIONS {
                    // Key: (wallet_address:62, !timestamp:8, conversation_id:32)
                    // klv1 bech32 addresses with 32-byte Ed25519 keys are 62 characters
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(62));
                }
                if *name == cf::NODE_STATE {
                    // Audit final pre-mainnet W19b: lock-free counter accumulation
                    // for the `stat_*`/`TOTAL_*` keys (see `stat_counter_merge`'s
                    // doc comment). Only invoked for keys actually written via
                    // `merge_cf`; every other NODE_STATE key (chain cursor,
                    // migration sentinels, etc.) is unaffected, still a plain put/get.
                    cf_opts.set_merge_operator_associative("stat_counter_merge", stat_counter_merge);
                }
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = RocksDb::open_cf_descriptors(&db_opts, path, cf_descriptors)
            .with_context(|| format!("opening RocksDB at {}", path.display()))?;

        Ok(Self {
            db: Arc::new(db),
            pending_channel_delete_lock: Arc::new(std::sync::Mutex::new(())),
            channel_membership_lock: Arc::new(std::sync::Mutex::new(())),
            channel_key_envelope_lock: Arc::new(std::sync::Mutex::new(())),
            social_counters_lock: Arc::new(std::sync::Mutex::new(())),
            pending_channel_member_removal_lock: Arc::new(std::sync::Mutex::new(())),
        })
    }

    /// Get a value from a column family.
    pub fn get_cf(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;
        self.db
            .get_cf(&cf, key)
            .with_context(|| format!("reading from cf '{}'", cf_name))
    }

    /// Put a value into a column family.
    pub fn put_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;
        self.db
            .put_cf(&cf, key, value)
            .with_context(|| format!("writing to cf '{}'", cf_name))
    }

    /// Delete a value from a column family.
    pub fn delete_cf(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;
        self.db
            .delete_cf(&cf, key)
            .with_context(|| format!("deleting from cf '{}'", cf_name))
    }

    /// Check if a key exists in a column family (without reading the value).
    pub fn exists_cf(&self, cf_name: &str, key: &[u8]) -> Result<bool> {
        Ok(self.get_cf(cf_name, key)?.is_some())
    }

    /// Apply a RocksDB `merge` to a column family (see `stat_counter_merge` —
    /// currently only registered on `NODE_STATE`, for lock-free counter
    /// accumulation; audit final pre-mainnet W19b).
    pub fn merge_cf(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;
        self.db
            .merge_cf(&cf, key, value)
            .with_context(|| format!("merging into cf '{}'", cf_name))
    }

    /// Execute a write batch atomically across multiple column families.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        self.db
            .write(batch)
            .context("executing write batch")
    }

    /// Tombstone + remove a channel and its membership/admin state.
    ///
    /// Atomically writes a `DELETED_CHANNELS` tombstone (JSON: `deleted_at` +
    /// the member list captured just before it's wiped below) and drops the
    /// `CHANNELS` record, then best-effort clears the channel's
    /// members/moderators/bans/pins/invites. The tombstone is what the chain
    /// scanner consults to avoid resurrecting an intentionally-deleted channel
    /// on re-scan, so it MUST land even if the bulk cleanup partially fails.
    /// Idempotent: re-deleting an already-tombstoned channel is a no-op write.
    /// Shared by the REST `delete_channel` endpoint and the signed, gossiped
    /// `ChannelDelete` message handler so both paths behave identically.
    ///
    /// The captured member list lets the notification engine broadcast a live
    /// `channel_deleted` WS event to everyone who was a member — it can't
    /// derive that itself after the fact, since by the time it processes the
    /// envelope, `CHANNEL_MEMBERS` has already been emptied by this function.
    ///
    /// Code Audit follow-up (W18 adjacency): the idempotency-check-through-
    /// `CHANNELS`-delete section runs under `channel_membership_lock` — the
    /// SAME lock `add_channel_member`/`remove_channel_member_and_raise_epoch_
    /// floor` take — so a membership op whose read of the `CHANNELS` row
    /// lands before this delete can no longer write its updated row back
    /// AFTER this delete, which would otherwise silently resurrect a
    /// just-deleted channel. The guard is dropped explicitly right after
    /// that section — the bulk cleanup below (up to 5×10,000 rows) is
    /// best-effort/safe-if-partial and has no resurrection risk on its own,
    /// so it deliberately does NOT hold this node-wide lock for its
    /// duration.
    pub fn tombstone_channel(&self, channel_id: u64, deleted_at: u64) -> Result<()> {
        let channel_key = channel_id.to_be_bytes();
        let _guard = self
            .channel_membership_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Idempotency: a channel already tombstoned is a pure no-op — must NOT
        // rewrite the tombstone value. It carries the member list captured at
        // the ORIGINAL delete (CHANNEL_MEMBERS is long gone by a re-delivery, so
        // a second capture would be empty), and overwriting it here would wipe
        // that list out from under the delete-notification path. Also avoids
        // double-decrementing TOTAL_CHANNELS (e.g. the legacy REST delete + the
        // signed gossip delete, or a re-delivered ChannelDelete with a fresh
        // msg_id).
        if self.exists_cf(cf::DELETED_CHANNELS, &channel_key)? {
            return Ok(());
        }

        // Code Audit follow-up: only a channel this node actually counted
        // (i.e. had a `CHANNELS` row) should decrement `TOTAL_CHANNELS`
        // below — e.g. a `ChannelDelete` backfilled/gossiped for a channel
        // whose `ChannelCreate` this node never saw was never incremented,
        // and decrementing it anyway would drive the counter into permanent
        // negative debt (the new merge-operator counter, audit W19b,
        // accumulates deltas rather than clamping at write time the way the
        // old get-then-put did, so an unmatched decrement here no longer
        // self-corrects on the next write — it silently eats future genuine
        // increments until enough of them pay the debt down).
        let channel_existed = self.exists_cf(cf::CHANNELS, &channel_key)?;

        // Capture BEFORE the cleanup loop below wipes CHANNEL_MEMBERS. Best-effort:
        // an empty/failed capture just means the delete notification has no
        // audience, not a failed delete (the tombstone write below is what matters
        // for correctness).
        let members: Vec<String> = self
            .prefix_iter_cf(cf::CHANNEL_MEMBERS, &channel_key, 10_000)
            .map(|entries| {
                entries
                    .into_iter()
                    .filter_map(|(k, _)| {
                        if k.len() > 8 {
                            String::from_utf8(k[8..].to_vec()).ok()
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let tombstone_value = serde_json::to_vec(&serde_json::json!({
            "deleted_at": deleted_at,
            "members": members,
        }))
        .unwrap_or_else(|_| deleted_at.to_be_bytes().to_vec());

        let mut batch = WriteBatch::default();
        let tombstone_cf = self.cf_handle(cf::DELETED_CHANNELS)?;
        let channels_cf = self.cf_handle(cf::CHANNELS)?;
        batch.put_cf(&tombstone_cf, channel_key, tombstone_value);
        batch.delete_cf(&channels_cf, channel_key);
        self.write_batch(batch)
            .context("writing channel deletion batch")?;
        drop(_guard);

        // Bulk cleanup — the tombstone already prevents resurrection, so a partial
        // failure here is safe (the leftover rows are unreachable once CHANNELS is gone).
        let cleanup_cfs: &[(&str, usize)] = &[
            (cf::CHANNEL_MEMBERS, 10_000),
            (cf::CHANNEL_MODERATORS, 10_000),
            (cf::CHANNEL_BANS, 10_000),
            (cf::CHANNEL_PINS, 100),
            (cf::CHANNEL_INVITES, 10_000),
        ];
        for &(cf_name, limit) in cleanup_cfs {
            match self.prefix_iter_cf(cf_name, &channel_key, limit) {
                Ok(entries) => {
                    for (key, _) in &entries {
                        if let Err(e) = self.delete_cf(cf_name, key) {
                            tracing::warn!(channel_id, cf = cf_name, error = %e, "channel cleanup: delete failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(channel_id, cf = cf_name, error = %e, "channel cleanup: iterate failed");
                }
            }
        }

        if channel_existed {
            if let Err(e) = self.decrement_stat(crate::storage::schema::state_keys::TOTAL_CHANNELS) {
                tracing::warn!(channel_id, error = %e, "Failed to decrement TOTAL_CHANNELS");
            }
        }
        Ok(())
    }

    /// The member list `tombstone_channel` captured at delete time, for the
    /// notification engine's `channel_deleted` broadcast (CHANNEL_MEMBERS itself
    /// is already gone by the time that runs). Empty if the channel was never
    /// deleted, or predates this field (falls back to the legacy raw-`deleted_at`
    /// encoding, which has no member list).
    pub fn deleted_channel_members(&self, channel_id: u64) -> Result<Vec<String>> {
        match self.get_cf(cf::DELETED_CHANNELS, &channel_id.to_be_bytes())? {
            Some(bytes) => Ok(serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("members").cloned())
                .and_then(|m| serde_json::from_value::<Vec<String>>(m).ok())
                .unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Records a `ChannelDelete` claim for a `channel_id` this node doesn't know about
    /// yet (audit final pre-mainnet W14). Overwrites any prior claim for the same
    /// `channel_id` — a channel has exactly one eventual real creator, so only the most
    /// recent claim is ever relevant. Consumed by `take_pending_channel_delete` the
    /// first time the channel is actually created.
    ///
    /// Serialized against `take_pending_channel_delete` via
    /// `pending_channel_delete_lock` (Security Audit follow-up): without this, a
    /// concurrent take (a `ChannelCreate` consuming a stale, non-matching claim) could
    /// read-then-delete the row while a genuine new claim from THIS call was landing in
    /// between, silently dropping it.
    pub fn put_pending_channel_delete(
        &self,
        channel_id: u64,
        claimant: &str,
        requested_at: u64,
    ) -> Result<()> {
        let value = serde_json::to_vec(&serde_json::json!({
            "claimant": claimant,
            "requested_at": requested_at,
        }))
        .context("serializing pending channel delete claim")?;
        // Code Audit / Security Audit follow-up (both independently flagged
        // this): the 3 newer locks (channel_membership_lock etc, audit
        // W12/W18/W19) all use `unwrap_or_else(|p| p.into_inner())` so one
        // panic while holding a lock can't permanently poison it and brick
        // every future caller node-wide. Aligning this pre-existing lock to
        // the same idiom for consistency.
        let _guard = self
            .pending_channel_delete_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.put_cf(
            cf::PENDING_CHANNEL_DELETES,
            &channel_id.to_be_bytes(),
            &value,
        )
    }

    /// Consumes (reads and removes) the pending delete claim for `channel_id`, if any.
    /// One-shot: a claim is relevant only at the moment its channel is first created,
    /// whether or not the claimant matches the actual creator.
    ///
    /// Serialized against `put_pending_channel_delete` — see that method's doc comment.
    pub fn take_pending_channel_delete(&self, channel_id: u64) -> Result<Option<(String, u64)>> {
        let key = channel_id.to_be_bytes();
        // Code Audit / Security Audit follow-up (both independently flagged
        // this): the 3 newer locks (channel_membership_lock etc, audit
        // W12/W18/W19) all use `unwrap_or_else(|p| p.into_inner())` so one
        // panic while holding a lock can't permanently poison it and brick
        // every future caller node-wide. Aligning this pre-existing lock to
        // the same idiom for consistency.
        let _guard = self
            .pending_channel_delete_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let claim = match self.get_cf(cf::PENDING_CHANNEL_DELETES, &key)? {
            Some(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| {
                    let claimant = v.get("claimant")?.as_str()?.to_string();
                    let requested_at = v.get("requested_at")?.as_u64()?;
                    Some((claimant, requested_at))
                }),
            None => None,
        };
        if claim.is_some() {
            self.delete_cf(cf::PENDING_CHANNEL_DELETES, &key)?;
        }
        Ok(claim)
    }

    /// Max pending member-removal claims retained per channel_id — matches
    /// `reconcile::channel_meta_envelopes`'s `CHANNEL_META_CAP`. Best-effort:
    /// beyond this, new claims are silently dropped (same tolerance as every
    /// other per-scope cap in this codebase).
    const PENDING_CHANNEL_MEMBER_REMOVAL_CAP: usize = 256;

    /// Records that `address`'s removal from `channel_id` (P2d key-epoch-floor
    /// raise included) couldn't be applied because the `CHANNELS` row doesn't
    /// exist locally yet (W18 residual). Called from inside
    /// `remove_channel_member_and_raise_epoch_floor`'s "CHANNELS absent"
    /// branch — see `pending_channel_member_removal_lock`'s doc comment for
    /// why this is a dedicated lock, not a reuse of `channel_membership_lock`
    /// (already held by the caller) or `pending_channel_delete_lock`.
    ///
    /// Security Audit follow-up (WARNING-3): the stored timestamp is this
    /// node's OWN clock read at persist time, never a caller-supplied value.
    /// The envelope's `timestamp` field is attacker-controlled (any signed
    /// `ChannelLeave` sets it), and the reaper (`node.rs`'s
    /// `plan_channel_member_removal_reap`) compares this stored value against
    /// a local retention cutoff — a claim stamped with a far-future timestamp
    /// would never expire, letting an attacker defeat the reaper's cleanup
    /// entirely across many fabricated `channel_id`s. Using the local clock
    /// closes that off; it does not change the pending-claim's semantics
    /// (only the reaper's expiry math reads this value).
    fn put_pending_channel_member_removal(&self, channel_id: u64, address: &str) -> Result<()> {
        let _guard = self
            .pending_channel_member_removal_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prefix = channel_id.to_be_bytes();
        let existing = self.prefix_iter_cf(
            cf::PENDING_CHANNEL_MEMBER_REMOVALS,
            &prefix,
            Self::PENDING_CHANNEL_MEMBER_REMOVAL_CAP,
        )?;
        if existing.len() >= Self::PENDING_CHANNEL_MEMBER_REMOVAL_CAP {
            return Ok(()); // best-effort drop beyond cap
        }
        let key = super::schema::encode_channel_member_key(channel_id, address);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.put_cf(
            cf::PENDING_CHANNEL_MEMBER_REMOVALS,
            &key,
            &now_ms.to_be_bytes(),
        )
    }

    /// Consumes (reads and removes) ALL pending member-removal claims for
    /// `channel_id`. Unlike `take_pending_channel_delete` (one claim per
    /// channel_id), multiple independent rows can exist here — several
    /// different wallets can each need their removal replayed once the
    /// channel becomes known — so this returns every `(address, requested_at)`
    /// pair recorded.
    pub fn take_pending_channel_member_removals(
        &self,
        channel_id: u64,
    ) -> Result<Vec<(String, u64)>> {
        let _guard = self
            .pending_channel_member_removal_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prefix = channel_id.to_be_bytes();
        let rows = self.prefix_iter_cf(
            cf::PENDING_CHANNEL_MEMBER_REMOVALS,
            &prefix,
            Self::PENDING_CHANNEL_MEMBER_REMOVAL_CAP,
        )?;
        let mut out = Vec::with_capacity(rows.len());
        for (key, value) in &rows {
            // key: channel_id(8) ++ address — address is everything after byte 8.
            if key.len() <= 8 {
                continue;
            }
            let Ok(address) = String::from_utf8(key[8..].to_vec()) else {
                continue;
            };
            let Ok(ts_bytes) = <[u8; 8]>::try_from(value.as_slice()) else {
                continue;
            };
            out.push((address, u64::from_be_bytes(ts_bytes)));
        }
        for (key, _) in &rows {
            self.delete_cf(cf::PENDING_CHANNEL_MEMBER_REMOVALS, key)?;
        }
        Ok(out)
    }

    /// Highest channel-key epoch currently stored for a `key_scope` (0 if none).
    ///
    /// `channel_keys` rows end in an 8-byte big-endian epoch
    /// (`…device_id_hex ++ epoch_be8`, see `encode_channel_key`), so the max over a
    /// scope's prefix is the channel's current epoch. Used to set the rotation floor
    /// on member removal (`floor = max_epoch + 1`) so a removed member's keys all
    /// fall below it. Bounded scan (per-scope envelopes are capped at 4096).
    pub fn max_channel_key_epoch(&self, key_scope: &[u8; 32]) -> Result<u64> {
        let entries = self.prefix_iter_cf(cf::CHANNEL_KEYS, &key_scope[..], 8192)?;
        let mut max = 0u64;
        for (k, _) in &entries {
            if k.len() >= 8 {
                let epoch = u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap());
                if epoch > max {
                    max = epoch;
                }
            }
        }
        Ok(max)
    }

    /// Add a member to a channel, atomically updating `member_count`.
    ///
    /// Audit final pre-mainnet W18: previously this was two separate
    /// unbatched, unlocked reads/writes of the `CHANNELS` row (once by the
    /// caller to check the channel exists, once here to bump
    /// `member_count`), letting concurrent membership changes on the same
    /// channel race and drop/duplicate a `member_count` update. Now: one
    /// `channel_membership_lock`-guarded critical section, one `WriteBatch`
    /// covering the member row and the updated `CHANNELS` row. Returns
    /// `false` (no-op) if the channel doesn't exist or `address` is already
    /// a member — same idempotent contract as before.
    pub fn add_channel_member(
        &self,
        channel_id: u64,
        address: &str,
        timestamp: u64,
        role: &str,
    ) -> Result<bool> {
        let _guard = self
            .channel_membership_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let channel_key = channel_id.to_be_bytes();
        let Some(channel_data) = self.get_cf(cf::CHANNELS, &channel_key)? else {
            return Ok(false); // channel doesn't exist
        };
        let member_key = super::schema::encode_channel_member_key(channel_id, address);
        if self.exists_cf(cf::CHANNEL_MEMBERS, &member_key)? {
            return Ok(false); // already a member
        }

        let record = serde_json::json!({
            "joined_at": timestamp,
            "role": role,
        });
        let record_bytes = serde_json::to_vec(&record).context("serializing member record")?;

        let members_cf = self.cf_handle(cf::CHANNEL_MEMBERS)?;
        let channels_cf = self.cf_handle(cf::CHANNELS)?;
        let mut batch = WriteBatch::default();
        batch.put_cf(&members_cf, &member_key, &record_bytes);
        if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&channel_data) {
            // Code Audit follow-up: `meta["member_count"] = ...` (`IndexMut`)
            // PANICS if `meta` decoded as valid-but-non-object JSON (the chain
            // scanner has its own defensive check for exactly this shape —
            // `scanner.rs`'s "CHANNELS record is not a JSON object" branch —
            // so it's a real, if rare, stored state). `as_object_mut()` is a
            // safe no-op instead of a panic; `saturating_add` avoids a
            // debug-build overflow panic on the count itself.
            if let Some(obj) = meta.as_object_mut() {
                let count = obj.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0);
                obj.insert("member_count".into(), serde_json::json!(count.saturating_add(1)));
            }
            if let Ok(bytes) = serde_json::to_vec(&meta) {
                batch.put_cf(&channels_cf, channel_key, bytes);
            }
        }
        self.write_batch(batch)?;
        Ok(true)
    }

    /// Remove a member from a channel and — for private channels — raise the
    /// P2d key-epoch floor, atomically.
    ///
    /// Audit final pre-mainnet W18: previously `remove_channel_member` (member
    /// delete + `member_count` decrement) and `raise_channel_key_epoch_floor`
    /// (a THIRD independent read-modify-write of the same `CHANNELS` row) were
    /// separate, unbatched, unlocked operations. A crash between them left a
    /// removed member's old epoch keys valid forever (defeats P2d forward
    /// secrecy for that member) since the envelope that triggered the removal
    /// is already stored/deduped and never re-runs. Concurrent `CHANNELS`
    /// writers could also race the JSON RMW into member_count drift or a lost
    /// floor raise. Now: one `channel_membership_lock`-guarded critical
    /// section (the SAME lock as `add_channel_member`, since both mutate
    /// `member_count` on possibly the same channel) computes the decremented
    /// `member_count` AND (if `channel_type == 2`) the new `key_epoch_floor`
    /// together, and writes both plus the member-row delete in one
    /// `WriteBatch`.
    ///
    /// **W18 residual, found + FIXED 2026-08-19** (previously documented here
    /// as a known-open gap, flagged independently by both the Code Audit and
    /// Security Audit passes on the original W18 fix): if the `CHANNELS` row
    /// doesn't exist locally yet (e.g. a `ChannelLeave` reaching a node via
    /// gossip/reconcile before its `ChannelCreate` — `ChannelLeave` has no
    /// `authorize_channel_action` gate requiring the channel to exist,
    /// unlike Kick/Ban), the member-delete still runs (a safe no-op if the
    /// row was never present either) and the floor raise is now persisted as
    /// a pending claim (`Storage::put_pending_channel_member_removal`) rather
    /// than silently dropped — consumed (replayed through this same
    /// function) the first time the channel becomes known, mirroring
    /// `ChannelDelete`-before-`ChannelCreate`'s W14 pending-claim mechanism.
    ///
    /// No `requested_at` parameter (Security Audit WARNING-3 fix, see
    /// `put_pending_channel_member_removal`'s doc comment): the pending
    /// claim's retention timestamp is always this node's own clock, never
    /// caller-supplied, so there is nothing for a caller to pass through.
    pub fn remove_channel_member_and_raise_epoch_floor(
        &self,
        channel_id: u64,
        address: &str,
    ) -> Result<()> {
        let _guard = self
            .channel_membership_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.remove_channel_member_and_raise_epoch_floor_locked(channel_id, address)
    }

    /// Body of `remove_channel_member_and_raise_epoch_floor`, assuming
    /// `channel_membership_lock` is ALREADY held by the caller. Split out
    /// (Code Audit WARNING #2 fix) so `put_channel_and_replay_pending_member_removals`
    /// can run the create-write and the replay loop under ONE lock
    /// acquisition instead of calling back into the public, self-locking
    /// method (which would deadlock on the non-reentrant `std::sync::Mutex`).
    /// Never call this directly except from inside a block that already
    /// holds `channel_membership_lock`.
    fn remove_channel_member_and_raise_epoch_floor_locked(
        &self,
        channel_id: u64,
        address: &str,
    ) -> Result<()> {
        let channel_key = channel_id.to_be_bytes();
        let member_key = super::schema::encode_channel_member_key(channel_id, address);
        let members_cf = self.cf_handle(cf::CHANNEL_MEMBERS)?;
        let channels_cf = self.cf_handle(cf::CHANNELS)?;
        // Code Audit follow-up: check BEFORE staging the delete — the old
        // pre-W18 code decremented `member_count` unconditionally on every
        // call, including for a `Kick`/`Ban`/`Leave` whose target was never
        // actually a local member (e.g. reconciled out of order, or a
        // duplicate removal) — permanent undercount drift. Only decrement
        // when there was really a row to remove; the delete_cf below is a
        // safe no-op either way.
        let was_member = self.exists_cf(cf::CHANNEL_MEMBERS, &member_key)?;
        let mut batch = WriteBatch::default();
        batch.delete_cf(&members_cf, &member_key);

        let channel_data = self.get_cf(cf::CHANNELS, &channel_key)?;
        if channel_data.is_none() {
            // Channel not known locally yet — persist a pending claim so the
            // floor raise (and, harmlessly, a re-attempt of the member
            // removal) replays once the channel is created. Best-effort: a
            // failure here just means this one removal's floor raise stays
            // lost, same as the pre-fix behavior — never blocks the member
            // delete this function already committed to applying.
            let _ = self.put_pending_channel_member_removal(channel_id, address);
        }
        if let Some(data) = channel_data {
            if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&data) {
                // Code Audit follow-up: `as_object_mut()` guard, same
                // panic-safety rationale as `add_channel_member` above.
                if was_member {
                    if let Some(obj) = meta.as_object_mut() {
                        let count = obj.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0);
                        obj.insert("member_count".into(), serde_json::json!(count.saturating_sub(1)));
                    }
                }

                // Only private channels (channel_type == 2) rotate.
                let ctype = meta.get("channel_type").and_then(|v| v.as_u64()).unwrap_or(0);
                if ctype == 2 {
                    let scope = crate::crypto::compute_channel_scope(channel_id);
                    let max_epoch = self.max_channel_key_epoch(&scope)?;
                    let cur_floor = meta.get("key_epoch_floor").and_then(|v| v.as_u64()).unwrap_or(0);
                    let new_floor = cur_floor.max(max_epoch.saturating_add(1));
                    if new_floor != cur_floor {
                        if let Some(obj) = meta.as_object_mut() {
                            obj.insert("key_epoch_floor".into(), serde_json::json!(new_floor));
                        }
                    }
                }

                if let Ok(bytes) = serde_json::to_vec(&meta) {
                    batch.put_cf(&channels_cf, channel_key, bytes);
                }
            }
        }
        self.write_batch(batch)
    }

    /// Writes a newly-created channel's `CHANNELS` row and replays any
    /// pending member-removal claims recorded while the channel was still
    /// unknown (W18 residual), as ONE `channel_membership_lock`-guarded
    /// critical section (Code Audit WARNING #2 fix).
    ///
    /// Without this, the row write (`put_cf`) and the claim replay used to
    /// be two separate, unlocked/differently-locked steps (`scanner.rs`'s
    /// `ChannelCreated` handler and `router.rs`'s `ChannelCreate` handler
    /// each did: raw `put_cf(CHANNELS, ...)`, then later
    /// `take_pending_channel_member_removals` + replay). A concurrent
    /// `remove_channel_member_and_raise_epoch_floor` call for the SAME
    /// channel_id could interleave between them: it takes
    /// `channel_membership_lock`, sees `CHANNELS` still absent (the create's
    /// unlocked write hadn't landed yet, or hadn't been observed), and
    /// persists a brand-new pending claim — which, if that write lands after
    /// this method's own claim-consuming read, is silently orphaned (never
    /// replayed, only ever swept un-applied once the reaper's retention
    /// window expires).
    ///
    /// Holding `channel_membership_lock` across BOTH the row write and the
    /// replay closes this: any concurrent removal's own lock-guarded
    /// absent-check is now strictly ordered before or after this entire
    /// critical section. If before, its claim is already durably persisted
    /// (by the time IT releases the lock) and gets picked up by this call's
    /// replay. If after, it will observe `CHANNELS` as already present (this
    /// call already wrote it) and apply directly instead of writing a claim
    /// at all. Either way, no window remains for an orphaned claim.
    pub fn put_channel_and_replay_pending_member_removals(
        &self,
        channel_id: u64,
        channel_bytes: &[u8],
    ) -> Result<()> {
        let _guard = self
            .channel_membership_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let channel_key = channel_id.to_be_bytes();
        self.put_cf(cf::CHANNELS, &channel_key, channel_bytes)?;
        let removals = self.take_pending_channel_member_removals(channel_id)?;
        for (address, _requested_at) in removals {
            self.remove_channel_member_and_raise_epoch_floor_locked(channel_id, &address)?;
        }
        Ok(())
    }

    /// Get a column family handle for use in WriteBatch operations.
    pub fn cf_handle(&self, cf_name: &str) -> Result<Arc<BoundColumnFamily<'_>>> {
        self.db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))
    }

    /// Iterate over a column family with a key prefix.
    ///
    /// Returns key-value pairs in lexicographic order starting from the prefix.
    pub fn prefix_iter_cf(
        &self,
        cf_name: &str,
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(prefix);

        let mut results = Vec::with_capacity(limit.min(500));
        while iter.valid() && results.len() < limit {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                if !key.starts_with(prefix) {
                    break;
                }
                results.push((key.to_vec(), value.to_vec()));
            }
            iter.next();
        }

        Ok(results)
    }

    /// Count entries under a prefix without materializing their keys/values.
    ///
    /// Security audit final pre-mainnet W20: `get_comment_count`/
    /// `get_counter_vote_count` used to call `prefix_iter_cf(..., 10_000)`
    /// and take `.len()` — heap-copying every key AND value into an owned
    /// `Vec<(Vec<u8>, Vec<u8>)>` (up to 10,000 entries) just to discard the
    /// bytes and keep a count, on a hot feed-enrichment path called once per
    /// post per request. This walks the same rows via the identical
    /// `raw_iterator_cf`/`seek`/prefix-check/`next` loop as `prefix_iter_cf`
    /// but never calls `.to_vec()` on anything — same O(n) row traversal,
    /// zero allocation.
    pub fn count_prefix_cf(&self, cf_name: &str, prefix: &[u8], limit: usize) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(prefix);

        // Security-audit follow-up: unlike `prefix_iter_cf`, this only
        // reads `iter.key()`, never `iter.value()` — safe because
        // `DBRawIteratorWithThreadMode::key()`/`value()` are both gated on
        // the identical `valid()` check with no mutation between them
        // (rust-rocksdb), so a `Some` key with an unreadable value can't
        // occur outside DB corruption; the two functions walk the same
        // row set.
        let mut count = 0u64;
        while iter.valid() && (count as usize) < limit {
            match iter.key() {
                Some(key) if key.starts_with(prefix) => count += 1,
                _ => break,
            }
            iter.next();
        }

        Ok(count)
    }

    /// Iterate over a column family starting strictly after a given key.
    ///
    /// Seeks to `start_key`, skips it, then iterates forward within the prefix.
    /// Used for incremental fetching (e.g., "give me messages after this one").
    pub fn prefix_iter_cf_after(
        &self,
        cf_name: &str,
        start_key: &[u8],
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(start_key);

        // Skip the start_key itself (we want entries strictly after it)
        if iter.valid() {
            if let Some(key) = iter.key() {
                if key == start_key {
                    iter.next();
                }
            }
        }

        let mut results = Vec::with_capacity(limit.min(500));
        while iter.valid() && results.len() < limit {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                if !key.starts_with(prefix) {
                    break;
                }
                results.push((key.to_vec(), value.to_vec()));
            }
            iter.next();
        }

        Ok(results)
    }

    /// Iterate backwards over a column family starting from a key.
    ///
    /// Returns key-value pairs in reverse lexicographic order.
    pub fn reverse_iter_cf(
        &self,
        cf_name: &str,
        start_key: &[u8],
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_for_prev(start_key);

        let mut results = Vec::with_capacity(limit.min(500));
        while iter.valid() && results.len() < limit {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                if !key.starts_with(prefix) {
                    break;
                }
                results.push((key.to_vec(), value.to_vec()));
            }
            iter.prev();
        }

        Ok(results)
    }

    /// Iterate backwards over a column family starting strictly before a given key.
    ///
    /// Seeks to `start_key` (or the nearest key ≤ it), skips it if it's an exact
    /// match, then iterates backward within the prefix. Used for "load older"
    /// pagination (e.g. "give me messages before this one"), mirroring
    /// `prefix_iter_cf_after`'s forward/skip-boundary behavior in reverse.
    pub fn reverse_iter_cf_before(
        &self,
        cf_name: &str,
        start_key: &[u8],
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_for_prev(start_key);

        // Skip the start_key itself (we want entries strictly before it)
        if iter.valid() {
            if let Some(key) = iter.key() {
                if key == start_key {
                    iter.prev();
                }
            }
        }

        let mut results = Vec::with_capacity(limit.min(500));
        while iter.valid() && results.len() < limit {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                if !key.starts_with(prefix) {
                    break;
                }
                results.push((key.to_vec(), value.to_vec()));
            }
            iter.prev();
        }

        Ok(results)
    }

    /// Store a message envelope and atomically increment the message counter.
    ///
    /// Uses a WriteBatch to ensure the message and its counter update are
    /// written together, preventing counter drift on partial failure.
    ///
    /// Audit final pre-mainnet W19b: the counter update is a RocksDB `merge`
    /// (see `stat_counter_merge`), not a get-then-put — this both closes the
    /// prior TOCTOU (concurrent `store_message` calls used to race the same
    /// read-modified-write of `TOTAL_MESSAGES`, causing permanent drift under
    /// concurrency) and removes a synchronous read from the hottest write
    /// path in the node.
    pub fn store_message(
        &self,
        msg_id: &[u8; 32],
        envelope_bytes: &[u8],
    ) -> Result<()> {
        let messages_cf = self.cf_handle(cf::MESSAGES)?;
        let state_cf = self.cf_handle(cf::NODE_STATE)?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&messages_cf, msg_id, envelope_bytes);
        batch.merge_cf(
            &state_cf,
            super::schema::state_keys::TOTAL_MESSAGES,
            1i64.to_be_bytes(),
        );
        self.write_batch(batch)
    }

    /// Get a message envelope by its ID.
    pub fn get_message(&self, msg_id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        self.get_cf(cf::MESSAGES, msg_id)
    }

    /// Check if a message exists (for deduplication).
    pub fn message_exists(&self, msg_id: &[u8; 32]) -> Result<bool> {
        self.exists_cf(cf::MESSAGES, msg_id)
    }

    /// Iterate a column family starting at `seek_key`, bounded by `prefix`.
    ///
    /// Seeks to the first key >= `seek_key`, then iterates forward as long as
    /// keys start with `prefix`. This allows seeking to a specific point within
    /// a prefix range (e.g., seeking to a specific timestamp within a channel).
    pub fn iter_cf_from(
        &self,
        cf_name: &str,
        seek_key: &[u8],
        prefix: &[u8],
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;

        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(seek_key);

        let mut results = Vec::with_capacity(limit.min(500));
        while iter.valid() && results.len() < limit {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                if !key.starts_with(prefix) {
                    break;
                }
                results.push((key.to_vec(), value.to_vec()));
            }
            iter.next();
        }

        Ok(results)
    }

    /// Get the latest Lamport timestamp for a channel from the CHANNEL_MSGS index.
    ///
    /// Key format: (channel_id:8, lamport_ts:8, msg_id:32).
    /// Seeks to the end of the channel's prefix to find the newest entry.
    pub fn latest_channel_timestamp(&self, channel_id: u64) -> Result<Option<u64>> {
        let prefix = channel_id.to_be_bytes();
        // Seek to end of this channel's key space: next channel_id prefix
        let mut end_key = (channel_id + 1).to_be_bytes().to_vec();

        let entries = self.reverse_iter_cf(cf::CHANNEL_MSGS, &end_key, &prefix, 1)?;
        end_key.fill(0); // not secret, just tidy

        match entries.first() {
            Some((key, _)) if key.len() >= 16 => {
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&key[8..16]);
                Ok(Some(u64::from_be_bytes(ts_bytes)))
            }
            _ => Ok(None),
        }
    }

    /// Store the chain scanner cursor (last processed block height).
    pub fn set_chain_cursor(&self, block_height: u64) -> Result<()> {
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::CHAIN_CURSOR,
            &block_height.to_be_bytes(),
        )
    }

    /// Get the chain scanner cursor.
    pub fn get_chain_cursor(&self) -> Result<u64> {
        match self.get_cf(cf::NODE_STATE, super::schema::state_keys::CHAIN_CURSOR)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    /// Store or update the local Lamport counter.
    pub fn set_lamport_counter(&self, counter: u64) -> Result<()> {
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::LAMPORT_COUNTER,
            &counter.to_be_bytes(),
        )
    }

    /// Get the local Lamport counter.
    pub fn get_lamport_counter(&self) -> Result<u64> {
        match self.get_cf(cf::NODE_STATE, super::schema::state_keys::LAMPORT_COUNTER)? {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    // --- Social graph (follows) ---

    /// Record a follow relationship and update counts atomically via WriteBatch.
    ///
    /// Audit final pre-mainnet W19b: guarded by `social_counters_lock` — the
    /// exists-check + count reads + batched write below are otherwise a TOCTOU
    /// RMW (two concurrent `follow()` calls for the same edge could both pass
    /// the exists-check and both compute counts from the same stale read).
    pub fn follow(&self, follower: &str, followed: &str) -> Result<()> {
        let _guard = self
            .social_counters_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let follow_key = super::schema::encode_follow_key(follower, followed);

        // Check if already following (idempotent)
        if self.exists_cf(cf::FOLLOWS, &follow_key)? {
            return Ok(());
        }

        let reverse_key = super::schema::encode_follow_key(followed, follower);
        let (mut following_count, follower_count) = self.get_follower_counts(follower)?;
        following_count += 1;
        let (following_count2, mut follower_count2) = self.get_follower_counts(followed)?;
        follower_count2 += 1;

        let mut batch = WriteBatch::default();
        let follows_cf = self.cf_handle(cf::FOLLOWS)?;
        let followers_cf = self.cf_handle(cf::FOLLOWERS)?;
        let counts_cf = self.cf_handle(cf::FOLLOWER_COUNTS)?;

        batch.put_cf(&follows_cf, &follow_key, &[]);
        batch.put_cf(&followers_cf, &reverse_key, &[]);

        let mut bytes1 = Vec::with_capacity(16);
        bytes1.extend_from_slice(&following_count.to_be_bytes());
        bytes1.extend_from_slice(&follower_count.to_be_bytes());
        batch.put_cf(&counts_cf, follower.as_bytes(), &bytes1);

        let mut bytes2 = Vec::with_capacity(16);
        bytes2.extend_from_slice(&following_count2.to_be_bytes());
        bytes2.extend_from_slice(&follower_count2.to_be_bytes());
        batch.put_cf(&counts_cf, followed.as_bytes(), &bytes2);

        self.write_batch(batch)
    }

    /// Remove a follow relationship and update counts atomically via WriteBatch.
    ///
    /// Audit final pre-mainnet W19b: guarded by `social_counters_lock`, same
    /// TOCTOU rationale as `follow()` above.
    pub fn unfollow(&self, follower: &str, followed: &str) -> Result<()> {
        let _guard = self
            .social_counters_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let follow_key = super::schema::encode_follow_key(follower, followed);

        // Check if actually following (idempotent)
        if !self.exists_cf(cf::FOLLOWS, &follow_key)? {
            return Ok(());
        }

        let reverse_key = super::schema::encode_follow_key(followed, follower);
        let (mut following_count, follower_count) = self.get_follower_counts(follower)?;
        following_count = following_count.saturating_sub(1);
        let (following_count2, mut follower_count2) = self.get_follower_counts(followed)?;
        follower_count2 = follower_count2.saturating_sub(1);

        let mut batch = WriteBatch::default();
        let follows_cf = self.cf_handle(cf::FOLLOWS)?;
        let followers_cf = self.cf_handle(cf::FOLLOWERS)?;
        let counts_cf = self.cf_handle(cf::FOLLOWER_COUNTS)?;

        batch.delete_cf(&follows_cf, &follow_key);
        batch.delete_cf(&followers_cf, &reverse_key);

        let mut bytes1 = Vec::with_capacity(16);
        bytes1.extend_from_slice(&following_count.to_be_bytes());
        bytes1.extend_from_slice(&follower_count.to_be_bytes());
        batch.put_cf(&counts_cf, follower.as_bytes(), &bytes1);

        let mut bytes2 = Vec::with_capacity(16);
        bytes2.extend_from_slice(&following_count2.to_be_bytes());
        bytes2.extend_from_slice(&follower_count2.to_be_bytes());
        batch.put_cf(&counts_cf, followed.as_bytes(), &bytes2);

        self.write_batch(batch)
    }

    /// Apply a Follow (`follow=true`) or Unfollow (`follow=false`) with
    /// last-writer-wins ordering by signed `ts` (P-2). Rejects a stale/replayed
    /// edge change so a malicious backfill can't tamper a follow graph. Returns
    /// `true` if applied, `false` if it was stale (no-op). `follow`/`unfollow`
    /// are idempotent, so `FOLLOWS` stays the authoritative state and this only
    /// adds the per-edge timestamp watermark.
    pub fn apply_follow_edge(
        &self,
        follower: &str,
        followed: &str,
        follow: bool,
        ts: u64,
    ) -> Result<bool> {
        let edge_key = super::schema::encode_follow_key(follower, followed);
        let prev_ts = self
            .get_cf(cf::FOLLOW_EDGE_TS, &edge_key)?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        if ts <= prev_ts {
            return Ok(false); // stale — no-op
        }
        if follow {
            self.follow(follower, followed)?;
        } else {
            self.unfollow(follower, followed)?;
        }
        self.put_cf(cf::FOLLOW_EDGE_TS, &edge_key, &ts.to_be_bytes())?;
        Ok(true)
    }

    /// Check if follower is following followed.
    pub fn is_following(&self, follower: &str, followed: &str) -> Result<bool> {
        let key = super::schema::encode_follow_key(follower, followed);
        self.exists_cf(cf::FOLLOWS, &key)
    }

    /// Whether a `Followers`-only news post authored by `author` is visible
    /// to `caller` (audit W37: `NewsPostPayload.visibility` was decoded and
    /// stored but never checked on any read path — a "followers-only" post
    /// was actually served to everyone, including the public feed). The
    /// author always sees their own post; anyone else must be an
    /// authenticated, currently-following wallet. `None` (unauthenticated /
    /// unresolvable caller) can never see it — matches the private-channel
    /// precedent of failing closed rather than open on a missing identity.
    /// Callers check `payload.visibility == Visibility::Followers` first —
    /// `Public` posts never call this.
    pub fn news_followers_post_visible_to(&self, author: &str, caller: Option<&str>) -> bool {
        match caller {
            Some(addr) if addr == author => true,
            Some(addr) => self.is_following(addr, author).unwrap_or(false),
            None => false,
        }
    }

    /// Get follower counts for an address: (following_count, follower_count).
    pub fn get_follower_counts(&self, address: &str) -> Result<(u64, u64)> {
        match self.get_cf(cf::FOLLOWER_COUNTS, address.as_bytes())? {
            Some(bytes) if bytes.len() == 16 => {
                let following = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
                let followers = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
                Ok((following, followers))
            }
            _ => Ok((0, 0)),
        }
    }

    fn set_follower_counts(
        &self,
        address: &str,
        following: u64,
        followers: u64,
    ) -> Result<()> {
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&following.to_be_bytes());
        bytes.extend_from_slice(&followers.to_be_bytes());
        self.put_cf(cf::FOLLOWER_COUNTS, address.as_bytes(), &bytes)
    }

    /// Get list of addresses that `address` follows.
    pub fn get_following(&self, address: &str, limit: usize) -> Result<Vec<String>> {
        let mut prefix = Vec::with_capacity(address.len() + 1);
        prefix.extend_from_slice(address.as_bytes());
        prefix.push(0xFF);
        let entries = self.prefix_iter_cf(cf::FOLLOWS, &prefix, limit)?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, _)| {
                // Key: follower_bytes + 0xFF + followed_bytes
                let sep = key.iter().position(|&b| b == 0xFF)?;
                String::from_utf8(key[sep + 1..].to_vec()).ok()
            })
            .collect())
    }

    /// Get list of addresses that follow `address`.
    pub fn get_followers(&self, address: &str, limit: usize) -> Result<Vec<String>> {
        let mut prefix = Vec::with_capacity(address.len() + 1);
        prefix.extend_from_slice(address.as_bytes());
        prefix.push(0xFF);
        let entries = self.prefix_iter_cf(cf::FOLLOWERS, &prefix, limit)?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, _)| {
                let sep = key.iter().position(|&b| b == 0xFF)?;
                String::from_utf8(key[sep + 1..].to_vec()).ok()
            })
            .collect())
    }

    // --- News Reactions ---

    /// Add or remove a reaction on a news post, updating cached counts atomically.
    ///
    /// Audit final pre-mainnet W19b: guarded by `social_counters_lock` — same
    /// exists-then-count-then-write TOCTOU shape as `follow()`.
    pub fn toggle_news_reaction(
        &self,
        msg_id: &[u8; 32],
        emoji: &str,
        author: &str,
        remove: bool,
    ) -> Result<()> {
        let _guard = self
            .social_counters_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        use super::schema;
        let reaction_key = schema::encode_news_reaction_key(msg_id, emoji, author);
        let count_key = schema::encode_reaction_count_key(msg_id, emoji);

        let exists = self.exists_cf(cf::NEWS_REACTIONS, &reaction_key)?;

        let mut batch = WriteBatch::default();
        let reactions_cf = self.cf_handle(cf::NEWS_REACTIONS)?;
        let counts_cf = self.cf_handle(cf::REACTION_COUNTS)?;

        if remove {
            if !exists {
                return Ok(());
            }
            batch.delete_cf(&reactions_cf, &reaction_key);
            let count = self.get_reaction_count(msg_id, emoji)?.saturating_sub(1);
            batch.put_cf(&counts_cf, &count_key, &count.to_be_bytes());
        } else {
            if exists {
                return Ok(()); // already reacted
            }
            batch.put_cf(&reactions_cf, &reaction_key, &[]);
            let count = self.get_reaction_count(msg_id, emoji)? + 1;
            batch.put_cf(&counts_cf, &count_key, &count.to_be_bytes());
        }
        self.write_batch(batch)
    }

    /// Get the reaction count for a specific emoji on a post.
    pub fn get_reaction_count(&self, msg_id: &[u8; 32], emoji: &str) -> Result<u64> {
        let key = super::schema::encode_reaction_count_key(msg_id, emoji);
        match self.get_cf(cf::REACTION_COUNTS, &key)? {
            Some(bytes) if bytes.len() == 8 => {
                Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    /// Check if a user has reacted with a specific emoji on a post.
    pub fn has_user_reacted(
        &self,
        msg_id: &[u8; 32],
        emoji: &str,
        author: &str,
    ) -> Result<bool> {
        let key = super::schema::encode_news_reaction_key(msg_id, emoji, author);
        self.exists_cf(cf::NEWS_REACTIONS, &key)
    }

    /// Get all reactions for a news post with counts.
    pub fn get_news_reactions(
        &self,
        msg_id: &[u8; 32],
    ) -> Result<Vec<(String, u64)>> {
        let prefix = msg_id.to_vec();
        let entries = self.prefix_iter_cf(cf::REACTION_COUNTS, &prefix, 100)?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, value)| {
                if value.len() == 8 {
                    let emoji = super::schema::decode_reaction_count_emoji(&key)?;
                    let count = u64::from_be_bytes(value.try_into().ok()?);
                    if count > 0 {
                        Some((emoji, count))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect())
    }

    // --- Reposts ---

    /// Record a repost and update the count atomically.
    ///
    /// Audit final pre-mainnet W19b: guarded by `social_counters_lock` — same
    /// exists-then-count-then-write TOCTOU shape as `follow()`.
    pub fn add_repost(
        &self,
        original_id: &[u8; 32],
        reposter: &str,
        repost_msg_id: &[u8; 32],
    ) -> Result<()> {
        let _guard = self
            .social_counters_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = super::schema::encode_repost_key(original_id, reposter);
        if self.exists_cf(cf::REPOSTS, &key)? {
            return Ok(()); // idempotent
        }

        let count = self.get_repost_count(original_id)? + 1;
        let mut batch = WriteBatch::default();
        let reposts_cf = self.cf_handle(cf::REPOSTS)?;
        let counts_cf = self.cf_handle(cf::REPOST_COUNTS)?;

        batch.put_cf(&reposts_cf, &key, repost_msg_id);
        batch.put_cf(&counts_cf, original_id, &count.to_be_bytes());
        self.write_batch(batch)
    }

    /// Get repost count for a post.
    pub fn get_repost_count(&self, msg_id: &[u8; 32]) -> Result<u64> {
        match self.get_cf(cf::REPOST_COUNTS, msg_id)? {
            Some(bytes) if bytes.len() == 8 => {
                Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    // --- Bookmarks ---

    /// Save a post to the user's bookmarks.
    /// Stores both the ordered key (for listing) and a reverse index (for O(1) removal).
    pub fn add_bookmark(
        &self,
        user_address: &str,
        msg_id: &[u8; 32],
        timestamp: u64,
    ) -> Result<()> {
        let key = super::schema::encode_bookmark_key(user_address, timestamp, msg_id);
        // Store reverse index: NODE_STATE "bm:{user}:{msg_id_hex}" -> bookmark key
        let reverse_key = format!("bm:{}:{}", user_address, hex::encode(msg_id));
        let mut batch = WriteBatch::default();
        let bookmarks_cf = self.cf_handle(cf::BOOKMARKS)?;
        let state_cf = self.cf_handle(cf::NODE_STATE)?;
        batch.put_cf(&bookmarks_cf, &key, &[]);
        batch.put_cf(&state_cf, reverse_key.as_bytes(), &key);
        self.write_batch(batch)
    }

    /// Remove a post from the user's bookmarks using the reverse index (O(1)).
    pub fn remove_bookmark(
        &self,
        user_address: &str,
        msg_id: &[u8; 32],
    ) -> Result<bool> {
        let reverse_key = format!("bm:{}:{}", user_address, hex::encode(msg_id));
        match self.get_cf(cf::NODE_STATE, reverse_key.as_bytes())? {
            Some(bookmark_key) => {
                let mut batch = WriteBatch::default();
                let bookmarks_cf = self.cf_handle(cf::BOOKMARKS)?;
                let state_cf = self.cf_handle(cf::NODE_STATE)?;
                batch.delete_cf(&bookmarks_cf, &bookmark_key);
                batch.delete_cf(&state_cf, reverse_key.as_bytes());
                self.write_batch(batch)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// List the user's bookmarks (returns msg_ids).
    pub fn list_bookmarks(
        &self,
        user_address: &str,
        limit: usize,
    ) -> Result<Vec<[u8; 32]>> {
        let mut prefix = Vec::with_capacity(user_address.len() + 1);
        prefix.extend_from_slice(user_address.as_bytes());
        prefix.push(0xFF);
        let entries = self.prefix_iter_cf(cf::BOOKMARKS, &prefix, limit)?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, _)| {
                if key.len() >= prefix.len() + 8 + 32 {
                    let msg_id: [u8; 32] = key[key.len() - 32..].try_into().ok()?;
                    Some(msg_id)
                } else {
                    None
                }
            })
            .collect())
    }

    // --- Channel Administration ---

    /// Check if a user is a moderator of a channel.
    pub fn is_channel_moderator(&self, channel_id: u64, address: &str) -> Result<bool> {
        let key = super::schema::encode_channel_moderator_key(channel_id, address);
        self.exists_cf(cf::CHANNEL_MODERATORS, &key)
    }

    /// Check if a user is banned from a channel, respecting ban expiration.
    pub fn is_channel_banned(&self, channel_id: u64, address: &str) -> Result<bool> {
        let key = super::schema::encode_channel_ban_key(channel_id, address);
        match self.get_cf(cf::CHANNEL_BANS, &key)? {
            Some(data) => {
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
                    let duration = record.get("duration_secs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if duration > 0 {
                        let banned_at = record.get("banned_at")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let elapsed_secs = now_ms.saturating_sub(banned_at) / 1000;
                        if elapsed_secs >= duration {
                            // Ban expired — clean up
                            let _ = self.delete_cf(cf::CHANNEL_BANS, &key);
                            return Ok(false);
                        }
                    }
                }
                Ok(true) // permanent ban or not yet expired
            }
            None => Ok(false),
        }
    }

    /// Get pinned message count for a channel.
    pub fn get_pin_count(&self, channel_id: u64) -> Result<u32> {
        let prefix = channel_id.to_be_bytes();
        let entries = self.prefix_iter_cf(cf::CHANNEL_PINS, &prefix, 11)?;
        Ok(entries.len() as u32)
    }

    // --- State Anchoring ---

    /// Compute the current L2 state Merkle root by iterating USERS, CHANNELS,
    /// DELEGATIONS, and CHANNEL_MEMBERS column families.
    ///
    /// Returns `(state_root, message_count, channel_count, user_count)`.
    /// Should be called from `spawn_blocking` to avoid blocking the async runtime.
    pub fn compute_current_state_root(&self) -> Result<([u8; 32], u64, u32, u32)> {
        use crate::crypto::merkle::StateManager;
        use super::schema::state_keys;

        let mut state_mgr = StateManager::new();

        // Iterate USERS
        let user_cf = self.db.cf_handle(cf::USERS)
            .context("USERS cf not found")?;
        let mut user_count = 0u32;
        let mut iter = self.db.raw_iterator_cf(&user_cf);
        iter.seek_to_first();
        while iter.valid() {
            if let Some(value) = iter.value() {
                state_mgr.add_user(value);
                user_count += 1;
            }
            iter.next();
        }

        // Iterate CHANNELS
        let chan_cf = self.db.cf_handle(cf::CHANNELS)
            .context("CHANNELS cf not found")?;
        let mut channel_count = 0u32;
        let mut iter = self.db.raw_iterator_cf(&chan_cf);
        iter.seek_to_first();
        while iter.valid() {
            if let Some(value) = iter.value() {
                state_mgr.add_channel(value);
                channel_count += 1;
            }
            iter.next();
        }

        // Iterate DELEGATIONS
        let deleg_cf = self.db.cf_handle(cf::DELEGATIONS)
            .context("DELEGATIONS cf not found")?;
        let mut iter = self.db.raw_iterator_cf(&deleg_cf);
        iter.seek_to_first();
        while iter.valid() {
            if let Some(value) = iter.value() {
                state_mgr.add_delegation(value);
            }
            iter.next();
        }

        // Iterate CHANNEL_MEMBERS (v3, audit C2 — was transferred by
        // snapshot bootstrap but not covered by the anchored commitment).
        let members_cf = self.db.cf_handle(cf::CHANNEL_MEMBERS)
            .context("CHANNEL_MEMBERS cf not found")?;
        let mut iter = self.db.raw_iterator_cf(&members_cf);
        iter.seek_to_first();
        while iter.valid() {
            // CHANNEL_MEMBERS values don't redundantly encode their key
            // (channel_id + address) the way USERS/DELEGATIONS values do —
            // the key must be hashed in too (see `add_channel_member` doc).
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                state_mgr.add_channel_member(key, value);
            }
            iter.next();
        }

        let state_root = state_mgr.compute_state_root();
        let message_count = self.get_stat(state_keys::TOTAL_MESSAGES)?;

        Ok((state_root, message_count, channel_count, user_count))
    }

    // --- Snapshot Bootstrap (spec 11-snapshot-sync.md) ---

    /// Build the chunk-set for a single CF in the snapshot pipeline.
    ///
    /// Iterates the CF in key-sorted order (RocksDB's natural iteration order)
    /// and packs `(key, value)` rows into chunks of roughly `chunk_size_bytes`
    /// of uncompressed payload. Returns the per-CF manifest (chunk headers +
    /// Merkle root) and the compressed chunk bytes indexed by `seq`.
    ///
    /// `codec_id` is one of `schema::snapshot::codec::*`. The serve path uses
    /// `ZSTD` (level 3); `NONE` is available for tests where determinism
    /// trumps size.
    ///
    /// Should be called from `spawn_blocking` — full-CF iteration is unbounded.
    pub fn build_snapshot_cf(
        &self,
        cf_name: &str,
        chunk_size_bytes: u32,
        codec_id: u8,
    ) -> Result<super::snapshot::BuiltCf> {
        use super::snapshot::{
            finish_chunk, BuiltCf, ChunkHeader, MAX_BUILD_BYTES_PER_CF, MAX_BUILD_ENTRIES_PER_CF,
        };
        use crate::crypto::merkle::{compute_root, hash_kv};

        if chunk_size_bytes == 0 {
            anyhow::bail!("chunk_size_bytes must be > 0");
        }
        if codec_id != super::schema::snapshot::codec::ZSTD
            && codec_id != super::schema::snapshot::codec::NONE
        {
            anyhow::bail!("unsupported snapshot codec id: {}", codec_id);
        }

        let cf_handle = self.db.cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;
        let target_chunk_bytes = chunk_size_bytes as usize;

        let mut current_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut current_uncompressed: usize = 0;
        let mut current_leaves: Vec<[u8; 32]> = Vec::new();
        let mut chunk_headers: Vec<ChunkHeader> = Vec::new();
        let mut compressed_chunks: Vec<Vec<u8>> = Vec::new();
        let mut all_chunk_roots: Vec<[u8; 32]> = Vec::new();
        let mut total_entries: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut seq: u32 = 0;

        // RocksDB iterators take an implicit DB snapshot at creation, so
        // concurrent scanner writes don't produce inconsistent chunks here.
        let mut iter = self.db.raw_iterator_cf(&cf_handle);
        iter.seek_to_first();
        while iter.valid() {
            if let (Some(key), Some(value)) = (iter.key(), iter.value()) {
                let row_size = key.len() + value.len();
                total_entries = total_entries.saturating_add(1);
                total_bytes = total_bytes.saturating_add(row_size as u64);

                // Abort the build before allocating if an adversarial CF is
                // larger than we'll ever serve. The previous cache stays in
                // place so serving doesn't go dark on an attack.
                if total_entries > MAX_BUILD_ENTRIES_PER_CF {
                    anyhow::bail!(
                        "cf '{}' exceeds MAX_BUILD_ENTRIES_PER_CF ({}); aborting build",
                        cf_name, MAX_BUILD_ENTRIES_PER_CF
                    );
                }
                if total_bytes > MAX_BUILD_BYTES_PER_CF {
                    anyhow::bail!(
                        "cf '{}' exceeds MAX_BUILD_BYTES_PER_CF ({} bytes); aborting build",
                        cf_name, MAX_BUILD_BYTES_PER_CF
                    );
                }

                current_leaves.push(hash_kv(key, value));
                current_entries.push((key.to_vec(), value.to_vec()));
                current_uncompressed = current_uncompressed.saturating_add(row_size);

                if current_uncompressed >= target_chunk_bytes {
                    finish_chunk(
                        cf_name,
                        seq,
                        codec_id,
                        &mut current_entries,
                        &mut current_leaves,
                        &mut chunk_headers,
                        &mut compressed_chunks,
                        &mut all_chunk_roots,
                    )?;
                    current_uncompressed = 0;
                    seq = seq.checked_add(1).ok_or_else(|| {
                        anyhow::anyhow!("cf '{}' produced more than u32::MAX chunks", cf_name)
                    })?;
                }
            }
            iter.next();
        }
        // Surface RocksDB iteration errors (corruption, I/O) rather than
        // letting a truncated scan silently produce a wrong Merkle root.
        iter.status()
            .with_context(|| format!("rocksdb iteration error on cf '{}'", cf_name))?;

        if !current_entries.is_empty() {
            finish_chunk(
                cf_name,
                seq,
                codec_id,
                &mut current_entries,
                &mut current_leaves,
                &mut chunk_headers,
                &mut compressed_chunks,
                &mut all_chunk_roots,
            )?;
        }

        let cf_root = compute_root(&all_chunk_roots);

        Ok(BuiltCf {
            cf_name: cf_name.to_string(),
            num_entries: total_entries,
            total_bytes,
            chunk_size_bytes,
            chunks: chunk_headers,
            cf_root,
            compressed_chunks,
        })
    }

    /// Clear every row from a column family.
    ///
    /// Uses RocksDB's native `delete_range_cf` over `[0x00; 0..]..[0xff; 256]`
    /// for an O(1) range tombstone — far cheaper than iterating and deleting
    /// row-by-row on a multi-million-row CF.
    ///
    /// Should be called from `spawn_blocking`; the range delete walks file
    /// metadata and can block briefly on large CFs.
    pub fn clear_cf(&self, cf_name: &str) -> Result<()> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;
        // `delete_range_cf` is [start, end) — we pass empty start and a
        // large-enough end to cover any practical key. Snapshot CFs use
        // key lengths well under 256 bytes; this end key is comfortably
        // beyond any real entry.
        let end_key: Vec<u8> = vec![0xffu8; 256];
        self.db
            .delete_range_cf(&cf, b"".as_ref(), end_key.as_slice())
            .with_context(|| format!("delete_range on cf '{}'", cf_name))?;
        // Walk once and clean up any keys >= the end_key sentinel — rare
        // but possible if a row's key happens to be all-0xff for 256 bytes.
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(&end_key);
        let mut tail = Vec::new();
        while iter.valid() {
            if let Some(k) = iter.key() {
                tail.push(k.to_vec());
            }
            iter.next();
        }
        iter.status()
            .with_context(|| format!("rocksdb iter status after clear on '{}'", cf_name))?;
        for k in tail {
            self.db
                .delete_cf(&cf, &k)
                .with_context(|| format!("deleting tail key in '{}'", cf_name))?;
        }
        Ok(())
    }

    /// Apply a snapshot `ChunkPayload` to the given column family.
    ///
    /// Writes every `(key, value)` row in a single RocksDB `WriteBatch`
    /// for atomicity. Should be called AFTER `clear_cf` for the same CF
    /// and BEFORE writing the `SNAPSHOT_APPLIED_AT_HEIGHT` sentinel.
    ///
    /// **Pre-condition:** the caller has already verified the chunk's hash
    /// against the manifest's `chunk_hash` and decoded it via
    /// `storage::snapshot::decode_chunk`. This method does not re-verify.
    pub fn apply_snapshot_chunk(
        &self,
        cf_name: &str,
        chunk: &super::snapshot::ChunkPayload,
    ) -> Result<()> {
        if chunk.cf_name != cf_name {
            anyhow::bail!(
                "snapshot chunk cf_name mismatch: payload says '{}', expected '{}'",
                chunk.cf_name,
                cf_name
            );
        }
        let cf = self
            .db
            .cf_handle(cf_name)
            .with_context(|| format!("column family '{}' not found", cf_name))?;
        let mut batch = WriteBatch::default();
        for (k, v) in &chunk.entries {
            batch.put_cf(&cf, k, v);
        }
        self.write_batch(batch)
            .with_context(|| format!("applying snapshot chunk to '{}'", cf_name))
    }

    /// Create a RocksDB Checkpoint at `path` for rollback safety.
    ///
    /// Checkpoint uses hard links where possible — cheap on the same
    /// filesystem (a few hundred milliseconds even for multi-GB DBs).
    /// Returned path is the directory containing the checkpoint SSTs.
    ///
    /// **Caller invariant:** `path` must not already exist and its parent
    /// directory must be writable. The caller is responsible for cleaning
    /// up the checkpoint after the apply succeeds AND the chain scanner
    /// has advanced past the cutoff height.
    pub fn create_checkpoint(&self, path: &Path) -> Result<()> {
        if path.exists() {
            anyhow::bail!("checkpoint path already exists: {}", path.display());
        }
        let cp = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .context("creating rocksdb Checkpoint handle")?;
        cp.create_checkpoint(path)
            .with_context(|| format!("writing checkpoint to {}", path.display()))?;
        Ok(())
    }

    /// Compute the snapshot Merkle root from per-CF roots in canonical order.
    ///
    /// `cf_roots` must be in the same order as
    /// `super::schema::snapshot::DOMAIN_CFS`. The output is the value peers
    /// compare during quorum agreement (spec 11-snapshot-sync.md §3.3).
    pub fn compute_snapshot_root(
        block_height: u64,
        cf_roots: &[[u8; 32]],
        total_users: u64,
        total_channels: u64,
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(super::schema::snapshot::SNAPSHOT_ROOT_DOMAIN);
        hasher.update(block_height.to_be_bytes());
        for root in cf_roots {
            hasher.update(root);
        }
        hasher.update(total_users.to_be_bytes());
        hasher.update(total_channels.to_be_bytes());
        hasher.finalize().into()
    }

    // --- Network Stats Counters ---

    /// Read a u64 stat counter (or any other 8-byte big-endian NODE_STATE
    /// value) — clamped at zero.
    ///
    /// Audit final pre-mainnet W19b: the 5 `TOTAL_*` counter keys are now
    /// written via RocksDB `merge` (signed `i64` deltas, see
    /// `stat_counter_merge`), and `Get` transparently folds any pending
    /// merge operands — no other caller needs to change. Every OTHER
    /// NODE_STATE value this function reads (migration sentinels,
    /// `CHAIN_CURSOR`, `LAST_ANCHOR_TS`, etc.) is still written via a plain
    /// `put_cf` and is small/non-negative, so reinterpreting the stored
    /// bytes as `i64` instead of `u64` is a no-op for them (identical bit
    /// pattern, nowhere near `i64::MAX`).
    pub fn get_stat(&self, key: &[u8]) -> Result<u64> {
        match self.get_cf(cf::NODE_STATE, key)? {
            Some(bytes) if bytes.len() == 8 => {
                let signed = i64::from_be_bytes(bytes.try_into().unwrap());
                Ok(signed.max(0) as u64)
            }
            _ => Ok(0),
        }
    }

    /// Increment a u64 stat counter in NODE_STATE by 1.
    ///
    /// Audit final pre-mainnet W19b: was a plain get-then-put (racy TOCTOU
    /// under concurrent callers — permanent drift). Now a RocksDB `merge`,
    /// which RocksDB itself makes safe under arbitrary concurrency without
    /// an application-level lock — this is called on every message store,
    /// the hottest path in the node, where a coarse `Mutex` (the fix used
    /// for every other RMW in this batch) would be a real throughput cost.
    pub fn increment_stat(&self, key: &[u8]) -> Result<()> {
        self.merge_cf(cf::NODE_STATE, key, &1i64.to_be_bytes())
    }

    /// Decrement a u64 stat counter, saturating at zero.
    ///
    /// Note: the "saturating at zero" guarantee is now over the AGGREGATE
    /// net total (across however many concurrent increments/decrements land
    /// before the next read), not per individual call — a behavior change
    /// only observable under the exact concurrent bursts that already
    /// produced nondeterministic results under the old racy code, so this is
    /// a strict improvement, not a regression.
    pub fn decrement_stat(&self, key: &[u8]) -> Result<()> {
        self.merge_cf(cf::NODE_STATE, key, &(-1i64).to_be_bytes())
    }

    // --- DM Recipient Message Counter (audit final pre-mainnet W11) ---
    //
    // Dedicated pair rather than a generalized `increment_stat`/`decrement_stat`
    // over an arbitrary CF: those two are hardcoded to `cf::NODE_STATE` and have
    // exactly one call site here, so a small dedicated pair is simpler than
    // widening a shared helper's signature for a single new caller.

    /// Read the number of `DM_MESSAGES` rows currently attributed to `recipient`
    /// (`DM_RECIPIENT_MSG_COUNTS`). Missing/malformed entries read as 0.
    pub fn get_dm_recipient_count(&self, recipient: &[u8]) -> Result<u64> {
        match self.get_cf(cf::DM_RECIPIENT_MSG_COUNTS, recipient)? {
            Some(bytes) if bytes.len() == 8 => {
                Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    /// Increment `recipient`'s stored-DM count by 1. Called once per stored
    /// `DirectMessage`, from `MessageRouter::update_indexes`.
    pub fn increment_dm_recipient_count(&self, recipient: &[u8]) -> Result<u64> {
        let new_val = self.get_dm_recipient_count(recipient)? + 1;
        self.put_cf(cf::DM_RECIPIENT_MSG_COUNTS, recipient, &new_val.to_be_bytes())?;
        Ok(new_val)
    }

    /// Decrement `recipient`'s stored-DM count by 1, saturating at zero.
    /// Called once per reaped `DM_MESSAGES` row, from the DM retention reaper.
    pub fn decrement_dm_recipient_count(&self, recipient: &[u8]) -> Result<u64> {
        let new_val = self.get_dm_recipient_count(recipient)?.saturating_sub(1);
        self.put_cf(cf::DM_RECIPIENT_MSG_COUNTS, recipient, &new_val.to_be_bytes())?;
        Ok(new_val)
    }

    /// Estimate total database size in bytes from RocksDB properties.
    ///
    /// Uses `rocksdb.estimate-live-data-size` across all column families.
    /// This is an approximation — actual disk usage may differ due to
    /// compaction, WAL, and SST overhead.
    pub fn estimate_db_size(&self) -> Result<u64> {
        let mut total: u64 = 0;
        for cf_name in cf::ALL {
            if let Some(cf_handle) = self.db.cf_handle(cf_name) {
                if let Ok(Some(size_str)) =
                    self.db.property_value_cf(&cf_handle, "rocksdb.estimate-live-data-size")
                {
                    if let Ok(size) = size_str.parse::<u64>() {
                        total += size;
                    }
                }
            }
        }
        Ok(total)
    }

    /// Get estimated key count and data size per column family.
    ///
    /// Used by the dashboard storage breakdown endpoint.
    pub fn cf_stats(&self) -> Vec<(String, u64, u64)> {
        let mut stats = Vec::new();
        for cf_name in cf::ALL {
            if let Some(cf_handle) = self.db.cf_handle(cf_name) {
                let keys = self
                    .db
                    .property_value_cf(&cf_handle, "rocksdb.estimate-num-keys")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let size = self
                    .db
                    .property_value_cf(&cf_handle, "rocksdb.estimate-live-data-size")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                if keys > 0 || size > 0 {
                    stats.push((cf_name.to_string(), keys, size));
                }
            }
        }
        stats
    }

    /// Rebuild stat counters by scanning existing data.
    /// Called once on startup when counters are zero but data exists.
    pub fn rebuild_stat_counters(&self) -> Result<()> {
        use tracing::info;

        // Count messages
        let msg_cf = self.db.cf_handle(cf::MESSAGES)
            .context("MESSAGES cf not found")?;
        let mut msg_count = 0u64;
        let mut iter = self.db.raw_iterator_cf(&msg_cf);
        iter.seek_to_first();
        while iter.valid() {
            msg_count += 1;
            iter.next();
        }
        if msg_count > 0 {
            self.put_cf(
                cf::NODE_STATE,
                super::schema::state_keys::TOTAL_MESSAGES,
                &msg_count.to_be_bytes(),
            )?;
        }

        // Count news messages (from NEWS_FEED index)
        let news_cf = self.db.cf_handle(cf::NEWS_FEED)
            .context("NEWS_FEED cf not found")?;
        let mut news_count = 0u64;
        let mut iter = self.db.raw_iterator_cf(&news_cf);
        iter.seek_to_first();
        while iter.valid() {
            news_count += 1;
            iter.next();
        }
        if news_count > 0 {
            self.put_cf(
                cf::NODE_STATE,
                super::schema::state_keys::TOTAL_NEWS_MESSAGES,
                &news_count.to_be_bytes(),
            )?;
        }

        // Count channel messages (from CHANNEL_MSGS index)
        let ch_msg_cf = self.db.cf_handle(cf::CHANNEL_MSGS)
            .context("CHANNEL_MSGS cf not found")?;
        let mut ch_msg_count = 0u64;
        let mut iter = self.db.raw_iterator_cf(&ch_msg_cf);
        iter.seek_to_first();
        while iter.valid() {
            ch_msg_count += 1;
            iter.next();
        }
        if ch_msg_count > 0 {
            self.put_cf(
                cf::NODE_STATE,
                super::schema::state_keys::TOTAL_CHANNEL_MESSAGES,
                &ch_msg_count.to_be_bytes(),
            )?;
        }

        // Count users
        let user_cf = self.db.cf_handle(cf::USERS)
            .context("USERS cf not found")?;
        let mut user_count = 0u64;
        let mut iter = self.db.raw_iterator_cf(&user_cf);
        iter.seek_to_first();
        while iter.valid() {
            user_count += 1;
            iter.next();
        }
        if user_count > 0 {
            self.put_cf(
                cf::NODE_STATE,
                super::schema::state_keys::TOTAL_USERS,
                &user_count.to_be_bytes(),
            )?;
        }

        // Count channels
        let ch_cf = self.db.cf_handle(cf::CHANNELS)
            .context("CHANNELS cf not found")?;
        let mut ch_count = 0u64;
        let mut iter = self.db.raw_iterator_cf(&ch_cf);
        iter.seek_to_first();
        while iter.valid() {
            ch_count += 1;
            iter.next();
        }
        if ch_count > 0 {
            self.put_cf(
                cf::NODE_STATE,
                super::schema::state_keys::TOTAL_CHANNELS,
                &ch_count.to_be_bytes(),
            )?;
        }

        info!(
            messages = msg_count,
            news_messages = news_count,
            channel_messages = ch_msg_count,
            users = user_count,
            channels = ch_count,
            "Stat counters rebuilt from existing data"
        );

        // Write sentinel so we don't rebuild on every startup
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::COUNTERS_V2,
            &1u64.to_be_bytes(),
        )?;

        Ok(())
    }

    /// Normalize channel_type from string enum names to u8 integers.
    /// Runs once on startup; idempotent.
    pub fn normalize_channel_types(&self) -> Result<()> {
        use tracing::info;

        let type_map: &[(&str, u8)] = &[
            ("Public", 0),
            ("ReadPublic", 1),
            ("Private", 2),
        ];

        let entries = self.prefix_iter_cf(cf::CHANNELS, &[], 10_000)?;
        let mut fixed = 0u32;

        for (key, value) in &entries {
            if let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(value) {
                if let Some(serde_json::Value::String(s)) = meta.get("channel_type") {
                    if let Some(&(_, num)) = type_map.iter().find(|&&(name, _)| name == s) {
                        meta["channel_type"] = serde_json::json!(num);
                        if let Ok(bytes) = serde_json::to_vec(&meta) {
                            self.put_cf(cf::CHANNELS, key, &bytes)?;
                            fixed += 1;
                        }
                    }
                }
            }
        }

        if fixed > 0 {
            info!(fixed, "Normalized channel_type values from string to u8");
        }

        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::CHANNEL_TYPE_NORMALIZED,
            &1u64.to_be_bytes(),
        )?;

        Ok(())
    }

    /// Backfill USERS_BY_NAME from existing USERS records.
    ///
    /// The USERS_BY_NAME column family is the prefix index for the
    /// `@`-mention autocomplete endpoint (`GET /api/v1/users/search`). It's
    /// maintained in lockstep on every ProfileUpdate, but pre-existing
    /// users (registered before v0.32.0) need a one-time backfill.
    ///
    /// Idempotent — protected by the USERS_BY_NAME_BACKFILLED sentinel
    /// in NODE_STATE.
    pub fn backfill_users_by_name(&self) -> Result<()> {
        use tracing::info;

        let entries = self.prefix_iter_cf(cf::USERS, &[], 100_000)?;
        let mut written = 0u32;

        for (key, value) in &entries {
            let record: serde_json::Value = match serde_json::from_slice(value) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let display_name = match record.get("display_name").and_then(|v| v.as_str()) {
                Some(n) if !n.trim().is_empty() => n,
                _ => continue, // skip users with no display name
            };
            let address = match std::str::from_utf8(key) {
                Ok(s) if s.starts_with("klv1") => s,
                _ => continue,
            };
            let index_key = super::schema::encode_users_by_name_key(
                &display_name.to_lowercase(),
                address,
            );
            self.put_cf(cf::USERS_BY_NAME, &index_key, &[])?;
            written += 1;
        }

        if written > 0 {
            info!(written, "Backfilled USERS_BY_NAME from existing USERS records");
        }

        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::USERS_BY_NAME_BACKFILLED,
            &1u64.to_be_bytes(),
        )?;

        Ok(())
    }

    /// Backfill DEVICE_WALLET_MAP from existing DELEGATIONS entries.
    /// The chain scanner stored delegations but missed writing the identity map.
    /// Runs once on startup; idempotent.
    pub fn backfill_delegation_map(&self) -> Result<()> {
        use tracing::info;

        let entries = self.prefix_iter_cf(cf::DELEGATIONS, &[], 10_000)?;
        let mut created = 0u32;

        for (_key, value) in &entries {
            let record: serde_json::Value = match serde_json::from_slice(value) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let user = match record.get("user_address").and_then(|v| v.as_str()) {
                Some(u) => u,
                None => continue,
            };
            let device_pub_hex = match record.get("device_pub_key").and_then(|v| v.as_str()) {
                Some(d) => d,
                None => continue,
            };
            let active = record.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
            if !active { continue; }

            // Convert hex pubkey → klv1 address
            let pubkey_bytes = match hex::decode(device_pub_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            let vk = match ed25519_dalek::VerifyingKey::from_bytes(
                &<[u8; 32]>::try_from(pubkey_bytes.as_slice()).unwrap(),
            ) {
                Ok(vk) => vk,
                Err(_) => continue,
            };
            let device_address = match crate::crypto::device_pubkey_to_address(&vk) {
                Ok(a) => a,
                Err(_) => continue,
            };

            // Skip if already mapped
            if self.exists_cf(cf::DEVICE_WALLET_MAP, device_address.as_bytes())? {
                continue;
            }

            // Write forward map: device_address → wallet_address
            self.put_cf(cf::DEVICE_WALLET_MAP, device_address.as_bytes(), user.as_bytes())?;

            // Write reverse map: (wallet, 0xFF, device) → claim
            let wd_key = super::schema::encode_wallet_device_key(user, &device_address);
            let claim = serde_json::json!({
                "device_address": device_address,
                "wallet_address": user,
                "created_at": record.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
            });
            if let Ok(claim_bytes) = serde_json::to_vec(&claim) {
                self.put_cf(cf::WALLET_DEVICES, &wd_key, &claim_bytes)?;
            }

            created += 1;
        }

        if created > 0 {
            info!(created, "Backfilled DEVICE_WALLET_MAP from DELEGATIONS");
        }

        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::DELEGATION_MAP_BACKFILLED,
            &1u64.to_be_bytes(),
        )?;

        Ok(())
    }

    /// One-time backfill of `IDENTITY_ENVELOPES` from existing `MESSAGES`
    /// (P-1 identity-sync, l2-node 0.50.0+). STREAMS every stored envelope
    /// (raw iterator — no full materialization) and indexes the five identity
    /// types under their resolved wallet, so a node upgraded with history can
    /// serve pre-existing delegations/profiles/follows. Idempotent — guarded by
    /// the `IDENTITY_ENVELOPES_INDEXED` sentinel. MUST run AFTER
    /// `backfill_delegation_map` so device→wallet resolution is populated.
    pub fn backfill_identity_envelopes(&self) -> Result<()> {
        use crate::messages::envelope::Envelope;
        use crate::messages::types::MessageType;
        use tracing::info;

        let cf = self
            .db
            .cf_handle(cf::MESSAGES)
            .with_context(|| "column family 'messages' not found")?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();

        let mut indexed = 0u64;
        while iter.valid() {
            if let Some(raw) = iter.value() {
                if let Ok(envelope) = rmp_serde::from_slice::<Envelope>(raw) {
                    let is_identity = matches!(
                        envelope.msg_type,
                        MessageType::ProfileUpdate
                            | MessageType::DeviceDelegation
                            | MessageType::DeviceRevocation
                            | MessageType::Follow
                            | MessageType::Unfollow
                    );
                    if is_identity {
                        // Index under the resolved wallet (device-authored
                        // profile/follow envelopes resolve via DEVICE_WALLET_MAP;
                        // DeviceDelegation is already wallet-authored). Falls
                        // back to the raw author if unmapped.
                        let wallet = match self.resolve_wallet(&envelope.author) {
                            Ok(Some(w)) => w,
                            _ => envelope.author.clone(),
                        };
                        let key = super::schema::encode_identity_envelope_key(
                            &wallet,
                            envelope.msg_type_u8(),
                            envelope.timestamp,
                            &envelope.msg_id,
                        );
                        self.put_cf(cf::IDENTITY_ENVELOPES, &key, &[])?;
                        indexed += 1;
                    }
                }
            }
            iter.next();
        }

        if indexed > 0 {
            info!(indexed, "Backfilled IDENTITY_ENVELOPES from MESSAGES");
        }
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::IDENTITY_ENVELOPES_INDEXED,
            &1u64.to_be_bytes(),
        )?;
        Ok(())
    }

    /// One-time backfill of `CHANNEL_META_MSGS` from existing `MESSAGES`
    /// (P-3b channel-metadata). Streams every envelope and indexes channel
    /// metadata/membership types (ChannelCreate/Update/Join/Leave) by
    /// channel_id, so the channel-history reconcile can serve a channel's L2
    /// metadata. Idempotent — guarded by `CHANNEL_META_INDEXED`.
    pub fn backfill_channel_meta(&self) -> Result<()> {
        use crate::messages::envelope::Envelope;
        use crate::messages::types::MessageType;
        use tracing::info;

        let cf = self
            .db
            .cf_handle(cf::MESSAGES)
            .with_context(|| "column family 'messages' not found")?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();

        let mut indexed = 0u64;
        while iter.valid() {
            if let Some(raw) = iter.value() {
                if let Ok(envelope) = rmp_serde::from_slice::<Envelope>(raw) {
                    if matches!(
                        envelope.msg_type,
                        MessageType::ChannelCreate
                            | MessageType::ChannelUpdate
                            | MessageType::ChannelJoin
                            | MessageType::ChannelLeave
                    ) {
                        if let Ok(p) =
                            rmp_serde::from_slice::<serde_json::Value>(&envelope.payload)
                        {
                            if let Some(cid) =
                                p.get("channel_id").and_then(|v| v.as_u64())
                            {
                                let key = super::schema::encode_channel_meta_key(
                                    cid,
                                    envelope.msg_type_u8(),
                                    envelope.timestamp,
                                    &envelope.msg_id,
                                );
                                self.put_cf(cf::CHANNEL_META_MSGS, &key, &[])?;
                                indexed += 1;
                            }
                        }
                    }
                }
            }
            iter.next();
        }

        if indexed > 0 {
            info!(indexed, "Backfilled CHANNEL_META_MSGS from MESSAGES");
        }
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::CHANNEL_META_INDEXED,
            &1u64.to_be_bytes(),
        )?;
        Ok(())
    }

    /// One-time backfill of `CHANNEL_EDIT_DELETE_MSGS`/`DM_EDIT_DELETE_MSGS`/
    /// `NEWS_EDIT_DELETE` from existing `MESSAGES` (audit final pre-mainnet W6:
    /// backfill previously omitted edit/delete markers, so "deleted for
    /// everyone" content was re-served forever by any fresh/cold-joining
    /// node). Streams every envelope and indexes `ChatEdit`/`ChatDelete`/
    /// `DirectMessageEdit`/`DirectMessageDelete`/`NewsEdit`/`NewsDelete` into
    /// their side-index CF. Without this migration, only edits/deletes made
    /// AFTER the upgrade would ever backfill correctly — this makes the fix
    /// retroactive. Idempotent — guarded by `EDIT_DELETE_MARKERS_INDEXED`.
    pub fn backfill_edit_delete_markers(&self) -> Result<()> {
        use crate::messages::envelope::Envelope;
        use crate::messages::types::{
            ChatMessagePayload, DeletePayload, DirectMessagePayload, EditPayload, MessageType,
        };
        use tracing::info;

        let cf = self
            .db
            .cf_handle(cf::MESSAGES)
            .with_context(|| "column family 'messages' not found")?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();

        let mut indexed = 0u64;
        while iter.valid() {
            if let Some(raw) = iter.value() {
                if let Ok(envelope) = rmp_serde::from_slice::<Envelope>(raw) {
                    match envelope.msg_type {
                        MessageType::ChatEdit | MessageType::ChatDelete => {
                            // Security-audit follow-up on W6 (2026-08-18):
                            // derive channel_id from the ORIGINAL message,
                            // never from `EditPayload`/`DeletePayload::
                            // channel_id` — that field is author-controlled
                            // and unvalidated, so trusting it (as the first
                            // version of this migration did) would let a
                            // spoofed/omitted value index nowhere or pollute
                            // an unrelated channel. Mirrors the DM branch
                            // below, which already did this correctly.
                            let target_id = if envelope.msg_type == MessageType::ChatEdit {
                                rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                                    .ok()
                                    .map(|p| p.target_id)
                            } else {
                                rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                                    .ok()
                                    .map(|p| p.target_id)
                            };
                            let channel_id = target_id.and_then(|target_id| {
                                self.get_cf(cf::MESSAGES, &target_id)
                                    .ok()
                                    .flatten()
                                    .and_then(|orig_raw| {
                                        rmp_serde::from_slice::<Envelope>(&orig_raw).ok()
                                    })
                                    .and_then(|orig_env| {
                                        rmp_serde::from_slice::<ChatMessagePayload>(
                                            &orig_env.payload,
                                        )
                                        .ok()
                                    })
                                    .map(|p| p.channel_id)
                            });
                            if let Some(cid) = channel_id {
                                let key = super::schema::encode_channel_msg_key(
                                    cid,
                                    envelope.timestamp,
                                    &envelope.msg_id,
                                );
                                self.put_cf(cf::CHANNEL_EDIT_DELETE_MSGS, &key, &[])?;
                                indexed += 1;
                            }
                        }
                        MessageType::DirectMessageEdit | MessageType::DirectMessageDelete => {
                            let target_id = if envelope.msg_type == MessageType::DirectMessageEdit
                            {
                                rmp_serde::from_slice::<EditPayload>(&envelope.payload)
                                    .ok()
                                    .map(|p| p.target_id)
                            } else {
                                rmp_serde::from_slice::<DeletePayload>(&envelope.payload)
                                    .ok()
                                    .map(|p| p.target_id)
                            };
                            let conv_id = target_id.and_then(|target_id| {
                                self.get_cf(cf::MESSAGES, &target_id)
                                    .ok()
                                    .flatten()
                                    .and_then(|orig_raw| {
                                        rmp_serde::from_slice::<Envelope>(&orig_raw).ok()
                                    })
                                    .and_then(|orig_env| {
                                        rmp_serde::from_slice::<DirectMessagePayload>(
                                            &orig_env.payload,
                                        )
                                        .ok()
                                    })
                                    .map(|p| p.conversation_id)
                            });
                            if let Some(conv_id) = conv_id {
                                let key = super::schema::encode_dm_msg_key(
                                    &conv_id,
                                    envelope.timestamp,
                                    &envelope.msg_id,
                                );
                                self.put_cf(cf::DM_EDIT_DELETE_MSGS, &key, &[])?;
                                indexed += 1;
                            }
                        }
                        MessageType::NewsEdit | MessageType::NewsDelete => {
                            let key = super::schema::encode_news_key(
                                envelope.timestamp,
                                &envelope.msg_id,
                            );
                            self.put_cf(cf::NEWS_EDIT_DELETE, &key, &[])?;
                            indexed += 1;
                        }
                        _ => {}
                    }
                }
            }
            iter.next();
        }

        if indexed > 0 {
            info!(indexed, "Backfilled edit/delete marker indexes from MESSAGES");
        }
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::EDIT_DELETE_MARKERS_INDEXED,
            &1u64.to_be_bytes(),
        )?;
        Ok(())
    }

    /// One-time re-index: CHANNEL_MSGS keys used `lamport_ts`, but clients always
    /// send `lamport_ts: 0`, so the index sorted by msg_id (random) — breaking
    /// chronological pagination and the unread fast-skip (`0 <= read_cursor` was
    /// always true). Re-key every chat message by its signed wall-clock
    /// `timestamp` (identical on every node). The old (lamport, msg_id) key is
    /// deleted and the new (timestamp, msg_id) key written. Idempotent — guarded
    /// by `CHANNEL_MSGS_TS_REINDEXED`. Messages live in MESSAGES (source of
    /// truth), so this only rewrites the index, never message content.
    pub fn reindex_channel_msgs_by_timestamp(&self) -> Result<()> {
        use crate::messages::envelope::Envelope;
        use crate::messages::types::{ChatMessagePayload, MessageType};
        use tracing::info;

        let cf = self
            .db
            .cf_handle(cf::MESSAGES)
            .with_context(|| "column family 'messages' not found")?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek_to_first();

        let mut reindexed = 0u64;
        while iter.valid() {
            if let Some(raw) = iter.value() {
                if let Ok(envelope) = rmp_serde::from_slice::<Envelope>(raw) {
                    if matches!(envelope.msg_type, MessageType::ChatMessage) {
                        // Typed decode — the payload may carry a `reply_to` bin
                        // that serde_json::Value cannot represent.
                        if let Ok(p) =
                            rmp_serde::from_slice::<ChatMessagePayload>(&envelope.payload)
                        {
                            let old_key = super::schema::encode_channel_msg_key(
                                p.channel_id,
                                envelope.lamport_ts,
                                &envelope.msg_id,
                            );
                            let new_key = super::schema::encode_channel_msg_key(
                                p.channel_id,
                                envelope.timestamp,
                                &envelope.msg_id,
                            );
                            if old_key != new_key {
                                self.delete_cf(cf::CHANNEL_MSGS, &old_key)?;
                                self.put_cf(cf::CHANNEL_MSGS, &new_key, &[])?;
                                reindexed += 1;
                            }
                        }
                    }
                }
            }
            iter.next();
        }

        if reindexed > 0 {
            info!(reindexed, "Re-indexed CHANNEL_MSGS by timestamp");
        }
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::CHANNEL_MSGS_TS_REINDEXED,
            &1u64.to_be_bytes(),
        )?;
        Ok(())
    }

    /// Migrate device addresses from klv1... to ogd1... prefix.
    ///
    /// Re-derives all device addresses in DEVICE_WALLET_MAP and WALLET_DEVICES
    /// using the `ogd` bech32 HRP instead of `klv`. Old entries are removed.
    /// Runs once on startup; idempotent.
    pub fn migrate_device_hrp(&self) -> Result<()> {
        use tracing::{info, warn};

        // Collect all existing DEVICE_WALLET_MAP entries
        let entries = self.prefix_iter_cf(cf::DEVICE_WALLET_MAP, &[], 100_000)?;
        let mut migrated = 0u32;
        let mut skipped = 0u32;

        for (key_bytes, wallet_bytes) in &entries {
            let old_address = match std::str::from_utf8(key_bytes) {
                Ok(s) => s,
                Err(_) => { skipped += 1; continue; }
            };

            // Skip entries that already use the ogd prefix
            if old_address.starts_with("ogd1") {
                continue;
            }

            // Only migrate klv1 device entries
            if !old_address.starts_with("klv1") {
                continue;
            }

            // Decode the old klv1 address to pubkey bytes, re-encode as ogd1
            let pubkey_bytes = match crate::crypto::address_to_pubkey_bytes(old_address) {
                Ok(b) => b,
                Err(_) => { skipped += 1; continue; }
            };
            let vk = match ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes) {
                Ok(vk) => vk,
                Err(_) => { skipped += 1; continue; }
            };
            let new_address = match crate::crypto::device_pubkey_to_address(&vk) {
                Ok(a) => a,
                Err(_) => { skipped += 1; continue; }
            };

            let wallet = match std::str::from_utf8(wallet_bytes) {
                Ok(s) => s.to_string(),
                Err(_) => { skipped += 1; continue; }
            };

            // Write new forward map: ogd1... → wallet
            self.put_cf(cf::DEVICE_WALLET_MAP, new_address.as_bytes(), wallet.as_bytes())?;
            // Delete old forward map: klv1... → wallet
            self.delete_cf(cf::DEVICE_WALLET_MAP, key_bytes)?;

            // Migrate reverse map: delete old (wallet, klv1) key, write (wallet, ogd1) key
            let old_wd_key = super::schema::encode_wallet_device_key(&wallet, old_address);
            let old_claim = self.get_cf(cf::WALLET_DEVICES, &old_wd_key)?;
            if let Some(claim_bytes) = old_claim {
                // Update the device_address field in the claim JSON
                let mut claim: serde_json::Value = serde_json::from_slice(&claim_bytes)
                    .unwrap_or_default();
                claim["device_address"] = serde_json::json!(new_address);

                let new_wd_key = super::schema::encode_wallet_device_key(&wallet, &new_address);
                if let Ok(new_claim_bytes) = serde_json::to_vec(&claim) {
                    self.put_cf(cf::WALLET_DEVICES, &new_wd_key, &new_claim_bytes)?;
                }
                self.delete_cf(cf::WALLET_DEVICES, &old_wd_key)?;
            }

            migrated += 1;
        }

        if migrated > 0 || skipped > 0 {
            info!(migrated, skipped, "Migrated device addresses from klv1 to ogd1 prefix");
        }
        if skipped > 0 {
            warn!(skipped, "Some device address entries were skipped during HRP migration (corrupted data)");
        }

        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::DEVICE_HRP_MIGRATED,
            &1u64.to_be_bytes(),
        )?;

        Ok(())
    }

    /// One-time migration (audit 2026-06-07 C3): rebuild both reaction-count CFs
    /// with the v2 length-prefixed key format. Reaction counts are DERIVED data,
    /// so the per-reaction CFs (CHAT_REACTIONS / NEWS_REACTIONS) are the source
    /// of truth — we recount from them rather than transcode the old keys.
    /// Idempotent + crash-safe: a re-run clears and rebuilds to the same result.
    pub fn migrate_reaction_count_keys(&self) -> Result<()> {
        use tracing::info;
        let chat = self.rebuild_reaction_counts(cf::CHAT_REACTIONS, cf::CHAT_REACTION_COUNTS)?;
        let news = self.rebuild_reaction_counts(cf::NEWS_REACTIONS, cf::REACTION_COUNTS)?;
        info!(
            chat_counts = chat,
            news_counts = news,
            "Rebuilt reaction-count keys (v2 length-prefixed format)"
        );
        self.put_cf(
            cf::NODE_STATE,
            super::schema::state_keys::REACTION_COUNT_KEYV2,
            &1u64.to_be_bytes(),
        )?;
        Ok(())
    }

    /// Recount per-reaction entries in `reaction_cf` by (msg_id, emoji) and
    /// rewrite `count_cf` with v2 length-prefixed count keys. The per-reaction
    /// key format is `msg_id(32) ++ u16 len ++ emoji ++ 0xFF ++ author` for both
    /// chat and news. Returns the number of distinct (msg_id, emoji) counts.
    fn rebuild_reaction_counts(&self, reaction_cf: &str, count_cf: &str) -> Result<usize> {
        use std::collections::HashMap;
        // Generous bound; WARN (never silently truncate) if a CF exceeds it, so
        // an undercount in this one-shot migration is detectable (audit W-1).
        const SCAN_CAP: usize = 10_000_000;
        // Tally per-reaction entries, keyed by the canonical v2 count-key bytes.
        let mut counts: HashMap<Vec<u8>, u64> = HashMap::new();
        let reaction_entries = self.prefix_iter_cf(reaction_cf, &[], SCAN_CAP)?;
        if reaction_entries.len() >= SCAN_CAP {
            tracing::warn!(
                cf = %reaction_cf,
                cap = SCAN_CAP,
                "reaction-count rebuild hit the scan cap — counts may be undercounted"
            );
        }
        for (key, _val) in reaction_entries {
            if key.len() < 34 {
                continue;
            }
            let mut msg_id = [0u8; 32];
            msg_id.copy_from_slice(&key[0..32]);
            let len = u16::from_be_bytes([key[32], key[33]]) as usize;
            let Some(emoji_bytes) = key.get(34..34 + len) else {
                continue;
            };
            let Ok(emoji) = std::str::from_utf8(emoji_bytes) else {
                continue;
            };
            let count_key = super::schema::encode_reaction_count_key(&msg_id, emoji);
            *counts.entry(count_key).or_insert(0) += 1;
        }
        // Clear existing count keys (old unframed AND any prior v2) then write
        // the freshly-derived set, so the CF holds exactly the recomputed counts.
        for (key, _val) in self.prefix_iter_cf(count_cf, &[], SCAN_CAP)? {
            self.delete_cf(count_cf, &key)?;
        }
        for (key, count) in &counts {
            self.put_cf(count_cf, key, &count.to_be_bytes())?;
        }
        Ok(counts.len())
    }

    /// Get the comment count for a news post by prefix-scanning NEWS_COMMENTS.
    pub fn get_comment_count(&self, post_id: &[u8; 32]) -> Result<u64> {
        self.count_prefix_cf(cf::NEWS_COMMENTS, post_id, 10_000)
    }

    // --- Deletion Markers ---

    /// Store a soft-delete marker for a message.
    ///
    /// Records who deleted the message and when, without removing the actual
    /// content from storage. API responses filter out soft-deleted messages.
    pub fn store_deletion_marker(
        &self,
        msg_id: &[u8; 32],
        deleted_by: &str,
        deleted_at: u64,
    ) -> Result<()> {
        let value = serde_json::to_vec(&serde_json::json!({
            "deleted_by": deleted_by,
            "deleted_at": deleted_at,
        }))?;
        self.put_cf(cf::DELETION_MARKERS, msg_id, &value)
    }

    /// Check if a message has been soft-deleted.
    pub fn is_deleted(&self, msg_id: &[u8; 32]) -> Result<bool> {
        self.exists_cf(cf::DELETION_MARKERS, msg_id)
    }

    // --- Edit History ---

    /// Store an edit record linking an original message to its replacement.
    ///
    /// The edit chain is ordered by `edit_timestamp`, allowing retrieval of
    /// the full edit history in chronological order.
    pub fn store_edit(
        &self,
        original_msg_id: &[u8; 32],
        edit_timestamp: u64,
        edit_msg_id: &[u8; 32],
    ) -> Result<()> {
        use super::schema;
        let key = schema::encode_edit_history_key(original_msg_id, edit_timestamp);
        self.put_cf(cf::EDIT_HISTORY, &key, edit_msg_id)
    }

    /// Get the edit history for a message.
    ///
    /// **Ordering contract:** returns entries in ASCENDING `(timestamp, edit_msg_id)`
    /// order — the caller MUST rely on `vec.last()` being the most recent
    /// edit. This is what `enrich_message_json` does to surface the latest
    /// version of the message. The order is a consequence of the key
    /// encoding `(original_msg_id || timestamp_be)`: RocksDB iterates
    /// keys in lexicographic order, big-endian timestamps sort the same
    /// way as numeric timestamps. Any change to the key encoding (e.g.
    /// reversing the timestamp to make "newest first" O(1)) MUST also
    /// reverse the iteration here, or every projection will surface the
    /// oldest edit instead of the newest.
    pub fn get_edit_history(
        &self,
        original_msg_id: &[u8; 32],
    ) -> Result<Vec<(u64, [u8; 32])>> {
        let entries = self.prefix_iter_cf(cf::EDIT_HISTORY, original_msg_id, 100)?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, value)| {
                // Key layout: original_msg_id(32) + edit_timestamp(8)
                if key.len() == 40 && value.len() == 32 {
                    let ts = u64::from_be_bytes(key[32..40].try_into().ok()?);
                    let edit_id: [u8; 32] = value.try_into().ok()?;
                    Some((ts, edit_id))
                } else {
                    None
                }
            })
            .collect())
    }

    /// Check if a message has been edited.
    pub fn is_edited(&self, msg_id: &[u8; 32]) -> Result<bool> {
        let entries = self.prefix_iter_cf(cf::EDIT_HISTORY, msg_id, 1)?;
        Ok(!entries.is_empty())
    }

    // --- Chat Reactions ---

    /// Add or remove a reaction on a channel chat message, updating cached counts atomically.
    ///
    /// Mirrors [`toggle_news_reaction`] but operates on the CHAT_REACTIONS
    /// and CHAT_REACTION_COUNTS column families. Audit final pre-mainnet
    /// W19b: guarded by `social_counters_lock`, same rationale.
    pub fn toggle_chat_reaction(
        &self,
        msg_id: &[u8; 32],
        emoji: &str,
        author: &str,
        remove: bool,
    ) -> Result<()> {
        let _guard = self
            .social_counters_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        use super::schema;
        let reaction_key = schema::encode_chat_reaction_key(msg_id, emoji, author);
        let count_key = schema::encode_chat_reaction_count_key(msg_id, emoji);

        let exists = self.exists_cf(cf::CHAT_REACTIONS, &reaction_key)?;

        let mut batch = WriteBatch::default();
        let reactions_cf = self.cf_handle(cf::CHAT_REACTIONS)?;
        let counts_cf = self.cf_handle(cf::CHAT_REACTION_COUNTS)?;

        if remove {
            if !exists {
                return Ok(());
            }
            batch.delete_cf(&reactions_cf, &reaction_key);
            let count = self.get_chat_reaction_count(msg_id, emoji)?.saturating_sub(1);
            batch.put_cf(&counts_cf, &count_key, &count.to_be_bytes());
        } else {
            if exists {
                return Ok(()); // already reacted
            }
            batch.put_cf(&reactions_cf, &reaction_key, &[]);
            let count = self.get_chat_reaction_count(msg_id, emoji)? + 1;
            batch.put_cf(&counts_cf, &count_key, &count.to_be_bytes());
        }
        self.write_batch(batch)
    }

    /// Get the reaction count for a specific emoji on a channel chat message.
    pub fn get_chat_reaction_count(&self, msg_id: &[u8; 32], emoji: &str) -> Result<u64> {
        let key = super::schema::encode_chat_reaction_count_key(msg_id, emoji);
        match self.get_cf(cf::CHAT_REACTION_COUNTS, &key)? {
            Some(bytes) if bytes.len() == 8 => {
                Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    /// Get all reactions for a channel chat message with counts.
    pub fn get_chat_reactions(
        &self,
        msg_id: &[u8; 32],
    ) -> Result<Vec<(String, u64)>> {
        let prefix = msg_id.to_vec();
        let entries = self.prefix_iter_cf(cf::CHAT_REACTION_COUNTS, &prefix, 100)?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, value)| {
                if value.len() == 8 {
                    let emoji = super::schema::decode_reaction_count_emoji(&key)?;
                    let count = u64::from_be_bytes(value.try_into().ok()?);
                    if count > 0 {
                        Some((emoji, count))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect())
    }

    // --- Moderation ---

    /// Store a report against a message or user.
    ///
    /// Each reporter can only submit one report per target (keyed by target + reporter).
    pub fn store_report(
        &self,
        target_id: &[u8; 32],
        reporter: &str,
        reason: &str,
        details: &str,
        timestamp: u64,
    ) -> Result<()> {
        use super::schema;
        let key = schema::encode_report_key(target_id, reporter);
        let value = serde_json::to_vec(&serde_json::json!({
            "reporter": reporter,
            "reason": reason,
            "details": details,
            "timestamp": timestamp,
        }))?;
        self.put_cf(cf::REPORTS, &key, &value)
    }

    /// Get all reports for a target (message or user).
    pub fn get_reports(&self, target_id: &[u8; 32]) -> Result<Vec<serde_json::Value>> {
        let entries = self.prefix_iter_cf(cf::REPORTS, target_id, 1000)?;
        Ok(entries
            .into_iter()
            .filter_map(|(_, value)| serde_json::from_slice(&value).ok())
            .collect())
    }

    /// Store a counter-vote on a report, indicating community disagreement.
    pub fn store_counter_vote(
        &self,
        target_id: &[u8; 32],
        voter: &str,
        timestamp: u64,
    ) -> Result<()> {
        use super::schema;
        let key = schema::encode_counter_vote_key(target_id, voter);
        self.put_cf(cf::COUNTER_VOTES, &key, &timestamp.to_be_bytes())
    }

    /// Get the counter-vote count for a target.
    pub fn get_counter_vote_count(&self, target_id: &[u8; 32]) -> Result<u64> {
        self.count_prefix_cf(cf::COUNTER_VOTES, target_id, 10_000)
    }

    /// Store a channel mute record.
    ///
    /// A `duration_secs` of 0 means a permanent mute. Otherwise the mute
    /// expires after `muted_at + duration_secs * 1000` milliseconds.
    pub fn store_channel_mute(
        &self,
        channel_id: u64,
        target: &str,
        muted_by: &str,
        duration_secs: u64,
        reason: &str,
        muted_at: u64,
    ) -> Result<()> {
        use super::schema;
        let key = schema::encode_channel_mute_key(channel_id, target);
        let value = serde_json::to_vec(&serde_json::json!({
            "muted_by": muted_by,
            "duration_secs": duration_secs,
            "reason": reason,
            "muted_at": muted_at,
        }))?;
        self.put_cf(cf::CHANNEL_MUTES, &key, &value)
    }

    /// Check if a user is muted in a channel, handling expiration.
    ///
    /// Returns `true` for permanent mutes (duration_secs == 0) or mutes that
    /// haven't expired yet. Expired mutes are cleaned up automatically.
    pub fn is_channel_muted(&self, channel_id: u64, address: &str) -> Result<bool> {
        use super::schema;
        let key = schema::encode_channel_mute_key(channel_id, address);
        match self.get_cf(cf::CHANNEL_MUTES, &key)? {
            Some(data) => {
                if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&data) {
                    let duration = record.get("duration_secs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if duration > 0 {
                        let muted_at = record.get("muted_at")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let now_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        let elapsed_secs = now_ms.saturating_sub(muted_at) / 1000;
                        if elapsed_secs >= duration {
                            // Mute expired — clean up
                            let _ = self.delete_cf(cf::CHANNEL_MUTES, &key);
                            return Ok(false);
                        }
                    }
                }
                Ok(true) // permanent mute or not yet expired
            }
            None => Ok(false),
        }
    }

    /// Remove a channel mute (for unmuting).
    pub fn remove_channel_mute(&self, channel_id: u64, address: &str) -> Result<()> {
        use super::schema;
        let key = schema::encode_channel_mute_key(channel_id, address);
        self.delete_cf(cf::CHANNEL_MUTES, &key)
    }

    // --- Settings Sync ---

    /// Store encrypted settings blob for a user.
    ///
    /// The blob is opaque to the node — encryption/decryption happens client-side.
    pub fn store_settings(&self, wallet_address: &str, data: &[u8]) -> Result<()> {
        self.put_cf(cf::SETTINGS_SYNC, wallet_address.as_bytes(), data)
    }

    /// Get encrypted settings blob for a user.
    pub fn get_settings(&self, wallet_address: &str) -> Result<Option<Vec<u8>>> {
        self.get_cf(cf::SETTINGS_SYNC, wallet_address.as_bytes())
    }

    // --- Key-Recovery Vault (E2E P3) ---

    /// Store the encrypted E2E key-recovery vault for a user.
    ///
    /// The blob is opaque to the node — sealed under a wallet-derived backup key the
    /// node never holds. Last-write-wins; one record per wallet.
    pub fn store_key_vault(&self, wallet_address: &str, data: &[u8]) -> Result<()> {
        self.put_cf(cf::KEY_VAULT, wallet_address.as_bytes(), data)
    }

    /// Get the encrypted E2E key-recovery vault for a user.
    pub fn get_key_vault(&self, wallet_address: &str) -> Result<Option<Vec<u8>>> {
        self.get_cf(cf::KEY_VAULT, wallet_address.as_bytes())
    }

    /// Delete a user's encrypted key-recovery vault + settings blob (account
    /// deletion). These are the most sensitive per-account artifacts, so a
    /// "delete all my content" request must purge them, not just news rows.
    pub fn delete_key_vault(&self, wallet_address: &str) -> Result<()> {
        self.delete_cf(cf::KEY_VAULT, wallet_address.as_bytes())
    }

    /// Delete a user's encrypted settings blob (account deletion).
    pub fn delete_settings(&self, wallet_address: &str) -> Result<()> {
        self.delete_cf(cf::SETTINGS_SYNC, wallet_address.as_bytes())
    }

    // --- Notifications ---

    /// Store a notification for a user.
    ///
    /// Notifications are stored in reverse-chronological order (newest first)
    /// using negated timestamps in the key.
    pub fn store_notification(
        &self,
        target_address: &str,
        notification_id: &[u8; 32],
        timestamp: u64,
        notification: &serde_json::Value,
    ) -> Result<()> {
        use super::schema;
        let key = schema::encode_notification_key(target_address, timestamp, notification_id);
        let value = serde_json::to_vec(notification)?;
        self.put_cf(cf::NOTIFICATIONS, &key, &value)
    }

    /// Store a notification, evicting the target address's OLDEST stored
    /// notification first if they're already at `max_per_address`
    /// (Security Audit follow-up, audit final pre-mainnet W31).
    ///
    /// The scheduled retention reaper (`reap_expired_notifications`,
    /// `node.rs`) bounds growth over TIME, but its fixed per-tick
    /// throughput (2,000 deletions / 15 min ≈ 2.2/sec) is far below what
    /// a single already-rate-limited sender can generate (30
    /// ChatMessages/min × 50 mentions/message ≈ 25 notification
    /// rows/sec) — a sustained flood still grows the CF unboundedly,
    /// just slower. This per-address cap is the orthogonal, O(1)-per-row
    /// backstop the original finding's own text named as an alternative
    /// fix ("a per-address row cap on write"): it bounds worst-case
    /// storage per address regardless of how fast an attacker floods.
    ///
    /// Evict-oldest (not reject-newest, unlike the DM per-recipient cap
    /// from W11) is the correct choice here: a notification is a
    /// low-stakes, recoverable POINTER (the underlying chat/news message
    /// it references is still fully readable in the channel itself), not
    /// irreplaceable content like a DM — so losing the oldest one under
    /// sustained flood is an acceptable degradation, and rejecting new
    /// notifications instead would just make the notification feed stop
    /// updating for a flooded user, arguably worse.
    ///
    /// `max_per_address == 0` disables the cap (test-only / explicit
    /// opt-out — callers should not pass 0 in production).
    pub fn store_notification_capped(
        &self,
        target_address: &str,
        notification_id: &[u8; 32],
        timestamp: u64,
        notification: &serde_json::Value,
        max_per_address: u64,
    ) -> Result<()> {
        if max_per_address > 0 {
            let mut prefix = Vec::with_capacity(target_address.len() + 1);
            prefix.extend_from_slice(target_address.as_bytes());
            prefix.push(0xFF);
            let count = self.count_prefix_cf(cf::NOTIFICATIONS, &prefix, max_per_address as usize)?;
            if count >= max_per_address {
                // Oldest row = highest raw key within this address's
                // prefix range (keys are negated-timestamp, so ascending
                // key order is newest-first) — seek to the maximum
                // possible key for this prefix and walk backward one.
                let mut upper_bound = prefix.clone();
                upper_bound.extend(std::iter::repeat(0xFFu8).take(40)); // !ts(8) + id(32)
                if let Some((oldest_key, _)) = self
                    .reverse_iter_cf(cf::NOTIFICATIONS, &upper_bound, &prefix, 1)?
                    .into_iter()
                    .next()
                {
                    self.delete_cf(cf::NOTIFICATIONS, &oldest_key)?;
                }
            }
        }
        self.store_notification(target_address, notification_id, timestamp, notification)
    }

    /// Get notifications for a user, optionally filtered by a since timestamp.
    ///
    /// Returns notifications in reverse-chronological order (newest first).
    /// If `since` is provided, only notifications newer than that timestamp are returned.
    pub fn get_notifications(
        &self,
        address: &str,
        since: Option<u64>,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let mut prefix = Vec::with_capacity(address.len() + 1);
        prefix.extend_from_slice(address.as_bytes());
        prefix.push(0xFF);

        let entries = self.prefix_iter_cf(cf::NOTIFICATIONS, &prefix, limit)?;
        Ok(entries
            .into_iter()
            .filter_map(|(key, value)| {
                // Key layout: address + 0xFF + !timestamp(8) + notification_id(32)
                let ts_start = prefix.len();
                if key.len() < ts_start + 8 + 32 {
                    return None;
                }
                let neg_ts = u64::from_be_bytes(key[ts_start..ts_start + 8].try_into().ok()?);
                let timestamp = !neg_ts;

                // Filter by since timestamp if provided
                if let Some(since_ts) = since {
                    if timestamp <= since_ts {
                        return None;
                    }
                }

                serde_json::from_slice(&value).ok()
            })
            .collect())
    }

    /// Delete notifications older than a given timestamp (for 30-day TTL cleanup).
    ///
    /// Returns the number of deleted notifications.
    pub fn cleanup_old_notifications(&self, address: &str, older_than: u64) -> Result<u64> {
        let mut prefix = Vec::with_capacity(address.len() + 1);
        prefix.extend_from_slice(address.as_bytes());
        prefix.push(0xFF);

        let entries = self.prefix_iter_cf(cf::NOTIFICATIONS, &prefix, 10_000)?;
        let mut deleted = 0u64;

        for (key, _) in &entries {
            let ts_start = prefix.len();
            if key.len() < ts_start + 8 + 32 {
                continue;
            }
            let neg_ts = u64::from_be_bytes(key[ts_start..ts_start + 8].try_into().unwrap_or([0; 8]));
            let timestamp = !neg_ts;

            if timestamp < older_than {
                self.delete_cf(cf::NOTIFICATIONS, key)?;
                deleted += 1;
            }
        }

        Ok(deleted)
    }

    // --- Anchor Verification ---

    /// Compute the anchor verification status for a given node.
    ///
    /// Levels:
    /// - "active": anchored consistently (at least 1 per 24h window) for 7+ days
    /// - "verified": anchored at least once in the last 24h
    /// - "none": no recent anchors
    pub fn compute_anchor_status(&self, node_id: &str) -> Result<AnchorStatus> {
        // Klever TX timestamps are in unix seconds, so use seconds throughout
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut prefix = Vec::with_capacity(node_id.len() + 1);
        prefix.extend_from_slice(node_id.as_bytes());
        prefix.push(0xFF);

        let seven_days = 7 * 24 * 60 * 60u64;
        let cutoff = now.saturating_sub(seven_days);

        // Single full-prefix scan (no 200 cap — previously made any node
        // with >200 lifetime anchors show "level: none" because the 200
        // oldest were all > 7 days old and filtered out). One row per
        // anchor for this node only, bounded by anchoring frequency.
        let cf = self
            .db
            .cf_handle(cf::ANCHOR_BY_NODE)
            .context("ANCHOR_BY_NODE cf not found")?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(&prefix);

        let mut timestamps: Vec<u64> = Vec::new();
        let mut all_count = 0u64;
        let mut earliest: Option<u64> = None;

        while iter.valid() {
            let k = match iter.key() {
                Some(k) if k.starts_with(&prefix) => k,
                _ => break,
            };
            if k.len() > prefix.len() + 7 {
                let ts_start = k.len() - 8;
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&k[ts_start..]);
                let ts = u64::from_be_bytes(ts_bytes);
                all_count += 1;
                // Forward iter is timestamp-ascending — first hit is oldest.
                if earliest.is_none() {
                    earliest = Some(ts);
                }
                if ts >= cutoff {
                    timestamps.push(ts);
                }
            }
            iter.next();
        }
        iter.status()
            .context("rocksdb iter status in compute_anchor_status")?;

        if all_count == 0 {
            return Ok(AnchorStatus {
                verified: false,
                level: "none".to_string(),
                last_anchor_age_seconds: None,
                anchoring_since: None,
                total_anchors: 0,
            });
        }

        if timestamps.is_empty() {
            return Ok(AnchorStatus {
                verified: false,
                level: "none".to_string(),
                last_anchor_age_seconds: None,
                anchoring_since: earliest,
                total_anchors: all_count,
            });
        }

        timestamps.sort_unstable();
        let most_recent = *timestamps.last().unwrap();
        let age_secs = now.saturating_sub(most_recent);

        let twenty_four_hours = 24 * 60 * 60u64;

        // Check if anchored in last 24h
        if age_secs > twenty_four_hours {
            return Ok(AnchorStatus {
                verified: false,
                level: "none".to_string(),
                last_anchor_age_seconds: Some(age_secs),
                anchoring_since: earliest,
                total_anchors: all_count,
            });
        }

        // Check if consistently anchored for 7+ days
        // Need at least one anchor per 24h window across all 7 days
        let mut level = "verified".to_string();
        if timestamps.len() >= 7 {
            let seven_days_ago = now.saturating_sub(seven_days);
            if *timestamps.first().unwrap() <= seven_days_ago + twenty_four_hours {
                // Check each 24h window
                let mut all_days_covered = true;
                for day in 0..7 {
                    let window_start = now.saturating_sub((day + 1) as u64 * twenty_four_hours);
                    let window_end = now.saturating_sub(day as u64 * twenty_four_hours);
                    let has_anchor = timestamps.iter().any(|&ts| ts >= window_start && ts < window_end);
                    if !has_anchor {
                        all_days_covered = false;
                        break;
                    }
                }
                if all_days_covered {
                    level = "active".to_string();
                }
            }
        }

        Ok(AnchorStatus {
            verified: true,
            level,
            last_anchor_age_seconds: Some(age_secs),
            anchoring_since: earliest,
            total_anchors: all_count,
        })
    }

    /// Get the self anchor status for this node (used in /network/stats).
    ///
    /// Uses the ANCHOR_BY_NODE index to query only this node's anchors,
    /// then looks up the most recent STATE_ANCHORS entry for block height.
    pub fn get_self_anchor_status(&self, node_id: &str) -> Result<SelfAnchorStatus> {
        let mut prefix = Vec::with_capacity(node_id.len() + 1);
        prefix.extend_from_slice(node_id.as_bytes());
        prefix.push(0xFF);

        // Full prefix scan with no limit — previously capped at 200 via
        // prefix_iter_cf, which made total_anchors stick at 200 once a
        // node crossed that many. ANCHOR_BY_NODE is one row per anchor
        // for this node only, bounded by anchoring interval (~9k/year
        // at hourly anchoring), so a full scan is cheap.
        let cf = self
            .db
            .cf_handle(cf::ANCHOR_BY_NODE)
            .context("ANCHOR_BY_NODE cf not found")?;
        let mut iter = self.db.raw_iterator_cf(&cf);
        iter.seek(&prefix);

        let mut total: u64 = 0;
        let mut earliest_ts: Option<u64> = None;
        let mut latest_ts: u64 = 0;
        let mut latest_height: u64 = 0;

        while iter.valid() {
            let (k, v) = match (iter.key(), iter.value()) {
                (Some(k), Some(v)) if k.starts_with(&prefix) => (k, v),
                _ => break,
            };
            if k.len() >= prefix.len() + 8 {
                let ts_start = k.len() - 8;
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&k[ts_start..]);
                let ts = u64::from_be_bytes(ts_bytes);
                total += 1;
                // Forward iter is timestamp-ascending — first hit is oldest.
                if earliest_ts.is_none() {
                    earliest_ts = Some(ts);
                }
                if ts > latest_ts {
                    latest_ts = ts;
                    if v.len() == 8 {
                        let mut h = [0u8; 8];
                        h.copy_from_slice(v);
                        latest_height = u64::from_be_bytes(h);
                    }
                }
            }
            iter.next();
        }
        iter.status()
            .context("rocksdb iter status in get_self_anchor_status")?;

        if total == 0 {
            return Ok(SelfAnchorStatus {
                is_anchorer: false,
                last_anchor_height: None,
                last_anchor_age_seconds: None,
                total_anchors: 0,
                anchoring_since: None,
            });
        }

        // Klever TX timestamps are in unix seconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_age = if latest_ts > 0 {
            Some(now.saturating_sub(latest_ts))
        } else {
            None
        };

        Ok(SelfAnchorStatus {
            is_anchorer: total > 0,
            last_anchor_height: if latest_height > 0 { Some(latest_height) } else { None },
            last_anchor_age_seconds: last_age,
            total_anchors: total,
            anchoring_since: earliest_ts,
        })
    }

    // --- Device-to-Wallet Identity Mapping ---

    /// Register a device key as belonging to a wallet.
    ///
    /// Atomically writes both the forward map (device → wallet) and the reverse
    /// index (wallet+device → claim). Idempotent: re-registering the same
    /// device-wallet pair updates the claim in place.
    pub fn register_device(&self, claim: &DeviceClaim) -> Result<()> {
        let claim_bytes = rmp_serde::to_vec(claim)
            .context("serializing DeviceClaim")?;

        let device_key = claim.device_address.as_bytes();
        let wallet_device_key =
            encode_wallet_device_key(&claim.wallet_address, &claim.device_address);

        let map_cf = self.cf_handle(cf::DEVICE_WALLET_MAP)?;
        let devices_cf = self.cf_handle(cf::WALLET_DEVICES)?;

        let mut batch = WriteBatch::default();
        // Forward: device_address → wallet_address
        batch.put_cf(&map_cf, device_key, claim.wallet_address.as_bytes());
        // Reverse: (wallet_address, 0xFF, device_address) → DeviceClaim
        batch.put_cf(&devices_cf, &wallet_device_key, &claim_bytes);
        self.write_batch(batch)
    }

    /// Revoke a device registration.
    ///
    /// Removes both the forward and reverse mappings. Returns `true` if the
    /// device was registered (and is now removed), `false` if it wasn't found.
    ///
    /// Note: the read-then-delete is not fully atomic (TOCTOU). The API layer
    /// (Phase 3) serializes revocations per wallet via auth, making concurrent
    /// register+revoke for the same device by different wallets impossible.
    pub fn revoke_device(
        &self,
        device_address: &str,
        wallet_address: &str,
        revoked_at: u64,
    ) -> Result<bool> {
        let device_key = device_address.as_bytes();
        // Verify this device is actually mapped to this wallet. Only the owning
        // wallet (while mapped) may tombstone the device — otherwise a wallet
        // could tombstone a device it doesn't own and DoS the real owner's
        // delegation.
        match self.get_cf(cf::DEVICE_WALLET_MAP, device_key)? {
            Some(stored_wallet) => {
                if stored_wallet != wallet_address.as_bytes() {
                    return Ok(false); // device belongs to a different wallet
                }
            }
            None => return Ok(false), // device not registered
        }

        let wallet_device_key = encode_wallet_device_key(wallet_address, device_address);

        let map_cf = self.cf_handle(cf::DEVICE_WALLET_MAP)?;
        let devices_cf = self.cf_handle(cf::WALLET_DEVICES)?;
        let revoc_cf = self.cf_handle(cf::DEVICE_REVOCATIONS)?;

        // P-2: write a revocation tombstone (last-writer-wins by timestamp) so a
        // later replayed/stale DeviceDelegation cannot resurrect this device.
        let prev = self
            .get_cf(cf::DEVICE_REVOCATIONS, device_key)?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        let tombstone_ts = revoked_at.max(prev);

        let mut batch = WriteBatch::default();
        batch.delete_cf(&map_cf, device_key);
        batch.delete_cf(&devices_cf, &wallet_device_key);
        batch.put_cf(&revoc_cf, device_key, tombstone_ts.to_be_bytes());
        self.write_batch(batch)?;
        Ok(true)
    }

    /// Revocation-tombstone timestamp for a device, if it was ever revoked
    /// (P-2). A `DeviceDelegation` with `timestamp <= revoked_at` must be
    /// rejected to prevent resurrecting a revoked device via stale replay.
    pub fn get_device_revoked_at(&self, device_address: &str) -> Result<Option<u64>> {
        Ok(self
            .get_cf(cf::DEVICE_REVOCATIONS, device_address.as_bytes())?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes))
    }

    /// Resolve a device address to its owning wallet address.
    ///
    /// Returns `None` if no mapping exists (device key IS the wallet in
    /// built-in wallet mode — caller handles fallback).
    pub fn resolve_wallet(&self, device_address: &str) -> Result<Option<String>> {
        match self.get_cf(cf::DEVICE_WALLET_MAP, device_address.as_bytes())? {
            Some(bytes) => {
                let wallet = String::from_utf8(bytes)
                    .context("invalid UTF-8 in stored wallet address")?;
                Ok(Some(wallet))
            }
            None => Ok(None),
        }
    }

    // --- Private Channel Anchor Node Storage ---

    /// Store encrypted group key material for a private channel epoch.
    pub fn store_private_channel_keys(
        &self,
        channel_id: u64,
        epoch: u64,
        key_data: &[u8],
    ) -> Result<()> {
        use super::schema;
        let key = schema::encode_private_channel_key(channel_id, epoch);
        self.put_cf(cf::PRIVATE_CHANNEL_KEYS, &key, key_data)
    }

    /// Get the latest (highest epoch) key distribution for a private channel.
    pub fn get_private_channel_keys_latest(&self, channel_id: u64) -> Result<Option<(u64, Vec<u8>)>> {
        use super::schema;
        let prefix = channel_id.to_be_bytes();
        // Reverse iterate to get the highest epoch first
        let start = schema::encode_private_channel_key(channel_id, u64::MAX);
        let entries = self.reverse_iter_cf(cf::PRIVATE_CHANNEL_KEYS, &start, &prefix, 1)?;
        if let Some((key, value)) = entries.into_iter().next() {
            if key.len() >= 16 {
                let epoch = u64::from_be_bytes(key[8..16].try_into().unwrap_or([0; 8]));
                return Ok(Some((epoch, value)));
            }
        }
        Ok(None)
    }

    /// Get key distribution for a specific epoch.
    pub fn get_private_channel_keys(&self, channel_id: u64, epoch: u64) -> Result<Option<Vec<u8>>> {
        use super::schema;
        let key = schema::encode_private_channel_key(channel_id, epoch);
        self.get_cf(cf::PRIVATE_CHANNEL_KEYS, &key)
    }

    // --- Channel key envelopes (per-device E2E key delivery, spec 8.1.1 / 8.2) ---

    /// Store a per-device wrapped key envelope (`channel_keys` CF) under
    /// **first-write-wins** semantics with a per-scope cap. `value` is the opaque
    /// serialized record (the node never decrypts it).
    ///
    /// Returns [`KeyEnvelopeStore`] so the caller can log the reason a write was a
    /// no-op. First-write-wins prevents a later (possibly hostile) publisher from
    /// clobbering a good key already cached for `(key_scope, epoch, target, device)`;
    /// the cap bounds storage per scope against a flood of bogus envelopes.
    ///
    /// Audit final pre-mainnet W19a: the whole body runs under
    /// `channel_key_envelope_lock`. Without it, two concurrent publishers for
    /// the same `(key_scope, target, author, device, epoch)` could both pass
    /// the `exists_cf` check below and both reach the final `put_cf` — the
    /// LAST write physically wins, silently violating the first-write-wins
    /// guarantee this function exists to provide (an attacker racing a
    /// victim's genuine key-envelope publish, observable via gossip, could
    /// clobber the victim's wrapped key).
    pub fn put_channel_key_envelope_fww(
        &self,
        key_scope: &[u8; 32],
        target: &str,
        author: &str,
        device_id_hex: &str,
        epoch: u64,
        value: &[u8],
        scope_cap: usize,
    ) -> Result<KeyEnvelopeStore> {
        let _guard = self
            .channel_key_envelope_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        use super::schema;
        let key = schema::encode_channel_key(key_scope, target, author, device_id_hex, epoch);
        if self.exists_cf(cf::CHANNEL_KEYS, &key)? {
            return Ok(KeyEnvelopeStore::AlreadyPresent);
        }
        // Cap is checked on the new key's absence: scan up to scope_cap+1 entries.
        let prefix = schema::encode_channel_key_scope_prefix(key_scope);
        let existing = self.prefix_iter_cf(cf::CHANNEL_KEYS, &prefix, scope_cap + 1)?;
        if existing.len() >= scope_cap {
            // P2d hardening (C2): the scope is full. Rather than reject (which would
            // let a member brick the channel by flooding the scope so legitimate key
            // ROTATION envelopes can't be stored), evict the LOWEST-epoch entry — but
            // only if the incoming envelope's epoch is strictly higher, so we always
            // make room for newer epochs (rotation uses the highest epoch) and never
            // evict newer keys to admit an older one. The trade-off is that very old
            // epochs' keys may be dropped under pressure (old-history decryption
            // degrades), which is acceptable versus a permanently unsendable channel.
            let epoch_of = |k: &[u8]| -> u64 {
                if k.len() >= 8 {
                    u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap_or([0; 8]))
                } else {
                    0
                }
            };
            let lowest = existing.iter().min_by_key(|(k, _)| epoch_of(k));
            match lowest {
                Some((lk, _)) if epoch_of(lk) < epoch => {
                    // Security Audit follow-up: evict-then-store as one
                    // WriteBatch, not two separate writes — under the new
                    // lock this was already concurrency-safe, but a crash
                    // between a bare `delete_cf` and a later `put_cf` would
                    // have lost the evicted entry without ever storing its
                    // replacement (worse than either write alone).
                    let cf_handle = self.cf_handle(cf::CHANNEL_KEYS)?;
                    let mut batch = WriteBatch::default();
                    batch.delete_cf(&cf_handle, lk);
                    batch.put_cf(&cf_handle, &key, value);
                    self.write_batch(batch)?;
                    return Ok(KeyEnvelopeStore::Stored);
                }
                _ => return Ok(KeyEnvelopeStore::ScopeFull),
            }
        }
        self.put_cf(cf::CHANNEL_KEYS, &key, value)?;
        Ok(KeyEnvelopeStore::Stored)
    }

    /// Get the latest-epoch wrapped key envelope for one `(scope, target, author,
    /// device)` — i.e. author X's key for this recipient device. Returns `(epoch, value)`.
    pub fn get_channel_key_envelope_latest(
        &self,
        key_scope: &[u8; 32],
        target: &str,
        author: &str,
        device_id_hex: &str,
    ) -> Result<Option<(u64, Vec<u8>)>> {
        use super::schema;
        let prefix = schema::encode_channel_key_device_prefix(key_scope, target, author, device_id_hex);
        // start just past the highest possible epoch for this device prefix.
        let mut start = prefix.clone();
        start.extend_from_slice(&u64::MAX.to_be_bytes());
        let entries = self.reverse_iter_cf(cf::CHANNEL_KEYS, &start, &prefix, 1)?;
        if let Some((key, value)) = entries.into_iter().next() {
            if key.len() >= 8 {
                let epoch = u64::from_be_bytes(
                    key[key.len() - 8..].try_into().unwrap_or([0; 8]),
                );
                return Ok(Some((epoch, value)));
            }
        }
        Ok(None)
    }

    /// Get the wrapped key envelope for an exact `(scope, target, author, device, epoch)`.
    pub fn get_channel_key_envelope(
        &self,
        key_scope: &[u8; 32],
        target: &str,
        author: &str,
        device_id_hex: &str,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>> {
        use super::schema;
        let key = schema::encode_channel_key(key_scope, target, author, device_id_hex, epoch);
        self.get_cf(cf::CHANNEL_KEYS, &key)
    }

    /// Store anchor node info for a remote private channel.
    pub fn store_private_channel_anchor(
        &self,
        channel_id: u64,
        anchor_data: &[u8],
    ) -> Result<()> {
        use super::schema;
        let key = schema::encode_private_channel_anchor_key(channel_id);
        self.put_cf(cf::PRIVATE_CHANNEL_ANCHORS, &key, anchor_data)
    }

    /// Get the anchor node info for a private channel.
    pub fn get_private_channel_anchor(&self, channel_id: u64) -> Result<Option<Vec<u8>>> {
        use super::schema;
        let key = schema::encode_private_channel_anchor_key(channel_id);
        self.get_cf(cf::PRIVATE_CHANNEL_ANCHORS, &key)
    }

    /// Check if this node is the anchor for a given private channel.
    ///
    /// A channel is locally anchored if it exists in the CHANNELS CF with type Private
    /// and there is no entry in PRIVATE_CHANNEL_ANCHORS (which stores remote anchors).
    pub fn is_local_anchor(&self, channel_id: u64) -> Result<bool> {
        use super::schema;
        let key = channel_id.to_be_bytes();
        if let Some(meta_bytes) = self.get_cf(cf::CHANNELS, &key)? {
            let meta: serde_json::Value = serde_json::from_slice(&meta_bytes)
                .context("deserializing channel metadata")?;
            if meta.get("channel_type").and_then(|v| v.as_u64()) == Some(2) {
                // It's a private channel and we have its metadata — we're the anchor
                let anchor_key = schema::encode_private_channel_anchor_key(channel_id);
                return Ok(!self.exists_cf(cf::PRIVATE_CHANNEL_ANCHORS, &anchor_key)?);
            }
        }
        Ok(false)
    }

    /// List all devices registered to a wallet address.
    ///
    /// Returns the stored `DeviceClaim` for each device, ordered by key.
    pub fn list_devices(&self, wallet_address: &str) -> Result<Vec<DeviceClaim>> {
        let prefix = {
            let mut p = Vec::with_capacity(wallet_address.len() + 1);
            p.extend_from_slice(wallet_address.as_bytes());
            p.push(0xFF);
            p
        };

        let entries = self.prefix_iter_cf(cf::WALLET_DEVICES, &prefix, 50)?;
        let mut claims = Vec::with_capacity(entries.len());

        for (_key, value) in entries {
            let claim: DeviceClaim = rmp_serde::from_slice(&value)
                .context("deserializing DeviceClaim")?;
            claims.push(claim);
        }

        Ok(claims)
    }
}

/// Get number of CPUs for RocksDB parallelism.
fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(2)
}

#[cfg(test)]
mod channel_key_tests {
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn channel_key_envelope_fww_and_latest() {
        let (s, _d) = db();
        let scope = [7u8; 32];
        let target = "klv1aaaa";
        let author = "klv1author";
        let device = "ab".repeat(32); // 64 hex chars
        let cap = 16;

        // First write stores.
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, target, author, &device, 1, b"v1", cap)
                .unwrap(),
            KeyEnvelopeStore::Stored
        );
        // A second write to the same (scope, author, epoch, device) is rejected (FWW).
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, target, author, &device, 1, b"attacker", cap)
                .unwrap(),
            KeyEnvelopeStore::AlreadyPresent
        );
        // The original value is preserved.
        assert_eq!(
            s.get_channel_key_envelope(&scope, target, author, &device, 1)
                .unwrap()
                .as_deref(),
            Some(&b"v1"[..])
        );
        // A newer epoch is a distinct entry; latest returns the highest epoch.
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, target, author, &device, 2, b"v2", cap)
                .unwrap(),
            KeyEnvelopeStore::Stored
        );
        let (ep, val) = s
            .get_channel_key_envelope_latest(&scope, target, author, &device)
            .unwrap()
            .unwrap();
        assert_eq!(ep, 2);
        assert_eq!(val, b"v2");

        // PER-SENDER: a different author's key for the SAME device coexists (no
        // collision — this is the split-brain fix).
        let author2 = "klv1other";
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, target, author2, &device, 1, b"k2", cap)
                .unwrap(),
            KeyEnvelopeStore::Stored
        );
        assert_eq!(
            s.get_channel_key_envelope(&scope, target, author2, &device, 1)
                .unwrap()
                .as_deref(),
            Some(&b"k2"[..])
        );
        // author1's key is still its own value, not clobbered.
        assert_eq!(
            s.get_channel_key_envelope(&scope, target, author, &device, 1)
                .unwrap()
                .as_deref(),
            Some(&b"v1"[..])
        );

        // A different device under the same scope/author does not collide.
        let other = "cd".repeat(32);
        assert!(s
            .get_channel_key_envelope_latest(&scope, target, author, &other)
            .unwrap()
            .is_none());
    }

    #[test]
    fn channel_key_envelope_scope_cap() {
        let (s, _d) = db();
        let scope = [9u8; 32];
        let cap = 3;
        for i in 0..cap {
            let device = format!("{:064x}", i);
            assert_eq!(
                s.put_channel_key_envelope_fww(&scope, "klv1t", "klv1a", &device, 1, b"x", cap)
                    .unwrap(),
                KeyEnvelopeStore::Stored
            );
        }
        // One past the cap is rejected.
        let device = format!("{:064x}", 99);
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, "klv1t", "klv1a", &device, 1, b"x", cap)
                .unwrap(),
            KeyEnvelopeStore::ScopeFull
        );
    }
}

#[cfg(test)]
mod tombstone_channel_tests {
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn put_member(s: &Storage, channel_id: u64, address: &str) {
        let key = crate::storage::schema::encode_channel_member_key(channel_id, address);
        s.put_cf(cf::CHANNEL_MEMBERS, &key, b"{}").unwrap();
    }

    #[test]
    fn captures_members_for_the_delete_broadcast_and_wipes_channel_members() {
        let (s, _d) = db();
        let channel_id = 42;
        put_member(&s, channel_id, "klv1creator");
        put_member(&s, channel_id, "klv1joiner");

        s.tombstone_channel(channel_id, 1_700_000_000).unwrap();

        let mut members = s.deleted_channel_members(channel_id).unwrap();
        members.sort();
        assert_eq!(members, vec!["klv1creator".to_string(), "klv1joiner".to_string()]);

        // CHANNEL_MEMBERS itself is gone — the whole reason deleted_channel_members
        // exists is that nothing can derive the audience from there anymore.
        let key = crate::storage::schema::encode_channel_member_key(channel_id, "klv1creator");
        assert!(s.get_cf(cf::CHANNEL_MEMBERS, &key).unwrap().is_none());
    }

    #[test]
    fn re_deleting_an_already_tombstoned_channel_keeps_the_original_member_list() {
        let (s, _d) = db();
        let channel_id = 43;
        put_member(&s, channel_id, "klv1a");
        s.tombstone_channel(channel_id, 100).unwrap();

        // A second delete (e.g. a re-delivered ChannelDelete) must not overwrite the
        // captured list with an empty one — CHANNEL_MEMBERS is already gone by then.
        s.tombstone_channel(channel_id, 200).unwrap();
        assert_eq!(s.deleted_channel_members(channel_id).unwrap(), vec!["klv1a".to_string()]);
    }

    #[test]
    fn non_deleted_channel_has_no_captured_members() {
        let (s, _d) = db();
        assert_eq!(s.deleted_channel_members(999).unwrap(), Vec::<String>::new());
    }

    /// Code Audit follow-up: `TOTAL_CHANNELS` must only be decremented for a
    /// channel this node actually counted (had a `CHANNELS` row for) — e.g.
    /// a `ChannelDelete` backfilled/gossiped for a channel whose
    /// `ChannelCreate` this node never locally saw was never incremented.
    /// Decrementing anyway would (with the new merge-operator counter,
    /// audit W19b) drive `TOTAL_CHANNELS` into permanent negative debt that
    /// silently eats future genuine increments, unlike the old
    /// clamp-at-write `decrement_stat`.
    #[test]
    fn deleting_a_channel_never_locally_created_does_not_decrement_total_channels() {
        let (s, _d) = db();
        // A genuine, counted channel first, to prove the counter isn't just
        // stuck at 0 for an unrelated reason.
        s.increment_stat(crate::storage::schema::state_keys::TOTAL_CHANNELS).unwrap();
        assert_eq!(s.get_stat(crate::storage::schema::state_keys::TOTAL_CHANNELS).unwrap(), 1);

        // Tombstone a DIFFERENT channel_id that never had a CHANNELS row —
        // e.g. a ChannelDelete this node backfilled without ever seeing the
        // matching ChannelCreate.
        let never_created_channel_id = 9999u64;
        assert!(s.get_cf(cf::CHANNELS, &never_created_channel_id.to_be_bytes()).unwrap().is_none());
        s.tombstone_channel(never_created_channel_id, 1_000).unwrap();

        assert_eq!(
            s.get_stat(crate::storage::schema::state_keys::TOTAL_CHANNELS).unwrap(),
            1,
            "TOTAL_CHANNELS must be unaffected by tombstoning a channel that was never counted"
        );
    }

    /// Code Audit follow-up (W18 adjacency): `tombstone_channel` now shares
    /// `channel_membership_lock` with `add_channel_member`/
    /// `remove_channel_member_and_raise_epoch_floor` — a membership op that
    /// reads the CHANNELS row before a concurrent delete, then writes its
    /// updated row after, would otherwise resurrect a just-deleted channel.
    #[test]
    fn concurrent_removal_never_resurrects_a_channel_being_tombstoned() {
        let (s, _d) = db();
        let s = std::sync::Arc::new(s);
        let channel_id = 558u64;
        s.put_cf(
            cf::CHANNELS,
            &channel_id.to_be_bytes(),
            &serde_json::to_vec(&serde_json::json!({"member_count": 1, "channel_type": 0})).unwrap(),
        )
        .unwrap();
        s.add_channel_member(channel_id, "klv1lastmember", 1_000, "member").unwrap();

        std::thread::scope(|scope| {
            let s1 = s.clone();
            scope.spawn(move || {
                s1.tombstone_channel(channel_id, 2_000).unwrap();
            });
            let s2 = s.clone();
            scope.spawn(move || {
                let _ = s2.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1lastmember");
            });
        });

        assert!(
            s.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()).unwrap().is_none(),
            "CHANNELS row must stay deleted — a racing member-removal must never resurrect it"
        );
        assert!(s.deleted_channel_members(channel_id).unwrap().len() <= 1);
    }
}

#[cfg(test)]
mod pending_channel_delete_lock_tests {
    //! Audit final pre-mainnet W14, Security Audit follow-up:
    //! `take_pending_channel_delete`'s read-then-delete previously had no
    //! synchronization with `put_pending_channel_delete`, so a `take` could
    //! read a stale claim and then delete a DIFFERENT, newer claim that a
    //! concurrent `put` had written into the gap between the read and the
    //! delete — silently dropping a genuine claim without either operation
    //! ever observing the loss.
    //!
    //! An outside-the-call timing probe (increment a counter before calling,
    //! decrement after) cannot actually prove mutual exclusion here — the
    //! measured window is the whole call, not the lock-held section inside
    //! it, so it would flag "overlap" for any two calls in flight
    //! simultaneously regardless of whether the internal lock works,
    //! producing a test that fails even when the fix is correct. Instead
    //! this drives the exact failure shape under real concurrency and
    //! checks the invariant the lock exists to guarantee: every value ever
    //! written is either still in storage at the end, or was returned by
    //! SOME `take` call — never silently discarded by a `take` that read a
    //! different value.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn survives_heavy_concurrent_put_and_take_without_poisoning_or_losing_every_write() {
        let (s, _d) = db();
        let s = std::sync::Arc::new(s);
        let channel_id = 888u64;
        const WRITES_PER_THREAD: u64 = 200;
        const WRITER_THREADS: u64 = 8;
        let total_puts = WRITER_THREADS * WRITES_PER_THREAD;

        // Every write gets a globally unique `requested_at` so successful
        // takes can be counted precisely. An overwrite by a later put before
        // any take reads the row is expected/correct behavior (see
        // `put_pending_channel_delete`'s doc comment — one row per
        // channel_id, latest claim wins), so this can't assert every write
        // is individually observed. What it CAN assert: every `.unwrap()`
        // below panics (poisoning `pending_channel_delete_lock` for the rest
        // of the run) the instant either method's critical section is
        // entered while corrupted state from another thread is visible —
        // heavy contention (1,600 puts / 1,600 takes racing 16 threads for
        // the same single row) is exactly the condition that would surface
        // a broken or missing lock as a panic, not a silent pass.
        let taken_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        std::thread::scope(|scope| {
            for w in 0..WRITER_THREADS {
                let s = s.clone();
                scope.spawn(move || {
                    for i in 0..WRITES_PER_THREAD {
                        let unique_ts = w * WRITES_PER_THREAD + i;
                        s.put_pending_channel_delete(channel_id, "klv1claimant", unique_ts)
                            .unwrap();
                    }
                });
            }
            for _ in 0..WRITER_THREADS {
                let s = s.clone();
                let taken_count = taken_count.clone();
                scope.spawn(move || {
                    for _ in 0..WRITES_PER_THREAD {
                        if s.take_pending_channel_delete(channel_id).unwrap().is_some() {
                            taken_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                });
            }
        });

        let leftover = s.take_pending_channel_delete(channel_id).unwrap().is_some();
        let total_observed = taken_count.load(std::sync::atomic::Ordering::SeqCst)
            + if leftover { 1 } else { 0 };
        assert!(
            total_observed >= 1,
            "at least one write must have been observed across 1,600 puts and 1,600+1 take attempts \
             — zero would indicate the mechanism is silently no-op'ing, not just racing"
        );
        assert!(
            total_observed <= total_puts,
            "can never observe more values than were ever written"
        );
    }
}

#[cfg(test)]
mod channel_membership_lock_tests {
    //! Audit final pre-mainnet W18: `add_channel_member` and
    //! `remove_channel_member_and_raise_epoch_floor` used to be 3 separate
    //! unbatched, unlocked read-modify-writes of the same `CHANNELS` row
    //! (member add, member remove, epoch-floor raise). A crash between
    //! member-removal and the epoch-floor raise permanently defeated P2d
    //! forward secrecy for the removed member; concurrent writers could also
    //! race the JSON RMW into `member_count` drift. This drives heavy
    //! concurrent join/leave churn on one channel and asserts the final
    //! `member_count` matches the net effect exactly — any lost or
    //! double-applied update would show up as drift.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn member_count(s: &Storage, channel_id: u64) -> u64 {
        let data = s.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()).unwrap().unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&data).unwrap();
        meta.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0)
    }

    #[test]
    fn concurrent_joins_and_leaves_never_drift_member_count() {
        let (s, _d) = db();
        let channel_id = 555u64;
        s.put_cf(
            cf::CHANNELS,
            &channel_id.to_be_bytes(),
            &serde_json::to_vec(&serde_json::json!({"member_count": 0, "channel_type": 0})).unwrap(),
        )
        .unwrap();

        const MEMBERS: u64 = 40;
        // Every thread joins its own unique address, then immediately leaves
        // — net effect on `member_count` must be exactly 0, regardless of
        // how many threads interleave their add/remove critical sections.
        std::thread::scope(|scope| {
            for i in 0..MEMBERS {
                let s = &s;
                scope.spawn(move || {
                    let addr = format!("klv1member{i}");
                    let added = s.add_channel_member(channel_id, &addr, 1_000, "member").unwrap();
                    assert!(added, "each unique address must successfully join exactly once");
                    s.remove_channel_member_and_raise_epoch_floor(channel_id, &addr)
                        .unwrap();
                });
            }
        });

        assert_eq!(
            member_count(&s, channel_id),
            0,
            "member_count must net back to 0 — any drift means a concurrent \
             add/remove pair raced the CHANNELS row RMW"
        );
    }

    /// Private channels (channel_type == 2) must have their key-epoch floor
    /// raised on every removal, even under heavy concurrent churn on
    /// DIFFERENT members of the same channel — the floor write must never be
    /// silently lost to a racing `member_count` update on the same row.
    #[test]
    fn concurrent_removals_on_private_channel_always_leave_a_floor_raised() {
        let (s, _d) = db();
        let channel_id = 556u64;
        s.put_cf(
            cf::CHANNELS,
            &channel_id.to_be_bytes(),
            &serde_json::to_vec(&serde_json::json!({"member_count": 0, "channel_type": 2})).unwrap(),
        )
        .unwrap();

        const MEMBERS: u64 = 20;
        for i in 0..MEMBERS {
            s.add_channel_member(channel_id, &format!("klv1priv{i}"), 1_000, "member").unwrap();
        }
        assert_eq!(member_count(&s, channel_id), MEMBERS);

        std::thread::scope(|scope| {
            for i in 0..MEMBERS {
                let s = &s;
                scope.spawn(move || {
                    s.remove_channel_member_and_raise_epoch_floor(channel_id, &format!("klv1priv{i}"))
                        .unwrap();
                });
            }
        });

        assert_eq!(member_count(&s, channel_id), 0, "all members removed");
        // No CHANNEL_KEYS envelopes exist for this scope, so max_channel_key_epoch
        // is 0 and the floor should have been raised to 1 (max_epoch + 1) by
        // the first removal to observe an unraised floor — and never reset by
        // a later racing removal, since `new_floor` is monotonic (`cur.max(...)`).
        let data = s.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()).unwrap().unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&data).unwrap();
        let floor = meta.get("key_epoch_floor").and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!(floor, 1, "key_epoch_floor must be raised, not lost, under concurrent removals");
    }

    /// Code Audit follow-up: removing a wallet that was never actually a
    /// local member (e.g. a `ChannelKick`/`ChannelBan`/`ChannelLeave`
    /// reconciled for a wallet whose `ChannelJoin` this node never
    /// received) must NOT decrement `member_count` — the pre-W18 code did
    /// this unconditionally and this rewrite must not resurrect that bug.
    #[test]
    fn removing_a_non_member_does_not_decrement_member_count() {
        let (s, _d) = db();
        let channel_id = 557u64;
        s.put_cf(
            cf::CHANNELS,
            &channel_id.to_be_bytes(),
            &serde_json::to_vec(&serde_json::json!({"member_count": 3, "channel_type": 0})).unwrap(),
        )
        .unwrap();

        s.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1never-a-member")
            .unwrap();

        assert_eq!(
            member_count(&s, channel_id),
            3,
            "member_count must be unchanged — the removed address was never a member"
        );
    }
}

#[cfg(test)]
mod pending_channel_member_removal_tests {
    //! W18 residual, found + fixed 2026-08-19: a removal for a channel not
    //! yet known locally now persists a pending claim instead of silently
    //! dropping the P2d key-epoch-floor raise forever — mirrors W14's
    //! `ChannelDelete`-before-`ChannelCreate` pending-claim mechanism.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    /// Code Audit WARNING #2 regression: a concurrent removal racing the
    /// exact moment a channel is created must never have its pending claim
    /// orphaned. Before the fix, the create path's row write and its claim
    /// replay were separate critical sections (or entirely unlocked), so a
    /// racing removal could squeeze a fresh claim into the gap between them
    /// and have it missed forever. Now both run under one
    /// `channel_membership_lock` acquisition
    /// (`put_channel_and_replay_pending_member_removals`), so any racing
    /// removal is strictly ordered before or after that whole critical
    /// section: before → its claim is durably persisted in time to be
    /// replayed; after → it observes `CHANNELS` already present and applies
    /// directly, never writing a claim at all. Either way nothing survives
    /// as a dangling claim. Runs many fresh channel_ids to exercise both
    /// interleavings across scheduler runs.
    #[test]
    fn concurrent_removal_racing_channel_creation_is_never_orphaned() {
        for i in 0..50u64 {
            let (s, _d) = db();
            let s = std::sync::Arc::new(s);
            let channel_id = 10_000 + i;
            let channel_bytes = serde_json::to_vec(
                &serde_json::json!({"member_count": 0, "channel_type": 2}),
            )
            .unwrap();

            std::thread::scope(|scope| {
                let s1 = s.clone();
                let bytes = channel_bytes.clone();
                scope.spawn(move || {
                    s1.put_channel_and_replay_pending_member_removals(channel_id, &bytes)
                        .unwrap();
                });
                let s2 = s.clone();
                scope.spawn(move || {
                    s2.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1racer")
                        .unwrap();
                });
            });

            let claims = s.take_pending_channel_member_removals(channel_id).unwrap();
            assert!(
                claims.is_empty(),
                "iteration {i}: a pending claim survived a create/removal race — \
                 orphaned (WARNING #2 regression)"
            );
        }
    }

    #[test]
    fn removal_for_unknown_channel_persists_a_pending_claim() {
        let (s, _d) = db();
        let channel_id = 700u64;
        // Channel doesn't exist locally yet.
        s.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1late")
            .unwrap();

        // Security Audit WARNING-3 fix: the persisted timestamp is the
        // node's own clock (not caller-supplied), so this only asserts the
        // address round-trips — not an exact stamp value.
        let claims = s.take_pending_channel_member_removals(channel_id).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "klv1late");
    }

    #[test]
    fn multiple_independent_removals_all_persist_and_replay() {
        let (s, _d) = db();
        let channel_id = 701u64;
        s.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1a")
            .unwrap();
        s.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1b")
            .unwrap();
        s.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1c")
            .unwrap();

        let mut claims: Vec<String> = s
            .take_pending_channel_member_removals(channel_id)
            .unwrap()
            .into_iter()
            .map(|(addr, _ts)| addr)
            .collect();
        claims.sort();
        assert_eq!(claims, vec!["klv1a", "klv1b", "klv1c"]);
        // One-shot: consumed claims are gone.
        assert!(s.take_pending_channel_member_removals(channel_id).unwrap().is_empty());
    }

    /// End-to-end convergence: a private channel's key-epoch floor still
    /// gets raised for a member removed BEFORE the channel existed locally,
    /// once the channel is created and the claim replayed — the actual
    /// property W14's pending-claim pattern exists to guarantee.
    #[test]
    fn floor_raise_survives_removal_before_channel_create_once_replayed() {
        let (s, _d) = db();
        let channel_id = 702u64;

        // Late removal arrives first — channel unknown, claim persisted.
        s.remove_channel_member_and_raise_epoch_floor(channel_id, "klv1departed")
            .unwrap();

        // Channel now gets created (private) with the departed member never
        // having been re-added — mirrors router.rs's ChannelCreate handler:
        // create the row, then replay pending removal claims.
        s.put_cf(
            cf::CHANNELS,
            &channel_id.to_be_bytes(),
            &serde_json::to_vec(&serde_json::json!({"member_count": 0, "channel_type": 2})).unwrap(),
        )
        .unwrap();
        let claims = s.take_pending_channel_member_removals(channel_id).unwrap();
        for (address, _requested_at) in claims {
            s.remove_channel_member_and_raise_epoch_floor(channel_id, &address)
                .unwrap();
        }

        let data = s.get_cf(cf::CHANNELS, &channel_id.to_be_bytes()).unwrap().unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&data).unwrap();
        let floor = meta.get("key_epoch_floor").and_then(|v| v.as_u64()).unwrap_or(0);
        assert_eq!(
            floor, 1,
            "key_epoch_floor must be raised on replay — this is the actual W18 residual bug fixed"
        );
    }

    #[test]
    fn cap_drops_beyond_256_per_channel() {
        let (s, _d) = db();
        let channel_id = 703u64;
        for i in 0..300u64 {
            s.remove_channel_member_and_raise_epoch_floor(channel_id, &format!("klv1n{i}"))
                .unwrap();
        }
        let claims = s.take_pending_channel_member_removals(channel_id).unwrap();
        assert!(claims.len() <= 256, "must not exceed the per-channel cap");
    }
}

#[cfg(test)]
mod channel_key_envelope_lock_tests {
    //! Audit final pre-mainnet W19a: `put_channel_key_envelope_fww`'s
    //! exists-check + put used to have no lock, so two concurrent publishers
    //! for the SAME `(key_scope, target, author, device, epoch)` tuple could
    //! both pass the exists-check and both write — the LAST write physically
    //! wins, violating the documented first-write-wins guarantee (an
    //! attacker racing a victim's genuine key-envelope publish could clobber
    //! the victim's wrapped key). This proves the OUTCOME the lock
    //! guarantees (exactly one `Stored`, all others `AlreadyPresent`) rather
    //! than an external timing measurement — see
    //! `pending_channel_delete_lock_tests` above for why an
    //! outside-the-call probe can't prove mutual exclusion.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn concurrent_publishers_for_the_same_tuple_yield_exactly_one_stored() {
        let (s, _d) = db();
        let s = std::sync::Arc::new(s);
        let key_scope = [7u8; 32];
        const RACERS: usize = 24;
        let stored_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        std::thread::scope(|scope| {
            for i in 0..RACERS {
                let s = s.clone();
                let stored_count = stored_count.clone();
                scope.spawn(move || {
                    // Distinct VALUE per racer (so a wrong winner would be
                    // detectable), identical scope/target/author/device/epoch
                    // — the FWW identity tuple that must serialize.
                    let value = format!("envelope-from-racer-{i}").into_bytes();
                    let outcome = s
                        .put_channel_key_envelope_fww(
                            &key_scope, "target", "author", "device1", 1, &value, 100,
                        )
                        .unwrap();
                    if outcome == KeyEnvelopeStore::Stored {
                        stored_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });

        assert_eq!(
            stored_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly one concurrent publisher must win Stored for the same \
             (scope,target,author,device,epoch) — more than one means the \
             FWW guarantee was violated (a later write clobbered an earlier one)"
        );
    }
}

#[cfg(test)]
mod stat_counter_merge_tests {
    //! Audit final pre-mainnet W19b: `increment_stat`/`decrement_stat` used
    //! to be a plain get-then-put — concurrent callers raced the same
    //! read-modify-write, causing permanent counter drift. Now backed by a
    //! RocksDB merge (`stat_counter_merge`), which accumulates deltas
    //! without any application-level lock. This drives concurrent
    //! increments AND decrements from many threads and asserts the final
    //! `get_stat` value matches the exact net total — any drift would mean
    //! the merge operator lost or double-applied an operand.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn concurrent_increments_and_decrements_match_exact_net_total() {
        let (s, _d) = db();
        let s = std::sync::Arc::new(s);
        let key = super::super::schema::state_keys::TOTAL_MESSAGES;

        const INCREMENTERS: u64 = 30;
        const INCS_PER_THREAD: u64 = 50;
        const DECREMENTERS: u64 = 10;
        const DECS_PER_THREAD: u64 = 50;
        let expected_net = INCREMENTERS * INCS_PER_THREAD - DECREMENTERS * DECS_PER_THREAD;

        std::thread::scope(|scope| {
            for _ in 0..INCREMENTERS {
                let s = s.clone();
                scope.spawn(move || {
                    for _ in 0..INCS_PER_THREAD {
                        s.increment_stat(key).unwrap();
                    }
                });
            }
            for _ in 0..DECREMENTERS {
                let s = s.clone();
                scope.spawn(move || {
                    for _ in 0..DECS_PER_THREAD {
                        s.decrement_stat(key).unwrap();
                    }
                });
            }
        });

        assert_eq!(
            s.get_stat(key).unwrap(),
            expected_net,
            "the merge operator must accumulate every concurrent delta exactly \
             — any drift would mean an operand was lost or double-applied"
        );
    }

    /// The merge function is invoked identically for full-merge (base +
    /// operands) and partial-merge (operands + operands, used internally
    /// during compaction) — this forces a real compaction between writes so
    /// partial-merge actually runs, not just full-merge at read time.
    #[test]
    fn survives_compaction_between_merges() {
        let (s, _d) = db();
        let key = super::super::schema::state_keys::TOTAL_CHANNELS;
        for _ in 0..25 {
            s.increment_stat(key).unwrap();
        }
        s.decrement_stat(key).unwrap();
        s.decrement_stat(key).unwrap();
        // Force compaction so any pending merge operands are resolved via
        // partial_merge / full_merge, not just read-time folding.
        s.db.compact_range_cf::<&[u8], &[u8]>(&s.cf_handle(cf::NODE_STATE).unwrap(), None, None);
        for _ in 0..5 {
            s.increment_stat(key).unwrap();
        }
        assert_eq!(s.get_stat(key).unwrap(), 25 - 2 + 5);
    }
}

#[cfg(test)]
mod message_pagination_tests {
    use super::*;
    use crate::storage::schema::{encode_channel_msg_key, message_key_upper_bound};
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    /// Seed `count` channel messages with strictly increasing timestamps
    /// `base_ts..base_ts+count`, msg_id derived from the index so each is
    /// distinguishable, and returns their keys in seeded (ascending) order.
    fn seed_channel_messages(s: &Storage, channel_id: u64, base_ts: u64, count: u64) -> Vec<Vec<u8>> {
        let mut keys = Vec::with_capacity(count as usize);
        for i in 0..count {
            let mut msg_id = [0u8; 32];
            msg_id[24..].copy_from_slice(&i.to_be_bytes());
            let key = encode_channel_msg_key(channel_id, base_ts + i, &msg_id);
            s.put_cf(cf::CHANNEL_MSGS, &key, b"{}").unwrap();
            keys.push(key);
        }
        keys
    }

    #[test]
    fn no_cursor_returns_newest_page_not_oldest() {
        // Regression test for the bug this session fixed: a fresh conversation
        // open (no cursor) must land on the newest messages, not the oldest —
        // it previously always returned the oldest `limit` via `prefix_iter_cf`.
        let (s, _d) = db();
        let channel_id = 100;
        let all_keys = seed_channel_messages(&s, channel_id, 1_000, 10);
        let prefix = channel_id.to_be_bytes();

        let limit = 4;
        let mut newest = s
            .reverse_iter_cf(cf::CHANNEL_MSGS, &message_key_upper_bound(&prefix), &prefix, limit)
            .unwrap();
        newest.reverse(); // route handlers reverse back to ascending order

        let newest_keys: Vec<Vec<u8>> = newest.into_iter().map(|(k, _)| k).collect();
        // The 4 newest of 10 seeded messages are the last 4 in seed order.
        assert_eq!(newest_keys, all_keys[6..10].to_vec());

        // Sanity: the OLD (buggy) behavior would have returned the first 4 —
        // explicitly confirm the fix actually changed the selected window.
        let oldest = s.prefix_iter_cf(cf::CHANNEL_MSGS, &prefix, limit).unwrap();
        let oldest_keys: Vec<Vec<u8>> = oldest.into_iter().map(|(k, _)| k).collect();
        assert_eq!(oldest_keys, all_keys[0..4].to_vec());
        assert_ne!(newest_keys, oldest_keys);
    }

    #[test]
    fn before_cursor_returns_the_page_immediately_preceding_it() {
        let (s, _d) = db();
        let channel_id = 101;
        let all_keys = seed_channel_messages(&s, channel_id, 2_000, 10);
        let prefix = channel_id.to_be_bytes();

        // "Load older" from the 7th message (index 6) should return the 4
        // immediately before it (indices 2..6), newest-first before reversal.
        let cursor_key = &all_keys[6];
        let mut older = s
            .reverse_iter_cf_before(cf::CHANNEL_MSGS, cursor_key, &prefix, 4)
            .unwrap();
        older.reverse();
        let older_keys: Vec<Vec<u8>> = older.into_iter().map(|(k, _)| k).collect();
        assert_eq!(older_keys, all_keys[2..6].to_vec());
    }

    #[test]
    fn message_key_upper_bound_does_not_leak_into_another_channel() {
        let (s, _d) = db();
        seed_channel_messages(&s, 200, 5_000, 3);
        seed_channel_messages(&s, 201, 5_000, 3);
        let prefix_200 = 200u64.to_be_bytes();

        let entries = s
            .reverse_iter_cf(cf::CHANNEL_MSGS, &message_key_upper_bound(&prefix_200), &prefix_200, 100)
            .unwrap();
        assert_eq!(entries.len(), 3);
        for (key, _) in &entries {
            assert!(key.starts_with(&prefix_200));
        }
    }
}

#[cfg(test)]
mod backfill_edit_delete_markers_tests {
    use super::*;
    use crate::messages::envelope::Envelope;
    use crate::messages::types::{
        ChatMessagePayload, DeletePayload, DirectMessagePayload, MessageType,
    };
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn put_message(s: &Storage, envelope: &Envelope) {
        s.put_cf(
            cf::MESSAGES,
            &envelope.msg_id,
            &rmp_serde::to_vec_named(envelope).unwrap(),
        )
        .unwrap();
    }

    /// Regression for audit final pre-mainnet W6: a fresh node upgraded to
    /// 0.95.0+ must still learn about ChatDelete/DirectMessageDelete
    /// envelopes that were applied and stored BEFORE the upgrade — this is
    /// what makes the backfill fix retroactive rather than only covering
    /// edits/deletes made going forward.
    #[test]
    fn backfills_existing_chat_and_dm_deletes_from_messages() {
        let (s, _d) = db();

        // A ChatDelete already stored (as if applied by a pre-0.95.0 node),
        // with NO corresponding CHANNEL_EDIT_DELETE_MSGS row yet. The
        // original ChatMessage it targets must also exist — the migration
        // (post security-audit fix) derives channel_id from THAT message,
        // never from the delete's own (author-controlled, unvalidated)
        // payload field.
        let channel_id = 55u64;
        let chat_target = [1u8; 32];
        let chat_delete_id = [2u8; 32];
        put_message(
            &s,
            &Envelope {
                version: crate::messages::envelope::PROTOCOL_VERSION,
                msg_type: MessageType::ChatMessage,
                msg_id: chat_target,
                author: "klv1author".to_string(),
                timestamp: 800,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&ChatMessagePayload {
                    channel_id,
                    content: "original".to_string(),
                    content_rating: Default::default(),
                    reply_to: None,
                    mentions: vec![],
                    attachments: vec![],
                    enc_content: None,
                    enc_nonce: None,
                    key_epoch: None,
                })
                .unwrap(),
                signature: vec![],
                relay_path: vec![],
            },
        );
        put_message(
            &s,
            &Envelope {
                version: crate::messages::envelope::PROTOCOL_VERSION,
                msg_type: MessageType::ChatDelete,
                msg_id: chat_delete_id,
                author: "klv1author".to_string(),
                timestamp: 1_000,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&DeletePayload {
                    target_id: chat_target,
                    // Deliberately a DIFFERENT channel_id than the real one
                    // (55) — proves the migration ignores this field and
                    // derives the real channel from the original message.
                    channel_id: Some(999),
                })
                .unwrap(),
                signature: vec![],
                relay_path: vec![],
            },
        );

        // A DirectMessage + its DirectMessageDelete, same pre-upgrade state.
        let conversation_id = [9u8; 32];
        let dm_target = [3u8; 32];
        let dm_delete_id = [4u8; 32];
        put_message(
            &s,
            &Envelope {
                version: crate::messages::envelope::PROTOCOL_VERSION,
                msg_type: MessageType::DirectMessage,
                msg_id: dm_target,
                author: "klv1sender".to_string(),
                timestamp: 900,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&DirectMessagePayload {
                    recipient: "klv1recipient".to_string(),
                    conversation_id,
                    content: vec![1, 2, 3],
                    nonce: [0u8; 24],
                    key_epoch: 1,
                    reply_to: None,
                    attachments: vec![],
                })
                .unwrap(),
                signature: vec![],
                relay_path: vec![],
            },
        );
        put_message(
            &s,
            &Envelope {
                version: crate::messages::envelope::PROTOCOL_VERSION,
                msg_type: MessageType::DirectMessageDelete,
                msg_id: dm_delete_id,
                author: "klv1sender".to_string(),
                timestamp: 1_100,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&DeletePayload {
                    target_id: dm_target,
                    channel_id: None,
                })
                .unwrap(),
                signature: vec![],
                relay_path: vec![],
            },
        );

        // A plain ChatMessage must NOT be indexed (only edit/delete types).
        put_message(
            &s,
            &Envelope {
                version: crate::messages::envelope::PROTOCOL_VERSION,
                msg_type: MessageType::ChatMessage,
                msg_id: [5u8; 32],
                author: "klv1author".to_string(),
                timestamp: 950,
                lamport_ts: 0,
                payload: rmp_serde::to_vec_named(&ChatMessagePayload {
                    channel_id,
                    content: "hi".to_string(),
                    content_rating: Default::default(),
                    reply_to: None,
                    mentions: vec![],
                    attachments: vec![],
                    enc_content: None,
                    enc_nonce: None,
                    key_epoch: None,
                })
                .unwrap(),
                signature: vec![],
                relay_path: vec![],
            },
        );

        // Sentinel absent before the migration runs.
        assert_eq!(s.get_stat(crate::storage::schema::state_keys::EDIT_DELETE_MARKERS_INDEXED).unwrap(), 0);

        s.backfill_edit_delete_markers().unwrap();

        // Sentinel now set (idempotency guard).
        assert!(s.get_stat(crate::storage::schema::state_keys::EDIT_DELETE_MARKERS_INDEXED).unwrap() > 0);

        // ChatDelete indexed under CHANNEL_EDIT_DELETE_MSGS[channel_id].
        let chat_rows = s
            .prefix_iter_cf(cf::CHANNEL_EDIT_DELETE_MSGS, &channel_id.to_be_bytes(), 10)
            .unwrap();
        assert_eq!(chat_rows.len(), 1);
        let msg_id: [u8; 32] = chat_rows[0].0[16..48].try_into().unwrap();
        assert_eq!(msg_id, chat_delete_id);

        // DirectMessageDelete indexed under DM_EDIT_DELETE_MSGS[conversation_id]
        // — proves the migration recovered conversation_id from the ORIGINAL
        // DirectMessage's own payload, same as the live indexing path.
        let dm_rows = s
            .prefix_iter_cf(cf::DM_EDIT_DELETE_MSGS, &conversation_id[..], 10)
            .unwrap();
        assert_eq!(dm_rows.len(), 1);
        let dm_msg_id: [u8; 32] = dm_rows[0].0[40..72].try_into().unwrap();
        assert_eq!(dm_msg_id, dm_delete_id);

        // Re-running is a no-op that doesn't duplicate rows (idempotent).
        s.backfill_edit_delete_markers().unwrap();
        let chat_rows_again = s
            .prefix_iter_cf(cf::CHANNEL_EDIT_DELETE_MSGS, &channel_id.to_be_bytes(), 10)
            .unwrap();
        assert_eq!(chat_rows_again.len(), 1);
    }
}

#[cfg(test)]
mod count_prefix_cf_tests {
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    /// Security audit final pre-mainnet W20: `count_prefix_cf` must return
    /// the exact same count `prefix_iter_cf(...).len()` would, without
    /// materializing any key/value bytes.
    #[test]
    fn count_prefix_cf_matches_prefix_iter_cf_len() {
        let (s, _d) = db();
        let prefix = [7u8; 32];
        for i in 0..5u8 {
            let mut key = prefix.to_vec();
            key.push(i);
            s.put_cf(cf::COUNTER_VOTES, &key, b"x").unwrap();
        }
        // An unrelated prefix must not be counted.
        s.put_cf(cf::COUNTER_VOTES, &[9u8; 33], b"x").unwrap();

        let counted = s.count_prefix_cf(cf::COUNTER_VOTES, &prefix, 10_000).unwrap();
        let materialized = s.prefix_iter_cf(cf::COUNTER_VOTES, &prefix, 10_000).unwrap();
        assert_eq!(counted, 5);
        assert_eq!(counted as usize, materialized.len());
    }

    #[test]
    fn count_prefix_cf_respects_limit() {
        let (s, _d) = db();
        let prefix = [3u8; 32];
        for i in 0..10u8 {
            let mut key = prefix.to_vec();
            key.push(i);
            s.put_cf(cf::COUNTER_VOTES, &key, b"x").unwrap();
        }
        assert_eq!(s.count_prefix_cf(cf::COUNTER_VOTES, &prefix, 4).unwrap(), 4);
        assert_eq!(s.count_prefix_cf(cf::COUNTER_VOTES, &prefix, 10_000).unwrap(), 10);
    }

    #[test]
    fn count_prefix_cf_no_matches_is_zero() {
        let (s, _d) = db();
        assert_eq!(s.count_prefix_cf(cf::COUNTER_VOTES, &[1u8; 32], 10_000).unwrap(), 0);
    }

    #[test]
    fn count_prefix_cf_with_a_genuinely_empty_prefix_counts_the_whole_cf() {
        // Code-audit follow-up on W20: the previous "empty prefix" test
        // actually used a full 32-byte prefix with no matches, not an
        // empty `&[]` prefix. `&[]` is a real, valid input (every key
        // "starts_with" an empty slice), so it should count every row in
        // the column family regardless of which of several distinct
        // prefixes each row happens to have.
        let (s, _d) = db();
        s.put_cf(cf::COUNTER_VOTES, &[1u8; 33], b"x").unwrap();
        s.put_cf(cf::COUNTER_VOTES, &[2u8; 33], b"x").unwrap();
        s.put_cf(cf::COUNTER_VOTES, &[3u8; 33], b"x").unwrap();
        assert_eq!(s.count_prefix_cf(cf::COUNTER_VOTES, &[], 10_000).unwrap(), 3);
    }

    #[test]
    fn get_comment_count_reflects_real_writes() {
        let (s, _d) = db();
        let post_id = [4u8; 32];
        for i in 0..3u8 {
            let key = crate::storage::schema::encode_news_comment_key(&post_id, 1_000 + i as u64, &[i; 32]);
            s.put_cf(cf::NEWS_COMMENTS, &key, &[]).unwrap();
        }
        assert_eq!(s.get_comment_count(&post_id).unwrap(), 3);
        assert_eq!(s.get_comment_count(&[0u8; 32]).unwrap(), 0);
    }

    #[test]
    fn get_counter_vote_count_reflects_real_writes() {
        let (s, _d) = db();
        let target_id = [5u8; 32];
        s.store_counter_vote(&target_id, "klv1voter1", 1_000).unwrap();
        s.store_counter_vote(&target_id, "klv1voter2", 1_001).unwrap();
        assert_eq!(s.get_counter_vote_count(&target_id).unwrap(), 2);

        // Same voter voting again overwrites their own row (idempotent,
        // one vote per voter) rather than double-counting — this is the
        // EXISTING `encode_counter_vote_key(target, voter)` semantic,
        // unchanged by this fix; a naive increment-only cached counter
        // would have gotten this wrong, which is why this fix uses a raw
        // recount instead.
        s.store_counter_vote(&target_id, "klv1voter1", 1_002).unwrap();
        assert_eq!(s.get_counter_vote_count(&target_id).unwrap(), 2);
    }
}

#[cfg(test)]
mod dm_recipient_count_tests {
    //! Audit final pre-mainnet W11.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn increment_and_decrement_are_paired() {
        let (s, _d) = db();
        let recipient = b"klv1recipient";
        assert_eq!(s.get_dm_recipient_count(recipient).unwrap(), 0);
        s.increment_dm_recipient_count(recipient).unwrap();
        s.increment_dm_recipient_count(recipient).unwrap();
        assert_eq!(s.get_dm_recipient_count(recipient).unwrap(), 2);
        s.decrement_dm_recipient_count(recipient).unwrap();
        assert_eq!(s.get_dm_recipient_count(recipient).unwrap(), 1);
    }

    #[test]
    fn decrement_saturates_at_zero() {
        let (s, _d) = db();
        let recipient = b"klv1recipient";
        s.decrement_dm_recipient_count(recipient).unwrap();
        s.decrement_dm_recipient_count(recipient).unwrap();
        assert_eq!(s.get_dm_recipient_count(recipient).unwrap(), 0);
    }

    #[test]
    fn counts_are_independent_per_recipient() {
        let (s, _d) = db();
        s.increment_dm_recipient_count(b"klv1alice").unwrap();
        s.increment_dm_recipient_count(b"klv1alice").unwrap();
        s.increment_dm_recipient_count(b"klv1bob").unwrap();
        assert_eq!(s.get_dm_recipient_count(b"klv1alice").unwrap(), 2);
        assert_eq!(s.get_dm_recipient_count(b"klv1bob").unwrap(), 1);
    }
}

#[cfg(test)]
mod store_notification_capped_tests {
    //! Security Audit follow-up, audit final pre-mainnet W31: the
    //! time-based notification reaper alone doesn't bound growth under a
    //! sustained flood from a single already-rate-limited sender; this
    //! per-address cap is the orthogonal backstop.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    fn n(i: u8) -> serde_json::Value {
        serde_json::json!({"n": i})
    }

    #[test]
    fn evicts_oldest_when_at_cap() {
        let (s, _d) = db();
        let addr = "klv1alice";
        for i in 0..5u8 {
            s.store_notification_capped(addr, &[i; 32], 1000 + i as u64, &n(i), 5)
                .unwrap();
        }
        // At cap (5). The 6th store must evict the oldest (timestamp 1000).
        s.store_notification_capped(addr, &[5; 32], 1005, &n(5), 5)
            .unwrap();

        let stored = s.get_notifications(addr, None, 100).unwrap();
        assert_eq!(stored.len(), 5, "count must stay at cap, not grow to 6");
        let survivors: Vec<u64> = stored.iter().map(|v| v["n"].as_u64().unwrap()).collect();
        assert!(
            !survivors.contains(&0),
            "the oldest notification (n=0, ts=1000) must have been evicted"
        );
        assert!(
            survivors.contains(&5),
            "the newly-stored notification (n=5) must be present"
        );
    }

    #[test]
    fn does_not_evict_when_under_cap() {
        let (s, _d) = db();
        let addr = "klv1bob";
        for i in 0..3u8 {
            s.store_notification_capped(addr, &[i; 32], 1000 + i as u64, &n(i), 10)
                .unwrap();
        }
        let stored = s.get_notifications(addr, None, 100).unwrap();
        assert_eq!(stored.len(), 3, "under cap — nothing should be evicted");
    }

    #[test]
    fn cap_is_per_address_not_global() {
        let (s, _d) = db();
        for i in 0..3u8 {
            s.store_notification_capped("klv1alice", &[i; 32], 1000 + i as u64, &n(i), 3)
                .unwrap();
        }
        // A different address must have its own independent budget —
        // storing for bob must not evict any of alice's rows even though
        // the CF-wide total is now over what a single address's cap is.
        s.store_notification_capped("klv1bob", &[9; 32], 2000, &n(9), 3)
            .unwrap();
        assert_eq!(s.get_notifications("klv1alice", None, 100).unwrap().len(), 3);
        assert_eq!(s.get_notifications("klv1bob", None, 100).unwrap().len(), 1);
    }

    #[test]
    fn zero_cap_means_unlimited() {
        let (s, _d) = db();
        let addr = "klv1carol";
        for i in 0..10u8 {
            s.store_notification_capped(addr, &[i; 32], 1000 + i as u64, &n(i), 0)
                .unwrap();
        }
        assert_eq!(s.get_notifications(addr, None, 100).unwrap().len(), 10);
    }
}

#[cfg(test)]
mod news_followers_visibility_tests {
    //! Audit W37: `NewsPostPayload.visibility == Followers` was decoded and
    //! stored but never checked on any read path. This covers the pure
    //! predicate; `api::routes` and `network::news_sync` cover the actual
    //! read-path wiring.
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Storage, TempDir) {
        let dir = TempDir::new().unwrap();
        (Storage::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn author_always_sees_their_own_post() {
        let (s, _d) = db();
        assert!(s.news_followers_post_visible_to("klv1author", Some("klv1author")));
    }

    #[test]
    fn unauthenticated_caller_never_sees_it() {
        let (s, _d) = db();
        assert!(!s.news_followers_post_visible_to("klv1author", None));
    }

    #[test]
    fn non_follower_does_not_see_it() {
        let (s, _d) = db();
        assert!(!s.news_followers_post_visible_to("klv1author", Some("klv1stranger")));
    }

    #[test]
    fn a_real_follower_sees_it() {
        let (s, _d) = db();
        s.apply_follow_edge("klv1fan", "klv1author", true, 1_000).unwrap();
        assert!(s.news_followers_post_visible_to("klv1author", Some("klv1fan")));
    }

    #[test]
    fn unfollowing_revokes_visibility() {
        let (s, _d) = db();
        s.apply_follow_edge("klv1fan", "klv1author", true, 1_000).unwrap();
        assert!(s.news_followers_post_visible_to("klv1author", Some("klv1fan")));
        s.apply_follow_edge("klv1fan", "klv1author", false, 2_000).unwrap();
        assert!(!s.news_followers_post_visible_to("klv1author", Some("klv1fan")));
    }
}
