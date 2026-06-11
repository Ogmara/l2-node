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
/// Claim format: `"ogmara-device-claim:{device_pubkey_hex}:{wallet_address}:{timestamp}"`
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
                if *name == cf::CHANNEL_MSGS {
                    // Key: (channel_id:8, lamport_ts:8, msg_id:32) — prefix by channel_id
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
                }
                if *name == cf::DM_MESSAGES || *name == cf::NEWS_COMMENTS {
                    // DM_MESSAGES key: (conversation_id:32, timestamp:8, msg_id:32)
                    // NEWS_COMMENTS key: (post_id:32, timestamp:8, msg_id:32)
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                }
                if *name == cf::DM_CONVERSATIONS {
                    // Key: (wallet_address:62, !timestamp:8, conversation_id:32)
                    // klv1 bech32 addresses with 32-byte Ed25519 keys are 62 characters
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(62));
                }
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let db = RocksDb::open_cf_descriptors(&db_opts, path, cf_descriptors)
            .with_context(|| format!("opening RocksDB at {}", path.display()))?;

        Ok(Self { db: Arc::new(db) })
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

    /// Execute a write batch atomically across multiple column families.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        self.db
            .write(batch)
            .context("executing write batch")
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

    /// Store a message envelope and atomically increment the message counter.
    ///
    /// Uses a WriteBatch to ensure the message and its counter update are
    /// written together, preventing counter drift on partial failure.
    pub fn store_message(
        &self,
        msg_id: &[u8; 32],
        envelope_bytes: &[u8],
    ) -> Result<()> {
        let messages_cf = self.cf_handle(cf::MESSAGES)?;
        let state_cf = self.cf_handle(cf::NODE_STATE)?;
        let new_count = self.get_stat(super::schema::state_keys::TOTAL_MESSAGES)? + 1;

        let mut batch = WriteBatch::default();
        batch.put_cf(&messages_cf, msg_id, envelope_bytes);
        batch.put_cf(&state_cf, super::schema::state_keys::TOTAL_MESSAGES, &new_count.to_be_bytes());
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
    pub fn follow(&self, follower: &str, followed: &str) -> Result<()> {
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
    pub fn unfollow(&self, follower: &str, followed: &str) -> Result<()> {
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
    pub fn toggle_news_reaction(
        &self,
        msg_id: &[u8; 32],
        emoji: &str,
        author: &str,
        remove: bool,
    ) -> Result<()> {
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
    pub fn add_repost(
        &self,
        original_id: &[u8; 32],
        reposter: &str,
        repost_msg_id: &[u8; 32],
    ) -> Result<()> {
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
    /// and DELEGATIONS column families.
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

    /// Read a u64 stat counter from NODE_STATE.
    pub fn get_stat(&self, key: &[u8]) -> Result<u64> {
        match self.get_cf(cf::NODE_STATE, key)? {
            Some(bytes) if bytes.len() == 8 => {
                Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
            }
            _ => Ok(0),
        }
    }

    /// Increment a u64 stat counter in NODE_STATE by 1.
    pub fn increment_stat(&self, key: &[u8]) -> Result<u64> {
        let new_val = self.get_stat(key)? + 1;
        self.put_cf(cf::NODE_STATE, key, &new_val.to_be_bytes())?;
        Ok(new_val)
    }

    /// Decrement a u64 stat counter, saturating at zero.
    pub fn decrement_stat(&self, key: &[u8]) -> Result<u64> {
        let new_val = self.get_stat(key)?.saturating_sub(1);
        self.put_cf(cf::NODE_STATE, key, &new_val.to_be_bytes())?;
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
        let entries = self.prefix_iter_cf(cf::NEWS_COMMENTS, post_id, 10_000)?;
        Ok(entries.len() as u64)
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
    /// and CHAT_REACTION_COUNTS column families.
    pub fn toggle_chat_reaction(
        &self,
        msg_id: &[u8; 32],
        emoji: &str,
        author: &str,
        remove: bool,
    ) -> Result<()> {
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
        let entries = self.prefix_iter_cf(cf::COUNTER_VOTES, target_id, 10_000)?;
        Ok(entries.len() as u64)
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
    pub fn put_channel_key_envelope_fww(
        &self,
        key_scope: &[u8; 32],
        target: &str,
        device_id_hex: &str,
        epoch: u64,
        value: &[u8],
        scope_cap: usize,
    ) -> Result<KeyEnvelopeStore> {
        use super::schema;
        let key = schema::encode_channel_key(key_scope, target, device_id_hex, epoch);
        if self.exists_cf(cf::CHANNEL_KEYS, &key)? {
            return Ok(KeyEnvelopeStore::AlreadyPresent);
        }
        // Cap is checked on the new key's absence: scan up to scope_cap+1 entries.
        let prefix = schema::encode_channel_key_scope_prefix(key_scope);
        let existing = self.prefix_iter_cf(cf::CHANNEL_KEYS, &prefix, scope_cap + 1)?;
        if existing.len() >= scope_cap {
            return Ok(KeyEnvelopeStore::ScopeFull);
        }
        self.put_cf(cf::CHANNEL_KEYS, &key, value)?;
        Ok(KeyEnvelopeStore::Stored)
    }

    /// Get the latest-epoch wrapped key envelope for one `(scope, target, device)`.
    /// Returns `(epoch, value)`.
    pub fn get_channel_key_envelope_latest(
        &self,
        key_scope: &[u8; 32],
        target: &str,
        device_id_hex: &str,
    ) -> Result<Option<(u64, Vec<u8>)>> {
        use super::schema;
        let prefix = schema::encode_channel_key_device_prefix(key_scope, target, device_id_hex);
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

    /// Get the wrapped key envelope for an exact `(scope, target, device, epoch)`.
    pub fn get_channel_key_envelope(
        &self,
        key_scope: &[u8; 32],
        target: &str,
        device_id_hex: &str,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>> {
        use super::schema;
        let key = schema::encode_channel_key(key_scope, target, device_id_hex, epoch);
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
        let device = "ab".repeat(32); // 64 hex chars
        let cap = 16;

        // First write stores.
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, target, &device, 1, b"v1", cap)
                .unwrap(),
            KeyEnvelopeStore::Stored
        );
        // A second write to the same (scope, epoch, device) is rejected (first-write-wins).
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, target, &device, 1, b"attacker", cap)
                .unwrap(),
            KeyEnvelopeStore::AlreadyPresent
        );
        // The original value is preserved.
        assert_eq!(
            s.get_channel_key_envelope(&scope, target, &device, 1)
                .unwrap()
                .as_deref(),
            Some(&b"v1"[..])
        );
        // A newer epoch is a distinct entry; latest returns the highest epoch.
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, target, &device, 2, b"v2", cap)
                .unwrap(),
            KeyEnvelopeStore::Stored
        );
        let (ep, val) = s
            .get_channel_key_envelope_latest(&scope, target, &device)
            .unwrap()
            .unwrap();
        assert_eq!(ep, 2);
        assert_eq!(val, b"v2");

        // A different device under the same scope does not collide.
        let other = "cd".repeat(32);
        assert!(s
            .get_channel_key_envelope_latest(&scope, target, &other)
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
                s.put_channel_key_envelope_fww(&scope, "klv1t", &device, 1, b"x", cap)
                    .unwrap(),
                KeyEnvelopeStore::Stored
            );
        }
        // One past the cap is rejected.
        let device = format!("{:064x}", 99);
        assert_eq!(
            s.put_channel_key_envelope_fww(&scope, "klv1t", &device, 1, b"x", cap)
                .unwrap(),
            KeyEnvelopeStore::ScopeFull
        );
    }
}
