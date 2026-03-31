//! RocksDB storage implementation.
//!
//! Provides the persistent storage backend using column families
//! for namespaced data (spec 3.5).

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rocksdb::{BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options, WriteBatch};

use super::schema::cf;

/// Type alias for the multi-threaded RocksDB instance.
pub type RocksDb = DBWithThreadMode<MultiThreaded>;

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
                if *name == cf::CHANNEL_MSGS
                    || *name == cf::DM_MESSAGES
                    || *name == cf::DM_CONVERSATIONS
                {
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
                }
                // NEWS_COMMENTS is keyed by (post_id[32], timestamp[8], msg_id[32])
                if *name == cf::NEWS_COMMENTS {
                    cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
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
                if key.len() > 32 && value.len() == 8 {
                    let emoji = String::from_utf8(key[32..].to_vec()).ok()?;
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

    /// Get the comment count for a news post by prefix-scanning NEWS_COMMENTS.
    pub fn get_comment_count(&self, post_id: &[u8; 32]) -> Result<u64> {
        let entries = self.prefix_iter_cf(cf::NEWS_COMMENTS, post_id, 10_000)?;
        Ok(entries.len() as u64)
    }

    // --- Anchor Verification ---

    /// Compute the anchor verification status for a given node.
    ///
    /// Levels:
    /// - "active": anchored consistently (at least 1 per 24h window) for 7+ days
    /// - "verified": anchored at least once in the last 24h
    /// - "none": no recent anchors
    pub fn compute_anchor_status(&self, node_id: &str) -> Result<AnchorStatus> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut prefix = Vec::with_capacity(node_id.len() + 1);
        prefix.extend_from_slice(node_id.as_bytes());
        prefix.push(0xFF);

        // Fetch recent anchors for this node (200 covers 7+ days of hourly anchoring)
        let seven_days_ms = 7 * 24 * 60 * 60 * 1000u64;
        let cutoff = now_ms.saturating_sub(seven_days_ms);

        let entries = self.prefix_iter_cf(cf::ANCHOR_BY_NODE, &prefix, 200)?;

        if entries.is_empty() {
            return Ok(AnchorStatus {
                verified: false,
                level: "none".to_string(),
                last_anchor_age_seconds: None,
                anchoring_since: None,
                total_anchors: 0,
            });
        }

        // Parse timestamps from keys and filter recent ones
        let mut timestamps: Vec<u64> = Vec::new();
        let mut all_count = 0u64;
        let mut earliest: Option<u64> = None;

        for (key, _) in &entries {
            if key.len() > prefix.len() + 7 {
                let ts_start = key.len() - 8;
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&key[ts_start..]);
                let ts = u64::from_be_bytes(ts_bytes);
                all_count += 1;
                if earliest.is_none() || ts < earliest.unwrap() {
                    earliest = Some(ts);
                }
                if ts >= cutoff {
                    timestamps.push(ts);
                }
            }
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
        let age_secs = now_ms.saturating_sub(most_recent) / 1000;

        let twenty_four_hours_ms = 24 * 60 * 60 * 1000u64;

        // Check if anchored in last 24h
        if age_secs > 24 * 60 * 60 {
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
            let seven_days_ago = now_ms.saturating_sub(seven_days_ms);
            if *timestamps.first().unwrap() <= seven_days_ago + twenty_four_hours_ms {
                // Check each 24h window
                let mut all_days_covered = true;
                for day in 0..7 {
                    let window_start = now_ms.saturating_sub((day + 1) as u64 * twenty_four_hours_ms);
                    let window_end = now_ms.saturating_sub(day as u64 * twenty_four_hours_ms);
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

        let entries = self.prefix_iter_cf(cf::ANCHOR_BY_NODE, &prefix, 200)?;
        let total = entries.len() as u64;

        if entries.is_empty() {
            return Ok(SelfAnchorStatus {
                is_anchorer: false,
                last_anchor_height: None,
                last_anchor_age_seconds: None,
                total_anchors: 0,
                anchoring_since: None,
            });
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Extract timestamps from keys and block heights from values
        let mut earliest_ts: Option<u64> = None;
        let mut latest_ts: u64 = 0;
        let mut latest_height: u64 = 0;

        for (key, value) in &entries {
            if key.len() >= prefix.len() + 8 {
                let ts_start = key.len() - 8;
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&key[ts_start..]);
                let ts = u64::from_be_bytes(ts_bytes);

                if earliest_ts.is_none() || ts < earliest_ts.unwrap() {
                    earliest_ts = Some(ts);
                }
                if ts > latest_ts {
                    latest_ts = ts;
                    if value.len() == 8 {
                        let mut h = [0u8; 8];
                        h.copy_from_slice(value);
                        latest_height = u64::from_be_bytes(h);
                    }
                }
            }
        }

        let last_age = if latest_ts > 0 {
            Some(now_ms.saturating_sub(latest_ts) / 1000)
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
}

/// Get number of CPUs for RocksDB parallelism.
fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(2)
}
