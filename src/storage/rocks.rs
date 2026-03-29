//! RocksDB storage implementation.
//!
//! Provides the persistent storage backend using column families
//! for namespaced data (spec 3.5).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rocksdb::{ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options};

use super::schema::cf;

/// Type alias for the multi-threaded RocksDB instance.
pub type RocksDb = DBWithThreadMode<MultiThreaded>;

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

    /// Store a message envelope and update all relevant indexes.
    pub fn store_message(
        &self,
        msg_id: &[u8; 32],
        envelope_bytes: &[u8],
    ) -> Result<()> {
        self.put_cf(cf::MESSAGES, msg_id, envelope_bytes)
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

    /// Record a follow relationship and update counts.
    pub fn follow(&self, follower: &str, followed: &str) -> Result<()> {
        let follow_key = super::schema::encode_follow_key(follower, followed);
        let reverse_key = super::schema::encode_follow_key(followed, follower);

        // Check if already following (idempotent)
        if self.exists_cf(cf::FOLLOWS, &follow_key)? {
            return Ok(());
        }

        self.put_cf(cf::FOLLOWS, &follow_key, &[])?;
        self.put_cf(cf::FOLLOWERS, &reverse_key, &[])?;

        // Update counts
        let (mut following_count, follower_count) = self.get_follower_counts(follower)?;
        following_count += 1;
        self.set_follower_counts(follower, following_count, follower_count)?;

        let (following_count2, mut follower_count2) = self.get_follower_counts(followed)?;
        follower_count2 += 1;
        self.set_follower_counts(followed, following_count2, follower_count2)?;

        Ok(())
    }

    /// Remove a follow relationship and update counts.
    pub fn unfollow(&self, follower: &str, followed: &str) -> Result<()> {
        let follow_key = super::schema::encode_follow_key(follower, followed);
        let reverse_key = super::schema::encode_follow_key(followed, follower);

        // Check if actually following (idempotent)
        if !self.exists_cf(cf::FOLLOWS, &follow_key)? {
            return Ok(());
        }

        self.delete_cf(cf::FOLLOWS, &follow_key)?;
        self.delete_cf(cf::FOLLOWERS, &reverse_key)?;

        // Update counts
        let (mut following_count, follower_count) = self.get_follower_counts(follower)?;
        following_count = following_count.saturating_sub(1);
        self.set_follower_counts(follower, following_count, follower_count)?;

        let (following_count2, mut follower_count2) = self.get_follower_counts(followed)?;
        follower_count2 = follower_count2.saturating_sub(1);
        self.set_follower_counts(followed, following_count2, follower_count2)?;

        Ok(())
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
}

/// Get number of CPUs for RocksDB parallelism.
fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(2)
}
