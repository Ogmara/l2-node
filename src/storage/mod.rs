//! Storage engine backed by RocksDB.
//!
//! Uses column families (spec 3.5) for efficient namespaced key-value storage.

pub mod identity;
pub mod key_commits;
pub mod rocks;
pub mod schema;
pub mod snapshot;
pub mod state_checkpoints;
