//! Storage engine backed by RocksDB.
//!
//! Uses column families (spec 3.5) for efficient namespaced key-value storage.

pub mod rocks;
pub mod schema;
