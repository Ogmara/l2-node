//! Snapshot bootstrap protocol (spec 11-snapshot-sync.md).
//!
//! New nodes joining an established network can fetch a Merkle-rooted
//! summary of SC-derived state from peers instead of replaying millions of
//! Klever blocks. This module defines the libp2p request-response codec,
//! manifest format, and the serving helper used by `NetworkService`.
//!
//! ## Phase 1 (v0.34)
//!
//! Serve only. A `SnapshotCache` is built periodically from local storage
//! and held in memory so peers can fetch manifests and chunks without
//! re-iterating RocksDB. The client-side fetch + apply path lands in
//! v0.35 (Phase 2) and the anchor-verified cutover in v0.36 (Phase 3).
//!
//! ## Wire format
//!
//! All request/response messages are CBOR-encoded via libp2p's
//! `request_response::cbor::Behaviour`. Chunk payloads are pre-compressed
//! (zstd-3 by default) and travel as opaque `Vec<u8>`. Receivers verify
//! every chunk against the manifest's `chunk_hash` before decompressing.

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::storage::rocks::Storage;
use crate::storage::schema::{self, snapshot::DOMAIN_CFS};
use crate::storage::snapshot::{BuiltCf, CfManifest};

/// Maximum manifest payload size accepted from a peer (1 MiB).
/// Manifests are small (a few KB of headers per CF) — anything larger is
/// almost certainly an attempt to OOM the receiver.
pub const MAX_MANIFEST_BYTES: u32 = 1024 * 1024;

/// Maximum compressed chunk size accepted from a peer (16 MiB).
pub const MAX_CHUNK_BYTES: u32 = 16 * 1024 * 1024;

// --- Wire types ---------------------------------------------------------

/// Snapshot manifest — small header peers exchange before fetching chunks.
///
/// The producer signs `canonical_signing_bytes(&manifest)` with its node
/// identity Ed25519 key; receivers verify against the libp2p PeerId-derived
/// public key. (Phase 1 builds the signature but does not verify on the
/// client side — Phase 2 wires verification when the fetch path lands.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Format version. Phase 1 = `schema::snapshot::MANIFEST_VERSION` (1).
    pub version: u8,
    /// "mainnet" or "testnet" — receivers reject manifests from other networks.
    pub network_id: String,
    /// Klever block height at which the snapshot was taken.
    /// Equals the producer's `chain_cursor` at build time. Receivers set
    /// their own `chain_cursor` to (at most) this value after applying.
    pub block_height: u64,
    /// SHA-256 over all per-CF roots and counters — the value peers vote
    /// on during quorum agreement.
    pub snapshot_root: [u8; 32],
    /// Per-CF manifest entries, in `DOMAIN_CFS` order.
    pub cfs: Vec<CfManifest>,
    /// Producer's most-recent on-chain-verified anchor height (0 if none).
    /// Reserved for Phase 3 anchor verification — receivers don't trust this
    /// claim without independently checking Klever.
    pub last_verified_anchor_height: u64,
    /// Cached counter — `TOTAL_USERS` at build time.
    pub total_users: u64,
    /// Cached counter — `TOTAL_CHANNELS` at build time.
    pub total_channels: u64,
    /// Unix seconds when the cache was built.
    pub created_at: u64,
    /// Producer's Ogmara node_id (Base58 of SHA-256(pubkey)[:20]).
    pub producer_node_id: String,
    /// Ed25519 signature (64 bytes) over `canonical_signing_bytes(self)`.
    /// Stored as `Vec<u8>` because serde lacks native support for `[u8; 64]`.
    /// Receivers MUST check `len() == 64` before passing to `Signature::from_slice`.
    pub producer_signature: Vec<u8>,
    /// **v0.36+:** producer's Ed25519 public key (32 bytes), used for
    /// `producer_signature` verification. Phase 3 receivers verify
    /// `Base58(SHA-256(producer_pubkey)[:20]) == producer_node_id` and
    /// then check the signature against this key. Older (Phase 1/2)
    /// producers leave this empty; receivers fall back to "quorum +
    /// merkle + anchor verification only" with a warning.
    /// Included in `canonical_signing_bytes` only when non-empty so
    /// Phase 1/2 signatures remain canonical.
    #[serde(default)]
    pub producer_pubkey: Vec<u8>,
}

/// Result of `SnapshotManifest::verify_producer_signature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheck {
    /// Pubkey present and signature verifies.
    Verified,
    /// Pubkey absent (Phase 1/2 producer). Caller decides whether to
    /// accept the manifest with reduced trust.
    SkippedNoPubkey,
}

impl SnapshotManifest {
    /// Validate a decoded manifest before trusting any field.
    ///
    /// Cheap structural checks that catch malicious / malformed manifests
    /// before the receiver wastes resources on chunks. Specifically:
    /// - signature length is exactly 64 bytes (Ed25519),
    /// - identifier-like strings are length-bounded (DoS via giant strings),
    /// - `version` matches what this build understands,
    /// - the CF list is bounded.
    ///
    /// Wired in Phase 1 so the inbound libp2p path can validate any manifest
    /// it sees (even though Phase 1 doesn't actively *consume* manifests as
    /// a client) and so Phase 2's fetch path has a ready validator.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != schema::snapshot::MANIFEST_VERSION {
            anyhow::bail!(
                "unsupported snapshot manifest version: got {}, expected {}",
                self.version,
                schema::snapshot::MANIFEST_VERSION
            );
        }
        if self.producer_signature.len() != 64 {
            anyhow::bail!(
                "producer_signature must be 64 bytes, got {}",
                self.producer_signature.len()
            );
        }
        if self.network_id.len() > 32 {
            anyhow::bail!("network_id too long ({} > 32)", self.network_id.len());
        }
        if self.producer_node_id.len() > 64 {
            anyhow::bail!(
                "producer_node_id too long ({} > 64)",
                self.producer_node_id.len()
            );
        }
        // Bound on CFs — current spec has 6 (`DOMAIN_CFS.len()`), allow a
        // little headroom for future additive versions but reject obviously
        // malicious manifests with thousands of CFs.
        if self.cfs.len() > 64 {
            anyhow::bail!("cfs list too long ({} > 64)", self.cfs.len());
        }
        // v0.36+ pubkey field — when present must be exactly 32 bytes (Ed25519).
        // Absent means producer is v0.34/v0.35; receivers fall back to
        // quorum-only trust with a warning.
        if !self.producer_pubkey.is_empty() && self.producer_pubkey.len() != 32 {
            anyhow::bail!(
                "producer_pubkey must be empty or exactly 32 bytes, got {}",
                self.producer_pubkey.len()
            );
        }
        // Sanity on per-CF chunk counts — refuse 100M+ chunks per CF.
        for cf in &self.cfs {
            if cf.chunks.len() > 1_000_000 {
                anyhow::bail!(
                    "cf '{}' has {} chunks — refusing as malformed",
                    cf.cf_name,
                    cf.chunks.len()
                );
            }
            if cf.cf_name.len() > 64 {
                anyhow::bail!("cf_name too long ({} > 64)", cf.cf_name.len());
            }
        }
        Ok(())
    }

    /// Verify the producer signature over the canonical bytes.
    ///
    /// **Phase 3** (v0.36+): if `producer_pubkey` is present, verify
    /// strictly:
    ///   1. `producer_pubkey.len() == 32` (Ed25519),
    ///   2. `Base58(SHA-256(producer_pubkey)[:20]) == producer_node_id`,
    ///   3. Ed25519 signature verifies over `canonical_signing_bytes()`.
    /// Mismatch on any of these → `Err`.
    ///
    /// If `producer_pubkey` is absent (Phase 1/2 producer), the function
    /// returns `Ok(SignatureCheck::SkippedNoPubkey)`. Callers warn but
    /// proceed — trust falls back to quorum + Merkle + anchor verification.
    pub fn verify_producer_signature(&self) -> anyhow::Result<SignatureCheck> {
        use ed25519_dalek::{Signature, VerifyingKey};
        use sha2::{Digest, Sha256};

        if self.producer_pubkey.is_empty() {
            return Ok(SignatureCheck::SkippedNoPubkey);
        }
        if self.producer_pubkey.len() != 32 {
            anyhow::bail!(
                "producer_pubkey must be 32 bytes, got {}",
                self.producer_pubkey.len()
            );
        }
        if self.producer_signature.len() != 64 {
            anyhow::bail!(
                "producer_signature must be 64 bytes, got {}",
                self.producer_signature.len()
            );
        }
        // Pubkey → node_id check.
        let pubkey_arr: [u8; 32] = self.producer_pubkey.as_slice().try_into().unwrap();
        let computed_node_id = {
            let hash = Sha256::digest(pubkey_arr);
            bs58::encode(&hash[..20]).into_string()
        };
        if computed_node_id != self.producer_node_id {
            anyhow::bail!(
                "producer_pubkey does not derive producer_node_id: claim={}, computed={}",
                self.producer_node_id,
                computed_node_id
            );
        }
        // Signature verification.
        let vk = VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|e| anyhow::anyhow!("invalid producer_pubkey: {}", e))?;
        let sig_arr: [u8; 64] = self.producer_signature.as_slice().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_arr);
        let canonical = self.canonical_signing_bytes();
        // verify_strict rejects small-subgroup component R signatures —
        // not strictly required for snapshot auth, but cheap defense in
        // depth (audit Phase 3 Sec N1).
        vk.verify_strict(&canonical, &sig)
            .map_err(|e| anyhow::anyhow!("producer_signature failed Ed25519 verification: {}", e))?;
        Ok(SignatureCheck::Verified)
    }

    /// Build the canonical byte string used for signing.
    ///
    /// Excludes `producer_signature` itself so the signature can be added
    /// after computation. Deterministic — receivers reconstruct the same
    /// bytes when verifying.
    ///
    /// **Coverage:** the signed bytes include
    /// - the protocol domain separator and version (anti cross-protocol replay),
    /// - `network_id` (anti cross-network replay),
    /// - `block_height`, `snapshot_root`, the cached counters,
    /// - `created_at` and `producer_node_id`, and
    /// - the per-CF `(cf_name, cf_root, num_chunks)` triples in order.
    ///
    /// `snapshot_root` already binds every `cf_root` by construction
    /// (it's a SHA-256 over them), but we ALSO bind each `cf_root`
    /// directly here so that a peer can't ship a manifest where the
    /// `cfs` vector has been swapped for a different valid sequence
    /// that happens to produce the same `snapshot_root`. In practice a
    /// preimage attack on SHA-256 is infeasible, but defense-in-depth
    /// is cheap and makes the receiver's verification logic strict.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(schema::snapshot::SNAPSHOT_ROOT_DOMAIN);
        buf.push(self.version);
        buf.extend_from_slice(self.network_id.as_bytes());
        buf.push(0); // null separator
        buf.extend_from_slice(&self.block_height.to_be_bytes());
        buf.extend_from_slice(&self.snapshot_root);
        buf.extend_from_slice(&self.last_verified_anchor_height.to_be_bytes());
        buf.extend_from_slice(&self.total_users.to_be_bytes());
        buf.extend_from_slice(&self.total_channels.to_be_bytes());
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        buf.extend_from_slice(self.producer_node_id.as_bytes());
        buf.push(0); // null separator before cfs
        // CFs: bind each (cf_name, cf_root, num_chunks) into the signed bytes.
        buf.extend_from_slice(&(self.cfs.len() as u32).to_be_bytes());
        for cf in &self.cfs {
            buf.extend_from_slice(&(cf.cf_name.len() as u32).to_be_bytes());
            buf.extend_from_slice(cf.cf_name.as_bytes());
            buf.extend_from_slice(&cf.cf_root);
            buf.extend_from_slice(&(cf.chunks.len() as u32).to_be_bytes());
        }
        // v0.36+ producer_pubkey extension — included ONLY when non-empty
        // so v0.34 / v0.35 producers' signatures remain canonical and
        // verifiable against the unextended form.
        if !self.producer_pubkey.is_empty() {
            buf.push(0); // separator before pubkey
            buf.extend_from_slice(&(self.producer_pubkey.len() as u32).to_be_bytes());
            buf.extend_from_slice(&self.producer_pubkey);
        }
        buf
    }
}

/// libp2p request — what one node asks another about snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotRequest {
    /// "What's your latest snapshot height + verified anchor?"
    /// Cheap; used during quorum candidate sampling.
    Advertise,
    /// Fetch the manifest for a specific block height
    /// (or the producer's best snapshot if `block_height == 0`).
    GetManifest { block_height: u64 },
    /// Fetch a single chunk by `(cf_name, seq)`.
    GetChunk {
        block_height: u64,
        cf_name: String,
        seq: u32,
    },
}

/// libp2p response — answers from the serving peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotResponse {
    Advertise {
        /// `Some(height)` if this peer is serving a cached snapshot, else `None`.
        latest_snapshot_height: Option<u64>,
        /// Snapshot root (zeros if `latest_snapshot_height` is `None`).
        latest_snapshot_root: [u8; 32],
        /// Producer's last on-chain-verified anchor height. 0 if not anchoring.
        latest_verified_anchor_height: u64,
        /// Whether this peer is currently accepting `GetChunk` requests.
        /// May be `false` even when a cache exists (e.g., rate-limited).
        serve_enabled: bool,
    },
    Manifest(SnapshotManifest),
    Chunk {
        /// The chunk header from the manifest (echoed for self-contained verification).
        header: crate::storage::snapshot::ChunkHeader,
        /// Compressed payload bytes; decode via `storage::snapshot::decode_chunk`.
        payload: Vec<u8>,
    },
    /// Returned when the requested snapshot/chunk isn't available, or when
    /// the serving peer is throttling. The client should fall back to a
    /// different peer (or full chain scan).
    Error {
        code: SnapshotErrorCode,
        message: String,
    },
}

/// Reasons a `SnapshotResponse::Error` may be returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SnapshotErrorCode {
    /// No cached snapshot exists yet, or `serve_enabled = false`.
    NotAvailable = 0x01,
    /// Snapshot at the requested height is not the one currently cached.
    HeightMismatch = 0x02,
    /// Unknown CF name or seq out of range.
    NotFound = 0x03,
    /// Server is throttling outbound chunks.
    RateLimited = 0x04,
    /// Snapshot format version doesn't match.
    UnsupportedVersion = 0x05,
}

/// Codec type alias for the snapshot protocol — mirrors `SyncCodec`.
pub type SnapshotCodec = libp2p::request_response::cbor::Behaviour<SnapshotRequest, SnapshotResponse>;

// --- Cache --------------------------------------------------------------

/// In-memory representation of the most recently built snapshot.
///
/// Held in an `Arc<RwLock<Option<...>>>` by `NetworkService` and the
/// background cache-builder task. The cache-builder rebuilds it every
/// `snapshot.serve_rebuild_interval_secs`; serving requests read it under
/// a read-lock.
///
/// **Memory note (Phase 1):** the full compressed chunk corpus is held in
/// RAM. At mature-network scale (10s of MB compressed) this is acceptable.
/// Phase 3 may switch to a pinned `rocksdb::Snapshot` + lazy chunk streaming
/// if memory becomes a concern.
pub struct SnapshotCache {
    pub manifest: SnapshotManifest,
    /// Compressed chunk bytes keyed by `(cf_name, seq)`. `Arc<Vec<u8>>` so
    /// `GetChunk` handlers can clone the handle cheaply under the read-lock
    /// and copy out the bytes (or move them into a response) after dropping
    /// the lock. Avoids holding the cache lock during multi-MiB memcpys.
    pub chunks: std::collections::HashMap<(String, u32), Arc<Vec<u8>>>,
    /// Chunk header lookups — same key as `chunks`, for echoing headers in
    /// `SnapshotResponse::Chunk` without re-scanning the manifest. Wrapped
    /// in `Arc` for the same reason.
    pub chunk_headers:
        std::collections::HashMap<(String, u32), Arc<crate::storage::snapshot::ChunkHeader>>,
    /// Total compressed bytes held by this cache (sum over `chunks`).
    pub compressed_total_bytes: u64,
}

/// Shared handle for the snapshot cache.
pub type SharedSnapshotCache = Arc<RwLock<Option<SnapshotCache>>>;

/// Build a fresh `SnapshotCache` from current storage state.
///
/// Iterates every `DOMAIN_CFS` entry, packs them into chunks at
/// `chunk_size_bytes`, computes the per-CF and overall Merkle roots, and
/// signs the manifest with `signing_key`. Pass `codec_id = codec::ZSTD` in
/// production; tests use `codec::NONE` for determinism.
///
/// Long-running (full-CF scan) — call from `tokio::task::spawn_blocking`.
pub fn build_cache(
    storage: &Storage,
    network_id: &str,
    node_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
    chunk_size_bytes: u32,
    codec_id: u8,
) -> Result<SnapshotCache> {
    use ed25519_dalek::Signer;

    let block_height = storage
        .get_chain_cursor()
        .context("reading chain_cursor for snapshot cache")?;
    let total_users = storage
        .get_stat(schema::state_keys::TOTAL_USERS)
        .context("reading TOTAL_USERS")?;
    let total_channels = storage
        .get_stat(schema::state_keys::TOTAL_CHANNELS)
        .context("reading TOTAL_CHANNELS")?;

    let mut cfs_manifest: Vec<CfManifest> = Vec::with_capacity(DOMAIN_CFS.len());
    let mut cf_roots: Vec<[u8; 32]> = Vec::with_capacity(DOMAIN_CFS.len());
    let mut chunks_map: std::collections::HashMap<(String, u32), Arc<Vec<u8>>> =
        std::collections::HashMap::new();
    let mut chunk_headers_map: std::collections::HashMap<
        (String, u32),
        Arc<crate::storage::snapshot::ChunkHeader>,
    > = std::collections::HashMap::new();
    let mut compressed_total_bytes: u64 = 0;

    for cf_name in DOMAIN_CFS {
        let built: BuiltCf = storage
            .build_snapshot_cf(cf_name, chunk_size_bytes, codec_id)
            .with_context(|| format!("building snapshot for cf '{}'", cf_name))?;

        // Snapshot the per-CF manifest before we consume `built.chunks` /
        // `built.compressed_chunks` — `to_manifest` only borrows.
        let cf_manifest = built.to_manifest();

        // Sanity: the two parallel vecs MUST stay in lockstep — finish_chunk
        // pushes to both. A mismatch would mean a logic bug; loudly notice it.
        debug_assert_eq!(
            built.chunks.len(),
            built.compressed_chunks.len(),
            "chunks/compressed_chunks length mismatch for cf '{}'",
            cf_name
        );

        for (seq, (header, payload)) in built
            .chunks
            .into_iter()
            .zip(built.compressed_chunks.into_iter())
            .enumerate()
        {
            compressed_total_bytes =
                compressed_total_bytes.saturating_add(payload.len() as u64);
            let key = (cf_name.to_string(), seq as u32);
            chunks_map.insert(key.clone(), Arc::new(payload));
            chunk_headers_map.insert(key, Arc::new(header));
        }

        cf_roots.push(built.cf_root);
        cfs_manifest.push(cf_manifest);
    }

    let snapshot_root = Storage::compute_snapshot_root(
        block_height,
        &cf_roots,
        total_users,
        total_channels,
    );

    let created_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // v0.36+: include the producer's Ed25519 pubkey so receivers can
    // verify producer_signature without an out-of-band identity lookup.
    let producer_pubkey = signing_key.verifying_key().to_bytes().to_vec();

    let mut manifest = SnapshotManifest {
        version: schema::snapshot::MANIFEST_VERSION,
        network_id: network_id.to_string(),
        block_height,
        snapshot_root,
        cfs: cfs_manifest,
        last_verified_anchor_height: 0, // populated by anchor verifier in Phase 3
        total_users,
        total_channels,
        created_at,
        producer_node_id: node_id.to_string(),
        producer_signature: Vec::new(),
        producer_pubkey,
    };

    // Sign the canonical bytes (with pubkey extension).
    let canonical = manifest.canonical_signing_bytes();
    let sig = signing_key.sign(&canonical);
    manifest.producer_signature = sig.to_bytes().to_vec();

    Ok(SnapshotCache {
        manifest,
        chunks: chunks_map,
        chunk_headers: chunk_headers_map,
        compressed_total_bytes,
    })
}

/// Update the diagnostic counter recording the most recent successful build.
///
/// Read by the admin `/admin/snapshot/status` endpoint. Best-effort —
/// failure to write is logged but doesn't fail the build.
pub fn record_serve_height(storage: &Storage, block_height: u64) {
    if let Err(e) = storage.put_cf(
        schema::cf::NODE_STATE,
        schema::state_keys::SNAPSHOT_LAST_SERVED_HEIGHT,
        &block_height.to_be_bytes(),
    ) {
        warn!(error = %e, "Failed to persist SNAPSHOT_LAST_SERVED_HEIGHT (cosmetic only)");
    }
}

// --- Serve helpers ------------------------------------------------------

/// Build a `SnapshotResponse` for an incoming `SnapshotRequest`.
///
/// Pure read against the shared cache — safe to call from the libp2p event
/// loop. Returns `SnapshotResponse::Error { code: NotAvailable }` if the
/// cache hasn't been built yet (server still warming up).
pub fn build_response(
    cache: &SharedSnapshotCache,
    serve_enabled: bool,
    request: SnapshotRequest,
) -> SnapshotResponse {
    let guard = match cache.read() {
        Ok(g) => g,
        Err(_) => {
            return SnapshotResponse::Error {
                code: SnapshotErrorCode::NotAvailable,
                message: "cache lock poisoned".into(),
            };
        }
    };

    match request {
        SnapshotRequest::Advertise => match guard.as_ref() {
            Some(c) => SnapshotResponse::Advertise {
                latest_snapshot_height: Some(c.manifest.block_height),
                latest_snapshot_root: c.manifest.snapshot_root,
                latest_verified_anchor_height: c.manifest.last_verified_anchor_height,
                serve_enabled,
            },
            None => SnapshotResponse::Advertise {
                latest_snapshot_height: None,
                latest_snapshot_root: [0u8; 32],
                latest_verified_anchor_height: 0,
                serve_enabled,
            },
        },

        SnapshotRequest::GetManifest { block_height } => match guard.as_ref() {
            Some(c) if block_height == 0 || block_height == c.manifest.block_height => {
                SnapshotResponse::Manifest(c.manifest.clone())
            }
            Some(_) => SnapshotResponse::Error {
                code: SnapshotErrorCode::HeightMismatch,
                message: "requested height not cached".into(),
            },
            None => SnapshotResponse::Error {
                code: SnapshotErrorCode::NotAvailable,
                message: "no snapshot cached yet".into(),
            },
        },

        SnapshotRequest::GetChunk { block_height, cf_name, seq } => {
            // Clone the cheap Arcs under the lock, then drop the guard before
            // the (potentially multi-MiB) byte copy into the response. This
            // keeps the read-lock window short so the cache-rebuild writer
            // doesn't get starved by concurrent GetChunk requests.
            let (payload_arc, header_arc) = match guard.as_ref() {
                Some(c) if block_height == c.manifest.block_height => {
                    let key = (cf_name.clone(), seq);
                    match (c.chunks.get(&key), c.chunk_headers.get(&key)) {
                        (Some(p), Some(h)) => (p.clone(), h.clone()),
                        _ => {
                            return SnapshotResponse::Error {
                                code: SnapshotErrorCode::NotFound,
                                message: format!("chunk ({}, {}) not in cache", key.0, key.1),
                            };
                        }
                    }
                }
                Some(_) => {
                    return SnapshotResponse::Error {
                        code: SnapshotErrorCode::HeightMismatch,
                        message: "requested height not cached".into(),
                    };
                }
                None => {
                    return SnapshotResponse::Error {
                        code: SnapshotErrorCode::NotAvailable,
                        message: "no snapshot cached yet".into(),
                    };
                }
            };
            drop(guard);

            SnapshotResponse::Chunk {
                header: (*header_arc).clone(),
                payload: (*payload_arc).clone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_cache_handle() -> SharedSnapshotCache {
        Arc::new(RwLock::new(None))
    }

    #[test]
    fn advertise_with_no_cache_returns_none() {
        let cache = empty_cache_handle();
        let resp = build_response(&cache, true, SnapshotRequest::Advertise);
        match resp {
            SnapshotResponse::Advertise {
                latest_snapshot_height,
                serve_enabled,
                ..
            } => {
                assert!(latest_snapshot_height.is_none());
                assert!(serve_enabled);
            }
            _ => panic!("expected Advertise"),
        }
    }

    #[test]
    fn get_manifest_with_no_cache_returns_not_available() {
        let cache = empty_cache_handle();
        let resp = build_response(
            &cache,
            true,
            SnapshotRequest::GetManifest { block_height: 0 },
        );
        match resp {
            SnapshotResponse::Error { code, .. } => {
                assert_eq!(code, SnapshotErrorCode::NotAvailable);
            }
            _ => panic!("expected Error"),
        }
    }

    fn good_manifest() -> SnapshotManifest {
        SnapshotManifest {
            version: schema::snapshot::MANIFEST_VERSION,
            network_id: "testnet".into(),
            block_height: 100,
            snapshot_root: [0u8; 32],
            cfs: vec![],
            last_verified_anchor_height: 0,
            total_users: 0,
            total_channels: 0,
            created_at: 0,
            producer_node_id: "node1".into(),
            producer_signature: vec![0u8; 64],
            producer_pubkey: Vec::new(),
        }
    }

    #[test]
    fn validate_accepts_good_manifest() {
        good_manifest().validate().expect("good manifest should validate");
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let mut m = good_manifest();
        m.version = 99;
        assert!(m.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_signature_length() {
        let mut m = good_manifest();
        m.producer_signature = vec![0u8; 32]; // wrong length
        assert!(m.validate().is_err());
        m.producer_signature = vec![0u8; 65];
        assert!(m.validate().is_err());
        m.producer_signature = vec![]; // empty
        assert!(m.validate().is_err());
    }

    #[test]
    fn validate_rejects_oversize_strings() {
        let mut m = good_manifest();
        m.network_id = "x".repeat(33);
        assert!(m.validate().is_err());

        let mut m = good_manifest();
        m.producer_node_id = "x".repeat(65);
        assert!(m.validate().is_err());
    }

    #[test]
    fn verify_producer_signature_skips_when_pubkey_absent() {
        // v0.34/v0.35 producers ship no pubkey — receivers fall back to
        // quorum-only trust with a warning, not a hard reject.
        let m = good_manifest();
        assert!(m.producer_pubkey.is_empty());
        match m.verify_producer_signature() {
            Ok(SignatureCheck::SkippedNoPubkey) => {}
            other => panic!("expected SkippedNoPubkey, got {:?}", other),
        }
    }

    #[test]
    fn verify_producer_signature_round_trip() {
        // Build a v0.36 manifest by hand with matching pubkey + signature,
        // confirm verify() accepts it.
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;
        use sha2::{Digest, Sha256};

        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes().to_vec();
        let node_id = {
            let hash = Sha256::digest(&pubkey);
            bs58::encode(&hash[..20]).into_string()
        };
        let mut m = good_manifest();
        m.producer_node_id = node_id;
        m.producer_pubkey = pubkey;
        let canonical = m.canonical_signing_bytes();
        let sig = key.sign(&canonical);
        m.producer_signature = sig.to_bytes().to_vec();

        match m.verify_producer_signature() {
            Ok(SignatureCheck::Verified) => {}
            other => panic!("expected Verified, got {:?}", other),
        }
    }

    #[test]
    fn verify_producer_signature_catches_pubkey_node_id_mismatch() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let mut m = good_manifest();
        // Pubkey doesn't hash to producer_node_id="node1".
        m.producer_pubkey = key.verifying_key().to_bytes().to_vec();
        let canonical = m.canonical_signing_bytes();
        m.producer_signature = key.sign(&canonical).to_bytes().to_vec();
        let result = m.verify_producer_signature();
        assert!(result.is_err(), "node_id mismatch must fail");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(msg.contains("does not derive producer_node_id"));
    }

    #[test]
    fn verify_producer_signature_catches_tampered_signature() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;
        use sha2::{Digest, Sha256};

        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes().to_vec();
        let node_id = {
            let hash = Sha256::digest(&pubkey);
            bs58::encode(&hash[..20]).into_string()
        };
        let mut m = good_manifest();
        m.producer_node_id = node_id;
        m.producer_pubkey = pubkey;
        let canonical = m.canonical_signing_bytes();
        let mut sig = key.sign(&canonical).to_bytes();
        // Flip a byte in the signature.
        sig[0] ^= 0xff;
        m.producer_signature = sig.to_vec();

        let result = m.verify_producer_signature();
        assert!(result.is_err(), "tampered signature must fail");
    }

    #[test]
    fn validate_rejects_bad_pubkey_length() {
        let mut m = good_manifest();
        m.producer_pubkey = vec![0u8; 31]; // wrong
        assert!(m.validate().is_err());
        m.producer_pubkey = vec![0u8; 33];
        assert!(m.validate().is_err());
        m.producer_pubkey = vec![0u8; 32];
        assert!(m.validate().is_ok()); // OK length but won't verify; that's a separate check
    }

    #[test]
    fn validate_rejects_too_many_cfs() {
        let mut m = good_manifest();
        m.cfs = (0..65)
            .map(|i| crate::storage::snapshot::CfManifest {
                cf_name: format!("cf{}", i),
                num_entries: 0,
                total_bytes: 0,
                chunk_size_bytes: 4 * 1024 * 1024,
                chunks: vec![],
                cf_root: [0u8; 32],
            })
            .collect();
        assert!(m.validate().is_err());
    }

    #[test]
    fn manifest_canonical_bytes_excludes_signature() {
        // Two manifests differing only in signature must produce the same
        // canonical bytes — otherwise signature verification would self-loop.
        let m1 = SnapshotManifest {
            version: 1,
            network_id: "testnet".into(),
            block_height: 12345,
            snapshot_root: [9u8; 32],
            cfs: vec![],
            last_verified_anchor_height: 0,
            total_users: 5,
            total_channels: 3,
            created_at: 1_700_000_000,
            producer_node_id: "node1".into(),
            producer_signature: vec![1u8; 64],
            producer_pubkey: Vec::new(),
        };
        let mut m2 = m1.clone();
        m2.producer_signature = vec![2u8; 64];

        assert_eq!(m1.canonical_signing_bytes(), m2.canonical_signing_bytes());
    }

    #[test]
    fn get_chunk_with_mismatched_height_returns_height_mismatch() {
        let cache_data = SnapshotCache {
            manifest: SnapshotManifest {
                version: 1,
                network_id: "testnet".into(),
                block_height: 100,
                snapshot_root: [0u8; 32],
                cfs: vec![],
                last_verified_anchor_height: 0,
                total_users: 0,
                total_channels: 0,
                created_at: 0,
                producer_node_id: "node1".into(),
                producer_signature: Vec::new(),
                producer_pubkey: Vec::new(),
            },
            chunks: std::collections::HashMap::new(),
            chunk_headers: std::collections::HashMap::new(),
            compressed_total_bytes: 0,
        };
        let cache = Arc::new(RwLock::new(Some(cache_data)));

        let resp = build_response(
            &cache,
            true,
            SnapshotRequest::GetChunk {
                block_height: 999,
                cf_name: "users".into(),
                seq: 0,
            },
        );
        match resp {
            SnapshotResponse::Error { code, .. } => {
                assert_eq!(code, SnapshotErrorCode::HeightMismatch);
            }
            _ => panic!("expected HeightMismatch error"),
        }
    }
}
