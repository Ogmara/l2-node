//! Snapshot bootstrap data structures (spec 11-snapshot-sync.md).
//!
//! These types are shared between the storage layer (which builds snapshots
//! by iterating snapshot-domain column families) and the network layer (which
//! wraps them in libp2p request-response messages). Wire format is CBOR via
//! serde derives — receivers on the same protocol version recompute the
//! Merkle roots and verify against the producer's manifest signature.
//!
//! For Phase 1 (v0.34) only the build/serve path is wired. Apply and quorum
//! verification ship in v0.35+.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Maximum total uncompressed bytes a single CF may contribute to a snapshot
/// build. Hit on adversarial on-chain spam (millions of registrations); the
/// builder aborts and keeps the previous cache rather than OOM.
pub const MAX_BUILD_BYTES_PER_CF: u64 = 256 * 1024 * 1024;
/// Maximum number of `(key, value)` entries per CF during a snapshot build.
pub const MAX_BUILD_ENTRIES_PER_CF: u64 = 5_000_000;

/// Header describing a single chunk within a CF.
///
/// `chunk_hash` is SHA-256(hash_leaf-encoded uncompressed payload) — receivers
/// verify each chunk against this before accepting it into the apply pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHeader {
    /// Zero-based sequence number within the CF.
    pub seq: u32,
    /// Smallest key in this chunk (inclusive).
    pub first_key: Vec<u8>,
    /// Largest key in this chunk (inclusive).
    pub last_key: Vec<u8>,
    /// Uncompressed payload size in bytes (after MessagePack serialization).
    pub uncompressed_bytes: u32,
    /// Compressed payload size in bytes (zstd, or equal to uncompressed for `codec::NONE`).
    pub compressed_bytes: u32,
    /// SHA-256(uncompressed payload via `hash_leaf`) — receivers compare to detect
    /// corruption or tampering before decompressing.
    pub chunk_hash: [u8; 32],
    /// Compression codec — one of `schema::snapshot::codec::*`.
    pub codec: u8,
    /// Number of (key, value) entries in this chunk.
    pub num_entries: u32,
}

/// Chunk payload — the actual `(key, value)` rows for one chunk.
///
/// Serialized via rmp-serde (MessagePack) for compactness, then optionally
/// zstd-compressed. The compressed bytes are what travel over the wire as
/// the `Vec<u8>` payload in `SnapshotResponse::Chunk`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChunkPayload {
    /// Source CF (matches `BuiltCf::cf_name`).
    pub cf_name: String,
    /// Sequence number within the CF.
    pub seq: u32,
    /// `(key, value)` pairs, sorted by key (ascending).
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Per-CF manifest entry: chunk index + Merkle root.
///
/// `cf_root = merkle_root_of(chunk_roots)` where each `chunk_root` is the
/// Merkle root of the per-row `hash_kv(key, value)` leaves in that chunk.
/// Receivers can re-derive `cf_root` chunk-by-chunk during fetch without
/// holding all entries in RAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfManifest {
    pub cf_name: String,
    /// Number of `(key, value)` rows across all chunks.
    pub num_entries: u64,
    /// Sum of raw `key.len() + value.len()` across all rows. **Not** the
    /// MessagePack-serialized chunk payload size, and **not** the compressed
    /// size — receivers wanting the latter must sum `ChunkHeader.compressed_bytes`.
    pub total_bytes: u64,
    /// Producer's target chunk size in uncompressed bytes (advisory; trailing
    /// chunks are smaller).
    pub chunk_size_bytes: u32,
    pub chunks: Vec<ChunkHeader>,
    pub cf_root: [u8; 32],
}

/// What `Storage::build_snapshot_cf` returns for a single CF.
///
/// The `compressed_chunks` vector is indexed by `seq` and held in memory by
/// the snapshot cache builder so that incoming `SnapshotRequest::GetChunk`
/// requests can be answered without re-reading RocksDB.
#[derive(Debug, Clone)]
pub struct BuiltCf {
    pub cf_name: String,
    pub num_entries: u64,
    pub total_bytes: u64,
    pub chunk_size_bytes: u32,
    pub chunks: Vec<ChunkHeader>,
    pub cf_root: [u8; 32],
    pub compressed_chunks: Vec<Vec<u8>>,
}

impl BuiltCf {
    /// Produce a wire-format `CfManifest` (drops in-memory payload bytes).
    pub fn to_manifest(&self) -> CfManifest {
        CfManifest {
            cf_name: self.cf_name.clone(),
            num_entries: self.num_entries,
            total_bytes: self.total_bytes,
            chunk_size_bytes: self.chunk_size_bytes,
            chunks: self.chunks.clone(),
            cf_root: self.cf_root,
        }
    }
}

/// Helper: serialize, hash, compress, and record one chunk's accumulated state.
///
/// Pulled out of `Storage::build_snapshot_cf` so the loop body stays readable.
/// Mutates the buffers in-place: clears the `entries`/`leaves` slots, appends
/// the new header to `headers`, the compressed bytes to `compressed`, and the
/// chunk's Merkle root to `chunk_roots`.
pub(crate) fn finish_chunk(
    cf_name: &str,
    seq: u32,
    codec_id: u8,
    entries: &mut Vec<(Vec<u8>, Vec<u8>)>,
    leaves: &mut Vec<[u8; 32]>,
    headers: &mut Vec<ChunkHeader>,
    compressed: &mut Vec<Vec<u8>>,
    chunk_roots: &mut Vec<[u8; 32]>,
) -> Result<()> {
    use crate::crypto::merkle::{compute_root, hash_leaf};

    debug_assert!(!entries.is_empty(), "finish_chunk called with no entries");

    let first_key = entries.first().unwrap().0.clone();
    let last_key = entries.last().unwrap().0.clone();
    let num_entries = u32::try_from(entries.len())
        .context("snapshot chunk has more than u32::MAX entries — refuse to encode")?;

    let payload = ChunkPayload {
        cf_name: cf_name.to_string(),
        seq,
        entries: std::mem::take(entries),
    };
    let uncompressed = rmp_serde::to_vec(&payload)
        .context("serializing snapshot chunk payload (MessagePack)")?;
    let uncompressed_bytes = u32::try_from(uncompressed.len())
        .context("snapshot chunk uncompressed payload >4 GiB — refuse to encode")?;
    let chunk_hash = hash_leaf(&uncompressed);

    let compressed_bytes = match codec_id {
        id if id == super::schema::snapshot::codec::ZSTD => {
            zstd::stream::encode_all(uncompressed.as_slice(), 3)
                .context("zstd compressing snapshot chunk")?
        }
        id if id == super::schema::snapshot::codec::NONE => uncompressed.clone(),
        other => anyhow::bail!("unsupported snapshot codec id: {}", other),
    };
    let compressed_bytes_len = u32::try_from(compressed_bytes.len())
        .context("snapshot chunk compressed payload >4 GiB — refuse to encode")?;

    let chunk_root = compute_root(leaves);
    leaves.clear();
    chunk_roots.push(chunk_root);

    headers.push(ChunkHeader {
        seq,
        first_key,
        last_key,
        uncompressed_bytes,
        compressed_bytes: compressed_bytes_len,
        chunk_hash,
        codec: codec_id,
        num_entries,
    });
    compressed.push(compressed_bytes);

    Ok(())
}

/// Decode a chunk payload back into `(key, value)` rows.
///
/// `compressed_bytes` is the on-wire payload; `codec_id` and `expected_hash`
/// come from the manifest's `ChunkHeader`. Returns an error if the chunk
/// hash doesn't match — receivers MUST drop the peer and refetch.
///
/// Provided for use by the Phase 2/3 client. Verified by Phase 1 unit tests
/// to keep the build/decode pair from silently diverging across releases.
pub fn decode_chunk(
    compressed_bytes: &[u8],
    codec_id: u8,
    expected_hash: &[u8; 32],
) -> Result<ChunkPayload> {
    use crate::crypto::merkle::hash_leaf;

    let uncompressed: Vec<u8> = match codec_id {
        id if id == super::schema::snapshot::codec::ZSTD => {
            zstd::stream::decode_all(compressed_bytes)
                .context("zstd decompressing snapshot chunk")?
        }
        id if id == super::schema::snapshot::codec::NONE => compressed_bytes.to_vec(),
        other => anyhow::bail!("unsupported snapshot codec id: {}", other),
    };

    let actual_hash = hash_leaf(&uncompressed);
    if &actual_hash != expected_hash {
        anyhow::bail!(
            "snapshot chunk hash mismatch: expected {}, got {}",
            hex::encode(expected_hash),
            hex::encode(actual_hash)
        );
    }

    let payload: ChunkPayload = rmp_serde::from_slice(&uncompressed)
        .context("deserializing snapshot chunk payload (MessagePack)")?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::merkle::{compute_root, hash_kv};
    use crate::storage::schema::snapshot::codec;

    fn sample_rows() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (b"a".to_vec(), b"alpha".to_vec()),
            (b"b".to_vec(), b"beta".to_vec()),
            (b"c".to_vec(), b"gamma".to_vec()),
        ]
    }

    fn run_finish_chunk_with(codec_id: u8) -> (ChunkHeader, Vec<u8>) {
        let rows = sample_rows();
        let mut entries = rows.clone();
        let mut leaves: Vec<[u8; 32]> = rows.iter().map(|(k, v)| hash_kv(k, v)).collect();
        let mut headers = Vec::new();
        let mut compressed = Vec::new();
        let mut chunk_roots = Vec::new();

        finish_chunk(
            "users",
            0,
            codec_id,
            &mut entries,
            &mut leaves,
            &mut headers,
            &mut compressed,
            &mut chunk_roots,
        )
        .unwrap();

        assert!(entries.is_empty(), "entries should be drained");
        assert!(leaves.is_empty(), "leaves should be drained");
        assert_eq!(headers.len(), 1);
        assert_eq!(compressed.len(), 1);
        assert_eq!(chunk_roots.len(), 1);

        let header = headers.pop().unwrap();
        let payload = compressed.pop().unwrap();
        (header, payload)
    }

    #[test]
    fn finish_chunk_zstd_round_trips() {
        let (header, payload) = run_finish_chunk_with(codec::ZSTD);
        assert_eq!(header.seq, 0);
        assert_eq!(header.num_entries, 3);
        assert_eq!(header.first_key, b"a");
        assert_eq!(header.last_key, b"c");
        assert_eq!(header.codec, codec::ZSTD);

        let decoded = decode_chunk(&payload, header.codec, &header.chunk_hash).unwrap();
        assert_eq!(decoded.cf_name, "users");
        assert_eq!(decoded.seq, 0);
        assert_eq!(decoded.entries, sample_rows());
    }

    #[test]
    fn finish_chunk_none_round_trips() {
        let (header, payload) = run_finish_chunk_with(codec::NONE);
        assert_eq!(header.codec, codec::NONE);
        assert_eq!(header.uncompressed_bytes, header.compressed_bytes);

        let decoded = decode_chunk(&payload, header.codec, &header.chunk_hash).unwrap();
        assert_eq!(decoded.entries, sample_rows());
    }

    #[test]
    fn decode_chunk_rejects_tampered_payload() {
        let (header, mut payload) = run_finish_chunk_with(codec::NONE);
        // Flip a byte in the payload — should fail the hash check.
        if !payload.is_empty() {
            payload[0] ^= 0xff;
        }
        let result = decode_chunk(&payload, header.codec, &header.chunk_hash);
        assert!(result.is_err(), "tampered payload must be rejected");
    }

    #[test]
    fn decode_chunk_rejects_unknown_codec() {
        let result = decode_chunk(b"abc", 99, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn cf_root_matches_chunk_root_for_single_chunk() {
        // When a CF fits in one chunk, the cf_root equals the chunk_root
        // because compute_root of a single-element vec is the element itself.
        let rows = sample_rows();
        let leaves: Vec<[u8; 32]> = rows.iter().map(|(k, v)| hash_kv(k, v)).collect();
        let single_chunk_root = compute_root(&leaves);
        let cf_root = compute_root(&[single_chunk_root]);
        assert_eq!(cf_root, single_chunk_root);
    }

    #[test]
    fn built_cf_to_manifest_strips_payload() {
        let header = ChunkHeader {
            seq: 0,
            first_key: b"a".to_vec(),
            last_key: b"b".to_vec(),
            uncompressed_bytes: 10,
            compressed_bytes: 8,
            chunk_hash: [0u8; 32],
            codec: codec::ZSTD,
            num_entries: 2,
        };
        let built = BuiltCf {
            cf_name: "users".to_string(),
            num_entries: 2,
            total_bytes: 10,
            chunk_size_bytes: 4 * 1024 * 1024,
            chunks: vec![header.clone()],
            cf_root: [1u8; 32],
            compressed_chunks: vec![vec![1, 2, 3]],
        };
        let manifest = built.to_manifest();
        assert_eq!(manifest.cf_name, "users");
        assert_eq!(manifest.chunks.len(), 1);
        assert_eq!(manifest.cf_root, [1u8; 32]);
    }
}
