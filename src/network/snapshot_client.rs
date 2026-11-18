//! Phase 2 snapshot bootstrap client (spec 11-snapshot-sync.md §3.2, §5).
//!
//! Runs as a one-shot task at node startup when `snapshot.bootstrap_enabled
//! = true`. Discovers snapshot-capable peers via libp2p connections + the
//! existing snapshot protocol's `Advertise` request, picks a quorum of
//! peers that agree on the same snapshot root, fetches the manifest from
//! the primary, fetches chunks in parallel from the mirrors with
//! hash-verification, then applies the snapshot to local RocksDB through
//! a checkpoint-rollback-safe pipeline.
//!
//! ## Threading
//!
//! The client runs in its own tokio task. It does NOT own the libp2p
//! swarm — all wire-level operations go through the `ClientHandle` which
//! talks to `NetworkService::handle_snapshot_client_command` over an
//! unbounded mpsc channel. Each outbound request gets a fresh
//! `oneshot::Sender` so we can await responses without blocking the
//! swarm event loop.
//!
//! ## What is verified (manifest v2, l2-node 0.148.0)
//!
//! A snapshot carries only the anchored chain mirror (`ANCHORED_STATE`) as
//! sealed at the manifest's `block_height`. The receiver checks every row
//! is canonical and filed under its own key, recomputes the anchored state
//! root (v4) from the rows, and requires it to equal the FINAL canonical
//! root on-chain at that height (`sc_views::get_final_canonical_anchor`)
//! — unless the operator set `experimental_skip_anchor_verify`. Nothing
//! that root does not cover is imported: profiles, channel metadata and
//! memberships arrive later through the signed sync paths.
//!
//! ## What this module does NOT do
//!
//! - **Producer signature verification against libp2p PeerId.** We
//!   structurally validate via `SnapshotManifest::validate()`, but
//!   binding the signature to the peer's identity Ed25519 key is
//!   deferred — quorum agreement is the primary trust anchor in Phase 2.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use libp2p::PeerId;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::config::SnapshotConfig;
use crate::storage::rocks::Storage;
use crate::storage::schema::snapshot::DOMAIN_CFS;
use crate::storage::snapshot::{decode_chunk, ChunkHeader, ChunkPayload};

use super::snapshot::{
    SnapshotErrorCode, SnapshotManifest, SnapshotRequest, SnapshotResponse,
};
use super::{SnapshotClientCommand, SnapshotClientError, SnapshotClientResult};

// --- ClientHandle: thin wrapper over the command channel ---------------

/// Handle the bootstrap task uses to talk to the swarm.
///
/// Cheap to clone (it's an mpsc sender + a couple of timeouts). All
/// methods are `async` and time-out on the configured deadlines.
#[derive(Clone)]
pub struct ClientHandle {
    tx: mpsc::UnboundedSender<SnapshotClientCommand>,
    manifest_timeout: Duration,
    chunk_timeout: Duration,
}

impl ClientHandle {
    pub fn new(
        tx: mpsc::UnboundedSender<SnapshotClientCommand>,
        config: &SnapshotConfig,
    ) -> Self {
        Self {
            tx,
            manifest_timeout: Duration::from_secs(config.manifest_timeout_secs),
            chunk_timeout: Duration::from_secs(config.chunk_timeout_secs),
        }
    }

    /// Send a snapshot request to `peer` and await the response with `timeout`.
    ///
    /// Returns `Err` on the inner libp2p outbound failure, on timeout, or
    /// if the network task dropped the oneshot sender (shutdown).
    async fn send(
        &self,
        peer: PeerId,
        request: SnapshotRequest,
        timeout: Duration,
    ) -> Result<SnapshotResponse, SnapshotClientError> {
        let (reply_tx, reply_rx) = oneshot::channel::<SnapshotClientResult>();
        let cmd = SnapshotClientCommand::SendRequest {
            peer,
            request,
            reply: reply_tx,
        };
        if self.tx.send(cmd).is_err() {
            return Err(SnapshotClientError::Cancelled);
        }
        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(Ok(resp))) => Ok(resp),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(SnapshotClientError::Cancelled),
            Err(_) => Err(SnapshotClientError::OutboundFailure(format!(
                "request timed out after {:?}",
                timeout
            ))),
        }
    }

    /// Ask NetworkService for the current set of connected peer ids.
    pub async fn connected_peers(&self) -> Result<Vec<PeerId>, SnapshotClientError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(SnapshotClientCommand::ListConnectedPeers { reply: reply_tx })
            .is_err()
        {
            return Err(SnapshotClientError::Cancelled);
        }
        reply_rx.await.map_err(|_| SnapshotClientError::Cancelled)
    }
}

// --- Quorum sampling ----------------------------------------------------

/// Result of probing peers for snapshot availability.
#[derive(Debug, Clone)]
pub struct QuorumResult {
    /// Block height the quorum agreed on.
    pub block_height: u64,
    /// Snapshot Merkle root they all advertised.
    pub snapshot_root: [u8; 32],
    /// Peers in agreement — order is arbitrary; pick `[0]` as primary,
    /// the rest as mirrors.
    pub agreeing_peers: Vec<PeerId>,
}

/// Tabulate `Advertise` responses into a quorum group.
///
/// Pure logic, no I/O — separate from the discovery loop so it's
/// unit-testable. The "agreeing peers" must share BOTH the same
/// `latest_snapshot_height` AND the same `latest_snapshot_root`.
/// `(height, root)` tuples with fewer than `quorum_min_peers` agreeing
/// peers are discarded. Among tuples that meet the threshold, the one
/// with the most agreeing peers wins (ties broken by highest height).
pub fn select_quorum(
    advertisements: &[(PeerId, u64, [u8; 32])],
    quorum_min_peers: u32,
) -> Option<QuorumResult> {
    let min = quorum_min_peers as usize;
    if min == 0 {
        return None;
    }
    // Group by (height, root).
    let mut groups: HashMap<(u64, [u8; 32]), Vec<PeerId>> = HashMap::new();
    for (peer, height, root) in advertisements {
        if *height == 0 {
            continue; // peer has no cached snapshot
        }
        groups.entry((*height, *root)).or_default().push(*peer);
    }
    // Keep only groups that reach quorum.
    let mut winners: Vec<((u64, [u8; 32]), Vec<PeerId>)> = groups
        .into_iter()
        .filter(|(_, peers)| peers.len() >= min)
        .collect();
    // Sort: most peers first, then highest height first, then root bytes
    // (deterministic tie-break so split-brain detection below is reliable).
    winners.sort_by(|a, b| {
        b.1.len()
            .cmp(&a.1.len())
            .then_with(|| (b.0).0.cmp(&(a.0).0))
            .then_with(|| (b.0).1.cmp(&(a.0).1))
    });
    // Split-brain detection: if two distinct groups tie on (size, height)
    // but disagree on the root, we have inconsistent peers and MUST NOT
    // pick a coin-flip winner. The original formulation relied on
    // HashMap::into_iter ordering — non-deterministic across runs.
    // (Audit finding Phase 2 Code W5.)
    if winners.len() >= 2 {
        let top = &winners[0];
        let next = &winners[1];
        if top.1.len() == next.1.len() && (top.0).0 == (next.0).0 && (top.0).1 != (next.0).1 {
            // Two equally-sized groups at the same height with different
            // roots — split brain. Refuse to pick.
            return None;
        }
    }
    winners
        .into_iter()
        .next()
        .map(|((height, root), peers)| QuorumResult {
            block_height: height,
            snapshot_root: root,
            agreeing_peers: peers,
        })
}

/// Probe a set of candidate peers with `Advertise` and tabulate the responses.
async fn discover_quorum(
    handle: &ClientHandle,
    candidates: &[PeerId],
    quorum_min_peers: u32,
) -> Result<Option<QuorumResult>> {
    let mut ads: Vec<(PeerId, u64, [u8; 32])> = Vec::with_capacity(candidates.len());
    for &peer in candidates {
        match handle
            .send(peer, SnapshotRequest::Advertise, handle.manifest_timeout)
            .await
        {
            Ok(SnapshotResponse::Advertise {
                latest_snapshot_height: Some(h),
                latest_snapshot_root,
                serve_enabled: true,
                ..
            }) => {
                ads.push((peer, h, latest_snapshot_root));
            }
            Ok(SnapshotResponse::Advertise { serve_enabled: false, .. })
            | Ok(SnapshotResponse::Advertise { latest_snapshot_height: None, .. }) => {
                debug!(peer = %peer, "Peer not serving snapshots");
            }
            Ok(other) => {
                debug!(peer = %peer, ?other, "Unexpected Advertise response shape");
            }
            Err(e) => {
                debug!(peer = %peer, error = %e, "Advertise failed");
            }
        }
    }
    Ok(select_quorum(&ads, quorum_min_peers))
}

// --- Manifest fetch -----------------------------------------------------

/// Fetch + structurally validate a manifest from `primary`.
///
/// `expected_root` is the quorum-agreed root; we reject if the served
/// manifest's `snapshot_root` doesn't match. `expected_height` similarly
/// pins the height. `expected_network_id` blocks cross-network bleed.
async fn fetch_manifest(
    handle: &ClientHandle,
    primary: PeerId,
    expected_height: u64,
    expected_root: [u8; 32],
    expected_network_id: &str,
    max_total_bytes: u64,
) -> Result<SnapshotManifest> {
    let resp = handle
        .send(
            primary,
            SnapshotRequest::GetManifest {
                block_height: expected_height,
            },
            handle.manifest_timeout,
        )
        .await
        .map_err(|e| anyhow!("manifest fetch failed: {e}"))?;
    let manifest = match resp {
        SnapshotResponse::Manifest(m) => m,
        SnapshotResponse::Error { code, message } => {
            bail!("manifest fetch returned error {:?}: {}", code, message);
        }
        other => bail!("unexpected response shape for GetManifest: {:?}", other),
    };

    manifest.validate().context("manifest structural validation")?;

    // Producer signature is now MANDATORY (audit 2026-06-07 W7). Previously a
    // manifest with no pubkey field was tolerated with a warning (to pull from
    // pre-signature v0.34/v0.35 laggards) — but that let an attacker simply
    // OMIT the signature to bypass verification. As of the coordinated cutover,
    // every producer signs, so a missing/invalid signature is a hard reject;
    // trust no longer silently degrades to quorum + Merkle + anchor checks.
    match manifest.verify_producer_signature() {
        Ok(crate::network::snapshot::SignatureCheck::Verified) => {
            tracing::debug!("Producer signature verified");
        }
        Ok(crate::network::snapshot::SignatureCheck::SkippedNoPubkey) => {
            bail!(
                "producer manifest carries no pubkey/signature — rejected \
                 (signature is mandatory as of the 2026-06 cutover)"
            );
        }
        Err(e) => {
            bail!("producer signature verification failed: {}", e);
        }
    }

    if manifest.network_id != expected_network_id {
        bail!(
            "manifest network_id mismatch: peer={}, local={}",
            manifest.network_id,
            expected_network_id
        );
    }
    if manifest.block_height != expected_height {
        bail!(
            "manifest block_height mismatch: peer={}, quorum={}",
            manifest.block_height,
            expected_height
        );
    }
    if manifest.snapshot_root != expected_root {
        bail!("manifest snapshot_root mismatch with quorum agreement");
    }

    // Total-size cap: sum CF total_bytes.
    let total: u64 = manifest.cfs.iter().map(|c| c.total_bytes).sum();
    if total > max_total_bytes {
        bail!(
            "manifest total_bytes ({}) exceeds max_total_bytes ({})",
            total,
            max_total_bytes
        );
    }
    // `total_bytes` is the producer's own claim about its rows; what is
    // actually decoded into memory is each chunk's declared uncompressed
    // size (the decoder enforces it). Bound THAT sum — otherwise a manifest
    // claiming `total_bytes = 1` could list thousands of 128 MiB chunks.
    let declared: u64 = manifest
        .cfs
        .iter()
        .flat_map(|c| &c.chunks)
        .map(|ch| u64::from(ch.uncompressed_bytes))
        .sum();
    if declared > max_total_bytes {
        bail!(
            "manifest chunks declare {} uncompressed bytes, exceeding max_total_bytes ({})",
            declared,
            max_total_bytes
        );
    }

    // Anchor height bounds — defense against a malicious primary serving
    // `last_verified_anchor_height = u64::MAX` (which would make the
    // chain scanner refuse to scan ever again after apply).
    if manifest.last_verified_anchor_height > manifest.block_height {
        bail!(
            "manifest last_verified_anchor_height ({}) exceeds block_height ({})",
            manifest.last_verified_anchor_height,
            manifest.block_height
        );
    }

    // CFs covered must match local DOMAIN_CFS (in order). Future minor
    // additions could be tolerated; for v0.35 we require exact match.
    if manifest.cfs.len() != DOMAIN_CFS.len() {
        bail!(
            "manifest cfs count mismatch: peer={}, local={}",
            manifest.cfs.len(),
            DOMAIN_CFS.len()
        );
    }
    for (got, want) in manifest.cfs.iter().zip(DOMAIN_CFS.iter()) {
        if got.cf_name != *want {
            bail!(
                "manifest cfs ordering mismatch at position {}: got '{}', want '{}'",
                got.cf_name,
                got.cf_name,
                want
            );
        }
    }

    Ok(manifest)
}

// --- Chunk fetching -----------------------------------------------------

/// All chunks for one CF, decoded and verified.
type DecodedChunks = Vec<ChunkPayload>;

/// Fetch every chunk in the manifest, distributing across mirrors with
/// per-chunk retry. Verifies each chunk's hash before decoding.
///
/// Returns a per-CF map of decoded payloads in seq order. On any chunk
/// that exhausts the retry budget, aborts the whole bootstrap — the
/// receiver-side spec calls for hard abort over partial apply.
async fn fetch_all_chunks(
    handle: &ClientHandle,
    manifest: &SnapshotManifest,
    mirrors: &[PeerId],
    retries: u32,
) -> Result<HashMap<String, DecodedChunks>> {
    if mirrors.is_empty() {
        bail!("no mirrors available for chunk fetch");
    }
    let mut out: HashMap<String, DecodedChunks> = HashMap::new();
    let mut mirror_index: usize = 0;

    for cf in &manifest.cfs {
        let mut decoded: Vec<ChunkPayload> = Vec::with_capacity(cf.chunks.len());
        for header in &cf.chunks {
            let payload = fetch_one_chunk(
                handle,
                mirrors,
                &mut mirror_index,
                manifest.block_height,
                &cf.cf_name,
                header,
                retries,
            )
            .await
            .with_context(|| {
                format!("fetching chunk ({}, seq {})", cf.cf_name, header.seq)
            })?;
            decoded.push(payload);
        }
        out.insert(cf.cf_name.clone(), decoded);
    }

    Ok(out)
}

async fn fetch_one_chunk(
    handle: &ClientHandle,
    mirrors: &[PeerId],
    mirror_index: &mut usize,
    block_height: u64,
    cf_name: &str,
    header: &ChunkHeader,
    retries: u32,
) -> Result<ChunkPayload> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..=retries {
        let peer = mirrors[*mirror_index % mirrors.len()];
        *mirror_index = mirror_index.wrapping_add(1);

        match handle
            .send(
                peer,
                SnapshotRequest::GetChunk {
                    block_height,
                    cf_name: cf_name.to_string(),
                    seq: header.seq,
                },
                handle.chunk_timeout,
            )
            .await
        {
            Ok(SnapshotResponse::Chunk { header: got, payload }) => {
                // Sanity: header should match manifest header.
                if got.seq != header.seq || got.chunk_hash != header.chunk_hash {
                    last_err = Some(anyhow!(
                        "chunk header echo mismatch from peer {}: seq {} vs {}",
                        peer, got.seq, header.seq
                    ));
                    continue;
                }
                if got.compressed_bytes as usize != payload.len() {
                    last_err = Some(anyhow!(
                        "chunk size mismatch from peer {}: header={}, payload={}",
                        peer, got.compressed_bytes, payload.len()
                    ));
                    continue;
                }
                // decode_chunk verifies the SHA-256 hash against header.chunk_hash
                // and bounds decompression at header.uncompressed_bytes (W16).
                match decode_chunk(
                    &payload, header.codec, &header.chunk_hash, header.uncompressed_bytes,
                ) {
                    Ok(p) => return Ok(p),
                    Err(e) => {
                        last_err = Some(e.context(format!("decode chunk from peer {}", peer)));
                        continue;
                    }
                }
            }
            Ok(SnapshotResponse::Error { code, message }) => {
                last_err = Some(anyhow!(
                    "peer {} returned error {:?}: {}",
                    peer, code, message
                ));
                // For RateLimited and HeightMismatch, immediately retry on a
                // different mirror without counting against the budget — these
                // are server-side conditions, not chunk problems.
                if matches!(code, SnapshotErrorCode::RateLimited | SnapshotErrorCode::HeightMismatch)
                    && attempt < retries
                {
                    continue;
                }
            }
            Ok(other) => {
                last_err = Some(anyhow!(
                    "peer {} returned unexpected response: {:?}",
                    peer, other
                ));
            }
            Err(e) => {
                last_err = Some(anyhow!("peer {} request error: {}", peer, e));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("chunk fetch exhausted all retries")))
}

// --- Merkle root verification (audit fix Phase 2 Sec C1) ----------------

/// Recompute every Merkle root from the actual decoded chunks and confirm
/// they match what the manifest claims.
///
/// For each CF:
///   1. Recompute every chunk's leaf hashes from its `(key, value)` rows
///      via `hash_kv` and roll up to a `chunk_root`.
///   2. Confirm the chunk header's `chunk_hash` matches what the decoder
///      already validated (cheap, but defense in depth).
///   3. Compute `cf_root = compute_root(chunk_roots)` and confirm it
///      equals the manifest's `cf_root`.
///
/// Then recompute the overall `snapshot_root` via `Storage::compute_snapshot_root`
/// and confirm it equals the manifest's `snapshot_root`.
///
/// Returns `Err` on any mismatch — the caller MUST abort the apply.
/// This is the single most important defense in the Phase 2 client:
/// without it, a peer can substitute attacker-chosen rows inside a
/// chunk and only its `chunk_hash` in the manifest would need to match
/// what was sent, which the chunk decoder already enforces — making the
/// whole quorum agreement on `snapshot_root` meaningless.
pub fn verify_merkle_consistency(
    manifest: &SnapshotManifest,
    chunks: &HashMap<String, DecodedChunks>,
) -> Result<()> {
    use crate::crypto::merkle::{compute_root, hash_kv};
    use crate::storage::rocks::Storage;

    let mut cf_roots: Vec<[u8; 32]> = Vec::with_capacity(manifest.cfs.len());

    for cf_manifest in &manifest.cfs {
        let decoded_cf = chunks.get(&cf_manifest.cf_name).ok_or_else(|| {
            anyhow!("missing decoded chunks for cf '{}'", cf_manifest.cf_name)
        })?;
        if decoded_cf.len() != cf_manifest.chunks.len() {
            bail!(
                "cf '{}' chunk count mismatch: manifest={}, decoded={}",
                cf_manifest.cf_name,
                cf_manifest.chunks.len(),
                decoded_cf.len()
            );
        }

        let mut chunk_roots: Vec<[u8; 32]> = Vec::with_capacity(decoded_cf.len());
        for (chunk_header, chunk_payload) in cf_manifest.chunks.iter().zip(decoded_cf.iter()) {
            if chunk_payload.seq != chunk_header.seq {
                bail!(
                    "cf '{}' seq order mismatch: manifest={}, decoded={}",
                    cf_manifest.cf_name,
                    chunk_header.seq,
                    chunk_payload.seq
                );
            }
            // Per-row leaves rebuilt from actual decoded payload.
            let leaves: Vec<[u8; 32]> = chunk_payload
                .entries
                .iter()
                .map(|(k, v)| hash_kv(k, v))
                .collect();
            let computed_root = compute_root(&leaves);
            chunk_roots.push(computed_root);
        }

        let computed_cf_root = compute_root(&chunk_roots);
        if computed_cf_root != cf_manifest.cf_root {
            bail!(
                "cf '{}' root mismatch: manifest={}, computed={}",
                cf_manifest.cf_name,
                hex::encode(cf_manifest.cf_root),
                hex::encode(computed_cf_root)
            );
        }
        cf_roots.push(computed_cf_root);
    }

    let computed_snapshot_root = Storage::compute_snapshot_root(
        manifest.block_height,
        &cf_roots,
        manifest.total_users,
        manifest.total_channels,
    );
    if computed_snapshot_root != manifest.snapshot_root {
        bail!(
            "snapshot_root mismatch: manifest={}, computed={}",
            hex::encode(manifest.snapshot_root),
            hex::encode(computed_snapshot_root)
        );
    }

    Ok(())
}

// --- Peer mirror fetch (anchored-state repair) -------------------------

/// Largest declared uncompressed chunk accepted from a repair peer. Honest
/// producers chunk at `[snapshot] chunk_size_bytes` (4 MiB default; a chunk
/// closes once it passes the target). Decoding inflates a hostile chunk
/// (msgpack arrays of tiny entries) about 16× in memory, so this bounds the
/// transient peak of one decode.
pub const PEER_MIRROR_MAX_CHUNK_BYTES: u32 = 8 * 1024 * 1024;

/// Stream `peer`'s served sealed mirror rows (manifest v2) for the
/// anchored-state repair sweep: its advertised height, the signed manifest
/// (size-capped at `max_total_bytes`), then ONE chunk at a time — fetched,
/// hash-checked, decoded, each row checked for canonical form
/// (`anchored_state::validate_row`) and handed to `on_row` in key order,
/// then dropped. `on_row` returns `false` to stop early. NOT checked against
/// a canonical root or the manifest's Merkle root: the repair sweep treats
/// every row only as a candidate the SC must confirm, so a lying peer can
/// only cost SC calls — and memory stays one capped chunk. Returns the
/// height served.
pub async fn stream_peer_mirror(
    handle: &ClientHandle,
    peer: PeerId,
    network_id: &str,
    max_total_bytes: u64,
    retries: u32,
    mut on_row: impl FnMut(&[u8], &[u8]) -> bool,
) -> Result<u64> {
    let (height, root) = match handle.send(peer, SnapshotRequest::Advertise, handle.manifest_timeout).await {
        Ok(SnapshotResponse::Advertise {
            latest_snapshot_height: Some(h),
            latest_snapshot_root,
            serve_enabled: true,
            ..
        }) => (h, latest_snapshot_root),
        Ok(_) => bail!("peer serves no snapshot"),
        Err(e) => bail!("advertise failed: {e}"),
    };
    let manifest = fetch_manifest(handle, peer, height, root, network_id, max_total_bytes).await?;
    let cf = manifest
        .cfs
        .iter()
        .find(|c| c.cf_name == crate::storage::schema::cf::ANCHORED_STATE)
        .ok_or_else(|| anyhow!("peer snapshot carries no anchored_state"))?;
    let mut headers: Vec<&ChunkHeader> = cf.chunks.iter().collect();
    headers.sort_by_key(|h| h.seq);
    let mut mirror_index = 0usize;
    let mut previous: Option<Vec<u8>> = None;
    for header in headers {
        if header.uncompressed_bytes > PEER_MIRROR_MAX_CHUNK_BYTES {
            bail!("peer chunk {} declares {} bytes, above the repair cap", header.seq, header.uncompressed_bytes);
        }
        let chunk = fetch_one_chunk(handle, &[peer], &mut mirror_index, height, &cf.cf_name, header, retries).await?;
        for (k, v) in chunk.entries {
            if previous.as_deref().is_some_and(|p| p >= k.as_slice()) {
                bail!("peer mirror rows are not in ascending key order");
            }
            crate::storage::anchored_state::validate_row(&k, &v).context("invalid row in peer mirror")?;
            if !on_row(&k, &v) {
                return Ok(height);
            }
            previous = Some(k);
        }
    }
    Ok(height)
}

// --- Verification against the canonical anchored root ------------------

/// Recompute the anchored state root (v4) from the snapshot's decoded
/// `ANCHORED_STATE` rows, validating each row on the way (canonical form,
/// filed under its own key — `anchored_state::validate_row`). Rows arrive
/// key-sorted across ascending chunk `seq`s, and the three subtrees are
/// contiguous key ranges (`c` < `d` < `u`), so each subtree's leaves come
/// out in the order `Storage::compute_state_checkpoint` reads them.
pub fn recompute_anchored_root(chunks: &HashMap<String, DecodedChunks>) -> Result<[u8; 32]> {
    use crate::crypto::merkle::StateManager;
    use crate::storage::anchored_state::validate_row;
    use crate::storage::schema::cf;
    use crate::storage::state_checkpoints::Subtree;

    let mut cf_chunks: Vec<&ChunkPayload> = chunks
        .get(cf::ANCHORED_STATE)
        .ok_or_else(|| anyhow!("missing decoded chunks for cf '{}'", cf::ANCHORED_STATE))?
        .iter()
        .collect();
    cf_chunks.sort_by_key(|c| c.seq);
    let mut mgr = StateManager::new();
    let mut previous: Option<&[u8]> = None;
    for chunk in cf_chunks {
        for (k, v) in &chunk.entries {
            if previous.is_some_and(|p| p >= k.as_slice()) {
                bail!("snapshot anchored_state rows are not in ascending key order");
            }
            previous = Some(k);
            validate_row(k, v).context("invalid anchored_state row in snapshot")?;
            let subtree = Subtree::ALL
                .into_iter()
                .find(|s| k.first() == Some(&s.prefix()))
                .expect("validate_row accepted the prefix");
            mgr.add(subtree.index(), v);
        }
    }
    Ok(mgr.compute_state_root())
}

/// Require the snapshot's recomputed root to equal the final canonical
/// anchored root at its `block_height`. Factored out of `run_bootstrap` so
/// the decision is unit-testable without Klever RPC.
pub fn verify_root_against_canonical(content_root: [u8; 32], canonical: Option<&str>, height: u64) -> Result<()> {
    let content_hex = hex::encode(content_root);
    match canonical {
        None => bail!(
            "no final canonical anchored root on-chain at height {height} — the snapshot cannot be verified"
        ),
        Some(root) if root.eq_ignore_ascii_case(&content_hex) => Ok(()),
        Some(root) => bail!(
            "POISONED SNAPSHOT — anchored_state content root {content_hex} differs from the canonical root {root} at height {height}; refusing to apply"
        ),
    }
}

// --- Apply path ---------------------------------------------------------

/// Result of a successful bootstrap.
#[derive(Debug)]
pub struct BootstrapOutcome {
    /// Block height of the snapshot that was applied.
    pub applied_at: u64,
    /// New chain_cursor after applying (==`cutoff_height`).
    pub new_cursor: u64,
    /// Path to the rollback checkpoint dir. Caller should garbage-collect
    /// it after the scanner has caught up.
    pub rollback_dir: std::path::PathBuf,
}

/// Apply a verified snapshot to local storage.
///
/// Pipeline (atomic-ish — see §5 of spec):
/// 1. Verify no stale `SNAPSHOT_APPLIED_AT_HEIGHT` from a prior aborted apply.
/// 2. Create a rocksdb Checkpoint of the live DB at `data_dir/snapshot_rollback_<ts>`.
/// 3. Persist the checkpoint path in `SNAPSHOT_ROLLBACK_DIR` (so the next
///    boot can detect a half-applied state).
/// 4. For each CF in DOMAIN_CFS: `clear_cf` then `apply_snapshot_chunk` per chunk in seq order.
/// 5. Backfill `DEVICE_WALLET_MAP` and `WALLET_DEVICES` from `DELEGATIONS`
///    (these CFs are excluded from the snapshot for privacy — re-derived here).
/// 6. Write CHAIN_CURSOR = `cutoff_height`, TOTAL_USERS, TOTAL_CHANNELS.
/// 7. Write `SNAPSHOT_APPLIED_AT_HEIGHT` sentinel LAST (commit point).
///
/// **Note:** `clear_snapshot_rollback_dir` should be called by the chain
/// scanner once `chain_cursor > cutoff_height + buffer`, NOT here.
pub fn apply_snapshot(
    storage: &Storage,
    data_dir: &std::path::Path,
    manifest: &SnapshotManifest,
    chunks: &HashMap<String, DecodedChunks>,
    cutoff_height: u64,
) -> Result<BootstrapOutcome> {
    use crate::storage::schema::{cf, state_keys};

    info!(
        block_height = manifest.block_height,
        cutoff_height,
        "Applying snapshot to local storage"
    );

    // 1. Pre-apply check — refuse if a previous apply didn't complete.
    if let Some(prev) = storage.get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_APPLIED_AT_HEIGHT)? {
        if let Ok(arr) = <[u8; 8]>::try_from(prev.as_slice()) {
            let prev_h = u64::from_be_bytes(arr);
            // Idempotent: same snapshot already applied → no-op.
            if prev_h == manifest.block_height {
                bail!(
                    "snapshot {} already applied locally — refusing to re-apply",
                    prev_h
                );
            }
        } else {
            warn!(
                bytes = prev.len(),
                "SNAPSHOT_APPLIED_AT_HEIGHT has unexpected length — treating as absent"
            );
        }
    }

    // 2-3. Create rollback checkpoint.
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let rollback_dir = data_dir.join(format!("snapshot_rollback_{}", ts_ms));
    storage
        .create_checkpoint(&rollback_dir)
        .context("creating rollback checkpoint")?;
    storage
        .put_cf(
            cf::NODE_STATE,
            state_keys::SNAPSHOT_ROLLBACK_DIR,
            rollback_dir.to_string_lossy().as_bytes(),
        )
        .context("persisting rollback dir path")?;
    info!(rollback_dir = %rollback_dir.display(), "Rollback checkpoint created");

    // 4a. Pre-flight validation: every row in every JSON-valued CF must
    // parse as valid JSON. Refusing the apply atomically here protects
    // downstream consumers (API handlers `serde_json::from_slice` the
    // values and would otherwise crash later on malformed data — a
    // persistent DoS vector if a peer in the quorum is malicious).
    // The chain scanner normally writes these values from on-chain
    // events, so by accepting peer-supplied bytes here we'd bypass
    // that implicit validation. (Audit finding Phase 2 Sec C3.)
    for cf_name in DOMAIN_CFS {
        let cf_payloads = chunks
            .get(*cf_name)
            .ok_or_else(|| anyhow!("decoded chunks missing for cf '{}'", cf_name))?;
        for chunk in cf_payloads {
            for (k, v) in &chunk.entries {
                if let Err(e) = crate::storage::anchored_state::validate_row(k, v) {
                    bail!(
                        "cf '{}' row {:?} is invalid ({e}) — refusing apply (malicious peer or corrupt snapshot)",
                        cf_name,
                        hex::encode(&k[..k.len().min(16)])
                    );
                }
            }
        }
    }

    // 4b. Apply each CF.
    for cf_name in DOMAIN_CFS {
        let cf_payloads = chunks
            .get(*cf_name)
            .ok_or_else(|| anyhow!("decoded chunks missing for cf '{}'", cf_name))?;

        storage
            .clear_cf(cf_name)
            .with_context(|| format!("clearing cf '{}' before apply", cf_name))?;

        for chunk in cf_payloads {
            storage
                .apply_snapshot_chunk(cf_name, chunk)
                .with_context(|| {
                    format!("applying chunk seq={} to cf '{}'", chunk.seq, cf_name)
                })?;
        }
    }

    // 5. Derive the chain-owned USERS / CHANNELS / DELEGATIONS rows from
    //    the verified mirror, then DEVICE_WALLET_MAP + WALLET_DEVICES from
    //    DELEGATIONS. The mirror is complete as of the cutoff, so the
    //    repair sweep's first-pass gate is satisfied.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (users, channels, delegations) = storage
        .derive_rows_from_anchored_state(now_secs)
        .context("deriving rows from the anchored mirror after apply")?;
    info!(users, channels, delegations, "Derived chain rows from the snapshot's anchored mirror");
    storage
        .set_anchored_state_migrated()
        .context("marking the anchored mirror complete after apply")?;
    // Re-derive DEVICE_WALLET_MAP + WALLET_DEVICES from DELEGATIONS.
    //    These CFs are excluded from snapshot (privacy: §3.1 spec). The
    //    existing migration helper rebuilds them from DELEGATIONS rows.
    storage
        .backfill_delegation_map()
        .context("backfilling device-wallet maps after apply")?;

    // 6. Cursor + counters.
    storage
        .set_chain_cursor_with_mirror(cutoff_height)
        .context("setting chain_cursor after apply")?;
    // Counters from the verified rows, not from the manifest's claim.
    storage
        .put_cf(cf::NODE_STATE, state_keys::TOTAL_USERS, &users.to_be_bytes())
        .context("updating TOTAL_USERS")?;
    storage
        .put_cf(cf::NODE_STATE, state_keys::TOTAL_CHANNELS, &channels.to_be_bytes())
        .context("updating TOTAL_CHANNELS")?;

    // 7. Commit point: sentinel written last.
    storage
        .put_cf(
            cf::NODE_STATE,
            state_keys::SNAPSHOT_APPLIED_AT_HEIGHT,
            &manifest.block_height.to_be_bytes(),
        )
        .context("writing SNAPSHOT_APPLIED_AT_HEIGHT sentinel")?;

    info!(
        applied_at = manifest.block_height,
        new_cursor = cutoff_height,
        "Snapshot apply complete"
    );

    Ok(BootstrapOutcome {
        applied_at: manifest.block_height,
        new_cursor: cutoff_height,
        rollback_dir,
    })
}

// --- Top-level orchestrator --------------------------------------------

/// Run the full snapshot bootstrap (Phase 3 — anchor-verified).
///
/// Returns `Ok(Some(outcome))` if a snapshot was successfully applied,
/// `Ok(None)` if bootstrap was skipped (no quorum, peers unavailable,
/// no on-chain anchors yet — log + fall back to scan), and `Err` only
/// on fatal errors the caller should surface to the operator (poisoned
/// snapshot detected via anchor mismatch is in this last bucket).
///
/// `data_dir` is where the rollback checkpoint will be written.
/// `klever_node_url` and `contract_address` are used to read the final
/// canonical anchored root at the snapshot's height
/// (`sc_views::get_final_canonical_anchor`).
pub async fn run_bootstrap(
    handle: &ClientHandle,
    storage: Arc<Storage>,
    config: &SnapshotConfig,
    network_id: &str,
    klever_node_url: &str,
    contract_address: &str,
    data_dir: &std::path::Path,
) -> Result<Option<BootstrapOutcome>> {

    // Discovery: wait up to discovery_timeout for peers to appear, then
    // probe everyone connected.
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(config.discovery_timeout_secs);
    loop {
        let peers = handle.connected_peers().await.unwrap_or_default();
        if peers.len() >= config.quorum_min_peers as usize {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            warn!(
                connected = peers.len(),
                quorum_min = config.quorum_min_peers,
                discovery_timeout_secs = config.discovery_timeout_secs,
                "Snapshot bootstrap aborting: only {} peer(s) reachable within discovery timeout, \
                 need at least {}. On a small / private network (e.g. a 2-node testnet) you can \
                 set [snapshot] quorum_min_peers = 1 in ogmara.toml to allow bootstrap from a \
                 single trusted peer. Trades off the quorum-vote sybil resistance — only do this \
                 when you trust your immediate peer set.",
                peers.len(),
                config.quorum_min_peers,
            );
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let candidates = handle.connected_peers().await.unwrap_or_default();
    info!(
        candidates = candidates.len(),
        "Probing peers for snapshot availability"
    );

    let quorum = match discover_quorum(handle, &candidates, config.quorum_min_peers).await {
        Ok(Some(q)) => q,
        Ok(None) => {
            warn!("No snapshot quorum reached — falling back to chain scan");
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    info!(
        block_height = quorum.block_height,
        agreeing_peers = quorum.agreeing_peers.len(),
        snapshot_root = %hex::encode(quorum.snapshot_root),
        "Snapshot quorum reached"
    );

    let primary = quorum.agreeing_peers[0];
    let manifest = fetch_manifest(
        handle,
        primary,
        quorum.block_height,
        quorum.snapshot_root,
        network_id,
        config.max_total_bytes,
    )
    .await
    .context("fetching primary manifest")?;
    info!(
        cfs = manifest.cfs.len(),
        total_users = manifest.total_users,
        total_channels = manifest.total_channels,
        "Manifest fetched and validated"
    );

    let mirrors_count = (config.parallel_fetches as usize)
        .min(quorum.agreeing_peers.len())
        .max(1);
    let mirrors: Vec<PeerId> = quorum.agreeing_peers.iter().take(mirrors_count).copied().collect();

    let chunks = fetch_all_chunks(handle, &manifest, &mirrors, config.chunk_retries)
        .await
        .context("fetching snapshot chunks")?;
    info!(
        chunks = chunks.values().map(|v| v.len()).sum::<usize>(),
        "All chunks fetched and verified"
    );

    // CRITICAL: recompute the Merkle structure from the actual decoded
    // chunks and refuse if it doesn't match the quorum-agreed root.
    // Without this, a peer in the agreeing quorum could swap chunk
    // contents for any value — they'd just need a matching `chunk_hash`
    // in the manifest, since per-chunk hashes are verified at decode
    // time but never tied back to `cf_root`/`snapshot_root`.
    verify_merkle_consistency(&manifest, &chunks)
        .context("snapshot Merkle root verification failed")?;

    // The rows must be exactly what the chain's final canonical anchored
    // root at this height commits to. Checked BEFORE anything is written.
    let content_root = match recompute_anchored_root(&chunks) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Snapshot content is invalid — falling back to chain scan");
            return Ok(None);
        }
    };
    let cutoff_height = manifest.block_height;
    if config.experimental_skip_anchor_verify {
        // Small-network escape hatch: fewer than ANCHOR_QUORUM_MIN (=3)
        // anchorers means no height ever goes canonical. Operators who
        // control every anchorer may opt out explicitly; quorum, Merkle,
        // row validation and the producer signature still apply.
        warn!(
            block_height = cutoff_height,
            content_root = %hex::encode(content_root),
            "experimental_skip_anchor_verify=true — NOT checking the snapshot against the \
             canonical anchored root. Use ONLY when you control every anchorer."
        );
    } else {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("building HTTP client for Klever anchor verify")?;
        let canonical = match crate::chain::sc_views::get_final_canonical_anchor(
            &http,
            klever_node_url,
            contract_address,
            cutoff_height,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Could not read the canonical anchored root — falling back to chain scan");
                return Ok(None);
            }
        };
        if let Err(e) = verify_root_against_canonical(content_root, canonical.as_deref(), cutoff_height) {
            warn!(
                error = %e,
                "Snapshot not verified against the chain — falling back to chain scan. On a \
                 network with fewer than 3 anchorers no height becomes canonical; set \
                 [snapshot] experimental_skip_anchor_verify = true only if you control them all."
            );
            return Ok(None);
        }
        info!(cutoff_height, "Snapshot verified against the canonical anchored root");
    }

    // Run apply in spawn_blocking — multi-CF clear+write is not async.
    let storage_for_apply = storage.clone();
    let data_dir = data_dir.to_path_buf();
    let manifest_for_apply = manifest;
    let chunks_for_apply = chunks;
    let outcome = tokio::task::spawn_blocking(move || {
        apply_snapshot(
            &storage_for_apply,
            &data_dir,
            &manifest_for_apply,
            &chunks_for_apply,
            cutoff_height,
        )
    })
    .await
    .context("apply_snapshot task join")?
    .context("apply_snapshot failed")?;

    Ok(Some(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn peer(seed: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        // Construct a deterministic peer id from a fake Ed25519 key.
        let kp = Keypair::ed25519_from_bytes(bytes).expect("seed must be 32 bytes");
        kp.public().to_peer_id()
    }

    #[test]
    fn select_quorum_empty_returns_none() {
        assert!(select_quorum(&[], 3).is_none());
    }

    #[test]
    fn select_quorum_below_threshold_returns_none() {
        let ads = vec![
            (peer(1), 100, [9u8; 32]),
            (peer(2), 100, [9u8; 32]),
        ];
        assert!(select_quorum(&ads, 3).is_none());
    }

    #[test]
    fn select_quorum_exact_threshold_picks_group() {
        let ads = vec![
            (peer(1), 100, [9u8; 32]),
            (peer(2), 100, [9u8; 32]),
            (peer(3), 100, [9u8; 32]),
            (peer(4), 200, [7u8; 32]),
        ];
        let q = select_quorum(&ads, 3).expect("quorum reached");
        assert_eq!(q.block_height, 100);
        assert_eq!(q.snapshot_root, [9u8; 32]);
        assert_eq!(q.agreeing_peers.len(), 3);
    }

    #[test]
    fn select_quorum_majority_wins_over_minority() {
        // Two groups both meet threshold — larger wins.
        let ads = vec![
            (peer(1), 100, [9u8; 32]),
            (peer(2), 100, [9u8; 32]),
            (peer(3), 100, [9u8; 32]),
            (peer(4), 200, [7u8; 32]),
            (peer(5), 200, [7u8; 32]),
            (peer(6), 200, [7u8; 32]),
            (peer(7), 200, [7u8; 32]),
        ];
        let q = select_quorum(&ads, 3).expect("quorum reached");
        assert_eq!(q.block_height, 200);
        assert_eq!(q.snapshot_root, [7u8; 32]);
        assert_eq!(q.agreeing_peers.len(), 4);
    }

    #[test]
    fn select_quorum_ties_break_by_height() {
        let ads = vec![
            (peer(1), 100, [9u8; 32]),
            (peer(2), 100, [9u8; 32]),
            (peer(3), 100, [9u8; 32]),
            (peer(4), 200, [7u8; 32]),
            (peer(5), 200, [7u8; 32]),
            (peer(6), 200, [7u8; 32]),
        ];
        let q = select_quorum(&ads, 3).expect("quorum reached");
        // Both groups have 3 peers; higher height wins.
        assert_eq!(q.block_height, 200);
    }

    #[test]
    fn select_quorum_disagreeing_roots_at_same_height_are_separate_groups() {
        // Same height, different roots → two distinct groups.
        let ads = vec![
            (peer(1), 100, [9u8; 32]),
            (peer(2), 100, [9u8; 32]),
            (peer(3), 100, [7u8; 32]),
        ];
        // No group reaches threshold=3.
        assert!(select_quorum(&ads, 3).is_none());
        // But threshold=2 picks the [9u8] group.
        let q = select_quorum(&ads, 2).expect("threshold=2 reached");
        assert_eq!(q.snapshot_root, [9u8; 32]);
    }

    #[test]
    fn select_quorum_ignores_height_zero_advertisements() {
        let ads = vec![
            (peer(1), 0, [0u8; 32]),
            (peer(2), 0, [0u8; 32]),
            (peer(3), 0, [0u8; 32]),
            (peer(4), 100, [9u8; 32]),
            (peer(5), 100, [9u8; 32]),
        ];
        // height=0 means "no snapshot" — should never form a quorum even
        // though three peers nominally agree on (0, [0;32]).
        assert!(select_quorum(&ads, 3).is_none());
        // And the lone (100, [9]) group also doesn't reach threshold=3.
        assert!(select_quorum(&ads, 3).is_none());
        // Threshold=2 picks the height=100 group, NOT the height=0 one.
        let q = select_quorum(&ads, 2).expect("threshold=2 reached");
        assert_eq!(q.block_height, 100);
    }

    #[test]
    fn select_quorum_zero_min_returns_none() {
        let ads = vec![(peer(1), 100, [9u8; 32])];
        assert!(select_quorum(&ads, 0).is_none());
    }

    #[test]
    fn select_quorum_split_brain_refuses_to_pick() {
        // Two equally-sized groups at the same height with different
        // roots. Phase 2 must refuse instead of letting HashMap ordering
        // decide. (Audit fix Phase 2 Code W5.)
        let ads = vec![
            (peer(1), 100, [9u8; 32]),
            (peer(2), 100, [9u8; 32]),
            (peer(3), 100, [9u8; 32]),
            (peer(4), 100, [7u8; 32]),
            (peer(5), 100, [7u8; 32]),
            (peer(6), 100, [7u8; 32]),
        ];
        // 3-vs-3 at same height, different roots → split brain → None.
        assert!(select_quorum(&ads, 3).is_none(), "split brain must be refused");
    }

    #[test]
    fn verify_merkle_consistency_accepts_clean_snapshot() {
        // A snapshot built via build_cache must satisfy
        // verify_merkle_consistency against its own decoded chunks.
        use crate::network::snapshot::build_cache;
        use crate::storage::schema::snapshot::codec;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let (storage, _dir) = fresh_storage();
        seed_and_seal(&storage, 50);

        let key = SigningKey::generate(&mut OsRng);
        let cache = build_cache(&storage, "testnet", "node1", &key, 64 * 1024, codec::NONE).unwrap();

        let mut decoded: HashMap<String, Vec<ChunkPayload>> = HashMap::new();
        for cf in &cache.manifest.cfs {
            let mut by_cf = vec![];
            for header in &cf.chunks {
                let p = cache.chunks.get(&(cf.cf_name.clone(), header.seq)).unwrap();
                by_cf.push(
                    crate::storage::snapshot::decode_chunk(
                        p.as_slice(), header.codec, &header.chunk_hash, header.uncompressed_bytes,
                    )
                        .unwrap(),
                );
            }
            decoded.insert(cf.cf_name.clone(), by_cf);
        }
        verify_merkle_consistency(&cache.manifest, &decoded)
            .expect("clean snapshot must verify");
    }

    #[test]
    fn verify_merkle_consistency_catches_tampered_row() {
        // The whole point of Phase 2 Sec C1: a peer in the quorum can't
        // serve a chunk whose `(key, value)` rows differ from what the
        // manifest's cf_root commits to. Tamper a row in the decoded
        // payload AFTER fetch and confirm verification fails.
        use crate::network::snapshot::build_cache;
        use crate::storage::schema::snapshot::codec;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let (storage, _dir) = fresh_storage();
        seed_and_seal(&storage, 50);

        let key = SigningKey::generate(&mut OsRng);
        let cache = build_cache(&storage, "testnet", "node1", &key, 64 * 1024, codec::NONE).unwrap();

        let mut decoded: HashMap<String, Vec<ChunkPayload>> = HashMap::new();
        for cf in &cache.manifest.cfs {
            let mut by_cf = vec![];
            for header in &cf.chunks {
                let p = cache.chunks.get(&(cf.cf_name.clone(), header.seq)).unwrap();
                by_cf.push(
                    crate::storage::snapshot::decode_chunk(
                        p.as_slice(), header.codec, &header.chunk_hash, header.uncompressed_bytes,
                    )
                        .unwrap(),
                );
            }
            decoded.insert(cf.cf_name.clone(), by_cf);
        }

        // Tamper: rewrite alice's value AFTER fetch+decode, simulating a
        // malicious peer in the agreeing group. Real attacker would also
        // rewrite chunk_hash in the manifest, but the manifest's cf_root
        // would no longer match the actual rows — which is what we catch.
        let chunks = decoded.get_mut(cf_names::ANCHORED_STATE).expect("anchored_state chunks");
        let (_, v) = chunks[0].entries.first_mut().expect("a row");
        *v = br#"{"channel_id":7,"creator":"klv1mallory","slug":"general"}"#.to_vec();

        let result = verify_merkle_consistency(&cache.manifest, &decoded);
        assert!(result.is_err(), "tampered row must fail Merkle verification");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("root mismatch") || msg.contains("snapshot_root mismatch"),
            "error should name the mismatch: {}",
            msg
        );
    }

    // --- Apply path tests against a real RocksDB tempdir ---------------

    use crate::storage::rocks::Storage;
    use crate::storage::schema;
    use crate::storage::schema::cf as cf_names;
    use crate::storage::snapshot::ChunkPayload;
    use tempfile::TempDir;

    /// Build a `Storage` open against a fresh tempdir, returning both the
    /// handle and the `TempDir` keeper (drop = cleanup).
    fn fresh_storage() -> (Storage, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(dir.path()).expect("Storage::open");
        (storage, dir)
    }

    #[test]
    fn clear_cf_empties_a_populated_cf() {
        let (storage, _dir) = fresh_storage();
        // Populate the USERS CF with 50 rows.
        for i in 0u32..50 {
            let key = format!("klv1user{:05}", i);
            let value = serde_json::json!({ "klever_address": key.clone() })
                .to_string()
                .into_bytes();
            storage.put_cf(cf_names::USERS, key.as_bytes(), &value).unwrap();
        }
        let before = storage.prefix_iter_cf(cf_names::USERS, &[], 100).unwrap();
        assert_eq!(before.len(), 50);

        storage.clear_cf(cf_names::USERS).expect("clear_cf");

        let after = storage.prefix_iter_cf(cf_names::USERS, &[], 100).unwrap();
        assert_eq!(after.len(), 0, "CF should be empty after clear_cf");
    }

    #[test]
    fn clear_cf_on_empty_cf_is_noop() {
        let (storage, _dir) = fresh_storage();
        // CHANNELS starts empty.
        storage.clear_cf(cf_names::CHANNELS).expect("clear_cf");
        let after = storage.prefix_iter_cf(cf_names::CHANNELS, &[], 100).unwrap();
        assert_eq!(after.len(), 0);
    }

    #[test]
    fn apply_snapshot_chunk_writes_rows() {
        let (storage, _dir) = fresh_storage();
        let chunk = ChunkPayload {
            cf_name: cf_names::USERS.to_string(),
            seq: 0,
            entries: vec![
                (b"klv1a".to_vec(), b"alpha".to_vec()),
                (b"klv1b".to_vec(), b"beta".to_vec()),
                (b"klv1c".to_vec(), b"gamma".to_vec()),
            ],
        };
        storage
            .apply_snapshot_chunk(cf_names::USERS, &chunk)
            .expect("apply_snapshot_chunk");
        let rows = storage.prefix_iter_cf(cf_names::USERS, &[], 100).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            storage.get_cf(cf_names::USERS, b"klv1a").unwrap().unwrap(),
            b"alpha"
        );
    }

    #[test]
    fn apply_snapshot_chunk_rejects_cf_name_mismatch() {
        let (storage, _dir) = fresh_storage();
        let chunk = ChunkPayload {
            cf_name: "users".to_string(),
            seq: 0,
            entries: vec![(b"k".to_vec(), b"v".to_vec())],
        };
        let result = storage.apply_snapshot_chunk(cf_names::CHANNELS, &chunk);
        assert!(result.is_err(), "wrong cf_name must be rejected");
    }

    #[test]
    fn create_checkpoint_produces_usable_db_copy() {
        let (storage, dir) = fresh_storage();
        // Write something we can verify after restoring.
        storage
            .put_cf(cf_names::USERS, b"klv1pre_checkpoint", b"snapshot_me")
            .unwrap();
        let cp_path = dir.path().join("rollback");
        storage.create_checkpoint(&cp_path).expect("checkpoint");
        assert!(cp_path.exists(), "checkpoint dir must exist");
        // Re-open the checkpoint as a fresh Storage and verify the row.
        let restored = Storage::open(&cp_path).expect("open checkpoint");
        let got = restored.get_cf(cf_names::USERS, b"klv1pre_checkpoint").unwrap();
        assert_eq!(got.as_deref(), Some(&b"snapshot_me"[..]));
    }

    #[test]
    fn create_checkpoint_refuses_existing_path() {
        let (storage, dir) = fresh_storage();
        let cp_path = dir.path().join("rollback_taken");
        std::fs::create_dir(&cp_path).unwrap();
        let result = storage.create_checkpoint(&cp_path);
        assert!(result.is_err(), "must refuse to overwrite existing path");
    }

    /// Seed the chain mirror, seal it at `height`, and return the root.
    fn seed_and_seal(storage: &Storage, height: u64) -> [u8; 32] {
        storage.anchored_register_user("klv1a", "aa").unwrap();
        storage.anchored_register_user("klv1b", "bb").unwrap();
        storage.anchored_create_channel(7, "general", "klv1a").unwrap();
        storage
            .anchored_delegate(&crate::storage::anchored_state::AnchoredDelegation {
                created_at: 1_700_000_000,
                device_key: "dd".repeat(32),
                expires_at: 0,
                permissions: 7,
                revoked_at: 0,
                user: "klv1a".into(),
            })
            .unwrap();
        let cp = storage.compute_state_checkpoint().unwrap();
        storage.store_state_checkpoint(height, &cp).unwrap();
        cp.state_root
    }

    /// Build decoded chunks from `storage` via the real `build_cache` +
    /// `decode_chunk` pipeline (what `fetch_all_chunks` delivers).
    fn build_decoded(storage: &Storage) -> (SnapshotManifest, HashMap<String, DecodedChunks>) {
        use crate::network::snapshot::build_cache;
        use crate::storage::schema::snapshot::codec;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        // 64-byte chunks: several chunks, so ordering across seqs is exercised.
        let cache = build_cache(storage, "testnet", "test_node", &signing_key, 64, codec::NONE)
            .expect("build_cache");
        let mut decoded: HashMap<String, DecodedChunks> = HashMap::new();
        for cf in &cache.manifest.cfs {
            let mut by_cf: Vec<ChunkPayload> = Vec::with_capacity(cf.chunks.len());
            for header in &cf.chunks {
                let payload_arc = cache
                    .chunks
                    .get(&(cf.cf_name.clone(), header.seq))
                    .expect("chunk in cache");
                let payload = crate::storage::snapshot::decode_chunk(
                    payload_arc.as_slice(),
                    header.codec,
                    &header.chunk_hash,
                    header.uncompressed_bytes,
                )
                .expect("decode chunk");
                by_cf.push(payload);
            }
            decoded.insert(cf.cf_name.clone(), by_cf);
        }
        (cache.manifest, decoded)
    }

    /// End-to-end: seal a chain mirror, change it afterwards, build a
    /// snapshot, verify it, apply it to a fresh DB, and check the target
    /// holds exactly the sealed state — and nothing gossip-derived.
    #[test]
    fn full_apply_roundtrip_against_real_rocksdb() {
        let (source, _source_dir) = fresh_storage();
        let sealed_root = seed_and_seal(&source, 12_600);
        // After the seal: the snapshot must still serve the sealed state.
        source.anchored_register_user("klv1late", "cc").unwrap();
        source.set_chain_cursor(12_999).unwrap();
        // Gossip rows must never travel.
        source.put_cf(cf_names::USERS, b"klv1a", br#"{"display_name":"alice"}"#).unwrap();
        source
            .put_cf(
                cf_names::CHANNEL_MEMBERS,
                &crate::storage::schema::encode_channel_member_key(7, "klv1b"),
                br#"{"joined_at":1,"role":"member"}"#,
            )
            .unwrap();

        let (manifest, decoded) = build_decoded(&source);
        assert_eq!(manifest.block_height, 12_600);
        assert_eq!((manifest.total_users, manifest.total_channels), (2, 1));
        assert!(decoded[cf_names::ANCHORED_STATE].len() > 1, "multi-chunk");
        let content_root = recompute_anchored_root(&decoded).unwrap();
        assert_eq!(content_root, sealed_root);
        verify_root_against_canonical(content_root, Some(&hex::encode(sealed_root)), 12_600).unwrap();

        let (target, target_dir) = fresh_storage();
        let outcome = apply_snapshot(&target, target_dir.path(), &manifest, &decoded, manifest.block_height)
            .expect("apply_snapshot");
        assert_eq!(outcome.new_cursor, 12_600);
        assert_eq!(target.get_chain_cursor().unwrap(), 12_600);
        let (target_root, ..) = target.compute_current_state_root().unwrap();
        assert_eq!(target_root, sealed_root, "the target mirror is the sealed state");
        assert!(target.anchored_user("klv1late").unwrap().is_none());
        assert!(target.anchored_state_migrated().unwrap());

        // Chain rows derived; gossip content absent.
        let a: serde_json::Value =
            serde_json::from_slice(&target.get_cf(cf_names::USERS, b"klv1a").unwrap().unwrap()).unwrap();
        assert_eq!(a["public_key"], "aa");
        assert_eq!(a["registered_at"], crate::storage::anchored_state::REGISTERED_AT_UNKNOWN);
        assert!(a.get("display_name").map_or(true, |v| v.is_null()));
        assert!(target.get_cf(cf_names::CHANNELS, &7u64.to_be_bytes()).unwrap().is_some());
        assert!(target
            .get_cf(cf_names::CHANNEL_MEMBERS, &crate::storage::schema::encode_channel_member_key(7, "klv1b"))
            .unwrap()
            .is_none());
        assert_eq!(target.get_stat(schema::state_keys::TOTAL_USERS).unwrap(), 2);

        // Rollback dir was created and is openable.
        assert!(outcome.rollback_dir.exists());
        Storage::open(&outcome.rollback_dir).expect("open rollback");
    }

    #[test]
    fn tampered_snapshot_rows_are_refused() {
        let (source, _d) = fresh_storage();
        seed_and_seal(&source, 900);
        let (_, decoded) = build_decoded(&source);
        let mutate = |f: &dyn Fn(&mut Vec<ChunkPayload>)| {
            let mut d = decoded.clone();
            f(d.get_mut(cf_names::ANCHORED_STATE).unwrap());
            recompute_anchored_root(&d)
        };
        // A user filed under another address.
        assert!(mutate(&|c| {
            let row = c.iter_mut().flat_map(|p| p.entries.iter_mut()).find(|(k, _)| k[0] == b'u').unwrap();
            row.0 = crate::storage::anchored_state::user_key("klv1zzz");
        })
        .is_err());
        // Rows out of order (chunks swapped).
        assert!(mutate(&|c| {
            let first = c.remove(0);
            for p in c.iter_mut() {
                p.seq -= 1;
            }
            let mut first = first;
            first.seq = c.len() as u32;
            c.push(first);
        })
        .is_err());
        // An unknown prefix.
        assert!(mutate(&|c| c[0].entries.insert(0, (b"a".to_vec(), b"{}".to_vec()))).is_err());
        // A changed value under the right key still recomputes, but to a
        // different root — which the canonical check refuses.
        let changed = mutate(&|c| {
            let row = c.iter_mut().flat_map(|p| p.entries.iter_mut()).find(|(k, _)| k[0] == b'u').unwrap();
            row.1 = br#"{"address":"klv1a","public_key":"ff"}"#.to_vec();
        })
        .unwrap();
        let genuine = recompute_anchored_root(&decoded).unwrap();
        assert_ne!(changed, genuine);
        assert!(verify_root_against_canonical(changed, Some(&hex::encode(genuine)), 900).is_err());
    }

    #[test]
    fn the_canonical_root_decides() {
        let root = [7u8; 32];
        assert!(verify_root_against_canonical(root, Some(&hex::encode(root)), 1).is_ok());
        assert!(verify_root_against_canonical(root, Some(&hex::encode(root).to_uppercase()), 1).is_ok());
        assert!(verify_root_against_canonical(root, Some(&"00".repeat(32)), 1).is_err());
        assert!(verify_root_against_canonical(root, None, 1).is_err(), "nothing canonical yet");
    }

    #[test]
    fn a_node_without_a_sealed_checkpoint_serves_no_snapshot() {
        use crate::network::snapshot::build_cache;
        use crate::storage::schema::snapshot::codec;
        let (s, _d) = fresh_storage();
        s.anchored_register_user("klv1a", "aa").unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        assert!(build_cache(&s, "testnet", "n", &key, 64, codec::NONE).is_err());
    }

    // --- Phase 3 rollback GC test ---

    #[test]
    fn rollback_gc_clears_after_cursor_advances() {
        use crate::chain::scanner::gc_snapshot_rollback_if_ready;
        use crate::storage::schema::{cf, state_keys};

        let (storage, dir) = fresh_storage();
        // Plant the marker keys + an actual rollback dir on disk.
        let rb_path = dir.path().join("snapshot_rollback_test");
        std::fs::create_dir(&rb_path).unwrap();
        storage
            .put_cf(
                cf::NODE_STATE,
                state_keys::SNAPSHOT_APPLIED_AT_HEIGHT,
                &1000u64.to_be_bytes(),
            )
            .unwrap();
        storage
            .put_cf(
                cf::NODE_STATE,
                state_keys::SNAPSHOT_ROLLBACK_DIR,
                rb_path.to_string_lossy().as_bytes(),
            )
            .unwrap();

        // Too early: cursor only 50 blocks past cutoff — GC waits.
        gc_snapshot_rollback_if_ready(&storage, 1050);
        assert!(rb_path.exists(), "GC must wait for buffer");
        assert!(storage
            .get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR)
            .unwrap()
            .is_some());

        // Past buffer (100 blocks): GC runs.
        gc_snapshot_rollback_if_ready(&storage, 1100);
        assert!(!rb_path.exists(), "rollback dir must be deleted");
        assert!(storage
            .get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_ROLLBACK_DIR)
            .unwrap()
            .is_none(), "marker must be cleared");
        assert!(storage
            .get_cf(cf::NODE_STATE, state_keys::SNAPSHOT_APPLIED_AT_HEIGHT)
            .unwrap()
            .is_none(), "applied-at sentinel cleared after GC");
    }

    #[test]
    fn rollback_gc_noop_when_no_marker() {
        use crate::chain::scanner::gc_snapshot_rollback_if_ready;
        let (storage, _dir) = fresh_storage();
        // No-op (no marker set) — must not panic.
        gc_snapshot_rollback_if_ready(&storage, 9999);
    }

    #[test]
    fn apply_snapshot_refuses_double_apply() {
        // Re-applying the same snapshot at the same height returns Err.
        use crate::network::snapshot::build_cache;
        use crate::storage::schema::snapshot::codec;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let (source, _src_dir) = fresh_storage();
        seed_and_seal(&source, 100);

        let signing = SigningKey::generate(&mut OsRng);
        let cache = build_cache(&source, "testnet", "node1", &signing, 64 * 1024, codec::NONE)
            .unwrap();

        let mut decoded: HashMap<String, Vec<ChunkPayload>> = HashMap::new();
        for cf in &cache.manifest.cfs {
            let mut by_cf = vec![];
            for header in &cf.chunks {
                let payload_arc = cache.chunks.get(&(cf.cf_name.clone(), header.seq)).unwrap();
                by_cf.push(
                    crate::storage::snapshot::decode_chunk(
                        payload_arc.as_slice(),
                        header.codec,
                        &header.chunk_hash,
                        header.uncompressed_bytes,
                    )
                    .unwrap(),
                );
            }
            decoded.insert(cf.cf_name.clone(), by_cf);
        }

        let (target, tdir) = fresh_storage();
        apply_snapshot(&target, tdir.path(), &cache.manifest, &decoded, cache.manifest.block_height)
            .expect("first apply ok");
        let second = apply_snapshot(
            &target,
            tdir.path(),
            &cache.manifest,
            &decoded,
            cache.manifest.block_height,
        );
        assert!(second.is_err(), "re-apply at same height must fail");
    }
}
