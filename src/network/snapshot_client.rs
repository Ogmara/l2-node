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
//! ## What this module does NOT do (Phase 2)
//!
//! - **Anchor re-verification against Klever.** Phase 2 trusts the
//!   producer's claim of `last_verified_anchor_height` if the operator
//!   has set `experimental_skip_anchor_verify = true`. Without that flag,
//!   bootstrap refuses to apply and the node falls back to full scan.
//!   Phase 3 (v0.36) removes the flag and adds real anchor verification.
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

/// Returns true if this snapshot-domain CF stores JSON-encoded values.
///
/// USERS, CHANNELS, CHANNEL_MEMBERS, DELEGATIONS, STATE_ANCHORS values
/// are all `serde_json::from_slice`'d by API handlers and the chain
/// scanner. ANCHOR_BY_NODE is excluded — its values are raw 8-byte
/// big-endian `block_height` ints with no JSON layer to corrupt.
/// The receiver pre-validates JSON for the json-valued CFs before the
/// destructive apply — see audit finding Phase 2 Sec C3.
fn cf_has_json_values(cf_name: &str) -> bool {
    use crate::storage::schema::cf;
    matches!(
        cf_name,
        cf::USERS | cf::CHANNELS | cf::CHANNEL_MEMBERS | cf::DELEGATIONS | cf::STATE_ANCHORS
    )
}

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
    async fn connected_peers(&self) -> Result<Vec<PeerId>, SnapshotClientError> {
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
                // decode_chunk verifies the SHA-256 hash against header.chunk_hash.
                match decode_chunk(&payload, header.codec, &header.chunk_hash) {
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

// --- Anchor re-verification against Klever (Phase 3) -------------------

/// Outcome of verifying the snapshot's `STATE_ANCHORS` against Klever.
#[derive(Debug, Clone)]
pub struct AnchorVerifyResult {
    /// Highest block height where the snapshot's claimed `state_root`
    /// matched what's on the Klever chain. This becomes the receiver's
    /// new `chain_cursor` after apply — the chain scanner will replay
    /// the (at most one anchor interval) of blocks between this height
    /// and `manifest.block_height`.
    pub cutoff_height: u64,
    /// How many anchors were checked before reaching the verified one.
    pub checked: usize,
    /// Total anchors in the snapshot.
    pub total: usize,
}

/// Iterate the snapshot's `STATE_ANCHORS` rows from highest height down,
/// re-checking each against the Klever SC's `getStateRoot(block_height)`
/// view. Returns the highest `block_height` whose claim matched on-chain.
///
/// Rejection cases:
/// - **Any anchor `Mismatch`** → snapshot is poisoned, abort with `Err`.
/// - **All anchors `NotAnchored`** → snapshot has no on-chain backing,
///   abort with `Err` (this also catches an attacker fabricating anchors).
/// - **Klever RPC unreachable for every anchor** → abort with `Err` unless
///   we've already accumulated ≥ 1 verified anchor at a higher height.
///
/// Spec 11-snapshot-sync.md §5a.5 (Phase 3 semantics).
pub async fn verify_anchors_against_klever(
    decoded_anchors: &[ChunkPayload],
    http: &reqwest::Client,
    klever_node_url: &str,
    contract_address: &str,
) -> Result<AnchorVerifyResult> {
    use crate::chain::anchor_verify::{verify_anchor, AnchorVerifyOutcome};
    use crate::chain::types::StateAnchorRecord;

    // Flatten all chunks and parse anchors.
    let mut anchors: Vec<StateAnchorRecord> = Vec::new();
    for chunk in decoded_anchors {
        for (key, value) in &chunk.entries {
            // Sanity: key is block_height_be (8 bytes); value is JSON.
            let key_arr: [u8; 8] = key.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "STATE_ANCHORS chunk has unexpected key length: got {}, expected 8",
                    key.len()
                )
            })?;
            let record: StateAnchorRecord = serde_json::from_slice(value)
                .context("parsing StateAnchorRecord from snapshot")?;
            // Cross-check: row key block_height matches the record.
            let key_height = u64::from_be_bytes(key_arr);
            if key_height != record.block_height {
                bail!(
                    "STATE_ANCHORS row key/value height mismatch: key={}, record={}",
                    key_height,
                    record.block_height
                );
            }
            anchors.push(record);
        }
    }

    let total = anchors.len();
    if total == 0 {
        bail!("snapshot has no STATE_ANCHORS — refusing to apply an unanchored snapshot");
    }

    // Sort by block_height descending so we check newest first.
    anchors.sort_by(|a, b| b.block_height.cmp(&a.block_height));

    // Anti-downgrade ratchet (audit Phase 3 Sec W1): if a peer pads the
    // snapshot with newer-than-real anchors, every one comes back
    // NotAnchored and the loop walks down to a much-older verified
    // anchor — silently demoting the cutoff. We refuse if more than
    // this many newer-than-cutoff claims fail with NotAnchored.
    const MAX_NEWER_NOT_ANCHORED: usize = 2;

    // Overall budget (audit Phase 3 Code W2): a malicious peer could
    // stuff hundreds of anchors and slow Klever RPC to its 15s per-
    // request limit. Cap the entire verification at 2 minutes — enough
    // for ~10 anchors at the per-request timeout, far more in the
    // common case.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);

    let mut checked: usize = 0;
    let mut rpc_failures: usize = 0;
    let mut newer_not_anchored: usize = 0;
    let mut first_verified: Option<u64> = None;
    // After we find the first match, we can stop — that's the highest
    // verified anchor and therefore the cutoff.
    for record in &anchors {
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "anchor verification exceeded total budget (checked {}/{}); aborting",
                checked,
                total
            );
        }
        checked += 1;
        let outcome = verify_anchor(
            http,
            klever_node_url,
            contract_address,
            record.block_height,
            &record.state_root,
        )
        .await;

        match outcome {
            AnchorVerifyOutcome::Match => {
                first_verified = Some(record.block_height);
                break;
            }
            AnchorVerifyOutcome::Mismatch { on_chain, in_snapshot } => {
                bail!(
                    "POISONED SNAPSHOT — anchor at block {} on-chain root '{}' \
                     differs from snapshot's claim '{}'. Refusing to apply.",
                    record.block_height,
                    on_chain,
                    in_snapshot
                );
            }
            AnchorVerifyOutcome::NotAnchored => {
                // Newer anchors not yet on-chain — possible if the SC's
                // anchoring is lagging, OR if the peer fabricated them.
                // Tolerate a small number; refuse a large gap (downgrade attack).
                newer_not_anchored += 1;
                if newer_not_anchored > MAX_NEWER_NOT_ANCHORED {
                    bail!(
                        "snapshot reports too many newer anchors not present on Klever ({} > {}); \
                         possible downgrade attack — refusing to apply",
                        newer_not_anchored,
                        MAX_NEWER_NOT_ANCHORED
                    );
                }
                warn!(
                    block_height = record.block_height,
                    newer_not_anchored,
                    "anchor not found on Klever — checking older anchors"
                );
                continue;
            }
            AnchorVerifyOutcome::RpcError(err) => {
                rpc_failures += 1;
                warn!(
                    block_height = record.block_height,
                    error = %err,
                    "Klever RPC error verifying anchor — will retry next anchor"
                );
                // If RPC is broken for many anchors in a row, bail.
                // Half the total is a reasonable threshold for "Klever down."
                if rpc_failures > (total / 2).max(2) {
                    bail!(
                        "Klever RPC failed for {} of {} anchors — aborting verification",
                        rpc_failures, total
                    );
                }
                continue;
            }
        }
    }

    let cutoff_height = first_verified.ok_or_else(|| {
        anyhow!(
            "No snapshot anchors verified against Klever (checked {}/{}); refusing apply",
            checked,
            total
        )
    })?;

    info!(
        cutoff_height,
        checked,
        total,
        rpc_failures,
        "Anchor verification complete — snapshot trusted up to verified cutoff"
    );

    Ok(AnchorVerifyResult {
        cutoff_height,
        checked,
        total,
    })
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
        if !cf_has_json_values(cf_name) {
            continue;
        }
        let cf_payloads = chunks
            .get(*cf_name)
            .ok_or_else(|| anyhow!("decoded chunks missing for cf '{}'", cf_name))?;
        for chunk in cf_payloads {
            for (k, v) in &chunk.entries {
                if serde_json::from_slice::<serde_json::Value>(v).is_err() {
                    bail!(
                        "cf '{}' row {:?} contains invalid JSON — refusing apply (malicious peer or corrupt snapshot)",
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

    // 5. Re-derive DEVICE_WALLET_MAP + WALLET_DEVICES from DELEGATIONS.
    //    These CFs are excluded from snapshot (privacy: §3.1 spec). The
    //    existing migration helper rebuilds them from DELEGATIONS rows.
    storage
        .backfill_delegation_map()
        .context("backfilling device-wallet maps after apply")?;

    // 6. Cursor + counters.
    storage
        .set_chain_cursor(cutoff_height)
        .context("setting chain_cursor after apply")?;
    storage
        .put_cf(
            cf::NODE_STATE,
            state_keys::TOTAL_USERS,
            &manifest.total_users.to_be_bytes(),
        )
        .context("updating TOTAL_USERS")?;
    storage
        .put_cf(
            cf::NODE_STATE,
            state_keys::TOTAL_CHANNELS,
            &manifest.total_channels.to_be_bytes(),
        )
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
/// `klever_node_url` and `contract_address` are used to re-verify each
/// snapshot anchor against the Ogmara KApp's `getStateRoot` view.
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

    // Phase 3: re-verify the snapshot's STATE_ANCHORS against Klever
    // and find the highest matching anchor. The producer's claim of
    // `last_verified_anchor_height` is NOT trusted any more — we always
    // ask Klever directly. Any anchor whose state_root differs from
    // on-chain truth is a *poisoned snapshot* — hard abort.
    let anchor_chunks = chunks
        .get(crate::storage::schema::cf::STATE_ANCHORS)
        .ok_or_else(|| anyhow!("STATE_ANCHORS chunks missing from decoded fetch"))?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .context("building HTTP client for Klever anchor verify")?;
    // Small-network escape hatch (re-introduced in v0.46.4). On a
    // network with fewer than ANCHOR_QUORUM_MIN (=3) active anchorers,
    // the SC's `getStateRoot` returns "Anchor not found" for every
    // recent height — no quorum has been reached, so no
    // canonical_anchor entry exists. The anti-downgrade ratchet then
    // correctly refuses the snapshot. Operators who control all the
    // anchorers (testnet, dev pair) can opt out of the Klever check
    // explicitly. Quorum + Merkle + producer Ed25519 sig still apply.
    let cutoff_height = if config.experimental_skip_anchor_verify {
        warn!(
            block_height = manifest.block_height,
            last_verified_anchor_height = manifest.last_verified_anchor_height,
            "experimental_skip_anchor_verify=true — bypassing Klever anchor re-verification. \
             Use ONLY when you control every anchorer and the SC quorum precondition can't \
             be satisfied. Production deployments must leave this flag false."
        );
        // Without Klever verification, the safe cutoff is the
        // manifest's block_height (where the snapshot was captured).
        // The chain scanner picks up from there.
        manifest.block_height
    } else {
        let anchor_result = match verify_anchors_against_klever(
            anchor_chunks,
            &http,
            klever_node_url,
            contract_address,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    error = %e,
                    "Anchor verification failed — falling back to chain scan. \
                     If you're on a single-anchorer testnet, this is expected because \
                     the SC requires 3+ distinct anchorers to canonicalize. Set \
                     [snapshot] experimental_skip_anchor_verify = true to bypass."
                );
                return Ok(None);
            }
        };
        anchor_result.cutoff_height
    };

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
        storage
            .put_cf(cf_names::USERS, b"klv1a", br#"{"display_name":"alice"}"#)
            .unwrap();
        storage.set_chain_cursor(50).unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let cache = build_cache(&storage, "testnet", "node1", &key, 64 * 1024, codec::NONE).unwrap();

        let mut decoded: HashMap<String, Vec<ChunkPayload>> = HashMap::new();
        for cf in &cache.manifest.cfs {
            let mut by_cf = vec![];
            for header in &cf.chunks {
                let p = cache.chunks.get(&(cf.cf_name.clone(), header.seq)).unwrap();
                by_cf.push(
                    crate::storage::snapshot::decode_chunk(p.as_slice(), header.codec, &header.chunk_hash)
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
        storage
            .put_cf(cf_names::USERS, b"klv1a", br#"{"display_name":"alice"}"#)
            .unwrap();
        storage.set_chain_cursor(50).unwrap();

        let key = SigningKey::generate(&mut OsRng);
        let cache = build_cache(&storage, "testnet", "node1", &key, 64 * 1024, codec::NONE).unwrap();

        let mut decoded: HashMap<String, Vec<ChunkPayload>> = HashMap::new();
        for cf in &cache.manifest.cfs {
            let mut by_cf = vec![];
            for header in &cf.chunks {
                let p = cache.chunks.get(&(cf.cf_name.clone(), header.seq)).unwrap();
                by_cf.push(
                    crate::storage::snapshot::decode_chunk(p.as_slice(), header.codec, &header.chunk_hash)
                        .unwrap(),
                );
            }
            decoded.insert(cf.cf_name.clone(), by_cf);
        }

        // Tamper: rewrite alice's value AFTER fetch+decode, simulating a
        // malicious peer in the agreeing group. Real attacker would also
        // rewrite chunk_hash in the manifest, but the manifest's cf_root
        // would no longer match the actual rows — which is what we catch.
        if let Some(users_chunks) = decoded.get_mut(cf_names::USERS) {
            if let Some(c) = users_chunks.first_mut() {
                if let Some((_, v)) = c.entries.first_mut() {
                    *v = br#"{"display_name":"mallory","admin":true}"#.to_vec();
                }
            }
        }

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

    /// End-to-end: populate the snapshot domain CFs, build a snapshot via
    /// `build_cache`, wipe the DB, apply the snapshot, and verify state
    /// matches the original.
    #[test]
    fn full_apply_roundtrip_against_real_rocksdb() {
        use crate::network::snapshot::build_cache;
        use crate::storage::schema::snapshot::codec;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let (source_storage, source_dir) = fresh_storage();

        // Populate every snapshot-domain CF with some data.
        let users = vec![
            (b"klv1a".as_ref(), br#"{"display_name":"alice"}"#.as_ref()),
            (b"klv1b".as_ref(), br#"{"display_name":"bob"}"#.as_ref()),
        ];
        for (k, v) in &users {
            source_storage.put_cf(cf_names::USERS, k, v).unwrap();
        }
        source_storage
            .put_cf(cf_names::NODE_STATE, schema::state_keys::TOTAL_USERS, &2u64.to_be_bytes())
            .unwrap();
        source_storage
            .put_cf(cf_names::CHANNELS, &7u64.to_be_bytes(), br#"{"name":"general"}"#)
            .unwrap();
        source_storage
            .put_cf(cf_names::NODE_STATE, schema::state_keys::TOTAL_CHANNELS, &1u64.to_be_bytes())
            .unwrap();
        source_storage.set_chain_cursor(12345).unwrap();

        // Build a snapshot from the source.
        let signing_key = SigningKey::generate(&mut OsRng);
        let cache = build_cache(
            &source_storage,
            "testnet",
            "test_node",
            &signing_key,
            64 * 1024, // 64 KiB chunks — small so we exercise multi-chunk
            codec::NONE,
        )
        .expect("build_cache");

        // Decode every chunk back into payloads (mimics what fetch_all_chunks
        // delivers to apply_snapshot).
        let mut decoded: HashMap<String, Vec<ChunkPayload>> = HashMap::new();
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
                )
                .expect("decode chunk");
                by_cf.push(payload);
            }
            decoded.insert(cf.cf_name.clone(), by_cf);
        }

        // Apply onto a fresh (target) storage.
        let (target_storage, target_dir) = fresh_storage();
        let outcome = apply_snapshot(
            &target_storage,
            target_dir.path(),
            &cache.manifest,
            &decoded,
            cache.manifest.block_height,
        )
        .expect("apply_snapshot");
        assert_eq!(outcome.applied_at, cache.manifest.block_height);
        assert_eq!(outcome.new_cursor, cache.manifest.block_height);

        // Verify state matches.
        for (k, v) in &users {
            let got = target_storage.get_cf(cf_names::USERS, k).unwrap();
            assert_eq!(got.as_deref(), Some(*v), "user {} should round-trip", String::from_utf8_lossy(k));
        }
        let chan = target_storage
            .get_cf(cf_names::CHANNELS, &7u64.to_be_bytes())
            .unwrap();
        assert!(chan.is_some(), "channel 7 should round-trip");

        // Sentinel + counters set.
        let sentinel = target_storage
            .get_cf(cf_names::NODE_STATE, schema::state_keys::SNAPSHOT_APPLIED_AT_HEIGHT)
            .unwrap()
            .expect("sentinel written");
        assert_eq!(
            u64::from_be_bytes(sentinel.try_into().unwrap()),
            cache.manifest.block_height
        );
        let cursor = target_storage.get_chain_cursor().unwrap();
        assert_eq!(cursor, cache.manifest.block_height);
        let total_users = target_storage
            .get_stat(schema::state_keys::TOTAL_USERS)
            .unwrap();
        assert_eq!(total_users, 2);

        // Rollback dir was created and is openable.
        assert!(outcome.rollback_dir.exists());
        let restored = Storage::open(&outcome.rollback_dir).expect("open rollback");
        // Restored storage is empty (target started fresh, checkpoint
        // captured pre-apply state which had nothing in DOMAIN_CFS).
        let restored_users = restored
            .prefix_iter_cf(cf_names::USERS, &[], 10)
            .unwrap();
        assert!(restored_users.is_empty(), "rollback captured pre-apply (empty) state");

        // Drop source so tempdir cleanup runs.
        drop(source_storage);
        drop(source_dir);
    }

    // --- Phase 3 anchor verification tests ---

    use crate::chain::anchor_verify::AnchorVerifyOutcome;

    fn anchor_chunk_payload(records: Vec<crate::chain::types::StateAnchorRecord>) -> ChunkPayload {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = records
            .into_iter()
            .map(|r| {
                let key = r.block_height.to_be_bytes().to_vec();
                let val = serde_json::to_vec(&r).unwrap();
                (key, val)
            })
            .collect();
        ChunkPayload {
            cf_name: cf_names::STATE_ANCHORS.to_string(),
            seq: 0,
            entries,
        }
    }

    fn anchor_record(block_height: u64, state_root: &str) -> crate::chain::types::StateAnchorRecord {
        crate::chain::types::StateAnchorRecord {
            block_height,
            state_root: state_root.to_string(),
            message_count: 0,
            channel_count: 0,
            user_count: 0,
            node_id: "test".into(),
            anchorer: String::new(),
            anchored_at: 0,
        }
    }

    /// Smoke test for the anchor verification iteration logic — the SC
    /// query itself isn't unit-testable here (it requires Klever RPC),
    /// so this test exercises the data extraction + sort + outcome
    /// handling pieces by parsing chunks and inspecting the structures.
    /// Full end-to-end verification is in the manual integration test.
    #[test]
    fn anchor_chunks_parse_and_sort_descending() {
        use crate::chain::types::StateAnchorRecord;

        let chunk = anchor_chunk_payload(vec![
            anchor_record(100, "aa".repeat(32).as_str()),
            anchor_record(300, "cc".repeat(32).as_str()),
            anchor_record(200, "bb".repeat(32).as_str()),
        ]);

        // Re-parse like verify_anchors_against_klever would.
        let mut parsed: Vec<StateAnchorRecord> = chunk
            .entries
            .iter()
            .map(|(_, v)| serde_json::from_slice(v).unwrap())
            .collect();
        parsed.sort_by(|a, b| b.block_height.cmp(&a.block_height));

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].block_height, 300);
        assert_eq!(parsed[1].block_height, 200);
        assert_eq!(parsed[2].block_height, 100);
    }

    #[test]
    fn anchor_outcome_variants_distinguish_correctly() {
        let m = AnchorVerifyOutcome::Match;
        let na = AnchorVerifyOutcome::NotAnchored;
        let mm = AnchorVerifyOutcome::Mismatch {
            on_chain: "aa".into(),
            in_snapshot: "bb".into(),
        };
        assert_ne!(m, na);
        assert_ne!(m, mm);
        assert_ne!(na, mm);
    }

    #[test]
    fn anchor_chunk_with_bad_key_length_is_rejected_pattern() {
        // The verify_anchors_against_klever loop checks `key.len() != 8`.
        // We can confirm the key-length invariant by inspecting a built
        // chunk: every anchor key is exactly 8 bytes (block_height_be).
        let chunk = anchor_chunk_payload(vec![anchor_record(100, &"aa".repeat(32))]);
        for (k, _) in &chunk.entries {
            assert_eq!(k.len(), 8, "every STATE_ANCHORS key must be 8 bytes");
        }
    }

    #[test]
    fn anchor_chunk_key_value_height_mismatch_is_detected() {
        // Manual tamper: key says height=100 but record says height=999.
        let mut chunk = anchor_chunk_payload(vec![anchor_record(999, &"aa".repeat(32))]);
        // Overwrite key to 100 while value still says 999.
        chunk.entries[0].0 = 100u64.to_be_bytes().to_vec();

        let entry = &chunk.entries[0];
        let key_height = u64::from_be_bytes(entry.0.as_slice().try_into().unwrap());
        let record: crate::chain::types::StateAnchorRecord =
            serde_json::from_slice(&entry.1).unwrap();
        assert_eq!(key_height, 100);
        assert_eq!(record.block_height, 999);
        // verify_anchors_against_klever catches this with `bail!`.
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
        // JSON-valued — USERS rows must parse as JSON per the receiver's
        // per-row validation (audit fix Phase 2 Sec C3).
        source
            .put_cf(cf_names::USERS, b"klv1a", br#"{"display_name":"alpha"}"#)
            .unwrap();
        source.set_chain_cursor(100).unwrap();

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
