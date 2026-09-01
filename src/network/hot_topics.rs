//! Hot Topics mesh aggregation (spec 3 §3.9, protocol §3.15).
//!
//! Each node keeps, per `(tag, bucket_hour)`, a HyperLogLog sketch of the
//! distinct `NewsPost` `msg_id`s it has indexed (`HOT_TOPICS_LOCAL`). On a
//! timer it publishes a signed [`HotTopicsDigest`] on the `/network` topic
//! carrying those sketches for the most recent buckets. A receiving node
//! folds an accepted digest into `HOT_TOPICS_MERGED` by HLL **union**, so a
//! post that reached every node is counted once. `GET /api/v1/news/hot-topics`
//! reads the merged view, applies a median trim and a minimum-contributors
//! gate, and returns the top tags.
//!
//! The digest is a standalone libp2p-key-signed struct (same pattern as
//! [`super::presence::PresenceRecord`]), NOT an `Envelope` through the message
//! router — its acceptance needs the gossip `propagation_source` and the SC
//! active-node set, both of which live in the network layer. `0xE1` is its
//! reserved protocol tag (`MessageType::HotTopicsDigest`), carried as a field
//! so a `/network`-topic reader can classify it cheaply.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::HotTopicsConfig;
use crate::hll::Hll;
use crate::storage::rocks::Storage;
use crate::storage::schema::{self, HOT_TOPICS_BUCKET_MS};

/// Protocol tag for a Hot Topics digest (`MessageType::HotTopicsDigest`).
pub const HOT_TOPICS_DIGEST_TAG: u8 = 0xE1;

/// Accept a digest whose `timestamp` is within this many seconds in the past.
const DIGEST_PAST_SKEW_SECS: u64 = 3600;
/// ...or this many seconds in the future.
const DIGEST_FUTURE_SKEW_SECS: u64 = 300;

// --- Wire types (protocol §3.15) ---

/// One tag's sketch inside a digest bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestTag {
    /// Canonical normalized tag (`util::normalize_tag`).
    pub tag: String,
    /// `Hll::to_bytes()` — 1-byte `sketch_format` + zstd(registers).
    pub hll: Vec<u8>,
    /// Sender's own cardinality estimate for `(tag, bucket)` — drives the
    /// receiver's per-node contribution clamp and the query-time median trim.
    pub approx: u32,
}

/// One bucket-hour's worth of tag sketches inside a digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestBucket {
    /// `NewsPost.timestamp / HOT_TOPICS_BUCKET_MS`.
    pub bucket_hour: u64,
    pub tags: Vec<DigestTag>,
}

/// The signed portion of a digest (everything except `signature`). Signing and
/// verification both operate on `rmp_serde::to_vec_named` of THIS struct, so
/// there is no "did both sides blank the signature field identically" footgun.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotTopicsDigestSigned {
    /// Reserved protocol tag — always [`HOT_TOPICS_DIGEST_TAG`].
    pub msg_type: u8,
    /// Base58 libp2p PeerId of the originator. MUST equal the gossip
    /// propagation source.
    pub peer_id: String,
    /// `klv1…` anchoring address, or `""` for a presence-only node.
    pub node_address: String,
    /// `"mainnet"` | `"testnet"` — receiver rejects on mismatch.
    pub network_id: String,
    /// Unix seconds the digest was minted.
    pub timestamp: u64,
    /// Sender's rolling-window width — receiver rejects if `!=` its own.
    pub window_hours: u64,
    pub buckets: Vec<DigestBucket>,
}

/// A signed Hot Topics digest as it travels on the `/network` topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotTopicsDigest {
    pub signed: HotTopicsDigestSigned,
    /// Ed25519 signature over `rmp_serde::to_vec_named(&signed)` with the
    /// libp2p key whose public half produces `peer_id`.
    pub signature: Vec<u8>,
}

// --- Stored merged view (`HOT_TOPICS_MERGED` value) ---

/// Per-`(tag, bucket_hour)` merged state. Persisted as `rmp_serde` (named).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HotTopicsMerged {
    /// Union of this node's local sketch and every accepted peer sketch for
    /// `(tag, bucket)`. `Hll::to_bytes()` form.
    pub merged_hll: Vec<u8>,
    /// Distinct contributing nodes folded so far (capped at
    /// `digest_max_peers`). `1` means "local only".
    pub contributor_count: u16,
    /// Ring of the most recent contributor cardinality estimates (`approx`
    /// values, plus this node's local estimate). Drives the median trim.
    pub approx_ring: Vec<u32>,
    /// Wall-clock ms of the last update (diagnostics / eviction sanity).
    pub updated_at: u64,
}

const APPROX_RING_MAX: usize = 32;

impl HotTopicsMerged {
    fn push_approx(&mut self, v: u32) {
        self.approx_ring.push(v);
        if self.approx_ring.len() > APPROX_RING_MAX {
            let drop = self.approx_ring.len() - APPROX_RING_MAX;
            self.approx_ring.drain(0..drop);
        }
    }
}

// --- Endpoint result ---

/// One row of `GET /api/v1/news/hot-topics`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HotTopic {
    pub hashtag: String,
    pub count: u64,
}

/// `scope` field of the endpoint response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// This node has folded enough peer digests to call the list network-wide.
    Network,
    /// Fresh / partitioned / mesh-disabled node serving only its own counts.
    Local,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Network => "network",
            Scope::Local => "local",
        }
    }
}

/// Full result of a hot-topics query.
#[derive(Debug, Clone)]
pub struct HotTopicsResult {
    pub scope: Scope,
    pub topics: Vec<HotTopic>,
}

/// Outcome of folding an inbound digest — maps to a gossip
/// `MessageAcceptance` at the call site.
#[derive(Debug, PartialEq, Eq)]
pub enum InboundOutcome {
    /// Folded (or a harmless duplicate/refresh) — safe to re-propagate.
    Accepted,
    /// Structurally/cryptographically invalid — reject + penalize the relay.
    Invalid(String),
    /// Well-formed but not folded (untrusted sender, rate-limited, out of
    /// window). Ignore, do not penalize.
    Ignored(String),
}

// --- Aggregator ---

/// Shared Hot Topics state: owns the RocksDB CFs' access, the per-PeerId
/// inbound rate limiter, the trusted-node snapshot, and the endpoint result
/// cache. One instance, wrapped in `Arc`, shared by `NetworkService` (publish
/// + inbound) and the API layer (`query`).
pub struct HotTopicsAggregator {
    storage: Storage,
    config: HotTopicsConfig,
    network_id: String,
    /// PeerId → last accepted digest `Instant`.
    rate: Mutex<HashMap<PeerId, Instant>>,
    /// Node addresses (`klv1…`) whose digests may be folded — SC-registered
    /// ∪ presence-`both`. Refreshed by `NetworkService`.
    trusted_nodes: RwLock<HashSet<String>>,
    /// `(computed_at, result)` — TTL `config.cache_ttl_secs`.
    result_cache: Mutex<Option<(Instant, HotTopicsResult)>>,
}

impl HotTopicsAggregator {
    pub fn new(storage: Storage, config: HotTopicsConfig, network_id: impl Into<String>) -> Self {
        Self {
            storage,
            config,
            network_id: network_id.into(),
            rate: Mutex::new(HashMap::new()),
            trusted_nodes: RwLock::new(HashSet::new()),
            result_cache: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &HotTopicsConfig {
        &self.config
    }

    /// Replace the trusted-node set (SC-registered ∪ presence-`both`).
    pub fn set_trusted_nodes(&self, set: HashSet<String>) {
        if let Ok(mut g) = self.trusted_nodes.write() {
            *g = set;
        }
    }

    fn trusted_nodes_empty(&self) -> bool {
        self.trusted_nodes.read().map(|g| g.is_empty()).unwrap_or(true)
    }

    fn is_trusted_node(&self, addr: &str) -> bool {
        !addr.is_empty()
            && self
                .trusted_nodes
                .read()
                .map(|g| g.contains(addr))
                .unwrap_or(false)
    }

    fn current_bucket(now_ms: u64) -> u64 {
        now_ms / HOT_TOPICS_BUCKET_MS
    }

    /// Oldest bucket still inside the rolling window (+ eviction slack).
    fn window_lo_bucket(&self, now_ms: u64) -> u64 {
        Self::current_bucket(now_ms)
            .saturating_sub(self.config.window_hours + self.config.eviction_slack_hours)
    }

    // --- Outbound ---

    /// Build and sign a digest for the recent buckets, or `None` if mesh
    /// aggregation is off / there is nothing to send / signing fails.
    pub fn build_and_sign_digest(
        &self,
        keypair: &libp2p::identity::Keypair,
        node_address: &str,
        now_ms: u64,
    ) -> Option<Vec<u8>> {
        if !self.config.enabled || !self.config.mesh_enabled {
            return None;
        }
        let cur = Self::current_bucket(now_ms);
        let lo = cur.saturating_sub(self.config.max_buckets_per_digest.saturating_sub(1) as u64);

        let mut buckets = Vec::new();
        for bh in (lo..=cur).rev() {
            let prefix = bh.to_be_bytes();
            let rows = self
                .storage
                .prefix_iter_cf(schema::cf::HOT_TOPICS_LOCAL, &prefix, self.config.max_tags_per_digest.saturating_mul(4))
                .ok()?;
            let mut tags: Vec<DigestTag> = Vec::new();
            for (key, val) in rows {
                let Some((_, tag)) = schema::decode_hot_topics_key(&key) else { continue };
                let Some(hll) = Hll::from_bytes(&val) else { continue };
                if hll.to_bytes().len() > self.config.max_sketch_bytes {
                    continue;
                }
                tags.push(DigestTag {
                    tag: tag.to_string(),
                    approx: hll.estimate_u32(),
                    hll: val,
                });
            }
            if tags.is_empty() {
                continue;
            }
            // Highest-cardinality tags first, then cap.
            tags.sort_by(|a, b| b.approx.cmp(&a.approx));
            tags.truncate(self.config.max_tags_per_digest);
            buckets.push(DigestBucket { bucket_hour: bh, tags });
        }
        if buckets.is_empty() {
            return None;
        }

        let signed = HotTopicsDigestSigned {
            msg_type: HOT_TOPICS_DIGEST_TAG,
            peer_id: keypair.public().to_peer_id().to_base58(),
            node_address: node_address.to_string(),
            network_id: self.network_id.clone(),
            timestamp: unix_secs(now_ms),
            window_hours: self.config.window_hours,
            buckets,
        };
        let canon = rmp_serde::to_vec_named(&signed).ok()?;
        let signature = keypair.sign(&canon).ok()?;
        let digest = HotTopicsDigest { signed, signature };
        rmp_serde::to_vec_named(&digest).ok()
    }

    // --- Inbound ---

    /// Try to decode `bytes` as a Hot Topics digest. Cheap classifier for the
    /// `/network` topic reader — a `NodeAnnouncement` envelope has none of the
    /// required fields and fails here.
    pub fn looks_like_digest(bytes: &[u8], max_envelope_bytes: usize) -> bool {
        if bytes.len() > max_envelope_bytes {
            return false;
        }
        match rmp_serde::from_slice::<HotTopicsDigest>(bytes) {
            Ok(d) => d.signed.msg_type == HOT_TOPICS_DIGEST_TAG,
            Err(_) => false,
        }
    }

    /// Validate an inbound digest and, if accepted, fold it into
    /// `HOT_TOPICS_MERGED`. The cost-ordered pipeline mirrors
    /// `presence::validate_record`.
    pub fn handle_inbound(
        &self,
        propagation_source: PeerId,
        bytes: &[u8],
        now_ms: u64,
    ) -> InboundOutcome {
        if !self.config.enabled || !self.config.mesh_enabled {
            return InboundOutcome::Ignored("mesh disabled".into());
        }
        // 1. Envelope-size guard (pre-decode).
        if bytes.len() > self.config.digest_max_envelope_bytes {
            return InboundOutcome::Invalid(format!(
                "digest {} bytes exceeds {}",
                bytes.len(),
                self.config.digest_max_envelope_bytes
            ));
        }
        // 2. Decode.
        let digest: HotTopicsDigest = match rmp_serde::from_slice(bytes) {
            Ok(d) => d,
            Err(e) => return InboundOutcome::Invalid(format!("decode: {e}")),
        };
        let s = &digest.signed;
        if s.msg_type != HOT_TOPICS_DIGEST_TAG {
            return InboundOutcome::Invalid("wrong msg_type".into());
        }
        // 3. PeerId parse + denylist + propagation-source match.
        let claimed: PeerId = match s.peer_id.parse() {
            Ok(p) => p,
            Err(e) => return InboundOutcome::Invalid(format!("bad peer_id: {e}")),
        };
        if self.config.digest_denylist.iter().any(|d| d == &s.peer_id) {
            return InboundOutcome::Ignored("denylisted".into());
        }
        if claimed != propagation_source {
            return InboundOutcome::Invalid("peer_id != propagation source".into());
        }
        // 4. Rate-limit PEEK (non-mutating, cheap).
        if !self.rate_peek(&claimed, now_ms) {
            return InboundOutcome::Ignored("rate limited".into());
        }
        // 5. Timestamp skew.
        let now_s = unix_secs(now_ms);
        if s.timestamp <= now_s.saturating_sub(DIGEST_PAST_SKEW_SECS)
            || s.timestamp >= now_s.saturating_add(DIGEST_FUTURE_SKEW_SECS)
        {
            return InboundOutcome::Invalid("timestamp skew".into());
        }
        // 6. network_id.
        if s.network_id != self.network_id {
            return InboundOutcome::Invalid("network_id mismatch".into());
        }
        // 7. window_hours.
        if s.window_hours != self.config.window_hours {
            return InboundOutcome::Ignored("window_hours mismatch".into());
        }
        // 8. Shape caps.
        if s.buckets.len() > self.config.max_buckets_per_digest {
            return InboundOutcome::Invalid("too many buckets".into());
        }
        if s.buckets.iter().any(|b| b.tags.len() > self.config.max_tags_per_digest) {
            return InboundOutcome::Invalid("too many tags in a bucket".into());
        }
        // 9. Signature (Ed25519 over to_vec_named(signed)).
        if let Err(e) = verify_digest_sig(&digest) {
            return InboundOutcome::Invalid(format!("bad signature: {e}"));
        }
        // 10. Rate-limit COMMIT.
        if !self.rate_commit(&claimed, now_ms) {
            return InboundOutcome::Ignored("rate limited".into());
        }
        // 11. Sender-identity gate.
        let trusted = self.is_trusted_node(&s.node_address)
            || (self.config.require_sc_registered_sender && self.trusted_nodes_empty());
        //          ^ no Klever RPC configured / set not yet populated → fall
        //            back to "meshed peer" acceptance (we only get here for a
        //            gossip-mesh delivery whose peer_id matched the source).
        if self.config.require_sc_registered_sender && !trusted {
            return InboundOutcome::Ignored("sender not a known active node".into());
        }
        // 12. Fold each (bucket, tag).
        let lo = self.window_lo_bucket(now_ms);
        let hi = Self::current_bucket(now_ms) + 1;
        let mut folded = 0usize;
        for b in &s.buckets {
            if b.bucket_hour < lo || b.bucket_hour > hi {
                continue;
            }
            for t in &b.tags {
                if crate::util::normalize_tag(&t.tag).as_deref() != Some(t.tag.as_str()) {
                    continue; // non-canonical tag in a digest — skip
                }
                if t.hll.len() > self.config.max_sketch_bytes {
                    continue;
                }
                let Some(incoming) = Hll::from_bytes(&t.hll) else { continue };
                // Per-node contribution clamp.
                if t.approx > self.config.max_node_tag_contribution.saturating_mul(2) {
                    warn!(peer = %claimed, tag = %t.tag, approx = t.approx, "hot-topics: dropping wildly-inflated tag from digest");
                    continue;
                }
                if t.approx > self.config.max_node_tag_contribution {
                    warn!(peer = %claimed, tag = %t.tag, approx = t.approx, "hot-topics: peer contribution above clamp (folding anyway)");
                }
                if let Err(e) = self.fold_one(b.bucket_hour, &t.tag, &incoming, t.approx, now_ms) {
                    debug!(error = %e, "hot-topics: fold failed");
                }
                folded += 1;
            }
        }
        debug!(peer = %claimed, folded, "hot-topics: digest folded");
        self.invalidate_cache();
        InboundOutcome::Accepted
    }

    fn fold_one(
        &self,
        bucket_hour: u64,
        tag: &str,
        incoming: &Hll,
        approx: u32,
        now_ms: u64,
    ) -> Result<()> {
        let key = schema::encode_hot_topics_key(bucket_hour, tag);
        let mut merged: HotTopicsMerged = self
            .storage
            .get_cf(schema::cf::HOT_TOPICS_MERGED, &key)?
            .and_then(|b| rmp_serde::from_slice(&b).ok())
            .unwrap_or_default();

        // Seed from local on first touch so the merged view is never behind
        // this node's own ingest.
        let mut acc = if merged.merged_hll.is_empty() {
            let local = self
                .storage
                .get_cf(schema::cf::HOT_TOPICS_LOCAL, &key)?
                .and_then(|b| Hll::from_bytes(&b))
                .unwrap_or_default();
            merged.contributor_count = 1;
            merged.push_approx(local.estimate_u32());
            local
        } else {
            Hll::from_bytes(&merged.merged_hll).unwrap_or_default()
        };

        acc.merge(incoming);
        merged.merged_hll = acc.to_bytes();
        merged.contributor_count = merged
            .contributor_count
            .saturating_add(1)
            .min(self.config.digest_max_peers as u16);
        merged.push_approx(approx);
        merged.updated_at = now_ms;

        let bytes = rmp_serde::to_vec_named(&merged)?;
        self.storage
            .put_cf(schema::cf::HOT_TOPICS_MERGED, &key, &bytes)?;
        Ok(())
    }

    fn rate_peek(&self, peer: &PeerId, now_ms: u64) -> bool {
        let gap = std::time::Duration::from_secs(self.config.inbound_rate_limit_secs);
        let _ = now_ms;
        match self.rate.lock() {
            Ok(g) => g.get(peer).map(|prev| prev.elapsed() >= gap).unwrap_or(true),
            Err(_) => true,
        }
    }

    fn rate_commit(&self, peer: &PeerId, now_ms: u64) -> bool {
        let _ = now_ms;
        let gap = std::time::Duration::from_secs(self.config.inbound_rate_limit_secs);
        let Ok(mut g) = self.rate.lock() else { return true };
        if let Some(prev) = g.get(peer) {
            if prev.elapsed() < gap {
                return false;
            }
        } else if g.len() >= 16_384 {
            // Sybil-flood soft cap on the tracker (mirrors presence).
            return false;
        }
        g.insert(*peer, Instant::now());
        true
    }

    /// Drop rate-limiter entries older than `2 × inbound_rate_limit_secs`.
    pub fn prune_rate_limiter(&self) {
        let cutoff = std::time::Duration::from_secs(self.config.inbound_rate_limit_secs * 2);
        if let Ok(mut g) = self.rate.lock() {
            g.retain(|_, t| t.elapsed() < cutoff);
        }
    }

    fn invalidate_cache(&self) {
        if let Ok(mut g) = self.result_cache.lock() {
            *g = None;
        }
    }

    // --- Query ---

    /// Compute (or serve from the TTL cache) the top-N trending tags.
    pub fn query(&self, limit: usize, now_ms: u64) -> HotTopicsResult {
        if let Ok(g) = self.result_cache.lock() {
            if let Some((at, res)) = g.as_ref() {
                if at.elapsed() < std::time::Duration::from_secs(self.config.cache_ttl_secs) {
                    let mut r = res.clone();
                    r.topics.truncate(limit);
                    return r;
                }
            }
        }
        let res = self.compute_query(now_ms);
        if let Ok(mut g) = self.result_cache.lock() {
            *g = Some((Instant::now(), res.clone()));
        }
        let mut r = res;
        r.topics.truncate(limit);
        r
    }

    fn compute_query(&self, now_ms: u64) -> HotTopicsResult {
        let cur = Self::current_bucket(now_ms);
        let lo = cur.saturating_sub(self.config.window_hours.saturating_sub(1));

        // tag -> (window-union HLL, best contributor_count, approx ring merged)
        let mut merged_acc: HashMap<String, (Hll, u16, Vec<u32>)> = HashMap::new();
        let mut local_acc: HashMap<String, Hll> = HashMap::new();

        for bh in lo..=cur {
            let prefix = bh.to_be_bytes();
            if let Ok(rows) =
                self.storage
                    .prefix_iter_cf(schema::cf::HOT_TOPICS_MERGED, &prefix, 100_000)
            {
                for (key, val) in rows {
                    let Some((_, tag)) = schema::decode_hot_topics_key(&key) else { continue };
                    let Ok(m) = rmp_serde::from_slice::<HotTopicsMerged>(&val) else { continue };
                    let Some(hll) = Hll::from_bytes(&m.merged_hll) else { continue };
                    let e = merged_acc
                        .entry(tag.to_string())
                        .or_insert_with(|| (Hll::new(), 0, Vec::new()));
                    e.0.merge(&hll);
                    e.1 = e.1.max(m.contributor_count);
                    e.2.extend(m.approx_ring);
                }
            }
            if let Ok(rows) =
                self.storage
                    .prefix_iter_cf(schema::cf::HOT_TOPICS_LOCAL, &prefix, 100_000)
            {
                for (key, val) in rows {
                    let Some((_, tag)) = schema::decode_hot_topics_key(&key) else { continue };
                    let Some(hll) = Hll::from_bytes(&val) else { continue };
                    local_acc.entry(tag.to_string()).or_default().merge(&hll);
                }
            }
        }

        let mesh_ok = self.config.mesh_enabled && !merged_acc.is_empty();
        let mut topics: Vec<(HotTopic, bool)> = Vec::new(); // (row, is_network_scope)

        // union of all tags seen in either view
        let mut all_tags: HashSet<&str> = HashSet::new();
        for k in merged_acc.keys() {
            all_tags.insert(k.as_str());
        }
        for k in local_acc.keys() {
            all_tags.insert(k.as_str());
        }

        for tag in all_tags {
            let local_est = local_acc.get(tag).map(|h| h.estimate_u32()).unwrap_or(0) as u64;
            let (count, contributors) = match merged_acc.get(tag) {
                Some((hll, contributors, ring)) => {
                    let raw = hll.estimate_u32() as u64;
                    // Median trim.
                    let trimmed = if *contributors >= self.config.min_contributors_for_trim
                        && !ring.is_empty()
                    {
                        let mut r = ring.clone();
                        r.sort_unstable();
                        let median = r[r.len() / 2] as u64;
                        raw.min(median.saturating_mul(self.config.trim_multiplier as u64))
                    } else {
                        // Too few contributors for a stable median → bound by
                        // local cardinality × multiplier.
                        raw.min(
                            local_est.saturating_mul(self.config.local_only_multiplier as u64),
                        )
                    };
                    (trimmed.max(local_est), *contributors)
                }
                None => (local_est, 1),
            };

            if count < self.config.min_count {
                continue;
            }
            let network_scope = contributors >= self.config.min_contributors;
            // A tag shows if it is network-scoped, OR it clears min_count in
            // this node's OWN local view.
            if !network_scope && local_est < self.config.min_count {
                continue;
            }
            topics.push((
                HotTopic {
                    hashtag: tag.to_string(),
                    count,
                },
                network_scope,
            ));
        }

        topics.sort_by(|a, b| {
            b.0.count
                .cmp(&a.0.count)
                .then_with(|| a.0.hashtag.cmp(&b.0.hashtag))
        });
        let cap = self.config.limit_cap.min(100);
        topics.truncate(cap);

        let scope = if mesh_ok && topics.iter().any(|(_, ns)| *ns) {
            Scope::Network
        } else {
            Scope::Local
        };
        HotTopicsResult {
            scope,
            topics: topics.into_iter().map(|(t, _)| t).collect(),
        }
    }

    // --- Maintenance ---

    /// Range-delete buckets older than `now - window - slack` from both CFs.
    /// Returns the number of keys removed.
    pub fn evict_stale(&self, now_ms: u64) -> Result<u64> {
        let lo = self.window_lo_bucket(now_ms);
        let mut removed = 0u64;
        for cf in [schema::cf::HOT_TOPICS_LOCAL, schema::cf::HOT_TOPICS_MERGED] {
            // Keys sort by BE bucket_hour, so every stale key is a contiguous
            // head range `[0, lo)`.
            'cf: loop {
                let batch = self.storage.prefix_iter_cf(cf, &[], 4096)?;
                if batch.is_empty() {
                    break;
                }
                let mut deleted_any = false;
                for (key, _) in &batch {
                    let Some((bh, _)) = schema::decode_hot_topics_key(key) else { continue };
                    if bh >= lo {
                        // First in-window key — nothing older remains in THIS
                        // cf. Move on to the next cf, not out of the function.
                        break 'cf;
                    }
                    self.storage.delete_cf(cf, key)?;
                    removed += 1;
                    deleted_any = true;
                }
                if !deleted_any {
                    break;
                }
            }
        }
        Ok(removed)
    }

    /// On first start after upgrade: if `HOT_TOPICS_LOCAL` is empty but
    /// `NEWS_FEED` is not, rebuild the local sketches from the last
    /// `window_hours` of posts. Returns the number of posts scanned.
    pub fn bootstrap_local_from_news_feed(&self, now_ms: u64) -> Result<u64> {
        if !self.config.enabled {
            return Ok(0);
        }
        let already = self
            .storage
            .prefix_iter_cf(schema::cf::HOT_TOPICS_LOCAL, &[], 1)?;
        if !already.is_empty() {
            return Ok(0);
        }
        let lo_bucket = Self::current_bucket(now_ms)
            .saturating_sub(self.config.window_hours + self.config.eviction_slack_hours);
        let lo_ms = lo_bucket * HOT_TOPICS_BUCKET_MS;

        // NEWS_FEED is keyed by `!timestamp` (newest first). Walk from the
        // head until we pass out of the window.
        let mut scanned = 0u64;
        let mut sketches: HashMap<Vec<u8>, Hll> = HashMap::new();
        let rows = self
            .storage
            .prefix_iter_cf(schema::cf::NEWS_FEED, &[], 200_000)?;
        for (key, _) in rows {
            if key.len() < 40 {
                continue;
            }
            let inv_ts = u64::from_be_bytes(key[0..8].try_into().unwrap_or([0; 8]));
            let ts = !inv_ts;
            if ts < lo_ms {
                break;
            }
            let msg_id: [u8; 32] = key[8..40].try_into().unwrap_or([0u8; 32]);
            let Ok(Some(env_bytes)) = self.storage.get_message(&msg_id) else { continue };
            let Ok(env) =
                rmp_serde::from_slice::<crate::messages::envelope::Envelope>(&env_bytes)
            else {
                continue;
            };
            if env.msg_type != crate::messages::types::MessageType::NewsPost {
                continue;
            }
            let Ok(payload) = rmp_serde::from_slice::<crate::messages::types::NewsPostPayload>(
                &env.payload,
            ) else {
                continue;
            };
            let bh = env.timestamp / HOT_TOPICS_BUCKET_MS;
            for tag in crate::util::normalize_tags_dedup(&payload.tags) {
                let k = schema::encode_hot_topics_key(bh, &tag);
                sketches.entry(k).or_default().insert(&msg_id);
            }
            scanned += 1;
        }
        for (k, hll) in sketches {
            self.storage
                .put_cf(schema::cf::HOT_TOPICS_LOCAL, &k, &hll.to_bytes())?;
        }
        Ok(scanned)
    }
}

/// Verify a digest's Ed25519 signature against the public key embedded in its
/// `peer_id`.
fn verify_digest_sig(digest: &HotTopicsDigest) -> Result<(), String> {
    let peer_id: PeerId = digest
        .signed
        .peer_id
        .parse()
        .map_err(|e: libp2p::identity::ParseError| e.to_string())?;
    let pk = super::presence::extract_ed25519_public_key(&peer_id)
        .map_err(|e| e.to_string())?;
    let canon = rmp_serde::to_vec_named(&digest.signed).map_err(|e| e.to_string())?;
    if !pk.verify(&canon, &digest.signature) {
        return Err("ed25519 verify failed".into());
    }
    Ok(())
}

fn unix_secs(now_ms: u64) -> u64 {
    now_ms / 1000
}

/// Convenience: current wall-clock ms (falls back to 0 pre-epoch).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn agg(cfg: HotTopicsConfig) -> (HotTopicsAggregator, TempDir) {
        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        (HotTopicsAggregator::new(storage, cfg, "testnet"), dir)
    }

    fn id(n: u64) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ht-test");
        h.update(n.to_le_bytes());
        h.finalize().into()
    }

    fn put_local(a: &HotTopicsAggregator, bucket: u64, tag: &str, ids: &[u64]) {
        let mut hll = Hll::new();
        for &i in ids {
            hll.insert(&id(i));
        }
        a.storage
            .put_cf(
                schema::cf::HOT_TOPICS_LOCAL,
                &schema::encode_hot_topics_key(bucket, tag),
                &hll.to_bytes(),
            )
            .unwrap();
    }

    #[test]
    fn local_only_query_returns_local_scope() {
        let (a, _d) = agg(HotTopicsConfig::default());
        let now = 1_000 * HOT_TOPICS_BUCKET_MS + 5;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        put_local(&a, cur, "klever", &(0..40).collect::<Vec<_>>());
        put_local(&a, cur, "defi", &(0..3).collect::<Vec<_>>());

        let res = a.query(10, now);
        assert_eq!(res.scope, Scope::Local);
        assert_eq!(res.topics[0].hashtag, "klever");
        // ~40 distinct, small HLL error tolerance.
        assert!((res.topics[0].count as i64 - 40).abs() <= 3, "{}", res.topics[0].count);
        // "defi" (3) clears default min_count 2.
        assert!(res.topics.iter().any(|t| t.hashtag == "defi"));
    }

    #[test]
    fn min_count_filters_rare_tags() {
        let mut cfg = HotTopicsConfig::default();
        cfg.min_count = 5;
        let (a, _d) = agg(cfg);
        let now = 500 * HOT_TOPICS_BUCKET_MS;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        put_local(&a, cur, "rare", &(0..3).collect::<Vec<_>>());
        put_local(&a, cur, "hot", &(0..50).collect::<Vec<_>>());
        let res = a.query(10, now);
        assert!(res.topics.iter().all(|t| t.hashtag != "rare"));
        assert!(res.topics.iter().any(|t| t.hashtag == "hot"));
    }

    #[test]
    fn evict_stale_drops_old_buckets_from_both_cfs() {
        let (a, _d) = agg(HotTopicsConfig::default());
        let now = 10_000 * HOT_TOPICS_BUCKET_MS;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        put_local(&a, cur, "fresh", &[1, 2, 3]);
        put_local(&a, cur - 5, "recent", &[4, 5]);
        put_local(&a, cur - 200, "ancient", &[6, 7]); // window 24 + slack 2 → gone
        // A stale MERGED row too — must be swept even though LOCAL's scan
        // reaches an in-window key first (regression: the early-return bug).
        a.storage
            .put_cf(
                schema::cf::HOT_TOPICS_MERGED,
                &schema::encode_hot_topics_key(cur - 300, "ancientmerged"),
                &rmp_serde::to_vec_named(&HotTopicsMerged::default()).unwrap(),
            )
            .unwrap();

        let removed = a.evict_stale(now).unwrap();
        assert_eq!(removed, 2); // 1 local + 1 merged

        let local_left = a
            .storage
            .prefix_iter_cf(schema::cf::HOT_TOPICS_LOCAL, &[], 100)
            .unwrap();
        assert_eq!(local_left.len(), 2, "fresh + recent survive");
        let merged_left = a
            .storage
            .prefix_iter_cf(schema::cf::HOT_TOPICS_MERGED, &[], 100)
            .unwrap();
        assert!(merged_left.is_empty(), "stale merged row must be evicted");
    }

    #[test]
    fn digest_roundtrip_build_then_fold_five_nodes_counts_union_once() {
        // Five nodes each ingest the SAME 100 posts under #klever. A merged
        // estimate must be ~100, not ~500 — the whole point of the design.
        let now = 2_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;

        let (receiver, _d) = agg(HotTopicsConfig::default());
        // receiver trusts everyone for the test
        let mut trusted = HashSet::new();

        for node in 0..5u64 {
            let (sender, _sd) = agg(HotTopicsConfig::default());
            put_local(&sender, cur, "klever", &(0..100).collect::<Vec<_>>());
            let kp = libp2p::identity::Keypair::generate_ed25519();
            let addr = format!("klv1node{node}");
            trusted.insert(addr.clone());
            let bytes = sender
                .build_and_sign_digest(&kp, &addr, now)
                .expect("digest");
            receiver.set_trusted_nodes(trusted.clone());
            let src = kp.public().to_peer_id();
            let out = receiver.handle_inbound(src, &bytes, now + node); // +node so rate limiter differs
            assert_eq!(out, InboundOutcome::Accepted, "node {node}");
        }

        let res = receiver.query(10, now);
        let k = res.topics.iter().find(|t| t.hashtag == "klever").expect("klever present");
        assert!(
            (k.count as i64 - 100).abs() <= 10,
            "over-counted across nodes: {}",
            k.count
        );
        assert_eq!(res.scope, Scope::Network);
    }

    #[test]
    fn untrusted_sender_is_ignored_not_folded() {
        let now = 3_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &(0..100).collect::<Vec<_>>());
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let bytes = sender.build_and_sign_digest(&kp, "klv1rogue", now).unwrap();

        let (receiver, _d) = agg(HotTopicsConfig::default());
        // trusted set explicitly populated but WITHOUT the rogue → not empty,
        // so the mesh fallback does not apply.
        receiver.set_trusted_nodes(HashSet::from(["klv1someoneelse".to_string()]));
        let out = receiver.handle_inbound(kp.public().to_peer_id(), &bytes, now);
        assert!(matches!(out, InboundOutcome::Ignored(_)), "{out:?}");
    }

    #[test]
    fn tampered_signature_is_invalid() {
        let now = 4_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &[1, 2, 3, 4, 5]);
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let mut bytes = sender.build_and_sign_digest(&kp, "klv1x", now).unwrap();
        *bytes.last_mut().unwrap() ^= 0xFF;
        let (receiver, _d) = agg(HotTopicsConfig::default());
        let out = receiver.handle_inbound(kp.public().to_peer_id(), &bytes, now);
        assert!(matches!(out, InboundOutcome::Invalid(_)), "{out:?}");
    }

    #[test]
    fn wrong_network_is_invalid() {
        let now = 5_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &[1, 2, 3]);
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let bytes = sender.build_and_sign_digest(&kp, "klv1x", now).unwrap();

        let dir = TempDir::new().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let receiver =
            HotTopicsAggregator::new(storage, HotTopicsConfig::default(), "mainnet");
        let out = receiver.handle_inbound(kp.public().to_peer_id(), &bytes, now);
        assert!(matches!(out, InboundOutcome::Invalid(_)), "{out:?}");
    }

    #[test]
    fn rate_limit_blocks_a_rapid_second_digest() {
        let now = 6_000 * HOT_TOPICS_BUCKET_MS + 1;
        let cur = now / HOT_TOPICS_BUCKET_MS;
        let (sender, _sd) = agg(HotTopicsConfig::default());
        put_local(&sender, cur, "klever", &(0..20).collect::<Vec<_>>());
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let addr = "klv1n";
        let (receiver, _d) = agg(HotTopicsConfig::default());
        receiver.set_trusted_nodes(HashSet::from([addr.to_string()]));
        let b1 = sender.build_and_sign_digest(&kp, addr, now).unwrap();
        let b2 = sender.build_and_sign_digest(&kp, addr, now + 1).unwrap();
        assert_eq!(
            receiver.handle_inbound(kp.public().to_peer_id(), &b1, now),
            InboundOutcome::Accepted
        );
        assert!(matches!(
            receiver.handle_inbound(kp.public().to_peer_id(), &b2, now + 1),
            InboundOutcome::Ignored(_)
        ));
    }

    #[test]
    fn bootstrap_is_noop_when_local_already_populated() {
        let (a, _d) = agg(HotTopicsConfig::default());
        let now = 7_000 * HOT_TOPICS_BUCKET_MS;
        put_local(&a, now / HOT_TOPICS_BUCKET_MS, "x", &[1]);
        assert_eq!(a.bootstrap_local_from_news_feed(now).unwrap(), 0);
    }
}
